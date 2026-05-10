"""
BlueSploit Module: Local Adapter Spoof

Spoofs properties of the local Bluetooth adapter to impersonate
another device or evade fingerprinting. Supports four spoof targets:

  hostname  — change the host's broadcast Bluetooth name (HCI_Write_Local_Name)
  alias     — set the BlueZ controller alias (mgmt API via bluetoothctl)
  cod       — set the Class of Device (HCI_Write_Class_Of_Device)
  bdaddr    — change the adapter's BD_ADDR (vendor-specific HCI commands)

The cod/bdaddr operations are vendor-specific and require root + a
compatible chipset (CSR, Broadcom, Intel, TI, Zeevo, Ericsson).
"""

import os
import re
import socket
import struct
import subprocess
import time
from typing import Optional

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

AF_BLUETOOTH    = 31
BTPROTO_HCI     = 1
HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT   = 0x04
EVT_CMD_COMPLETE= 0x0E

# Common CoD presets
COD_PRESETS = {
    "smartphone":   0x5A020C,  # Phone, Smartphone
    "headphones":   0x240404,  # Audio, Wearable Headset
    "speaker":      0x240414,  # Audio, Loudspeaker
    "keyboard":     0x002540,  # Peripheral, Keyboard
    "mouse":        0x002580,  # Peripheral, Pointing
    "computer":     0x12010C,  # Computer, Laptop
    "imaging":      0x680680,  # Imaging
    "wearable":     0x000704,  # Wearable
    "toy":          0x000804,  # Toy
    "uncategorized":0x000000,  # No info
}


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Local Adapter Spoof",
        description="Spoof local adapter hostname, alias, Class of Device, or BD_ADDR",
        author=["BlueSploit"],
        protocol=BTProtocol.DUAL,
        severity=Severity.INFO,
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="What to spoof: hostname, alias, cod, bdaddr",
            default="hostname",
        ))
        self.add_option(ModuleOption(
            name="value",
            required=True,
            description="New value (string for hostname/alias, hex for CoD, MAC for bdaddr)",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="restart",
            required=False,
            description="Restart the adapter after spoof (true/false)",
            default="true",
        ))

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root required for local adapter spoofing")
            return False

        mode    = (self.get_option("mode") or "hostname").lower()
        value   = self.get_option("value")
        iface   = self.get_option("interface") or "hci0"
        restart = (self.get_option("restart") or "true").lower() == "true"

        if not value:
            print_error("'value' option is required")
            return False
        if mode not in ("hostname", "alias", "cod", "bdaddr"):
            print_error(f"Invalid mode: {mode}")
            return False

        print_info(f"Mode     : {mode}")
        print_info(f"Value    : {value}")
        print_info(f"Interface: {iface}")

        if mode == "hostname":
            return self._spoof_hostname(iface, value)
        if mode == "alias":
            return self._spoof_alias(iface, value)
        if mode == "cod":
            return self._spoof_cod(iface, value)
        if mode == "bdaddr":
            return self._spoof_bdaddr(iface, value, restart)
        return False

    # ── hostname ──────────────────────────────────────────────────────────

    def _spoof_hostname(self, iface: str, name: str) -> bool:
        """HCI_Write_Local_Name (OGF=0x03, OCF=0x0013) — 248-byte name."""
        if len(name.encode("utf-8")) > 248:
            print_error("Name too long (max 248 bytes UTF-8)")
            return False
        hci = self._open_hci(iface)
        if not hci:
            return False
        try:
            name_bytes = name.encode("utf-8").ljust(248, b"\x00")
            self._hci_cmd(hci, 0x03, 0x0013, name_bytes)
            ev = self._wait_event(hci, EVT_CMD_COMPLETE, timeout=3.0)
            if ev and len(ev) >= 4 and ev[3] == 0x00:
                print_success(f"Local name set to '{name}'")
                self.add_result({"mode": "hostname", "value": name, "success": True})
                return True
            print_error("Write_Local_Name failed")
            return False
        finally:
            hci.close()

    # ── alias (BlueZ-side display name) ───────────────────────────────────

    def _spoof_alias(self, iface: str, alias: str) -> bool:
        """Set the BlueZ controller alias via bluetoothctl."""
        if not self._cmd_exists("bluetoothctl"):
            print_error("bluetoothctl not found — install bluez")
            return False
        try:
            r = subprocess.run(
                ["bluetoothctl", "system-alias", alias],
                capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                print_success(f"Controller alias set to '{alias}'")
                self.add_result({"mode": "alias", "value": alias, "success": True})
                return True
            print_error(f"system-alias failed: {r.stderr.strip() or r.stdout.strip()}")
            return False
        except Exception as e:
            print_error(f"bluetoothctl error: {e}")
            return False

    # ── Class of Device ───────────────────────────────────────────────────

    def _spoof_cod(self, iface: str, value: str) -> bool:
        """HCI_Write_Class_Of_Device (OGF=0x03, OCF=0x0024)."""
        # Parse value: preset name OR hex (0x......) OR int
        v = value.strip().lower()
        if v in COD_PRESETS:
            cod = COD_PRESETS[v]
            print_info(f"Using preset '{v}' → 0x{cod:06X}")
        else:
            try:
                cod = int(value, 0)
            except ValueError:
                print_error(f"Invalid CoD: {value}. Use hex (0x...) or preset: "
                            f"{', '.join(COD_PRESETS)}")
                return False
        if cod > 0xFFFFFF:
            print_error("CoD must fit in 24 bits")
            return False

        hci = self._open_hci(iface)
        if not hci:
            return False
        try:
            params = struct.pack("<I", cod)[:3]  # 3 bytes little-endian
            self._hci_cmd(hci, 0x03, 0x0024, params)
            ev = self._wait_event(hci, EVT_CMD_COMPLETE, timeout=3.0)
            if ev and len(ev) >= 4 and ev[3] == 0x00:
                print_success(f"Class of Device set to 0x{cod:06X}")
                self.add_result({"mode": "cod", "value": f"0x{cod:06X}", "success": True})
                return True
            print_error("Write_Class_Of_Device failed")
            return False
        finally:
            hci.close()

    # ── BD_ADDR (vendor-specific) ─────────────────────────────────────────

    def _spoof_bdaddr(self, iface: str, new_addr: str, restart: bool) -> bool:
        """
        BD_ADDR change is vendor-specific. Try the `bdaddr` tool from the
        bluez source tree first, fall back to known vendor commands.
        """
        if not re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", new_addr):
            print_error(f"Invalid BD_ADDR: {new_addr}")
            return False

        # Try bdaddr CLI (most reliable, supports all vendors it knows)
        if self._cmd_exists("bdaddr"):
            try:
                cmd = ["bdaddr", "-i", iface, new_addr]
                if restart:
                    cmd.append("-r")
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    print_success(f"BD_ADDR changed to {new_addr} via bdaddr")
                    self.add_result({"mode": "bdaddr", "value": new_addr, "success": True,
                                     "method": "bdaddr"})
                    return True
                print_warning(f"bdaddr failed: {r.stderr.strip() or r.stdout.strip()}")
            except Exception as e:
                print_warning(f"bdaddr error: {e}")
        else:
            print_warning("bdaddr tool not installed (apt install bluez-hcidump or build from BlueZ source)")

        # Fall back: try CSR vendor command (OGF=0x3F, OCF=0x0001)
        print_info("Falling back to CSR vendor-specific BD_ADDR write...")
        hci = self._open_hci(iface)
        if not hci:
            return False
        try:
            addr = bytes(int(x, 16) for x in reversed(new_addr.split(":")))
            # CSR PSKEY_BDADDR write template (works on most CSR chips)
            csr_pkt = b"\xc2\x02\x00\x0c\x00\x11G\x03p\x00\x00\x00" + \
                      bytes([addr[2], 0x00, addr[0], addr[1], addr[5], 0x00, addr[3], addr[4]]) + \
                      b"\x00" * 4
            self._hci_cmd(hci, 0x3F, 0x0001, csr_pkt)
            ev = self._wait_event(hci, EVT_CMD_COMPLETE, timeout=5.0)
            if ev and len(ev) >= 4 and ev[3] == 0x00:
                print_success(f"BD_ADDR write accepted (CSR vendor cmd) — restart adapter")
                if restart:
                    self._restart_adapter(iface)
                self.add_result({"mode": "bdaddr", "value": new_addr, "success": True,
                                 "method": "csr_vendor"})
                return True
            print_error("CSR vendor BD_ADDR write rejected — chipset may need a different command")
            print_info("Try: build the bluez 'bdaddr' tool from source for your chipset")
            return False
        finally:
            hci.close()

    def _restart_adapter(self, iface: str):
        try:
            subprocess.run(["hciconfig", iface, "down"], timeout=3)
            time.sleep(0.5)
            subprocess.run(["hciconfig", iface, "up"], timeout=3)
            print_info(f"{iface} restarted")
        except Exception as e:
            print_warning(f"hciconfig restart failed: {e}")

    # ── HCI plumbing ──────────────────────────────────────────────────────

    def _open_hci(self, iface: str) -> Optional[socket.socket]:
        try:
            hci = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
            dev_id = int(iface.replace("hci", ""))
            hci.bind((dev_id,))
            return hci
        except OSError as e:
            print_error(f"HCI open failed on {iface}: {e}")
            return None

    def _hci_cmd(self, hci, ogf, ocf, params=b''):
        opcode = (ogf << 10) | ocf
        pkt = struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params
        hci.setblocking(True); hci.send(pkt); hci.setblocking(False)

    def _wait_event(self, hci, event_code, timeout=5.0) -> Optional[bytes]:
        import select
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([hci], [], [], 0.5)
            if not r:
                continue
            pkt = hci.recv(255)
            if pkt and pkt[0] == HCI_EVENT_PKT and pkt[1] == event_code:
                return pkt[3:]
        return None

    @staticmethod
    def _cmd_exists(cmd: str) -> bool:
        from shutil import which
        return which(cmd) is not None
