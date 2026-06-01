"""
BlueSploit Module: GATT Enumerator
Connects to a BLE device, prints a device-identity header (BD_ADDR, name,
manufacturer, chipset, LL version), then enumerates all GATT services and
characteristics.
"""

import asyncio
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional

from core.base import (
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    ScannerModule,
    Severity,
)
from core.ble_meta import (
    CHIPSET_VENDORS as _CHIPSET_VENDORS,
)
from core.ble_meta import (
    LMP_SUBVER_CHIPSET as _LMP_SUBVER_CHIPSET,
)
from core.ble_meta import (
    MFR_CHIPSET_HINTS as _MFR_CHIPSET_HINTS,
)
from core.ble_meta import (
    OUI_CHIPSET as _OUI_CHIPSET,
)
from core.utils.printer import (
    Colors,
    print_error,
    print_info,
    print_success,
    print_warning,
)

try:
    from bleak import BleakClient
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# ── Well-known GATT service UUIDs ─────────────────────────────────────────────

KNOWN_SERVICES: Dict[str, str] = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001812-0000-1000-8000-00805f9b34fb": "HID Service",
    "00001813-0000-1000-8000-00805f9b34fb": "Scan Parameters",
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": "Nordic UART (NUS)",
}

# ── Well-known characteristic UUIDs ───────────────────────────────────────────

KNOWN_CHARACTERISTICS: Dict[str, str] = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Periph Pref Conn",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a06-0000-1000-8000-00805f9b34fb": "Alert Level",
    "00002a07-0000-1000-8000-00805f9b34fb": "Tx Power Level",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Rev",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Rev",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Rev",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer",
    "00002a2b-0000-1000-8000-00805f9b34fb": "Current Time",
    "00002a50-0000-1000-8000-00805f9b34fb": "PnP ID",
}

# Short UUIDs that feed the device identity block
_IDENTITY_CHARS: Dict[str, str] = {
    "2a00": "device_name",
    "2a23": "system_id",
    "2a24": "model",
    "2a25": "serial",
    "2a26": "firmware",
    "2a27": "hardware",
    "2a28": "software",
    "2a29": "manufacturer",
    "2a50": "pnp_id_raw",
}

def _short_uuid(uuid: str) -> str:
    u = uuid.lower()
    if u.startswith("0000") and u.endswith("-0000-1000-8000-00805f9b34fb"):
        return u[4:8]
    return u[:4] if len(u) == 4 else ""


def _decode_pnp_id(raw: bytes) -> Dict[str, Any]:
    """
    PnP ID (0x2A50): 7 bytes
      B0    vendor_id_source  1=BT SIG  2=USB
      B1-2  vendor_id         little-endian
      B3-4  product_id        little-endian
      B5-6  product_version   little-endian  BCD 0xJJMN → J.M.N
    """
    if len(raw) < 7:
        return {}
    src, vid, pid, ver = struct.unpack_from("<BHHH", raw)
    src_label = "BT SIG" if src == 1 else "USB" if src == 2 else f"src={src}"
    vendor    = _CHIPSET_VENDORS.get(vid, f"0x{vid:04X}")
    major, minor, patch = (ver >> 8) & 0xFF, (ver >> 4) & 0x0F, ver & 0x0F
    return {
        "vendor_id_source": src_label,
        "vendor_id":        vid,
        "vendor_name":      vendor,
        "product_id":       pid,
        "version":          f"{major}.{minor}.{patch}",
        "chipset":          vendor,
    }


def _infer_chipset(manufacturer: Optional[str], addr: str) -> Optional[str]:
    """Infer BLE chipset from manufacturer name string or OUI."""
    if manufacturer:
        mlow = manufacturer.lower()
        for hint, label in _MFR_CHIPSET_HINTS.items():
            if hint in mlow:
                return label
    oui = addr.replace(":", "").upper()[:6]
    return _OUI_CHIPSET.get(oui)


def _parse_hci_version_lines(lines: List[str], info: Dict[str, Any]) -> None:
    """Parse LMP Version / Manufacturer lines from hcitool info or leinfo."""
    for line in lines:
        ls = line.strip()
        if ls.startswith("LMP Version:"):
            m = re.search(r"(\d+\.\d+)\s+\(0x[0-9a-fA-F]+\)\s+LMP Subversion:\s+0x([0-9a-fA-F]+)", ls)
            if m:
                info["lmp_version"]    = m.group(1)
                raw_subver             = int(m.group(2), 16)
                info["lmp_subversion"] = f"0x{raw_subver:04X}"
                # Exact chipset from subversion table
                if raw_subver in _LMP_SUBVER_CHIPSET:
                    info["chipset_exact"] = _LMP_SUBVER_CHIPSET[raw_subver]
        elif ls.startswith("Manufacturer:"):
            info["manufacturer"] = ls.split(":", 1)[1].strip()
        elif ls.startswith("Features:"):
            info["le_features"] = ls.split(":", 1)[1].strip()


def _get_ll_info(addr: str) -> Dict[str, Any]:
    """
    Collect LL/LMP version, manufacturer, device name.

    Priority:
      1. hcitool leinfo , BLE LE connection, reads remote version (needs sudo)
      2. hcitool info   , Classic BR/EDR inquiry (works for Dual devices)
      3. bluetoothctl   , BlueZ cached record (works for any known device)
    """
    info: Dict[str, Any] = {
        "lmp_version": None, "lmp_subversion": None,
        "manufacturer": None, "bt_name": None,
        "appearance": None,   "le_features": None,
        "chipset_exact": None,
    }

    # 1, hcitool leinfo (BLE LE connection)
    try:
        r = subprocess.run(
            ["hcitool", "leinfo", addr],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and "LMP Version" in r.stdout:
            _parse_hci_version_lines(r.stdout.splitlines(), info)
    except Exception:
        pass

    # 2, hcitool info (Classic inquiry, fallback for Dual devices)
    if not info["lmp_version"]:
        try:
            r = subprocess.run(
                ["hcitool", "info", addr],
                capture_output=True, text=True, timeout=8,
            )
            if r.returncode == 0 and "LMP Version" in r.stdout:
                _parse_hci_version_lines(r.stdout.splitlines(), info)
        except Exception:
            pass

    # 3, bluetoothctl info (reads BlueZ cached record, no root needed)
    try:
        r = subprocess.run(
            ["bluetoothctl", "info", addr],
            capture_output=True, text=True, timeout=6,
        )
        for line in r.stdout.splitlines():
            ls = line.strip()
            if ls.startswith("Name:") and not info["bt_name"]:
                info["bt_name"] = ls.split(":", 1)[1].strip()
            elif ls.startswith("Alias:") and not info["bt_name"]:
                info["bt_name"] = ls.split(":", 1)[1].strip()
            elif ls.startswith("Appearance:"):
                info["appearance"] = ls.split(":", 1)[1].strip()
    except Exception:
        pass

    return info


def _read_str(raw: bytes) -> str:
    try:
        return raw.decode("utf-8").strip("\x00").strip()
    except Exception:
        return raw.hex()


# ── Module ────────────────────────────────────────────────────────────────────

class Module(ScannerModule):
    """GATT Service/Characteristic Enumerator with device identity header"""

    info = ModuleInfo(
        name="GATT Enumerator",
        description="Enumerate GATT services and characteristics + device identity (manufacturer, chipset, LL version)",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=["https://www.bluetooth.com/specifications/gatt/"],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)",
            ),
            "timeout": ModuleOption(
                name="timeout", required=False,
                description="Connection timeout in seconds", default=15,
            ),
            "read_values": ModuleOption(
                name="read_values", required=False,
                description="Attempt to read characteristic values", default=True,
            ),
            "output_file": ModuleOption(
                name="output_file", required=False,
                description="Save results to JSON file", default=None,
            ),
        }

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_service_name(self, uuid: str) -> str:
        u = uuid.lower()
        return KNOWN_SERVICES.get(u, f"Vendor 0x{uuid[4:8].upper()}")

    def _get_char_name(self, uuid: str) -> str:
        u = uuid.lower()
        return KNOWN_CHARACTERISTICS.get(u, f"0x{uuid[4:8].upper()}")

    def _format_props(self, props: List[str]) -> str:
        parts = []
        if "read"                  in props: parts.append("R")
        if "write"                 in props: parts.append("W")
        if "write-without-response" in props: parts.append("WNR")
        if "notify"                in props: parts.append("N")
        if "indicate"              in props: parts.append("I")
        return " ".join(parts) if parts else "-"

    def _format_value(self, value: Any, max_len: int = 18) -> str:
        if value is None:
            return "-"
        if isinstance(value, bytes):
            try:
                decoded = value.decode("utf-8").strip("\x00")
                if decoded.isprintable() and decoded:
                    return (decoded[:max_len - 2] + "..") if len(decoded) > max_len else decoded
            except Exception:
                pass
            h = value.hex()
            return ("0x" + h[:max_len - 4] + "..") if len(h) > max_len - 2 else "0x" + h
        return str(value)[:max_len]

    # ── Async enumeration ─────────────────────────────────────────────────────

    async def _enumerate_async(self, address: str) -> Dict[str, Any]:
        timeout     = self.get_option("timeout")
        read_values = self.get_option("read_values")

        identity: Dict[str, Any] = {
            "bd_addr": address.upper(),
            "device_name": None, "manufacturer": None,
            "model": None,       "serial": None,
            "firmware": None,    "hardware": None,
            "software": None,    "system_id": None,
            "pnp":     None,     "chipset":  None,
            "addr_type": None,
            "ll_version": None,  "ll_subversion": None,
            "ll_manufacturer": None,
        }

        results: Dict[str, Any] = {
            "target": address, "identity": identity,
            "services": [], "characteristics": [],
            "stats": {
                "total_services": 0, "total_chars": 0,
                "readable": 0, "writable": 0, "notify": 0,
            },
        }

        # ── Pre-connect: grab adv name + BlueZ cached info ───────────────────
        print_info(f"Scanning for {address} (5s)...")
        try:
            from bleak import BleakScanner as _BS
            adv_dev = await _BS.find_device_by_address(address, timeout=5.0)
            if adv_dev and adv_dev.name:
                identity["device_name"] = adv_dev.name
        except Exception:
            pass

        ll = _get_ll_info(address)
        if ll.get("bt_name") and not identity["device_name"]:
            identity["device_name"] = ll["bt_name"]
        if ll.get("lmp_version"):
            identity["ll_version"]      = ll["lmp_version"]
            identity["ll_subversion"]   = ll.get("lmp_subversion")
            identity["ll_manufacturer"] = ll.get("manufacturer")
        if ll.get("chipset_exact"):
            identity["chipset"] = ll["chipset_exact"]
        if ll.get("appearance"):
            identity.setdefault("appearance", ll["appearance"])

        print_info(f"Connecting to {address}...")

        try:
            async with BleakClient(address, timeout=timeout) as client:
                if not client.is_connected:
                    print_error("Failed to connect")
                    return results

                print_success(f"Connected to {address}")

                # Address type from BlueZ backend
                try:
                    props = client._backend._device_info  # type: ignore
                    identity["addr_type"] = props.get("AddressType")
                except Exception:
                    pass

                print_info("Enumerating GATT services...\n")

                for service in client.services:
                    svc_uuid = str(service.uuid)
                    svc_name = self._get_service_name(svc_uuid)

                    results["stats"]["total_services"] += 1
                    results["services"].append({
                        "uuid": svc_uuid, "name": svc_name,
                        "handle": service.handle,
                        "chars": len(service.characteristics),
                    })

                    for char in service.characteristics:
                        char_uuid = str(char.uuid)
                        char_name = self._get_char_name(char_uuid)
                        props_list = list(char.properties)
                        short      = _short_uuid(char_uuid)

                        results["stats"]["total_chars"] += 1

                        is_read   = "read" in props_list
                        is_write  = "write" in props_list or "write-without-response" in props_list
                        is_notify = "notify" in props_list or "indicate" in props_list

                        if is_read:   results["stats"]["readable"] += 1
                        if is_write:  results["stats"]["writable"] += 1
                        if is_notify: results["stats"]["notify"]   += 1

                        raw_bytes: Optional[bytes] = None
                        value = "-"
                        if read_values and is_read:
                            try:
                                raw_bytes = await client.read_gatt_char(char.uuid)
                                value     = self._format_value(raw_bytes)
                            except Exception:
                                value = "(error)"

                        # ── Capture identity fields ───────────────────────
                        if raw_bytes and short in _IDENTITY_CHARS:
                            field = _IDENTITY_CHARS[short]
                            if field == "pnp_id_raw":
                                pnp = _decode_pnp_id(raw_bytes)
                                if pnp:
                                    identity["pnp"]     = pnp
                                    identity["chipset"] = pnp.get("chipset")
                            else:
                                identity[field] = _read_str(raw_bytes)

                        results["characteristics"].append({
                            "svc_uuid": svc_uuid, "svc_name": svc_name,
                            "uuid": char_uuid,    "name": char_name,
                            "handle": char.handle, "props": props_list,
                            "is_read": is_read,    "is_write": is_write,
                            "is_notify": is_notify, "value": value,
                        })

                print_success("Enumeration complete")

        except asyncio.TimeoutError:
            print_error(f"Timeout after {timeout}s")
        except BleakError as e:
            print_error(f"BLE error: {e}")
        except Exception as e:
            print_error(f"Error: {e}")

        # ── Chipset inference (fallback when no PnP ID) ───────────────────
        if not identity["chipset"]:
            identity["chipset"] = _infer_chipset(
                identity.get("manufacturer"), address
            )
        # Prefer chipset from ll_manufacturer if still nothing
        if not identity["chipset"] and identity.get("ll_manufacturer"):
            identity["chipset"] = identity["ll_manufacturer"]

        return results

    # ── Output ────────────────────────────────────────────────────────────────

    def _print_identity(self, identity: Dict[str, Any]) -> None:
        C = Colors
        print(f"\n  {C.BOLD}DEVICE IDENTITY{C.RESET}")
        print(f"  {C.CYAN}{'─'*75}{C.RESET}")

        def row(label: str, value: Any, color: str = "") -> None:
            if value is None or value == "":
                return
            v = str(value)
            print(f"  {label:<16}: {color}{v}{C.RESET if color else ''}")

        row("BD_ADDR",      identity["bd_addr"],         C.WHITE)
        row("Address Type", identity.get("addr_type"))
        row("Device Name",  identity.get("device_name"), C.GREEN)
        row("Appearance",   identity.get("appearance"))
        row("Manufacturer", identity.get("manufacturer"))
        row("Model",        identity.get("model"))
        row("Serial",       identity.get("serial"))
        row("Firmware",     identity.get("firmware"),  C.YELLOW)
        row("Hardware",     identity.get("hardware"))
        row("Software",     identity.get("software"))

        sys_id = identity.get("system_id")
        if sys_id:
            row("System ID", sys_id)

        pnp = identity.get("pnp")
        if pnp:
            pnp_str = (
                f"VID={pnp['vendor_id_source']} 0x{pnp['vendor_id']:04X} "
                f"({pnp['vendor_name']})  "
                f"PID=0x{pnp['product_id']:04X}  "
                f"Ver={pnp['version']}"
            )
            row("PnP ID", pnp_str)

        chipset = identity.get("chipset")
        if chipset:
            row("Chipset",  chipset, C.CYAN)

        if identity.get("ll_version"):
            ver_str = identity["ll_version"]
            if identity.get("ll_subversion"):
                ver_str += f"  (subver {identity['ll_subversion']})"
            if identity.get("ll_manufacturer"):
                ver_str += f" , {identity['ll_manufacturer']}"
            row("LL/LMP Ver", ver_str, C.CYAN)

        print(f"  {C.CYAN}{'─'*75}{C.RESET}")

    def _print_table(self, results: Dict[str, Any]) -> None:
        C = Colors

        self._print_identity(results.get("identity", {}))

        if not results["characteristics"]:
            print_warning("No characteristics found")
            return

        stats = results["stats"]

        print(f"\n  {C.CYAN}{'='*105}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}GATT ENUMERATION RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*105}{C.RESET}")
        print(f"  Target: {C.WHITE}{results['target']}{C.RESET}\n")

        # Services table
        print(f"  {C.BOLD}SERVICES ({stats['total_services']}){C.RESET}\n")
        print(f"  {C.DARK_GREY}+------+------------------------------------------+----------------------------+--------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<4}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'UUID':<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'NAME':<26}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'CHARS':<6}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+------+------------------------------------------+----------------------------+--------+{C.RESET}")
        for i, s in enumerate(results["services"], 1):
            print(f"  {C.DARK_GREY}|{C.RESET} {i:<4} {C.DARK_GREY}|{C.RESET} {C.CYAN}{s['uuid']:<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {s['name'][:26]:<26} {C.DARK_GREY}|{C.RESET} {s['chars']:<6} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+------+------------------------------------------+----------------------------+--------+{C.RESET}")

        # Characteristics table
        print(f"\n  {C.BOLD}CHARACTERISTICS ({stats['total_chars']}){C.RESET}\n")
        print(f"  {C.DARK_GREY}+-----+------------------------------------------+------------------+----------+--------+--------------------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<3}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'UUID':<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'NAME':<16}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'PROPS':<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'HANDLE':<6}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'VALUE':<18}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+-----+------------------------------------------+------------------+----------+--------+--------------------+{C.RESET}")
        for i, c in enumerate(results["characteristics"], 1):
            props  = self._format_props(c["props"])[:8]
            handle = f"0x{c['handle']:04X}"
            value  = c["value"][:18]
            pc     = C.YELLOW if c["is_write"] else (C.MAGENTA if c["is_notify"] else "")
            print(
                f"  {C.DARK_GREY}|{C.RESET} {i:<3} {C.DARK_GREY}|{C.RESET} "
                f"{C.CYAN}{c['uuid']:<40}{C.RESET} {C.DARK_GREY}|{C.RESET} "
                f"{c['name'][:16]:<16} {C.DARK_GREY}|{C.RESET} "
                f"{pc}{props:<8}{C.RESET} {C.DARK_GREY}|{C.RESET} "
                f"{handle:<6} {C.DARK_GREY}|{C.RESET} "
                f"{C.GREEN}{value:<18}{C.RESET} {C.DARK_GREY}|{C.RESET}"
            )
        print(f"  {C.DARK_GREY}+-----+------------------------------------------+------------------+----------+--------+--------------------+{C.RESET}")

        print(f"\n  {C.DARK_GREY}Props: R=Read  W=Write  WNR=Write-No-Response  N=Notify  I=Indicate{C.RESET}")

        # Summary
        print(f"\n  {C.CYAN}{'-'*105}{C.RESET}")
        print(f"  {C.BOLD}SUMMARY{C.RESET}")
        print(f"  {C.CYAN}{'-'*105}{C.RESET}")
        print(
            f"  Services: {stats['total_services']}   "
            f"Characteristics: {stats['total_chars']}   "
            f"{C.GREEN}Readable: {stats['readable']}{C.RESET}   "
            f"{C.YELLOW}Writable: {stats['writable']}{C.RESET}   "
            f"{C.MAGENTA}Notify: {stats['notify']}{C.RESET}"
        )

        writable = [c for c in results["characteristics"] if c["is_write"]]
        if writable:
            print(f"\n  {C.YELLOW}WRITABLE CHARACTERISTICS (Attack Surface):{C.RESET}")
            for c in writable:
                print(f"    {C.YELLOW}>{C.RESET} {c['uuid']}  [{self._format_props(c['props'])}]  {c['name']}")

        notify = [c for c in results["characteristics"] if c["is_notify"]]
        if notify:
            print(f"\n  {C.MAGENTA}NOTIFY/INDICATE CHARACTERISTICS:{C.RESET}")
            for c in notify:
                print(f"    {C.MAGENTA}>{C.RESET} {c['uuid']}  [{self._format_props(c['props'])}]  {c['name']}")

        print(f"\n  {C.CYAN}{'='*105}{C.RESET}\n")

    def _save_results(self, results: Dict[str, Any], filename: str) -> None:
        import json
        try:
            with open(filename, "w") as f:
                json.dump(results, f, indent=2, default=str)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False

        target = self.target
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        try:
            results = asyncio.run(self._enumerate_async(target))
            self.add_result(results)
            self._print_table(results)

            out = self.get_option("output_file")
            if out:
                self._save_results(results, out)

            return results["stats"]["total_services"] > 0

        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Failed: {e}")
            return False
