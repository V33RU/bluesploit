"""
BlueSploit Module: Full Spectrum Device Scanner
Discover all nearby Bluetooth Classic (BR/EDR) and BLE devices
with signal strength, estimated distance, and vendor information.
"""

import asyncio
import json
import re
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from core.base import (
    BTProtocol, ModuleInfo, ModuleOption,
    ReconModule, Severity, Target,
)
from core.utils.printer import Colors, print_error, print_info, print_success, print_warning

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# ──────────────────────────────────────────────
#  Lookup tables
# ──────────────────────────────────────────────

# BLE company IDs → vendor name
BLE_COMPANY_IDS: Dict[int, str] = {
    0x004C: "Apple",       0x0006: "Microsoft",   0x000F: "Broadcom",
    0x0075: "Samsung",     0x00E0: "Google",       0x0059: "Nordic Semi",
    0x000D: "Texas Instr", 0x0131: "Huawei",       0x0157: "Xiaomi",
    0x038F: "Espressif",   0x0087: "Garmin",       0x00D2: "Fitbit",
    0x0171: "Amazon",      0x0002: "Intel",        0x001D: "Qualcomm",
    0x0822: "Govee",       0x0969: "Tuya",         0x0499: "Ruuvi",
    0x0603: "Sonos",       0x0310: "Wyze",
}

# OUI prefix (first 3 bytes, uppercase colon-sep) → vendor name
OUI_DB: Dict[str, str] = {
    # Apple
    "00:03:93": "Apple",    "00:0A:95": "Apple",    "00:11:24": "Apple",
    "00:14:51": "Apple",    "00:16:CB": "Apple",    "00:19:E3": "Apple",
    "00:1B:63": "Apple",    "00:1C:B3": "Apple",    "00:21:E9": "Apple",
    "00:23:6C": "Apple",    "00:25:BC": "Apple",    "00:26:BB": "Apple",
    "28:CF:DA": "Apple",    "34:C0:59": "Apple",    "3C:15:C2": "Apple",
    "4C:57:CA": "Apple",    "60:C5:47": "Apple",    "70:DE:E2": "Apple",
    "78:31:C1": "Apple",    "80:E6:50": "Apple",    "84:78:8B": "Apple",
    "A4:B1:97": "Apple",    "AC:BC:32": "Apple",    "F4:F9:51": "Apple",
    # Samsung
    "00:00:F0": "Samsung",  "00:07:AB": "Samsung",  "00:12:47": "Samsung",
    "00:15:99": "Samsung",  "00:17:C9": "Samsung",  "00:1A:8A": "Samsung",
    "08:37:3D": "Samsung",  "10:D5:42": "Samsung",  "18:3A:2D": "Samsung",
    "28:CC:01": "Samsung",  "38:01:95": "Samsung",  "60:A1:0A": "Samsung",
    "78:59:5E": "Samsung",  "94:35:0A": "Samsung",
    # Google
    "00:1A:11": "Google",   "3C:5A:B4": "Google",   "54:60:09": "Google",
    "94:EB:2C": "Google",   "F4:F5:D8": "Google",
    # Intel
    "00:02:B3": "Intel",    "00:03:47": "Intel",    "00:0C:F1": "Intel",
    "00:16:6F": "Intel",    "00:1B:21": "Intel",    "00:1D:E0": "Intel",
    # Broadcom
    "00:03:19": "Broadcom", "00:10:18": "Broadcom", "00:1A:2B": "Broadcom",
    # Qualcomm / CSR
    "00:02:5B": "Qualcomm", "00:11:67": "Qualcomm", "00:1A:7D": "Qualcomm",
    # Xiaomi
    "04:CF:8C": "Xiaomi",   "0C:1D:AF": "Xiaomi",   "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",   "64:B4:73": "Xiaomi",   "98:FA:E3": "Xiaomi",
    # Espressif
    "24:0A:C4": "Espr.",    "24:62:AB": "Espr.",    "30:AE:A4": "Espr.",
    "3C:71:BF": "Espr.",    "5C:CF:7F": "Espr.",    "84:CC:A8": "Espr.",
    "A4:CF:12": "Espr.",    "CC:50:E3": "Espr.",    "EC:FA:BC": "Espr.",
    # Nordic Semi
    "D4:36:39": "Nordic",   "F4:CE:36": "Nordic",
    # Huawei
    "00:1E:10": "Huawei",   "00:25:9E": "Huawei",   "0C:37:DC": "Huawei",
    "4C:1F:CC": "Huawei",   "54:89:98": "Huawei",
    # Sony
    "00:01:4A": "Sony",     "00:13:A9": "Sony",     "00:17:9A": "Sony",
    "28:3F:69": "Sony",     "30:17:C8": "Sony",     "90:C1:15": "Sony",
    # Microsoft
    "00:02:44": "Microsoft","00:17:FA": "Microsoft", "28:18:78": "Microsoft",
    "30:59:B7": "Microsoft","60:45:BD": "Microsoft",
}

# Bluetooth Class of Device — major device class
COD_MAJOR: Dict[int, str] = {
    0x01: "Computer",  0x02: "Phone",      0x03: "LAN/Net",
    0x04: "Audio/AV",  0x05: "Peripheral", 0x06: "Imaging",
    0x07: "Wearable",  0x08: "Toy",        0x09: "Health",
}

# Reference TX power at 1 m (dBm) used for distance estimation
_TX_POWER_1M = -59
# Path-loss exponent: 2.0 = free space, 2.7 = typical indoor
_PATH_LOSS_N = 2.7


# ──────────────────────────────────────────────
#  Data model
# ──────────────────────────────────────────────

@dataclass
class Device:
    address: str
    name: Optional[str]     = None
    rssi: Optional[int]     = None
    tx_power: Optional[int] = None
    protocol: str           = "?"          # CLASSIC | BLE | DUAL
    vendor: Optional[str]   = None
    dev_type: Optional[str] = None         # CoD string for classic / "BLE" for LE
    services: List[str]     = field(default_factory=list)


# ──────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────

def _oui_vendor(addr: str) -> Optional[str]:
    return OUI_DB.get(addr.upper()[:8])


def _decode_cod(cod_hex: str) -> str:
    try:
        cod   = int(cod_hex, 16)
        major = (cod >> 8) & 0x1F
        return COD_MAJOR.get(major, "BT Device")
    except Exception:
        return "BT Device"


def _estimate_distance(rssi: int, tx_power: Optional[int] = None) -> float:
    """Estimate distance in metres using log-distance path loss model."""
    ref = tx_power if tx_power is not None else _TX_POWER_1M
    return round(10 ** ((ref - rssi) / (10 * _PATH_LOSS_N)), 1)


def _rssi_bar(rssi: Optional[int]) -> str:
    C = Colors
    if rssi is None:
        return f"{C.DARK_GREY}─────{C.RESET}"
    strength = min(5, max(0, (rssi + 100) // 14))
    bar = "█" * strength + "░" * (5 - strength)
    if strength >= 4:
        return f"{C.GREEN}{bar}{C.RESET}"
    elif strength >= 2:
        return f"{C.YELLOW}{bar}{C.RESET}"
    return f"{C.RED}{bar}{C.RESET}"


# ──────────────────────────────────────────────
#  Module
# ──────────────────────────────────────────────

class Module(ReconModule):
    """
    Full Spectrum Bluetooth Device Scanner

    Runs Classic BR/EDR inquiry (hcitool) and BLE advertisement
    scan (bleak) simultaneously, then presents a unified table
    showing address, vendor, signal strength, estimated distance,
    device type, and protocol for every device found.
    """

    info = ModuleInfo(
        name="recon/device_scan",
        description="Discover all nearby Bluetooth Classic + BLE devices",
        author=["BlueSploit"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
    )

    def _setup_options(self) -> None:
        self.options = {
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Scan duration in seconds",
                default=15,
            ),
            "mode": ModuleOption(
                name="mode",
                required=False,
                description="Protocol: all | ble | classic",
                default="all",
            ),
            "interface": ModuleOption(
                name="interface",
                required=False,
                description="HCI adapter (e.g. hci0)",
                default="hci0",
            ),
            "min_rssi": ModuleOption(
                name="min_rssi",
                required=False,
                description="Ignore BLE devices weaker than this RSSI (e.g. -80)",
                default=None,
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON file",
                default=None,
            ),
        }

    # ── Classic scan ──────────────────────────

    def _scan_classic(self, iface: str, timeout: int) -> List[Device]:
        """Discover BR/EDR devices via hcitool inq + name resolution."""
        found: Dict[str, Device] = {}

        # Inquiry length in 1.28 s units (max 48 = ~61 s)
        inq_units = min(48, max(4, timeout * 100 // 128))

        # Step 1: raw inquiry → addresses + CoD + RSSI
        try:
            r = subprocess.run(
                ["hcitool", "-i", iface, "inq",
                 "--length", str(inq_units), "--numrsp", "255", "--rssi"],
                capture_output=True, text=True, timeout=timeout + 8,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                # format: AA:BB:CC:DD:EE:FF  clock offset: 0x…  class: 0x…  rssi: -NN
                m = re.match(
                    r'([0-9A-Fa-f:]{17})'
                    r'.*?class:\s*(\S+)'
                    r'(?:.*?rssi:\s*(-?\d+))?',
                    line, re.IGNORECASE,
                )
                if m:
                    addr   = m.group(1).upper()
                    cod    = m.group(2)
                    rssi   = int(m.group(3)) if m.group(3) else None
                    found[addr] = Device(
                        address=addr,
                        rssi=rssi,
                        protocol="CLASSIC",
                        vendor=_oui_vendor(addr),
                        dev_type=_decode_cod(cod),
                    )
        except FileNotFoundError:
            print_warning("hcitool not found — Classic scan unavailable (apt install bluez)")
            return []
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        # Step 2: hcitool scan → addresses + names (also catches devices missed by inq)
        try:
            r = subprocess.run(
                ["hcitool", "-i", iface, "scan", "--flush",
                 "--length", str(inq_units)],
                capture_output=True, text=True, timeout=timeout + 8,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                m = re.match(r'([0-9A-Fa-f:]{17})\s+(.*)', line, re.IGNORECASE)
                if m:
                    addr = m.group(1).upper()
                    name = m.group(2).strip() or None
                    if addr in found:
                        found[addr].name = name
                    else:
                        found[addr] = Device(
                            address=addr,
                            name=name,
                            protocol="CLASSIC",
                            vendor=_oui_vendor(addr),
                            dev_type="BT Device",
                        )
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return list(found.values())

    # ── BLE scan ──────────────────────────────

    async def _scan_ble_async(
        self, timeout: int, min_rssi: Optional[int]
    ) -> List[Device]:
        """Collect BLE advertisement packets for `timeout` seconds."""
        found: Dict[str, Device] = {}

        def _callback(dev: "BLEDevice", adv: "AdvertisementData") -> None:
            rssi = adv.rssi if hasattr(adv, "rssi") else None
            if min_rssi is not None and (rssi is None or rssi < min_rssi):
                return

            addr   = dev.address.upper()
            name   = adv.local_name or dev.name or None
            vendor = None
            txp    = adv.tx_power if hasattr(adv, "tx_power") else None

            if adv.manufacturer_data:
                for cid in adv.manufacturer_data:
                    vendor = BLE_COMPANY_IDS.get(cid, f"0x{cid:04X}")
                    break

            if vendor is None:
                vendor = _oui_vendor(addr)

            if addr not in found:
                found[addr] = Device(
                    address=addr,
                    name=name,
                    rssi=rssi,
                    tx_power=txp,
                    protocol="BLE",
                    vendor=vendor,
                    dev_type="BLE",
                    services=list(adv.service_uuids) if adv.service_uuids else [],
                )
            else:
                d = found[addr]
                if rssi is not None and (d.rssi is None or rssi > d.rssi):
                    d.rssi = rssi
                if name and not d.name:
                    d.name = name

        scanner = BleakScanner(detection_callback=_callback)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return list(found.values())

    # ── Merge ─────────────────────────────────

    @staticmethod
    def _merge(classic: List[Device], ble: List[Device]) -> List[Device]:
        merged: Dict[str, Device] = {d.address: d for d in classic}
        for d in ble:
            if d.address in merged:
                merged[d.address].protocol = "DUAL"
                if not merged[d.address].rssi:
                    merged[d.address].rssi = d.rssi
                if not merged[d.address].name:
                    merged[d.address].name = d.name
                if d.services:
                    merged[d.address].services = d.services
            else:
                merged[d.address] = d
        return list(merged.values())

    # ── Output ────────────────────────────────

    def _print_table(self, devices: List[Device]) -> None:
        C = Colors

        proto_order = {"CLASSIC": 0, "DUAL": 1, "BLE": 2}
        rows = sorted(
            devices,
            key=lambda d: (proto_order.get(d.protocol, 3), -(d.rssi or -999)),
        )

        proto_color = {"CLASSIC": C.BLUE, "BLE": C.GREEN, "DUAL": C.CYAN}

        # Column widths
        W = {"#": 4, "PROTO": 8, "BD_ADDRESS": 20, "NAME": 22,
             "VENDOR": 14, "TYPE": 12, "RSSI": 9, "SIGNAL": 7, "DIST": 8}

        sep = "  " + "─" * sum(W.values()) + "─" * (len(W) - 1) * 2

        print(f"\n  {C.CYAN}{'═' * (sum(W.values()) + (len(W)-1)*2 + 2)}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}BLUETOOTH SCAN RESULTS  —  {len(devices)} device(s) found{C.RESET}")
        print(f"  {C.CYAN}{'═' * (sum(W.values()) + (len(W)-1)*2 + 2)}{C.RESET}\n")

        hdr = (
            f"  {C.BOLD}"
            f"{'#':<{W['#']}}"
            f"{'PROTO':<{W['PROTO']}}"
            f"{'BD ADDRESS':<{W['BD_ADDRESS']}}"
            f"{'NAME':<{W['NAME']}}"
            f"{'VENDOR':<{W['VENDOR']}}"
            f"{'TYPE':<{W['TYPE']}}"
            f"{'RSSI':<{W['RSSI']}}"
            f"{'SIGNAL':<{W['SIGNAL']}}"
            f"{'DIST (m)':<{W['DIST']}}"
            f"{C.RESET}"
        )
        print(hdr)
        print(sep)

        for idx, d in enumerate(rows, 1):
            pc = proto_color.get(d.protocol, C.WHITE)

            name = d.name or ""
            name = (name[:20] + "..") if len(name) > 22 else name
            name_col = name or f"{C.DARK_GREY}—{C.RESET}"

            vendor = d.vendor or "—"
            vendor = (vendor[:12] + "..") if len(vendor) > 14 else vendor

            dev_type = d.dev_type or "—"
            dev_type = (dev_type[:10] + "..") if len(dev_type) > 12 else dev_type

            rssi_str   = f"{d.rssi} dBm" if d.rssi is not None else "—"
            signal_bar = _rssi_bar(d.rssi)

            if d.rssi is not None:
                dist = _estimate_distance(d.rssi, d.tx_power)
                dist_str = f"~{dist} m"
                if dist <= 2:
                    dist_col = C.RED
                elif dist <= 8:
                    dist_col = C.YELLOW
                else:
                    dist_col = C.WHITE
                dist_str = f"{dist_col}{dist_str}{C.RESET}"
            else:
                dist_str = f"{C.DARK_GREY}N/A{C.RESET}"

            print(
                f"  {idx:<{W['#']}}"
                f"{pc}{d.protocol:<{W['PROTO']}}{C.RESET}"
                f"{d.address:<{W['BD_ADDRESS']}}"
                f"{name_col:<{W['NAME']}}"
                f"{vendor:<{W['VENDOR']}}"
                f"{dev_type:<{W['TYPE']}}"
                f"{rssi_str:<{W['RSSI']}}"
                f"{signal_bar}  "
                f"{dist_str}"
            )

        print(sep)

        classic_n = sum(1 for d in devices if d.protocol == "CLASSIC")
        ble_n     = sum(1 for d in devices if d.protocol == "BLE")
        dual_n    = sum(1 for d in devices if d.protocol == "DUAL")
        named_n   = sum(1 for d in devices if d.name)

        print(
            f"\n  {C.BOLD}SUMMARY{C.RESET}  "
            f"{C.BLUE}Classic: {classic_n}{C.RESET}  "
            f"{C.GREEN}BLE: {ble_n}{C.RESET}  "
            f"{C.CYAN}Dual-mode: {dual_n}{C.RESET}  "
            f"Named: {named_n}  "
            f"Total: {len(devices)}"
        )
        print(f"  {C.DARK_GREY}Distance is estimated (RSSI-based, ±50% accuracy){C.RESET}")
        print(f"  {C.CYAN}{'═' * (sum(W.values()) + (len(W)-1)*2 + 2)}{C.RESET}\n")

    def _save_json(self, devices: List[Device], path: str) -> None:
        out = {
            "total": len(devices),
            "devices": [
                {
                    "address":    d.address,
                    "name":       d.name,
                    "protocol":   d.protocol,
                    "rssi":       d.rssi,
                    "tx_power":   d.tx_power,
                    "vendor":     d.vendor,
                    "type":       d.dev_type,
                    "services":   d.services,
                    "distance_m": _estimate_distance(d.rssi, d.tx_power) if d.rssi is not None else None,
                }
                for d in devices
            ],
        }
        try:
            with open(path, "w") as f:
                json.dump(out, f, indent=2)
            print_success(f"Saved: {path}")
        except Exception as e:
            print_error(f"Save failed: {e}")

    # ── Entry point ───────────────────────────

    def run(self) -> bool:
        timeout  = int(self.get_option("timeout"))
        mode     = (self.get_option("mode") or "all").lower()
        iface    = self.get_option("interface") or "hci0"
        min_rssi_raw = self.get_option("min_rssi")
        min_rssi = int(min_rssi_raw) if min_rssi_raw is not None else None

        if mode not in ("all", "ble", "classic"):
            print_error("mode must be: all, ble, or classic")
            return False

        C = Colors
        print(f"\n  {C.CYAN}╔{'═'*50}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET}  {C.BOLD}Bluetooth Full Spectrum Scanner{C.RESET}               {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═'*50}╝{C.RESET}")
        print_info(f"Mode     : {mode.upper()}")
        print_info(f"Interface: {iface}")
        print_info(f"Duration : {timeout}s")
        if min_rssi is not None:
            print_info(f"Min RSSI : {min_rssi} dBm")
        print()

        classic_devices: List[Device] = []
        ble_devices:     List[Device] = []

        # Container for Classic thread result
        _classic_result: List[List[Device]] = [[]]

        try:
            # ── Start Classic scan in background thread ──
            if mode in ("all", "classic"):
                def _classic_worker() -> None:
                    print_info(f"{C.BLUE}[Classic]{C.RESET} Inquiry started on {iface}...")
                    _classic_result[0] = self._scan_classic(iface, timeout)

                classic_thread = threading.Thread(target=_classic_worker, daemon=True)
                classic_thread.start()

            # ── BLE scan in main thread (asyncio) ──
            if mode in ("all", "ble"):
                if not BLEAK_AVAILABLE:
                    print_warning("BLE scan skipped — install bleak: pip install bleak")
                else:
                    print_info(f"{C.GREEN}[BLE]{C.RESET}    Advertisement scan started...")
                    try:
                        ble_devices = asyncio.run(
                            self._scan_ble_async(timeout, min_rssi)
                        )
                    except RuntimeError as e:
                        if "running event loop" not in str(e):
                            raise
                        loop = asyncio.get_event_loop()
                        ble_devices = loop.run_until_complete(
                            self._scan_ble_async(timeout, min_rssi)
                        )
                    print_success(f"BLE done  — {len(ble_devices)} device(s)")

            # ── Wait for Classic to finish ──
            if mode in ("all", "classic"):
                classic_thread.join(timeout=timeout + 15)
                classic_devices = _classic_result[0]
                print_success(f"Classic done — {len(classic_devices)} device(s)")

        except KeyboardInterrupt:
            print_warning("\nScan interrupted — showing partial results")

        all_devices = self._merge(classic_devices, ble_devices)

        # Store in framework
        for d in all_devices:
            self.add_device(Target(
                address=d.address,
                name=d.name,
                rssi=d.rssi,
                manufacturer=d.vendor,
            ))
            self.add_result(d)

        self._print_table(all_devices)

        out = self.get_option("output_file")
        if out:
            self._save_json(all_devices, out)

        return len(all_devices) > 0
