"""
BlueSploit Module: Bluetooth Discovery
Full-spectrum passive discovery — Classic BR/EDR + BLE.
No connections. All intelligence extracted from advertisement packets only.

Passive sources used:
  • Manufacturer data   → Apple product ID, Microsoft Swift Pair
  • Service UUIDs       → device class, security flags
  • Service data        → Eddystone-URL / Eddystone-UID beacon content
  • iBeacon payload     → UUID / Major / Minor / TX power
  • BLE flags byte      → discoverable mode, BR/EDR support
  • RSSI rolling avg    → stable distance estimate
"""

import asyncio
import json
import re
import subprocess
import threading
import uuid as _uuid_mod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

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


# ── Lookup tables ─────────────────────────────────────────────────────────────

BLE_COMPANY_IDS: Dict[int, str] = {
    0x004C: "Apple",        0x0006: "Microsoft",    0x000F: "Broadcom",
    0x0075: "Samsung",      0x00E0: "Google",        0x0059: "Nordic Semi",
    0x000D: "Texas Instr",  0x0131: "Huawei",        0x0157: "Xiaomi",
    0x038F: "Espressif",    0x0087: "Garmin",        0x00D2: "Fitbit",
    0x0171: "Amazon",       0x0002: "Intel",         0x001D: "Qualcomm",
    0x0822: "Govee",        0x0969: "Tuya",          0x0499: "Ruuvi",
    0x0603: "Sonos",        0x0310: "Wyze",          0x04F7: "Tile",
    0x03DA: "Bose",         0x001A: "Nokia",         0x012D: "Jabra",
    0x054C: "Sony",         0x008A: "LG Elec.",
}

OUI_DB: Dict[str, str] = {
    "00:03:93": "Apple",    "00:0A:95": "Apple",    "00:11:24": "Apple",
    "00:14:51": "Apple",    "00:16:CB": "Apple",    "00:19:E3": "Apple",
    "00:1B:63": "Apple",    "00:1C:B3": "Apple",    "00:21:E9": "Apple",
    "00:23:6C": "Apple",    "00:25:BC": "Apple",    "00:26:BB": "Apple",
    "28:CF:DA": "Apple",    "34:C0:59": "Apple",    "3C:15:C2": "Apple",
    "4C:57:CA": "Apple",    "60:C5:47": "Apple",    "70:DE:E2": "Apple",
    "78:31:C1": "Apple",    "80:E6:50": "Apple",    "84:78:8B": "Apple",
    "A4:B1:97": "Apple",    "AC:BC:32": "Apple",    "F4:F9:51": "Apple",
    "DC:A4:CA": "Apple",    "B8:09:8A": "Apple",    "E0:B9:BA": "Apple",
    "00:00:F0": "Samsung",  "00:07:AB": "Samsung",  "00:12:47": "Samsung",
    "00:15:99": "Samsung",  "00:17:C9": "Samsung",  "00:1A:8A": "Samsung",
    "08:37:3D": "Samsung",  "10:D5:42": "Samsung",  "18:3A:2D": "Samsung",
    "28:CC:01": "Samsung",  "38:01:95": "Samsung",  "60:A1:0A": "Samsung",
    "78:59:5E": "Samsung",  "94:35:0A": "Samsung",  "2C:AE:2B": "Samsung",
    "00:1A:11": "Google",   "3C:5A:B4": "Google",   "54:60:09": "Google",
    "94:EB:2C": "Google",   "F4:F5:D8": "Google",   "1C:F2:9A": "Google",
    "00:02:B3": "Intel",    "00:03:47": "Intel",    "00:0C:F1": "Intel",
    "00:16:6F": "Intel",    "00:1B:21": "Intel",    "00:1D:E0": "Intel",
    "00:03:19": "Broadcom", "00:10:18": "Broadcom", "00:1A:2B": "Broadcom",
    "00:02:5B": "Qualcomm", "00:11:67": "Qualcomm", "00:1A:7D": "Qualcomm",
    "04:CF:8C": "Xiaomi",   "0C:1D:AF": "Xiaomi",   "28:6C:07": "Xiaomi",
    "64:09:80": "Xiaomi",   "64:B4:73": "Xiaomi",   "98:FA:E3": "Xiaomi",
    "58:44:98": "Xiaomi",   "74:23:44": "Xiaomi",   "F0:B4:29": "Xiaomi",
    "24:0A:C4": "Espressif","24:62:AB": "Espressif","30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif","5C:CF:7F": "Espressif","84:CC:A8": "Espressif",
    "A4:CF:12": "Espressif","CC:50:E3": "Espressif","EC:FA:BC": "Espressif",
    "08:3A:F2": "Espressif","10:52:1C": "Espressif",
    "D4:36:39": "Nordic",   "F4:CE:36": "Nordic",
    "00:1E:10": "Huawei",   "00:25:9E": "Huawei",   "0C:37:DC": "Huawei",
    "4C:1F:CC": "Huawei",   "54:89:98": "Huawei",   "E0:19:1D": "Huawei",
    "00:01:4A": "Sony",     "00:13:A9": "Sony",     "28:3F:69": "Sony",
    "90:C1:15": "Sony",     "00:17:9A": "Sony",     "30:17:C8": "Sony",
    "00:02:44": "Microsoft","00:17:FA": "Microsoft", "28:18:78": "Microsoft",
    "30:59:B7": "Microsoft","60:45:BD": "Microsoft",
    "04:52:C7": "Bose",     "88:DF:9E": "Bose",
    "50:C2:ED": "Jabra",    "A0:E9:DB": "Jabra",
    "30:91:8F": "Tile",
    "00:12:4B": "TI",       "18:EE:69": "TI",
    "40:B4:CD": "Amazon",   "68:54:FD": "Amazon",
    "74:75:48": "Amazon",   "FC:65:DE": "Amazon",
}

COD_MAJOR: Dict[int, str] = {
    0x01: "Computer",  0x02: "Phone",    0x03: "LAN/Net",
    0x04: "Audio/AV",  0x05: "HID",      0x06: "Imaging",
    0x07: "Wearable",  0x08: "Toy",      0x09: "Health",
}

SERVICE_CLASS_MAP: Dict[str, str] = {
    "1108": "Headset",      "110b": "AudioSink",    "110a": "AudioSource",
    "111e": "Handsfree",    "110d": "A2DP",         "110c": "AVRCP",
    "1812": "HID",
    "180d": "HeartRate",    "1810": "BloodPress",   "1809": "Thermometer",
    "181a": "EnvSensor",    "1816": "CycleSpeed",   "1818": "CyclingPwr",
    "1826": "FitMachine",   "1814": "Running",      "181c": "UserData",
    "1116": "NAP",          "1115": "PANU",
    "180a": "DevInfo",      "180f": "Battery",
    "fe59": "DFU",
    "fddf": "MeshProv",     "fdd9": "MeshProxy",
    "1802": "Proximity",    "1803": "LinkLoss",     "1804": "TxPower",
    "fe95": "Xiaomi IoT",   "fcd9": "Tuya IoT",
    "fd6f": "Apple FindMy", "fd44": "AirTag",
    "fe2c": "FastPair",     "fef3": "GoogleNearby",
    "feaa": "Eddystone",
}

RISKY_SERVICES: Set[str] = {"fe59", "1812", "fddf", "fdd9"}

APPLE_MFR_TYPES: Dict[tuple, str] = {
    (0x02, 0x15): "iBeacon",
    (0x10, 0x05): "AirPods",
    (0x10, 0x06): "AirPods Pro",
    (0x10, 0x0E): "AirPods Max",
    (0x10, 0x0C): "AirPods 3",
    (0x10, 0x14): "AirPods Pro2",
    (0x10, 0x20): "AirPods 4",
    (0x10, 0x24): "AirPods Pro2",
    (0x0B, None): "Apple Watch",
    (0x0F, None): "FindMy Tag",
    (0x07, None): "iPhone/Mac",
    (0x08, None): "Handoff",
    (0x09, None): "iOS Nearby",
    (0x01, None): "AirPrint",
    (0x03, None): "AirPlay",
    (0x06, None): "AppleTV",
    (0x0D, None): "HomeKit",
}

# Eddystone-URL scheme prefixes
_ES_SCHEMES = {
    0x00: "http://www.", 0x01: "https://www.",
    0x02: "http://",     0x03: "https://",
}
# Eddystone-URL encoded suffixes
_ES_SUFFIXES = {
    0x00: ".com/",  0x01: ".org/",  0x02: ".edu/",
    0x03: ".net/",  0x04: ".info/", 0x05: ".biz/",
    0x06: ".gov/",  0x07: ".com",   0x08: ".org",
    0x09: ".edu",   0x0A: ".net",   0x0B: ".info",
    0x0C: ".biz",   0x0D: ".gov",
}

_TX_POWER_1M  = -59
_PATH_LOSS_N  = 2.7
_RSSI_BUF_LEN = 6


# ── Passive parsers ───────────────────────────────────────────────────────────

def _oui_vendor(addr: str) -> Optional[str]:
    return OUI_DB.get(addr.upper()[:8])


def _decode_cod(cod_hex: str) -> str:
    try:
        cod   = int(cod_hex, 16)
        major = (cod >> 8) & 0x1F
        label = COD_MAJOR.get(major, "BT Device")
        if ((cod >> 13) & 0x7FF) & 0x20:
            label += "/Audio"
        return label
    except Exception:
        return "BT Device"


def _extract_short_uuid(uuid: str) -> str:
    u = uuid.lower()
    if u.startswith("0000") and u.endswith("-0000-1000-8000-00805f9b34fb"):
        return u[4:8]
    if len(u) == 4:
        return u
    return ""


def _short_uuids(services: List[str]) -> Set[str]:
    return {s for raw in services if (s := _extract_short_uuid(raw))}


def _detect_apple(mfr_bytes: bytes) -> Optional[str]:
    """Identify Apple product from manufacturer data payload."""
    if len(mfr_bytes) < 2:
        return None
    t, s = mfr_bytes[0], mfr_bytes[1]
    if (t, s) in APPLE_MFR_TYPES:
        return APPLE_MFR_TYPES[(t, s)]
    if (t, None) in APPLE_MFR_TYPES:
        return APPLE_MFR_TYPES[(t, None)]
    return f"Apple ({t:#04x})"


def _parse_ibeacon(mfr_bytes: bytes) -> Optional[str]:
    """
    Parse iBeacon payload from Apple manufacturer data.
    Returns 'UUID  Maj:N  Min:N  TX:-NN' or None.
    """
    if len(mfr_bytes) < 23 or mfr_bytes[0] != 0x02 or mfr_bytes[1] != 0x15:
        return None
    try:
        proximity_uuid = str(_uuid_mod.UUID(bytes=bytes(mfr_bytes[2:18]))).upper()
        major    = (mfr_bytes[18] << 8) | mfr_bytes[19]
        minor    = (mfr_bytes[20] << 8) | mfr_bytes[21]
        tx_power = mfr_bytes[22] if mfr_bytes[22] < 128 else mfr_bytes[22] - 256
        return f"{proximity_uuid}  Maj:{major}  Min:{minor}  TX:{tx_power:+d}dBm"
    except Exception:
        return None


def _decode_eddystone_url(payload: bytes) -> Optional[str]:
    """Decode an Eddystone-URL frame into a URL string."""
    if len(payload) < 3:
        return None
    scheme = _ES_SCHEMES.get(payload[2], "?://")
    url = scheme
    for b in payload[3:]:
        url += _ES_SUFFIXES.get(b, chr(b) if 0x20 <= b <= 0x7E else "")
    return url


def _parse_eddystone(service_data: Dict[str, bytes]) -> Optional[Tuple[str, str]]:
    """
    Parse Eddystone service data.
    Returns (frame_label, content_string) or None.
    """
    for key, payload in service_data.items():
        if "feaa" not in key.lower():
            continue
        if not payload:
            continue
        frame = payload[0]
        if frame == 0x10:                        # Eddystone-URL
            url = _decode_eddystone_url(payload)
            if url:
                return ("Eddystone-URL", url)
        elif frame == 0x00 and len(payload) >= 18:  # Eddystone-UID
            ns  = payload[2:12].hex().upper()
            ins = payload[12:18].hex().upper()
            return ("Eddystone-UID", f"NS:{ns}  Inst:{ins}")
        elif frame == 0x20:                      # Eddystone-TLM (telemetry)
            return ("Eddystone-TLM", "telemetry beacon")
    return None


def _classify_ble(
    services: List[str],
    vendor: Optional[str],
    mfr_data: Dict[int, bytes],
    service_data: Dict[str, bytes],
) -> Tuple[str, bool, Optional[str]]:
    """
    Return (class_label, is_risky, extra_info).
    All derived from passive advertisement data — no connections.
    """
    extra: Optional[str] = None

    # ── Apple products ──────────────────────────────────────────────────────
    if 0x004C in mfr_data:
        raw    = mfr_data[0x004C]
        label  = _detect_apple(raw) or "Apple Device"
        if label == "iBeacon":
            extra = _parse_ibeacon(raw)
        return label, False, extra

    # ── Microsoft Swift Pair ────────────────────────────────────────────────
    if 0x0006 in mfr_data and mfr_data[0x0006][:1] == b'\x06':
        return "SwiftPair", False, None

    # ── Eddystone beacons (via service data) ────────────────────────────────
    if service_data:
        es = _parse_eddystone(service_data)
        if es:
            return es[0], False, es[1]

    # ── BLE service UUID classification ────────────────────────────────────
    shorts = _short_uuids(services)
    risky  = bool(shorts & RISKY_SERVICES)

    for svc, label in SERVICE_CLASS_MAP.items():
        if svc in shorts:
            return label, risky, extra

    # ── Vendor-based hints ──────────────────────────────────────────────────
    if vendor == "Tile":
        return "Tracker", False, None
    if vendor == "Ruuvi":
        return "EnvSensor", False, None

    return "—", risky, extra


def _smooth_rssi(buf: List[int], new_rssi: int) -> int:
    buf.append(new_rssi)
    if len(buf) > _RSSI_BUF_LEN:
        buf.pop(0)
    return int(sum(buf) / len(buf))


def _estimate_distance(rssi: int, tx_power: Optional[int] = None) -> float:
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


# Strip ANSI escape codes to measure visible character width
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _vis(s: str) -> int:
    """Return the number of visible (non-ANSI) characters in string s."""
    return len(_ANSI_RE.sub('', s))


def _cpad(s: str, w: int) -> str:
    """Left-pad string s to visible width w, ignoring ANSI escape codes."""
    return s + ' ' * max(0, w - _vis(s))


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Device:
    address:     str
    name:        Optional[str]   = None
    rssi:        Optional[int]   = None
    tx_power:    Optional[int]   = None
    protocol:    str             = "?"
    vendor:      Optional[str]   = None
    dev_class:   Optional[str]   = None     # e.g. AirPods Pro, HeartRate, DFU
    services:    List[str]       = field(default_factory=list)
    risky:       bool            = False
    addr_type:   str             = "?"      # public | random
    connectable: bool            = False
    extra_info:  Optional[str]   = None     # iBeacon UUID, Eddystone URL, etc.
    _rssi_buf:   List[int]       = field(default_factory=list, repr=False)


# ── Module ────────────────────────────────────────────────────────────────────

class Module(ReconModule):
    """
    Full-Spectrum Bluetooth Discovery Scanner (passive only — no connections)

    Extracts from raw advertisement packets:
      • Apple product type  (manufacturer data byte-pattern matching)
      • iBeacon UUID / Major / Minor / TX power
      • Eddystone-URL  (decodes the full beacon URL)
      • Eddystone-UID  (namespace + instance)
      • Device class from BLE service UUIDs
      • Security flags: DFU / HID / Mesh Provisioning
      • RSSI 6-sample rolling average → stable distance
      • BLE address type (public / random)
      • Microsoft Swift Pair
    """

    info = ModuleInfo(
        name="recon/discovery",
        description="Passive full-spectrum Bluetooth discovery — Classic + BLE",
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
                description="Ignore BLE devices below this RSSI (e.g. -85)",
                default=None,
            ),
            "live": ModuleOption(
                name="live",
                required=False,
                description="Print each new device as it is discovered",
                default=True,
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON",
                default=None,
            ),
        }

    # ── Classic BR/EDR scan ───────────────────────────────────────────────────

    def _scan_classic(self, iface: str, timeout: int) -> List[Device]:
        found: Dict[str, Device] = {}
        inq_units = min(48, max(4, timeout * 100 // 128))

        try:
            r = subprocess.run(
                ["hcitool", "-i", iface, "inq",
                 "--length", str(inq_units), "--numrsp", "255", "--rssi"],
                capture_output=True, text=True, timeout=timeout + 8,
            )
            for line in r.stdout.splitlines():
                m = re.match(
                    r'([0-9A-Fa-f:]{17}).*?class:\s*(\S+)'
                    r'(?:.*?rssi:\s*(-?\d+))?',
                    line.strip(), re.IGNORECASE,
                )
                if m:
                    addr = m.group(1).upper()
                    cod  = m.group(2)
                    rssi = int(m.group(3)) if m.group(3) else None
                    found[addr] = Device(
                        address=addr, rssi=rssi,
                        protocol="CLASSIC",
                        vendor=_oui_vendor(addr),
                        dev_class=_decode_cod(cod),
                    )
        except FileNotFoundError:
            print_warning("hcitool not found — Classic scan skipped (apt install bluez)")
            return []
        except (subprocess.TimeoutExpired, Exception):
            pass

        try:
            r = subprocess.run(
                ["hcitool", "-i", iface, "scan", "--flush",
                 "--length", str(inq_units)],
                capture_output=True, text=True, timeout=timeout + 8,
            )
            for line in r.stdout.splitlines():
                m = re.match(r'([0-9A-Fa-f:]{17})\s+(.*)', line.strip(), re.IGNORECASE)
                if m:
                    addr = m.group(1).upper()
                    name = m.group(2).strip() or None
                    if addr in found:
                        found[addr].name = name
                    else:
                        found[addr] = Device(
                            address=addr, name=name,
                            protocol="CLASSIC",
                            vendor=_oui_vendor(addr),
                            dev_class="BT Device",
                        )
        except (subprocess.TimeoutExpired, Exception):
            pass

        return list(found.values())

    # ── Column widths (single source of truth) ───────────────────────────────

    _W = {
        "#":       4,   # row number / risky flag
        "PROTO":   8,   # BLE / BR/EDR / DUAL
        "ADDRESS": 20,  # BD_ADDR
        "NAME":    22,  # device name
        "CLASS":   16,  # classification
        "VENDOR":  13,  # manufacturer
        "RSSI":    9,   # dBm value
        "SIGNAL":  7,   # 5-bar + 2 spaces (always 7 visible)
        "DIST":    9,   # estimated distance
    }

    # ── Shared row formatter ──────────────────────────────────────────────────

    def _format_row(self, idx: int, d: Device) -> str:
        """
        Format one device as a fixed-width table row.
        Uses _cpad() on every colored cell so ANSI codes never break alignment.
        """
        C  = Colors
        W  = self._W
        pc = {"CLASSIC": C.BLUE, "BLE": C.GREEN, "DUAL": C.CYAN}.get(d.protocol, C.WHITE)

        # # ── index / risky marker (width 4)
        col_idx = _cpad(
            f"{C.RED}{idx:<3}!{C.RESET}" if d.risky else f"{idx}",
            W["#"]
        )

        # PROTO (width 8)
        col_proto = _cpad(f"{pc}{d.protocol}{C.RESET}", W["PROTO"])

        # ADDRESS (width 20) — always plain, :<N> is safe
        col_addr = f"{d.address:<{W['ADDRESS']}}"

        # NAME (width 22) — pad PLAIN string, then colorize
        name_raw = d.name or ""
        name_raw = (name_raw[:20] + "..") if len(name_raw) > 22 else name_raw
        col_name = (
            _cpad(f"{C.DARK_GREY}—{C.RESET}", W["NAME"])
            if not d.name
            else f"{name_raw:<{W['NAME']}}"
        )

        # CLASS (width 16) — prefix with "! " when risky, then _cpad
        cls_raw  = (d.dev_class or "—")
        cls_raw  = (cls_raw[:13] + "..") if len(cls_raw) > 15 else cls_raw
        col_class = (
            _cpad(f"{C.RED}! {cls_raw}{C.RESET}", W["CLASS"])
            if d.risky
            else f"{cls_raw:<{W['CLASS']}}"
        )

        # VENDOR (width 13) — always plain
        vendor = (d.vendor or "—")
        vendor = (vendor[:11] + "..") if len(vendor) > 13 else vendor
        col_vendor = f"{vendor:<{W['VENDOR']}}"

        # RSSI (width 9) — always plain
        rssi_str  = f"{d.rssi} dBm" if d.rssi is not None else "—"
        col_rssi  = f"{rssi_str:<{W['RSSI']}}"

        # SIGNAL (7) — _rssi_bar always returns exactly 5 visible chars
        col_signal = _rssi_bar(d.rssi) + "  "

        # DIST (9) — _cpad handles the color codes
        if d.rssi is not None:
            dist  = _estimate_distance(d.rssi, d.tx_power)
            dcol  = C.RED if dist <= 2 else (C.YELLOW if dist <= 10 else C.WHITE)
            col_dist = _cpad(f"{dcol}~{dist} m{C.RESET}", W["DIST"])
        else:
            col_dist = _cpad(f"{C.DARK_GREY}N/A{C.RESET}", W["DIST"])

        return (
            f"  {col_idx}{col_proto}{col_addr}{col_name}"
            f"{col_class}{col_vendor}{col_rssi}{col_signal}{col_dist}"
        )

    def _table_header(self) -> str:
        W = self._W
        C = Colors
        return (
            f"  {C.BOLD}"
            f"{'#':<{W['#']}}{'PROTO':<{W['PROTO']}}{'BD ADDRESS':<{W['ADDRESS']}}"
            f"{'NAME':<{W['NAME']}}{'CLASS':<{W['CLASS']}}{'VENDOR':<{W['VENDOR']}}"
            f"{'RSSI':<{W['RSSI']}}{'SIGNAL':<{W['SIGNAL']}}{'DIST (m)':<{W['DIST']}}"
            f"{C.RESET}"
        )

    def _separator(self) -> str:
        return "  " + "─" * sum(self._W.values())

    # ── Live output ───────────────────────────────────────────────────────────

    def _live_print(self, idx: int, d: Device) -> None:
        """Print one table row for a newly found device (during scanning)."""
        print(self._format_row(idx, d))
        if d.extra_info:
            C    = Colors
            info = d.extra_info[:88] + ".." if len(d.extra_info) > 90 else d.extra_info
            indent = " " * (self._W["#"] + self._W["PROTO"] + self._W["ADDRESS"] + 2)
            print(f"  {indent}{C.DARK_GREY}-> {info}{C.RESET}")

    async def _scan_ble_async(
        self, timeout: int, min_rssi: Optional[int], live: bool
    ) -> List[Device]:
        found: Dict[str, Device] = {}

        def _callback(dev: "BLEDevice", adv: "AdvertisementData") -> None:
            rssi = adv.rssi if hasattr(adv, "rssi") else None
            if min_rssi is not None and (rssi is None or rssi < min_rssi):
                return

            addr         = dev.address.upper()
            name         = adv.local_name or dev.name or None
            txp          = adv.tx_power if hasattr(adv, "tx_power") else None
            mfr_data     = dict(adv.manufacturer_data) if adv.manufacturer_data else {}
            services     = list(adv.service_uuids) if adv.service_uuids else []
            service_data = dict(adv.service_data)  if hasattr(adv, "service_data") and adv.service_data else {}

            # Vendor
            vendor = None
            for cid in mfr_data:
                vendor = BLE_COMPANY_IDS.get(cid, f"0x{cid:04X}")
                break
            if vendor is None:
                vendor = _oui_vendor(addr)

            # Classify from passive adv data
            dev_class, risky, extra = _classify_ble(services, vendor, mfr_data, service_data)

            # Address type (BlueZ backend)
            addr_type = "?"
            try:
                addr_type = dev.details.get("AddressType", "?")
            except Exception:
                pass

            connectable = bool(getattr(adv, "connectable", False))

            is_new = addr not in found
            if is_new:
                buf: List[int] = []
                smooth = _smooth_rssi(buf, rssi) if rssi is not None else None
                found[addr] = Device(
                    address=addr, name=name,
                    rssi=smooth, tx_power=txp,
                    protocol="BLE",
                    vendor=vendor, dev_class=dev_class,
                    services=services, risky=risky,
                    addr_type=addr_type, connectable=connectable,
                    extra_info=extra, _rssi_buf=buf,
                )
                if live:
                    self._live_print(len(found), found[addr])
            else:
                d = found[addr]
                if rssi is not None:
                    d.rssi = _smooth_rssi(d._rssi_buf, rssi)
                if name and not d.name:
                    d.name = name
                if services and not d.services:
                    d.services = services
                    new_cls, new_risky, new_extra = _classify_ble(
                        services, d.vendor, mfr_data, service_data
                    )
                    if new_cls != "—":
                        d.dev_class = new_cls
                    d.risky = d.risky or new_risky
                    if new_extra and not d.extra_info:
                        d.extra_info = new_extra

        scanner = BleakScanner(detection_callback=_callback)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return list(found.values())

    # ── Merge ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _merge(classic: List[Device], ble: List[Device]) -> List[Device]:
        merged: Dict[str, Device] = {d.address: d for d in classic}
        for d in ble:
            if d.address in merged:
                m = merged[d.address]
                m.protocol  = "DUAL"
                m.risky     = m.risky or d.risky
                if not m.rssi and d.rssi:   m.rssi      = d.rssi
                if not m.name and d.name:   m.name      = d.name
                if d.services:              m.services  = d.services
                if d.dev_class and d.dev_class != "—":
                    m.dev_class = d.dev_class
                if d.extra_info and not m.extra_info:
                    m.extra_info = d.extra_info
            else:
                merged[d.address] = d
        return list(merged.values())

    # ── Summary table ─────────────────────────────────────────────────────────

    def _print_table(self, devices: List[Device], rows_already_shown: bool = False) -> None:
        """
        Print the BLUETOOTH DISCOVERY summary.

        If `rows_already_shown` is True (live mode), skip the redundant per-device
        rows — they were already printed during scanning — and emit only the
        banner + summary footer.
        """
        C       = Colors
        total_w = sum(self._W.values())
        sep     = self._separator()

        risky_n   = sum(1 for d in devices if d.risky)
        classic_n = sum(1 for d in devices if d.protocol == "CLASSIC")
        ble_n     = sum(1 for d in devices if d.protocol == "BLE")
        dual_n    = sum(1 for d in devices if d.protocol == "DUAL")
        named_n   = sum(1 for d in devices if d.name)

        if not rows_already_shown:
            rows = sorted(
                devices,
                key=lambda d: (
                    {"CLASSIC": 0, "DUAL": 1, "BLE": 2}.get(d.protocol, 3),
                    0 if d.risky else 1,
                    -(d.rssi or -999),
                ),
            )
            print(f"\n  {C.CYAN}{'═'*(total_w+2)}{C.RESET}")
            print(
                f"  {C.BOLD}{C.WHITE}BLUETOOTH DISCOVERY  —  {len(devices)} device(s) found"
                + (f"  {C.RED}[ {risky_n} RISKY ]{C.WHITE}" if risky_n else "")
                + C.RESET
            )
            print(f"  {C.CYAN}{'═'*(total_w+2)}{C.RESET}\n")
            print(self._table_header())
            print(sep)
            for idx, d in enumerate(rows, 1):
                print(self._format_row(idx, d))
                if d.extra_info:
                    indent = " " * (self._W["#"] + self._W["PROTO"] + self._W["ADDRESS"] + 2)
                    info   = d.extra_info[:88] + ".." if len(d.extra_info) > 90 else d.extra_info
                    print(f"  {indent}{C.DARK_GREY}-> {info}{C.RESET}")
            print(sep)

        print(
            f"\n  {C.BOLD}SUMMARY{C.RESET}  "
            f"{C.BLUE}Classic: {classic_n}{C.RESET}  "
            f"{C.GREEN}BLE: {ble_n}{C.RESET}  "
            f"{C.CYAN}Dual: {dual_n}{C.RESET}  "
            f"Named: {named_n}  Total: {len(devices)}"
            + (f"  {C.RED}Risky: {risky_n}{C.RESET}" if risky_n else "")
        )
        print(f"  {C.DARK_GREY}Distance: RSSI path-loss estimate  |  ! = DFU/HID/MeshProv attack surface{C.RESET}")
        print(f"  {C.CYAN}{'═'*(total_w+2)}{C.RESET}\n")

    # ── JSON export ───────────────────────────────────────────────────────────

    def _save_json(self, devices: List[Device], path: str) -> None:
        out = {
            "total": len(devices),
            "risky": sum(1 for d in devices if d.risky),
            "devices": [
                {
                    "address":     d.address,
                    "name":        d.name,
                    "protocol":    d.protocol,
                    "rssi":        d.rssi,
                    "tx_power":    d.tx_power,
                    "vendor":      d.vendor,
                    "class":       d.dev_class,
                    "services":    d.services,
                    "risky":       d.risky,
                    "addr_type":   d.addr_type,
                    "connectable": d.connectable,
                    "extra_info":  d.extra_info,
                    "distance_m":  (
                        _estimate_distance(d.rssi, d.tx_power)
                        if d.rssi is not None else None
                    ),
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

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> bool:
        timeout      = int(self.get_option("timeout"))
        mode         = (self.get_option("mode") or "all").lower()
        iface        = self.get_option("interface") or "hci0"
        min_rssi_raw = self.get_option("min_rssi")
        min_rssi     = int(min_rssi_raw) if min_rssi_raw is not None else None
        live         = bool(self.get_option("live"))

        if mode not in ("all", "ble", "classic"):
            print_error("mode must be: all | ble | classic")
            return False

        C = Colors
        print(f"\n  {C.CYAN}╔{'═'*52}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET}  {C.BOLD}Bluetooth Discovery Scanner{C.RESET}                      {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═'*52}╝{C.RESET}")
        print_info(f"Mode: {mode.upper()}  |  Interface: {iface}  |  Duration: {timeout}s")
        if min_rssi is not None:
            print_info(f"Min RSSI: {min_rssi} dBm")
        print()

        if live and mode in ("all", "ble"):
            print_info("Live feed — new devices as discovered:\n")
            print(self._table_header())
            print(self._separator())

        classic_devices: List[Device] = []
        ble_devices:     List[Device] = []
        _classic_result: List[List[Device]] = [[]]

        try:
            if mode in ("all", "classic"):
                def _classic_worker() -> None:
                    print_info(f"{C.BLUE}[BR/EDR]{C.RESET} Inquiry on {iface}...")
                    _classic_result[0] = self._scan_classic(iface, timeout)

                classic_thread = threading.Thread(target=_classic_worker, daemon=True)
                classic_thread.start()

            if mode in ("all", "ble"):
                if not BLEAK_AVAILABLE:
                    print_warning("BLE scan skipped — pip install bleak")
                else:
                    try:
                        ble_devices = asyncio.run(
                            self._scan_ble_async(timeout, min_rssi, live)
                        )
                    except RuntimeError as e:
                        if "running event loop" not in str(e):
                            raise
                        loop = asyncio.get_event_loop()
                        ble_devices = loop.run_until_complete(
                            self._scan_ble_async(timeout, min_rssi, live)
                        )
                    print_success(f"\nBLE done — {len(ble_devices)} device(s)")

            if mode in ("all", "classic"):
                classic_thread.join(timeout=timeout + 15)
                classic_devices = _classic_result[0]
                print_success(f"BR/EDR done — {len(classic_devices)} device(s)")

        except KeyboardInterrupt:
            print_warning("\nInterrupted — showing partial results")

        all_devices = self._merge(classic_devices, ble_devices)

        for d in all_devices:
            self.add_device(Target(
                address=d.address, name=d.name,
                rssi=d.rssi, manufacturer=d.vendor,
            ))
            self.add_result(d)

        print()
        # When live mode is on, the per-device rows were already streamed —
        # avoid printing them again and only show the summary footer.
        rows_already_shown = bool(live and mode in ("all", "ble"))
        self._print_table(all_devices, rows_already_shown=rows_already_shown)

        out = self.get_option("output_file")
        if out:
            self._save_json(all_devices, out)

        return len(all_devices) > 0
