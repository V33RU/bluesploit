"""
BlueSploit Module: BLE Advertisement Parser
Deep passive analysis of BLE advertisement packets, no connections required.

Decodes:
  • Apple Continuity , iBeacon, AirPods (model + battery + in-ear), Nearby Info
                        (iOS version + status), Handoff, FindMy/AirTag, HomeKit,
                        AirDrop, AirPlay, Apple Watch
  • Eddystone       , URL (full decode), UID (namespace + instance), TLM
  • iBeacon         , UUID / Major / Minor / TX power
  • Microsoft       , Swift Pair (pairing available)
  • Google          , Fast Pair model ID
  • BLE flags byte  , discoverable mode, cross-transport, connectable
  • Service UUIDs   , 16-bit SIG + well-known 128-bit vendor UUIDs
  • Address kind    , public | static-random | RPA | NRPA
  • Distance        , log-distance path-loss estimate from RSSI + TX power
  • Risk scoring    , DFU, HID, NUS, Mesh, cross-transport flagged per device
"""

import asyncio
import json
import math
import re
import struct
import uuid as _uuid_mod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.base import (
    BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity, Target,
)
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# ── Lookup tables ─────────────────────────────────────────────────────────────

COMPANY_IDS: Dict[int, str] = {
    0x0000: "Ericsson",        0x0001: "Nokia",           0x0002: "Intel",
    0x0006: "Microsoft",       0x000D: "Texas Instr.",    0x000F: "Broadcom",
    0x001A: "Nokia",           0x001D: "Qualcomm",        0x0059: "Nordic Semi",
    0x006B: "Toshiba",         0x0075: "Samsung",         0x0087: "Garmin",
    0x00D2: "Dialog Semi",     0x00E0: "Google",          0x0131: "Huawei",
    0x0157: "Xiaomi",          0x0171: "Amazon",          0x01FF: "Goodix",
    0x022B: "Bose",            0x0310: "Wyze",            0x038F: "Tile",
    0x03DA: "Bose",            0x0499: "Ruuvi",           0x004C: "Apple",
    0x0603: "Sonos",           0x0822: "Espressif",       0x08D4: "Polar",
    0x09A3: "Govee",           0x0969: "Tuya",            0x012D: "Jabra",
    0x054C: "Sony",            0x008A: "LG Elec.",        0x0310: "Wyze",
    0x04F7: "Tile",            0x038F: "Espressif",       0x0131: "Anhui Huami",
    0x00CB: "KaHa",            0xCB55: "KaHa",
}

# 16-bit BT SIG service UUIDs
SERVICE_UUIDS_16: Dict[int, Tuple[str, bool]] = {
    # (name, is_risky)
    0x1800: ("Generic Access",      False),
    0x1801: ("Generic Attribute",   False),
    0x1802: ("Immediate Alert",     False),
    0x1803: ("Link Loss",           False),
    0x1804: ("Tx Power",            False),
    0x1805: ("Current Time",        False),
    0x1809: ("Health Thermometer",  False),
    0x180A: ("Device Information",  False),
    0x180D: ("Heart Rate",          False),
    0x180F: ("Battery Service",     False),
    0x1810: ("Blood Pressure",      False),
    0x1812: ("HID",                 True),   # keystroke injection
    0x1813: ("Scan Parameters",     False),
    0x1816: ("Cycling Speed",       False),
    0x1818: ("Cycling Power",       False),
    0x181A: ("Environmental",       False),
    0x181C: ("User Data",           False),
    0x181D: ("Weight Scale",        False),
    0x181E: ("Bond Management",     True),
    0x1822: ("PLX / SpO2",          False),
    0x1826: ("Fitness Machine",     False),
    0xFDDF: ("BLE Mesh Prov.",      True),   # unauthenticated mesh join
    0xFDD9: ("BLE Mesh Proxy",      False),
    0xFE59: ("Nordic DFU",          True),   # firmware update
    0xFE95: ("Xiaomi Mi",           False),
    0xFEAA: ("Eddystone",           False),
    0xFECD: ("Polar",               False),
    0xFCF1: ("Google Nearby",       False),
    0xFE2C: ("Google Fast Pair",    False),
    0xFD6F: ("Apple FindMy",        False),
    0xFD44: ("AirTag / FindMy",     False),
    0xFFE0: ("Common IoT",          True),   # often unauth writes
    0xFFF0: ("Vendor Specific",     False),
    0xFFD0: ("Vendor Specific 2",   False),
}

# Well-known 128-bit vendor UUIDs
SERVICE_UUIDS_128: Dict[str, Tuple[str, bool]] = {
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": ("Nordic UART (NUS)",    True),
    "00001530-1212-efde-1523-785feabcd123": ("Nordic Legacy DFU",     True),
    "a3c87500-8ed3-4bdf-8a39-a01bebede295": ("Eddystone Config",      True),
    "7905f431-b5ce-4e99-a40f-4b1e122d00d0": ("ANCS (Apple Notif.)",   False),
    "89d3502b-0f36-433a-8ef4-c502ad55f8dc": ("Apple Media (AMS)",     False),
    "0000fef5-0000-1000-8000-00805f9b34fb": ("Dialog SUOTA DFU",      True),
    "b9402000-f5f8-466e-aff9-25556b57fe6d": ("Estimote",              False),
    "0000fee0-0000-1000-8000-00805f9b34fb": ("Xiaomi / Huami",        False),
}

# Apple Continuity type → label (type_byte, optional subtype_byte)
_APPLE_TYPES: Dict[Tuple[int, Optional[int]], str] = {
    (0x01, None): "AirPrint",
    (0x02, 0x15): "iBeacon",
    (0x03, None): "AirPlay Target",
    (0x05, None): "AirPlay Source",
    (0x06, None): "Apple TV",
    (0x07, None): "AirPods / Beats",
    (0x08, None): "Siri",
    (0x09, None): "AirPlay",
    (0x0B, None): "Apple Watch",
    (0x0C, None): "Handoff",
    (0x0D, None): "Hotspot",
    (0x0E, None): "Nearby Action",
    (0x0F, None): "FindMy Tag",
    (0x10, None): "Nearby Info",
    (0x12, None): "FindMy / AirTag",
    (0x13, None): "Auto Unlock",
    (0x14, None): "HomeKit",
    (0x15, None): "Magic Switch",
    (0x19, None): "Airdrop",
}

# AirPods model byte (inside type=0x07 payload byte 0)
_AIRPODS_MODELS: Dict[int, str] = {
    0x02: "AirPods 1st gen",  0x0F: "AirPods 2nd gen",
    0x13: "AirPods 3rd gen",  0x14: "AirPods Pro",
    0x0E: "AirPods Pro 2",    0x0A: "AirPods Max",
    0x20: "AirPods 4",        0x24: "AirPods Pro 2 (USB-C)",
    0x0B: "Powerbeats3",      0x0C: "Beats X",
    0x12: "Beats Solo3",      0x03: "Powerbeats3 (no case)",
    0x11: "Beats Studio3",
}

# Eddystone URL scheme prefixes
_ES_SCHEMES: Dict[int, str] = {
    0x00: "http://www.", 0x01: "https://www.",
    0x02: "http://",     0x03: "https://",
}
_ES_SUFFIXES: Dict[int, str] = {
    0x00: ".com/",  0x01: ".org/",  0x02: ".edu/",  0x03: ".net/",
    0x04: ".info/", 0x05: ".biz/",  0x06: ".gov/",  0x07: ".com",
    0x08: ".org",   0x09: ".edu",   0x0A: ".net",   0x0B: ".info",
    0x0C: ".biz",   0x0D: ".gov",
}

# BLE advertising flags byte
_FLAG_LE_LIMITED_DISC  = 0x01
_FLAG_LE_GENERAL_DISC  = 0x02
_FLAG_BREDR_NOT_SUPP   = 0x04
_FLAG_SIMUL_LE_BREDR_C = 0x08
_FLAG_SIMUL_LE_BREDR_H = 0x10

_PATH_LOSS_N  = 2.7
_TX_REF_1M    = -59
_RSSI_BUF     = 5
_ANSI_RE      = re.compile(r"\033\[[0-9;]*m")


# ── Decoders ──────────────────────────────────────────────────────────────────

def _decode_ibeacon(payload: bytes) -> Optional[Dict[str, Any]]:
    """iBeacon: type=0x02 len=0x15 in Apple manufacturer data."""
    if len(payload) < 23 or payload[0] != 0x02 or payload[1] != 0x15:
        return None
    try:
        prox_uuid = str(_uuid_mod.UUID(bytes=bytes(payload[2:18]))).upper()
        major     = (payload[18] << 8) | payload[19]
        minor     = (payload[20] << 8) | payload[21]
        tx_power  = payload[22] if payload[22] < 128 else payload[22] - 256
        return {"uuid": prox_uuid, "major": major, "minor": minor, "tx_power": tx_power}
    except Exception:
        return None


def _decode_airpods(payload: bytes) -> Dict[str, Any]:
    """
    AirPods / Beats status (type=0x07).
    Bytes: [model][status][battery_right][battery_left][battery_case][lid_open][color][suffix]
    """
    info: Dict[str, Any] = {}
    if len(payload) < 2:
        return info
    info["model"] = _AIRPODS_MODELS.get(payload[0], f"Unknown (0x{payload[0]:02X})")
    if len(payload) >= 6:
        status = payload[1]
        # bit 5 = left in-ear, bit 1 = right in-ear
        info["left_in_ear"]  = bool(status & 0x20)
        info["right_in_ear"] = bool(status & 0x02)
        batt_r = payload[2] & 0x0F
        batt_l = payload[3] & 0x0F
        batt_c = payload[4] & 0x0F
        if batt_r < 11: info["battery_right"] = f"{batt_r * 10}%"
        if batt_l < 11: info["battery_left"]  = f"{batt_l * 10}%"
        if batt_c < 11: info["battery_case"]  = f"{batt_c * 10}%"
        charging = payload[2] >> 7
        info["charging"] = bool(charging)
    return info


def _decode_nearby_info(payload: bytes) -> Dict[str, Any]:
    """Nearby Info (type=0x10), iOS version + activity status."""
    info: Dict[str, Any] = {}
    if len(payload) < 2:
        return info
    status = payload[0]
    ios_major = (status >> 4) & 0x0F
    ios_minor = (status >> 0) & 0x0F
    if ios_major > 0:
        info["ios_version"] = f"~iOS {ios_major + 8}.{ios_minor}"
    info["screen_on"] = bool(status & 0x04)
    if len(payload) >= 2:
        action = payload[1]
        _actions = {
            0x00: "Idle",           0x01: "Playing Audio",
            0x02: "On a Call",      0x03: "Screen Off",
            0x05: "Driving",        0x07: "Running",
            0x09: "Walking",        0x0A: "Screen On",
        }
        info["activity"] = _actions.get(action, f"0x{action:02X}")
    return info


def _decode_apple_payload(payload: bytes) -> Dict[str, Any]:
    """Dispatch Apple manufacturer data (bytes after company ID 0x004C)."""
    result: Dict[str, Any] = {"raw_type": None, "label": "Apple Device", "details": {}}
    if len(payload) < 2:
        return result

    t = payload[0]
    result["raw_type"] = t

    # Look up label
    key2 = (t, payload[1]) if len(payload) >= 2 else None
    if key2 and key2 in _APPLE_TYPES:
        result["label"] = _APPLE_TYPES[key2]
    elif (t, None) in _APPLE_TYPES:
        result["label"] = _APPLE_TYPES[(t, None)]
    else:
        result["label"] = f"Apple (0x{t:02X})"

    if t == 0x02:
        ib = _decode_ibeacon(payload)
        if ib:
            result["details"] = ib
            result["label"]   = "iBeacon"
    elif t == 0x07:
        result["details"] = _decode_airpods(payload[2:])
    elif t == 0x10:
        result["details"] = _decode_nearby_info(payload[2:])
    elif t == 0x0C:
        result["details"] = {"note": "Handoff clipboard token (encrypted)"}
    elif t in (0x0F, 0x12):
        result["details"] = {"note": "Offline FindMy beacon (encrypted location)"}

    return result


def _decode_eddystone(service_data: Dict[str, bytes]) -> Optional[Dict[str, Any]]:
    """Decode Eddystone service data (keyed by UUID string)."""
    for key, payload in service_data.items():
        if "feaa" not in key.lower() or len(payload) < 1:
            continue
        frame = payload[0]
        if frame == 0x10 and len(payload) >= 3:      # URL
            scheme = _ES_SCHEMES.get(payload[2], "?://")
            url = scheme
            for b in payload[3:]:
                url += _ES_SUFFIXES.get(b, chr(b) if 0x20 <= b <= 0x7E else "")
            return {"type": "Eddystone-URL", "url": url}
        elif frame == 0x00 and len(payload) >= 18:   # UID
            ns  = payload[2:12].hex().upper()
            ins = payload[12:18].hex().upper()
            return {"type": "Eddystone-UID", "namespace": ns, "instance": ins}
        elif frame == 0x20:                           # TLM
            return {"type": "Eddystone-TLM", "note": "Telemetry beacon"}
    return None


def _decode_fast_pair(service_data: Dict[str, bytes]) -> Optional[str]:
    """Google Fast Pair, 3-byte model ID in service data for 0xFE2C."""
    for key, payload in service_data.items():
        if "fe2c" in key.lower() and len(payload) >= 3:
            model_id = (payload[0] << 16) | (payload[1] << 8) | payload[2]
            return f"0x{model_id:06X}"
    return None


def _decode_swift_pair(payload: bytes) -> bool:
    """Microsoft Swift Pair, first byte 0x06 means pairing available."""
    return len(payload) >= 1 and payload[0] == 0x06


def _addr_kind(addr: str, bluez_addr_type: Optional[str]) -> str:
    """Classify address: public | static | rpa | nrpa."""
    if bluez_addr_type == "public":
        return "public"
    try:
        first = int(addr.split(":")[0], 16)
        top   = (first >> 6) & 0x03
        if top == 0b11: return "static"
        if top == 0b01: return "rpa"
        if top == 0b00: return "nrpa"
    except Exception:
        pass
    return "unknown"


def _decode_flags(flags: int) -> List[str]:
    out: List[str] = []
    if flags & _FLAG_LE_LIMITED_DISC:  out.append("Limited Disc.")
    if flags & _FLAG_LE_GENERAL_DISC:  out.append("General Disc.")
    if flags & _FLAG_BREDR_NOT_SUPP:   out.append("BLE-only")
    if flags & _FLAG_SIMUL_LE_BREDR_C: out.append("Simul.Classic(C)")
    if flags & _FLAG_SIMUL_LE_BREDR_H: out.append("Simul.Classic(H)")
    return out


def _estimate_dist(rssi: int, tx_power: Optional[int]) -> float:
    ref = tx_power if tx_power is not None else _TX_REF_1M
    try:
        return round(10 ** ((ref - rssi) / (10 * _PATH_LOSS_N)), 1)
    except Exception:
        return -1.0


def _smooth(buf: List[int], val: int) -> int:
    buf.append(val)
    if len(buf) > _RSSI_BUF:
        buf.pop(0)
    return int(sum(buf) / len(buf))


def _vis(s: str) -> int:
    return len(_ANSI_RE.sub("", s))


def _cpad(s: str, w: int) -> str:
    return s + " " * max(0, w - _vis(s))


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ParsedAdv:
    address:      str
    addr_kind:    str               = "unknown"   # public | static | rpa | nrpa
    name:         str               = ""
    rssi:         int               = -100
    tx_power:     Optional[int]     = None
    distance_m:   float             = -1.0

    # Manufacturer
    mfg_id:       Optional[int]     = None
    mfg_name:     str               = ""
    mfg_raw:      bytes             = b""

    # Decoded payloads
    apple:        Optional[Dict]    = None        # decoded Apple Continuity
    eddystone:    Optional[Dict]    = None        # decoded Eddystone
    fast_pair_id: Optional[str]     = None        # Google Fast Pair model ID
    swift_pair:   bool              = False       # Microsoft Swift Pair

    # Services
    services_16:  List[Dict]        = field(default_factory=list)
    services_128: List[str]         = field(default_factory=list)
    service_data: Dict[str, bytes]  = field(default_factory=dict)

    # BLE flags
    flags:        Optional[int]     = None
    flags_decoded: List[str]        = field(default_factory=list)
    connectable:  bool              = False
    cross_transport: bool           = False

    # Risk
    risky:        bool              = False
    risk_reasons: List[str]         = field(default_factory=list)

    # Internal
    _rssi_buf:    List[int]         = field(default_factory=list, repr=False)


# ── Module ────────────────────────────────────────────────────────────────────

class Module(ScannerModule):
    """BLE Advertisement Parser, deep passive decode, no connections"""

    info = ModuleInfo(
        name="scanners/ble/adv_parser",
        description="Deep BLE advertisement analysis, Apple Continuity, Eddystone, iBeacon, Fast Pair, risk scoring",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=["https://www.bluetooth.com/specifications/assigned-numbers/"],
    )

    def _setup_options(self) -> None:
        self.options = {
            "timeout":     ModuleOption("timeout",     False, "Scan duration (seconds)", 15),
            "target":      ModuleOption("target",      False, "Filter to single BD_ADDR", None),
            "filter_name": ModuleOption("filter_name", False, "Filter by device name substring", None),
            "show_raw":    ModuleOption("show_raw",    False, "Show raw manufacturer data bytes", False),
            "min_rssi":    ModuleOption("min_rssi",    False, "Ignore devices weaker than this dBm", None),
            "risky_only":  ModuleOption("risky_only",  False, "Show only risky devices", False),
            "output_file": ModuleOption("output_file", False, "Save results to JSON", None),
        }

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_services(self, uuids: List[str]) -> Tuple[List[Dict], List[str], bool]:
        """Return (services_16, services_128, any_risky)."""
        s16: List[Dict] = []
        s128: List[str] = []
        risky = False
        for u in uuids:
            ul = u.lower()
            if ul in SERVICE_UUIDS_128:
                name, r = SERVICE_UUIDS_128[ul]
                s128.append(ul)
                if r: risky = True
            elif ul.startswith("0000") and ul.endswith("-0000-1000-8000-00805f9b34fb"):
                try:
                    uid16 = int(ul[4:8], 16)
                    name, r = SERVICE_UUIDS_16.get(uid16, (f"0x{uid16:04X}", False))
                    s16.append({"uuid": f"0x{uid16:04X}", "uuid_int": uid16, "name": name, "risky": r})
                    if r: risky = True
                except Exception:
                    s128.append(ul)
            else:
                s128.append(ul)
        return s16, s128, risky

    def _assess_risk(self, dev: ParsedAdv) -> Tuple[bool, List[str]]:
        reasons: List[str] = []

        for s in dev.services_16:
            if s.get("risky"):
                reasons.append(f"{s['name']} service (attack surface)")
        for u in dev.services_128:
            if u in SERVICE_UUIDS_128 and SERVICE_UUIDS_128[u][1]:
                reasons.append(f"{SERVICE_UUIDS_128[u][0]} (attack surface)")

        if dev.addr_kind == "public":
            reasons.append("Public address, permanently trackable")
        if dev.cross_transport:
            reasons.append("Cross-transport (BR/EDR + LE), BLUR attack surface")
        if dev.mfg_id in (0x0157, 0x0131):
            reasons.append("Xiaomi / Huami, check unauthenticated GATT writes")
        if dev.apple and dev.apple.get("raw_type") == 0x10:
            details = dev.apple.get("details", {})
            if "ios_version" in details:
                reasons.append(f"iOS version visible: {details['ios_version']}")
        if dev.apple and dev.apple.get("raw_type") in (0x0F, 0x12):
            reasons.append("FindMy / AirTag beacon, location privacy concern")
        if dev.swift_pair:
            reasons.append("Swift Pair active, device accepting new pairings")
        if dev.fast_pair_id:
            reasons.append(f"Google Fast Pair model {dev.fast_pair_id}, pairing available")

        return bool(reasons), reasons

    def _parse_adv(self, device: "BLEDevice", adv: "AdvertisementData") -> ParsedAdv:
        rssi     = adv.rssi if hasattr(adv, "rssi") else -100
        tx_power = getattr(adv, "tx_power", None)

        # Address type from BlueZ backend
        bluez_addr_type: Optional[str] = None
        try:
            if isinstance(device.details, dict):
                bluez_addr_type = device.details.get(
                    "AddressType",
                    device.details.get("props", {}).get("AddressType")
                )
        except Exception:
            pass

        dev = ParsedAdv(
            address    = device.address.upper(),
            addr_kind  = _addr_kind(device.address, bluez_addr_type),
            name       = adv.local_name or device.name or "",
            rssi       = rssi,
            tx_power   = tx_power,
            distance_m = _estimate_dist(rssi, tx_power),
            connectable = bool(getattr(adv, "connectable", False)),
        )

        # Manufacturer data
        mfr = dict(adv.manufacturer_data) if adv.manufacturer_data else {}
        if mfr:
            dev.mfg_id, dev.mfg_raw = next(iter(mfr.items()))
            dev.mfg_raw = bytes(dev.mfg_raw)
            dev.mfg_name = COMPANY_IDS.get(dev.mfg_id, f"0x{dev.mfg_id:04X}")

            if dev.mfg_id == 0x004C:
                dev.apple = _decode_apple_payload(dev.mfg_raw)
            elif dev.mfg_id == 0x0006:
                dev.swift_pair = _decode_swift_pair(dev.mfg_raw)

        # Service data
        dev.service_data = {k: bytes(v) for k, v in (adv.service_data or {}).items()}
        dev.eddystone    = _decode_eddystone(dev.service_data)
        dev.fast_pair_id = _decode_fast_pair(dev.service_data)

        # Services
        dev.services_16, dev.services_128, _ = self._parse_services(
            list(adv.service_uuids or [])
        )

        # Flags byte from BlueZ
        try:
            props = device.details if isinstance(device.details, dict) else {}
            props = props.get("props", props)
            raw_flags = props.get("AdvertisingFlags")
            if isinstance(raw_flags, (bytes, bytearray)) and raw_flags:
                dev.flags = raw_flags[0]
            elif isinstance(raw_flags, int):
                dev.flags = raw_flags
        except Exception:
            pass
        if dev.flags is not None:
            dev.flags_decoded   = _decode_flags(dev.flags)
            dev.cross_transport = not bool(dev.flags & _FLAG_BREDR_NOT_SUPP)

        dev.risky, dev.risk_reasons = self._assess_risk(dev)
        return dev

    # ── Scanner ───────────────────────────────────────────────────────────────

    async def _scan_async(self) -> List[ParsedAdv]:
        timeout     = int(self.get_option("timeout"))
        target      = self.get_option("target")
        name_filter = self.get_option("filter_name")
        min_rssi    = self.get_option("min_rssi")
        if min_rssi is not None:
            min_rssi = int(min_rssi)

        found: Dict[str, ParsedAdv] = {}

        def callback(device: "BLEDevice", adv: "AdvertisementData") -> None:
            addr = device.address.upper()
            if target and addr != target.upper():
                return
            if name_filter:
                n = adv.local_name or device.name or ""
                if name_filter.lower() not in n.lower():
                    return
            rssi = adv.rssi if hasattr(adv, "rssi") else -100
            if min_rssi is not None and rssi < min_rssi:
                return

            if addr not in found:
                found[addr] = self._parse_adv(device, adv)
            else:
                existing = found[addr]
                if rssi is not None:
                    existing.rssi = _smooth(existing._rssi_buf, rssi)
                    existing.distance_m = _estimate_dist(existing.rssi, existing.tx_power)
                # Accumulate service UUIDs across multiple packets
                new_uuids = [u for u in (adv.service_uuids or [])
                             if u not in existing.services_128
                             and u not in [s["uuid"].lower() for s in existing.services_16]]
                if new_uuids:
                    s16, s128, r = self._parse_services(new_uuids)
                    existing.services_16.extend(s16)
                    existing.services_128.extend(s128)
                    if r and not existing.risky:
                        existing.risky, existing.risk_reasons = self._assess_risk(existing)
                # Update name if we get it later
                if not existing.name and (adv.local_name or device.name):
                    existing.name = adv.local_name or device.name or ""

        print_info(f"Scanning for {timeout} seconds...")
        scanner = BleakScanner(detection_callback=callback)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return list(found.values())

    # ── Output ────────────────────────────────────────────────────────────────

    def _rssi_bar(self, rssi: int) -> str:
        C = Colors
        strength = min(5, max(0, (rssi + 100) // 14))
        bar = "█" * strength + "░" * (5 - strength)
        if strength >= 4: return f"{C.GREEN}{bar}{C.RESET}"
        if strength >= 2: return f"{C.YELLOW}{bar}{C.RESET}"
        return f"{C.RED}{bar}{C.RESET}"

    def _print_table(self, devices: List[ParsedAdv]) -> None:
        C        = Colors
        show_raw = bool(self.get_option("show_raw"))

        if not devices:
            print_warning("No devices found")
            return

        devices.sort(key=lambda x: (-int(x.risky), x.rssi), reverse=False)
        devices.sort(key=lambda x: x.rssi, reverse=True)

        risky_count = sum(1 for d in devices if d.risky)

        # ── Summary table ────────────────────────────────────────────────────
        print(f"\n  {C.CYAN}{'='*115}{C.RESET}")
        print(f"  {C.BOLD}BLE ADVERTISEMENT ANALYSIS{C.RESET}  "
              f"- {len(devices)} device(s)"
              + (f"  {C.RED}[ {risky_count} RISKY ]{C.RESET}" if risky_count else ""))
        print(f"  {C.CYAN}{'='*115}{C.RESET}\n")

        W_IDX = 3; W_ADDR = 17; W_NAME = 22; W_RSSI = 5
        W_BAR = 7; W_DIST = 9; W_MFG = 18; W_TYPE = 20

        hdr = (f"  {C.BOLD}{'#':<{W_IDX}}  {'ADDRESS':<{W_ADDR}}  {'NAME':<{W_NAME}}"
               f"  {'RSSI':<{W_RSSI}}  {'SIG':<{W_BAR}}  {'DIST':<{W_DIST}}"
               f"  {'MANUFACTURER':<{W_MFG}}  {'TYPE / PAYLOAD':<{W_TYPE}}{C.RESET}")
        print(hdr)
        print("  " + "─" * 113)

        for idx, d in enumerate(devices, 1):
            name = (d.name[:20] + "..") if len(d.name) > 22 else (d.name or "-")
            mfg  = (d.mfg_name[:16] + "..") if len(d.mfg_name) > 18 else (d.mfg_name or "-")

            dtype = "-"
            if d.apple:
                label   = d.apple.get("label", "Apple")
                details = d.apple.get("details", {})
                if d.apple.get("raw_type") == 0x02 and details:
                    dtype = f"iBeacon Maj:{details.get('major','?')} Min:{details.get('minor','?')}"
                elif d.apple.get("raw_type") == 0x07 and details:
                    dtype = details.get("model", label)
                elif d.apple.get("raw_type") == 0x10 and details:
                    dtype = f"{label} {details.get('ios_version','')}"
                else:
                    dtype = label
            elif d.eddystone:
                if d.eddystone["type"] == "Eddystone-URL":
                    dtype = f"Eddystone {d.eddystone['url'][:22]}"
                else:
                    dtype = d.eddystone["type"]
            elif d.swift_pair:
                dtype = "Swift Pair (pairing)"
            elif d.fast_pair_id:
                dtype = f"Fast Pair {d.fast_pair_id}"
            else:
                # Infer from services
                for s in d.services_16:
                    if s["uuid_int"] == 0x180D: dtype = "Heart Rate"; break
                    if s["uuid_int"] == 0x1812: dtype = "HID Device"; break
                    if s["uuid_int"] == 0x1810: dtype = "Blood Pressure"; break
                    if s["uuid_int"] == 0x181D: dtype = "Weight Scale"; break
                    if s["uuid_int"] == 0xFE59: dtype = "DFU Target"; break
                else:
                    for u in d.services_128:
                        if "6e400001" in u: dtype = "NUS Device"; break
                        if "1530" in u:     dtype = "Legacy DFU"; break

            dtype = (dtype[:18] + "..") if len(dtype) > 20 else dtype
            dist  = f"~{d.distance_m}m" if d.distance_m >= 0 else "-"
            rc    = C.GREEN if d.rssi > -50 else (C.YELLOW if d.rssi > -70 else C.RED)
            bang  = f"{C.RED}!{C.RESET} " if d.risky else "  "

            print(f"  {bang}{idx:<{W_IDX-1}} {C.CYAN}{d.address:<{W_ADDR}}{C.RESET}  "
                  f"{name:<{W_NAME}}  {rc}{d.rssi:<{W_RSSI}}{C.RESET}  "
                  f"{self._rssi_bar(d.rssi):<{W_BAR}}  {dist:<{W_DIST}}  "
                  f"{mfg:<{W_MFG}}  {dtype:<{W_TYPE}}")

        print("  " + "─" * 113)

        # ── Detailed per-device section ───────────────────────────────────────
        print(f"\n  {C.BOLD}DETAILED ANALYSIS{C.RESET}\n")

        for idx, d in enumerate(devices, 1):
            addr_col = C.RED if d.risky else C.CYAN
            print(f"  {addr_col}[{idx}] {d.address}  {d.name or '-'}{C.RESET}")
            print(f"  {'─'*80}")

            # Identity
            print(f"    Address Kind  : {d.addr_kind.upper()}"
                  + ("  ⚠ permanent identifier" if d.addr_kind == "public" else ""))
            print(f"    RSSI          : {d.rssi} dBm"
                  + (f"  (est. {d.distance_m} m away)" if d.distance_m >= 0 else ""))
            if d.tx_power is not None:
                print(f"    TX Power      : {d.tx_power:+d} dBm")
            if d.connectable:
                print(f"    Connectable   : yes")
            if d.flags is not None:
                print(f"    Adv Flags     : 0x{d.flags:02X}  [{', '.join(d.flags_decoded) or '-'}]")
            if d.cross_transport:
                print(f"    Transport     : {C.YELLOW}BR/EDR + LE (cross-transport){C.RESET}")

            # Manufacturer
            if d.mfg_name:
                print(f"    Manufacturer  : {d.mfg_name} (0x{d.mfg_id:04X})")
            if d.mfg_raw and show_raw:
                print(f"    Mfg Data      : {d.mfg_raw.hex()[:64]}")

            # Apple Continuity
            if d.apple:
                ap = d.apple
                print(f"    {C.BOLD}Apple Continuity{C.RESET}")
                print(f"      Type        : {ap['label']} (0x{ap['raw_type']:02X})")
                det = ap.get("details", {})
                if det:
                    if "uuid" in det:
                        print(f"      UUID        : {det['uuid']}")
                        print(f"      Major/Minor : {det.get('major','?')} / {det.get('minor','?')}")
                        print(f"      TX Power    : {det.get('tx_power','?'):+d} dBm")
                    if "model" in det:
                        print(f"      Model       : {det['model']}")
                    if "battery_left" in det:
                        print(f"      Battery     : L={det.get('battery_left','?')}  "
                              f"R={det.get('battery_right','?')}  "
                              f"Case={det.get('battery_case','?')}"
                              + ("  [charging]" if det.get("charging") else ""))
                        print(f"      In-Ear      : L={det.get('left_in_ear','?')}  "
                              f"R={det.get('right_in_ear','?')}")
                    if "ios_version" in det:
                        print(f"      iOS Version : {det['ios_version']}")
                        print(f"      Screen On   : {det.get('screen_on','?')}")
                        print(f"      Activity    : {det.get('activity','?')}")
                    if "note" in det:
                        print(f"      Note        : {det['note']}")

            # Eddystone
            if d.eddystone:
                es = d.eddystone
                print(f"    {C.BOLD}Eddystone{C.RESET}  [{es['type']}]")
                if "url" in es:      print(f"      URL         : {es['url']}")
                if "namespace" in es:
                    print(f"      Namespace   : {es['namespace']}")
                    print(f"      Instance    : {es['instance']}")
                if "note" in es:     print(f"      Note        : {es['note']}")

            # Fast Pair / Swift Pair
            if d.fast_pair_id:
                print(f"    Fast Pair     : Model ID {d.fast_pair_id}")
            if d.swift_pair:
                print(f"    {C.YELLOW}Swift Pair    : Device is in pairing mode{C.RESET}")

            # Services
            if d.services_16:
                print(f"    Services (16-bit):")
                for s in d.services_16:
                    risk = f"  {C.RED}[RISK]{C.RESET}" if s.get("risky") else ""
                    print(f"      {s['uuid']}  {s['name']}{risk}")
            if d.services_128:
                print(f"    Services (128-bit):")
                for u in d.services_128:
                    label, risk = SERVICE_UUIDS_128.get(u, (u[:24], False))
                    risk_tag = f"  {C.RED}[RISK]{C.RESET}" if risk else ""
                    print(f"      {u}  {label if label != u[:24] else ''}{risk_tag}")

            # Risk findings
            if d.risk_reasons:
                print(f"    {C.RED}Risk Findings:{C.RESET}")
                for r in d.risk_reasons:
                    print(f"      {C.RED}!{C.RESET} {r}")

            print()

        # ── Statistics ────────────────────────────────────────────────────────
        print(f"  {C.CYAN}{'─'*115}{C.RESET}")
        print(f"  {C.BOLD}STATISTICS{C.RESET}")
        print(f"  {C.CYAN}{'─'*115}{C.RESET}")

        addr_kinds: Dict[str, int] = {}
        mfgs:       Dict[str, int] = {}
        for d in devices:
            addr_kinds[d.addr_kind] = addr_kinds.get(d.addr_kind, 0) + 1
            m = d.mfg_name or "Unknown"
            mfgs[m] = mfgs.get(m, 0) + 1

        print("  Addr types : " + "  ".join(f"{k}:{v}" for k, v in addr_kinds.items()))
        print("  By mfg     : " + "  ".join(
            f"{m}:{c}" for m, c in sorted(mfgs.items(), key=lambda x: -x[1])[:7]
        ))

        if risky_count:
            print(f"\n  {C.RED}RISKY TARGETS ({risky_count}):{C.RESET}")
            for d in devices:
                if d.risky:
                    print(f"    {C.RED}>{C.RESET} {d.address}  {d.name or d.mfg_name or '-'}")
                    for r in d.risk_reasons[:3]:
                        print(f"         {C.DARK_GREY}• {r}{C.RESET}")

        print(f"\n  {C.CYAN}{'='*115}{C.RESET}\n")

    # ── JSON export ───────────────────────────────────────────────────────────

    def _save_results(self, devices: List[ParsedAdv], filename: str) -> None:
        out: Dict[str, Any] = {"device_count": len(devices), "devices": []}
        for d in devices:
            out["devices"].append({
                "address": d.address, "addr_kind": d.addr_kind, "name": d.name,
                "rssi": d.rssi, "tx_power": d.tx_power, "distance_m": d.distance_m,
                "manufacturer_id":   d.mfg_id,
                "manufacturer_name": d.mfg_name,
                "manufacturer_data": d.mfg_raw.hex() if d.mfg_raw else None,
                "apple":     d.apple,
                "eddystone": d.eddystone,
                "fast_pair": d.fast_pair_id,
                "swift_pair": d.swift_pair,
                "services_16":  d.services_16,
                "services_128": d.services_128,
                "flags":        d.flags,
                "flags_decoded": d.flags_decoded,
                "cross_transport": d.cross_transport,
                "connectable": d.connectable,
                "risky":       d.risky,
                "risk_reasons": d.risk_reasons,
            })
        try:
            with open(filename, "w") as f:
                json.dump(out, f, indent=2, default=str)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False

        risky_only = bool(self.get_option("risky_only"))

        try:
            devices = asyncio.run(self._scan_async())
        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False

        if not devices:
            print_warning("No devices found")
            return False

        if risky_only:
            devices = [d for d in devices if d.risky]
            if not devices:
                print_warning("No risky devices found")
                return False

        print_success(f"Found {len(devices)} device(s)")
        for d in devices:
            self.add_result({
                "address": d.address, "name": d.name, "rssi": d.rssi,
                "mfg_id": d.mfg_id, "mfg_name": d.mfg_name,
                "services": [s["uuid"] for s in d.services_16] + d.services_128,
            })

        self._print_table(devices)

        out = self.get_option("output_file")
        if out:
            self._save_results(devices, out)

        return True
