"""
BlueSploit Module: iBeacon Security Tester
Discover iBeacons, let the user pick one, run a focused security test pass.

Workflow:
  Phase 1  Discovery     — LE active scan, list all iBeacons in range
  Phase 2  Selection     — interactive prompt to choose target BD_ADDR
  Phase 3  Security Test — focused tests on the selected beacon:
             - identifier persistence / rotation
             - advertising interval fingerprint
             - BD_ADDR classification (public OUI vs random RPA/NRPA/static)
             - default-UUID / SDK-sample detection
             - spoofing / collision (same UUID+Major+Minor on other addrs)
             - scan-response data leakage
             - connectability and GATT exposure (DFU, NUS, DIS, config svc)

GATT phase requires `bleak`. If unavailable, that test is skipped, others run.

References:
  - Apple iBeacon proximity UUID/Major/Minor format
  - Bluetooth Core 5.4 Vol 6 Part B (LL advertising, address types)
  - Nordic nRF5 SDK DFU/Secure DFU service UUIDs
"""

import asyncio
import errno
import os
import socket
import statistics
import struct
import sys
import time
from contextlib import contextmanager
from typing import Dict, Any, List, Optional, Tuple

from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    from bleak import BleakClient, BleakScanner   # noqa: F401
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

# =====================================================================
# HCI plumbing (TODO: lift to core.utils.hci — duplicated across modules)
# =====================================================================
AF_BLUETOOTH         = 31
BTPROTO_HCI          = 1
SOL_HCI              = 0
HCI_FILTER           = 2
HCI_COMMAND_PKT      = 0x01
HCI_EVENT_PKT        = 0x04

OGF_LE_CTL                    = 0x08
OCF_LE_SET_SCAN_PARAMETERS    = 0x000B
OCF_LE_SET_SCAN_ENABLE        = 0x000C

EVT_CMD_COMPLETE              = 0x0E
EVT_LE_META                   = 0x3E
EVT_LE_ADVERTISING_REPORT     = 0x02

# LE Advertising Report event types
ADV_IND          = 0x00   # connectable, scannable
ADV_DIRECT_IND   = 0x01
ADV_SCAN_IND     = 0x02   # non-connectable, scannable
ADV_NONCONN_IND  = 0x03   # the proper iBeacon type
SCAN_RSP         = 0x04


@contextmanager
def hci_socket(dev_id: int):
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
    try:
        s.bind((dev_id,))
        flt = struct.pack("<LLLH", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        s.setsockopt(SOL_HCI, HCI_FILTER, flt)
        yield s
    finally:
        try: s.close()
        except OSError: pass


def _hci_cmd(ogf: int, ocf: int, params: bytes) -> bytes:
    return struct.pack("<BHB", HCI_COMMAND_PKT, (ogf << 10) | ocf, len(params)) + params


def _drain_cmd_complete(sock: socket.socket, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            pkt = sock.recv(260)
        except socket.timeout:
            return
        if len(pkt) >= 4 and pkt[0] == HCI_EVENT_PKT and pkt[1] == EVT_CMD_COMPLETE:
            return


def _scan_enable(sock: socket.socket, enable: bool, active: bool = True) -> None:
    if enable:
        scan_type = 0x01 if active else 0x00
        params = struct.pack("<BHHBB", scan_type, 0x0010, 0x0010, 0x00, 0x00)
        sock.send(_hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, params))
        _drain_cmd_complete(sock, 1.0)
    sock.send(_hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                        struct.pack("<BB", 0x01 if enable else 0x00, 0x00)))
    _drain_cmd_complete(sock, 1.0)


def _read_adv_event(sock: socket.socket, timeout: float):
    """
    Yield (evt_type, addr_type, addr, rssi, data, monotonic_ts) from one
    HCI event packet, or None on timeout.
    """
    try:
        sock.settimeout(timeout)
        pkt = sock.recv(260)
    except socket.timeout:
        return None
    ts = time.monotonic()
    if len(pkt) < 3 or pkt[0] != HCI_EVENT_PKT or pkt[1] != EVT_LE_META:
        return []
    body = pkt[3:3 + pkt[2]]
    if not body or body[0] != EVT_LE_ADVERTISING_REPORT:
        return []
    out = []
    try:
        num = body[1]
        off = 2
        for _ in range(num):
            evt_type = body[off]; off += 1
            addr_type = body[off]; off += 1
            addr_le = body[off:off + 6]; off += 6
            dlen = body[off]; off += 1
            data = body[off:off + dlen]; off += dlen
            rssi = struct.unpack("<b", body[off:off + 1])[0]; off += 1
            addr = ":".join(f"{b:02X}" for b in reversed(addr_le))
            out.append((evt_type, addr_type, addr, rssi, data, ts))
    except (IndexError, struct.error):
        pass
    return out


# =====================================================================
# iBeacon parsing
# =====================================================================
APPLE_COMPANY_ID = 0x004C
IBEACON_TYPE     = 0x02
IBEACON_LENGTH   = 0x15

AD_MANUFACTURER_SPECIFIC_DATA = 0xFF

KNOWN_DEFAULT_UUIDS = {
    "B9407F30-F5F8-466E-AFF9-25556B57FE6D": "Estimote SDK default sample",
    "E2C56DB5-DFFB-48D2-B060-D0F5A71096E0": "Apple AirLocate sample",
    "F7826DA6-4FA2-4E98-8024-BC5B71E0893E": "Kontakt.io default",
    "8492E75F-4FD6-469D-B132-043FE94921D8": "Radius Networks demo",
    "74278BDA-B644-4520-8F0C-720EAF059935": "Glimworm Beacons demo",
    "00000000-0000-0000-0000-000000000000": "All-zero (test/demo only)",
    "FDA50693-A4E2-4FB1-AFCF-C6EB07647825": "Beaconinside generic",
}

# Beacon-vendor OUIs for public addresses
BEACON_VENDOR_OUIS = {
    "D0:D9:4F": "Estimote", "F4:B8:5E": "Estimote", "EC:F0:0E": "Estimote",
    "F8:5E:A0": "Estimote", "C2:9F:F1": "Estimote",
    "F2:84:C2": "Kontakt.io", "EE:CC:8B": "Kontakt.io",
    "50:91:F7": "Nordic Semiconductor", "EC:21:E5": "Nordic Semiconductor",
    "FF:2D:4F": "Nordic Semiconductor", "F4:CE:36": "Nordic Semiconductor",
    "00:18:31": "Texas Instruments", "00:1A:7D": "Texas Instruments",
    "30:AE:A4": "Espressif (ESP32)", "84:CC:A8": "Espressif (ESP32)",
    "A4:CF:12": "Espressif (ESP32)", "CC:50:E3": "Espressif (ESP32)",
}

# GATT UUIDs that signal exposure of interest on a beacon
INTERESTING_GATT = {
    "00001530-1212-efde-1523-785feabcd123": ("Nordic legacy DFU",       "high"),
    "0000fe59-0000-1000-8000-00805f9b34fb": ("Nordic Secure DFU",       "high"),
    "8e400001-f315-4f60-9fb8-838830daea50": ("Nordic Secure DFU alt",   "high"),
    "6e400001-b5a3-f393-e0a9-e50e24dcca9e": ("Nordic UART (NUS)",       "medium"),
    "0000180a-0000-1000-8000-00805f9b34fb": ("Device Information Svc",  "low"),
    "0000180f-0000-1000-8000-00805f9b34fb": ("Battery Service",         "low"),
    "0000fee0-0000-1000-8000-00805f9b34fb": ("Anhui Huami / Xiaomi",    "low"),
    "0000feaa-0000-1000-8000-00805f9b34fb": ("Eddystone (also broadcast)", "info"),
    "b9402000-f5f8-466e-aff9-25556b57fe6d": ("Estimote service",        "medium"),
}


def _uuid_str(b: bytes) -> str:
    h = b.hex().upper()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def parse_ibeacon(adv: bytes) -> Optional[Dict[str, Any]]:
    """Extract iBeacon fields from a raw advertising payload, or None."""
    i = 0
    while i < len(adv):
        ln = adv[i]
        if ln == 0 or i + 1 + ln > len(adv):
            return None
        ad_type = adv[i + 1]
        ad_data = adv[i + 2:i + 1 + ln]
        if ad_type == AD_MANUFACTURER_SPECIFIC_DATA and len(ad_data) >= 25:
            if struct.unpack("<H", ad_data[0:2])[0] == APPLE_COMPANY_ID \
                    and ad_data[2] == IBEACON_TYPE \
                    and ad_data[3] == IBEACON_LENGTH:
                return {
                    "uuid":     _uuid_str(ad_data[4:20]),
                    "major":    struct.unpack(">H", ad_data[20:22])[0],
                    "minor":    struct.unpack(">H", ad_data[22:24])[0],
                    "tx_power": struct.unpack("<b", ad_data[24:25])[0],
                }
        i += 1 + ln
    return None


def classify_addr(addr: str, addr_type: int) -> Tuple[str, Optional[str]]:
    """
    Returns (classification, vendor_or_None).

    Public  -> OUI lookup yields vendor.
    Random  -> top 2 bits of MSB classify:
        11 -> static random (fixed for power cycle)
        10 -> Resolvable Private Address (rotates ~15min)
        00 -> Non-Resolvable Private Address
    """
    if addr_type == 0:
        oui = addr[:8].upper()
        return ("public", BEACON_VENDOR_OUIS.get(oui))
    msb = int(addr.split(":")[0], 16)
    top = (msb >> 6) & 0x03
    if top == 0b11:
        return ("random/static", None)
    if top == 0b10:
        return ("random/RPA (rotates)", None)
    if top == 0b00:
        return ("random/NRPA", None)
    return ("random/reserved", None)


# =====================================================================
# Phase 1 — Discovery
# =====================================================================
def discover_ibeacons(dev_id: int, duration: float,
                       min_rssi: Optional[int]) -> List[Dict[str, Any]]:
    """Active scan for `duration` seconds; return list of unique iBeacons."""
    seen: Dict[str, Dict[str, Any]] = {}     # keyed by (addr, uuid, major, minor)

    with hci_socket(dev_id) as sock:
        _scan_enable(sock, enable=True, active=True)
        deadline = time.monotonic() + duration
        try:
            while time.monotonic() < deadline:
                events = _read_adv_event(sock, max(0.1, deadline - time.monotonic()))
                if not events:
                    continue
                for evt_type, addr_type, addr, rssi, data, _ts in events:
                    if min_rssi is not None and rssi < min_rssi:
                        continue
                    ib = parse_ibeacon(data)
                    if not ib:
                        continue
                    key = f"{addr}|{ib['uuid']}|{ib['major']}|{ib['minor']}"
                    rec = seen.get(key)
                    if rec is None:
                        rec = {
                            "addr": addr, "addr_type": addr_type,
                            "evt_types": set(), "rssi_min": rssi, "rssi_max": rssi,
                            "count": 0, **ib,
                        }
                        seen[key] = rec
                    rec["evt_types"].add(evt_type)
                    rec["rssi_min"] = min(rec["rssi_min"], rssi)
                    rec["rssi_max"] = max(rec["rssi_max"], rssi)
                    rec["count"] += 1
        finally:
            _scan_enable(sock, enable=False)

    out = list(seen.values())
    out.sort(key=lambda r: -r["rssi_max"])    # closest / strongest first
    return out


# =====================================================================
# Phase 2 — Interactive selection
# =====================================================================
def show_candidates(cands: List[Dict[str, Any]]) -> None:
    C = Colors
    print(f"\n  {C.CYAN}{'=' * 78}{C.RESET}")
    print(f"  {C.BOLD}DISCOVERED iBEACONS{C.RESET}")
    print(f"  {C.CYAN}{'=' * 78}{C.RESET}")
    print(f"  {'#':>3}  {'BD_ADDR':<17}  {'UUID':<36}  {'Maj':>5} {'Min':>5} "
          f"{'RSSI':>5}  Hint")
    print(f"  {C.CYAN}{'-' * 78}{C.RESET}")
    for i, c in enumerate(cands, 1):
        hint = KNOWN_DEFAULT_UUIDS.get(c["uuid"], "")
        cls, vendor = classify_addr(c["addr"], c["addr_type"])
        if vendor and not hint:
            hint = f"OUI: {vendor}"
        print(f"  {i:>3}  {c['addr']:<17}  {c['uuid']:<36}  "
              f"{c['major']:>5} {c['minor']:>5}  {c['rssi_max']:>4}  {hint}")


def select_target(cands: List[Dict[str, Any]],
                   auto_select: Optional[int]) -> Optional[Dict[str, Any]]:
    if auto_select is not None:
        idx = int(auto_select)
        if 1 <= idx <= len(cands):
            return cands[idx - 1]
        print_error(f"auto_select={idx} out of range (1..{len(cands)})")
        return None

    if not sys.stdin.isatty():
        print_warning("non-interactive stdin; set auto_select=N to pick a target")
        return None

    print(f"\n  Enter beacon number to test, or 'q' to quit.")
    while True:
        try:
            sel = input("  target > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        if sel in ("q", "quit", "exit"):
            return None
        if sel.isdigit():
            idx = int(sel)
            if 1 <= idx <= len(cands):
                return cands[idx - 1]
        print_error(f"  invalid; enter 1..{len(cands)} or 'q'")


# =====================================================================
# Phase 3 — Targeted security tests
# =====================================================================
class Findings:
    """Collects findings with severity. Severities: info, low, medium, high, critical."""
    SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self):
        self.items: List[Dict[str, Any]] = []

    def add(self, severity: str, title: str, detail: str,
            evidence: Optional[Dict[str, Any]] = None) -> None:
        self.items.append({
            "severity": severity, "title": title, "detail": detail,
            "evidence": evidence or {},
        })

    def by_severity(self):
        return sorted(self.items, key=lambda f: -self.SEV_RANK.get(f["severity"], 0))


def test_persistence_and_timing(target_addr: str, target_ib: Dict[str, Any],
                                  dev_id: int, duration: float, findings: Findings
                                  ) -> Dict[str, Any]:
    """
    Watch the target for `duration` seconds. Measure:
      - identifier rotation (UUID / Major / Minor changes)
      - advertising interval (mean, stdev) on its primary frames
      - which advertising event types appear
    """
    print_info(f"persistence/timing test ({duration:.0f}s)…")
    samples: List[float] = []         # timestamps for primary (non-SCAN_RSP) frames
    id_history: List[str] = []        # 'UUID|maj|min' on each frame
    evt_types: Dict[int, int] = {}
    addr_seen: Dict[str, int] = {}    # how many frames per addr (RPA may rotate)
    rssi_samples: List[int] = []

    with hci_socket(dev_id) as sock:
        _scan_enable(sock, enable=True, active=True)
        deadline = time.monotonic() + duration
        try:
            while time.monotonic() < deadline:
                events = _read_adv_event(sock, max(0.1, deadline - time.monotonic()))
                if not events:
                    continue
                for evt_type, addr_type, addr, rssi, data, ts in events:
                    if addr != target_addr:
                        continue
                    evt_types[evt_type] = evt_types.get(evt_type, 0) + 1
                    addr_seen[addr] = addr_seen.get(addr, 0) + 1
                    if evt_type == SCAN_RSP:
                        continue
                    ib = parse_ibeacon(data)
                    if not ib:
                        continue
                    samples.append(ts)
                    id_history.append(f"{ib['uuid']}|{ib['major']}|{ib['minor']}")
                    rssi_samples.append(rssi)
        finally:
            _scan_enable(sock, enable=False)

    result = {
        "frames_observed": len(samples),
        "evt_type_counts": {hex(k): v for k, v in evt_types.items()},
        "rssi_min": min(rssi_samples) if rssi_samples else None,
        "rssi_max": max(rssi_samples) if rssi_samples else None,
    }

    if len(samples) < 3:
        findings.add("low", "Insufficient frames captured",
                     f"Only {len(samples)} primary frames seen in {duration:.0f}s. "
                     f"Move closer or increase test_duration.")
        return result

    # Timing
    intervals = [b - a for a, b in zip(samples, samples[1:])]
    mean_ms = statistics.mean(intervals) * 1000
    stdev_ms = statistics.stdev(intervals) * 1000 if len(intervals) > 1 else 0.0
    result["adv_interval_mean_ms"] = round(mean_ms, 2)
    result["adv_interval_stdev_ms"] = round(stdev_ms, 2)
    print_info(f"  adv interval: mean={mean_ms:.1f}ms  stdev={stdev_ms:.1f}ms  "
               f"({len(samples)} frames)")

    # Persistence: should be perfectly static for a vanilla iBeacon
    unique_ids = set(id_history)
    result["unique_identities"] = len(unique_ids)
    if len(unique_ids) == 1:
        ib = target_ib
        findings.add("medium", "Static identifier (tracking risk)",
                     f"UUID/Major/Minor unchanged across all {len(samples)} frames "
                     f"over {duration:.0f}s. Anyone in range can correlate this "
                     f"device long-term.",
                     {"uuid": ib["uuid"], "major": ib["major"], "minor": ib["minor"]})
    else:
        findings.add("info", "Rotating identifier observed",
                     f"{len(unique_ids)} distinct UUID/Major/Minor combinations seen. "
                     f"Unusual for vanilla iBeacon — possible custom rotation scheme.",
                     {"identities": list(unique_ids)})

    # Event-type expectation: pure iBeacon should be ADV_NONCONN_IND only
    if ADV_IND in evt_types:
        findings.add("medium", "Beacon is connectable",
                     f"ADV_IND observed ({evt_types[ADV_IND]} frames). A pure "
                     f"iBeacon should use ADV_NONCONN_IND. Connectability exposes "
                     f"a GATT attack surface — see GATT enumeration findings.",
                     {"adv_ind_count": evt_types[ADV_IND]})
    if SCAN_RSP in evt_types:
        findings.add("low", "Beacon responds to SCAN_REQ",
                     f"SCAN_RSP observed ({evt_types[SCAN_RSP]} frames). A privacy-"
                     f"preserving beacon should not respond to scan requests.",
                     {"scan_rsp_count": evt_types[SCAN_RSP]})

    return result


def test_default_uuid(ib: Dict[str, Any], findings: Findings) -> None:
    hint = KNOWN_DEFAULT_UUIDS.get(ib["uuid"])
    if hint:
        findings.add("high", "Default / sample UUID in production",
                     f"The proximity UUID matches a known SDK default ({hint}). "
                     f"Real deployments should generate a unique UUID. Default "
                     f"UUIDs allow trivial impersonation by other deployments "
                     f"using the same default.",
                     {"uuid": ib["uuid"], "match": hint})


def test_address_classification(addr: str, addr_type: int, findings: Findings
                                  ) -> Dict[str, Any]:
    cls, vendor = classify_addr(addr, addr_type)
    info = {"addr": addr, "addr_type_raw": addr_type, "classification": cls,
            "vendor": vendor}

    if cls == "public":
        msg = (f"BD_ADDR is public — OUI maps to "
               f"{vendor or 'an unrecognized vendor'}. Public addresses are "
               f"globally unique, immutable, and trivially trackable.")
        findings.add("medium" if vendor else "low",
                     "Public BD_ADDR (trackable)", msg, info)
    elif cls == "random/static":
        findings.add("low", "Static random address",
                     "Address is fixed across the device's power cycle; trackable "
                     "until next reset/repower.", info)
    elif cls.startswith("random/NRPA"):
        findings.add("info", "Non-resolvable private address",
                     "Address is non-resolvable and rotates — good privacy posture.",
                     info)
    elif cls.startswith("random/RPA"):
        findings.add("info", "Resolvable private address",
                     "Address rotates and can only be linked back to identity by "
                     "holders of the IRK. Healthy privacy posture.", info)
    return info


def test_collision(target: Dict[str, Any], all_seen: List[Dict[str, Any]],
                    findings: Findings) -> None:
    matches = [c for c in all_seen
               if c["uuid"] == target["uuid"]
               and c["major"] == target["major"]
               and c["minor"] == target["minor"]
               and c["addr"] != target["addr"]]
    if matches:
        findings.add("high", "Identifier collision (cloning suspect)",
                     f"{len(matches)} other BD_ADDR(s) broadcasting the same "
                     f"UUID/Major/Minor as the target. Genuine beacons have a "
                     f"fixed BD_ADDR per identity.",
                     {"other_addrs": [m["addr"] for m in matches]})


def test_scan_response(target_addr: str, dev_id: int, findings: Findings,
                        duration: float = 5.0) -> Dict[str, Any]:
    """Active scan, harvest SCAN_RSP from target if any. Decode AD structures."""
    print_info(f"scan-response harvest ({duration:.0f}s)…")
    sr_data: Optional[bytes] = None
    with hci_socket(dev_id) as sock:
        _scan_enable(sock, enable=True, active=True)
        deadline = time.monotonic() + duration
        try:
            while time.monotonic() < deadline and sr_data is None:
                events = _read_adv_event(sock, max(0.1, deadline - time.monotonic()))
                if not events:
                    continue
                for evt_type, _at, addr, _rssi, data, _ts in events:
                    if addr == target_addr and evt_type == SCAN_RSP and data:
                        sr_data = data
                        break
        finally:
            _scan_enable(sock, enable=False)

    if not sr_data:
        return {"scan_response": None}

    # Decode AD structures in the scan response
    ads = []
    i = 0
    while i < len(sr_data):
        ln = sr_data[i]
        if ln == 0 or i + 1 + ln > len(sr_data):
            break
        ads.append({"type": hex(sr_data[i + 1]),
                    "data_hex": sr_data[i + 2:i + 1 + ln].hex()})
        i += 1 + ln

    findings.add("low", "Scan-response data exposed",
                 f"Beacon emits a non-empty SCAN_RSP ({len(sr_data)} bytes). "
                 f"Contents may include device name, firmware version, or other "
                 f"identifiers a privacy-preserving beacon would not advertise.",
                 {"raw_hex": sr_data.hex(), "ads": ads})
    return {"scan_response": sr_data.hex(), "ads": ads}


# ---------- GATT (bleak) ----------
async def _gatt_enumerate(addr: str, timeout: float) -> Dict[str, Any]:
    out: Dict[str, Any] = {"connected": False, "services": [],
                              "device_info": {}, "error": None}
    try:
        async with BleakClient(addr, timeout=timeout) as client:
            out["connected"] = client.is_connected
            if not client.is_connected:
                return out
            for svc in client.services:
                svc_info = {"uuid": str(svc.uuid).lower(),
                            "description": svc.description or "",
                            "characteristics": []}
                for ch in svc.characteristics:
                    svc_info["characteristics"].append({
                        "uuid": str(ch.uuid).lower(),
                        "properties": list(ch.properties),
                    })
                out["services"].append(svc_info)

            # DIS leak: read manufacturer/model/firmware/serial if present
            dis_chars = {
                "00002a29-0000-1000-8000-00805f9b34fb": "manufacturer",
                "00002a24-0000-1000-8000-00805f9b34fb": "model",
                "00002a26-0000-1000-8000-00805f9b34fb": "firmware",
                "00002a25-0000-1000-8000-00805f9b34fb": "serial",
                "00002a27-0000-1000-8000-00805f9b34fb": "hw_revision",
                "00002a28-0000-1000-8000-00805f9b34fb": "sw_revision",
            }
            for svc in client.services:
                for ch in svc.characteristics:
                    cu = str(ch.uuid).lower()
                    if cu in dis_chars and "read" in ch.properties:
                        try:
                            val = await client.read_gatt_char(ch.uuid)
                            out["device_info"][dis_chars[cu]] = \
                                val.decode("utf-8", errors="replace").strip("\x00").strip()
                        except Exception as e:    # noqa: BLE001
                            out["device_info"][dis_chars[cu]] = f"<read failed: {e}>"
    except Exception as e:    # noqa: BLE001
        out["error"] = str(e)
    return out


def test_gatt_exposure(target_addr: str, findings: Findings,
                        timeout: float = 8.0) -> Dict[str, Any]:
    if not BLEAK_AVAILABLE:
        print_warning("bleak not installed — skipping GATT exposure test "
                      "(`pip install bleak`)")
        findings.add("info", "GATT test skipped",
                     "bleak library not available; install with `pip install bleak` "
                     "to enable GATT enumeration.")
        return {"skipped": True}

    print_info("attempting GATT connection…")
    try:
        result = asyncio.run(_gatt_enumerate(target_addr, timeout))
    except RuntimeError as e:
        # If we're already inside an event loop, fall back to nested loop
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_gatt_enumerate(target_addr, timeout))
        finally:
            loop.close()

    if not result["connected"]:
        if result.get("error"):
            findings.add("info", "GATT connect failed",
                         f"Could not connect to {target_addr}: {result['error']}. "
                         f"This is the expected/healthy state for a pure iBeacon.",
                         {"error": result["error"]})
        return result

    # Connected — that itself is a finding
    findings.add("high", "Beacon accepts GATT connections",
                 f"Successfully connected to {target_addr} without pairing. "
                 f"A pure iBeacon should reject connections. Connection-level "
                 f"access exposes any GATT services for further abuse.",
                 {"service_count": len(result["services"])})

    # Match services against the interesting list
    flagged = []
    for svc in result["services"]:
        match = INTERESTING_GATT.get(svc["uuid"].lower())
        if match:
            label, sev = match
            flagged.append({"uuid": svc["uuid"], "label": label, "severity": sev})
            findings.add(sev, f"Sensitive GATT service exposed: {label}",
                         f"Service UUID {svc['uuid']} ({label}) is reachable on "
                         f"the beacon without pairing. Investigate for OTA flashing, "
                         f"command injection, or default credentials depending on "
                         f"service type.",
                         {"service": svc})

    if result["device_info"]:
        findings.add("medium", "Device Information Service leaks fingerprint",
                     "DIS characteristics were readable without authentication, "
                     "exposing manufacturer/model/firmware that aid attacker "
                     "vulnerability targeting.",
                     {"dis": result["device_info"]})

    result["flagged_services"] = flagged
    return result


# =====================================================================
# Reporting
# =====================================================================
def print_report(target: Dict[str, Any], findings: Findings,
                  test_results: Dict[str, Any]) -> None:
    C = Colors
    print(f"\n  {C.CYAN}{'=' * 78}{C.RESET}")
    print(f"  {C.BOLD}SECURITY TEST REPORT — {target['addr']}{C.RESET}")
    print(f"  {C.CYAN}{'=' * 78}{C.RESET}")
    print(f"  UUID  : {target['uuid']}")
    print(f"  Major : {target['major']}    Minor: {target['minor']}    "
          f"TX@1m: {target['tx_power']} dBm")
    print(f"  RSSI  : {target['rssi_min']}..{target['rssi_max']} dBm  "
          f"({target['count']} discovery frames)")

    # Test results summary line
    pt = test_results.get("persistence_timing") or {}
    if pt.get("adv_interval_mean_ms") is not None:
        print(f"  Adv   : {pt['adv_interval_mean_ms']:.1f}ms mean "
              f"(stdev {pt['adv_interval_stdev_ms']:.1f}ms, "
              f"{pt['frames_observed']} frames)")
    addr_info = test_results.get("address") or {}
    if addr_info.get("classification"):
        line = f"  Addr  : {addr_info['classification']}"
        if addr_info.get("vendor"):
            line += f"  ({addr_info['vendor']})"
        print(line)
    gatt = test_results.get("gatt") or {}
    if gatt.get("connected"):
        print(f"  GATT  : CONNECTED — {len(gatt.get('services', []))} services exposed")
    elif gatt.get("skipped"):
        print(f"  GATT  : skipped")
    elif "connected" in gatt:
        print(f"  GATT  : connection refused (healthy)")

    if not findings.items:
        print_warning("\n  no findings recorded")
        return

    # Severity tally
    tally: Dict[str, int] = {}
    for f in findings.items:
        tally[f["severity"]] = tally.get(f["severity"], 0) + 1
    sev_color = {"critical": C.RED, "high": C.RED, "medium": C.YELLOW,
                 "low": C.CYAN, "info": C.WHITE}
    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in tally:
            col = sev_color[sev]
            summary_parts.append(f"{col}{tally[sev]} {sev}{C.RESET}")
    print(f"\n  {C.BOLD}SUMMARY{C.RESET}: " + "  ".join(summary_parts))

    # Findings detail
    print(f"\n  {C.BOLD}FINDINGS ({len(findings.items)}){C.RESET}")
    print(f"  {C.CYAN}{'-' * 78}{C.RESET}")
    for f in findings.by_severity():
        col = sev_color.get(f["severity"], C.WHITE)
        print(f"\n  {col}[{f['severity'].upper():8s}]{C.RESET} {f['title']}")
        print(f"      {f['detail']}")
        if f["evidence"]:
            for k, v in f["evidence"].items():
                vs = _format_evidence(v)
                print(f"      • {k}: {vs}")
    print()


def _format_evidence(v: Any) -> str:
    """Render an evidence value for inline CLI display, no JSON files."""
    if isinstance(v, str):
        s = v
    elif isinstance(v, (int, float, bool)) or v is None:
        s = str(v)
    elif isinstance(v, (list, tuple)):
        s = ", ".join(_format_evidence(x) for x in v)
    elif isinstance(v, dict):
        s = ", ".join(f"{k}={_format_evidence(val)}" for k, val in v.items())
    else:
        s = str(v)
    if len(s) > 200:
        s = s[:200] + "…"
    return s


# =====================================================================
# Module
# =====================================================================
class Module(ScannerModule):
    """iBeacon Security Tester — discover, select, test."""

    info = ModuleInfo(
        name="scanners/ibeacon_sec_test",
        description="Discover iBeacons, select a target, run focused security tests",
        author=["BlueSploit", "@mr-iot"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        cve=[],
        references=[
            "https://developer.apple.com/ibeacon/",
            "Bluetooth Core 5.4 Vol 6 Part B (LL advertising, addr types)",
        ]
    )

    def _setup_options(self) -> None:
        self.options = {
            "hci_dev": ModuleOption("hci_dev", False,
                "HCI adapter index (0 for hci0)", 0),
            "discovery_duration": ModuleOption("discovery_duration", False,
                "Phase 1 scan duration in seconds", 12),
            "test_duration": ModuleOption("test_duration", False,
                "Phase 3 monitoring duration (persistence + timing)", 30),
            "min_rssi": ModuleOption("min_rssi", False,
                "Discovery RSSI floor (dBm); ignore weaker beacons", None),
            "auto_select": ModuleOption("auto_select", False,
                "Skip the prompt and select beacon at this 1-based index", None),
            "skip_gatt": ModuleOption("skip_gatt", False,
                "Skip GATT enumeration phase", False),
            "gatt_timeout": ModuleOption("gatt_timeout", False,
                "GATT connection timeout (seconds)", 8),
        }

    def run(self) -> bool:
        hci_dev            = int(self.get_option("hci_dev"))
        discovery_duration = float(self.get_option("discovery_duration"))
        test_duration      = float(self.get_option("test_duration"))
        min_rssi_opt       = self.get_option("min_rssi")
        min_rssi           = int(min_rssi_opt) if min_rssi_opt is not None else None
        auto_select        = self.get_option("auto_select")
        skip_gatt          = bool(self.get_option("skip_gatt"))
        gatt_timeout       = float(self.get_option("gatt_timeout"))

        C = Colors
        print(f"\n  {C.CYAN}╔{'═' * 55}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET} {C.BOLD}iBeacon Security Tester{C.RESET}                               {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═' * 55}╝{C.RESET}")

        # --------- Phase 1 ---------
        print_info(f"\n[Phase 1] Discovery — scanning hci{hci_dev} for "
                   f"{discovery_duration:.0f}s")
        try:
            cands = discover_ibeacons(hci_dev, discovery_duration, min_rssi)
        except OSError as e:
            print_error(f"HCI bind failed on hci{hci_dev}: "
                        f"{os.strerror(e.errno)} — need CAP_NET_RAW or root")
            return False

        if not cands:
            print_warning("no iBeacons found")
            return False
        print_success(f"discovered {len(cands)} iBeacon(s)")
        show_candidates(cands)

        # --------- Phase 2 ---------
        target = select_target(cands, auto_select)
        if target is None:
            print_warning("no target selected; exiting")
            return False
        print_success(f"\nselected target: {target['addr']}  "
                      f"UUID={target['uuid']}  "
                      f"Major={target['major']}  Minor={target['minor']}")

        # --------- Phase 3 ---------
        print_info(f"\n[Phase 3] Security tests on {target['addr']}")
        findings = Findings()
        test_results: Dict[str, Any] = {}

        # 3.1 Default UUID
        test_default_uuid(target, findings)

        # 3.2 Address classification
        test_results["address"] = test_address_classification(
            target["addr"], target["addr_type"], findings)

        # 3.3 Collision / spoofing in current sweep
        test_collision(target, cands, findings)

        # 3.4 Persistence + timing + event types
        try:
            test_results["persistence_timing"] = test_persistence_and_timing(
                target["addr"], target, hci_dev, test_duration, findings)
        except OSError as e:
            print_error(f"persistence test failed: {e}")

        # 3.5 Scan response
        try:
            test_results["scan_response"] = test_scan_response(
                target["addr"], hci_dev, findings)
        except OSError as e:
            print_error(f"scan-response test failed: {e}")

        # 3.6 GATT
        if skip_gatt:
            print_info("GATT phase skipped (skip_gatt=True)")
        else:
            test_results["gatt"] = test_gatt_exposure(
                target["addr"], findings, gatt_timeout)

        # --------- Report ---------
        print_report(target, findings, test_results)

        for f in findings.items:
            self.add_result(f)

        # Return True if any non-info finding was raised
        return any(f["severity"] != "info" for f in findings.items)