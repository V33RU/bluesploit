"""
BlueSploit Module: Unified Vulnerability Scanner
=================================================

A single scanner that handles BLE *and* Classic targets and combines two
analyses in one pass:

  1. **Fingerprint × CVE matcher** — detect protocol, vendor, OS, services,
     features; score every CVE in the framework's own module catalogue
     against the target's evidence; print the matching `use <module>`
     commands sorted by severity + confidence.

  2. **BLE GATT deep analysis** — when the target is reachable over BLE,
     enumerate every service / characteristic and flag:
        • known-risk services (DFU, Mesh, HID, Xiaomi, …)
        • sensitive characteristics writable without authentication
        • notify/indicate streams that leak personal data
        • info-disclosure reads (model/serial/firmware/etc.)
        • optionally, *active* unauthenticated write probes

The CVE knowledge base is rebuilt from the live `modules/` tree at
runtime, so the scanner stays in sync with whatever exploits the
framework ships (currently 141 modules across exploits/, dos/, aux/).

Replaces the old split between `scanners/vuln_scan` (BLE GATT) and
`scanners/vuln_scanner` (Classic CVE matcher) — both used to fail on
the wrong protocol; this one handles both transparently.
"""

import asyncio
import importlib.util
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from core.base import (
    BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity,
)
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False
    BleakError = Exception   # type: ignore


# ── Vendor / OS heuristics ────────────────────────────────────────────────────

BLE_VENDOR_OS: Dict[int, str] = {
    0x004C: "Apple",     0x0006: "Microsoft",  0x0075: "Samsung",
    0x00E0: "Google",    0x038F: "Espressif",  0x0131: "Huawei",
    0x0157: "Xiaomi",    0x000F: "Broadcom",   0x001D: "Qualcomm",
    0x0002: "Intel",     0x054C: "Sony",       0x0059: "Nordic",
}

APPLE_OUIS: Set[str] = {
    "00:03:93", "00:0A:95", "00:11:24", "00:14:51", "00:16:CB", "00:19:E3",
    "28:CF:DA", "34:C0:59", "3C:15:C2", "4C:57:CA", "60:C5:47", "70:DE:E2",
    "78:31:C1", "80:E6:50", "84:78:8B", "A4:B1:97", "AC:BC:32", "F4:F9:51",
    "DC:A4:CA", "B8:09:8A", "E0:B9:BA",
}

ESPRESSIF_OUIS: Set[str] = {
    "24:0A:C4", "24:62:AB", "24:6F:28", "30:AE:A4", "3C:71:BF", "40:F5:20",
    "4C:11:AE", "5C:CF:7F", "84:0D:8E", "84:CC:A8", "84:F3:EB", "A4:CF:12",
    "AC:67:B2", "B4:E6:2D", "BC:DD:C2", "C4:4F:33", "CC:50:E3", "D8:A0:1D",
    "DC:4F:22", "EC:FA:BC",
}

NAME_OS_HINTS: List[Tuple[List[str], str]] = [
    (["iphone", "ipad", "ipod", "macbook", "imac", "airpod", "apple watch", "homepod"], "Apple"),
    (["galaxy", "pixel", "sm-", "android", "redmi", "poco", "oneplus", "huawei",
      "xiaomi", "oppo", "vivo", "realme", "nokia "], "Android"),
    (["surface", "win-", "desktop-", "laptop-"], "Windows"),
    (["raspberrypi", "ubuntu", "bluez"], "Linux"),
    (["esp32", "esp_", "esp-"], "ESP32"),
    (["jbl", "bose", "sony ", "wh-", "wf-"], "AudioPeripheral"),
]

# CVE detection rules. ``modules`` is filled from the live tree at runtime;
# we only declare the *evidence* to look for here.
CVE_RULES: Dict[str, Dict[str, Any]] = {
    # BlueBorne family
    "CVE-2017-0781": {"os": ["Android"], "services": ["BNEP", "0x000F"]},
    "CVE-2017-0782": {"os": ["Android"], "services": ["BNEP"]},
    "CVE-2017-0785": {"os": ["Android"], "services": ["SDP", "0x0001"]},
    "CVE-2017-1000251": {"os": ["Linux"], "features": ["ertm"]},

    # KNOB / BIAS / ECDH-debug / BLURtooth
    "CVE-2019-9506":  {"protocol": "classic", "no_features": ["secure_connections"]},
    "CVE-2020-10135": {"protocol": "classic", "no_features": ["secure_connections"]},
    "CVE-2020-15802": {"protocol": "classic"},
    "CVE-2018-5383":  {"protocol": "classic"},

    # BleedingTooth (Oct 2020)
    "CVE-2020-12351": {"os": ["Linux"]},
    "CVE-2020-12352": {"os": ["Linux"]},
    "CVE-2020-24490": {"os": ["Linux"], "protocol": "ble"},

    # BlueFrag
    "CVE-2020-0022": {"os": ["Android"]},

    # BrakTooth
    "CVE-2021-28139": {"vendor": ["Espressif", "ESP32"]},

    # Pairing-method confusion
    "CVE-2020-26555": {"protocol": "classic"},
    "CVE-2020-26556": {"protocol": "ble"},
    "CVE-2020-26557": {"protocol": "ble"},
    "CVE-2020-26558": {"protocol": "ble"},
    "CVE-2020-26559": {"protocol": "ble"},
    "CVE-2020-26560": {"protocol": "ble"},

    # BLUFFS
    "CVE-2023-24023": {"protocol": "classic"},

    # 0-click HID keystroke injection
    "CVE-2023-45866": {"os": ["Android", "Linux", "Apple", "Windows"]},

    # Older Android stack
    "CVE-2018-9361": {"os": ["Android"]},
    "CVE-2018-9485": {"os": ["Android"]},

    # Linux kernel RFCOMM/L2CAP recent
    "CVE-2024-26903": {"os": ["Linux"]},
    "CVE-2024-50044": {"os": ["Linux"]},
    "CVE-2024-35966": {"os": ["Linux"]},
    "CVE-2024-43771": {"os": ["Linux"]},
    "CVE-2024-49939": {"os": ["Linux"]},
    "CVE-2025-21688": {"os": ["Linux"]},
    "CVE-2022-49910": {"os": ["Linux"]},

    # Android system_bt RCE waves
    "CVE-2022-20345": {"os": ["Android"]},
    "CVE-2022-20411": {"os": ["Android"]},
    "CVE-2022-20566": {"os": ["Android"]},
    "CVE-2022-25836": {"os": ["Android"]},
    "CVE-2022-25837": {"os": ["Android"]},
    "CVE-2022-42896": {"os": ["Android"]},
    "CVE-2023-21347": {"os": ["Android"]},
    "CVE-2023-21108": {"os": ["Android"]},
    "CVE-2023-35673": {"os": ["Android"]},
    "CVE-2023-40129": {"os": ["Android"]},
    "CVE-2024-0031":  {"os": ["Android"]},
    "CVE-2024-0039":  {"os": ["Android"]},
    "CVE-2024-22099": {"os": ["Android"]},
    "CVE-2024-56604": {"os": ["Android"]},
    "CVE-2025-0084":  {"os": ["Android"]},
    "CVE-2025-22403": {"os": ["Android"]},
    "CVE-2025-48593": {"os": ["Android"]},

    # Xiaomi peripherals
    "CVE-2025-13328": {"vendor": ["Xiaomi"]},
    "CVE-2025-13834": {"vendor": ["Xiaomi"]},

    # BLE chips / Sweyntooth
    "CVE-2021-31615": {"protocol": "ble"},
    "CVE-2021-22645": {"protocol": "ble"},
    "CVE-2021-37577": {"protocol": "ble"},

    # Older RFCOMM
    "CVE-2011-1265":  {"os": ["Linux"]},
    "CVE-2010-1084":  {"os": ["Linux"]},
    "CVE-2015-8956":  {"os": ["Linux"]},
    "CVE-2018-20378": {"vendor": ["Sony Ericsson"]},
}


# ── Module catalogue loader ───────────────────────────────────────────────────

@dataclass
class CataloguedModule:
    use_path:    str
    name:        str
    description: str
    severity:    str
    protocol:    str
    cves:        List[str] = field(default_factory=list)


def _load_module_metadata(path: str, mod_id: str) -> Optional[CataloguedModule]:
    """Import a module file in isolation and pull its ModuleInfo metadata."""
    try:
        spec = importlib.util.spec_from_file_location(mod_id, path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)            # pyright: ignore
        cls = getattr(mod, "Module", None)
        if cls is None:
            return None
        info = cls.info
        proto = info.protocol.value if hasattr(info.protocol, "value") else str(info.protocol)
        sev   = info.severity.value if hasattr(info.severity, "value") else str(info.severity)
        return CataloguedModule(
            use_path    = info.name,
            name        = info.name,
            description = info.description,
            severity    = sev.upper(),
            protocol    = proto.upper(),
            cves        = list(info.cve or []),
        )
    except Exception:
        return None


def _scan_module_tree(root: str) -> Dict[str, List[CataloguedModule]]:
    """Walk modules/{exploits,dos,auxiliary}/ → CVE → [modules]."""
    cve_index: Dict[str, List[CataloguedModule]] = {}
    for category in ("exploits", "dos", "auxiliary"):
        cat_dir = os.path.join(root, "modules", category)
        if not os.path.isdir(cat_dir):
            continue
        for fn in sorted(os.listdir(cat_dir)):
            if not fn.endswith(".py") or fn == "__init__.py":
                continue
            mod_id = f"_vs_{category}_{fn[:-3]}"
            cm = _load_module_metadata(os.path.join(cat_dir, fn), mod_id)
            if not cm:
                continue
            for cve in cm.cves:
                cve_index.setdefault(cve.upper(), []).append(cm)
    return cve_index


# ── Target fingerprinting ─────────────────────────────────────────────────────

@dataclass
class Fingerprint:
    address:      str
    protocol:     str             = "?"      # BLE | CLASSIC | BOTH
    name:         Optional[str]   = None
    vendor:       Optional[str]   = None
    os_guess:     str             = "Unknown"
    services:     List[str]       = field(default_factory=list)
    features:     List[str]       = field(default_factory=list)
    rssi:         Optional[int]   = None
    lmp_version:  Optional[str]   = None
    mfr_ids:      List[int]       = field(default_factory=list)
    addr_type:    str             = "?"


def _ble_address_likely(addr: str) -> bool:
    """Static-random LE addresses set both top bits of byte 0."""
    try:
        first = int(addr.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return (first & 0xC0) == 0xC0


def _classify_os(name: Optional[str], vendor: Optional[str], addr: str) -> str:
    oui = addr.upper()[:8]
    if oui in ESPRESSIF_OUIS or (vendor and "espressif" in vendor.lower()):
        return "ESP32"
    if oui in APPLE_OUIS or (vendor and "apple" in vendor.lower()):
        return "Apple"
    n = (name or "").lower()
    for keys, label in NAME_OS_HINTS:
        if any(k in n for k in keys):
            return label
    if vendor:
        v = vendor.lower()
        if "samsung" in v or "google" in v or "huawei" in v or "xiaomi" in v:
            return "Android"
        if "microsoft" in v:
            return "Windows"
    return "Unknown"


# ── BLE GATT deep-analysis primitives ─────────────────────────────────────────

_BT_SIG_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def _short_uuid(uuid: str) -> str:
    u = uuid.lower()
    if u.startswith("0000") and u.endswith(_BT_SIG_SUFFIX):
        return u[4:8]
    if len(u) == 4:
        return u
    return ""


class GattSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class GattVuln:
    name:           str
    severity:       GattSeverity
    description:    str
    affected:       str
    details:        str
    recommendation: str


VULN_PATTERNS: Dict[str, Dict] = {
    "ffe0": {"name": "Common IoT (FFE0)",      "risk": "Often has unauthenticated writes",                   "severity": GattSeverity.HIGH},
    "fff0": {"name": "Vendor (FFF0)",           "risk": "Custom protocol — verify authentication",            "severity": GattSeverity.MEDIUM},
    "ffd0": {"name": "Vendor (FFD0)",           "risk": "Custom protocol — verify authentication",            "severity": GattSeverity.MEDIUM},
    "fee0": {"name": "Xiaomi (FEE0)",           "risk": "Known unauthenticated write vulnerabilities",        "severity": GattSeverity.HIGH},
    "fe59": {"name": "Nordic DFU (FE59)",       "risk": "Unauthenticated firmware update possible",           "severity": GattSeverity.CRITICAL},
    "fddf": {"name": "Mesh Provisioning",       "risk": "Unauthenticated mesh device join",                   "severity": GattSeverity.HIGH},
    "fe0f": {"name": "Vendor Diagnostic",       "risk": "Debug commands exposed",                            "severity": GattSeverity.HIGH},
    "fce0": {"name": "Fitbit (FCE0)",           "risk": "Proprietary protocol — verify authentication",       "severity": GattSeverity.MEDIUM},
    "180a": {"name": "Device Information",      "risk": "Device metadata readable without auth",             "severity": GattSeverity.LOW},
    "180f": {"name": "Battery Service",         "risk": "Battery level disclosure",                          "severity": GattSeverity.INFO},
    "1812": {"name": "HID over GATT",           "risk": "Keystroke injection if writes are unauthenticated",  "severity": GattSeverity.HIGH},
    "1826": {"name": "Fitness Machine",         "risk": "Unauthenticated control commands",                  "severity": GattSeverity.MEDIUM},
    "181c": {"name": "User Data",               "risk": "Personal data exposure",                            "severity": GattSeverity.HIGH},
}

SENSITIVE_WRITE_CHARS: Dict[str, str] = {
    "2a00": "Device Name",          "2a06": "Alert Level",
    "2a24": "Model Number",         "2a25": "Serial Number",
    "2a26": "Firmware Revision",    "2a27": "Hardware Revision",
    "2a28": "Software Revision",    "2a29": "Manufacturer Name",
    "2a40": "Ringer Control Point", "2a46": "Alert Notif. Control Point",
    "2a50": "PnP ID",               "2a56": "Digital Output",
    "2a57": "Digital Input",        "2b1e": "Timed Challenge Response",
}

INFO_LEAK_CHARS: Dict[str, str] = {
    "2a00": "Device Name",   "2a01": "Appearance",   "2a23": "System ID",
    "2a24": "Model Number",  "2a25": "Serial Number","2a26": "Firmware Revision",
    "2a27": "Hardware Revision",                     "2a28": "Software Revision",
    "2a29": "Manufacturer Name", "2a50": "PnP ID",
    "2a85": "Date of Birth", "2a8a": "First Name",   "2a8c": "Gender",
    "2a90": "Last Name",
}

_TEST_PAYLOADS = [bytes([0x00]), bytes([0x01]), bytes([0x00, 0x00]),
                  bytes([0x41, 0x41, 0x41, 0x41])]


@dataclass
class GattReport:
    services_count:     int = 0
    chars_count:        int = 0
    writable_count:     int = 0
    notify_count:       int = 0
    unauth_write_count: int = 0
    info_leak_count:    int = 0
    vulns:              List[GattVuln] = field(default_factory=list)


# ── Async helpers (BLE) ───────────────────────────────────────────────────────

async def _ble_passive_adv(target: str, timeout: int) -> Optional[Fingerprint]:
    """Listen for the target's advertisements; populate adv-derived fields."""
    fp = Fingerprint(address=target.upper(), protocol="BLE")
    seen = False
    try:
        scanner = BleakScanner()
        await scanner.start()
        await asyncio.sleep(min(timeout, 8))
        await scanner.stop()
        for d, adv in scanner.discovered_devices_and_advertisement_data.values():
            if d.address.upper() == target.upper():
                fp.name    = adv.local_name or d.name
                fp.rssi    = getattr(adv, "rssi", None)
                fp.mfr_ids = list(adv.manufacturer_data.keys()) if adv.manufacturer_data else []
                if adv.service_uuids:
                    fp.services.extend(adv.service_uuids)
                if fp.mfr_ids:
                    fp.vendor = BLE_VENDOR_OS.get(fp.mfr_ids[0])
                try:
                    fp.addr_type = d.details.get("AddressType", "?")
                except Exception:
                    pass
                seen = True
                break
    except Exception:
        pass
    return fp if seen else None


async def _ble_gatt_deep(
    target: str, timeout: int, test_writes: bool, deep: bool,
) -> Tuple[Optional[Fingerprint], GattReport]:
    """
    Connect over GATT, enumerate services, run the deep-analysis checks
    inherited from the old vuln_scan module.
    """
    rep = GattReport()
    fp_extra: Optional[Fingerprint] = None
    if not BLEAK_AVAILABLE:
        return fp_extra, rep

    try:
        async with BleakClient(target, timeout=timeout) as client:
            if not client.is_connected:
                return None, rep

            fp_extra = Fingerprint(address=target.upper(), protocol="BLE")

            # Pull Device Name characteristic for the fingerprint
            try:
                for svc in client.services:
                    for ch in svc.characteristics:
                        if _short_uuid(str(ch.uuid)) == "2a00":
                            raw = await client.read_gatt_char(ch.uuid)
                            try:
                                fp_extra.name = raw.decode("utf-8").strip("\x00") or None
                            except Exception:
                                pass
                            break
                    if fp_extra.name:
                        break
            except Exception:
                pass

            seen_write_findings: Set[str] = set()

            for service in client.services:
                svc_uuid  = str(service.uuid).lower()
                short_svc = _short_uuid(svc_uuid)
                rep.services_count += 1
                fp_extra.services.append(svc_uuid)

                if short_svc and short_svc in VULN_PATTERNS:
                    pat = VULN_PATTERNS[short_svc]
                    rep.vulns.append(GattVuln(
                        name=f"Risk Service: {pat['name']}",
                        severity=pat["severity"],
                        description=pat["risk"],
                        affected=svc_uuid,
                        details=f"Service {short_svc.upper()} has documented security concerns",
                        recommendation="Verify all characteristics require authentication",
                    ))

                for char in service.characteristics:
                    char_uuid  = str(char.uuid).lower()
                    short_char = _short_uuid(char_uuid)
                    props      = set(char.properties)
                    rep.chars_count += 1

                    is_writable = bool(props & {"write", "write-without-response"})
                    is_readable = "read" in props
                    is_wnr      = "write-without-response" in props
                    has_notify  = bool(props & {"notify", "indicate"})

                    if is_writable: rep.writable_count += 1
                    if has_notify:  rep.notify_count   += 1

                    # sensitive-char writable
                    if is_writable and short_char in SENSITIVE_WRITE_CHARS:
                        cn = SENSITIVE_WRITE_CHARS[short_char]
                        sv = GattSeverity.CRITICAL if is_wnr else GattSeverity.HIGH
                        rep.vulns.append(GattVuln(
                            name=f"Sensitive Char Writable: {cn}",
                            severity=sv,
                            description=f"{cn} ({short_char.upper()}) accepts writes without confirmed auth",
                            affected=char_uuid,
                            details=f"Properties: {', '.join(sorted(props))}",
                            recommendation="Require encrypted+authenticated link before writes",
                        ))
                        seen_write_findings.add(char_uuid)

                    # WNR on a known-risk service
                    elif is_wnr and short_svc in VULN_PATTERNS:
                        if char_uuid not in seen_write_findings:
                            rep.vulns.append(GattVuln(
                                name="Write-Without-Response on Risk Service",
                                severity=GattSeverity.MEDIUM,
                                description=f"Char in known-risk service {short_svc.upper()} ({VULN_PATTERNS[short_svc]['name']}) allows WNR",
                                affected=char_uuid,
                                details=f"Properties: {', '.join(sorted(props))}",
                                recommendation="Enforce authentication server-side",
                            ))
                            seen_write_findings.add(char_uuid)

                    # notify/indicate on sensitive char
                    if has_notify and short_char in INFO_LEAK_CHARS:
                        rep.vulns.append(GattVuln(
                            name=f"Unencrypted Notify: {INFO_LEAK_CHARS[short_char]}",
                            severity=GattSeverity.MEDIUM,
                            description=f"{INFO_LEAK_CHARS[short_char]} supports notify — passive subscription possible",
                            affected=char_uuid,
                            details=f"Properties: {', '.join(sorted(props))}",
                            recommendation="Notify only on encrypted/authenticated links",
                        ))

                    # info disclosure read
                    if is_readable and short_char in INFO_LEAK_CHARS and deep:
                        try:
                            raw = await client.read_gatt_char(char.uuid)
                            if raw:
                                try:
                                    decoded = raw.decode("utf-8").strip("\x00").strip()
                                    val = decoded if decoded else raw.hex()
                                except Exception:
                                    val = raw.hex()
                                rep.info_leak_count += 1
                                rep.vulns.append(GattVuln(
                                    name=f"Info Disclosure: {INFO_LEAK_CHARS[short_char]}",
                                    severity=GattSeverity.LOW,
                                    description=f"Device exposes {INFO_LEAK_CHARS[short_char]} without authentication",
                                    affected=char_uuid,
                                    details=f"Value: {val[:60]}{'...' if len(val) > 60 else ''}",
                                    recommendation="Restrict reads to bonded peers",
                                ))
                        except Exception:
                            pass

                    # active write probe
                    if is_writable and test_writes and char_uuid not in seen_write_findings:
                        for payload in _TEST_PAYLOADS:
                            try:
                                await client.write_gatt_char(char_uuid, payload, response=False)
                                rep.unauth_write_count += 1
                                rep.vulns.append(GattVuln(
                                    name="Unauthenticated Write Confirmed",
                                    severity=GattSeverity.CRITICAL,
                                    description="Char accepted a write without prior pairing/bonding",
                                    affected=char_uuid,
                                    details=f"Service: {short_svc.upper() if short_svc else svc_uuid[:8]}",
                                    recommendation="Implement pairing/bonding and enforce on every write",
                                ))
                                break
                            except BleakError as e:
                                if any(k in str(e).lower() for k in
                                       ("auth", "encrypt", "insufficient", "not permit", "not support")):
                                    break
                            except Exception:
                                continue

            if (test_writes and rep.writable_count > 0
                    and rep.unauth_write_count == rep.writable_count):
                rep.vulns.append(GattVuln(
                    name="No Write Authentication Anywhere",
                    severity=GattSeverity.CRITICAL,
                    description="Every writable characteristic accepted an unauthenticated write",
                    affected="All writable characteristics",
                    details=f"All {rep.writable_count} writable chars lack auth enforcement",
                    recommendation="Implement BLE pairing/bonding requirements globally",
                ))
            if not test_writes and rep.writable_count > 8:
                rep.vulns.append(GattVuln(
                    name="Large Writable Attack Surface",
                    severity=GattSeverity.MEDIUM,
                    description=f"Device exposes {rep.writable_count} writable characteristics",
                    affected="Multiple",
                    details="High writable count → larger unauthenticated-write risk",
                    recommendation="Re-run with test_writes=true to confirm auth enforcement",
                ))

    except Exception:
        # Catches asyncio.TimeoutError, BleakError, and anything else the
        # underlying transport may raise — partial results are still useful.
        return fp_extra, rep
    return fp_extra, rep


def _classic_fingerprint(target: str) -> Optional[Fingerprint]:
    """Fingerprint a Classic target via hcitool / sdptool."""
    fp = Fingerprint(address=target.upper(), protocol="CLASSIC")
    saw = False

    try:
        r = subprocess.run(["hcitool", "name", target],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            fp.name = r.stdout.strip()
            saw = True
    except Exception:
        pass

    try:
        r = subprocess.run(["hcitool", "info", target],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                ls = line.strip()
                if ls.startswith("Manufacturer:"):
                    fp.vendor = ls.split(":", 1)[1].strip()
                    saw = True
                elif ls.startswith("LMP Version:"):
                    m = re.search(r"(\d+\.\d+)", ls)
                    if m:
                        fp.lmp_version = m.group(1)
                        saw = True
                elif ls.startswith("Features:"):
                    feats = ls.split(":", 1)[1].lower()
                    for kw, tag in [
                        ("encryption",         "encryption"),
                        ("secure connection",  "secure_connections"),
                        ("simple pairing",     "ssp"),
                        ("ertm",               "ertm"),
                        ("le supported",       "le"),
                        ("br/edr",             "bredr"),
                    ]:
                        if kw in feats:
                            fp.features.append(tag)
    except FileNotFoundError:
        return None
    except Exception:
        pass

    try:
        r = subprocess.run(["sdptool", "browse", target],
                           capture_output=True, text=True, timeout=20)
        if r.returncode == 0 and r.stdout:
            text = r.stdout
            for proto in ("SDP", "RFCOMM", "L2CAP", "BNEP", "AVDTP", "A2DP",
                          "AVRCP", "HFP", "HSP", "HID", "PAN", "OBEX",
                          "PBAP", "MAP"):
                if proto.lower() in text.lower():
                    fp.services.append(proto)
            for m in re.findall(r"0x([0-9a-fA-F]{4})", text):
                fp.services.append(f"0x{m.upper()}")
            if fp.services:
                saw = True
    except Exception:
        pass

    return fp if saw else None


# ── Scoring ───────────────────────────────────────────────────────────────────

def _score_cve(rule: Dict[str, Any], fp: Fingerprint) -> Tuple[int, List[str]]:
    score = 0
    evidence: List[str] = []

    proto = (rule.get("protocol") or "").lower()
    if proto:
        if proto == "ble"     and fp.protocol == "CLASSIC": return 0, []
        if proto == "classic" and fp.protocol == "BLE":     return 0, []
        score += 15
        evidence.append(f"protocol={proto}")

    if rule.get("os"):
        if fp.os_guess in rule["os"]:
            score += 45
            evidence.append(f"os={fp.os_guess}")
        else:
            return 0, []

    if rule.get("vendor"):
        v = (fp.vendor or "").lower()
        for hint in rule["vendor"]:
            if hint.lower() in v:
                score += 35
                evidence.append(f"vendor~{hint}")
                break
        else:
            return 0, []

    svc_lower = [s.lower() for s in fp.services]
    for svc in rule.get("services", []):
        if svc.lower() in svc_lower or any(svc.lower() in s for s in svc_lower):
            score += 18
            evidence.append(f"svc:{svc}")

    for feat in rule.get("features", []):
        if feat in fp.features:
            score += 12
            evidence.append(f"feat:{feat}")

    for feat in rule.get("no_features", []):
        if feat not in fp.features:
            score += 18
            evidence.append(f"missing:{feat}")

    return min(score, 100), evidence


def _confidence_tier(score: int) -> Tuple[str, str]:
    C = Colors
    if score >= 75: return "CONFIRMED", C.RED
    if score >= 55: return "LIKELY",    C.YELLOW
    if score >= 35: return "POSSIBLE",  C.BLUE
    return "WEAK",                       C.DARK_GREY


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── Module ────────────────────────────────────────────────────────────────────

class Module(ScannerModule):
    """
    Unified vulnerability scanner — BLE GATT deep analysis + CVE matcher
    backed by the live module catalogue.
    """

    info = ModuleInfo(
        name="scanners/vuln_scanner",
        description="Unified BLE+Classic vulnerability scanner — GATT deep analysis + CVE→module matcher",
        author=["BlueSploit"],
        protocol=BTProtocol.BOTH,
        severity=Severity.HIGH,
        references=[
            "https://nvd.nist.gov/",
            "https://www.bluetooth.com/security/",
            "https://www.usenix.org/conference/usenixsecurity19/presentation/wu-jianliang",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)",
            ),
            "protocol": ModuleOption(
                name="protocol", required=False, default="auto",
                description="Protocol: auto, ble, classic, both",
            ),
            "gatt_scan": ModuleOption(
                name="gatt_scan", required=False, default=True,
                description="Run BLE GATT deep analysis (services/characteristics)",
            ),
            "test_writes": ModuleOption(
                name="test_writes", required=False, default=False,
                description="Actively probe writable characteristics (modifies state!)",
            ),
            "deep_scan": ModuleOption(
                name="deep_scan", required=False, default=True,
                description="Read sensitive readable characteristics (info-leak check)",
            ),
            "timeout": ModuleOption(
                name="timeout", required=False, default=20,
                description="Per-phase timeout in seconds",
            ),
            "min_score": ModuleOption(
                name="min_score", required=False, default=35,
                description="Hide CVE matches below this confidence score (0-100)",
            ),
            "output_file": ModuleOption(
                name="output_file", required=False, default=None,
                description="Save full report to JSON",
            ),
        }

    # ── Run async helpers ───────────────────────────────────────────────────

    @staticmethod
    def _run_async(coro):
        try:
            return asyncio.run(coro)
        except RuntimeError as e:
            if "running event loop" not in str(e):
                raise
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    # ── Fingerprint pipeline ────────────────────────────────────────────────

    def _fingerprint(
        self, target: str, mode: str, timeout: int, gatt_scan: bool,
        test_writes: bool, deep_scan: bool,
    ) -> Tuple[Fingerprint, GattReport]:
        fp_ble:     Optional[Fingerprint] = None
        fp_classic: Optional[Fingerprint] = None
        gatt_rep:   GattReport            = GattReport()

        # Phase A — BLE
        if mode in ("auto", "ble", "both") and BLEAK_AVAILABLE:
            try:
                fp_ble = self._run_async(_ble_passive_adv(target, timeout))
            except Exception:
                fp_ble = None

            if fp_ble and gatt_scan:
                try:
                    fp_extra, gatt_rep = self._run_async(
                        _ble_gatt_deep(target, timeout, test_writes, deep_scan)
                    )
                    if fp_extra:
                        if fp_extra.name and not fp_ble.name:
                            fp_ble.name = fp_extra.name
                        for s in fp_extra.services:
                            if s not in fp_ble.services:
                                fp_ble.services.append(s)
                except Exception:
                    pass
        elif mode in ("auto", "ble", "both") and not BLEAK_AVAILABLE:
            print_warning("bleak not installed — BLE analysis skipped (pip install bleak)")

        # Phase B — Classic (skipped in auto mode if address looks BLE-only)
        if mode in ("auto", "classic", "both"):
            if mode != "auto" or not _ble_address_likely(target) or fp_ble is None:
                try:
                    fp_classic = _classic_fingerprint(target)
                except Exception:
                    fp_classic = None

        if fp_ble and fp_classic:
            fp = fp_ble
            fp.protocol  = "BOTH"
            fp.services += [s for s in fp_classic.services if s not in fp.services]
            fp.features += fp_classic.features
            fp.lmp_version = fp_classic.lmp_version
            fp.vendor = fp.vendor or fp_classic.vendor
            fp.name   = fp.name   or fp_classic.name
        elif fp_ble:
            fp = fp_ble
        elif fp_classic:
            fp = fp_classic
        else:
            fp = Fingerprint(
                address=target.upper(),
                protocol="BLE" if _ble_address_likely(target) else "CLASSIC",
            )

        fp.os_guess = _classify_os(fp.name, fp.vendor, fp.address)
        return fp, gatt_rep

    # ── Output ─────────────────────────────────────────────────────────────

    def _banner(self) -> None:
        C = Colors
        print(f"\n  {C.RED}╔{'═'*70}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}Bluetooth Vulnerability Scanner — GATT × CVE × Module{C.RESET}           {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*70}╝{C.RESET}")

    def _print_fingerprint(self, fp: Fingerprint) -> None:
        C = Colors
        print(f"\n  {C.BOLD}TARGET FINGERPRINT{C.RESET}")
        print(f"  {C.CYAN}{'─'*75}{C.RESET}")
        print(f"  BD_ADDR     : {C.WHITE}{fp.address}{C.RESET}")
        print(f"  Protocol    : {C.GREEN}{fp.protocol}{C.RESET}"
              + (f"  ({fp.addr_type})" if fp.addr_type and fp.addr_type != "?" else ""))
        print(f"  Name        : {fp.name or '—'}")
        print(f"  Vendor      : {fp.vendor or '—'}")
        print(f"  OS Guess    : {C.YELLOW}{fp.os_guess}{C.RESET}")
        if fp.lmp_version: print(f"  LMP Version : {fp.lmp_version}")
        if fp.rssi is not None: print(f"  RSSI        : {fp.rssi} dBm")
        if fp.features:
            print(f"  Features    : {', '.join(fp.features[:8])}")
        if fp.services:
            print(f"  Services    : {', '.join(fp.services[:10])}"
                  + (f"  +{len(fp.services)-10} more" if len(fp.services) > 10 else ""))
        if fp.mfr_ids:
            print(f"  MFR IDs     : " + ", ".join(f"0x{m:04X}" for m in fp.mfr_ids[:5]))

    def _print_gatt_report(self, rep: GattReport) -> None:
        C = Colors
        if rep.services_count == 0 and not rep.vulns:
            return

        print(f"\n  {C.BOLD}BLE GATT ANALYSIS{C.RESET}")
        print(f"  {C.CYAN}{'─'*75}{C.RESET}")
        print(f"  Services             : {rep.services_count}")
        print(f"  Characteristics      : {rep.chars_count}")
        print(f"  Writable             : {C.YELLOW}{rep.writable_count}{C.RESET}")
        print(f"  Notify/Indicate      : {rep.notify_count}")
        print(f"  Confirmed Unauth Wrt : {C.RED if rep.unauth_write_count else C.RESET}{rep.unauth_write_count}{C.RESET}")
        print(f"  Info Disclosures     : {rep.info_leak_count}")
        print(f"  GATT Findings        : {C.RED if rep.vulns else C.GREEN}{len(rep.vulns)}{C.RESET}")

        if not rep.vulns:
            return

        sev_col = {
            GattSeverity.CRITICAL: C.RED + C.BOLD, GattSeverity.HIGH:   C.RED,
            GattSeverity.MEDIUM:   C.YELLOW,        GattSeverity.LOW:    C.GREEN,
            GattSeverity.INFO:     C.CYAN,
        }
        sev_ord = {GattSeverity.CRITICAL: 0, GattSeverity.HIGH: 1,
                   GattSeverity.MEDIUM: 2, GattSeverity.LOW: 3, GattSeverity.INFO: 4}
        for v in sorted(rep.vulns, key=lambda x: sev_ord[x.severity]):
            print(f"\n  {sev_col[v.severity]}[{v.severity.value}] {v.name}{C.RESET}")
            print(f"    Affected     : {v.affected}")
            print(f"    Description  : {v.description}")
            print(f"    Details      : {v.details}")
            print(f"    Recommend    : {v.recommendation}")

    def _print_cve_findings(self, findings: List[Dict[str, Any]]) -> None:
        C = Colors

        tally = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            tally[f["severity"]] = tally.get(f["severity"], 0) + 1

        print(f"\n  {C.BOLD}CVE × MODULE MATCHES{C.RESET}")
        print(f"  {C.CYAN}{'─'*75}{C.RESET}")
        print(f"  {C.RED}CRITICAL : {tally['CRITICAL']}{C.RESET}    "
              f"{C.YELLOW}HIGH : {tally['HIGH']}{C.RESET}    "
              f"{C.BLUE}MEDIUM : {tally['MEDIUM']}{C.RESET}    "
              f"LOW : {tally['LOW']}    "
              f"TOTAL : {len(findings)}")

        if not findings:
            print(f"\n  {C.GREEN}No CVE matches above the score threshold{C.RESET}")
            print(f"  {C.YELLOW}Note: target evidence didn't match any rule — could be patched,{C.RESET}")
            print(f"  {C.YELLOW}      OS guess wrong, or CVE requires intrusive verification.{C.RESET}")
            return

        print(f"  {C.YELLOW}Note: matches are FINGERPRINT predictions, not verified.{C.RESET}\n")
        for f in findings:
            cve  = f["cve"];   sev = f["severity"];   score = f["score"]
            tier, tier_col = _confidence_tier(score)
            sev_col = {"CRITICAL": C.RED, "HIGH": C.YELLOW,
                       "MEDIUM": C.BLUE, "LOW": C.WHITE}.get(sev, C.WHITE)
            print(f"  {sev_col}{C.BOLD}{cve}{C.RESET}  "
                  f"{sev_col}[{sev}]{C.RESET}  "
                  f"{tier_col}{tier} ({score}%){C.RESET}")
            if f["evidence"]:
                print(f"     evidence : {', '.join(f['evidence'][:5])}")
            for m in f["modules"]:
                print(f"     {C.GREEN}► use {m.use_path}{C.RESET}    "
                      f"{C.DARK_GREY}({m.severity}){C.RESET}")
            print()

    # ── Main run ────────────────────────────────────────────────────────────

    def run(self) -> bool:
        target = self.target
        if not target:
            print_error("Target not set")
            return False
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        mode        = (self.get_option("protocol") or "auto").lower()
        gatt_scan   = bool(self.get_option("gatt_scan"))
        test_writes = bool(self.get_option("test_writes"))
        deep_scan   = bool(self.get_option("deep_scan"))
        timeout     = int(self.get_option("timeout"))
        min_score   = int(self.get_option("min_score"))
        out_file    = self.get_option("output_file")
        if mode not in ("auto", "ble", "classic", "both"):
            print_error("protocol must be: auto, ble, classic, both")
            return False

        self._banner()
        print_info(f"Target    : {target}")
        print_info(f"Protocol  : {mode}")
        print_info(f"GATT scan : {gatt_scan}    Test writes: {test_writes}    Timeout: {timeout}s")

        if test_writes:
            print_warning("test_writes enabled — this may modify device state!")
            print_info("Continuing in 3s (Ctrl+C to abort)")
            try:
                time.sleep(3)
            except KeyboardInterrupt:
                print_warning("Cancelled")
                return False

        # Phase 1 — fingerprint + (optional) GATT deep analysis
        print_info("\n[1/3] Fingerprinting target...")
        fp, gatt_rep = self._fingerprint(
            target, mode, timeout, gatt_scan, test_writes, deep_scan,
        )
        self._print_fingerprint(fp)
        self._print_gatt_report(gatt_rep)

        # Phase 2 — load module catalogue
        print_info("\n[2/3] Indexing exploit/DoS/aux modules...")
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        cve_modules = _scan_module_tree(repo_root)
        print_success(
            f"Indexed {sum(len(v) for v in cve_modules.values())} CVE references "
            f"across {len(cve_modules)} unique CVEs"
        )

        # Phase 3 — CVE scoring
        print_info("\n[3/3] Matching CVEs against target evidence...")
        findings: List[Dict[str, Any]] = []

        for cve, rule in CVE_RULES.items():
            score, evidence = _score_cve(rule, fp)
            if score < min_score: continue
            modules = cve_modules.get(cve, [])
            if not modules: continue
            sev = max((m.severity for m in modules),
                      key=lambda s: -_SEV_ORDER.get(s, 99))
            findings.append({
                "cve": cve, "score": score, "evidence": evidence,
                "modules": modules, "severity": sev,
            })

        # Best-effort fallback: catch CVEs whose module description mentions
        # the OS guess but that aren't covered by an explicit rule.
        for cve, modules in cve_modules.items():
            if cve in CVE_RULES: continue
            related = [m for m in modules
                       if (fp.os_guess.lower() in m.description.lower()
                           or fp.os_guess.lower() in m.name.lower())]
            if not related: continue
            findings.append({
                "cve": cve, "score": 35, "evidence": [f"name~{fp.os_guess}"],
                "modules": related,
                "severity": max((m.severity for m in related),
                                key=lambda s: -_SEV_ORDER.get(s, 99)),
            })

        findings.sort(key=lambda f: (_SEV_ORDER.get(f["severity"], 99), -f["score"]))
        self._print_cve_findings(findings)

        # ── Hardening footer ────────────────────────────────────────────────
        C = Colors
        print(f"  {C.BOLD}HARDENING RECOMMENDATIONS{C.RESET}")
        print(f"  {C.CYAN}{'─'*75}{C.RESET}")
        if fp.protocol != "BLE" and "secure_connections" not in fp.features:
            print(f"  {C.YELLOW}• Enable Secure Connections (BR/EDR){C.RESET}")
        if fp.protocol != "BLE" and "ssp" not in fp.features:
            print(f"  {C.YELLOW}• Enable Secure Simple Pairing{C.RESET}")
        print(f"  {C.CYAN}• Apply latest vendor / OS security patches{C.RESET}")
        print(f"  {C.CYAN}• Disable Bluetooth when not in use{C.RESET}")
        print(f"  {C.CYAN}• Set device to non-discoverable mode{C.RESET}")
        print(f"  {C.CYAN}{'═'*75}{C.RESET}\n")

        # ── Persist ─────────────────────────────────────────────────────────
        report = {
            "target":   target,
            "protocol": fp.protocol,
            "name":     fp.name,
            "vendor":   fp.vendor,
            "os_guess": fp.os_guess,
            "lmp":      fp.lmp_version,
            "services": fp.services,
            "features": fp.features,
            "gatt": {
                "services":         gatt_rep.services_count,
                "characteristics":  gatt_rep.chars_count,
                "writable":         gatt_rep.writable_count,
                "notify_indicate":  gatt_rep.notify_count,
                "unauth_writes":    gatt_rep.unauth_write_count,
                "info_leaks":       gatt_rep.info_leak_count,
                "findings": [
                    {"name": v.name, "severity": v.severity.value,
                     "description": v.description, "affected": v.affected,
                     "details": v.details, "recommendation": v.recommendation}
                    for v in gatt_rep.vulns
                ],
            },
            "cve_findings": [
                {"cve": f["cve"], "severity": f["severity"], "score": f["score"],
                 "evidence": f["evidence"],
                 "modules": [m.use_path for m in f["modules"]]}
                for f in findings
            ],
        }
        self.add_result(report)

        if out_file:
            try:
                with open(out_file, "w") as fp_out:
                    json.dump(report, fp_out, indent=2)
                print_success(f"Saved report → {out_file}")
            except Exception as e:
                print_error(f"Save failed: {e}")

        return bool(findings) or bool(gatt_rep.vulns) or gatt_rep.services_count > 0
