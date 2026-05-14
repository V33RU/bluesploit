"""
BlueSploit Module: SDP Service Enumerator (Advanced)
=====================================================

Deep enumeration + risk analysis of an SDP service catalogue on a Bluetooth
Classic target. Beyond the basic `sdptool browse` listing, this module:

  • **Risk-scores** every discovered service against a curated UUID → (severity,
    description, CVEs, suggested modules) map. The catch list covers HID
    (CVE-2023-45866), BNEP/PAN (BlueBorne CVE-2017-0781), OBEX FTP/OPP
    (BlueSnarfing), HFP/HSP (RFCOMM AT-command RCE), PBAP/MAP/SIM Access
    (privacy leak), A2DP/AVRCP (BlueFrag CVE-2020-0022), DUN, SDP itself
    (CVE-2017-0785), and so on.
  • **Decodes PnP Information (UUID 0x1200)**, vendor ID source, vendor ID,
    product ID, firmware version, and resolves common Bluetooth-SIG / USB
    vendor IDs to human names.
  • **Probes L2CAP PSMs** discovered in the records to confirm they are
    actually reachable (not just advertised), concurrent, low-timeout.
  • **Parses XML** (`sdptool browse --xml`) into structured attribute
    records, extracting Security/Class attributes that the plain-text
    parser misses.
  • **ANSI-safe table output** so the final view stays aligned regardless
    of the terminal width or color codes.

Modes:
    browse , standard `sdptool browse` parse (legacy default behavior)
    full   , browse + risk + pnp + l2cap-probe + xml-attrs (recommended)
    records, raw `sdptool records` dump
    tree   , raw `sdptool browse --tree` dump
"""

import json
import re
import socket
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.base import (
    BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity, Target,
)
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)


# ── Reference tables ──────────────────────────────────────────────────────────

KNOWN_SERVICES: Dict[str, str] = {
    "0x1000": "Service Discovery Server",
    "0x1001": "Browse Group Descriptor",
    "0x1002": "Public Browse Root",
    "0x1101": "Serial Port (SPP)",
    "0x1102": "LAN Access Using PPP",
    "0x1103": "Dialup Networking (DUN)",
    "0x1104": "IrMC Sync",
    "0x1105": "OBEX Object Push (OPP)",
    "0x1106": "OBEX File Transfer (FTP)",
    "0x1107": "IrMC Sync Command",
    "0x1108": "Headset",
    "0x1109": "Cordless Telephony",
    "0x110a": "Audio Source",
    "0x110b": "Audio Sink",
    "0x110c": "A/V Remote Control Target",
    "0x110d": "Advanced Audio Distribution (A2DP)",
    "0x110e": "A/V Remote Control",
    "0x110f": "A/V Remote Control Controller",
    "0x1110": "Intercom",
    "0x1111": "Fax",
    "0x1112": "Headset Audio Gateway",
    "0x1115": "PANU",
    "0x1116": "NAP",
    "0x1117": "GN",
    "0x1124": "Human Interface Device (HID)",
    "0x111e": "Handsfree",
    "0x111f": "Handsfree Audio Gateway",
    "0x112d": "SIM Access",
    "0x112e": "Phonebook Access PCE",
    "0x112f": "Phonebook Access PSE",
    "0x1130": "Phonebook Access",
    "0x1132": "Message Access Server",
    "0x1133": "Message Notification Server",
    "0x1134": "Message Access Profile",
    "0x1200": "PnP Information",
    "0x1300": "ESDP UPNP IP PAN",
    "0x1303": "Video Source",
    "0x1304": "Video Sink",
    "0x1305": "Video Distribution",
    "0x1400": "HDP",
}

KNOWN_PROTOCOLS: Dict[str, str] = {
    "0x0001": "SDP",       "0x0002": "UDP",        "0x0003": "RFCOMM",
    "0x0004": "TCP",       "0x0005": "TCS-BIN",    "0x0006": "TCS-AT",
    "0x0007": "ATT",       "0x0008": "OBEX",       "0x0009": "IP",
    "0x000a": "FTP",       "0x000c": "HTTP",       "0x000e": "WSP",
    "0x000f": "BNEP",      "0x0010": "UPNP",       "0x0011": "HIDP",
    "0x0017": "AVCTP",     "0x0019": "AVDTP",      "0x001b": "CMTP",
    "0x001e": "MCAP-CTRL", "0x001f": "MCAP-DATA",  "0x0100": "L2CAP",
}


# ── Risk database ─────────────────────────────────────────────────────────────

@dataclass
class Risk:
    severity:   str            # CRITICAL | HIGH | MEDIUM | LOW
    summary:    str
    cves:       List[str] = field(default_factory=list)
    modules:    List[str] = field(default_factory=list)


RISK_MAP: Dict[str, Risk] = {
    # HID, keystroke injection (BlueDucky / CVE-2023-45866)
    "0x1124": Risk("CRITICAL",
        "HID profile reachable, 0-click keystroke injection if peer accepts unauth HID reports.",
        ["CVE-2023-45866"],
        ["exploits/classic/keystroke_injection_android_linux",
         "exploits/classic/keystroke_injection_apple",
         "exploits/classic/keystroke_injection_windows"]),

    # SIM Access, direct SIM commands → cloning surface
    "0x112d": Risk("CRITICAL",
        "SIM Access Profile, direct SIM/USIM commands, IMSI/Ki extraction surface.",
        [], []),

    # OBEX FTP, BlueSnarfing
    "0x1106": Risk("HIGH",
        "OBEX File Transfer, historically allows unauthenticated filesystem browse (BlueSnarfing).",
        ["CVE-2004-1001"],
        ["exploits/classic/bluesnarfing", "exploits/classic/obex_exploit"]),

    # OBEX OPP, BlueJacking / vCard injection
    "0x1105": Risk("HIGH",
        "OBEX Object Push, accepts unauth object pushes (BlueJacking, vCard/vCal injection).",
        [],
        ["exploits/classic/obex_exploit", "exploits/classic/bluesnarfing"]),

    # PAN family, BlueBorne BNEP overflow
    "0x1115": Risk("HIGH",
        "PANU, BNEP frames reachable; BlueBorne BNEP overflow code path.",
        ["CVE-2017-0781"],
        ["exploits/classic/blueborne_bnep_overflow",
         "exploits/classic/bnep_heap_disclosure"]),
    "0x1116": Risk("HIGH",
        "NAP, BNEP + IP routing; larger attack surface than PANU.",
        ["CVE-2017-0781"],
        ["exploits/classic/blueborne_bnep_overflow"]),
    "0x1117": Risk("MEDIUM",
        "GN, BNEP-based, same BlueBorne surface.",
        ["CVE-2017-0781"], []),

    # HFP / HSP, AT-command RCE
    "0x111e": Risk("HIGH",
        "Hands-Free Profile, large RFCOMM AT-command attack surface; multiple recent Android RCE bugs.",
        ["CVE-2023-21347", "CVE-2024-0039", "CVE-2025-22403"],
        ["exploits/classic/hfp_rce_2023", "exploits/classic/android_hfp_uaf_2025"]),
    "0x111f": Risk("HIGH",
        "Handsfree Audio Gateway, same AT-command surface.",
        [],
        ["exploits/classic/hfp_rce_2023"]),
    "0x1108": Risk("MEDIUM",
        "Headset profile, RFCOMM AT-command channel reachable.",
        ["CVE-2023-21347"], []),
    "0x1112": Risk("MEDIUM",
        "Headset Audio Gateway, AT command RFCOMM channel.",
        [], []),

    # Phonebook / messaging, privacy leak
    "0x112e": Risk("MEDIUM",
        "Phonebook Access Client, peer can be tricked into exposing contacts.",
        [], []),
    "0x112f": Risk("HIGH",
        "Phonebook Access Server, contacts/call-log readable; auto-bond car-kits often expose this.",
        [], ["exploits/classic/bluebugging"]),
    "0x1130": Risk("HIGH",
        "Phonebook Access, privacy leak of contacts and call history.",
        [], []),
    "0x1132": Risk("HIGH",
        "Message Access Server, exposes SMS/MMS/IM messages.",
        [], []),
    "0x1133": Risk("MEDIUM",
        "Message Notification Server, message metadata leak.",
        [], []),
    "0x1134": Risk("HIGH",
        "Message Access Profile, historical privacy breach in car-kit pairings.",
        [], []),

    # A2DP / AVRCP, BlueFrag
    "0x110d": Risk("HIGH",
        "A2DP, AVDTP signalling reachable; BlueFrag heap overflow targets this on Android.",
        ["CVE-2020-0022"],
        ["exploits/classic/bluefrag", "dos/a2dp_flood"]),
    "0x110a": Risk("MEDIUM",
        "AVDTP audio source, same BlueFrag code path.",
        ["CVE-2020-0022"], []),
    "0x110b": Risk("MEDIUM",
        "AVDTP audio sink, same code path.",
        ["CVE-2020-0022"], []),
    "0x110c": Risk("MEDIUM",
        "AVRCP Target, older Android AVRCP RCEs.",
        ["CVE-2017-13258"], []),
    "0x110e": Risk("MEDIUM",
        "AVRCP, same AVRCP RCE family.",
        ["CVE-2017-13258"], []),

    # Serial / Dialup, open data channels
    "0x1101": Risk("MEDIUM",
        "Serial Port (SPP), raw RFCOMM channel; auth depends entirely on the application above.",
        [], ["exploits/classic/rfcomm_shell"]),
    "0x1103": Risk("HIGH",
        "Dialup Networking, AT-command channel; modem command injection / PIN brute possible.",
        [],
        ["exploits/classic/helomoto", "exploits/classic/bluebugging"]),
    "0x1102": Risk("MEDIUM",
        "Legacy LAN Access PPP, outdated, often weak auth.",
        [], []),

    # SDP itself (BlueBorne info leak)
    "0x0001": Risk("MEDIUM",
        "SDP server reachable, BlueBorne SDP heap leak abuses continuation state.",
        ["CVE-2017-0785"],
        ["exploits/classic/blueborne_sdp_leak"]),

    # IrMC Sync, old privacy leak
    "0x1104": Risk("MEDIUM",
        "Sync profile may expose phonebook/calendar without authentication on legacy stacks.",
        [], []),
    "0x1107": Risk("MEDIUM",
        "IrMC Sync Command, same legacy disclosure risk.",
        [], []),
}

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ── PnP Information (UUID 0x1200) decoder ─────────────────────────────────────
#
# Attribute IDs (Bluetooth SIG, Device ID Service):
#   0x0200 SpecificationID, 0x0201 VendorID,    0x0202 ProductID,
#   0x0203 Version,         0x0204 PrimaryRecord, 0x0205 VendorIDSource

PNP_VENDOR_SOURCE = {1: "Bluetooth SIG", 2: "USB"}

# Tiny subset of common USB vendors (vid → name). Keeps us from shipping a
# 30k-row CSV; covers the vendors most likely to show up on a BT host stack.
USB_VENDOR_DB: Dict[int, str] = {
    0x004C: "Apple",            0x05AC: "Apple",
    0x05E0: "Symbol",           0x046D: "Logitech",
    0x047D: "Kensington",       0x04CA: "Lite-On",
    0x04F2: "Chicony",          0x05C6: "Qualcomm",
    0x0489: "Foxconn",          0x0B05: "ASUSTek",
    0x0BDA: "Realtek",          0x0CF3: "Atheros / Qualcomm",
    0x0E0F: "VMware",           0x13D3: "IMC Networks",
    0x1A6E: "Global Unichip",   0x1D6B: "Linux Foundation",
    0x8086: "Intel",            0x8087: "Intel",
    0x004D: "Intel",            0x18D1: "Google",
    0x22B8: "Motorola",         0x2717: "Xiaomi",
    0x2A45: "Meizu",            0x2C26: "OnePlus",
    0x05B5: "Dispan",           0x0930: "Toshiba",
    0x0A12: "Cambridge Silicon Radio (CSR)",
    0x0E8D: "MediaTek",         0x148F: "Ralink",
    0x0BB4: "HTC",              0x12D1: "Huawei",
    0x04E8: "Samsung",          0x054C: "Sony",
    0x091E: "Garmin",           0x1532: "Razer",
    0x05C8: "Cheng Uei",        0x174C: "ASMedia",
}

BT_SIG_VENDOR_DB: Dict[int, str] = {
    0x000F: "Broadcom",         0x004C: "Apple",
    0x0006: "Microsoft",        0x0075: "Samsung",
    0x00E0: "Google",           0x038F: "Espressif",
    0x0131: "Huawei",           0x0157: "Xiaomi",
    0x001D: "Qualcomm",         0x0002: "Intel",
    0x054C: "Sony",             0x0059: "Nordic",
    0x000D: "Texas Instr.",     0x012D: "Jabra",
    0x008A: "LG Elec.",         0x03DA: "Bose",
}


@dataclass
class PnPInfo:
    vendor_id_source: Optional[int] = None
    vendor_id:        Optional[int] = None
    product_id:       Optional[int] = None
    version:          Optional[str] = None
    vendor_name:      Optional[str] = None


def _decode_pnp_from_xml(record_xml: ET.Element) -> Optional[PnPInfo]:
    """Pull PnP attributes out of a single SDP <record> element."""
    attrs = {a.get("id", "").lower(): a for a in record_xml.findall("attribute")}
    if "0x0201" not in attrs:                       # No VendorID → not a PnP record
        return None

    pnp = PnPInfo()

    def _get_uint(node: ET.Element) -> Optional[int]:
        val = (node.find("uint16") if node.find("uint16") is not None
               else node.find("uint8"))
        if val is None or val.get("value") is None:
            return None
        try:
            return int(val.get("value"), 0)
        except Exception:
            return None

    if "0x0205" in attrs:
        pnp.vendor_id_source = _get_uint(attrs["0x0205"])
    if "0x0201" in attrs:
        pnp.vendor_id = _get_uint(attrs["0x0201"])
    if "0x0202" in attrs:
        pnp.product_id = _get_uint(attrs["0x0202"])
    if "0x0203" in attrs:
        v = _get_uint(attrs["0x0203"])
        if v is not None:
            # Version is BCD: high nibble of MSB = major, low nibble = minor, LSB = sub
            major = (v >> 8) & 0xFF
            minor = (v >> 4) & 0x0F
            sub   =  v       & 0x0F
            pnp.version = f"{major}.{minor}.{sub}"

    # Resolve vendor
    if pnp.vendor_id is not None:
        if pnp.vendor_id_source == 1:
            pnp.vendor_name = BT_SIG_VENDOR_DB.get(pnp.vendor_id)
        elif pnp.vendor_id_source == 2:
            pnp.vendor_name = USB_VENDOR_DB.get(pnp.vendor_id)

    return pnp


def _decode_pnp_from_text(raw_record: str) -> Optional[PnPInfo]:
    """Best-effort PnP extraction from `sdptool browse` plain output."""
    if "PnP Information" not in raw_record and "0x1200" not in raw_record:
        return None
    pnp = PnPInfo()
    # sdptool emits hexadecimal attribute values inline, match them
    m = re.search(r"VendorIDSource[^0-9a-fx]*0x([0-9a-fA-F]+)", raw_record)
    if m: pnp.vendor_id_source = int(m.group(1), 16)
    m = re.search(r"VendorID[^0-9a-fx]*0x([0-9a-fA-F]+)", raw_record)
    if m: pnp.vendor_id = int(m.group(1), 16)
    m = re.search(r"ProductID[^0-9a-fx]*0x([0-9a-fA-F]+)", raw_record)
    if m: pnp.product_id = int(m.group(1), 16)
    m = re.search(r"Version[^0-9a-fx]*0x([0-9a-fA-F]+)", raw_record)
    if m:
        v = int(m.group(1), 16)
        pnp.version = f"{(v>>8)&0xFF}.{(v>>4)&0x0F}.{v&0x0F}"
    if pnp.vendor_id is None:
        return None
    if pnp.vendor_id_source == 1:
        pnp.vendor_name = BT_SIG_VENDOR_DB.get(pnp.vendor_id)
    elif pnp.vendor_id_source == 2:
        pnp.vendor_name = USB_VENDOR_DB.get(pnp.vendor_id)
    return pnp


# ── L2CAP PSM probe ───────────────────────────────────────────────────────────

def _probe_l2cap(target: str, psm: int, timeout: float = 1.5) -> bool:
    """
    Try a non-blocking L2CAP connect to (target, psm). Returns True on
    successful TCP-style handshake (connection accepted).
    """
    BTPROTO_L2CAP = 0
    AF_BLUETOOTH  = 31
    s = None
    try:
        s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        s.settimeout(timeout)
        s.connect((target, psm))
        return True
    except (OSError, socket.timeout, ConnectionRefusedError):
        return False
    except Exception:
        return False
    finally:
        try:
            if s: s.close()
        except Exception:
            pass


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class SDPService:
    name:            str
    service_classes: List[Dict[str, str]] = field(default_factory=list)
    protocols:       List[Dict[str, str]] = field(default_factory=list)
    profiles:        List[Dict[str, str]] = field(default_factory=list)
    provider:        str               = ""
    description:     str               = ""
    record_handle:   str               = ""
    channel:         Optional[int]     = None    # RFCOMM
    psm:             Optional[int]     = None    # L2CAP
    psm_reachable:   Optional[bool]    = None    # filled by probe
    raw:             str               = ""
    # Risk
    risk:            Optional[Risk]    = None
    risk_uuid:       Optional[str]     = None


# ── ANSI-safe padding (mirror discovery.py) ───────────────────────────────────

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
def _vis(s: str) -> int:    return len(_ANSI_RE.sub("", s))
def _cpad(s: str, w: int) -> str: return s + " " * max(0, w - _vis(s))


# ── Module ────────────────────────────────────────────────────────────────────

class Module(ScannerModule):
    """
    Advanced SDP enumerator with risk analysis, PnP decoding, and L2CAP
    reachability probes.
    """

    info = ModuleInfo(
        name="recon/sdp_enum",
        description="Advanced SDP enumerator, risk + CVE map, PnP decode, L2CAP probe",
        author=["BlueSploit"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/",
            "https://www.bluetooth.com/specifications/specs/device-identification-profile-1-3/",
            "https://www.bluez.org/",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)",
            ),
            "mode": ModuleOption(
                name="mode", required=False, default="full",
                description="Mode: full | browse | records | tree",
            ),
            "search": ModuleOption(
                name="search", required=False, default=None,
                description="Search a specific service (SP, DUN, OPP, FTP, HID, NAP, …)",
            ),
            "probe_l2cap": ModuleOption(
                name="probe_l2cap", required=False, default=True,
                description="Attempt L2CAP connect on each PSM to confirm reachability",
            ),
            "decode_pnp": ModuleOption(
                name="decode_pnp", required=False, default=True,
                description="Decode PnP Information record (UUID 0x1200)",
            ),
            "xml_attrs": ModuleOption(
                name="xml_attrs", required=False, default=True,
                description="Also fetch & parse XML attribute records",
            ),
            "timeout": ModuleOption(
                name="timeout", required=False, default=30,
                description="Per-command timeout in seconds",
            ),
            "output_file": ModuleOption(
                name="output_file", required=False, default=None,
                description="Save the full structured report to JSON",
            ),
        }

    # ── sdptool helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _have_sdptool() -> bool:
        try:
            r = subprocess.run(["which", "sdptool"], capture_output=True, timeout=5)
            return r.returncode == 0
        except Exception:
            return False

    def _run_sdptool(self, args: List[str], timeout: int) -> Optional[str]:
        try:
            r = subprocess.run(["sdptool"] + args,
                               capture_output=True, text=True, timeout=timeout)
            if r.returncode != 0 and r.stderr:
                print_warning(f"sdptool: {r.stderr.strip().splitlines()[-1]}")
            return r.stdout
        except subprocess.TimeoutExpired:
            print_error(f"sdptool timed out after {timeout}s")
        except Exception as e:
            print_error(f"sdptool error: {e}")
        return None

    @staticmethod
    def _service_name(uuid: str) -> str:
        u = uuid.lower()
        if not u.startswith("0x"):
            u = "0x" + u
        return KNOWN_SERVICES.get(u, f"Unknown ({uuid})")

    @staticmethod
    def _normalize_uuid(s: str) -> str:
        s = s.lower()
        if s.startswith("0x") and len(s) >= 6:
            return f"0x{s[-4:]}"
        if re.fullmatch(r"[0-9a-f]{4}", s):
            return f"0x{s}"
        return s

    # ── Plain-text parser ───────────────────────────────────────────────────

    def _parse_browse(self, output: str) -> List[SDPService]:
        """Parse the human-readable `sdptool browse` output."""
        services: List[SDPService] = []
        cur:      Optional[SDPService] = None
        section:  Optional[str] = None
        raw:      List[str] = []

        for line in output.split("\n"):
            stripped = line.rstrip()
            if line.startswith("Service Name:"):
                if cur:
                    cur.raw = "\n".join(raw)
                    services.append(cur)
                    raw = []
                cur = SDPService(name=stripped.split(":", 1)[1].strip() or "Unknown")
                section = None
                continue

            if cur is None:
                continue
            raw.append(stripped)

            if stripped.startswith("Service RecHandle:"):
                cur.record_handle = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Service Provider:"):
                cur.provider = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Service Description:"):
                cur.description = stripped.split(":", 1)[1].strip()
            elif "Service Class ID List:" in stripped:
                section = "classes"
            elif "Protocol Descriptor List:" in stripped:
                section = "protocols"
            elif "Profile Descriptor List:" in stripped:
                section = "profiles"
            elif "Language Base Attr List:" in stripped:
                section = None

            elif section == "classes":
                m = re.search(r'"([^"]+)".*?\((0x[0-9a-fA-F]+)\)', stripped)
                if m:
                    cur.service_classes.append({"name": m.group(1), "uuid": m.group(2)})
                else:
                    m = re.search(r"UUID:\s*(0x[0-9a-fA-F]+)", stripped)
                    if m:
                        u = m.group(1)
                        cur.service_classes.append(
                            {"name": self._service_name(u), "uuid": u})

            elif section == "protocols":
                m = re.search(r'"([^"]+)".*?\((0x[0-9a-fA-F]+)\)', stripped)
                if m:
                    cur.protocols.append({"name": m.group(1), "uuid": m.group(2)})
                m = re.search(r"Channel:\s*(\d+)", stripped)
                if m: cur.channel = int(m.group(1))
                m = re.search(r"PSM:\s*(\d+)", stripped)
                if m: cur.psm = int(m.group(1))

            elif section == "profiles":
                m = re.search(
                    r'"([^"]+)".*?\((0x[0-9a-fA-F]+)\).*?Version:\s*(0x[0-9a-fA-F]+)',
                    stripped)
                if m:
                    cur.profiles.append({"name": m.group(1),
                                         "uuid": m.group(2),
                                         "version": m.group(3)})

        if cur:
            cur.raw = "\n".join(raw)
            services.append(cur)
        return services

    # ── XML attribute parser (sdptool browse --xml) ─────────────────────────

    def _parse_xml_records(self, xml_text: str) -> Dict[str, Dict[str, str]]:
        """
        Return a dict keyed by record handle → { attr_id_hex: text_value }.
        Wraps the sdptool XML in a synthetic root since it emits a stream
        of <record> siblings.
        """
        out: Dict[str, Dict[str, str]] = {}
        if not xml_text.strip():
            return out
        try:
            root = ET.fromstring(f"<root>{xml_text}</root>")
        except ET.ParseError:
            return out
        for rec in root.findall("record"):
            rec_attrs: Dict[str, str] = {}
            for attr in rec.findall("attribute"):
                aid = (attr.get("id") or "").lower()
                # Capture first scalar child
                for child in attr:
                    val = child.get("value", "")
                    if val:
                        rec_attrs[aid] = val
                        break
            handle = rec_attrs.get("0x0000", "")
            out[handle] = rec_attrs
        return out

    # ── L2CAP PSM probing (concurrent) ──────────────────────────────────────

    def _probe_psms(self, target: str, services: List[SDPService]) -> None:
        psms = [s for s in services if s.psm]
        if not psms:
            return
        print_info(f"Probing {len(psms)} L2CAP PSM(s)...")
        threads: List[threading.Thread] = []
        results: Dict[int, bool] = {}

        def _worker(psm: int) -> None:
            results[psm] = _probe_l2cap(target, psm, timeout=1.5)

        for s in psms:
            t = threading.Thread(target=_worker, args=(s.psm,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=3)

        for s in services:
            if s.psm is not None:
                s.psm_reachable = results.get(s.psm, False)

    # ── Risk annotation ─────────────────────────────────────────────────────

    def _annotate_risk(self, services: List[SDPService]) -> None:
        for s in services:
            for c in s.service_classes:
                u = self._normalize_uuid(c.get("uuid", ""))
                if u in RISK_MAP:
                    s.risk = RISK_MAP[u]
                    s.risk_uuid = u
                    break

    # ── Output ──────────────────────────────────────────────────────────────

    def _print_table(self, target: str, services: List[SDPService]) -> None:
        C = Colors
        if not services:
            print_warning("No services found")
            return

        # Sort: risky first (CRITICAL → HIGH → MEDIUM → LOW → none)
        def _key(s: SDPService) -> int:
            if s.risk is None: return 99
            return _SEV_ORDER.get(s.risk.severity, 99)
        services = sorted(services, key=_key)

        W = {"#": 4, "NAME": 30, "UUID": 9, "CHAN": 6, "PSM": 7, "REACH": 7, "PROTO": 12, "RISK": 12}
        total = sum(W.values())

        print(f"\n  {C.CYAN}{'═'*(total+2)}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}SDP ENUMERATION ,  {target}  ·  {len(services)} service(s){C.RESET}")
        print(f"  {C.CYAN}{'═'*(total+2)}{C.RESET}")

        # Header
        hdr = (f"  {C.BOLD}{'#':<{W['#']}}{'SERVICE':<{W['NAME']}}{'UUID':<{W['UUID']}}"
               f"{'CHAN':<{W['CHAN']}}{'PSM':<{W['PSM']}}{'REACH':<{W['REACH']}}"
               f"{'PROTO':<{W['PROTO']}}{'RISK':<{W['RISK']}}{C.RESET}")
        print(hdr)
        print("  " + "─" * total)

        for idx, s in enumerate(services, 1):
            name = (s.name[:W["NAME"]-2] + "..") if len(s.name) > W["NAME"] else s.name
            uuid = s.service_classes[0]["uuid"] if s.service_classes else "-"
            chan = str(s.channel) if s.channel else "-"
            psm  = str(s.psm)     if s.psm     else "-"

            if s.psm is None:
                reach = "-"
            elif s.psm_reachable is True:
                reach = f"{C.GREEN}OPEN{C.RESET}"
            elif s.psm_reachable is False:
                reach = f"{C.DARK_GREY}closed{C.RESET}"
            else:
                reach = "?"

            proto = s.protocols[0]["name"][:W["PROTO"]-1] if s.protocols else "-"

            if s.risk is None:
                risk_cell = f"{C.DARK_GREY}-{C.RESET}"
            else:
                col = {"CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
                       "MEDIUM": C.YELLOW,         "LOW": C.GREEN}.get(s.risk.severity, C.WHITE)
                risk_cell = f"{col}{s.risk.severity}{C.RESET}"

            row = (
                f"  {idx:<{W['#']}}"
                f"{name:<{W['NAME']}}"
                f"{uuid:<{W['UUID']}}"
                f"{chan:<{W['CHAN']}}"
                f"{psm:<{W['PSM']}}"
                f"{_cpad(reach, W['REACH'])}"
                f"{proto:<{W['PROTO']}}"
                f"{_cpad(risk_cell, W['RISK'])}"
            )
            print(row)

        print("  " + "─" * total)

    def _print_risk(self, services: List[SDPService]) -> None:
        risky = [s for s in services if s.risk is not None]
        if not risky:
            return
        C = Colors
        print(f"\n  {C.BOLD}RISK FINDINGS{C.RESET}")
        print(f"  {C.CYAN}{'─'*78}{C.RESET}")

        for s in sorted(risky, key=lambda x: _SEV_ORDER.get(x.risk.severity, 99)):
            r = s.risk
            sev_col = {"CRITICAL": C.RED + C.BOLD, "HIGH": C.RED,
                       "MEDIUM": C.YELLOW,         "LOW": C.GREEN}.get(r.severity, C.WHITE)
            print(f"\n  {sev_col}[{r.severity}] {s.name}{C.RESET}  "
                  f"{C.DARK_GREY}({s.risk_uuid}){C.RESET}")
            print(f"    {r.summary}")
            if r.cves:
                print(f"    {C.YELLOW}CVEs       :{C.RESET} {', '.join(r.cves)}")
            if r.modules:
                for m in r.modules:
                    print(f"    {C.GREEN}► use {m}{C.RESET}")
            if s.channel:
                print(f"    {C.DARK_GREY}RFCOMM channel:{C.RESET} {s.channel}")
            if s.psm:
                tag = ("open" if s.psm_reachable
                       else "closed" if s.psm_reachable is False
                       else "untested")
                print(f"    {C.DARK_GREY}L2CAP PSM    :{C.RESET} {s.psm}  ({tag})")

    def _print_pnp(self, pnp: Optional[PnPInfo]) -> None:
        if pnp is None:
            return
        C = Colors
        print(f"\n  {C.BOLD}DEVICE IDENTIFICATION (PnP){C.RESET}")
        print(f"  {C.CYAN}{'─'*78}{C.RESET}")
        if pnp.vendor_id is not None:
            src = (PNP_VENDOR_SOURCE.get(pnp.vendor_id_source, f"src={pnp.vendor_id_source}")
                   if pnp.vendor_id_source else "src=?")
            vname = pnp.vendor_name or f"Unknown vendor"
            print(f"  Vendor      : {C.WHITE}0x{pnp.vendor_id:04X}{C.RESET}  ({src})  → {vname}")
        if pnp.product_id is not None:
            print(f"  Product     : 0x{pnp.product_id:04X}")
        if pnp.version:
            print(f"  Version     : {pnp.version}")

    def _print_summary(self, services: List[SDPService]) -> None:
        C = Colors
        rfcomm = [s for s in services if s.channel]
        l2cap  = [s for s in services if s.psm]
        risky  = [s for s in services if s.risk is not None]
        criti  = sum(1 for s in risky if s.risk.severity == "CRITICAL")
        high   = sum(1 for s in risky if s.risk.severity == "HIGH")

        print(f"\n  {C.BOLD}SUMMARY{C.RESET}  "
              f"Total: {len(services)}   RFCOMM: {len(rfcomm)}   L2CAP-PSM: {len(l2cap)}   "
              f"{C.RED}CRIT: {criti}{C.RESET}  {C.YELLOW}HIGH: {high}{C.RESET}  "
              f"Risk: {len(risky)}")
        print(f"  {C.CYAN}{'═'*80}{C.RESET}\n")

    # ── Save ────────────────────────────────────────────────────────────────

    def _save(self, target: str, services: List[SDPService],
              pnp: Optional[PnPInfo], xml_attrs: Dict[str, Dict[str, str]],
              path: str) -> None:
        report: Dict[str, Any] = {
            "target":          target,
            "service_count":   len(services),
            "pnp": (
                {"vendor_id_source": pnp.vendor_id_source,
                 "vendor_id":   pnp.vendor_id,
                 "product_id":  pnp.product_id,
                 "version":     pnp.version,
                 "vendor_name": pnp.vendor_name}
                if pnp else None
            ),
            "xml_attribute_records": xml_attrs,
            "services": [
                {"name":             s.name,
                 "record_handle":    s.record_handle,
                 "provider":         s.provider,
                 "description":      s.description,
                 "channel":          s.channel,
                 "psm":              s.psm,
                 "psm_reachable":    s.psm_reachable,
                 "service_classes":  s.service_classes,
                 "protocols":        s.protocols,
                 "profiles":         s.profiles,
                 "risk": (
                     {"severity":  s.risk.severity,
                      "uuid":      s.risk_uuid,
                      "summary":   s.risk.summary,
                      "cves":      s.risk.cves,
                      "modules":   s.risk.modules}
                     if s.risk else None),
                 }
                for s in services
            ],
        }
        try:
            with open(path, "w") as f:
                json.dump(report, f, indent=2)
            print_success(f"Saved report → {path}")
        except Exception as e:
            print_error(f"Save failed: {e}")

    # ── Main ────────────────────────────────────────────────────────────────

    def run(self) -> bool:
        target = self.target
        if not target:
            print_error("Target not set")
            return False
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        if not self._have_sdptool():
            print_error("sdptool not found, install BlueZ (`sudo apt install bluez`)")
            return False

        mode        = (self.get_option("mode") or "full").lower()
        search      = self.get_option("search")
        timeout     = int(self.get_option("timeout"))
        do_probe    = bool(self.get_option("probe_l2cap"))
        do_pnp      = bool(self.get_option("decode_pnp"))
        do_xml      = bool(self.get_option("xml_attrs"))
        out_file    = self.get_option("output_file")

        print_info(f"SDP Enumeration  Target: {target}  Mode: {mode}")

        # Pass-through legacy modes
        if mode == "records":
            output = self._run_sdptool(["records", target], timeout)
            if output:
                print(output)
            return bool(output)
        if mode == "tree":
            output = self._run_sdptool(["browse", "--tree", target], timeout)
            if output:
                print(output)
            return bool(output)

        # Browse / search
        if search:
            print_info(f"Searching '{search}'...")
            output = self._run_sdptool(["search", "--bdaddr", target, search], timeout)
        else:
            output = self._run_sdptool(["browse", target], timeout)

        if not output:
            print_warning("No SDP response, device out of range, paired-only, or stack patched")
            return False

        services = self._parse_browse(output)
        if not services:
            print_warning("Browse returned data but no services parsed")
            return False
        print_success(f"Parsed {len(services)} service record(s)")

        # Risk annotation
        self._annotate_risk(services)

        # PnP decoding (try XML first for accuracy, fall back to text)
        pnp:        Optional[PnPInfo] = None
        xml_attrs:  Dict[str, Dict[str, str]] = {}

        if mode == "full":
            if do_xml:
                xml = self._run_sdptool(["browse", "--xml", target], timeout) or ""
                xml_attrs = self._parse_xml_records(xml)
                if do_pnp and xml.strip():
                    try:
                        root = ET.fromstring(f"<root>{xml}</root>")
                        for rec in root.findall("record"):
                            pnp = _decode_pnp_from_xml(rec)
                            if pnp: break
                    except ET.ParseError:
                        pass

            if do_pnp and pnp is None:
                # text fallback
                for s in services:
                    if "PnP" in s.name or "0x1200" in s.raw:
                        pnp = _decode_pnp_from_text(s.raw)
                        if pnp: break

            if do_probe:
                self._probe_psms(target, services)

        # ── Render ────────────────────────────────────────────────────────
        self._print_table(target, services)
        if pnp:
            self._print_pnp(pnp)
        self._print_risk(services)
        self._print_summary(services)

        # ── Persist ──────────────────────────────────────────────────────
        result = {
            "target":   target,
            "services": services,
            "pnp":      pnp,
            "xml":      xml_attrs,
        }
        self.add_result(result)
        for s in services:
            self.add_device(Target(
                address=target,
                name=s.name,
                device_type="Bluetooth Classic",
                metadata={
                    "channel":         s.channel,
                    "psm":             s.psm,
                    "psm_reachable":   s.psm_reachable,
                    "service_classes": s.service_classes,
                    "risk":            s.risk.severity if s.risk else None,
                },
            ))

        if out_file:
            self._save(target, services, pnp, xml_attrs, out_file)

        return True
