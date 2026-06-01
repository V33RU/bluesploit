"""
Bluetooth SIG assigned numbers, curated for human-readable output.

Two tables in this module:

  - `SERVICE_NAMES`: GATT service UUID16 -> short name.
  - `CHARACTERISTIC_NAMES`: characteristic UUID16 -> short name.
  - `DESCRIPTOR_NAMES`: descriptor UUID16 -> short name.

These are NOT exhaustive copies of the SIG registry. They cover the
services and characteristics that show up most often during BLE recon
(Generic Access, Battery, Device Info, HRP, RSC, HID, Cycling, etc.)
plus the standard descriptors. Anything not in the table renders as
the raw UUID, which is also what the user wants for vendor-defined
services like the Nordic UART variants in the mirage example.

Updates: add new entries here as needed. The lookup helpers fall back
to an empty string rather than fabricating a name.

Properties decoding follows the GATT characteristic-properties bitmap
defined in BT Core Spec Vol 3 Part G Section 3.3.1.1.
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Optional

# 16-bit GATT service UUIDs and their short names.
# Pulled from the Bluetooth SIG Assigned Numbers (Services section).
SERVICE_NAMES = {
    0x1800: "Generic Access",
    0x1801: "Generic Attribute",
    0x1802: "Immediate Alert",
    0x1803: "Link Loss",
    0x1804: "Tx Power",
    0x1805: "Current Time",
    0x1806: "Reference Time Update",
    0x1807: "Next DST Change",
    0x1808: "Glucose",
    0x1809: "Health Thermometer",
    0x180A: "Device Information",
    0x180D: "Heart Rate",
    0x180E: "Phone Alert Status",
    0x180F: "Battery Service",
    0x1810: "Blood Pressure",
    0x1811: "Alert Notification",
    0x1812: "Human Interface Device",
    0x1813: "Scan Parameters",
    0x1814: "Running Speed and Cadence",
    0x1815: "Automation IO",
    0x1816: "Cycling Speed and Cadence",
    0x1818: "Cycling Power",
    0x1819: "Location and Navigation",
    0x181A: "Environmental Sensing",
    0x181B: "Body Composition",
    0x181C: "User Data",
    0x181D: "Weight Scale",
    0x181E: "Bond Management",
    0x181F: "Continuous Glucose Monitoring",
    0x1820: "Internet Protocol Support",
    0x1821: "Indoor Positioning",
    0x1822: "Pulse Oximeter",
    0x1823: "HTTP Proxy",
    0x1824: "Transport Discovery",
    0x1825: "Object Transfer",
    0x1826: "Fitness Machine",
    0x1827: "Mesh Provisioning",
    0x1828: "Mesh Proxy",
    0x1829: "Reconnection Configuration",
    0x183A: "Insulin Delivery",
    0x183B: "Binary Sensor",
    0x183C: "Emergency Configuration",
    0x183D: "Authorization Control",
    0x183E: "Physical Activity Monitor",
    0x1843: "Audio Input Control",
    0x1844: "Volume Control",
    0x1845: "Volume Offset Control",
    0x1846: "Coordinated Set Identification",
    0x1847: "Device Time",
    0x1848: "Media Control",
    0x1849: "Generic Media Control",
    0x184A: "Constant Tone Extension",
    0x184B: "Telephone Bearer",
    0x184C: "Generic Telephone Bearer",
    0x184D: "Microphone Control",
    0x184E: "Audio Stream Control",
    0x184F: "Broadcast Audio Scan",
    0x1850: "Published Audio Capabilities",
    0x1851: "Basic Audio Announcement",
    0x1852: "Broadcast Audio Announcement",
    0x1853: "Common Audio",
    0x1854: "Hearing Access",
    0x1855: "Telephony and Media Audio",
    0x1856: "Public Broadcast Announcement",
    0xFEAA: "Eddystone",
    0xFEED: "Tile",
    0xFD6F: "Exposure Notification",
}


# 16-bit GATT characteristic UUIDs and their short names.
CHARACTERISTIC_NAMES = {
    0x2A00: "Device Name",
    0x2A01: "Appearance",
    0x2A02: "Peripheral Privacy Flag",
    0x2A03: "Reconnection Address",
    0x2A04: "Peripheral Preferred Connection Parameters",
    0x2A05: "Service Changed",
    0x2A06: "Alert Level",
    0x2A07: "Tx Power Level",
    0x2A08: "Date Time",
    0x2A09: "Day of Week",
    0x2A0A: "Day Date Time",
    0x2A0C: "Exact Time 256",
    0x2A0D: "DST Offset",
    0x2A0E: "Time Zone",
    0x2A0F: "Local Time Information",
    0x2A11: "Time with DST",
    0x2A12: "Time Accuracy",
    0x2A13: "Time Source",
    0x2A14: "Reference Time Information",
    0x2A16: "Time Update Control Point",
    0x2A17: "Time Update State",
    0x2A18: "Glucose Measurement",
    0x2A19: "Battery Level",
    0x2A1C: "Temperature Measurement",
    0x2A1D: "Temperature Type",
    0x2A1E: "Intermediate Temperature",
    0x2A21: "Measurement Interval",
    0x2A22: "Boot Keyboard Input Report",
    0x2A23: "System ID",
    0x2A24: "Model Number String",
    0x2A25: "Serial Number String",
    0x2A26: "Firmware Revision String",
    0x2A27: "Hardware Revision String",
    0x2A28: "Software Revision String",
    0x2A29: "Manufacturer Name String",
    0x2A2A: "IEEE 11073-20601 Regulatory Cert Data List",
    0x2A2B: "Current Time",
    0x2A2C: "Magnetic Declination",
    0x2A31: "Scan Refresh",
    0x2A32: "Boot Keyboard Output Report",
    0x2A33: "Boot Mouse Input Report",
    0x2A34: "Glucose Measurement Context",
    0x2A35: "Blood Pressure Measurement",
    0x2A36: "Intermediate Cuff Pressure",
    0x2A37: "Heart Rate Measurement",
    0x2A38: "Body Sensor Location",
    0x2A39: "Heart Rate Control Point",
    0x2A3F: "Alert Status",
    0x2A40: "Ringer Control Point",
    0x2A41: "Ringer Setting",
    0x2A42: "Alert Category ID Bit Mask",
    0x2A43: "Alert Category ID",
    0x2A44: "Alert Notification Control Point",
    0x2A45: "Unread Alert Status",
    0x2A46: "New Alert",
    0x2A47: "Supported New Alert Category",
    0x2A48: "Supported Unread Alert Category",
    0x2A49: "Blood Pressure Feature",
    0x2A4A: "HID Information",
    0x2A4B: "Report Map",
    0x2A4C: "HID Control Point",
    0x2A4D: "Report",
    0x2A4E: "Protocol Mode",
    0x2A4F: "Scan Interval Window",
    0x2A50: "PnP ID",
    0x2A51: "Glucose Feature",
    0x2A52: "Record Access Control Point",
    0x2A53: "RSC Measurement",
    0x2A54: "RSC Feature",
    0x2A55: "SC Control Point",
    0x2A5A: "Aggregate",
    0x2A5B: "CSC Measurement",
    0x2A5C: "CSC Feature",
    0x2A5D: "Sensor Location",
    0x2A63: "Cycling Power Measurement",
    0x2A64: "Cycling Power Vector",
    0x2A65: "Cycling Power Feature",
    0x2A66: "Cycling Power Control Point",
    0x2A67: "Location and Speed",
    0x2A68: "Navigation",
    0x2A69: "Position Quality",
    0x2A6A: "LN Feature",
    0x2A6B: "LN Control Point",
    0x2A6C: "Elevation",
    0x2A6D: "Pressure",
    0x2A6E: "Temperature",
    0x2A6F: "Humidity",
    0x2A70: "True Wind Speed",
    0x2A71: "True Wind Direction",
    0x2A72: "Apparent Wind Speed",
    0x2A73: "Apparent Wind Direction",
    0x2A74: "Gust Factor",
    0x2A75: "Pollen Concentration",
    0x2A76: "UV Index",
    0x2A77: "Irradiance",
    0x2A78: "Rainfall",
    0x2A79: "Wind Chill",
    0x2A7A: "Heat Index",
    0x2A7B: "Dew Point",
    0x2A80: "Age",
    0x2A87: "Email Address",
    0x2A8A: "First Name",
    0x2A8C: "Gender",
    0x2A8D: "Heart Rate Max",
    0x2A8E: "Height",
    0x2A90: "Last Name",
    0x2A98: "Weight",
    0x2AA6: "Central Address Resolution",
    0x2AA8: "CGM Feature",
    0x2AA9: "CGM Status",
    0x2AAA: "CGM Session Start Time",
    0x2AAB: "CGM Session Run Time",
    0x2AB3: "Altitude",
    0x2AB5: "Latitude",
    0x2AB6: "Longitude",
    0x2AC9: "Resolvable Private Address Only",
    0x2ACD: "Step Counter Activity Summary Data",
    0x2ACE: "Cross Trainer Data",
    0x2ACF: "Step Climber Data",
    0x2AD0: "Stair Climber Data",
    0x2AD1: "Rower Data",
    0x2AD2: "Indoor Bike Data",
    0x2AD3: "Training Status",
}


# 16-bit GATT descriptor UUIDs and their short names.
DESCRIPTOR_NAMES = {
    0x2900: "Characteristic Extended Properties",
    0x2901: "Characteristic User Description",
    0x2902: "Client Characteristic Configuration",
    0x2903: "Server Characteristic Configuration",
    0x2904: "Characteristic Presentation Format",
    0x2905: "Characteristic Aggregate Format",
    0x2906: "Valid Range",
    0x2907: "External Report Reference",
    0x2908: "Report Reference",
    0x2909: "Number of Digitals",
    0x290A: "Value Trigger Setting",
    0x290B: "Environmental Sensing Configuration",
    0x290C: "Environmental Sensing Measurement",
    0x290D: "Environmental Sensing Trigger Setting",
    0x290E: "Time Trigger Setting",
    0x290F: "Complete BR-EDR Transport Block Data",
}


# ---------------------------------------------------------------------------
# UUID utilities
# ---------------------------------------------------------------------------

# Bluetooth SIG base UUID. Every standard 16- or 32-bit UUID is the
# 128-bit value `<value> << 96 | BASE`. We use this to recognize when
# a 128-bit UUID is actually a SIG-assigned short UUID in disguise.
_BASE_UUID_TAIL = "00001000800000805f9b34fb"


def short_uuid(uuid128: str) -> Optional[int]:
    """If `uuid128` is a SIG short UUID dressed in 128-bit form, return
    the 16-bit (or 32-bit) integer. Otherwise return None.

    Accepts both `00001800-0000-1000-8000-00805f9b34fb` and the same
    string with no dashes.
    """
    cleaned = uuid128.replace("-", "").lower()
    if len(cleaned) != 32 or not cleaned.endswith(_BASE_UUID_TAIL):
        return None
    short = cleaned[: 32 - len(_BASE_UUID_TAIL)]
    try:
        return int(short, 16)
    except ValueError:
        return None


def name_for_service(uuid128: str) -> str:
    short = short_uuid(uuid128)
    if short is None:
        return ""
    return SERVICE_NAMES.get(short, "")


def name_for_characteristic(uuid128: str) -> str:
    short = short_uuid(uuid128)
    if short is None:
        return ""
    return CHARACTERISTIC_NAMES.get(short, "")


def name_for_descriptor(uuid128: str) -> str:
    short = short_uuid(uuid128)
    if short is None:
        return ""
    return DESCRIPTOR_NAMES.get(short, "")


# ---------------------------------------------------------------------------
# Properties bitmap decoding
# ---------------------------------------------------------------------------

# Per BT Core Spec Vol 3 Part G Section 3.3.1.1
PROP_BIT_NAMES = {
    0x01: "Broadcast",
    0x02: "Read",
    0x04: "Write Without Response",
    0x08: "Write",
    0x10: "Notify",
    0x20: "Indicate",
    0x40: "Authenticated Signed Write",
    0x80: "Extended Properties",
}


def properties_to_permissions(props: Iterable[str]) -> List[str]:
    """Take bleak's list of property strings and return a clean, ordered
    permission list matching the labels GATT browsers use.

    bleak emits strings like 'read', 'write', 'notify', 'indicate',
    'write-without-response', 'broadcast', 'authenticated-signed-writes',
    'extended-properties', 'reliable-write', 'writable-auxiliaries'.
    We normalize them.
    """
    mapping = {
        "read": "Read",
        "write": "Write",
        "notify": "Notify",
        "indicate": "Indicate",
        "broadcast": "Broadcast",
        "write-without-response": "Write Without Response",
        "authenticated-signed-writes": "Authenticated Signed Write",
        "extended-properties": "Extended Properties",
        "reliable-write": "Reliable Write",
        "writable-auxiliaries": "Writable Auxiliaries",
    }
    out: List[str] = []
    seen: set[str] = set()
    for p in props:
        label = mapping.get(p.lower(), p)
        if label not in seen:
            out.append(label)
            seen.add(label)
    return out


def permissions_from_bitmap(bits: int) -> List[str]:
    """Decode a raw GATT properties bitmap (single byte) into the same
    ordered label list used everywhere else."""
    out: List[str] = []
    for bit, label in PROP_BIT_NAMES.items():
        if bits & bit:
            out.append(label)
    return out


# ── Chipset / vendor identification ──────────────────────────────────────────
#
# Shared truth used by recon modules that walk GATT (gatt_enum,
# ble_target_enum) and any future module that needs to map a BD_ADDR,
# PnP vendor id, or LMP subversion to a chipset label. Live in one place
# to avoid drift; previous duplicate copies caused real bugs (e.g. a
# malformed 7-char OUI key that never matched).

# Bluetooth SIG company identifiers -> chipset / brand vendor label.
CHIPSET_VENDORS: Dict[int, str] = {
    0x0002: "Intel",
    0x0006: "Microsoft",
    0x000D: "Texas Instruments",
    0x000F: "Broadcom",
    0x001D: "Qualcomm Atheros",
    0x0059: "Nordic Semiconductor",
    0x0075: "Samsung",
    0x0087: "Garmin",
    0x004C: "Apple",
    0x00E0: "Google",
    0x012D: "GN Audio (Jabra)",
    0x012E: "MediaTek",
    0x0131: "Huawei Technologies",
    0x0157: "Xiaomi / LYWSD",
    0x0310: "Wyze Labs",
    0x038F: "Espressif Systems",
    0x03DA: "Bose",
    0x0499: "Ruuvi Innovations",
    0x054C: "Sony",
    0x0603: "Sonos",
    0x0822: "Espressif",
}

# Manufacturer name substring -> probable chipset label. Used when the
# Device Information Service exposes a manufacturer string but no PnP ID.
MFR_CHIPSET_HINTS: Dict[str, str] = {
    "nordic":       "Nordic Semiconductor nRF5x",
    "dialog":       "Dialog Semiconductor DA14xxx",
    "texas":        "Texas Instruments CC264x",
    "ti ":          "Texas Instruments CC264x",
    "silicon labs": "Silicon Labs EFR32",
    "silabs":       "Silicon Labs EFR32",
    "telink":       "Telink TLSR",
    "realtek":      "Realtek RTL8762",
    "beken":        "Beken BK36xx",
    "mediatek":     "MediaTek MT25xx",
    "qualcomm":     "Qualcomm QCC",
    "cypress":      "Infineon/Cypress CYW43xxx",
    "broadcom":     "Broadcom BCM",
    "espressif":    "Espressif ESP32",
    "esp":          "Espressif ESP32",
    "nxp":          "NXP KW4x",
    "kaha":         "Realtek RTL8762 (KaHa platform)",
    "huawei":       "HiSilicon BLE SoC",
    "xiaomi":       "Beken / MediaTek platform",
}

# LMP / LE-LL subversion value -> exact chipset model. Read off the
# HCI_Read_Remote_Version response.
LMP_SUBVER_CHIPSET: Dict[int, str] = {
    0x0001: "Nordic nRF52xxx",
    0x000D: "Nordic nRF52840",
    0x0048: "Texas Instruments CC2640",
    0x0051: "Texas Instruments CC2642",
    0x1000: "Nordic nRF51xxx",
    0x22BB: "Silicon Labs EFR32BG22",
    0x6109: "Qualcomm QCC512x",
    0x8761: "Realtek RTL8761",
    0x8762: "Realtek RTL8762",
    0x8763: "Realtek RTL8763",
    0x9908: "Dialog DA14531",
}

# OUI prefix (6 uppercase hex chars, no colons) -> chipset / SoC vendor.
# Smaller than the full IEEE OUI table; covers only the BLE-relevant
# vendor blocks we want chipset attribution for.
OUI_CHIPSET: Dict[str, str] = {
    "000F00": "Broadcom",
    "001A8A": "Samsung Electro-Mechanics",
    "001B10": "Nokia / MediaTek",
    "001E10": "Huawei Technologies",
    "240AC4": "Espressif ESP32",
    "246FAB": "Espressif ESP32",
    "30AEA4": "Espressif ESP32",
    "3C71BF": "Espressif ESP32",
    "5091F7": "Nordic Semiconductor",
    "5CCF7F": "Espressif ESP32",
    "84CCA8": "Espressif ESP32",
    "F4CE36": "Nordic Semiconductor",
}


def chipset_for_company_id(cid: int) -> Optional[str]:
    """Map a Bluetooth SIG company id to a chipset / brand label."""
    return CHIPSET_VENDORS.get(cid)


def chipset_for_manufacturer(name: str) -> Optional[str]:
    """Best-effort chipset label from a manufacturer string (case-insensitive
    substring match against `MFR_CHIPSET_HINTS`)."""
    if not name:
        return None
    low = name.lower()
    for needle, label in MFR_CHIPSET_HINTS.items():
        if needle in low:
            return label
    return None


def chipset_for_lmp_subversion(subver: int) -> Optional[str]:
    """Map an LMP / LE-LL subversion value to a specific chipset model."""
    return LMP_SUBVER_CHIPSET.get(subver)


def chipset_for_address(bd_addr: str) -> Optional[str]:
    """Best-effort chipset / SoC vendor from a BD_ADDR's OUI prefix.

    Accepts addresses with or without colons, in any case. Returns None
    if the OUI is not in `OUI_CHIPSET`."""
    if not bd_addr:
        return None
    oui = bd_addr.replace(":", "").upper()[:6]
    if len(oui) != 6:
        return None
    return OUI_CHIPSET.get(oui)


__all__ = [
    "SERVICE_NAMES",
    "CHARACTERISTIC_NAMES",
    "DESCRIPTOR_NAMES",
    "PROP_BIT_NAMES",
    "CHIPSET_VENDORS",
    "MFR_CHIPSET_HINTS",
    "LMP_SUBVER_CHIPSET",
    "OUI_CHIPSET",
    "short_uuid",
    "name_for_service",
    "name_for_characteristic",
    "name_for_descriptor",
    "properties_to_permissions",
    "permissions_from_bitmap",
    "chipset_for_company_id",
    "chipset_for_manufacturer",
    "chipset_for_lmp_subversion",
    "chipset_for_address",
]
