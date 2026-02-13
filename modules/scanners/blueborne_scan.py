"""
BlueSploit Module: BlueBorne Vulnerability Scanner
Scans for Bluetooth Classic devices vulnerable to BlueBorne (CVE-2017-0785, etc.)

CVE-2017-0785 - Android Information Leak
CVE-2017-0781 - Android RCE
CVE-2017-0782 - Android RCE  
CVE-2017-0783 - Android MitM
CVE-2017-1000251 - Linux RCE (BlueZ)
CVE-2017-1000250 - Linux Info Leak
CVE-2017-8628 - Windows MitM

Author: v33ru
"""

import subprocess
import struct
import socket
import sys
import os
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info,
    print_warning, Colors
)

# Try importing pybluez
try:
    import bluetooth
    PYBLUEZ_AVAILABLE = True
except ImportError:
    PYBLUEZ_AVAILABLE = False


class VulnStatus(Enum):
    VULNERABLE = "VULNERABLE"
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    POSSIBLY_VULNERABLE = "POSSIBLY_VULNERABLE"
    PATCHED = "PATCHED"
    UNKNOWN = "UNKNOWN"


@dataclass
class VulnInfo:
    cve: str
    name: str
    severity: str
    affected_os: str
    description: str


@dataclass 
class DeviceVulnResult:
    address: str
    name: str
    manufacturer: str
    device_class: str
    os_guess: str
    vulnerabilities: List[VulnInfo]
    status: VulnStatus
    services: List[Dict[str, Any]]
    raw_data: Dict[str, Any]


# Known CVEs in BlueBorne family
BLUEBORNE_CVES = {
    "CVE-2017-0785": VulnInfo(
        cve="CVE-2017-0785",
        name="Android Information Leak",
        severity="HIGH",
        affected_os="Android",
        description="SDP information leak vulnerability allowing memory disclosure"
    ),
    "CVE-2017-0781": VulnInfo(
        cve="CVE-2017-0781",
        name="Android RCE (BNEP)",
        severity="CRITICAL",
        affected_os="Android",
        description="Heap overflow in BNEP allowing remote code execution"
    ),
    "CVE-2017-0782": VulnInfo(
        cve="CVE-2017-0782",
        name="Android RCE (BNEP)",
        severity="CRITICAL",
        affected_os="Android",
        description="Heap overflow in BNEP PAN profile"
    ),
    "CVE-2017-0783": VulnInfo(
        cve="CVE-2017-0783",
        name="Android MitM (PAN)",
        severity="HIGH",
        affected_os="Android",
        description="Man-in-the-Middle via Bluetooth PAN profile"
    ),
    "CVE-2017-1000251": VulnInfo(
        cve="CVE-2017-1000251",
        name="Linux RCE (L2CAP)",
        severity="CRITICAL",
        affected_os="Linux",
        description="Stack overflow in L2CAP config response handling"
    ),
    "CVE-2017-1000250": VulnInfo(
        cve="CVE-2017-1000250",
        name="Linux Info Leak (SDP)",
        severity="MEDIUM",
        affected_os="Linux",
        description="Information leak in SDP server"
    ),
    "CVE-2017-8628": VulnInfo(
        cve="CVE-2017-8628",
        name="Windows MitM",
        severity="HIGH",
        affected_os="Windows",
        description="Man-in-the-Middle attack via Bluetooth driver"
    ),
}

# Vulnerable device MAC prefixes (OUI) - Manufacturers with known vulnerable devices
# Format: OUI prefix -> (Manufacturer, Likely OS, Vulnerability likelihood)
VULNERABLE_OUIS = {
    # Samsung (Android)
    "00:1A:8A": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1D:25": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1E:75": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:21:19": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:21:D1": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:23:39": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:23:D6": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:23:99": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:24:54": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:25:66": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:26:37": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "08:D4:2B": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "0C:14:20": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "10:D5:42": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "14:49:E0": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "14:89:FD": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "18:3A:2D": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "1C:62:B8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "1C:66:AA": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "20:D5:BF": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "24:4B:81": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "28:98:7B": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "2C:AE:2B": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "30:96:FB": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "34:C3:AC": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "38:01:97": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "3C:5A:37": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "40:0E:85": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "44:4E:1A": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "4C:BC:A5": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "50:01:BB": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "50:A4:C8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "54:92:BE": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "58:C3:8B": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "5C:2E:59": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "5C:F6:DC": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "60:A1:0A": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "64:B3:10": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "68:48:98": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "6C:F3:73": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "70:F9:27": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "78:40:E4": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "78:47:1D": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "78:52:1A": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "7C:0B:C6": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "7C:F8:54": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "80:18:A7": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "84:11:9E": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "84:25:DB": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "84:38:38": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "84:55:A5": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "88:32:9B": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "8C:71:F8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "8C:77:12": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "90:18:7C": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "94:01:C2": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "94:35:0A": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "94:51:03": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "94:63:D1": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "98:0C:82": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "98:52:B1": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "9C:02:98": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "9C:3A:AF": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "A0:07:98": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "A0:82:1F": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "A4:07:B6": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "A8:06:00": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "A8:7C:01": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "AC:36:13": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "AC:5F:3E": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "B0:47:BF": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "B0:72:BF": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "B4:07:F9": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "B4:79:A7": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "B8:57:D8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "BC:14:EF": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "BC:44:86": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "BC:72:B1": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C0:97:27": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C4:42:02": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C4:50:06": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C8:14:79": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C8:19:F7": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "CC:07:AB": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D0:22:BE": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D0:59:E4": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D4:87:D8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D4:E8:B2": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D8:57:EF": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D8:90:E8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "DC:66:72": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E0:99:71": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E4:12:1D": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E4:40:E2": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E4:58:B8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E4:7C:F9": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E4:E0:C5": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E8:03:9A": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E8:4E:84": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "EC:1F:72": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "EC:9B:F3": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F0:25:B7": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F0:5B:7B": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F4:09:D8": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F4:42:8F": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F4:7B:5E": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F8:04:2E": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F8:3F:51": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    "FC:A1:3E": ("Samsung", "Android", VulnStatus.LIKELY_VULNERABLE),
    
    # Google Pixel (Android)
    "3C:28:6D": ("Google", "Android", VulnStatus.LIKELY_VULNERABLE),
    "54:60:09": ("Google", "Android", VulnStatus.LIKELY_VULNERABLE),
    "58:CB:52": ("Google", "Android", VulnStatus.LIKELY_VULNERABLE),
    "94:EB:2C": ("Google", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F4:F5:D8": ("Google", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F8:0F:F9": ("Google", "Android", VulnStatus.LIKELY_VULNERABLE),
    
    # Huawei (Android)
    "00:1E:10": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:25:68": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:25:9E": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:46:4B": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "04:02:1F": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "04:25:C5": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "04:B0:E7": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "04:C0:6F": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "04:F9:38": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "08:19:A6": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "08:63:61": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "08:7A:4C": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "0C:37:DC": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "0C:45:BA": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "0C:96:BF": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "10:1B:54": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "10:44:00": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    "10:47:80": ("Huawei", "Android", VulnStatus.LIKELY_VULNERABLE),
    
    # LG (Android)
    "00:1C:62": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1E:75": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1F:6B": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1F:E3": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:21:FB": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:22:A9": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:24:83": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:25:E5": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:26:E2": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:34:DA": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:AA:70": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:E0:91": ("LG", "Android", VulnStatus.LIKELY_VULNERABLE),
    
    # Sony (Android)
    "00:01:4A": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:0A:D9": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:0E:07": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:0F:DE": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:13:A9": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:15:C1": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:16:20": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:18:13": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:19:63": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1A:80": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1C:A4": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1D:28": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1E:A4": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    "00:1F:E4": ("Sony", "Android", VulnStatus.LIKELY_VULNERABLE),
    
    # Xiaomi (Android)
    "00:9E:C8": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "04:CF:8C": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "0C:1D:AF": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "10:2A:B3": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "14:F6:5A": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "18:59:36": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "20:34:FB": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "28:6C:07": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "34:80:B3": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "38:A4:ED": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "3C:BD:D8": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "44:23:7C": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "50:64:2B": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "58:44:98": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "5C:0A:5B": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "64:09:80": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "64:B4:73": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "68:DF:DD": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "74:23:44": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "74:51:BA": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "78:02:F8": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "7C:1D:D9": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "84:F3:EB": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "8C:BE:BE": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "98:FA:E3": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "9C:99:A0": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "A0:86:C6": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "AC:C1:EE": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "B0:E2:35": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C4:0B:CB": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "C8:D7:B0": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "D4:97:0B": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "E8:AB:FA": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F0:B4:29": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F4:F5:DB": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "F8:A4:5F": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    "FC:64:BA": ("Xiaomi", "Android", VulnStatus.LIKELY_VULNERABLE),
    
    # Linux devices (potential BlueZ vulnerability)
    "00:1A:7D": ("Raspberry Pi", "Linux", VulnStatus.POSSIBLY_VULNERABLE),
    "B8:27:EB": ("Raspberry Pi", "Linux", VulnStatus.POSSIBLY_VULNERABLE),
    "DC:A6:32": ("Raspberry Pi", "Linux", VulnStatus.POSSIBLY_VULNERABLE),
    "E4:5F:01": ("Raspberry Pi", "Linux", VulnStatus.POSSIBLY_VULNERABLE),
    
    # Windows devices
    "00:1B:DC": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "00:1D:D8": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "00:50:F2": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "28:18:78": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "30:59:B7": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "50:1A:C5": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "60:45:BD": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "7C:1E:52": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "7C:ED:8D": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "98:5F:D3": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "B4:0E:DE": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "C8:3F:26": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
    "DC:53:60": ("Microsoft", "Windows", VulnStatus.POSSIBLY_VULNERABLE),
}


# Device Class codes for OS fingerprinting
DEVICE_CLASS_MAP = {
    # Major device class masks
    0x100: "Computer",
    0x200: "Phone",
    0x300: "LAN/Network",
    0x400: "Audio/Video",
    0x500: "Peripheral",
    0x600: "Imaging",
    0x700: "Wearable",
    0x800: "Toy",
    0x900: "Health",
}


class Module(ScannerModule):
    """
    BlueBorne Vulnerability Scanner
    
    Scans for Bluetooth Classic devices and identifies those potentially
    vulnerable to BlueBorne family of vulnerabilities (CVE-2017-*)
    
    Detection Methods:
    1. OUI-based manufacturer identification
    2. Device class analysis for OS fingerprinting
    3. SDP service probing
    4. L2CAP response analysis
    """
    
    info = ModuleInfo(
        name="scanners/classic/blueborne_scan",
        description="Scan for BlueBorne vulnerable devices (CVE-2017-*)",
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=[
            "https://www.armis.com/blueborne/",
            "CVE-2017-0785",
            "CVE-2017-0781",
            "CVE-2017-0782",
            "CVE-2017-1000251"
        ]
    )
    
    def _setup_options(self) -> None:
        """Define module options"""
        self.options = {
            "interface": ModuleOption(
                name="interface",
                required=False,
                description="Bluetooth interface (hci0)",
                default="hci0"
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Scan duration in seconds",
                default=20
            ),
            "deep_scan": ModuleOption(
                name="deep_scan",
                required=False,
                description="Enable SDP probing for detailed analysis",
                default=True
            ),
            "target": ModuleOption(
                name="target",
                required=False,
                description="Specific target BD_ADDR (optional)",
                default=None
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON file",
                default=None
            )
        }
    
    def _check_requirements(self) -> bool:
        """Verify system requirements"""
        if sys.platform != "linux":
            print_error("This module requires Linux with BlueZ stack")
            return False
        
        if not PYBLUEZ_AVAILABLE:
            print_warning("PyBluez not available, using hcitool fallback")
        
        # Check hcitool
        try:
            result = subprocess.run(["which", "hcitool"], capture_output=True)
            if result.returncode != 0:
                print_error("hcitool not found. Install bluez: sudo apt install bluez")
                return False
        except Exception as e:
            print_error(f"Error checking hcitool: {e}")
            return False
        
        return True
    
    def _get_oui(self, address: str) -> str:
        """Extract OUI (first 3 octets) from BD_ADDR"""
        return address[:8].upper()
    
    def _lookup_manufacturer(self, address: str) -> Tuple[str, str, VulnStatus]:
        """Lookup manufacturer info from OUI database"""
        oui = self._get_oui(address)
        
        if oui in VULNERABLE_OUIS:
            return VULNERABLE_OUIS[oui]
        
        return ("Unknown", "Unknown", VulnStatus.UNKNOWN)
    
    def _parse_device_class(self, dev_class: int) -> str:
        """Parse device class to human readable string"""
        major_class = (dev_class >> 8) & 0x1F
        major_class_shifted = major_class << 8
        
        return DEVICE_CLASS_MAP.get(major_class_shifted, f"Unknown (0x{dev_class:06X})")
    
    def _guess_os(self, name: str, manufacturer: str, device_class: str) -> str:
        """Attempt to guess OS from device info"""
        name_lower = (name or "").lower()
        
        # Android indicators
        android_keywords = ["galaxy", "samsung", "pixel", "nexus", "huawei", 
                          "xiaomi", "redmi", "oneplus", "oppo", "vivo",
                          "android", "mi ", "poco"]
        for kw in android_keywords:
            if kw in name_lower:
                return "Android"
        
        # iOS indicators (not vulnerable to BlueBorne but good to identify)
        ios_keywords = ["iphone", "ipad", "airpods", "apple watch", "macbook"]
        for kw in ios_keywords:
            if kw in name_lower:
                return "iOS/macOS"
        
        # Windows indicators
        win_keywords = ["windows", "surface", "xbox"]
        for kw in win_keywords:
            if kw in name_lower:
                return "Windows"
        
        # Linux indicators
        linux_keywords = ["raspberry", "ubuntu", "linux", "pi"]
        for kw in linux_keywords:
            if kw in name_lower:
                return "Linux"
        
        # Guess from manufacturer
        if manufacturer in ["Samsung", "Google", "Huawei", "LG", "Sony", "Xiaomi"]:
            return "Android (likely)"
        elif manufacturer == "Microsoft":
            return "Windows (likely)"
        elif manufacturer == "Raspberry Pi":
            return "Linux (likely)"
        
        # Guess from device class
        if "Phone" in device_class:
            return "Android/iOS"
        elif "Computer" in device_class:
            return "Windows/Linux/macOS"
        
        return "Unknown"
    
    def _get_applicable_cves(self, os_guess: str) -> List[VulnInfo]:
        """Get CVEs applicable to the guessed OS"""
        cves = []
        os_lower = os_guess.lower()
        
        if "android" in os_lower:
            cves.extend([
                BLUEBORNE_CVES["CVE-2017-0785"],
                BLUEBORNE_CVES["CVE-2017-0781"],
                BLUEBORNE_CVES["CVE-2017-0782"],
                BLUEBORNE_CVES["CVE-2017-0783"],
            ])
        
        if "linux" in os_lower:
            cves.extend([
                BLUEBORNE_CVES["CVE-2017-1000251"],
                BLUEBORNE_CVES["CVE-2017-1000250"],
            ])
        
        if "windows" in os_lower:
            cves.append(BLUEBORNE_CVES["CVE-2017-8628"])
        
        return cves
    
    def _discover_devices_pybluez(self, duration: int) -> List[Tuple[str, str, int]]:
        """Discover devices using PyBluez"""
        devices = []
        
        try:
            print_info("Discovering devices with PyBluez...")
            discovered = bluetooth.discover_devices(
                duration=duration,
                lookup_names=True,
                lookup_class=True,
                flush_cache=True
            )
            
            for item in discovered:
                if len(item) == 3:
                    addr, name, dev_class = item
                    devices.append((addr, name or "Unknown", dev_class))
                elif len(item) == 2:
                    addr, name = item
                    devices.append((addr, name or "Unknown", 0))
                    
        except Exception as e:
            print_error(f"PyBluez discovery failed: {e}")
        
        return devices
    
    def _discover_devices_hcitool(self, duration: int) -> List[Tuple[str, str, int]]:
        """Discover devices using hcitool (fallback)"""
        devices = []
        
        try:
            print_info("Discovering devices with hcitool...")
            
            # Run hcitool scan
            result = subprocess.run(
                ["hcitool", "scan", "--flush"],
                capture_output=True,
                text=True,
                timeout=duration + 5
            )
            
            # Parse output
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith("Scanning"):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        addr = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else "Unknown"
                        
                        # Try to get device class
                        dev_class = 0
                        try:
                            info_result = subprocess.run(
                                ["hcitool", "info", addr],
                                capture_output=True,
                                text=True,
                                timeout=5
                            )
                            for info_line in info_result.stdout.split('\n'):
                                if "Class:" in info_line:
                                    class_str = info_line.split(":")[-1].strip()
                                    dev_class = int(class_str, 16)
                                    break
                        except:
                            pass
                        
                        devices.append((addr, name, dev_class))
                        
        except subprocess.TimeoutExpired:
            print_warning("Scan timed out")
        except Exception as e:
            print_error(f"hcitool discovery failed: {e}")
        
        return devices
    
    def _scan_specific_target(self, target: str) -> List[Tuple[str, str, int]]:
        """Scan a specific target address"""
        devices = []
        
        print_info(f"Scanning specific target: {target}")
        
        try:
            # Try to get device name
            name = "Unknown"
            try:
                if PYBLUEZ_AVAILABLE:
                    name = bluetooth.lookup_name(target, timeout=5) or "Unknown"
                else:
                    result = subprocess.run(
                        ["hcitool", "name", target],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    name = result.stdout.strip() or "Unknown"
            except:
                pass
            
            # Get device class
            dev_class = 0
            try:
                result = subprocess.run(
                    ["hcitool", "info", target],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                for line in result.stdout.split('\n'):
                    if "Class:" in line:
                        class_str = line.split(":")[-1].strip()
                        dev_class = int(class_str, 16)
                        break
            except:
                pass
            
            devices.append((target, name, dev_class))
            
        except Exception as e:
            print_error(f"Target scan failed: {e}")
        
        return devices
    
    def _probe_sdp_services(self, address: str) -> List[Dict[str, Any]]:
        """Probe SDP services on target"""
        services = []
        
        try:
            if PYBLUEZ_AVAILABLE:
                discovered = bluetooth.find_service(address=address)
                for svc in discovered:
                    services.append({
                        "name": svc.get("name", "Unknown"),
                        "protocol": svc.get("protocol", "Unknown"),
                        "port": svc.get("port", 0),
                        "service_id": svc.get("service-id", ""),
                        "profiles": svc.get("profiles", [])
                    })
            else:
                # Fallback to sdptool
                result = subprocess.run(
                    ["sdptool", "browse", address],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Parse sdptool output (basic parsing)
                current_service = {}
                for line in result.stdout.split('\n'):
                    if "Service Name:" in line:
                        if current_service:
                            services.append(current_service)
                        current_service = {"name": line.split(":")[-1].strip()}
                    elif "Protocol Descriptor List:" in line:
                        current_service["protocol"] = "L2CAP/RFCOMM"
                    elif "Channel:" in line:
                        try:
                            current_service["port"] = int(line.split(":")[-1].strip())
                        except:
                            pass
                
                if current_service:
                    services.append(current_service)
                    
        except Exception as e:
            print_warning(f"SDP probe failed for {address}: {e}")
        
        return services
    
    def _analyze_device(self, address: str, name: str, 
                       dev_class: int, deep_scan: bool) -> DeviceVulnResult:
        """Analyze a device for vulnerabilities"""
        # Lookup manufacturer
        manufacturer, likely_os, base_status = self._lookup_manufacturer(address)
        
        # Parse device class
        device_class_str = self._parse_device_class(dev_class)
        
        # Guess OS
        os_guess = self._guess_os(name, manufacturer, device_class_str)
        if os_guess == "Unknown" and likely_os != "Unknown":
            os_guess = likely_os
        
        # Get applicable CVEs
        vulnerabilities = self._get_applicable_cves(os_guess)
        
        # Determine final status
        if vulnerabilities:
            if base_status == VulnStatus.LIKELY_VULNERABLE:
                status = VulnStatus.LIKELY_VULNERABLE
            elif base_status == VulnStatus.POSSIBLY_VULNERABLE:
                status = VulnStatus.POSSIBLY_VULNERABLE
            else:
                status = VulnStatus.POSSIBLY_VULNERABLE
        else:
            status = VulnStatus.UNKNOWN
        
        # SDP probe if requested
        services = []
        if deep_scan:
            services = self._probe_sdp_services(address)
            
            # Check for vulnerable services
            for svc in services:
                svc_name = (svc.get("name") or "").lower()
                # BNEP/PAN services are particularly interesting for BlueBorne
                if "bnep" in svc_name or "pan" in svc_name or "network" in svc_name:
                    if status == VulnStatus.POSSIBLY_VULNERABLE:
                        status = VulnStatus.LIKELY_VULNERABLE
        
        return DeviceVulnResult(
            address=address,
            name=name,
            manufacturer=manufacturer,
            device_class=device_class_str,
            os_guess=os_guess,
            vulnerabilities=vulnerabilities,
            status=status,
            services=services,
            raw_data={"dev_class_raw": dev_class}
        )
    
    def _print_results_table(self, results: List[DeviceVulnResult]) -> None:
        """Print scan results in table format"""
        if not results:
            print_warning("No devices found")
            return
        
        # Separate by vulnerability status
        vulnerable = [r for r in results if r.status in 
                     [VulnStatus.VULNERABLE, VulnStatus.LIKELY_VULNERABLE]]
        possibly_vuln = [r for r in results if r.status == VulnStatus.POSSIBLY_VULNERABLE]
        unknown = [r for r in results if r.status == VulnStatus.UNKNOWN]
        patched = [r for r in results if r.status == VulnStatus.PATCHED]
        
        # Print header
        print(f"\n  {Colors.CYAN}{'═'*90}{Colors.RESET}")
        print(f"  {Colors.CYAN}BLUEBORNE VULNERABILITY SCAN RESULTS{Colors.RESET}")
        print(f"  {Colors.CYAN}{'═'*90}{Colors.RESET}\n")
        
        # Summary
        print(f"  {Colors.BOLD}Summary:{Colors.RESET}")
        print(f"  ├─ Total Devices      : {len(results)}")
        print(f"  ├─ {Colors.RED}Likely Vulnerable{Colors.RESET}  : {len(vulnerable)}")
        print(f"  ├─ {Colors.YELLOW}Possibly Vulnerable{Colors.RESET}: {len(possibly_vuln)}")
        print(f"  ├─ {Colors.GREEN}Patched/Safe{Colors.RESET}       : {len(patched)}")
        print(f"  └─ Unknown            : {len(unknown)}")
        
        # Table header
        print(f"\n  {Colors.BOLD}{'#':<3} {'ADDRESS':<18} {'NAME':<18} {'VENDOR':<12} {'OS':<12} {'STATUS':<20}{Colors.RESET}")
        print(f"  {'─'*3} {'─'*18} {'─'*18} {'─'*12} {'─'*12} {'─'*20}")
        
        # Print all devices sorted by vulnerability status
        all_sorted = vulnerable + possibly_vuln + unknown + patched
        
        for idx, dev in enumerate(all_sorted, 1):
            name = dev.name[:16] + ".." if len(dev.name) > 18 else dev.name
            manufacturer = dev.manufacturer[:10] + ".." if len(dev.manufacturer) > 12 else dev.manufacturer
            os_guess = dev.os_guess[:10] + ".." if len(dev.os_guess) > 12 else dev.os_guess
            
            # Color code status
            if dev.status == VulnStatus.LIKELY_VULNERABLE:
                status_str = f"{Colors.RED}LIKELY VULNERABLE{Colors.RESET}"
            elif dev.status == VulnStatus.POSSIBLY_VULNERABLE:
                status_str = f"{Colors.YELLOW}POSSIBLY VULN{Colors.RESET}"
            elif dev.status == VulnStatus.PATCHED:
                status_str = f"{Colors.GREEN}PATCHED{Colors.RESET}"
            else:
                status_str = "UNKNOWN"
            
            print(f"  {idx:<3} {dev.address:<18} {name:<18} {manufacturer:<12} {os_guess:<12} {status_str}")
        
        print(f"\n  {Colors.CYAN}{'═'*90}{Colors.RESET}")
        
        # Detailed vulnerable device info
        if vulnerable:
            print(f"\n  {Colors.RED}{'─'*50}")
            print(f"  LIKELY VULNERABLE DEVICES - DETAILED INFO")
            print(f"  {'─'*50}{Colors.RESET}\n")
            
            for dev in vulnerable:
                print(f"  {Colors.RED}[!]{Colors.RESET} {dev.address} - {dev.name}")
                print(f"      Manufacturer : {dev.manufacturer}")
                print(f"      OS (guessed) : {dev.os_guess}")
                print(f"      Device Class : {dev.device_class}")
                
                if dev.vulnerabilities:
                    print(f"      {Colors.RED}Potential CVEs:{Colors.RESET}")
                    for vuln in dev.vulnerabilities:
                        print(f"        - {vuln.cve}: {vuln.name} ({vuln.severity})")
                
                if dev.services:
                    print(f"      Services ({len(dev.services)}):")
                    for svc in dev.services[:5]:
                        print(f"        - {svc.get('name', 'Unknown')}")
                
                print()
        
        # Exploitation hint
        if vulnerable:
            print(f"  {Colors.YELLOW}[*] To exploit, use:{Colors.RESET}")
            print(f"      use exploits/classic/blueborne_rce")
            print(f"      set target <BD_ADDR>")
            print(f"      run\n")
    
    def _save_results(self, results: List[DeviceVulnResult], filename: str) -> None:
        """Save results to JSON file"""
        import json
        
        output = {
            "scan_info": {
                "module": self.info.name,
                "total_devices": len(results),
                "vulnerable": len([r for r in results if r.status == VulnStatus.LIKELY_VULNERABLE]),
            },
            "devices": []
        }
        
        for dev in results:
            output["devices"].append({
                "address": dev.address,
                "name": dev.name,
                "manufacturer": dev.manufacturer,
                "device_class": dev.device_class,
                "os_guess": dev.os_guess,
                "status": dev.status.value,
                "vulnerabilities": [
                    {"cve": v.cve, "name": v.name, "severity": v.severity}
                    for v in dev.vulnerabilities
                ],
                "services": dev.services
            })
        
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            print_success(f"Results saved to: {filename}")
        except Exception as e:
            print_error(f"Failed to save: {e}")
    
    def run(self) -> bool:
        """Execute BlueBorne vulnerability scan"""
        if not self._check_requirements():
            return False
        
        timeout = int(self.get_option("timeout"))
        deep_scan = self.get_option("deep_scan")
        target = self.get_option("target")
        output_file = self.get_option("output_file")
        
        print_info("BlueBorne Vulnerability Scanner")
        print_info(f"Scan Duration: {timeout}s | Deep Scan: {deep_scan}")
        print()
        
        # Discover devices
        if target:
            if not self.validate_bd_addr(target):
                print_error(f"Invalid BD_ADDR: {target}")
                return False
            devices = self._scan_specific_target(target)
        else:
            # Try PyBluez first, fall back to hcitool
            if PYBLUEZ_AVAILABLE:
                devices = self._discover_devices_pybluez(timeout)
            else:
                devices = self._discover_devices_hcitool(timeout)
        
        if not devices:
            print_warning("No Bluetooth devices found")
            return False
        
        print_success(f"Found {len(devices)} device(s)")
        print_info("Analyzing devices for vulnerabilities...\n")
        
        # Analyze each device
        results: List[DeviceVulnResult] = []
        
        for idx, (addr, name, dev_class) in enumerate(devices, 1):
            print(f"  [{idx}/{len(devices)}] Analyzing {addr} ({name})...", end="\r")
            result = self._analyze_device(addr, name, dev_class, deep_scan)
            results.append(result)
            
            # Store as Target for framework
            self.add_device(Target(
                address=addr,
                name=name,
                manufacturer=result.manufacturer,
                device_type=result.device_class
            ))
        
        print(" " * 60)  # Clear line
        
        # Print results table
        self._print_results_table(results)
        
        # Save if requested
        if output_file:
            self._save_results(results, output_file)
        
        # Store results
        for r in results:
            self.add_result(r)
        
        vulnerable_count = len([r for r in results if r.status in 
                               [VulnStatus.VULNERABLE, VulnStatus.LIKELY_VULNERABLE]])
        
        return len(results) > 0
