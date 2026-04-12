"""
BlueSploit Module: OUI Lookup
Bluetooth MAC Address Manufacturer Identification

Looks up device manufacturer from BD_ADDR OUI (first 3 bytes)
and provides detailed vendor information.

Author: v33ru
"""

import re
import urllib.request
from typing import Dict, Any, List, Optional, Tuple
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


# Built-in OUI database for common Bluetooth manufacturers
BUILTIN_OUI_DB = {
    # Apple
    "00:03:93": ("Apple", "Apple, Inc."),
    "00:0A:27": ("Apple", "Apple, Inc."),
    "00:0A:95": ("Apple", "Apple, Inc."),
    "00:0D:93": ("Apple", "Apple, Inc."),
    "00:11:24": ("Apple", "Apple, Inc."),
    "00:14:51": ("Apple", "Apple, Inc."),
    "00:16:CB": ("Apple", "Apple, Inc."),
    "00:17:F2": ("Apple", "Apple, Inc."),
    "00:19:E3": ("Apple", "Apple, Inc."),
    "00:1B:63": ("Apple", "Apple, Inc."),
    "00:1C:B3": ("Apple", "Apple, Inc."),
    "00:1D:4F": ("Apple", "Apple, Inc."),
    "00:1E:52": ("Apple", "Apple, Inc."),
    "00:1E:C2": ("Apple", "Apple, Inc."),
    "00:1F:5B": ("Apple", "Apple, Inc."),
    "00:1F:F3": ("Apple", "Apple, Inc."),
    "00:21:E9": ("Apple", "Apple, Inc."),
    "00:22:41": ("Apple", "Apple, Inc."),
    "00:23:12": ("Apple", "Apple, Inc."),
    "00:23:32": ("Apple", "Apple, Inc."),
    "00:23:6C": ("Apple", "Apple, Inc."),
    "00:23:DF": ("Apple", "Apple, Inc."),
    "00:24:36": ("Apple", "Apple, Inc."),
    "00:25:00": ("Apple", "Apple, Inc."),
    "00:25:4B": ("Apple", "Apple, Inc."),
    "00:25:BC": ("Apple", "Apple, Inc."),
    "00:26:08": ("Apple", "Apple, Inc."),
    "00:26:4A": ("Apple", "Apple, Inc."),
    "00:26:B0": ("Apple", "Apple, Inc."),
    "00:26:BB": ("Apple", "Apple, Inc."),
    
    # Samsung
    "00:00:F0": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:02:78": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:07:AB": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:09:18": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:0D:AE": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:0D:E5": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:12:47": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:12:FB": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:13:77": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:15:99": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:15:B9": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:16:32": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:16:6B": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:16:6C": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:16:DB": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:17:C9": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:17:D5": ("Samsung", "Samsung Electronics Co.,Ltd"),
    "00:18:AF": ("Samsung", "Samsung Electronics Co.,Ltd"),
    
    # Google
    "00:1A:11": ("Google", "Google, Inc."),
    "3C:5A:B4": ("Google", "Google, Inc."),
    "54:60:09": ("Google", "Google, Inc."),
    "94:EB:2C": ("Google", "Google, Inc."),
    "F4:F5:D8": ("Google", "Google, Inc."),
    "F4:F5:E8": ("Google", "Google, Inc."),
    
    # Espressif (ESP32)
    "24:0A:C4": ("Espressif", "Espressif Inc."),
    "24:62:AB": ("Espressif", "Espressif Inc."),
    "24:6F:28": ("Espressif", "Espressif Inc."),
    "30:AE:A4": ("Espressif", "Espressif Inc."),
    "3C:71:BF": ("Espressif", "Espressif Inc."),
    "40:F5:20": ("Espressif", "Espressif Inc."),
    "4C:11:AE": ("Espressif", "Espressif Inc."),
    "54:5A:A6": ("Espressif", "Espressif Inc."),
    "5C:CF:7F": ("Espressif", "Espressif Inc."),
    "60:01:94": ("Espressif", "Espressif Inc."),
    "68:C6:3A": ("Espressif", "Espressif Inc."),
    "84:0D:8E": ("Espressif", "Espressif Inc."),
    "84:CC:A8": ("Espressif", "Espressif Inc."),
    "84:F3:EB": ("Espressif", "Espressif Inc."),
    "A4:CF:12": ("Espressif", "Espressif Inc."),
    "A4:7B:9D": ("Espressif", "Espressif Inc."),
    "AC:67:B2": ("Espressif", "Espressif Inc."),
    "B4:E6:2D": ("Espressif", "Espressif Inc."),
    "BC:DD:C2": ("Espressif", "Espressif Inc."),
    "C4:4F:33": ("Espressif", "Espressif Inc."),
    "CC:50:E3": ("Espressif", "Espressif Inc."),
    "D8:A0:1D": ("Espressif", "Espressif Inc."),
    "DC:4F:22": ("Espressif", "Espressif Inc."),
    "EC:FA:BC": ("Espressif", "Espressif Inc."),
    
    # Nordic Semiconductor
    "00:19:0E": ("Nordic", "Nordic Semiconductor ASA"),
    "C0:F4:E3": ("Nordic", "Nordic Semiconductor ASA"),
    "D4:CA:6E": ("Nordic", "Nordic Semiconductor ASA"),
    "E7:C8:1F": ("Nordic", "Nordic Semiconductor ASA"),
    "F0:5C:D5": ("Nordic", "Nordic Semiconductor ASA"),
    "F8:E7:1E": ("Nordic", "Nordic Semiconductor ASA"),
    
    # Texas Instruments
    "00:12:37": ("Texas Instruments", "Texas Instruments"),
    "00:17:83": ("Texas Instruments", "Texas Instruments"),
    "00:17:E3": ("Texas Instruments", "Texas Instruments"),
    "00:17:E6": ("Texas Instruments", "Texas Instruments"),
    "00:17:E7": ("Texas Instruments", "Texas Instruments"),
    "00:17:E8": ("Texas Instruments", "Texas Instruments"),
    "00:17:E9": ("Texas Instruments", "Texas Instruments"),
    "00:17:EA": ("Texas Instruments", "Texas Instruments"),
    "00:17:EB": ("Texas Instruments", "Texas Instruments"),
    "00:17:EC": ("Texas Instruments", "Texas Instruments"),
    "00:18:2F": ("Texas Instruments", "Texas Instruments"),
    "00:18:30": ("Texas Instruments", "Texas Instruments"),
    "00:18:31": ("Texas Instruments", "Texas Instruments"),
    "00:18:32": ("Texas Instruments", "Texas Instruments"),
    "00:18:33": ("Texas Instruments", "Texas Instruments"),
    "00:18:34": ("Texas Instruments", "Texas Instruments"),
    "D0:39:72": ("Texas Instruments", "Texas Instruments"),
    "D0:B5:C2": ("Texas Instruments", "Texas Instruments"),
    "F4:B8:5E": ("Texas Instruments", "Texas Instruments"),
    
    # Qualcomm
    "00:03:7A": ("Qualcomm", "Qualcomm Inc."),
    "00:0A:F5": ("Qualcomm", "Qualcomm Inc."),
    "00:21:D1": ("Qualcomm", "Qualcomm Inc."),
    "00:24:D6": ("Qualcomm", "Qualcomm Inc."),
    "8C:FD:F0": ("Qualcomm", "Qualcomm Inc."),
    
    # Broadcom
    "00:03:19": ("Broadcom", "Broadcom Corporation"),
    "00:05:B5": ("Broadcom", "Broadcom Corporation"),
    "00:0A:F7": ("Broadcom", "Broadcom Corporation"),
    "00:10:18": ("Broadcom", "Broadcom Corporation"),
    "00:10:20": ("Broadcom", "Broadcom Corporation"),
    "00:1A:2B": ("Broadcom", "Broadcom Corporation"),
    "00:23:76": ("Broadcom", "Broadcom Corporation"),
    "00:24:D7": ("Broadcom", "Broadcom Corporation"),
    "00:25:56": ("Broadcom", "Broadcom Corporation"),
    "00:27:19": ("Broadcom", "Broadcom Corporation"),
    "20:16:D8": ("Broadcom", "Broadcom Corporation"),
    
    # Intel
    "00:02:B3": ("Intel", "Intel Corporation"),
    "00:03:47": ("Intel", "Intel Corporation"),
    "00:04:23": ("Intel", "Intel Corporation"),
    "00:07:E9": ("Intel", "Intel Corporation"),
    "00:0C:F1": ("Intel", "Intel Corporation"),
    "00:0E:0C": ("Intel", "Intel Corporation"),
    "00:0E:35": ("Intel", "Intel Corporation"),
    "00:11:11": ("Intel", "Intel Corporation"),
    "00:12:F0": ("Intel", "Intel Corporation"),
    "00:13:02": ("Intel", "Intel Corporation"),
    "00:13:20": ("Intel", "Intel Corporation"),
    "00:13:CE": ("Intel", "Intel Corporation"),
    "00:13:E8": ("Intel", "Intel Corporation"),
    "00:15:00": ("Intel", "Intel Corporation"),
    "00:15:17": ("Intel", "Intel Corporation"),
    "00:16:6F": ("Intel", "Intel Corporation"),
    "00:16:76": ("Intel", "Intel Corporation"),
    "00:16:EA": ("Intel", "Intel Corporation"),
    "00:16:EB": ("Intel", "Intel Corporation"),
    "00:18:DE": ("Intel", "Intel Corporation"),
    "00:19:D1": ("Intel", "Intel Corporation"),
    "00:19:D2": ("Intel", "Intel Corporation"),
    "00:1B:21": ("Intel", "Intel Corporation"),
    "00:1B:77": ("Intel", "Intel Corporation"),
    "00:1C:BF": ("Intel", "Intel Corporation"),
    "00:1C:C0": ("Intel", "Intel Corporation"),
    "00:1D:E0": ("Intel", "Intel Corporation"),
    "00:1D:E1": ("Intel", "Intel Corporation"),
    "00:1E:64": ("Intel", "Intel Corporation"),
    "00:1E:65": ("Intel", "Intel Corporation"),
    "00:1E:67": ("Intel", "Intel Corporation"),
    "00:1F:3B": ("Intel", "Intel Corporation"),
    "00:1F:3C": ("Intel", "Intel Corporation"),
    
    # Realtek
    "00:E0:4C": ("Realtek", "Realtek Semiconductor Corp."),
    "52:54:00": ("Realtek", "Realtek (QEMU virtual)"),
    
    # Cypress/Infineon
    "00:10:C6": ("Cypress", "Cypress Semiconductor"),
    "00:A0:50": ("Cypress", "Cypress Semiconductor"),
    
    # Cambridge Silicon Radio (CSR)
    "00:02:5B": ("CSR", "Cambridge Silicon Radio"),
    "00:02:72": ("CSR", "Cambridge Silicon Radio"),
    "00:02:C7": ("CSR", "Cambridge Silicon Radio"),
    "00:11:67": ("CSR", "Cambridge Silicon Radio"),
    "00:13:04": ("CSR", "Cambridge Silicon Radio"),
    "00:19:63": ("CSR", "Cambridge Silicon Radio"),
    "00:1A:7D": ("CSR", "Cambridge Silicon Radio"),
    "00:1B:DC": ("CSR", "Cambridge Silicon Radio"),
    "00:1E:A4": ("CSR", "Cambridge Silicon Radio"),
    "00:1E:DE": ("CSR", "Cambridge Silicon Radio"),
    "00:23:3D": ("CSR", "Cambridge Silicon Radio"),
    "00:24:03": ("CSR", "Cambridge Silicon Radio"),
    "00:25:BF": ("CSR", "Cambridge Silicon Radio"),
    
    # Sony
    "00:01:4A": ("Sony", "Sony Corporation"),
    "00:0A:D9": ("Sony", "Sony Corporation"),
    "00:0B:0D": ("Sony", "Sony Corporation"),
    "00:0D:F0": ("Sony", "Sony Corporation"),
    "00:0E:07": ("Sony", "Sony Corporation"),
    "00:12:EE": ("Sony", "Sony Corporation"),
    "00:13:15": ("Sony", "Sony Corporation"),
    "00:13:A9": ("Sony", "Sony Corporation"),
    "00:15:C1": ("Sony", "Sony Corporation"),
    "00:16:20": ("Sony", "Sony Corporation"),
    "00:18:13": ("Sony", "Sony Corporation"),
    "00:19:C5": ("Sony", "Sony Corporation"),
    "00:1A:80": ("Sony", "Sony Corporation"),
    "00:1B:59": ("Sony", "Sony Corporation"),
    "00:1C:A4": ("Sony", "Sony Corporation"),
    "00:1D:28": ("Sony", "Sony Corporation"),
    "00:1D:BA": ("Sony", "Sony Corporation"),
    "00:1E:4C": ("Sony", "Sony Corporation"),
    "00:1E:DC": ("Sony", "Sony Corporation"),
    "00:1F:E4": ("Sony", "Sony Corporation"),
    
    # Microsoft
    "00:0D:3A": ("Microsoft", "Microsoft Corporation"),
    "00:12:5A": ("Microsoft", "Microsoft Corporation"),
    "00:15:5D": ("Microsoft", "Microsoft Corporation"),
    "00:17:FA": ("Microsoft", "Microsoft Corporation"),
    "00:1D:D8": ("Microsoft", "Microsoft Corporation"),
    "00:22:48": ("Microsoft", "Microsoft Corporation"),
    "00:25:AE": ("Microsoft", "Microsoft Corporation"),
    "00:50:F2": ("Microsoft", "Microsoft Corporation"),
    "28:18:78": ("Microsoft", "Microsoft Corporation"),
    
    # Xiaomi
    "04:CF:8C": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "0C:1D:AF": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "10:2A:B3": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "14:F6:5A": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "18:59:36": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "20:34:FB": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "28:6C:07": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "34:80:B3": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "38:A4:ED": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "3C:BD:3E": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "50:64:2B": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "58:44:98": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "64:09:80": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "64:B4:73": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "68:DF:DD": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "74:23:44": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "7C:1C:4E": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "84:F3:EB": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "8C:BE:BE": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "98:FA:E3": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "9C:99:A0": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "A0:86:C6": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "AC:C1:EE": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "B0:E2:35": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "C4:0B:CB": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "C8:0C:C8": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "D4:97:0B": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "E4:46:DA": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "F0:B4:29": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "F8:A4:5F": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    "FC:64:BA": ("Xiaomi", "Xiaomi Communications Co Ltd"),
    
    # Huawei
    "00:18:82": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:1E:10": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:22:A1": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:25:68": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:25:9E": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:46:4B": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:66:4B": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:9A:CD": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "00:E0:FC": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "04:02:1F": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "04:25:C5": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "04:33:89": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "04:47:D6": ("Huawei", "Huawei Technologies Co.,Ltd"),
    "04:4F:4C": ("Huawei", "Huawei Technologies Co.,Ltd"),
    
    # Tile
    "C4:5B:BE": ("Tile", "Tile, Inc."),
    "D4:F5:47": ("Tile", "Tile, Inc."),
    "E3:2F:5E": ("Tile", "Tile, Inc."),
    
    # Fitbit
    "C0:E1:BE": ("Fitbit", "Fitbit, Inc."),
    "CB:36:1D": ("Fitbit", "Fitbit, Inc."),
    "E0:C5:3A": ("Fitbit", "Fitbit, Inc."),
    
    # Bose
    "00:0C:8A": ("Bose", "Bose Corporation"),
    "04:52:C7": ("Bose", "Bose Corporation"),
    "08:DF:1F": ("Bose", "Bose Corporation"),
    "2C:41:A1": ("Bose", "Bose Corporation"),
    "4C:87:5D": ("Bose", "Bose Corporation"),
    
    # JBL/Harman
    "00:02:3C": ("Harman", "Harman International"),
    "00:14:9A": ("Harman", "Harman International"),
    "00:1E:B2": ("Harman", "Harman International"),
    "70:99:1C": ("Harman", "Harman International"),
    "94:30:49": ("Harman", "Harman International"),
}

# Device type hints based on manufacturer
DEVICE_TYPE_HINTS = {
    "Apple": ["iPhone", "iPad", "Mac", "Apple Watch", "AirPods", "HomePod"],
    "Samsung": ["Galaxy Phone", "Galaxy Tab", "Galaxy Watch", "Galaxy Buds", "Smart TV"],
    "Google": ["Pixel Phone", "Nest", "Chromecast", "Pixel Buds"],
    "Espressif": ["ESP32 IoT Device", "Smart Home Device", "DIY Project"],
    "Nordic": ["BLE Beacon", "Fitness Tracker", "IoT Sensor", "Smart Watch"],
    "Texas Instruments": ["BLE Beacon", "Industrial IoT", "Sensor Tag"],
    "Xiaomi": ["Mi Phone", "Mi Band", "Mi Earbuds", "Smart Home"],
    "Huawei": ["Phone", "Watch", "Earbuds", "Smart Device"],
    "Tile": ["Bluetooth Tracker"],
    "Fitbit": ["Fitness Tracker", "Smartwatch"],
    "Bose": ["Headphones", "Speaker", "Earbuds"],
    "Harman": ["JBL Speaker", "JBL Headphones", "Audio Device"],
    "Sony": ["Headphones", "Speaker", "PlayStation", "Camera"],
    "Microsoft": ["Surface", "Xbox Controller", "Mouse", "Keyboard"],
}


class Module(ScannerModule):
    """
    OUI Lookup Module
    
    Identifies device manufacturer from Bluetooth MAC address.
    Uses built-in database and optional online lookup.
    
    Features:
    - Fast built-in lookup for common manufacturers
    - Online lookup via IEEE database
    - Device type hints
    - Batch lookup support
    """
    
    info = ModuleInfo(
        name="scanners/oui_lookup",
        description="Bluetooth MAC Address OUI Manufacturer Lookup",
        author=["v33ru"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
        references=[
            "https://standards-oui.ieee.org/",
            "https://www.wireshark.org/tools/oui-lookup.html"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="BD_ADDR or comma-separated list (XX:XX:XX:XX:XX:XX)"
            ),
            "online": ModuleOption(
                name="online",
                required=False,
                description="Use online lookup if not in database",
                default=False
            ),
            "verbose": ModuleOption(
                name="verbose",
                required=False,
                description="Show detailed output",
                default=True
            )
        }
    
    def _normalize_mac(self, mac: str) -> str:
        """Normalize MAC address format"""
        # Remove common separators and convert to uppercase
        mac = mac.upper().replace("-", ":").replace(".", ":")
        
        # Handle format without separators
        if ":" not in mac and len(mac) == 12:
            mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
        
        return mac
    
    def _get_oui(self, mac: str) -> str:
        """Extract OUI (first 3 bytes) from MAC"""
        mac = self._normalize_mac(mac)
        parts = mac.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3])
        return mac
    
    def _lookup_builtin(self, oui: str) -> Optional[Tuple[str, str]]:
        """Lookup OUI in built-in database"""
        return BUILTIN_OUI_DB.get(oui.upper())
    
    def _lookup_online(self, oui: str) -> Optional[Tuple[str, str]]:
        """Lookup OUI via online API"""
        try:
            # Use macvendors.co API (free, no key needed)
            url = f"https://api.macvendors.com/{oui}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'BlueSploit/1.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                vendor = response.read().decode('utf-8').strip()
                if vendor and "errors" not in vendor.lower():
                    # Extract short name
                    short_name = vendor.split()[0] if vendor else "Unknown"
                    return (short_name, vendor)
                    
        except Exception as e:
            pass
        
        return None
    
    def _get_device_hints(self, manufacturer: str) -> List[str]:
        """Get device type hints for manufacturer"""
        return DEVICE_TYPE_HINTS.get(manufacturer, ["Unknown device type"])
    
    def _lookup_single(self, mac: str, use_online: bool) -> Dict[str, Any]:
        """Lookup single MAC address"""
        result = {
            "mac": mac,
            "oui": "",
            "manufacturer": "Unknown",
            "vendor_full": "Unknown",
            "device_hints": [],
            "source": "none"
        }
        
        mac = self._normalize_mac(mac)
        oui = self._get_oui(mac)
        result["mac"] = mac
        result["oui"] = oui
        
        # Try built-in first
        lookup = self._lookup_builtin(oui)
        if lookup:
            result["manufacturer"] = lookup[0]
            result["vendor_full"] = lookup[1]
            result["device_hints"] = self._get_device_hints(lookup[0])
            result["source"] = "builtin"
            return result
        
        # Try online if enabled
        if use_online:
            lookup = self._lookup_online(oui)
            if lookup:
                result["manufacturer"] = lookup[0]
                result["vendor_full"] = lookup[1]
                result["device_hints"] = self._get_device_hints(lookup[0])
                result["source"] = "online"
                return result
        
        return result
    
    def _print_result(self, result: Dict, verbose: bool) -> None:
        """Print single lookup result"""
        C = Colors
        
        mac = result["mac"]
        mfg = result["manufacturer"]
        found = mfg != "Unknown"
        
        color = C.GREEN if found else C.YELLOW
        
        print(f"\n  {C.BOLD}MAC Address:{C.RESET} {C.WHITE}{mac}{C.RESET}")
        print(f"  {C.BOLD}OUI:{C.RESET}         {result['oui']}")
        print(f"  {C.BOLD}Manufacturer:{C.RESET} {color}{mfg}{C.RESET}")
        
        if verbose and found:
            print(f"  {C.BOLD}Full Name:{C.RESET}    {result['vendor_full']}")
            print(f"  {C.BOLD}Source:{C.RESET}       {result['source']}")
            
            if result["device_hints"]:
                hints = ", ".join(result["device_hints"][:3])
                print(f"  {C.BOLD}Likely Types:{C.RESET} {hints}")
    
    def _print_summary(self, results: List[Dict]) -> None:
        """Print summary of all lookups"""
        C = Colors
        
        total = len(results)
        found = sum(1 for r in results if r["manufacturer"] != "Unknown")
        
        # Count by manufacturer
        mfg_counts = {}
        for r in results:
            mfg = r["manufacturer"]
            mfg_counts[mfg] = mfg_counts.get(mfg, 0) + 1
        
        print(f"\n  {C.CYAN}{'='*60}{C.RESET}")
        print(f"  {C.BOLD}OUI LOOKUP SUMMARY{C.RESET}")
        print(f"  {C.CYAN}{'='*60}{C.RESET}")
        print(f"  Total Addresses : {total}")
        print(f"  Identified      : {C.GREEN}{found}{C.RESET}")
        print(f"  Unknown         : {C.YELLOW}{total - found}{C.RESET}")
        
        if found > 0:
            print(f"\n  {C.BOLD}Manufacturers Found:{C.RESET}")
            for mfg, count in sorted(mfg_counts.items(), key=lambda x: -x[1]):
                if mfg != "Unknown":
                    print(f"    {mfg}: {count}")
        
        print(f"\n  {C.CYAN}{'='*60}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute OUI lookup"""
        
        target = self.get_option("target")
        use_online = self.get_option("online")
        verbose = self.get_option("verbose")
        
        # Parse multiple addresses
        addresses = [t.strip() for t in target.split(",")]
        
        # Validate addresses
        valid_addresses = []
        for addr in addresses:
            normalized = self._normalize_mac(addr)
            if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', normalized):
                valid_addresses.append(normalized)
            elif re.match(r'^([0-9A-F]{2}:){2}[0-9A-F]{2}$', normalized):
                # OUI only
                valid_addresses.append(normalized)
            else:
                print_warning(f"Invalid MAC format: {addr}")
        
        if not valid_addresses:
            print_error("No valid MAC addresses provided!")
            return False
        
        C = Colors
        print(f"\n  {C.CYAN}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET} {C.BOLD}OUI Manufacturer Lookup{C.RESET}                              {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═'*55}╝{C.RESET}")
        
        print_info(f"Looking up {len(valid_addresses)} address(es)...")
        if use_online:
            print_info("Online lookup enabled")
        
        results = []
        
        for addr in valid_addresses:
            result = self._lookup_single(addr, use_online)
            results.append(result)
            self._print_result(result, verbose)
        
        if len(results) > 1:
            self._print_summary(results)
        
        # Store results
        for result in results:
            self.add_result(result)
        
        found = sum(1 for r in results if r["manufacturer"] != "Unknown")
        return found > 0
