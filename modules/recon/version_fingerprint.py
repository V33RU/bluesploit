"""
BlueSploit Module: Version Fingerprint
Bluetooth Device OS/Firmware Fingerprinting

Identifies the operating system, firmware version, and device type
through Bluetooth protocol analysis and feature enumeration.

"""

import subprocess
import re
from typing import Dict, Any, List, Optional, Tuple
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False

try:
    from bleak import BleakClient, BleakScanner
    import asyncio
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# Device class codes for identification
DEVICE_CLASSES = {
    # Major Device Classes (bits 12-8)
    0x00: "Miscellaneous",
    0x01: "Computer",
    0x02: "Phone",
    0x03: "LAN/Network Access Point",
    0x04: "Audio/Video",
    0x05: "Peripheral",
    0x06: "Imaging",
    0x07: "Wearable",
    0x08: "Toy",
    0x09: "Health",
    0x1F: "Uncategorized"
}

# Minor device classes
MINOR_COMPUTER = {
    0x00: "Uncategorized",
    0x01: "Desktop",
    0x02: "Server",
    0x03: "Laptop",
    0x04: "Handheld/PDA",
    0x05: "Palm-sized",
    0x06: "Wearable",
    0x07: "Tablet"
}

MINOR_PHONE = {
    0x00: "Uncategorized",
    0x01: "Cellular",
    0x02: "Cordless",
    0x03: "Smartphone",
    0x04: "Wired Modem",
    0x05: "ISDN"
}

MINOR_AUDIO = {
    0x00: "Uncategorized",
    0x01: "Headset",
    0x02: "Hands-free",
    0x04: "Microphone",
    0x05: "Loudspeaker",
    0x06: "Headphones",
    0x07: "Portable Audio",
    0x08: "Car Audio",
    0x09: "Set-top Box",
    0x0A: "HiFi Audio",
    0x0B: "VCR",
    0x0C: "Video Camera",
    0x0D: "Camcorder",
    0x0E: "Video Monitor",
    0x0F: "Video Display/Loudspeaker",
    0x10: "Video Conferencing",
    0x12: "Gaming/Toy"
}

MINOR_PERIPHERAL = {
    0x00: "Not Keyboard/Pointing",
    0x01: "Keyboard",
    0x02: "Pointing Device",
    0x03: "Combo Keyboard/Pointing"
}

MINOR_WEARABLE = {
    0x01: "Wristwatch",
    0x02: "Pager",
    0x03: "Jacket",
    0x04: "Helmet",
    0x05: "Glasses"
}

# OS fingerprint patterns based on device name, features, services
OS_FINGERPRINTS = {
    "iOS": {
        "name_patterns": [r"iPhone", r"iPad", r"iPod", r"Apple Watch", r"AirPods"],
        "services": ["0x1200"],  # PnP Information
        "features": ["sc_host", "sc_controller"],
        "manufacturer": "Apple"
    },
    "Android": {
        "name_patterns": [r"Galaxy", r"Pixel", r"SM-", r"Redmi", r"POCO", r"OnePlus", r"Huawei", r"Nokia", r"Xiaomi", r"OPPO", r"vivo"],
        "services": ["0x1200", "0x1116"],
        "features": [],
        "manufacturer": None
    },
    "Windows": {
        "name_patterns": [r"DESKTOP-", r"LAPTOP-", r"Surface", r"WIN-", r"PC-"],
        "services": ["0x1000", "0x1200"],
        "features": ["ssp_host"],
        "manufacturer": "Microsoft"
    },
    "macOS": {
        "name_patterns": [r"MacBook", r"iMac", r"Mac Pro", r"Mac mini", r"'s Mac"],
        "services": ["0x1200"],
        "features": ["sc_host"],
        "manufacturer": "Apple"
    },
    "Linux": {
        "name_patterns": [r"BlueZ", r"ubuntu", r"raspberrypi", r"linux", r"debian"],
        "services": ["0x1200"],
        "features": [],
        "manufacturer": None
    },
    "ESP32": {
        "name_patterns": [r"ESP", r"esp32", r"ESP_"],
        "services": [],
        "features": [],
        "manufacturer": "Espressif"
    },
    "PlayStation": {
        "name_patterns": [r"PS4", r"PS5", r"DualShock", r"DualSense", r"PlayStation"],
        "services": [],
        "features": [],
        "manufacturer": "Sony"
    },
    "Xbox": {
        "name_patterns": [r"Xbox", r"XB1"],
        "services": [],
        "features": [],
        "manufacturer": "Microsoft"
    }
}

# BLE appearance codes
BLE_APPEARANCES = {
    0x0000: ("Unknown", "Generic"),
    0x0040: ("Phone", "Generic Phone"),
    0x0080: ("Computer", "Generic Computer"),
    0x00C0: ("Watch", "Generic Watch"),
    0x00C1: ("Watch", "Sports Watch"),
    0x0100: ("Clock", "Generic Clock"),
    0x0140: ("Display", "Generic Display"),
    0x0180: ("Remote Control", "Generic Remote"),
    0x01C0: ("Eye-glasses", "Generic Eyeglasses"),
    0x0200: ("Tag", "Generic Tag"),
    0x0240: ("Keyring", "Generic Keyring"),
    0x0280: ("Media Player", "Generic Media Player"),
    0x02C0: ("Barcode Scanner", "Generic Barcode"),
    0x0300: ("Thermometer", "Generic Thermometer"),
    0x0340: ("Heart Rate Sensor", "Generic Heart Rate"),
    0x0380: ("Blood Pressure", "Generic Blood Pressure"),
    0x03C0: ("HID", "Generic HID"),
    0x03C1: ("HID", "Keyboard"),
    0x03C2: ("HID", "Mouse"),
    0x03C3: ("HID", "Joystick"),
    0x03C4: ("HID", "Gamepad"),
    0x0440: ("Glucose Meter", "Generic Glucose"),
    0x0480: ("Running Walking Sensor", "Generic Running"),
    0x04C0: ("Cycling", "Generic Cycling"),
    0x0540: ("Pulse Oximeter", "Generic Pulse Ox"),
    0x0580: ("Weight Scale", "Generic Scale"),
    0x05C0: ("Personal Mobility", "Wheelchair"),
    0x0640: ("Continuous Glucose Monitor", "CGM"),
    0x0680: ("Insulin Pump", "Generic Insulin"),
    0x0700: ("Medication Delivery", "Generic Medication"),
    0x0780: ("Outdoor Sports Activity", "Location Display"),
    0x0800: ("Outdoor Sports Activity", "Location Navigation Pod"),
    0x0840: ("Environmental Sensor", "Generic Environmental"),
}


class Module(ScannerModule):
    """
    Version Fingerprint Module
    
    Identifies device OS, firmware, and capabilities through:
    - Device class analysis
    - Name pattern matching
    - Service enumeration
    - Feature detection
    - BLE appearance codes
    - LMP version analysis
    """
    
    info = ModuleInfo(
        name="scanners/version_fingerprint",
        description="Bluetooth Device OS/Firmware Fingerprinting",
        author=["BlueSploit"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/assigned-numbers/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "protocol": ModuleOption(
                name="protocol",
                required=False,
                description="Protocol: auto, classic, or ble",
                default="auto"
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Scan timeout in seconds",
                default=30
            )
        }
    
    def _get_device_name(self, target: str) -> Optional[str]:
        """Get remote device name"""
        try:
            result = subprocess.run(
                ["hcitool", "name", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
        return None
    
    def _get_device_info(self, target: str) -> Dict[str, Any]:
        """Get device info via hcitool"""
        info = {
            "version": None,
            "manufacturer": None,
            "features": [],
            "class": None,
            "class_major": None,
            "class_minor": None
        }
        
        try:
            # Get device info
            result = subprocess.run(
                ["hcitool", "info", target],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse LMP version
                if "LMP Version:" in output:
                    for line in output.split('\n'):
                        if "LMP Version:" in line:
                            match = re.search(r'(\d+\.\d+)', line)
                            if match:
                                info["version"] = match.group(1)
                
                # Parse manufacturer
                if "Manufacturer:" in output:
                    for line in output.split('\n'):
                        if "Manufacturer:" in line:
                            parts = line.split(":")
                            if len(parts) >= 2:
                                info["manufacturer"] = parts[1].strip()
                
                # Parse device class
                if "Device Class:" in output or "Class:" in output:
                    for line in output.split('\n'):
                        if "Class:" in line:
                            match = re.search(r'0x([0-9a-fA-F]+)', line)
                            if match:
                                class_val = int(match.group(1), 16)
                                info["class"] = f"0x{class_val:06X}"
                                info["class_major"] = (class_val >> 8) & 0x1F
                                info["class_minor"] = (class_val >> 2) & 0x3F
            
            # Get features
            result = subprocess.run(
                ["hcitool", "lf", target],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                # Parse features
                feature_keywords = [
                    ("encryption", "encryption"),
                    ("role switch", "role_switch"),
                    ("hold mode", "hold_mode"),
                    ("sniff mode", "sniff_mode"),
                    ("rssi", "rssi"),
                    ("channel quality", "channel_quality"),
                    ("sco link", "sco"),
                    ("hv2 packets", "hv2"),
                    ("hv3 packets", "hv3"),
                    ("ev3 packets", "ev3"),
                    ("ev4 packets", "ev4"),
                    ("ev5 packets", "ev5"),
                    ("afh capable", "afh"),
                    ("3-slot", "3_slot"),
                    ("5-slot", "5_slot"),
                    ("edr", "edr"),
                    ("secure connections", "secure_connections"),
                    ("simple pairing", "ssp"),
                    ("le supported", "le"),
                    ("br/edr", "bredr")
                ]
                
                for keyword, feature in feature_keywords:
                    if keyword in output:
                        info["features"].append(feature)
                        
        except Exception as e:
            pass
        
        return info
    
    def _get_services_sdp(self, target: str) -> List[str]:
        """Get services via SDP"""
        services = []
        
        try:
            result = subprocess.run(
                ["sdptool", "browse", target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Extract service class IDs
                for line in result.stdout.split('\n'):
                    if "Service Class ID List" in line or "0x" in line:
                        matches = re.findall(r'0x([0-9a-fA-F]{4})', line)
                        for match in matches:
                            services.append(f"0x{match}")
                            
        except:
            pass
        
        return list(set(services))
    
    async def _get_ble_info(self, target: str, timeout: int) -> Dict[str, Any]:
        """Get BLE device information"""
        info = {
            "appearance": None,
            "appearance_name": None,
            "device_name": None,
            "manufacturer_data": None,
            "services": []
        }
        
        try:
            # Scan for device
            devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
            
            for addr, (device, adv_data) in devices.items():
                if addr.upper() == target.upper():
                    info["device_name"] = adv_data.local_name
                    
                    # Get appearance
                    if hasattr(adv_data, 'appearance') and adv_data.appearance:
                        info["appearance"] = adv_data.appearance
                        if adv_data.appearance in BLE_APPEARANCES:
                            info["appearance_name"] = BLE_APPEARANCES[adv_data.appearance]
                    
                    # Get manufacturer data
                    if adv_data.manufacturer_data:
                        for mfg_id, data in adv_data.manufacturer_data.items():
                            info["manufacturer_data"] = {
                                "id": mfg_id,
                                "data": data.hex()
                            }
                    
                    # Get service UUIDs
                    info["services"] = list(adv_data.service_uuids) if adv_data.service_uuids else []
                    break
            
            # Connect for more info
            try:
                async with BleakClient(target, timeout=timeout) as client:
                    if client.is_connected:
                        for service in client.services:
                            if service.uuid not in info["services"]:
                                info["services"].append(service.uuid)
            except:
                pass
                
        except Exception as e:
            pass
        
        return info
    
    def _parse_device_class(self, class_major: int, class_minor: int) -> Tuple[str, str]:
        """Parse device class into human-readable strings"""
        major_str = DEVICE_CLASSES.get(class_major, "Unknown")
        minor_str = "Unknown"
        
        if class_major == 0x01:  # Computer
            minor_str = MINOR_COMPUTER.get(class_minor, "Unknown")
        elif class_major == 0x02:  # Phone
            minor_str = MINOR_PHONE.get(class_minor, "Unknown")
        elif class_major == 0x04:  # Audio/Video
            minor_str = MINOR_AUDIO.get(class_minor, "Unknown")
        elif class_major == 0x05:  # Peripheral
            minor_str = MINOR_PERIPHERAL.get(class_minor & 0x03, "Unknown")
        elif class_major == 0x07:  # Wearable
            minor_str = MINOR_WEARABLE.get(class_minor, "Unknown")
        
        return major_str, minor_str
    
    def _fingerprint_os(self, name: str, manufacturer: str, 
                        features: List[str], services: List[str]) -> Dict[str, Any]:
        """Fingerprint OS based on collected data"""
        result = {
            "os": "Unknown",
            "confidence": 0,
            "matches": []
        }
        
        for os_name, patterns in OS_FINGERPRINTS.items():
            score = 0
            matches = []
            
            # Check name patterns
            if name:
                for pattern in patterns["name_patterns"]:
                    if re.search(pattern, name, re.IGNORECASE):
                        score += 40
                        matches.append(f"Name matches '{pattern}'")
                        break
            
            # Check manufacturer
            if patterns["manufacturer"] and manufacturer:
                if patterns["manufacturer"].lower() in manufacturer.lower():
                    score += 30
                    matches.append(f"Manufacturer: {manufacturer}")
            
            # Check services
            for svc in patterns["services"]:
                if svc in services:
                    score += 10
                    matches.append(f"Service {svc}")
            
            # Check features
            for feat in patterns["features"]:
                if feat in features:
                    score += 10
                    matches.append(f"Feature: {feat}")
            
            if score > result["confidence"]:
                result["os"] = os_name
                result["confidence"] = score
                result["matches"] = matches
        
        return result
    
    def _print_results(self, target: str, fingerprint: Dict) -> None:
        """Print fingerprint results"""
        C = Colors
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}DEVICE FINGERPRINT RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*70}{C.RESET}")
        
        print(f"\n  {C.BOLD}TARGET{C.RESET}")
        print(f"  {C.CYAN}{'-'*70}{C.RESET}")
        print(f"  BD_ADDR       : {C.WHITE}{target}{C.RESET}")
        print(f"  Device Name   : {fingerprint.get('name', 'Unknown')}")
        
        # Device class
        if fingerprint.get("class_major") is not None:
            major, minor = self._parse_device_class(
                fingerprint["class_major"], 
                fingerprint.get("class_minor", 0)
            )
            print(f"  Device Class  : {major} / {minor}")
            print(f"  Class Code    : {fingerprint.get('class', 'N/A')}")
        
        # OS Fingerprint
        os_result = fingerprint.get("os_fingerprint", {})
        os_name = os_result.get("os", "Unknown")
        confidence = os_result.get("confidence", 0)
        
        print(f"\n  {C.BOLD}OS FINGERPRINT{C.RESET}")
        print(f"  {C.CYAN}{'-'*70}{C.RESET}")
        
        if confidence >= 50:
            color = C.GREEN
        elif confidence >= 30:
            color = C.YELLOW
        else:
            color = C.RED
        
        print(f"  Operating System : {color}{os_name}{C.RESET}")
        print(f"  Confidence       : {color}{confidence}%{C.RESET}")
        
        if os_result.get("matches"):
            print(f"  Evidence         :")
            for match in os_result["matches"]:
                print(f"    - {match}")
        
        # Bluetooth info
        print(f"\n  {C.BOLD}BLUETOOTH INFO{C.RESET}")
        print(f"  {C.CYAN}{'-'*70}{C.RESET}")
        print(f"  LMP Version   : {fingerprint.get('version', 'Unknown')}")
        print(f"  Manufacturer  : {fingerprint.get('manufacturer', 'Unknown')}")
        
        # Features
        features = fingerprint.get("features", [])
        if features:
            print(f"\n  {C.BOLD}FEATURES ({len(features)}){C.RESET}")
            print(f"  {C.CYAN}{'-'*70}{C.RESET}")
            
            # Group features
            feature_str = ", ".join(features[:10])
            print(f"  {feature_str}")
            if len(features) > 10:
                print(f"  ... and {len(features) - 10} more")
        
        # Services
        services = fingerprint.get("services", [])
        if services:
            print(f"\n  {C.BOLD}SERVICES ({len(services)}){C.RESET}")
            print(f"  {C.CYAN}{'-'*70}{C.RESET}")
            for svc in services[:8]:
                print(f"    {svc}")
            if len(services) > 8:
                print(f"    ... and {len(services) - 8} more")
        
        # BLE info
        if fingerprint.get("ble_appearance"):
            print(f"\n  {C.BOLD}BLE INFO{C.RESET}")
            print(f"  {C.CYAN}{'-'*70}{C.RESET}")
            print(f"  Appearance    : {fingerprint['ble_appearance']}")
            if fingerprint.get("ble_manufacturer"):
                print(f"  MFG Data      : {fingerprint['ble_manufacturer']}")
        
        # Security assessment
        print(f"\n  {C.BOLD}SECURITY INDICATORS{C.RESET}")
        print(f"  {C.CYAN}{'-'*70}{C.RESET}")
        
        if "secure_connections" in features:
            print(f"  {C.GREEN}✓ Secure Connections supported{C.RESET}")
        else:
            print(f"  {C.YELLOW}✗ Secure Connections NOT detected{C.RESET}")
        
        if "ssp" in features:
            print(f"  {C.GREEN}✓ Secure Simple Pairing supported{C.RESET}")
        else:
            print(f"  {C.YELLOW}✗ SSP NOT detected{C.RESET}")
        
        if "encryption" in features:
            print(f"  {C.GREEN}✓ Encryption supported{C.RESET}")
        
        if "le" in features:
            print(f"  {C.CYAN}• BLE supported{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute fingerprinting"""
        
        target = self.target
        protocol = self.get_option("protocol")
        timeout = int(self.get_option("timeout"))
        
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        C = Colors
        print(f"\n  {C.CYAN}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET} {C.BOLD}Device Fingerprinting{C.RESET}                                 {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═'*55}╝{C.RESET}")
        
        print_info(f"Target: {target}")
        print_info(f"Protocol: {protocol}")
        print_info("Gathering device information...")
        
        fingerprint = {
            "target": target,
            "name": None,
            "version": None,
            "manufacturer": None,
            "features": [],
            "services": [],
            "class": None,
            "class_major": None,
            "class_minor": None,
            "os_fingerprint": {},
            "ble_appearance": None,
            "ble_manufacturer": None
        }
        
        # Get device name
        print_info("Getting device name...")
        name = self._get_device_name(target)
        if name:
            fingerprint["name"] = name
            print_success(f"Name: {name}")
        
        # Get Classic Bluetooth info
        if protocol in ["auto", "classic"]:
            print_info("Getting Classic Bluetooth info...")
            info = self._get_device_info(target)
            
            fingerprint["version"] = info["version"]
            fingerprint["manufacturer"] = info["manufacturer"]
            fingerprint["features"] = info["features"]
            fingerprint["class"] = info["class"]
            fingerprint["class_major"] = info["class_major"]
            fingerprint["class_minor"] = info["class_minor"]
            
            if info["manufacturer"]:
                print_success(f"Manufacturer: {info['manufacturer']}")
            
            # Get SDP services
            print_info("Enumerating SDP services...")
            services = self._get_services_sdp(target)
            fingerprint["services"] = services
            if services:
                print_success(f"Found {len(services)} services")
        
        # Get BLE info
        if protocol in ["auto", "ble"] and BLEAK_AVAILABLE:
            print_info("Getting BLE info...")
            try:
                ble_info = asyncio.run(self._get_ble_info(target, timeout))
                
                if ble_info["appearance_name"]:
                    fingerprint["ble_appearance"] = ble_info["appearance_name"]
                
                if ble_info["manufacturer_data"]:
                    fingerprint["ble_manufacturer"] = ble_info["manufacturer_data"]
                
                if ble_info["device_name"] and not fingerprint["name"]:
                    fingerprint["name"] = ble_info["device_name"]
                
                # Add BLE services
                for svc in ble_info["services"]:
                    if svc not in fingerprint["services"]:
                        fingerprint["services"].append(svc)
                        
            except Exception as e:
                print_warning(f"BLE scan failed: {e}")
        
        # Perform OS fingerprinting
        print_info("Analyzing fingerprint...")
        os_result = self._fingerprint_os(
            fingerprint["name"],
            fingerprint["manufacturer"],
            fingerprint["features"],
            fingerprint["services"]
        )
        fingerprint["os_fingerprint"] = os_result
        
        # Print results
        self._print_results(target, fingerprint)
        
        # Store result
        self.add_result(fingerprint)
        
        return fingerprint["os_fingerprint"]["confidence"] > 0
