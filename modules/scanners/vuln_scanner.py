"""
BlueSploit Module: Vulnerability Scanner
Automatic Bluetooth CVE Detection

Automatically scans devices and identifies potential vulnerabilities
based on device characteristics, OS fingerprint, and feature analysis.

Author: v33ru
"""

import subprocess
import time
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
    import bluetooth
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False


# CVE Database with detection criteria
CVE_DATABASE = {
    # BlueBorne Family (2017)
    "CVE-2017-0781": {
        "name": "BlueBorne BNEP Heap Overflow",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "targets": ["Android"],
        "versions": ["4.4.4 - 7.1.2", "8.0 (unpatched)"],
        "detection": {
            "os": ["Android"],
            "services": ["BNEP", "0x000F"],
            "features": []
        },
        "description": "Heap overflow in Android BNEP processing",
        "module": "exploits/classic/blueborne_leak",
        "patched": "September 2017"
    },
    "CVE-2017-0785": {
        "name": "BlueBorne SDP Info Leak",
        "severity": "HIGH",
        "cvss": 7.5,
        "targets": ["Android"],
        "versions": ["4.4.4 - 8.0 (unpatched)"],
        "detection": {
            "os": ["Android"],
            "services": ["SDP", "0x0001"],
            "features": []
        },
        "description": "Information disclosure via SDP",
        "module": "exploits/classic/blueborne_sdp",
        "patched": "September 2017"
    },
    "CVE-2017-1000251": {
        "name": "BlueBorne Linux L2CAP RCE",
        "severity": "CRITICAL",
        "cvss": 8.1,
        "targets": ["Linux"],
        "versions": ["kernel 3.3-rc1 to 4.13.1"],
        "detection": {
            "os": ["Linux"],
            "services": [],
            "features": ["ertm", "streaming"]
        },
        "description": "Stack buffer overflow in L2CAP config",
        "module": "exploits/classic/blueborne_linux_rce",
        "patched": "September 2017"
    },
    
    # KNOB Attack (2019)
    "CVE-2019-9506": {
        "name": "KNOB Attack",
        "severity": "HIGH",
        "cvss": 7.5,
        "targets": ["All BR/EDR"],
        "versions": ["All before Aug 2019 patches"],
        "detection": {
            "os": [],
            "services": [],
            "features": ["encryption", "bredr"],
            "no_features": ["secure_connections"]
        },
        "description": "Encryption key entropy reduction",
        "module": "exploits/classic/knob",
        "patched": "August 2019"
    },
    
    # BlueFrag (2020)
    "CVE-2020-0022": {
        "name": "BlueFrag",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "targets": ["Android"],
        "versions": ["8.0 - 9.0 (RCE)", "10.0 (DoS)"],
        "detection": {
            "os": ["Android"],
            "services": ["A2DP", "AVDTP", "0x0019"],
            "features": []
        },
        "description": "A2DP heap overflow RCE",
        "module": "exploits/classic/bluefrag",
        "patched": "February 2020"
    },
    
    # BIAS Attack (2020)
    "CVE-2020-10135": {
        "name": "BIAS Attack",
        "severity": "HIGH",
        "cvss": 7.5,
        "targets": ["All BR/EDR"],
        "versions": ["All before June 2020"],
        "detection": {
            "os": [],
            "services": [],
            "features": ["bredr"],
            "no_features": ["secure_connections"]
        },
        "description": "Bluetooth impersonation attacks",
        "module": "exploits/classic/bias",
        "patched": "June 2020"
    },
    
    # BleedingTooth (2020)
    "CVE-2020-12351": {
        "name": "BadKarma (BleedingTooth)",
        "severity": "CRITICAL",
        "cvss": 8.3,
        "targets": ["Linux"],
        "versions": ["kernel 4.8 - 5.9"],
        "detection": {
            "os": ["Linux"],
            "services": [],
            "features": ["bredr"]
        },
        "description": "L2CAP type confusion RCE",
        "module": "exploits/classic/badkarma",
        "patched": "October 2020"
    },
    "CVE-2020-12352": {
        "name": "BadChoice (BleedingTooth)",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "targets": ["Linux"],
        "versions": ["kernel 3.6 - 5.9"],
        "detection": {
            "os": ["Linux"],
            "services": [],
            "features": ["bredr"]
        },
        "description": "A2MP stack info leak",
        "module": "exploits/classic/badchoice",
        "patched": "October 2020"
    },
    
    # BrakTooth (2021)
    "CVE-2021-28139": {
        "name": "BrakTooth ESP32",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "targets": ["ESP32"],
        "versions": ["ESP-IDF < 4.4"],
        "detection": {
            "os": ["ESP32"],
            "manufacturer": ["Espressif"],
            "services": [],
            "features": []
        },
        "description": "Feature page arbitrary code execution",
        "module": "exploits/classic/braktooth_esp32",
        "patched": "ESP-IDF 4.4"
    },
    
    # Keystroke Injection (2023)
    "CVE-2023-45866": {
        "name": "0-Click Keystroke Injection",
        "severity": "CRITICAL",
        "cvss": 8.8,
        "targets": ["Android", "Linux", "macOS", "iOS"],
        "versions": ["Android all", "Linux unpatched", "macOS < 14.2", "iOS < 17.2"],
        "detection": {
            "os": ["Android", "Linux", "macOS", "iOS"],
            "services": ["HID", "0x0011", "0x0013"],
            "features": []
        },
        "description": "Unauthenticated HID keystroke injection",
        "module": "exploits/classic/keystroke_injection",
        "patched": "December 2023"
    },
    
    # Additional CVEs
    "CVE-2020-24490": {
        "name": "HCI Event Overflow",
        "severity": "HIGH",
        "cvss": 7.5,
        "targets": ["Linux"],
        "versions": ["kernel 4.19 - 5.7"],
        "detection": {
            "os": ["Linux"],
            "services": [],
            "features": ["le"]
        },
        "description": "Heap overflow in HCI event processing",
        "module": None,
        "patched": "2020"
    },
    "CVE-2021-3564": {
        "name": "BlueZ Double Free",
        "severity": "MEDIUM",
        "cvss": 5.5,
        "targets": ["Linux"],
        "versions": ["BlueZ < 5.59"],
        "detection": {
            "os": ["Linux"],
            "services": [],
            "features": []
        },
        "description": "Double free in disconnect handling",
        "module": None,
        "patched": "2021"
    },
    "CVE-2022-0847": {
        "name": "DirtyPipe (affects BT)",
        "severity": "HIGH",
        "cvss": 7.8,
        "targets": ["Linux"],
        "versions": ["kernel 5.8 - 5.16.11"],
        "detection": {
            "os": ["Linux"],
            "services": [],
            "features": []
        },
        "description": "Pipe buffer overwrite (local priv esc)",
        "module": None,
        "patched": "2022"
    }
}

# Espressif OUI prefixes
ESPRESSIF_OUIS = [
    "24:0A:C4", "24:62:AB", "24:6F:28", "30:AE:A4",
    "3C:71:BF", "40:F5:20", "4C:11:AE", "54:5A:A6",
    "5C:CF:7F", "60:01:94", "68:C6:3A", "84:0D:8E",
    "84:CC:A8", "84:F3:EB", "A4:CF:12", "A4:7B:9D",
    "AC:67:B2", "B4:E6:2D", "BC:DD:C2", "C4:4F:33",
    "CC:50:E3", "D8:A0:1D", "DC:4F:22", "EC:FA:BC"
]


class Module(ScannerModule):
    """
    Vulnerability Scanner Module
    
    Automatically detects potential Bluetooth vulnerabilities by:
    - Fingerprinting the target device
    - Matching against known CVE patterns
    - Checking for vulnerable features/services
    - Suggesting appropriate exploit modules
    """
    
    info = ModuleInfo(
        name="scanners/vuln_scanner",
        description="Automatic Bluetooth Vulnerability Detection",
        author=["v33ru"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
        references=[
            "https://nvd.nist.gov/",
            "https://www.bluetooth.com/security/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "thorough": ModuleOption(
                name="thorough",
                required=False,
                description="Perform thorough scan (slower)",
                default=True
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Scan timeout in seconds",
                default=60
            )
        }
    
    def _get_device_name(self, target: str) -> Optional[str]:
        """Get device name"""
        try:
            result = subprocess.run(
                ["hcitool", "name", target],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        return None
    
    def _get_device_info(self, target: str) -> Dict[str, Any]:
        """Get device info"""
        info = {
            "name": None,
            "manufacturer": None,
            "version": None,
            "features": [],
            "class": None
        }
        
        # Get name
        info["name"] = self._get_device_name(target)
        
        try:
            # Get extended info
            result = subprocess.run(
                ["hcitool", "info", target],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                if "Manufacturer:" in output:
                    for line in output.split('\n'):
                        if "Manufacturer:" in line:
                            info["manufacturer"] = line.split(":", 1)[1].strip()
                
                if "LMP Version:" in output:
                    for line in output.split('\n'):
                        if "LMP Version:" in line:
                            match = re.search(r'(\d+\.\d+)', line)
                            if match:
                                info["version"] = match.group(1)
            
            # Get features
            result = subprocess.run(
                ["hcitool", "lf", target],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                feature_map = {
                    "encryption": "encryption",
                    "secure connections": "secure_connections",
                    "simple pairing": "ssp",
                    "role switch": "role_switch",
                    "ertm": "ertm",
                    "streaming": "streaming",
                    "le supported": "le",
                    "br/edr": "bredr",
                    "3-slot": "3_slot",
                    "5-slot": "5_slot",
                    "edr": "edr"
                }
                
                for keyword, feature in feature_map.items():
                    if keyword in output:
                        info["features"].append(feature)
                        
        except Exception as e:
            pass
        
        return info
    
    def _get_services(self, target: str) -> List[str]:
        """Get SDP services"""
        services = []
        
        try:
            result = subprocess.run(
                ["sdptool", "browse", target],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Extract service names and IDs
                service_names = ["SDP", "RFCOMM", "L2CAP", "BNEP", "AVDTP", 
                               "A2DP", "AVRCP", "HFP", "HSP", "HID",
                               "PAN", "OBEX", "PBAP", "MAP"]
                
                for name in service_names:
                    if name.lower() in output.lower():
                        services.append(name)
                
                # Extract hex service IDs
                matches = re.findall(r'0x([0-9a-fA-F]{4})', output)
                for match in matches:
                    services.append(f"0x{match.upper()}")
                    
        except:
            pass
        
        return list(set(services))
    
    def _fingerprint_os(self, name: str, manufacturer: str, 
                        target: str) -> str:
        """Simple OS fingerprinting"""
        name_lower = (name or "").lower()
        mfg_lower = (manufacturer or "").lower()
        oui = target.upper()[:8]
        
        # Check for ESP32
        if oui in [o.upper() for o in ESPRESSIF_OUIS]:
            return "ESP32"
        if "espressif" in mfg_lower:
            return "ESP32"
        if "esp" in name_lower:
            return "ESP32"
        
        # Check for iOS
        if any(x in name_lower for x in ["iphone", "ipad", "ipod", "airpod", "apple watch"]):
            return "iOS"
        if "apple" in mfg_lower:
            return "iOS"
        
        # Check for Android
        if any(x in name_lower for x in ["galaxy", "pixel", "sm-", "android", "redmi", 
                                          "poco", "oneplus", "huawei", "xiaomi", "oppo"]):
            return "Android"
        
        # Check for macOS
        if any(x in name_lower for x in ["macbook", "imac", "mac pro", "mac mini"]):
            return "macOS"
        
        # Check for Windows
        if any(x in name_lower for x in ["desktop-", "laptop-", "surface", "win-"]):
            return "Windows"
        
        # Check for Linux
        if any(x in name_lower for x in ["linux", "ubuntu", "raspberrypi", "bluez"]):
            return "Linux"
        
        return "Unknown"
    
    def _check_vuln(self, cve_id: str, cve_info: Dict, 
                    device_info: Dict, services: List[str],
                    os_guess: str) -> Tuple[bool, int, List[str]]:
        """Check if device matches vulnerability criteria"""
        detection = cve_info.get("detection", {})
        matches = []
        score = 0
        
        # Check OS match
        target_os = detection.get("os", [])
        if target_os:
            if os_guess in target_os:
                score += 40
                matches.append(f"OS match: {os_guess}")
            else:
                return False, 0, []
        
        # Check manufacturer
        target_mfg = detection.get("manufacturer", [])
        if target_mfg:
            device_mfg = device_info.get("manufacturer", "")
            if any(m.lower() in (device_mfg or "").lower() for m in target_mfg):
                score += 30
                matches.append(f"Manufacturer match")
            else:
                return False, 0, []
        
        # Check services
        target_services = detection.get("services", [])
        for svc in target_services:
            if svc in services or svc.lower() in [s.lower() for s in services]:
                score += 15
                matches.append(f"Service: {svc}")
        
        # Check features
        target_features = detection.get("features", [])
        device_features = device_info.get("features", [])
        for feat in target_features:
            if feat in device_features:
                score += 10
                matches.append(f"Feature: {feat}")
        
        # Check NO features (vulnerability requires absence)
        no_features = detection.get("no_features", [])
        for feat in no_features:
            if feat not in device_features:
                score += 20
                matches.append(f"Missing protection: {feat}")
        
        # Minimum score threshold
        vulnerable = score >= 30 or (not target_os and not target_mfg and score > 0)
        
        return vulnerable, score, matches
    
    def _print_results(self, target: str, device_info: Dict,
                       services: List[str], os_guess: str,
                       vulnerabilities: List[Dict]) -> None:
        """Print scan results"""
        C = Colors
        
        print(f"\n  {C.CYAN}{'='*75}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}VULNERABILITY SCAN RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*75}{C.RESET}")
        
        # Device info
        print(f"\n  {C.BOLD}TARGET DEVICE{C.RESET}")
        print(f"  {C.CYAN}{'-'*75}{C.RESET}")
        print(f"  BD_ADDR       : {C.WHITE}{target}{C.RESET}")
        print(f"  Name          : {device_info.get('name', 'Unknown')}")
        print(f"  Manufacturer  : {device_info.get('manufacturer', 'Unknown')}")
        print(f"  OS Guess      : {C.YELLOW}{os_guess}{C.RESET}")
        
        if device_info.get('features'):
            features = ", ".join(device_info['features'][:8])
            print(f"  Features      : {features}")
        
        if services:
            svc_str = ", ".join(services[:8])
            print(f"  Services      : {svc_str}")
        
        # Vulnerabilities
        critical = [v for v in vulnerabilities if v['severity'] == 'CRITICAL']
        high = [v for v in vulnerabilities if v['severity'] == 'HIGH']
        medium = [v for v in vulnerabilities if v['severity'] == 'MEDIUM']
        low = [v for v in vulnerabilities if v['severity'] == 'LOW']
        
        print(f"\n  {C.BOLD}VULNERABILITY SUMMARY{C.RESET}")
        print(f"  {C.CYAN}{'-'*75}{C.RESET}")
        print(f"  {C.RED}CRITICAL : {len(critical)}{C.RESET}")
        print(f"  {C.YELLOW}HIGH     : {len(high)}{C.RESET}")
        print(f"  {C.BLUE}MEDIUM   : {len(medium)}{C.RESET}")
        print(f"  LOW      : {len(low)}")
        print(f"  {C.BOLD}TOTAL    : {len(vulnerabilities)}{C.RESET}")
        
        if vulnerabilities:
            print(f"\n  {C.BOLD}POTENTIAL VULNERABILITIES{C.RESET}")
            print(f"  {C.CYAN}{'-'*75}{C.RESET}")
            
            for vuln in sorted(vulnerabilities, key=lambda x: -x['score']):
                cve = vuln['cve']
                name = vuln['name']
                severity = vuln['severity']
                score = vuln['score']
                
                if severity == "CRITICAL":
                    color = C.RED
                    icon = "🔴"
                elif severity == "HIGH":
                    color = C.YELLOW
                    icon = "🟠"
                elif severity == "MEDIUM":
                    color = C.BLUE
                    icon = "🟡"
                else:
                    color = C.WHITE
                    icon = "⚪"
                
                print(f"\n  {icon} {color}{C.BOLD}{cve}{C.RESET} - {name}")
                print(f"     Severity   : {color}{severity}{C.RESET} (CVSS: {vuln.get('cvss', 'N/A')})")
                print(f"     Confidence : {score}%")
                print(f"     Description: {vuln['description']}")
                
                if vuln['matches']:
                    print(f"     Evidence   : {', '.join(vuln['matches'][:3])}")
                
                if vuln.get('module'):
                    print(f"     {C.GREEN}► Exploit: use {vuln['module']}{C.RESET}")
                else:
                    print(f"     {C.DARK_GREY}► No exploit module available{C.RESET}")
                
                print(f"     Patched    : {vuln.get('patched', 'Unknown')}")
        
        else:
            print(f"\n  {C.GREEN}No known vulnerabilities detected{C.RESET}")
            print(f"  {C.YELLOW}Note: This doesn't mean the device is secure{C.RESET}")
            print(f"  {C.YELLOW}      Unknown vulnerabilities may exist{C.RESET}")
        
        # Recommendations
        print(f"\n  {C.BOLD}RECOMMENDATIONS{C.RESET}")
        print(f"  {C.CYAN}{'-'*75}{C.RESET}")
        
        if critical or high:
            print(f"  {C.RED}⚠ CRITICAL/HIGH vulnerabilities found!{C.RESET}")
            print(f"    1. Apply security patches immediately")
            print(f"    2. Consider disabling Bluetooth if not needed")
            print(f"    3. Run suggested exploit modules to verify")
        
        if "secure_connections" not in device_info.get("features", []):
            print(f"  {C.YELLOW}• Enable Secure Connections if available{C.RESET}")
        
        if "ssp" not in device_info.get("features", []):
            print(f"  {C.YELLOW}• Enable Secure Simple Pairing{C.RESET}")
        
        print(f"  {C.CYAN}• Keep device firmware/OS updated{C.RESET}")
        print(f"  {C.CYAN}• Disable Bluetooth when not in use{C.RESET}")
        print(f"  {C.CYAN}• Set device to non-discoverable mode{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*75}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute vulnerability scan"""
        
        target = self.target
        thorough = self.get_option("thorough")
        timeout = int(self.get_option("timeout"))
        
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}Bluetooth Vulnerability Scanner{C.RESET}                         {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}")
        
        print_info(f"Target: {target}")
        print_info(f"Thorough mode: {thorough}")
        print_info("Starting vulnerability scan...")
        
        # Phase 1: Device Information
        print_info("\n[1/4] Gathering device information...")
        device_info = self._get_device_info(target)
        
        if device_info.get("name"):
            print_success(f"Device name: {device_info['name']}")
        if device_info.get("manufacturer"):
            print_success(f"Manufacturer: {device_info['manufacturer']}")
        
        # Phase 2: Service Discovery
        print_info("\n[2/4] Discovering services...")
        services = []
        if thorough:
            services = self._get_services(target)
            if services:
                print_success(f"Found {len(services)} services")
        
        # Phase 3: OS Fingerprinting
        print_info("\n[3/4] Fingerprinting OS...")
        os_guess = self._fingerprint_os(
            device_info.get("name"),
            device_info.get("manufacturer"),
            target
        )
        print_success(f"OS guess: {os_guess}")
        
        # Phase 4: CVE Matching
        print_info("\n[4/4] Checking for vulnerabilities...")
        vulnerabilities = []
        
        for cve_id, cve_info in CVE_DATABASE.items():
            is_vuln, score, matches = self._check_vuln(
                cve_id, cve_info, device_info, services, os_guess
            )
            
            if is_vuln:
                vulnerabilities.append({
                    "cve": cve_id,
                    "name": cve_info["name"],
                    "severity": cve_info["severity"],
                    "cvss": cve_info.get("cvss"),
                    "score": score,
                    "matches": matches,
                    "description": cve_info["description"],
                    "module": cve_info.get("module"),
                    "patched": cve_info.get("patched")
                })
        
        print_success(f"Found {len(vulnerabilities)} potential vulnerabilities")
        
        # Print results
        self._print_results(target, device_info, services, os_guess, vulnerabilities)
        
        # Store results
        self.add_result({
            "target": target,
            "device_info": device_info,
            "services": services,
            "os_guess": os_guess,
            "vulnerabilities": vulnerabilities
        })
        
        return len(vulnerabilities) > 0
