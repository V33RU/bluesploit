"""
BlueSploit Enhanced BLE Vulnerability Scanner
Comprehensive BLE security assessment with improved safety and features

Author: v33ru
Version: 2.0
"""

import asyncio
import json
import time
import re
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError, BleakDeviceNotFoundError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

# Import framework components
try:
    from core.base import ScannerModule, ModuleInfo, ModuleOption, BTProtocol, Severity
    from core.utils.printer import print_success, print_error, print_info, print_warning, Colors
    FRAMEWORK_AVAILABLE = True
except ImportError:
    FRAMEWORK_AVAILABLE = False
    # Fallback for standalone mode
    class Colors:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        DARK_GREY = '\033[90m'
        BOLD = '\033[1m'
        RESET = '\033[0m'
    
    def print_success(msg): print(f"{Colors.GREEN}[+] {msg}{Colors.RESET}")
    def print_error(msg): print(f"{Colors.RED}[-] {msg}{Colors.RESET}")
    def print_info(msg): print(f"{Colors.CYAN}[*] {msg}{Colors.RESET}")
    def print_warning(msg): print(f"{Colors.YELLOW}[!] {msg}{Colors.RESET}")


class VulnSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    name: str
    severity: VulnSeverity
    description: str
    affected: str  # UUID or component
    details: str
    recommendation: str
    cve: Optional[str] = None
    exploit_possible: bool = False


@dataclass
class ScanResult:
    address: str
    name: str
    rssi: int = 0
    connectable: bool = True
    vendor: Optional[str] = None
    vulns: List[Vulnerability] = field(default_factory=list)
    services_count: int = 0
    chars_count: int = 0
    writable_count: int = 0
    unauth_write_count: int = 0
    info_leak_count: int = 0
    scan_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# Extended vulnerable service patterns
VULN_PATTERNS = {
    # 16-bit UUIDs
    "ffe0": {"name": "Common IoT Service", "risk": "Often has unauth writes", "severity": VulnSeverity.HIGH},
    "fff0": {"name": "Vendor Service", "risk": "Custom protocol - check security", "severity": VulnSeverity.MEDIUM},
    "ffd0": {"name": "Vendor Service 2", "risk": "Custom protocol", "severity": VulnSeverity.MEDIUM},
    "fee0": {"name": "Xiaomi Service", "risk": "Known unauth write vulns", "severity": VulnSeverity.HIGH},
    "180f": {"name": "Battery Service", "risk": "Info disclosure", "severity": VulnSeverity.LOW},
    "fe59": {"name": "Eddystone", "risk": "Unauth configuration", "severity": VulnSeverity.HIGH},
    "fddf": {"name": "Mesh Provisioning", "risk": "Unauth device join", "severity": VulnSeverity.CRITICAL},
    "fe0f": {"name": "Vendor Diagnostic", "risk": "Debug commands", "severity": VulnSeverity.CRITICAL},
    "180a": {"name": "Device Info", "risk": "Information disclosure", "severity": VulnSeverity.LOW},
    "1812": {"name": "HID", "risk": "Keystroke injection", "severity": VulnSeverity.CRITICAL},
}

# Characteristics that should NOT be writable without auth
SENSITIVE_WRITE_CHARS = {
    "2a06": "Alert Level",  # Should require auth
    "2a00": "Device Name",  # Should be read-only
    "2a26": "Firmware Rev",  # Should be read-only
    "2a28": "Software Rev",  # Should be read-only
    "2a29": "Manufacturer",  # Should be read-only
    "2a24": "Model Number",  # Should be read-only
    "2a25": "Serial Number",  # Should be read-only
    "2a27": "Hardware Rev",  # Should be read-only
    "2a50": "PnP ID",  # Should be read-only
    "2a56": "Digital Output",  # Could control physical outputs
    "2a57": "Digital Input",  # Potentially writable for config
}

# Known info-leak characteristics
INFO_LEAK_CHARS = {
    "2a23": "System ID",
    "2a24": "Model Number",
    "2a25": "Serial Number",
    "2a27": "Hardware Revision",
    "2a29": "Manufacturer Name",
    "2a50": "PnP ID",
    "2a28": "Software Revision",
    "2a26": "Firmware Revision",
    "2a00": "Device Name",
    "2a01": "Appearance",
}

# Test payloads - minimal and non-destructive
TEST_PAYLOADS = [
    bytes([0x00]),  # Null/zero
    bytes([0xFF]),  # Max value
    bytes([0x01]),  # Minimal non-zero
    bytes([0x41, 0x41]),  # "AA"
]

# Vendor OUI prefixes for device identification
VENDOR_OUI = {
    "00:1A:7D": "Apple",
    "4C:32:75": "Apple",
    "DC:A6:32": "Raspberry Pi",
    "F0:6B:CA": "Samsung",
    "F4:5C:89": "Apple Watch",
    "CC:46:D6": "Cisco",
    "A4:34:D9": "Google",
    "38:2C:4A": "Google",
    "88:C6:26": "LG",
    "E4:5D:75": "Microsoft",
    "74:75:48": "Amazon",
    "FC:F5:C4": "Google",
}


class EnhancedBLEScanner:
    """Enhanced BLE vulnerability scanner with safety features"""
    
    def __init__(self, target: str, timeout: int = 10, test_writes: bool = False, 
                 deep_scan: bool = True, max_connections: int = 1):
        self.target = target
        self.timeout = timeout
        self.test_writes = test_writes
        self.deep_scan = deep_scan
        self.max_connections = max_connections
        self.results = []
        self.scan_start_time = 0
        self.active_connections = 0
        
        # Safety counters
        self.writes_attempted = 0
        self.writes_successful = 0
        self.writes_blocked = 0
        
    def _get_short_uuid(self, uuid: str) -> str:
        """Handle both 16-bit, 32-bit and 128-bit UUIDs"""
        if not uuid:
            return ""
        
        uuid = str(uuid).lower().replace('-', '').replace('0x', '')
        
        # Remove common 128-bit base UUID suffix
        if uuid.endswith('00001000800000805f9b34fb'):
            return uuid[:4]
        
        if len(uuid) == 4:  # 16-bit
            return uuid
        elif len(uuid) == 8:  # 32-bit
            return uuid[4:8] if len(uuid) >= 8 else uuid
        elif len(uuid) == 32:  # 128-bit
            return uuid[4:8] if len(uuid) >= 8 else uuid
        else:
            return uuid[:4] if len(uuid) >= 4 else uuid
    
    def _get_vendor_from_mac(self, mac: str) -> Optional[str]:
        """Identify vendor from MAC address OUI"""
        if not mac:
            return None
            
        # Clean MAC address
        mac = mac.upper().replace(':', '').replace('-', '')
        if len(mac) < 6:
            return None
            
        mac_prefix = mac[:6]
        
        for prefix, vendor in VENDOR_OUI.items():
            vendor_prefix = prefix.replace(':', '').replace('-', '')
            if mac_prefix == vendor_prefix[:6]:
                return vendor
        return None
    
    def _get_severity_color(self, severity: VulnSeverity) -> str:
        """Get color code for severity"""
        colors = {
            VulnSeverity.CRITICAL: Colors.RED + Colors.BOLD,
            VulnSeverity.HIGH: Colors.RED,
            VulnSeverity.MEDIUM: Colors.YELLOW,
            VulnSeverity.LOW: Colors.GREEN,
            VulnSeverity.INFO: Colors.CYAN
        }
        return colors.get(severity, Colors.RESET)
    
    async def _test_unauth_write_safe(self, client: BleakClient, char_uuid: str, 
                                     service_uuid: str, char_name: str) -> Tuple[bool, str]:
        """
        Safely test if characteristic allows unauthenticated write
        Returns: (is_vulnerable, details)
        """
        # Check if characteristic is in sensitive list
        short_uuid = self._get_short_uuid(char_uuid)
        char_display_name = SENSITIVE_WRITE_CHARS.get(short_uuid, f"Char {short_uuid}")
        
        print_info(f"Testing write on {char_display_name} ({short_uuid})...")
        
        for payload in TEST_PAYLOADS:
            try:
                self.writes_attempted += 1
                # Use write without response first (faster, less intrusive)
                await client.write_gatt_char(char_uuid, payload, response=False)
                
                # Success - this is potentially vulnerable
                self.writes_successful += 1
                
                details = (f"Write succeeded without authentication. "
                          f"Service: {service_uuid}, Payload: {payload.hex()}")
                
                # Try to read back to see if write had effect
                try:
                    value = await client.read_gatt_char(char_uuid)
                    details += f", Readback: {value.hex()[:20]}..."
                except:
                    pass
                    
                return True, details
                
            except BleakError as e:
                err = str(e).lower()
                
                if "auth" in err or "encrypt" in err or "insufficient" in err or "not authorized" in err:
                    self.writes_blocked += 1
                    return False, "Authentication required (GOOD)"
                
                if "not supported" in err or "not permit" in err or "write not permitted" in err:
                    return False, "Write not permitted"
                
                if "not connected" in err:
                    return False, "Device disconnected"
                    
            except Exception as e:
                return False, f"Error: {str(e)[:50]}"
        
        return False, "All write attempts failed"
    
    async def _check_info_disclosure(self, client: BleakClient, char_uuid: str) -> Optional[Tuple[str, bytes]]:
        """Check if sensitive info is readable, return (info_type, value)"""
        try:
            value = await client.read_gatt_char(char_uuid)
            if value and len(value) > 0:
                return char_uuid, value
        except Exception:
            pass
        return None
    
    async def _analyze_characteristic(self, client: BleakClient, service, 
                                     char, result: ScanResult) -> None:
        """
        Analyze a single characteristic for vulnerabilities
        service: bleak service object
        char: bleak characteristic object
        """
        try:
            char_uuid = str(char.uuid).lower()
            service_uuid = str(service.uuid).lower()
            short_char = self._get_short_uuid(char_uuid)
            short_svc = self._get_short_uuid(service_uuid)
            
            # Get properties safely
            properties = []
            if hasattr(char, 'properties'):
                # Convert properties to list if it's not already
                if isinstance(char.properties, list):
                    properties = char.properties
                else:
                    # Try to iterate or convert
                    try:
                        properties = list(char.properties)
                    except:
                        # Fallback: get property names from characteristic
                        props = []
                        if hasattr(char, 'read'):
                            props.append("read")
                        if hasattr(char, 'write'):
                            props.append("write")
                        if hasattr(char, 'write_without_response'):
                            props.append("write-without-response")
                        if hasattr(char, 'notify'):
                            props.append("notify")
                        if hasattr(char, 'indicate'):
                            props.append("indicate")
                        properties = props
            
            is_writable = "write" in properties or "write-without-response" in properties
            is_readable = "read" in properties
            is_notifiable = "notify" in properties or "indicate" in properties

            if is_writable:
                result.writable_count += 1
            
            # Check: Write Without Response
            if "write-without-response" in properties:
                result.vulns.append(Vulnerability(
                    name="Write-Without-Response Enabled",
                    severity=VulnSeverity.LOW,
                    description="Characteristic allows writes without acknowledgment",
                    affected=f"{short_char} in {short_svc}",
                    details=f"Properties: {', '.join(properties)}",
                    recommendation="Verify authentication is required before write",
                    exploit_possible=True
                ))
            
            # Check: Sensitive characteristic writable
            if is_writable and short_char in SENSITIVE_WRITE_CHARS:
                result.vulns.append(Vulnerability(
                    name=f"Sensitive Char Writable: {SENSITIVE_WRITE_CHARS[short_char]}",
                    severity=VulnSeverity.HIGH,
                    description=f"Sensitive characteristic appears writable",
                    affected=f"{short_char} ({SENSITIVE_WRITE_CHARS[short_char]})",
                    details=f"Service: {short_svc}, Properties: {', '.join(properties)}",
                    recommendation="Verify write requires authentication",
                    exploit_possible=True
                ))
            
            # Check: Information disclosure
            if is_readable and short_char in INFO_LEAK_CHARS and self.deep_scan:
                leak_data = await self._check_info_disclosure(client, char_uuid)
                if leak_data:
                    result.info_leak_count += 1
                    leaked_uuid, value = leak_data
                    
                    # Try to decode
                    try:
                        decoded = value.decode('utf-8', errors='ignore').strip('\x00')
                        display_value = decoded if decoded else value.hex()
                    except:
                        display_value = value.hex()
                    
                    result.vulns.append(Vulnerability(
                        name=f"Info Disclosure: {INFO_LEAK_CHARS[short_char]}",
                        severity=VulnSeverity.LOW,
                        description=f"Device exposes {INFO_LEAK_CHARS[short_char]}",
                        affected=char_uuid,
                        details=f"Leaked value: {display_value[:50]}{'...' if len(display_value) > 50 else ''}",
                        recommendation="Consider if this information should be protected"
                    ))
            
            # Check: Test unauthenticated writes
            if is_writable and self.test_writes:
                vulnerable, details = await self._test_unauth_write_safe(
                    client, char_uuid, service_uuid, short_char
                )
                if vulnerable:
                    result.unauth_write_count += 1
                    result.vulns.append(Vulnerability(
                        name="Unauthenticated Write Allowed",
                        severity=VulnSeverity.CRITICAL,
                        description="Characteristic accepts writes without authentication",
                        affected=f"{short_char} in {short_svc}",
                        details=details,
                        recommendation="Implement proper authentication for writes",
                        cve="CVE-PENDING (Pre-pairing GATT vulnerability)",
                        exploit_possible=True
                    ))
            
            # Check: Notify/Indicate without auth
            if is_notifiable and not is_readable and not is_writable:
                result.vulns.append(Vulnerability(
                    name="Notification/Indication Available",
                    severity=VulnSeverity.LOW,
                    description="Characteristic can notify/indicate without subscription auth",
                    affected=char_uuid,
                    details=f"Properties: {', '.join(properties)}",
                    recommendation="Verify subscription requires authentication",
                    exploit_possible=True
                ))
                
        except Exception as e:
            print_error(f"Error analyzing characteristic: {str(e)[:100]}")
    
    async def _scan_device(self, address: str, name: Optional[str] = None, rssi: int = 0) -> ScanResult:
        """Perform vulnerability scan on a single device"""
        result = ScanResult(address=address, name=name or "", rssi=rssi)
        
        print_info(f"Scanning {address} ({name or 'Unknown'})...")
        
        try:
            async with BleakClient(address, timeout=self.timeout) as client:
                if not client.is_connected:
                    print_error(f"Failed to connect to {address}")
                    return result
                
                print_success(f"Connected to {address}")
                
                # Get device name if not already known
                if not result.name:
                    try:
                        # Try to read device name characteristic
                        for service in client.services:
                            for char in service.characteristics:
                                char_uuid = str(char.uuid).lower()
                                short_uuid = self._get_short_uuid(char_uuid)
                                if short_uuid == "2a00":
                                    try:
                                        name_val = await client.read_gatt_char(char.uuid)
                                        result.name = name_val.decode('utf-8', errors='ignore').strip('\x00')
                                        break
                                    except:
                                        continue
                            if result.name:
                                break
                    except Exception as e:
                        print_error(f"Could not read device name: {e}")
                
                # Identify vendor
                result.vendor = self._get_vendor_from_mac(address)
                
                # Enumerate services
                services = list(client.services)
                result.services_count = len(services)
                
                total_chars = 0
                for service in services:
                    total_chars += len(service.characteristics)
                
                processed_chars = 0
                
                for service_idx, service in enumerate(services):
                    service_uuid = str(service.uuid).lower()
                    short_svc = self._get_short_uuid(service_uuid)
                    
                    # Check for known vulnerable service patterns
                    if short_svc in VULN_PATTERNS:
                        pattern = VULN_PATTERNS[short_svc]
                        result.vulns.append(Vulnerability(
                            name=f"Known Risk Service: {pattern['name']}",
                            severity=pattern['severity'],
                            description=pattern['risk'],
                            affected=service_uuid,
                            details=f"Service UUID: {short_svc.upper()}",
                            recommendation="Manually verify authentication requirements",
                            exploit_possible=True
                        ))
                    
                    # Analyze characteristics
                    for char in service.characteristics:
                        result.chars_count += 1
                        processed_chars += 1
                        
                        # Progress indicator
                        if processed_chars % 10 == 0 and total_chars > 0:
                            progress = (processed_chars / total_chars * 100)
                            print_info(f"Progress: {processed_chars}/{total_chars} characteristics ({progress:.1f}%)")
                        
                        await self._analyze_characteristic(client, service, char, result)
                
                # Post-scan analysis
                self._post_scan_analysis(result)
                
                print_success(f"Scan complete: {len(result.vulns)} vulnerabilities found")
                
        except asyncio.TimeoutError:
            print_error(f"Connection timed out after {self.timeout}s")
        except BleakDeviceNotFoundError:
            print_error(f"Device {address} not found")
        except BleakError as e:
            print_error(f"BLE error: {str(e)[:100]}")
        except Exception as e:
            print_error(f"Unexpected error: {type(e).__name__}: {str(e)[:100]}")
        
        result.scan_time = time.time() - self.scan_start_time
        return result
    
    def _post_scan_analysis(self, result: ScanResult) -> None:
        """Perform post-scan vulnerability analysis"""
        # Check: No authentication at all
        if result.writable_count > 0 and result.unauth_write_count == result.writable_count:
            result.vulns.append(Vulnerability(
                name="No Write Authentication",
                severity=VulnSeverity.CRITICAL,
                description="Device has no authentication for any writable characteristic",
                affected="All writable characteristics",
                details=f"All {result.writable_count} writable characteristics allow unauthenticated writes",
                recommendation="Implement BLE pairing/bonding requirements",
                exploit_possible=True
            ))
        
        # Check: Many writable characteristics without testing
        if not self.test_writes and result.writable_count > 5:
            result.vulns.append(Vulnerability(
                name="Multiple Writable Characteristics",
                severity=VulnSeverity.MEDIUM,
                description=f"Device has {result.writable_count} writable characteristics",
                affected="Multiple characteristics",
                details="Large attack surface - recommend testing with write_test enabled",
                recommendation="Enable write_test to verify authentication requirements"
            ))
        
        # Check: No security mode advertised
        if result.services_count > 0 and len(result.vulns) == 0:
            result.vulns.append(Vulnerability(
                name="No Security Services Found",
                severity=VulnSeverity.INFO,
                description="No security-specific services detected",
                affected="Device",
                details="Device does not advertise security services (e.g., pairing, bonding)",
                recommendation="Verify if device implements proper security"
            ))
    
    def _print_results(self, result: ScanResult) -> None:
        """Print detailed vulnerability scan results"""
        C = Colors
        
        # Header
        print(f"\n{C.CYAN}{'='*80}{C.RESET}")
        print(f"{C.BOLD}{C.WHITE}BLE VULNERABILITY SCAN REPORT{C.RESET}")
        print(f"{C.CYAN}{'='*80}{C.RESET}")
        
        # Device Info
        print(f"{C.BOLD}DEVICE INFORMATION{C.RESET}")
        print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
        print(f"  Address:    {C.WHITE}{result.address}{C.RESET}")
        print(f"  Name:       {C.WHITE}{result.name or 'Unknown'}{C.RESET}")
        print(f"  Vendor:     {C.WHITE}{result.vendor or 'Unknown'}{C.RESET}")
        print(f"  RSSI:       {result.rssi} dBm")
        print(f"  Scan Time:  {result.scan_time:.2f}s")
        print(f"  Timestamp:  {result.timestamp}")
        
        # Statistics
        print(f"\n{C.BOLD}SCAN STATISTICS{C.RESET}")
        print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
        stats = [
            ("Services", result.services_count, C.CYAN),
            ("Characteristics", result.chars_count, C.CYAN),
            ("Writable", result.writable_count, C.YELLOW),
            ("Unauth Writes", result.unauth_write_count, C.RED if result.unauth_write_count > 0 else C.GREEN),
            ("Info Leaks", result.info_leak_count, C.YELLOW),
            ("Total Vulns", len(result.vulns), C.RED if len(result.vulns) > 0 else C.GREEN)
        ]
        
        for label, value, color in stats:
            color_code = color if isinstance(color, str) else color
            print(f"  {label:<20} {color_code}{value}{C.RESET}")
        
        # Safety Stats (if writes were tested)
        if self.test_writes:
            print(f"\n{C.BOLD}SAFETY STATISTICS{C.RESET}")
            print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
            print(f"  Writes Attempted: {self.writes_attempted}")
            print(f"  Writes Successful: {C.RED if self.writes_successful > 0 else C.GREEN}{self.writes_successful}{C.RESET}")
            print(f"  Writes Blocked: {C.GREEN}{self.writes_blocked}{C.RESET}")
        
        if not result.vulns:
            print(f"\n{C.GREEN}[+] No vulnerabilities detected{C.RESET}")
            print(f"\n{C.CYAN}{'='*80}{C.RESET}")
            return
        
        # Vulnerability Summary
        sev_counts = {s: 0 for s in VulnSeverity}
        for v in result.vulns:
            sev_counts[v.severity] += 1
        
        print(f"\n{C.BOLD}VULNERABILITY SUMMARY{C.RESET}")
        print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
        severity_line = []
        for sev in VulnSeverity:
            count = sev_counts[sev]
            if count > 0:
                color = self._get_severity_color(sev)
                severity_line.append(f"{color}{sev.value}: {count}{C.RESET}")
        
        print("  " + "  ".join(severity_line))
        
        # Detailed Vulnerabilities
        print(f"\n{C.BOLD}DETAILED FINDINGS{C.RESET}")
        print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
        
        # Sort by severity
        severity_order = {VulnSeverity.CRITICAL: 0, VulnSeverity.HIGH: 1, 
                         VulnSeverity.MEDIUM: 2, VulnSeverity.LOW: 3, VulnSeverity.INFO: 4}
        sorted_vulns = sorted(result.vulns, key=lambda v: severity_order[v.severity])
        
        for idx, vuln in enumerate(sorted_vulns, 1):
            color = self._get_severity_color(vuln.severity)
            
            print(f"\n{C.BOLD}[{idx}] {color}{vuln.name}{C.RESET}")
            print(f"  {C.DARK_GREY}Severity:{C.RESET} {color}{vuln.severity.value}{C.RESET}")
            print(f"  {C.DARK_GREY}Affected:{C.RESET} {vuln.affected}")
            print(f"  {C.DARK_GREY}Description:{C.RESET} {vuln.description}")
            print(f"  {C.DARK_GREY}Details:{C.RESET} {vuln.details}")
            print(f"  {C.DARK_GREY}Recommendation:{C.RESET} {vuln.recommendation}")
            if vuln.cve:
                print(f"  {C.DARK_GREY}CVE:{C.RESET} {vuln.cve}")
            if vuln.exploit_possible:
                print(f"  {C.YELLOW}[!] Exploit possible{C.RESET}")
        
        # Risk Assessment
        print(f"\n{C.BOLD}RISK ASSESSMENT{C.RESET}")
        print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
        
        if sev_counts[VulnSeverity.CRITICAL] > 0:
            print(f"{C.RED}[!] CRITICAL RISK: Immediate action required{C.RESET}")
            print(f"    • {sev_counts[VulnSeverity.CRITICAL]} critical vulnerabilities found")
            print(f"    • Device may be completely compromisable")
        elif sev_counts[VulnSeverity.HIGH] > 0:
            print(f"{C.RED}[!] HIGH RISK: Security review required{C.RESET}")
            print(f"    • {sev_counts[VulnSeverity.HIGH]} high severity vulnerabilities")
            print(f"    • Device may have serious security flaws")
        elif sev_counts[VulnSeverity.MEDIUM] > 0:
            print(f"{C.YELLOW}[!] MODERATE RISK: Consider addressing issues{C.RESET}")
        else:
            print(f"{C.GREEN}[+] LOW RISK: Device appears reasonably secure{C.RESET}")
        
        # Next Steps
        print(f"\n{C.BOLD}NEXT STEPS{C.RESET}")
        print(f"{C.DARK_GREY}{'─'*40}{C.RESET}")
        
        if result.unauth_write_count > 0:
            print(f"{C.YELLOW}[*] Test exploitability:{C.RESET}")
            print(f"    • Use exploit module: exploits/ble/unauth_write")
            print(f"    • Capture traffic with: scanners/ble/sniffer")
            print(f"    • Test replay attacks")
        
        if result.info_leak_count > 0:
            print(f"{C.YELLOW}[*] Information disclosure:{C.RESET}")
            print(f"    • Assess leaked data sensitivity")
            print(f"    • Check if data can be used for fingerprinting")
        
        print(f"\n{C.CYAN}{'='*80}{C.RESET}\n")
    
    def save_results_json(self, result: ScanResult, filename: str) -> None:
        """Save results to JSON file"""
        output = {
            "scan_metadata": {
                "tool": "EnhancedBLEVulnScanner",
                "version": "2.0",
                "timestamp": result.timestamp,
                "scan_time": result.scan_time,
                "parameters": {
                    "target": result.address,
                    "test_writes": self.test_writes,
                    "deep_scan": self.deep_scan,
                    "timeout": self.timeout
                }
            },
            "device_info": {
                "address": result.address,
                "name": result.name,
                "vendor": result.vendor,
                "rssi": result.rssi,
                "connectable": result.connectable
            },
            "statistics": {
                "services": result.services_count,
                "characteristics": result.chars_count,
                "writable": result.writable_count,
                "unauth_writes": result.unauth_write_count,
                "info_leaks": result.info_leak_count,
                "total_vulns": len(result.vulns)
            },
            "safety_stats": {
                "writes_attempted": self.writes_attempted,
                "writes_successful": self.writes_successful,
                "writes_blocked": self.writes_blocked
            },
            "vulnerabilities": []
        }
        
        for v in result.vulns:
            output["vulnerabilities"].append({
                "name": v.name,
                "severity": v.severity.value,
                "description": v.description,
                "affected": v.affected,
                "details": v.details,
                "recommendation": v.recommendation,
                "cve": v.cve,
                "exploit_possible": v.exploit_possible
            })
        
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2, default=str)
            print_success(f"Results saved to {filename}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
    
    def save_results_csv(self, result: ScanResult, filename: str) -> None:
        """Save results to CSV file"""
        try:
            with open(filename, 'w', newline='') as f:
                import csv
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Address", "Name", "Vulnerability", 
                               "Severity", "Affected", "Description", "Details", 
                               "Recommendation", "CVE", "Exploit Possible"])
                
                for v in result.vulns:
                    writer.writerow([
                        result.timestamp,
                        result.address,
                        result.name,
                        v.name,
                        v.severity.value,
                        v.affected,
                        v.description,
                        v.details[:100],  # Truncate long details
                        v.recommendation,
                        v.cve or "",
                        "Yes" if v.exploit_possible else "No"
                    ])
            
            print_success(f"CSV saved to {filename}")
        except Exception as e:
            print_error(f"Failed to save CSV: {e}")
    
    async def scan(self) -> ScanResult:
        """Main scan method"""
        if not BLEAK_AVAILABLE:
            print_error("Bleak library not installed. Install with: pip install bleak")
            raise ImportError("Bleak required")
        
        print_info(f"Starting BLE vulnerability scan on {self.target}")
        print_warning("DISCLAIMER: Only scan devices you own or have permission to test!")
        
        # Validate MAC address
        if not self._validate_mac(self.target):
            print_warning(f"Target {self.target} may not be a valid MAC address")
        
        self.scan_start_time = time.time()
        result = await self._scan_device(self.target)
        self.results.append(result)
        
        return result
    
    async def discover_and_scan(self, scan_duration: int = 5) -> List[ScanResult]:
        """Discover nearby BLE devices and scan them"""
        print_info(f"Discovering BLE devices for {scan_duration} seconds...")
        
        try:
            devices = await BleakScanner.discover(
                timeout=scan_duration,
                return_adv=True
            )
        except Exception as e:
            print_error(f"Discovery failed: {e}")
            return []
        
        print_success(f"Found {len(devices)} devices")
        
        results = []
        for device, adv_data in devices.values():
            print_info(f"Found: {device.address} - {device.name or 'Unknown'} (RSSI: {adv_data.rssi})")
            
            if self._should_scan_device(device.address):
                try:
                    result = await self._scan_device(
                        device.address, 
                        device.name, 
                        adv_data.rssi
                    )
                    results.append(result)
                    
                    # Print brief results
                    if result.vulns:
                        critical_count = sum(1 for v in result.vulns if v.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH])
                        print_warning(f"  → Found {len(result.vulns)} vulns ({critical_count} critical/high)")
                    else:
                        print_success(f"  → No vulnerabilities found")
                        
                except Exception as e:
                    print_error(f"  → Scan failed: {str(e)[:50]}")
            
            # Rate limiting
            await asyncio.sleep(0.5)
        
        return results
    
    def _validate_mac(self, mac: str) -> bool:
        """Validate MAC address format"""
        patterns = [
            r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
            r'^([0-9A-Fa-f]{2}){6}$'
        ]
        return any(re.match(p, mac, re.IGNORECASE) for p in patterns)
    
    def _should_scan_device(self, address: str) -> bool:
        """Determine if a device should be scanned"""
        # Skip Apple devices by default (they have good security)
        vendor = self._get_vendor_from_mac(address)
        if vendor == "Apple" and not self.deep_scan:
            print_info(f"Skipping {vendor} device {address}")
            return False
        return True


def run_standalone():
    """Standalone execution function"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Enhanced BLE Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t AA:BB:CC:DD:EE:FF
  %(prog)s -t AA:BB:CC:DD:EE:FF -w
  %(prog)s --discover --duration 10
  %(prog)s -t AA:BB:CC:DD:EE:FF -o results.json
        
Safety Notice:
  Only scan devices you own or have explicit permission to test.
  Write testing may modify device state.
        """
    )
    
    parser.add_argument("-t", "--target", help="Target MAC address")
    parser.add_argument("-d", "--discover", action="store_true", help="Discover nearby devices")
    parser.add_argument("--duration", type=int, default=5, help="Discovery duration (seconds)")
    parser.add_argument("-w", "--write-test", action="store_true", help="Test write operations")
    parser.add_argument("--deep", action="store_true", default=True, help="Deep scan")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--csv", help="Output CSV file")
    parser.add_argument("--batch", action="store_true", help="Scan all discovered devices")
    
    args = parser.parse_args()
    
    if not args.target and not args.discover:
        parser.error("Either --target or --discover required")
    
    if not BLEAK_AVAILABLE:
        print_error("Bleak library required. Install with: pip install bleak")
        return
    
    target = args.target if args.target else ("discover" if args.discover else None)
    
    scanner = EnhancedBLEScanner(
        target=target if target != "discover" else "",
        timeout=args.timeout,
        test_writes=args.write_test,
        deep_scan=args.deep
    )
    
    try:
        if args.discover or args.batch:
            results = asyncio.run(scanner.discover_and_scan(args.duration))
            
            if not results:
                print_warning("No devices found or scanned")
                return
            
            # Print brief summary
            critical_devices = []
            for r in results:
                crit_count = sum(1 for v in r.vulns if v.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH])
                if crit_count > 0:
                    print_warning(f"{r.address}: {crit_count} critical/high vulnerabilities")
                    critical_devices.append(r)
                else:
                    print_success(f"{r.address}: No critical vulnerabilities")
            
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
            print(f"Scan complete: {len(results)} devices scanned")
            if critical_devices:
                print(f"{Colors.RED}Warning: {len(critical_devices)} devices have critical/high vulnerabilities{Colors.RESET}")
            print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
                    
        else:
            result = asyncio.run(scanner.scan())
            scanner._print_results(result)
            
            if args.output:
                scanner.save_results_json(result, args.output)
            if args.csv:
                scanner.save_results_csv(result, args.csv)
                
    except KeyboardInterrupt:
        print_warning("\nInterrupted by user")
    except Exception as e:
        print_error(f"Error: {e}")


# Framework module class
if FRAMEWORK_AVAILABLE:
    class Module(ScannerModule):
        """
        Enhanced BLE Vulnerability Scanner
        
        Features:
        - Unauthenticated write detection
        - Information disclosure checks
        - Vendor identification
        - Safety-first testing
        - Multiple output formats
        - Batch scanning
        """
        
        info = ModuleInfo(
            name="scanners/ble/vuln_scan_enhanced",
            description="Enhanced BLE vulnerability scanner with safety features",
            author=["v33ru"],
            protocol=BTProtocol.BLE,
            severity=Severity.HIGH,
            references=[
                "https://www.usenix.org/conference/usenixsecurity19/presentation/wu-jianliang",
                "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/",
                "https://github.com/virtualabs/btlejack"
            ]
        )
        
        def _setup_options(self) -> None:
            self.options = {
                "target": ModuleOption(
                    name="target",
                    required=False,
                    description="Target BD_ADDR (XX:XX:XX:XX:XX:XX) or 'discover'"
                ),
                "timeout": ModuleOption(
                    name="timeout",
                    required=False,
                    description="Connection timeout in seconds",
                    default=10
                ),
                "test_writes": ModuleOption(
                    name="test_writes",
                    required=False,
                    description="Test write operations (requires confirmation)",
                    default=False
                ),
                "deep_scan": ModuleOption(
                    name="deep_scan",
                    required=False,
                    description="Perform deep analysis",
                    default=True
                ),
                "scan_duration": ModuleOption(
                    name="scan_duration",
                    required=False,
                    description="Discovery scan duration (seconds)",
                    default=5
                ),
                "output_json": ModuleOption(
                    name="output_json",
                    required=False,
                    description="Save results to JSON file",
                    default=None
                ),
                "output_csv": ModuleOption(
                    name="output_csv",
                    required=False,
                    description="Save results to CSV file",
                    default=None
                ),
                "batch_scan": ModuleOption(
                    name="batch_scan",
                    required=False,
                    description="Scan all discovered devices",
                    default=False
                )
            }
        
        def run(self) -> bool:
            """Execute vulnerability scan"""
            if not BLEAK_AVAILABLE:
                print_error("Bleak library required. Install: pip install bleak")
                return False
            
            target = self.get_option("target") or "discover"
            timeout = int(self.get_option("timeout"))
            test_writes = self.get_option("test_writes")
            deep_scan = self.get_option("deep_scan")
            scan_duration = int(self.get_option("scan_duration"))
            batch_scan = self.get_option("batch_scan")
            
            # Safety confirmation for test_writes
            if test_writes:
                print_warning("""
╔══════════════════════════════════════════════════════════════╗
║                   WARNING: WRITE TESTING                     ║
╠══════════════════════════════════════════════════════════════╣
║ This will attempt to write data to the target device.        ║
║ This may:                                                    ║
║ • Modify device configuration                                ║
║ • Change device behavior                                     ║
║ • Cause unintended side effects                              ║
║                                                              ║
║ Only test devices you own or have permission to test!        ║
╚══════════════════════════════════════════════════════════════╝
                """)
                
                confirm = input(f"\n{Colors.YELLOW}[?] Test writes on {target}? [y/N]: {Colors.RESET}").strip().lower()
                if confirm != 'y':
                    print_warning("Write testing disabled")
                    test_writes = False
            
            scanner = EnhancedBLEScanner(
                target=target if target != "discover" else "",
                timeout=timeout,
                test_writes=test_writes,
                deep_scan=deep_scan
            )
            
            try:
                if target == "discover" or batch_scan:
                    print_info(f"Discovering devices for {scan_duration} seconds...")
                    results = asyncio.run(scanner.discover_and_scan(scan_duration))
                    
                    if not results:
                        print_warning("No devices found or scanned")
                        return False
                    
                    # Print summary
                    total_vulns = sum(len(r.vulns) for r in results)
                    critical_devices = [r for r in results if any(
                        v.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH] 
                        for v in r.vulns
                    )]
                    
                    print_success(f"\nScan complete: {len(results)} devices, {total_vulns} total vulnerabilities")
                    if critical_devices:
                        print_warning(f"  {len(critical_devices)} devices have critical/high vulnerabilities:")
                        for r in critical_devices:
                            crit_count = sum(1 for v in r.vulns if v.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH])
                            print_warning(f"    • {r.address} ({r.name or 'Unknown'}): {crit_count} critical/high")
                    
                    # Save results if requested
                    output_json = self.get_option("output_json")
                    if output_json:
                        combined = {
                            "scan_metadata": {
                                "type": "batch_scan",
                                "device_count": len(results),
                                "total_vulns": total_vulns,
                                "timestamp": datetime.now().isoformat()
                            },
                            "devices": []
                        }
                        for r in results:
                            device_data = {
                                "address": r.address,
                                "name": r.name,
                                "vuln_count": len(r.vulns),
                                "critical_count": sum(1 for v in r.vulns if v.severity == VulnSeverity.CRITICAL),
                                "high_count": sum(1 for v in r.vulns if v.severity == VulnSeverity.HIGH)
                            }
                            combined["devices"].append(device_data)
                        
                        try:
                            with open(output_json, 'w') as f:
                                json.dump(combined, f, indent=2)
                            print_success(f"Summary saved to {output_json}")
                        except Exception as e:
                            print_error(f"Failed to save summary: {e}")
                    
                    return len(critical_devices) > 0
                else:
                    # Single device scan
                    result = asyncio.run(scanner.scan())
                    
                    # Print results
                    scanner._print_results(result)
                    
                    # Save results
                    output_json = self.get_option("output_json")
                    output_csv = self.get_option("output_csv")
                    
                    if output_json:
                        scanner.save_results_json(result, output_json)
                    if output_csv:
                        scanner.save_results_csv(result, output_csv)
                    
                    # Return True if critical/high vulnerabilities found
                    critical_found = any(
                        v.severity in [VulnSeverity.CRITICAL, VulnSeverity.HIGH] 
                        for v in result.vulns
                    )
                    return critical_found
                    
            except KeyboardInterrupt:
                print_warning("\nScan interrupted by user")
                return False
            except Exception as e:
                print_error(f"Scan failed: {type(e).__name__}: {str(e)}")
                return False


if __name__ == "__main__":
    run_standalone()