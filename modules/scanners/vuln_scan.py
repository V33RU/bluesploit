"""
BlueSploit Module: BLE Vulnerability Scanner
Auto-detect BLE vulnerabilities including unauthenticated writes,
weak pairing, information disclosure, and known CVEs

Author: v33ru
"""

import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


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


@dataclass
class ScanResult:
    address: str
    name: str
    vulns: List[Vulnerability] = field(default_factory=list)
    services_count: int = 0
    chars_count: int = 0
    writable_count: int = 0
    unauth_write_count: int = 0
    info_leak_count: int = 0


# Known vulnerable service/char patterns
VULN_PATTERNS = {
    # Service UUIDs known to have issues
    "0000ffe0": {"name": "Common IoT Service", "risk": "Often has unauth writes"},
    "0000fff0": {"name": "Vendor Service", "risk": "Custom protocol - check security"},
    "0000ffd0": {"name": "Vendor Service 2", "risk": "Custom protocol"},
    "0000fee0": {"name": "Xiaomi Service", "risk": "Known unauth write vulns"},
    "0000180f": {"name": "Battery Service", "risk": "Info disclosure"},
}

# Characteristics that should NOT be writable without auth
SENSITIVE_WRITE_CHARS = {
    "00002a06": "Alert Level",  # Should require auth
    "00002a00": "Device Name",  # Should be read-only
    "00002a26": "Firmware Rev",  # Should be read-only
}

# Known info-leak characteristics
INFO_LEAK_CHARS = {
    "00002a23": "System ID",
    "00002a24": "Model Number",
    "00002a25": "Serial Number",
    "00002a27": "Hardware Revision",
    "00002a29": "Manufacturer Name",
    "00002a50": "PnP ID",
}

# Test payloads for write testing
TEST_PAYLOADS = [
    bytes([0x00]),
    bytes([0x01]),
    bytes([0x00, 0x00]),
    bytes([0x41, 0x41, 0x41, 0x41]),
]


class Module(ScannerModule):
    """
    BLE Vulnerability Scanner
    
    Automatically detects:
    - Unauthenticated GATT writes (pre-pairing vulns)
    - Information disclosure
    - Weak/missing authentication
    - Known vulnerable services
    - Sensitive data exposure
    """
    
    info = ModuleInfo(
        name="scanners/ble/vuln_scan",
        description="BLE vulnerability scanner - detect unauth writes, info leaks",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        references=[
            "https://www.usenix.org/conference/usenixsecurity19/presentation/wu-jianliang",
            "https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Connection timeout in seconds",
                default=15
            ),
            "test_writes": ModuleOption(
                name="test_writes",
                required=False,
                description="Actually test write operations (may modify device)",
                default=False
            ),
            "deep_scan": ModuleOption(
                name="deep_scan",
                required=False,
                description="Perform deep analysis (slower)",
                default=True
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON file",
                default=None
            )
        }
    
    def _get_short_uuid(self, uuid: str) -> str:
        """Extract short UUID from full 128-bit UUID"""
        return uuid[4:8].lower()
    
    def _is_sensitive_uuid(self, uuid: str) -> bool:
        """Check if UUID is in sensitive list"""
        short = self._get_short_uuid(uuid)
        return short in SENSITIVE_WRITE_CHARS or short in INFO_LEAK_CHARS
    
    async def _test_unauth_write(self, client: BleakClient, char_uuid: str) -> bool:
        """Test if characteristic allows unauthenticated write"""
        for payload in TEST_PAYLOADS:
            try:
                await client.write_gatt_char(char_uuid, payload, response=False)
                return True  # Write succeeded without auth!
            except BleakError as e:
                err = str(e).lower()
                if "auth" in err or "encrypt" in err or "insufficient" in err:
                    return False  # Requires auth - good
                if "not permit" in err or "not support" in err:
                    return False  # Not writable
                # Other error - try next payload
                continue
            except Exception:
                continue
        return False
    
    async def _check_info_disclosure(self, client: BleakClient, char_uuid: str) -> Optional[str]:
        """Check if sensitive info is readable"""
        try:
            value = await client.read_gatt_char(char_uuid)
            if value:
                try:
                    decoded = value.decode('utf-8').strip('\x00')
                    if decoded and len(decoded) > 0:
                        return decoded
                except:
                    return value.hex()
        except:
            pass
        return None
    
    async def _scan_async(self, address: str) -> ScanResult:
        """Perform async vulnerability scan"""
        timeout = int(self.get_option("timeout"))
        test_writes = self.get_option("test_writes")
        deep_scan = self.get_option("deep_scan")
        
        result = ScanResult(address=address, name="")
        
        print_info(f"Connecting to {address}...")
        
        try:
            async with BleakClient(address, timeout=timeout) as client:
                if not client.is_connected:
                    print_error("Failed to connect")
                    return result
                
                print_success(f"Connected to {address}")
                print_info("Scanning for vulnerabilities...\n")
                
                # Get device name
                try:
                    name_char = None
                    for service in client.services:
                        for char in service.characteristics:
                            if self._get_short_uuid(str(char.uuid)) == "2a00":
                                name_char = char.uuid
                                break
                    if name_char:
                        name_val = await client.read_gatt_char(name_char)
                        result.name = name_val.decode('utf-8').strip('\x00')
                except:
                    pass
                
                # Enumerate services and characteristics
                for service in client.services:
                    service_uuid = str(service.uuid).lower()
                    short_svc = self._get_short_uuid(service_uuid)
                    result.services_count += 1
                    
                    # Check for known vulnerable service patterns
                    if short_svc in VULN_PATTERNS:
                        pattern = VULN_PATTERNS[short_svc]
                        result.vulns.append(Vulnerability(
                            name=f"Known Risk Service: {pattern['name']}",
                            severity=VulnSeverity.MEDIUM,
                            description=pattern['risk'],
                            affected=service_uuid,
                            details=f"Service {short_svc.upper()} is commonly found in vulnerable IoT devices",
                            recommendation="Manually verify authentication requirements"
                        ))
                    
                    for char in service.characteristics:
                        char_uuid = str(char.uuid).lower()
                        short_char = self._get_short_uuid(char_uuid)
                        props = list(char.properties)
                        result.chars_count += 1
                        
                        is_writable = "write" in props or "write-without-response" in props
                        is_readable = "read" in props
                        
                        if is_writable:
                            result.writable_count += 1
                        
                        # ===== CHECK: Write Without Response (potentially dangerous) =====
                        if "write-without-response" in props:
                            result.vulns.append(Vulnerability(
                                name="Write-Without-Response Enabled",
                                severity=VulnSeverity.LOW,
                                description="Characteristic allows writes without acknowledgment",
                                affected=char_uuid,
                                details=f"Properties: {', '.join(props)}",
                                recommendation="Verify authentication is required before write"
                            ))
                        
                        # ===== CHECK: Sensitive characteristic writable =====
                        if is_writable and short_char in SENSITIVE_WRITE_CHARS:
                            result.vulns.append(Vulnerability(
                                name=f"Sensitive Char Writable: {SENSITIVE_WRITE_CHARS[short_char]}",
                                severity=VulnSeverity.HIGH,
                                description=f"Sensitive characteristic {short_char.upper()} appears writable",
                                affected=char_uuid,
                                details=f"This characteristic ({SENSITIVE_WRITE_CHARS[short_char]}) should typically be read-only",
                                recommendation="Verify write requires authentication"
                            ))
                        
                        # ===== CHECK: Information disclosure =====
                        if is_readable and short_char in INFO_LEAK_CHARS and deep_scan:
                            value = await self._check_info_disclosure(client, char_uuid)
                            if value:
                                result.info_leak_count += 1
                                result.vulns.append(Vulnerability(
                                    name=f"Info Disclosure: {INFO_LEAK_CHARS[short_char]}",
                                    severity=VulnSeverity.LOW,
                                    description=f"Device exposes {INFO_LEAK_CHARS[short_char]}",
                                    affected=char_uuid,
                                    details=f"Leaked value: {value[:50]}{'...' if len(value) > 50 else ''}",
                                    recommendation="Consider if this info should be protected"
                                ))
                        
                        # ===== CHECK: Test unauthenticated writes =====
                        if is_writable and test_writes:
                            print_info(f"Testing write on {short_char.upper()}...")
                            if await self._test_unauth_write(client, char_uuid):
                                result.unauth_write_count += 1
                                result.vulns.append(Vulnerability(
                                    name="Unauthenticated Write Allowed",
                                    severity=VulnSeverity.CRITICAL,
                                    description="Characteristic accepts writes without authentication",
                                    affected=char_uuid,
                                    details=f"Write succeeded without pairing/bonding. Service: {short_svc.upper()}",
                                    recommendation="Implement proper authentication for writes",
                                    cve="N/A - Pre-pairing GATT vulnerability"
                                ))
                
                # ===== CHECK: No authentication at all =====
                if result.writable_count > 0 and result.unauth_write_count == result.writable_count:
                    result.vulns.append(Vulnerability(
                        name="No Write Authentication",
                        severity=VulnSeverity.CRITICAL,
                        description="Device has no authentication for any writable characteristic",
                        affected="All writable characteristics",
                        details=f"All {result.writable_count} writable characteristics allow unauthenticated writes",
                        recommendation="Implement BLE pairing/bonding requirements"
                    ))
                
                # ===== CHECK: Many writable without testing =====
                if not test_writes and result.writable_count > 5:
                    result.vulns.append(Vulnerability(
                        name="Multiple Writable Characteristics",
                        severity=VulnSeverity.MEDIUM,
                        description=f"Device has {result.writable_count} writable characteristics",
                        affected="Multiple",
                        details="Large attack surface - recommend testing with test_writes=true",
                        recommendation="Run with test_writes=true to verify authentication"
                    ))
                
                print_success("Vulnerability scan complete")
                
        except asyncio.TimeoutError:
            print_error(f"Connection timed out after {timeout}s")
        except BleakError as e:
            print_error(f"BLE error: {e}")
        except Exception as e:
            print_error(f"Error: {e}")
        
        return result
    
    def _print_results(self, result: ScanResult) -> None:
        """Print vulnerability scan results"""
        C = Colors
        
        # Header
        print(f"\n  {C.CYAN}{'='*100}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}BLE VULNERABILITY SCAN RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*100}{C.RESET}")
        print(f"  Target: {C.WHITE}{result.address}{C.RESET}")
        print(f"  Name  : {C.WHITE}{result.name or 'Unknown'}{C.RESET}\n")
        
        # Statistics
        print(f"  {C.BOLD}SCAN STATISTICS{C.RESET}\n")
        print(f"  {C.DARK_GREY}+---------------------------+----------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {'Metric':<25} {C.DARK_GREY}|{C.RESET} {'Value':<8} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+---------------------------+----------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} Services                  {C.DARK_GREY}|{C.RESET} {result.services_count:<8} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} Characteristics           {C.DARK_GREY}|{C.RESET} {result.chars_count:<8} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} Writable Chars            {C.DARK_GREY}|{C.RESET} {C.YELLOW}{result.writable_count:<8}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} Unauth Write Vulns        {C.DARK_GREY}|{C.RESET} {C.RED}{result.unauth_write_count:<8}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} Info Disclosure           {C.DARK_GREY}|{C.RESET} {result.info_leak_count:<8} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}Total Vulnerabilities{C.RESET}     {C.DARK_GREY}|{C.RESET} {C.RED if result.vulns else C.GREEN}{len(result.vulns):<8}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+---------------------------+----------+{C.RESET}")
        
        if not result.vulns:
            print(f"\n  {C.GREEN}[+] No vulnerabilities detected{C.RESET}")
            print(f"\n  {C.CYAN}{'='*100}{C.RESET}\n")
            return
        
        # Count by severity
        sev_counts = {s: 0 for s in VulnSeverity}
        for v in result.vulns:
            sev_counts[v.severity] += 1
        
        print(f"\n  {C.BOLD}VULNERABILITY SUMMARY{C.RESET}")
        print(f"  {C.RED}CRITICAL: {sev_counts[VulnSeverity.CRITICAL]}{C.RESET}  {C.RED}HIGH: {sev_counts[VulnSeverity.HIGH]}{C.RESET}  {C.YELLOW}MEDIUM: {sev_counts[VulnSeverity.MEDIUM]}{C.RESET}  {C.GREEN}LOW: {sev_counts[VulnSeverity.LOW]}{C.RESET}  {C.CYAN}INFO: {sev_counts[VulnSeverity.INFO]}{C.RESET}")
        
        # Vulnerabilities table
        print(f"\n  {C.BOLD}VULNERABILITIES FOUND ({len(result.vulns)}){C.RESET}\n")
        print(f"  {C.DARK_GREY}+-----+----------+------------------------------------------+----------------------------------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<3}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'SEVERITY':<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'VULNERABILITY':<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'AFFECTED':<32}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+-----+----------+------------------------------------------+----------------------------------+{C.RESET}")
        
        # Sort by severity
        severity_order = {VulnSeverity.CRITICAL: 0, VulnSeverity.HIGH: 1, VulnSeverity.MEDIUM: 2, VulnSeverity.LOW: 3, VulnSeverity.INFO: 4}
        sorted_vulns = sorted(result.vulns, key=lambda v: severity_order[v.severity])
        
        for idx, vuln in enumerate(sorted_vulns, 1):
            name = (vuln.name[:38] + "..") if len(vuln.name) > 40 else vuln.name
            affected = (vuln.affected[:30] + "..") if len(vuln.affected) > 32 else vuln.affected
            
            sev_colors = {
                VulnSeverity.CRITICAL: C.RED + C.BOLD,
                VulnSeverity.HIGH: C.RED,
                VulnSeverity.MEDIUM: C.YELLOW,
                VulnSeverity.LOW: C.GREEN,
                VulnSeverity.INFO: C.CYAN
            }
            sc = sev_colors[vuln.severity]
            
            print(f"  {C.DARK_GREY}|{C.RESET} {idx:<3} {C.DARK_GREY}|{C.RESET} {sc}{vuln.severity.value:<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {name:<40} {C.DARK_GREY}|{C.RESET} {affected:<32} {C.DARK_GREY}|{C.RESET}")
        
        print(f"  {C.DARK_GREY}+-----+----------+------------------------------------------+----------------------------------+{C.RESET}")
        
        # Detailed vulnerability info
        print(f"\n  {C.BOLD}VULNERABILITY DETAILS{C.RESET}\n")
        
        for idx, vuln in enumerate(sorted_vulns, 1):
            sc = sev_colors[vuln.severity]
            
            print(f"  {sc}[{idx}] {vuln.name}{C.RESET}")
            print(f"  {C.DARK_GREY}{'─'*90}{C.RESET}")
            print(f"      Severity       : {sc}{vuln.severity.value}{C.RESET}")
            print(f"      Affected       : {vuln.affected}")
            print(f"      Description    : {vuln.description}")
            print(f"      Details        : {vuln.details}")
            print(f"      Recommendation : {vuln.recommendation}")
            if vuln.cve:
                print(f"      CVE            : {vuln.cve}")
            print()
        
        # Risk assessment
        print(f"  {C.CYAN}{'-'*100}{C.RESET}")
        print(f"  {C.BOLD}RISK ASSESSMENT{C.RESET}")
        print(f"  {C.CYAN}{'-'*100}{C.RESET}")
        
        if sev_counts[VulnSeverity.CRITICAL] > 0:
            print(f"  {C.RED}[!] CRITICAL RISK: Device has critical vulnerabilities requiring immediate attention{C.RESET}")
        elif sev_counts[VulnSeverity.HIGH] > 0:
            print(f"  {C.RED}[!] HIGH RISK: Device has high severity vulnerabilities{C.RESET}")
        elif sev_counts[VulnSeverity.MEDIUM] > 0:
            print(f"  {C.YELLOW}[!] MODERATE RISK: Device has medium severity issues{C.RESET}")
        else:
            print(f"  {C.GREEN}[+] LOW RISK: Only low severity or informational findings{C.RESET}")
        
        # Recommendations
        if result.unauth_write_count > 0:
            print(f"\n  {C.YELLOW}NEXT STEPS:{C.RESET}")
            print(f"    1. Test unauth writes with exploits/ble/unauth_write module")
            print(f"    2. Capture traffic to analyze protocol")
            print(f"    3. Check for replay attack possibilities")
        
        print(f"\n  {C.CYAN}{'='*100}{C.RESET}\n")
    
    def _save_results(self, result: ScanResult, filename: str) -> None:
        """Save results to JSON"""
        import json
        
        output = {
            "target": result.address,
            "name": result.name,
            "statistics": {
                "services": result.services_count,
                "characteristics": result.chars_count,
                "writable": result.writable_count,
                "unauth_writes": result.unauth_write_count,
                "info_leaks": result.info_leak_count,
                "total_vulns": len(result.vulns)
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
                "cve": v.cve
            })
        
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")
    
    def run(self) -> bool:
        """Execute vulnerability scan"""
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False
        
        target = self.target
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        test_writes = self.get_option("test_writes")
        if test_writes:
            print_warning("test_writes enabled - this may modify device state!")
            print_info("Proceeding in 3 seconds... (Ctrl+C to cancel)")
            try:
                import time
                time.sleep(3)
            except KeyboardInterrupt:
                print_warning("Cancelled")
                return False
        
        try:
            result = asyncio.run(self._scan_async(target))
            self.add_result(result)
            self._print_results(result)
            
            out = self.get_option("output_file")
            if out:
                self._save_results(result, out)
            
            return len(result.vulns) > 0 or result.services_count > 0
            
        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False
