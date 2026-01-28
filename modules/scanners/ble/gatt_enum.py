"""
BlueSploit Module: GATT Enumerator
Connects to a BLE device and enumerates all GATT services and characteristics
"""

import asyncio
from typing import Dict, Any, List, Optional
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, ScanResult, Target
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning,
    print_service, print_characteristic, Colors
)

try:
    from bleak import BleakClient
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# Well-known GATT service UUIDs
KNOWN_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
    "00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
    "00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "0000fee0-0000-1000-8000-00805f9b34fb": "Xiaomi Service",
    "0000feb3-0000-1000-8000-00805f9b34fb": "Tile Service",
}

# Well-known characteristic UUIDs
KNOWN_CHARACTERISTICS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Peripheral Preferred Connection Parameters",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number String",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number String",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision String",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision String",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision String",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name String",
    "00002a06-0000-1000-8000-00805f9b34fb": "Alert Level",
    "00002a07-0000-1000-8000-00805f9b34fb": "Tx Power Level",
}


class Module(ScannerModule):
    """
    GATT Service/Characteristic Enumerator
    
    Connects to a BLE device and extracts:
    - All GATT services
    - All characteristics with properties
    - Identifies potentially vulnerable characteristics
    - Attempts to read readable characteristics
    """
    
    info = ModuleInfo(
        name="scanners/ble/gatt_enum",
        description="Enumerate GATT services and characteristics",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/gatt/",
            "https://github.com/v33ru/PhantomTouch"
        ]
    )
    
    def _setup_options(self) -> None:
        """Define module options"""
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
            "read_values": ModuleOption(
                name="read_values",
                required=False,
                description="Attempt to read characteristic values",
                default=True
            ),
            "check_vulns": ModuleOption(
                name="check_vulns",
                required=False,
                description="Check for potential vulnerabilities",
                default=True
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON file",
                default=None
            )
        }
    
    def _get_service_name(self, uuid: str) -> str:
        """Get human-readable service name from UUID"""
        uuid_lower = uuid.lower()
        return KNOWN_SERVICES.get(uuid_lower, "Unknown Service")
    
    def _get_char_name(self, uuid: str) -> str:
        """Get human-readable characteristic name from UUID"""
        uuid_lower = uuid.lower()
        return KNOWN_CHARACTERISTICS.get(uuid_lower, "Unknown Characteristic")
    
    def _analyze_security(self, char_props: List[str], 
                          service_uuid: str) -> List[Dict[str, str]]:
        """
        Analyze characteristic for potential security issues
        
        Returns list of vulnerability flags
        """
        vulns = []
        
        # Check for write without response (potential for unauth writes)
        if "write-without-response" in char_props:
            vulns.append({
                "type": "UNAUTH_WRITE_POSSIBLE",
                "severity": "MEDIUM",
                "description": "Write-without-response enabled - may allow unauthenticated writes"
            })
        
        # Check for notify without authentication
        if "notify" in char_props or "indicate" in char_props:
            vulns.append({
                "type": "UNAUTH_NOTIFY",
                "severity": "LOW",
                "description": "Notifications enabled - data may leak without authentication"
            })
        
        # Check for broadcast
        if "broadcast" in char_props:
            vulns.append({
                "type": "BROADCAST_ENABLED",
                "severity": "LOW",
                "description": "Broadcast flag set - data may be publicly visible"
            })
        
        # Writable characteristics are interesting for exploitation
        if "write" in char_props or "write-without-response" in char_props:
            vulns.append({
                "type": "WRITABLE",
                "severity": "INFO",
                "description": "Writable characteristic - potential command injection point"
            })
        
        return vulns
    
    async def _enumerate_async(self, address: str) -> Dict[str, Any]:
        """Perform async GATT enumeration"""
        timeout = self.get_option("timeout")
        read_values = self.get_option("read_values")
        check_vulns = self.get_option("check_vulns")
        
        results = {
            "target": address,
            "services": [],
            "vulnerabilities": [],
            "readable_data": {},
            "stats": {
                "total_services": 0,
                "total_characteristics": 0,
                "writable_chars": 0,
                "readable_chars": 0
            }
        }
        
        print_info(f"Connecting to {address}...")
        
        try:
            async with BleakClient(address, timeout=timeout) as client:
                if not client.is_connected:
                    print_error("Failed to connect")
                    return results
                
                print_success(f"Connected to {address}")
                print_info("Enumerating GATT services...\n")
                
                for service in client.services:
                    service_uuid = str(service.uuid)
                    service_name = self._get_service_name(service_uuid)
                    
                    service_info = {
                        "uuid": service_uuid,
                        "name": service_name,
                        "handle": service.handle,
                        "characteristics": []
                    }
                    
                    # Print service
                    print(f"\n  {Colors.MAGENTA}[Service]{Colors.RESET} {service_uuid}")
                    print(f"  {Colors.DIM}{service_name} (Handle: 0x{service.handle:04X}){Colors.RESET}")
                    
                    results["stats"]["total_services"] += 1
                    
                    for char in service.characteristics:
                        char_uuid = str(char.uuid)
                        char_name = self._get_char_name(char_uuid)
                        
                        char_info = {
                            "uuid": char_uuid,
                            "name": char_name,
                            "handle": char.handle,
                            "properties": char.properties,
                            "descriptors": [str(d.uuid) for d in char.descriptors],
                            "value": None,
                            "vulnerabilities": []
                        }
                        
                        results["stats"]["total_characteristics"] += 1
                        
                        # Count writable/readable
                        if "write" in char.properties or "write-without-response" in char.properties:
                            results["stats"]["writable_chars"] += 1
                        if "read" in char.properties:
                            results["stats"]["readable_chars"] += 1
                        
                        # Check for vulnerabilities
                        if check_vulns:
                            vulns = self._analyze_security(char.properties, service_uuid)
                            char_info["vulnerabilities"] = vulns
                            for v in vulns:
                                results["vulnerabilities"].append({
                                    **v,
                                    "characteristic": char_uuid,
                                    "service": service_uuid
                                })
                        
                        # Try to read value
                        value_str = None
                        if read_values and "read" in char.properties:
                            try:
                                value = await client.read_gatt_char(char.uuid)
                                char_info["value"] = value.hex()
                                results["readable_data"][char_uuid] = value.hex()
                                
                                # Try to decode as string
                                try:
                                    value_str = value.decode('utf-8').strip('\x00')
                                except:
                                    value_str = f"0x{value.hex()}"
                            except Exception as e:
                                value_str = f"(read error: {str(e)[:30]})"
                        
                        # Print characteristic
                        props_str = ", ".join(char.properties)
                        vuln_indicator = ""
                        if char_info["vulnerabilities"]:
                            high_sev = [v for v in char_info["vulnerabilities"] 
                                       if v["severity"] in ["HIGH", "MEDIUM"]]
                            if high_sev:
                                vuln_indicator = f" {Colors.RED}⚠ VULN{Colors.RESET}"
                        
                        print(f"    {Colors.CYAN}├── [Char]{Colors.RESET} {char_uuid}{vuln_indicator}")
                        print(f"    │   {Colors.DIM}{char_name}{Colors.RESET}")
                        print(f"    │   Properties: {props_str}")
                        print(f"    │   Handle: 0x{char.handle:04X}")
                        
                        if value_str:
                            print(f"    │   Value: {Colors.GREEN}{value_str}{Colors.RESET}")
                        
                        if char_info["vulnerabilities"] and check_vulns:
                            for v in char_info["vulnerabilities"]:
                                if v["severity"] in ["HIGH", "MEDIUM"]:
                                    print(f"    │   {Colors.RED}⚠ {v['type']}: {v['description']}{Colors.RESET}")
                        
                        service_info["characteristics"].append(char_info)
                    
                    results["services"].append(service_info)
                
                print_success("\nEnumeration complete")
                
        except asyncio.TimeoutError:
            print_error(f"Connection timed out after {timeout}s")
        except BleakError as e:
            print_error(f"BLE error: {e}")
        except Exception as e:
            print_error(f"Unexpected error: {e}")
        
        return results
    
    def _print_summary(self, results: Dict[str, Any]) -> None:
        """Print enumeration summary"""
        stats = results["stats"]
        vulns = results["vulnerabilities"]
        
        print(f"\n  {Colors.CYAN}═══ Enumeration Summary ═══{Colors.RESET}")
        print(f"  Target: {results['target']}")
        print(f"  Services: {stats['total_services']}")
        print(f"  Characteristics: {stats['total_characteristics']}")
        print(f"  Readable: {stats['readable_chars']}")
        print(f"  Writable: {stats['writable_chars']}")
        
        if vulns:
            # Count by severity
            high = len([v for v in vulns if v["severity"] == "HIGH"])
            medium = len([v for v in vulns if v["severity"] == "MEDIUM"])
            low = len([v for v in vulns if v["severity"] == "LOW"])
            info = len([v for v in vulns if v["severity"] == "INFO"])
            
            print(f"\n  {Colors.RED}Potential Issues Found:{Colors.RESET}")
            if high:
                print(f"    {Colors.RED}HIGH: {high}{Colors.RESET}")
            if medium:
                print(f"    {Colors.YELLOW}MEDIUM: {medium}{Colors.RESET}")
            if low:
                print(f"    LOW: {low}")
            if info:
                print(f"    INFO: {info}")
            
            # Show writable characteristics (interesting for exploitation)
            writable = [v for v in vulns if v["type"] == "WRITABLE"]
            if writable:
                print(f"\n  {Colors.YELLOW}Writable Characteristics (potential attack surface):{Colors.RESET}")
                for v in writable[:5]:  # Show first 5
                    print(f"    - {v['characteristic']}")
        
        print()
    
    def _save_results(self, results: Dict[str, Any], filename: str) -> None:
        """Save results to JSON file"""
        import json
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print_success(f"Results saved to: {filename}")
        except Exception as e:
            print_error(f"Failed to save: {e}")
    
    def run(self) -> bool:
        """Execute GATT enumeration"""
        if not BLEAK_AVAILABLE:
            print_error("Bleak library not installed!")
            print_info("Install with: pip install bleak")
            return False
        
        target = self.target
        
        # Validate BD_ADDR format
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR format: {target}")
            print_info("Expected format: XX:XX:XX:XX:XX:XX")
            return False
        
        try:
            results = asyncio.run(self._enumerate_async(target))
            
            # Store results
            self.add_result(results)
            
            # Print summary
            self._print_summary(results)
            
            # Save if requested
            output_file = self.get_option("output_file")
            if output_file:
                self._save_results(results, output_file)
            
            return results["stats"]["total_services"] > 0
            
        except KeyboardInterrupt:
            print_warning("\nEnumeration interrupted")
            return False
        except Exception as e:
            print_error(f"Enumeration failed: {e}")
            return False
