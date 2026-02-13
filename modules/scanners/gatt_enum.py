"""
BlueSploit Module: GATT Enumerator
Connects to a BLE device and enumerates all GATT services and characteristics
"""

import asyncio
from typing import Dict, Any, List
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
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
    "00001805-0000-1000-8000-00805f9b34fb": "Current Time",
    "00001809-0000-1000-8000-00805f9b34fb": "Health Thermometer",
    "0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
    "00001812-0000-1000-8000-00805f9b34fb": "HID Service",
    "00001813-0000-1000-8000-00805f9b34fb": "Scan Parameters",
}

# Well-known characteristic UUIDs
KNOWN_CHARACTERISTICS = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a04-0000-1000-8000-00805f9b34fb": "Periph Pref Conn",
    "00002a05-0000-1000-8000-00805f9b34fb": "Service Changed",
    "00002a06-0000-1000-8000-00805f9b34fb": "Alert Level",
    "00002a07-0000-1000-8000-00805f9b34fb": "Tx Power Level",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Rev",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Rev",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Rev",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer",
    "00002a2b-0000-1000-8000-00805f9b34fb": "Current Time",
}


class Module(ScannerModule):
    """GATT Service/Characteristic Enumerator"""
    
    info = ModuleInfo(
        name="scanners/ble/gatt_enum",
        description="Enumerate GATT services and characteristics",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=["https://www.bluetooth.com/specifications/gatt/"]
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
            "read_values": ModuleOption(
                name="read_values",
                required=False,
                description="Attempt to read characteristic values",
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
        uuid_lower = uuid.lower()
        if uuid_lower in KNOWN_SERVICES:
            return KNOWN_SERVICES[uuid_lower]
        return f"Vendor 0x{uuid[4:8].upper()}"
    
    def _get_char_name(self, uuid: str) -> str:
        uuid_lower = uuid.lower()
        if uuid_lower in KNOWN_CHARACTERISTICS:
            return KNOWN_CHARACTERISTICS[uuid_lower]
        return f"0x{uuid[4:8].upper()}"
    
    def _format_props(self, props: List[str]) -> str:
        p = []
        if "read" in props:
            p.append("R")
        if "write" in props:
            p.append("W")
        if "write-without-response" in props:
            p.append("WNR")
        if "notify" in props:
            p.append("N")
        if "indicate" in props:
            p.append("I")
        return " ".join(p) if p else "-"
    
    def _format_value(self, value: Any, max_len: int = 18) -> str:
        if value is None:
            return "-"
        if isinstance(value, bytes):
            try:
                decoded = value.decode('utf-8').strip('\x00')
                if decoded.isprintable() and decoded:
                    if len(decoded) > max_len:
                        return decoded[:max_len-2] + ".."
                    return decoded
            except:
                pass
            hex_str = value.hex()
            if len(hex_str) > max_len - 2:
                return "0x" + hex_str[:max_len-4] + ".."
            return "0x" + hex_str
        return str(value)[:max_len]
    
    async def _enumerate_async(self, address: str) -> Dict[str, Any]:
        timeout = self.get_option("timeout")
        read_values = self.get_option("read_values")
        
        results = {
            "target": address,
            "services": [],
            "characteristics": [],
            "stats": {
                "total_services": 0,
                "total_chars": 0,
                "readable": 0,
                "writable": 0,
                "notify": 0
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
                    svc_uuid = str(service.uuid)
                    svc_name = self._get_service_name(svc_uuid)
                    
                    results["stats"]["total_services"] += 1
                    results["services"].append({
                        "uuid": svc_uuid,
                        "name": svc_name,
                        "handle": service.handle,
                        "chars": len(service.characteristics)
                    })
                    
                    for char in service.characteristics:
                        char_uuid = str(char.uuid)
                        char_name = self._get_char_name(char_uuid)
                        props = list(char.properties)
                        
                        results["stats"]["total_chars"] += 1
                        
                        is_read = "read" in props
                        is_write = "write" in props or "write-without-response" in props
                        is_notify = "notify" in props or "indicate" in props
                        
                        if is_read:
                            results["stats"]["readable"] += 1
                        if is_write:
                            results["stats"]["writable"] += 1
                        if is_notify:
                            results["stats"]["notify"] += 1
                        
                        value = "-"
                        if read_values and is_read:
                            try:
                                raw = await client.read_gatt_char(char.uuid)
                                value = self._format_value(raw)
                            except:
                                value = "(error)"
                        
                        results["characteristics"].append({
                            "svc_uuid": svc_uuid,
                            "svc_name": svc_name,
                            "uuid": char_uuid,
                            "name": char_name,
                            "handle": char.handle,
                            "props": props,
                            "is_read": is_read,
                            "is_write": is_write,
                            "is_notify": is_notify,
                            "value": value
                        })
                
                print_success("Enumeration complete")
                
        except asyncio.TimeoutError:
            print_error(f"Timeout after {timeout}s")
        except BleakError as e:
            print_error(f"BLE error: {e}")
        except Exception as e:
            print_error(f"Error: {e}")
        
        return results
    
    def _print_table(self, results: Dict[str, Any]) -> None:
        C = Colors
        
        if not results["characteristics"]:
            print_warning("No characteristics found")
            return
        
        stats = results["stats"]
        
        # ========== HEADER ==========
        print(f"\n  {C.CYAN}{'='*105}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}GATT ENUMERATION RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*105}{C.RESET}")
        print(f"  Target: {C.WHITE}{results['target']}{C.RESET}\n")
        
        # ========== SERVICES TABLE ==========
        print(f"  {C.BOLD}SERVICES ({stats['total_services']}){C.RESET}\n")
        print(f"  {C.DARK_GREY}+------+------------------------------------------+----------------------------+--------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<4}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'UUID':<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'NAME':<26}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'CHARS':<6}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+------+------------------------------------------+----------------------------+--------+{C.RESET}")
        
        for i, s in enumerate(results["services"], 1):
            name = s["name"][:26]
            print(f"  {C.DARK_GREY}|{C.RESET} {i:<4} {C.DARK_GREY}|{C.RESET} {C.CYAN}{s['uuid']:<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {name:<26} {C.DARK_GREY}|{C.RESET} {s['chars']:<6} {C.DARK_GREY}|{C.RESET}")
        
        print(f"  {C.DARK_GREY}+------+------------------------------------------+----------------------------+--------+{C.RESET}")
        
        # ========== CHARACTERISTICS TABLE ==========
        print(f"\n  {C.BOLD}CHARACTERISTICS ({stats['total_chars']}){C.RESET}\n")
        print(f"  {C.DARK_GREY}+-----+------------------------------------------+------------------+----------+--------+--------------------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<3}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'UUID':<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'NAME':<16}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'PROPS':<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'HANDLE':<6}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'VALUE':<18}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+-----+------------------------------------------+------------------+----------+--------+--------------------+{C.RESET}")
        
        for i, c in enumerate(results["characteristics"], 1):
            name = c["name"][:16]
            props = self._format_props(c["props"])[:8]
            handle = f"0x{c['handle']:04X}"
            value = c["value"][:18]
            
            if c["is_write"]:
                pc = C.YELLOW
            elif c["is_notify"]:
                pc = C.MAGENTA
            else:
                pc = ""
            
            print(f"  {C.DARK_GREY}|{C.RESET} {i:<3} {C.DARK_GREY}|{C.RESET} {C.CYAN}{c['uuid']:<40}{C.RESET} {C.DARK_GREY}|{C.RESET} {name:<16} {C.DARK_GREY}|{C.RESET} {pc}{props:<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {handle:<6} {C.DARK_GREY}|{C.RESET} {C.GREEN}{value:<18}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        
        print(f"  {C.DARK_GREY}+-----+------------------------------------------+------------------+----------+--------+--------------------+{C.RESET}")
        
        # Legend
        print(f"\n  {C.DARK_GREY}Props: R=Read  W=Write  WNR=Write-No-Response  N=Notify  I=Indicate{C.RESET}")
        
        # ========== SUMMARY ==========
        print(f"\n  {C.CYAN}{'-'*105}{C.RESET}")
        print(f"  {C.BOLD}SUMMARY{C.RESET}")
        print(f"  {C.CYAN}{'-'*105}{C.RESET}")
        print(f"  Services: {stats['total_services']}   Characteristics: {stats['total_chars']}   {C.GREEN}Readable: {stats['readable']}{C.RESET}   {C.YELLOW}Writable: {stats['writable']}{C.RESET}   {C.MAGENTA}Notify: {stats['notify']}{C.RESET}")
        
        # ========== WRITABLE LIST ==========
        writable = [c for c in results["characteristics"] if c["is_write"]]
        if writable:
            print(f"\n  {C.YELLOW}WRITABLE CHARACTERISTICS (Attack Surface):{C.RESET}")
            for c in writable:
                p = self._format_props(c["props"])
                print(f"    {C.YELLOW}>{C.RESET} {c['uuid']}  [{p}]")
        
        # ========== NOTIFY LIST ==========
        notify = [c for c in results["characteristics"] if c["is_notify"]]
        if notify:
            print(f"\n  {C.MAGENTA}NOTIFY/INDICATE CHARACTERISTICS:{C.RESET}")
            for c in notify:
                p = self._format_props(c["props"])
                print(f"    {C.MAGENTA}>{C.RESET} {c['uuid']}  [{p}]")
        
        print(f"\n  {C.CYAN}{'='*105}{C.RESET}\n")
    
    def _save_results(self, results: Dict[str, Any], filename: str) -> None:
        import json
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")
    
    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False
        
        target = self.target
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        try:
            results = asyncio.run(self._enumerate_async(target))
            self.add_result(results)
            self._print_table(results)
            
            out = self.get_option("output_file")
            if out:
                self._save_results(results, out)
            
            return results["stats"]["total_services"] > 0
            
        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Failed: {e}")
            return False
