"""
BlueSploit Module: BLE Discovery Scanner
Discovers nearby BLE devices with detailed information
"""

import asyncio
from typing import Dict, Any, Optional
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption, 
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info, 
    print_warning, print_device, Colors, progress_bar
)

# Try to import bleak, provide helpful error if not available
try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


class Module(ScannerModule):
    """
    BLE Discovery Scanner
    
    Scans for nearby BLE devices and extracts:
    - Device address (BD_ADDR)
    - Device name
    - RSSI signal strength
    - Manufacturer data
    - Service UUIDs
    - Advertisement data
    """
    
    info = ModuleInfo(
        name="scanners/ble/discovery",
        description="Discover nearby BLE devices",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification/"
        ]
    )
    
    def _setup_options(self) -> None:
        """Define scanner options"""
        self.options = {
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Scan duration in seconds",
                default=10
            ),
            "filter_name": ModuleOption(
                name="filter_name",
                required=False,
                description="Filter devices by name (substring match)",
                default=None
            ),
            "filter_rssi": ModuleOption(
                name="filter_rssi",
                required=False,
                description="Minimum RSSI threshold (e.g., -70)",
                default=None
            ),
            "show_duplicates": ModuleOption(
                name="show_duplicates",
                required=False,
                description="Show duplicate advertisements",
                default=False
            ),
            "live_output": ModuleOption(
                name="live_output",
                required=False,
                description="Show devices as they are found",
                default=True
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to file (JSON format)",
                default=None
            )
        }
    
    def _get_manufacturer_name(self, company_id: int) -> str:
        """
        Get manufacturer name from company ID
        Common Bluetooth SIG assigned company IDs
        """
        manufacturers = {
            0x004C: "Apple",
            0x0006: "Microsoft",
            0x000F: "Broadcom",
            0x0075: "Samsung",
            0x00E0: "Google",
            0x0059: "Nordic Semi",
            0x000D: "Texas Instruments",
            0x0131: "Huawei",
            0x0157: "Xiaomi",
            0x038F: "Espressif",
            0x0087: "Garmin",
            0x00D2: "Fitbit",
            0x0310: "Wyze",
            0x0171: "Amazon",
            0x02FF: "Facebook",
            0x0002: "Intel",
            0x001D: "Qualcomm",
            0x0078: "Nike",
            0x00E0: "Google",
            0x0822: "Govee",
            0x0969: "Tuya",
        }
        return manufacturers.get(company_id, f"0x{company_id:04X}")
    
    def _parse_advertisement(self, device: 'BLEDevice', 
                            adv_data: 'AdvertisementData') -> Dict[str, Any]:
        """Parse advertisement data into structured format"""
        result = {
            "address": device.address,
            "name": adv_data.local_name or device.name or None,
            "rssi": adv_data.rssi if hasattr(adv_data, 'rssi') else None,
            "services": [],
            "manufacturer": None,
            "manufacturer_data": {},
            "tx_power": adv_data.tx_power,
            "platform_data": {}
        }
        
        # Parse service UUIDs
        if adv_data.service_uuids:
            result["services"] = list(adv_data.service_uuids)
        
        # Parse manufacturer data
        if adv_data.manufacturer_data:
            for company_id, data in adv_data.manufacturer_data.items():
                result["manufacturer"] = self._get_manufacturer_name(company_id)
                result["manufacturer_data"][f"0x{company_id:04X}"] = data.hex()
        
        return result
    
    def _get_rssi_bar(self, rssi: int) -> str:
        """Generate visual RSSI strength bar"""
        if rssi is None:
            return "N/A  "
        
        # RSSI typically ranges from -100 (weak) to -30 (strong)
        # Normalize to 0-5 scale
        strength = min(5, max(0, (rssi + 100) // 14))
        
        bar = "█" * strength + "░" * (5 - strength)
        
        # Color based on strength
        if strength >= 4:
            return f"{Colors.GREEN}{bar}{Colors.RESET}"
        elif strength >= 2:
            return f"{Colors.YELLOW}{bar}{Colors.RESET}"
        else:
            return f"{Colors.RED}{bar}{Colors.RESET}"
    
    async def _scan_async(self) -> Dict[str, Dict[str, Any]]:
        """Perform async BLE scan"""
        timeout = self.get_option("timeout")
        filter_name = self.get_option("filter_name")
        filter_rssi = self.get_option("filter_rssi")
        show_duplicates = self.get_option("show_duplicates")
        live_output = self.get_option("live_output")
        
        devices: Dict[str, Dict[str, Any]] = {}
        
        def detection_callback(device: 'BLEDevice', adv_data: 'AdvertisementData'):
            """Callback for each detected device"""
            # Skip if already seen and not showing duplicates
            if device.address in devices and not show_duplicates:
                # Update RSSI if stronger
                current_rssi = adv_data.rssi if hasattr(adv_data, 'rssi') else -100
                if current_rssi and current_rssi > devices[device.address].get("rssi", -100):
                    devices[device.address]["rssi"] = current_rssi
                return
            
            # Parse advertisement data
            parsed = self._parse_advertisement(device, adv_data)
            
            # Apply filters
            if filter_name and filter_name.lower() not in (parsed["name"] or "").lower():
                return
            
            if filter_rssi:
                rssi = parsed.get("rssi")
                if rssi is None or rssi < int(filter_rssi):
                    return
            
            # Store device
            devices[device.address] = parsed
            
            # Print device info in real-time if enabled
            if live_output:
                extra = ""
                if parsed["manufacturer"]:
                    extra = f"[{parsed['manufacturer']}]"
                if parsed["services"]:
                    extra += f" Services: {len(parsed['services'])}"
                
                print_device(
                    parsed["address"],
                    parsed["name"],
                    parsed.get("rssi"),
                    extra
                )
        
        print_info(f"Scanning for BLE devices ({timeout}s)...")
        print_info("Press Ctrl+C to stop early\n")
        
        try:
            scanner = BleakScanner(detection_callback=detection_callback)
            await scanner.start()
            
            # Progress indicator
            for i in range(timeout):
                await asyncio.sleep(1)
                progress_bar(i + 1, timeout, prefix="Scanning", 
                           suffix=f"Found: {len(devices)}")
            
            await scanner.stop()
            
        except Exception as e:
            print_error(f"Scan error: {e}")
        
        return devices
    
    def _save_results(self, devices: Dict[str, Dict[str, Any]], 
                      filename: str) -> None:
        """Save scan results to JSON file"""
        import json
        
        output = {
            "scan_info": {
                "module": self.info.name,
                "timeout": self.get_option("timeout"),
                "device_count": len(devices)
            },
            "devices": list(devices.values())
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            print_success(f"Results saved to: {filename}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")
    
    def _print_table(self, devices: Dict[str, Dict[str, Any]]) -> None:
        """Print scan results in table format"""
        if not devices:
            print_warning("No devices found")
            return
        
        # Sort devices by RSSI (strongest first)
        sorted_devices = sorted(
            devices.values(), 
            key=lambda x: x.get("rssi") or -999, 
            reverse=True
        )
        
        # Print header
        print(f"\n  {Colors.CYAN}{'═'*85}{Colors.RESET}")
        print(f"  {Colors.CYAN}SCAN RESULTS{Colors.RESET} - {len(devices)} device(s) found")
        print(f"  {Colors.CYAN}{'═'*85}{Colors.RESET}\n")
        
        # Table header
        print(f"  {Colors.BOLD}{'#':<4}{'ADDRESS':<20}{'NAME':<22}{'RSSI':<8}{'SIGNAL':<9}{'VENDOR':<14}{'SVC':<4}{Colors.RESET}")
        print(f"  {'─'*4}{'─'*20}{'─'*22}{'─'*8}{'─'*9}{'─'*14}{'─'*4}")
        
        # Print each device
        for idx, dev in enumerate(sorted_devices, 1):
            address = dev["address"]
            
            name = dev.get("name") or "Unknown"
            if len(name) > 20:
                name = name[:17] + "..."
            
            rssi = dev.get("rssi")
            rssi_str = f"{rssi} dBm" if rssi else "N/A"
            signal_bar = self._get_rssi_bar(rssi)
            
            manufacturer = dev.get("manufacturer") or "-"
            if len(manufacturer) > 12:
                manufacturer = manufacturer[:9] + "..."
            
            services = len(dev.get("services", []))
            svc_str = str(services) if services > 0 else "-"
            
            print(
                f"  {idx:<4}"
                f"{address:<20}"
                f"{name:<22}"
                f"{rssi_str:<8}"
                f"{signal_bar}  "
                f"{manufacturer:<14}"
                f"{svc_str:<4}"
            )
        
        print(f"\n  {Colors.CYAN}{'═'*85}{Colors.RESET}")
        
        # Summary stats
        manufacturers: Dict[str, int] = {}
        with_services = 0
        with_name = 0
        
        for dev in devices.values():
            mfr = dev.get("manufacturer") or "Unknown"
            manufacturers[mfr] = manufacturers.get(mfr, 0) + 1
            if dev.get("services"):
                with_services += 1
            if dev.get("name"):
                with_name += 1
        
        print(f"\n  {Colors.CYAN}SUMMARY{Colors.RESET}")
        print(f"  ├─ Total Devices   : {len(devices)}")
        print(f"  ├─ Named Devices   : {with_name}")
        print(f"  ├─ With Services   : {with_services}")
        
        if manufacturers:
            print(f"  └─ Vendors         : ", end="")
            mfr_parts = [f"{k}({v})" for k, v in sorted(manufacturers.items(), key=lambda x: -x[1])[:5]]
            print(", ".join(mfr_parts))
        
        print()
    
    def run(self) -> bool:
        """Execute the BLE discovery scan"""
        if not BLEAK_AVAILABLE:
            print_error("Bleak library not installed!")
            print_info("Install with: pip install bleak")
            return False
        
        try:
            # Run the async scan
            devices = asyncio.run(self._scan_async())
            
            # Store results
            for addr, dev in devices.items():
                target = Target(
                    address=addr,
                    name=dev.get("name"),
                    rssi=dev.get("rssi"),
                    manufacturer=dev.get("manufacturer"),
                    services=dev.get("services", [])
                )
                self.add_device(target)
            
            # Print table output
            self._print_table(devices)
            
            # Save to file if requested
            output_file = self.get_option("output_file")
            if output_file:
                self._save_results(devices, output_file)
            
            return len(devices) > 0
            
        except KeyboardInterrupt:
            print_warning("\nScan interrupted by user")
            return True
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False
