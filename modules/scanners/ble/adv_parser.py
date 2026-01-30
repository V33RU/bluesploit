"""
BlueSploit Module: BLE Advertisement Parser
Deep analysis of BLE advertisement data including manufacturer data,
service UUIDs, flags, and device fingerprinting

Author: v33ru
"""

import asyncio
import struct
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice
    from bleak.backends.scanner import AdvertisementData
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# Company IDs (Bluetooth SIG assigned)
COMPANY_IDS = {
    0x0000: "Ericsson", 0x0001: "Nokia", 0x0002: "Intel", 0x0006: "Microsoft",
    0x000D: "Texas Instruments", 0x000F: "Broadcom", 0x004C: "Apple",
    0x0059: "Nordic Semi", 0x0075: "Samsung", 0x0087: "Garmin",
    0x00E0: "Google", 0x0157: "Huawei", 0x015D: "Xiaomi", 0x0171: "Amazon",
    0x0310: "Fitbit", 0x038F: "Tile", 0x0822: "Espressif", 0x09A3: "Wyze",
    0x00D2: "Dialog Semi", 0x022B: "Bose", 0x0131: "Anhui Huami",
}

# Known 16-bit Service UUIDs
SERVICE_UUIDS = {
    0x1800: "Generic Access", 0x1801: "Generic Attribute", 0x1802: "Immediate Alert",
    0x1803: "Link Loss", 0x1804: "Tx Power", 0x1805: "Current Time",
    0x180A: "Device Information", 0x180D: "Heart Rate", 0x180F: "Battery Service",
    0x1810: "Blood Pressure", 0x1812: "HID", 0x1813: "Scan Parameters",
    0x1816: "Cycling Speed", 0x1818: "Cycling Power", 0x181A: "Environmental",
    0x181D: "Weight Scale", 0xFE95: "Xiaomi Mi", 0xFEAA: "Eddystone",
    0xFFE0: "Common IoT", 0xFFF0: "Vendor Specific", 0xFFD0: "Vendor Specific 2",
}


@dataclass
class ParsedAdv:
    address: str
    address_type: str
    name: str
    rssi: int
    tx_power: Optional[int]
    mfg_id: Optional[int]
    mfg_name: str
    mfg_data: bytes
    services: List[Dict]
    services_128: List[str]
    service_data: Dict[str, bytes]
    device_type: str
    sec_notes: List[str]


class Module(ScannerModule):
    """BLE Advertisement Parser - Deep analysis of advertisement data"""
    
    info = ModuleInfo(
        name="scanners/ble/adv_parser",
        description="Deep BLE advertisement data analysis",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=["https://www.bluetooth.com/specifications/assigned-numbers/"]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "timeout": ModuleOption(name="timeout", required=False, description="Scan duration (seconds)", default=15),
            "target": ModuleOption(name="target", required=False, description="Filter by BD_ADDR", default=None),
            "filter_name": ModuleOption(name="filter_name", required=False, description="Filter by name", default=None),
            "show_raw": ModuleOption(name="show_raw", required=False, description="Show raw bytes", default=False),
            "output_file": ModuleOption(name="output_file", required=False, description="Save to JSON", default=None)
        }
    
    def _get_company(self, cid: int) -> str:
        return COMPANY_IDS.get(cid, f"Unknown (0x{cid:04X})")
    
    def _get_service(self, uuid16: int) -> str:
        return SERVICE_UUIDS.get(uuid16, f"0x{uuid16:04X}")
    
    def _guess_type(self, dev: ParsedAdv) -> str:
        name = (dev.name or "").lower()
        
        patterns = {
            "Phone": ["phone", "iphone", "galaxy", "pixel"],
            "Watch/Band": ["watch", "band", "fit", "mi band"],
            "Headphones": ["airpod", "buds", "headphone", "bose", "jabra"],
            "Speaker": ["speaker", "echo", "homepod", "soundbar"],
            "Tracker": ["tile", "airtag", "tag", "beacon"],
            "Smart Lock": ["lock", "sesame", "august", "schlage"],
            "Smart Bulb": ["bulb", "light", "hue", "lifx"],
            "Camera": ["camera", "cam", "ring", "wyze"],
            "Keyboard": ["keyboard"],
            "Mouse": ["mouse"],
        }
        
        for dtype, kws in patterns.items():
            if any(k in name for k in kws):
                return dtype
        
        if dev.mfg_id == 0x004C:
            return "Apple Device"
        if dev.mfg_id == 0x0075:
            return "Samsung Device"
        if dev.mfg_id in [0x015D, 0x0131]:
            return "Xiaomi Device"
        if dev.mfg_id == 0x038F:
            return "Tile Tracker"
        
        for svc in dev.services:
            if svc.get("uuid_int") == 0x1812:
                return "HID Device"
            if svc.get("uuid_int") == 0x180D:
                return "Heart Rate"
        
        return "BLE Device"
    
    def _assess_security(self, dev: ParsedAdv) -> List[str]:
        notes = []
        
        if dev.mfg_id == 0x004C and dev.mfg_data:
            if len(dev.mfg_data) >= 2:
                t = dev.mfg_data[0]
                if t == 0x02:
                    notes.append("iBeacon detected")
                elif t == 0x12:
                    notes.append("Apple FindMy/AirTag")
                elif t == 0x07:
                    notes.append("AirPods detected")
        
        if dev.mfg_id in [0x015D, 0x0131]:
            notes.append("Xiaomi - check unauth GATT")
        
        for svc in dev.services:
            if svc.get("uuid_int") == 0x1812:
                notes.append("HID service - keystroke injection risk")
            if svc.get("uuid_int") in [0xFFE0, 0xFFF0, 0xFFD0]:
                notes.append("Custom IoT service - likely weak security")
        
        if not dev.name:
            notes.append("No name advertised")
        
        return notes
    
    def _parse_adv(self, device: BLEDevice, adv: AdvertisementData) -> ParsedAdv:
        # Basic info
        address = device.address
        name = adv.local_name or device.name or ""
        rssi = adv.rssi if hasattr(adv, 'rssi') else -100
        tx_power = adv.tx_power
        
        # Manufacturer data
        mfg_id = None
        mfg_name = ""
        mfg_data = b""
        if adv.manufacturer_data:
            for mid, mdata in adv.manufacturer_data.items():
                mfg_id = mid
                mfg_name = self._get_company(mid)
                mfg_data = bytes(mdata)
                break
        
        # Services
        services = []
        services_128 = []
        if adv.service_uuids:
            for uuid_str in adv.service_uuids:
                uuid_str = uuid_str.lower()
                if uuid_str.endswith("-0000-1000-8000-00805f9b34fb"):
                    try:
                        uuid16 = int(uuid_str[4:8], 16)
                        services.append({
                            "uuid": f"0x{uuid16:04X}",
                            "uuid_int": uuid16,
                            "name": self._get_service(uuid16)
                        })
                    except:
                        services_128.append(uuid_str)
                else:
                    services_128.append(uuid_str)
        
        # Service data
        service_data = {}
        if adv.service_data:
            for svc_uuid, svc_bytes in adv.service_data.items():
                service_data[svc_uuid] = bytes(svc_bytes)
        
        # Determine address type
        first_byte = int(address.split(":")[0], 16)
        addr_type = "random" if (first_byte & 0xC0) in [0x40, 0xC0] else "public"
        
        dev = ParsedAdv(
            address=address, address_type=addr_type, name=name, rssi=rssi,
            tx_power=tx_power, mfg_id=mfg_id, mfg_name=mfg_name, mfg_data=mfg_data,
            services=services, services_128=services_128, service_data=service_data,
            device_type="", sec_notes=[]
        )
        
        dev.device_type = self._guess_type(dev)
        dev.sec_notes = self._assess_security(dev)
        
        return dev
    
    async def _scan_async(self) -> List[ParsedAdv]:
        timeout = int(self.get_option("timeout"))
        target = self.get_option("target")
        name_filter = self.get_option("filter_name")
        
        found: Dict[str, ParsedAdv] = {}
        
        def callback(device: BLEDevice, adv: AdvertisementData):
            if target and device.address.upper() != target.upper():
                return
            if name_filter:
                n = adv.local_name or device.name or ""
                if name_filter.lower() not in n.lower():
                    return
            
            parsed = self._parse_adv(device, adv)
            addr = device.address.upper()
            if addr not in found or parsed.rssi > found[addr].rssi:
                found[addr] = parsed
        
        print_info(f"Scanning for {timeout} seconds...")
        
        scanner = BleakScanner(detection_callback=callback)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        
        return list(found.values())
    
    def _print_table(self, devices: List[ParsedAdv]) -> None:
        C = Colors
        
        if not devices:
            print_warning("No devices found")
            return
        
        devices.sort(key=lambda x: x.rssi, reverse=True)
        show_raw = self.get_option("show_raw")
        
        # Header
        print(f"\n  {C.CYAN}{'='*115}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}BLE ADVERTISEMENT ANALYSIS{C.RESET}")
        print(f"  {C.CYAN}{'='*115}{C.RESET}")
        print(f"  Devices Found: {C.WHITE}{len(devices)}{C.RESET}\n")
        
        # Devices table
        print(f"  {C.BOLD}DISCOVERED DEVICES{C.RESET}\n")
        print(f"  {C.DARK_GREY}+-----+-------------------+------------------------+------+--------+--------------------+------------------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<3}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'ADDRESS':<17}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'NAME':<22}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'RSSI':<4}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'TX PWR':<6}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'MANUFACTURER':<18}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'TYPE':<16}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+-----+-------------------+------------------------+------+--------+--------------------+------------------+{C.RESET}")
        
        for idx, d in enumerate(devices, 1):
            name = (d.name[:20] + "..") if len(d.name) > 22 else d.name if d.name else "-"
            mfg = (d.mfg_name[:16] + "..") if len(d.mfg_name) > 18 else d.mfg_name if d.mfg_name else "-"
            dtype = (d.device_type[:14] + "..") if len(d.device_type) > 16 else d.device_type
            tx = str(d.tx_power) if d.tx_power else "-"
            
            rc = C.GREEN if d.rssi > -50 else C.YELLOW if d.rssi > -70 else C.RED
            
            print(f"  {C.DARK_GREY}|{C.RESET} {idx:<3} {C.DARK_GREY}|{C.RESET} {C.CYAN}{d.address:<17}{C.RESET} {C.DARK_GREY}|{C.RESET} {name:<22} {C.DARK_GREY}|{C.RESET} {rc}{d.rssi:<4}{C.RESET} {C.DARK_GREY}|{C.RESET} {tx:<6} {C.DARK_GREY}|{C.RESET} {mfg:<18} {C.DARK_GREY}|{C.RESET} {dtype:<16} {C.DARK_GREY}|{C.RESET}")
        
        print(f"  {C.DARK_GREY}+-----+-------------------+------------------------+------+--------+--------------------+------------------+{C.RESET}")
        
        # Detailed analysis
        print(f"\n  {C.BOLD}DETAILED ANALYSIS{C.RESET}\n")
        
        for idx, d in enumerate(devices, 1):
            print(f"  {C.CYAN}[{idx}] {d.address} - {d.name or 'Unknown'}{C.RESET}")
            print(f"  {C.DARK_GREY}{'─'*80}{C.RESET}")
            
            print(f"      Address Type  : {d.address_type}")
            print(f"      RSSI          : {d.rssi} dBm")
            if d.tx_power:
                print(f"      Tx Power      : {d.tx_power} dBm")
            print(f"      Device Type   : {d.device_type}")
            
            if d.mfg_name:
                print(f"      Manufacturer  : {d.mfg_name}" + (f" (0x{d.mfg_id:04X})" if d.mfg_id else ""))
            
            if d.mfg_data and show_raw:
                hex_data = d.mfg_data.hex()
                print(f"      Mfg Data      : {hex_data[:50]}{'...' if len(hex_data) > 50 else ''}")
            
            if d.services:
                print(f"      Services:")
                for svc in d.services:
                    print(f"        - {svc['name']} ({svc['uuid']})")
            
            if d.services_128:
                print(f"      Services (128-bit):")
                for uuid in d.services_128[:3]:
                    print(f"        - {uuid}")
                if len(d.services_128) > 3:
                    print(f"        ... +{len(d.services_128) - 3} more")
            
            if d.service_data and show_raw:
                print(f"      Service Data:")
                for svc_uuid, data in list(d.service_data.items())[:2]:
                    print(f"        - {svc_uuid}: {data.hex()[:30]}...")
            
            if d.sec_notes:
                print(f"      {C.YELLOW}Security Notes:{C.RESET}")
                for note in d.sec_notes:
                    print(f"        {C.YELLOW}!{C.RESET} {note}")
            
            print()
        
        # Statistics
        print(f"  {C.CYAN}{'-'*115}{C.RESET}")
        print(f"  {C.BOLD}STATISTICS{C.RESET}")
        print(f"  {C.CYAN}{'-'*115}{C.RESET}")
        
        # By type
        types = {}
        for d in devices:
            types[d.device_type] = types.get(d.device_type, 0) + 1
        print(f"  By Type: " + "  ".join([f"{t}: {c}" for t, c in sorted(types.items(), key=lambda x: -x[1])[:6]]))
        
        # By manufacturer
        mfgs = {}
        for d in devices:
            m = d.mfg_name or "Unknown"
            mfgs[m] = mfgs.get(m, 0) + 1
        print(f"  By Mfg:  " + "  ".join([f"{m}: {c}" for m, c in sorted(mfgs.items(), key=lambda x: -x[1])[:6]]))
        
        # Interesting targets
        interesting = [d for d in devices if d.sec_notes]
        if interesting:
            print(f"\n  {C.YELLOW}INTERESTING TARGETS:{C.RESET}")
            for d in interesting[:5]:
                print(f"    {C.YELLOW}>{C.RESET} {d.address} - {d.name or d.device_type}")
        
        print(f"\n  {C.CYAN}{'='*115}{C.RESET}\n")
    
    def _save_results(self, devices: List[ParsedAdv], filename: str) -> None:
        import json
        output = {"device_count": len(devices), "devices": []}
        for d in devices:
            output["devices"].append({
                "address": d.address, "address_type": d.address_type, "name": d.name,
                "rssi": d.rssi, "tx_power": d.tx_power, "manufacturer_id": d.mfg_id,
                "manufacturer_name": d.mfg_name,
                "manufacturer_data": d.mfg_data.hex() if d.mfg_data else None,
                "services": d.services, "services_128": d.services_128,
                "device_type": d.device_type, "security_notes": d.sec_notes
            })
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")
    
    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False
        
        try:
            devices = asyncio.run(self._scan_async())
            if not devices:
                print_warning("No devices found")
                return False
            
            print_success(f"Found {len(devices)} device(s)")
            self._print_table(devices)
            
            out = self.get_option("output_file")
            if out:
                self._save_results(devices, out)
            
            return True
        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False
