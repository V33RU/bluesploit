"""
BlueSploit Module: SDP Service Enumerator
Advanced SDP (Service Discovery Protocol) enumeration for Bluetooth Classic devices
Uses sdptool from BlueZ stack

Author: v33ru
"""

import subprocess
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)


# Well-known SDP Service Class UUIDs (16-bit)
KNOWN_SERVICES = {
    "0x1000": "Service Discovery Server",
    "0x1001": "Browse Group Descriptor",
    "0x1002": "Public Browse Root",
    "0x1101": "Serial Port (SPP)",
    "0x1102": "LAN Access Using PPP",
    "0x1103": "Dialup Networking (DUN)",
    "0x1104": "IrMC Sync",
    "0x1105": "OBEX Object Push (OPP)",
    "0x1106": "OBEX File Transfer (FTP)",
    "0x1107": "IrMC Sync Command",
    "0x1108": "Headset",
    "0x1109": "Cordless Telephony",
    "0x110a": "Audio Source",
    "0x110b": "Audio Sink",
    "0x110c": "A/V Remote Control Target",
    "0x110d": "Advanced Audio Distribution (A2DP)",
    "0x110e": "A/V Remote Control",
    "0x110f": "A/V Remote Control Controller",
    "0x1110": "Intercom",
    "0x1111": "Fax",
    "0x1112": "Headset Audio Gateway",
    "0x1113": "WAP",
    "0x1114": "WAP Client",
    "0x1115": "PANU",
    "0x1116": "NAP",
    "0x1117": "GN",
    "0x1118": "Direct Printing",
    "0x1119": "Reference Printing",
    "0x111a": "Basic Imaging Profile",
    "0x111b": "Imaging Responder",
    "0x111c": "Imaging Automatic Archive",
    "0x111d": "Imaging Referenced Objects",
    "0x111e": "Handsfree",
    "0x111f": "Handsfree Audio Gateway",
    "0x1120": "Direct Printing Reference",
    "0x1121": "Reflected UI",
    "0x1122": "Basic Printing",
    "0x1123": "Printing Status",
    "0x1124": "Human Interface Device (HID)",
    "0x1125": "Hardcopy Cable Replacement",
    "0x1126": "HCR Print",
    "0x1127": "HCR Scan",
    "0x1128": "Common ISDN Access",
    "0x112d": "SIM Access",
    "0x112e": "Phonebook Access PCE",
    "0x112f": "Phonebook Access PSE",
    "0x1130": "Phonebook Access",
    "0x1131": "Headset HS",
    "0x1132": "Message Access Server",
    "0x1133": "Message Notification Server",
    "0x1134": "Message Access Profile",
    "0x1135": "GNSS",
    "0x1136": "GNSS Server",
    "0x1137": "3D Display",
    "0x1138": "3D Glasses",
    "0x1139": "3D Synchronization",
    "0x113a": "MPS Profile",
    "0x113b": "MPS SC",
    "0x1200": "PnP Information",
    "0x1201": "Generic Networking",
    "0x1202": "Generic File Transfer",
    "0x1203": "Generic Audio",
    "0x1204": "Generic Telephony",
    "0x1205": "UPNP Service",
    "0x1206": "UPNP IP Service",
    "0x1300": "ESDP UPNP IP PAN",
    "0x1301": "ESDP UPNP IP LAP",
    "0x1302": "ESDP UPNP L2CAP",
    "0x1303": "Video Source",
    "0x1304": "Video Sink",
    "0x1305": "Video Distribution",
    "0x1400": "HDP",
    "0x1401": "HDP Source",
    "0x1402": "HDP Sink",
}

# Protocol UUIDs
KNOWN_PROTOCOLS = {
    "0x0001": "SDP",
    "0x0002": "UDP",
    "0x0003": "RFCOMM",
    "0x0004": "TCP",
    "0x0005": "TCS-BIN",
    "0x0006": "TCS-AT",
    "0x0007": "ATT",
    "0x0008": "OBEX",
    "0x0009": "IP",
    "0x000a": "FTP",
    "0x000c": "HTTP",
    "0x000e": "WSP",
    "0x000f": "BNEP",
    "0x0010": "UPNP",
    "0x0011": "HIDP",
    "0x0012": "HCRP-CTRL",
    "0x0014": "HCRP-DATA",
    "0x0016": "HCRP-NOTE",
    "0x0017": "AVCTP",
    "0x0019": "AVDTP",
    "0x001b": "CMTP",
    "0x001e": "MCAP-CTRL",
    "0x001f": "MCAP-DATA",
    "0x0100": "L2CAP",
}


@dataclass
class SDPService:
    """Represents a discovered SDP service"""
    name: str
    service_classes: List[str]
    protocols: List[Dict[str, Any]]
    profiles: List[Dict[str, str]]
    provider: str
    description: str
    record_handle: str
    channel: Optional[int]
    psm: Optional[int]
    raw_record: str


class Module(ScannerModule):
    """
    SDP Service Enumerator
    
    Advanced enumeration of Bluetooth Classic services using sdptool.
    Supports multiple browse modes, service search, and detailed output.
    """
    
    info = ModuleInfo(
        name="scanners/classic/sdp_enum",
        description="Enumerate SDP services on Bluetooth Classic devices",
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/",
            "https://www.bluez.org/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "mode": ModuleOption(
                name="mode",
                required=False,
                description="Browse mode: browse, records, tree",
                default="browse"
            ),
            "search": ModuleOption(
                name="search",
                required=False,
                description="Search specific service (e.g., SP, DUN, FAX, OPP, FTP, HS, HF, NAP, GN)",
                default=None
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Command timeout in seconds",
                default=30
            ),
            "xml_output": ModuleOption(
                name="xml_output",
                required=False,
                description="Get raw XML output",
                default=False
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to JSON file",
                default=None
            )
        }
    
    def _check_sdptool(self) -> bool:
        """Check if sdptool is available"""
        try:
            result = subprocess.run(
                ["which", "sdptool"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _get_service_name(self, uuid: str) -> str:
        """Get human-readable service name from UUID"""
        uuid_upper = uuid.upper()
        if not uuid_upper.startswith("0X"):
            uuid_upper = "0x" + uuid_upper
        uuid_lower = uuid_upper.lower()
        return KNOWN_SERVICES.get(uuid_lower, f"Unknown ({uuid})")
    
    def _get_protocol_name(self, uuid: str) -> str:
        """Get protocol name from UUID"""
        uuid_lower = uuid.lower()
        if not uuid_lower.startswith("0x"):
            uuid_lower = "0x" + uuid_lower
        return KNOWN_PROTOCOLS.get(uuid_lower, uuid)
    
    def _run_sdptool(self, args: List[str], timeout: int) -> Optional[str]:
        """Run sdptool command and return output"""
        try:
            cmd = ["sdptool"] + args
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode != 0 and result.stderr:
                print_warning(f"sdptool warning: {result.stderr.strip()}")
            return result.stdout
        except subprocess.TimeoutExpired:
            print_error(f"Command timed out after {timeout}s")
            return None
        except Exception as e:
            print_error(f"sdptool error: {e}")
            return None
    
    def _parse_browse_output(self, output: str) -> List[SDPService]:
        """Parse sdptool browse output into structured data"""
        services = []
        current_service = None
        current_section = None
        raw_record = []
        
        lines = output.split('\n')
        
        for line in lines:
            # New service record
            if line.startswith("Service Name:"):
                if current_service:
                    current_service["raw"] = '\n'.join(raw_record)
                    services.append(current_service)
                    raw_record = []
                
                current_service = {
                    "name": line.split(":", 1)[1].strip(),
                    "service_classes": [],
                    "protocols": [],
                    "profiles": [],
                    "provider": "",
                    "description": "",
                    "record_handle": "",
                    "channel": None,
                    "psm": None,
                }
                current_section = None
            
            elif current_service is not None:
                raw_record.append(line)
                
                if line.startswith("Service RecHandle:"):
                    current_service["record_handle"] = line.split(":", 1)[1].strip()
                
                elif line.startswith("Service Provider:"):
                    current_service["provider"] = line.split(":", 1)[1].strip()
                
                elif line.startswith("Service Description:"):
                    current_service["description"] = line.split(":", 1)[1].strip()
                
                elif "Service Class ID List:" in line:
                    current_section = "classes"
                
                elif "Protocol Descriptor List:" in line:
                    current_section = "protocols"
                
                elif "Profile Descriptor List:" in line:
                    current_section = "profiles"
                
                elif "Language Base Attr List:" in line:
                    current_section = None
                
                elif current_section == "classes" and '"' in line:
                    # Extract service class UUID
                    match = re.search(r'"([^"]+)".*\((0x[0-9a-fA-F]+)\)', line)
                    if match:
                        current_service["service_classes"].append({
                            "name": match.group(1),
                            "uuid": match.group(2)
                        })
                    else:
                        # Try alternative format
                        match = re.search(r'UUID:\s*(0x[0-9a-fA-F]+)', line)
                        if match:
                            uuid = match.group(1)
                            current_service["service_classes"].append({
                                "name": self._get_service_name(uuid),
                                "uuid": uuid
                            })
                
                elif current_section == "protocols":
                    # Extract protocol info
                    if '"' in line or 'UUID' in line:
                        proto_match = re.search(r'"([^"]+)".*\((0x[0-9a-fA-F]+)\)', line)
                        if proto_match:
                            proto = {
                                "name": proto_match.group(1),
                                "uuid": proto_match.group(2)
                            }
                            current_service["protocols"].append(proto)
                    
                    # Extract channel number
                    channel_match = re.search(r'Channel:\s*(\d+)', line)
                    if channel_match:
                        current_service["channel"] = int(channel_match.group(1))
                    
                    # Extract PSM
                    psm_match = re.search(r'PSM:\s*(\d+)', line)
                    if psm_match:
                        current_service["psm"] = int(psm_match.group(1))
                
                elif current_section == "profiles":
                    # Extract profile info
                    profile_match = re.search(r'"([^"]+)".*\((0x[0-9a-fA-F]+)\).*Version:\s*(0x[0-9a-fA-F]+)', line)
                    if profile_match:
                        current_service["profiles"].append({
                            "name": profile_match.group(1),
                            "uuid": profile_match.group(2),
                            "version": profile_match.group(3)
                        })
        
        # Don't forget the last service
        if current_service:
            current_service["raw"] = '\n'.join(raw_record)
            services.append(current_service)
        
        return services
    
    def _browse_services(self, target: str, timeout: int) -> List[SDPService]:
        """Browse all SDP services on target"""
        print_info(f"Browsing SDP services on {target}...")
        
        output = self._run_sdptool(["browse", target], timeout)
        if not output:
            return []
        
        return self._parse_browse_output(output)
    
    def _search_service(self, target: str, service: str, timeout: int) -> List[SDPService]:
        """Search for specific service on target"""
        print_info(f"Searching for {service} service on {target}...")
        
        output = self._run_sdptool(["search", "--bdaddr", target, service], timeout)
        if not output:
            return []
        
        return self._parse_browse_output(output)
    
    def _get_records(self, target: str, timeout: int) -> str:
        """Get all service records"""
        print_info(f"Getting service records from {target}...")
        
        output = self._run_sdptool(["records", target], timeout)
        return output or ""
    
    def _get_tree(self, target: str, timeout: int) -> str:
        """Get service tree view"""
        print_info(f"Getting service tree from {target}...")
        
        output = self._run_sdptool(["browse", "--tree", target], timeout)
        return output or ""
    
    def _get_xml(self, target: str, timeout: int) -> str:
        """Get XML output"""
        print_info(f"Getting XML records from {target}...")
        
        output = self._run_sdptool(["browse", "--xml", target], timeout)
        return output or ""
    
    def _print_results_table(self, services: List[Dict], target: str) -> None:
        """Print enumeration results in table format"""
        C = Colors
        
        if not services:
            print_warning("No services found")
            return
        
        # ========== HEADER ==========
        print(f"\n  {C.CYAN}{'='*110}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}SDP SERVICE ENUMERATION RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*110}{C.RESET}")
        print(f"  Target: {C.WHITE}{target}{C.RESET}")
        print(f"  Services Found: {C.WHITE}{len(services)}{C.RESET}\n")
        
        # ========== SERVICES TABLE ==========
        print(f"  {C.BOLD}DISCOVERED SERVICES{C.RESET}\n")
        print(f"  {C.DARK_GREY}+-----+--------------------------------+--------------------+----------+---------+------------------+{C.RESET}")
        print(f"  {C.DARK_GREY}|{C.RESET} {C.BOLD}{'#':<3}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'SERVICE NAME':<30}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'CLASS UUID':<18}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'CHANNEL':<8}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'PSM':<7}{C.RESET} {C.DARK_GREY}|{C.RESET} {C.BOLD}{'PROTOCOL':<16}{C.RESET} {C.DARK_GREY}|{C.RESET}")
        print(f"  {C.DARK_GREY}+-----+--------------------------------+--------------------+----------+---------+------------------+{C.RESET}")
        
        for idx, svc in enumerate(services, 1):
            name = svc["name"][:30] if svc["name"] else "Unknown"
            
            # Get primary class UUID
            class_uuid = "-"
            if svc["service_classes"]:
                class_uuid = svc["service_classes"][0].get("uuid", "-")[:18]
            
            # Channel and PSM
            channel = str(svc["channel"]) if svc["channel"] else "-"
            psm = str(svc["psm"]) if svc["psm"] else "-"
            
            # Primary protocol
            protocol = "-"
            if svc["protocols"]:
                protocol = svc["protocols"][0].get("name", "-")[:16]
            
            # Color code based on service type
            if "serial" in name.lower() or "spp" in name.lower() or svc["channel"]:
                name_color = C.YELLOW
            elif "obex" in name.lower() or "ftp" in name.lower() or "opp" in name.lower():
                name_color = C.GREEN
            elif "audio" in name.lower() or "a2dp" in name.lower():
                name_color = C.MAGENTA
            elif "hid" in name.lower() or "keyboard" in name.lower() or "mouse" in name.lower():
                name_color = C.RED
            else:
                name_color = C.CYAN
            
            print(f"  {C.DARK_GREY}|{C.RESET} {idx:<3} {C.DARK_GREY}|{C.RESET} {name_color}{name:<30}{C.RESET} {C.DARK_GREY}|{C.RESET} {class_uuid:<18} {C.DARK_GREY}|{C.RESET} {channel:<8} {C.DARK_GREY}|{C.RESET} {psm:<7} {C.DARK_GREY}|{C.RESET} {protocol:<16} {C.DARK_GREY}|{C.RESET}")
        
        print(f"  {C.DARK_GREY}+-----+--------------------------------+--------------------+----------+---------+------------------+{C.RESET}")
        
        # ========== DETAILED SERVICE INFO ==========
        print(f"\n  {C.BOLD}SERVICE DETAILS{C.RESET}\n")
        
        for idx, svc in enumerate(services, 1):
            name = svc["name"] if svc["name"] else "Unknown Service"
            
            print(f"  {C.CYAN}[{idx}] {name}{C.RESET}")
            print(f"  {C.DARK_GREY}{'─'*70}{C.RESET}")
            
            # Record handle
            if svc["record_handle"]:
                print(f"      Record Handle : {svc['record_handle']}")
            
            # Provider
            if svc["provider"]:
                print(f"      Provider      : {svc['provider']}")
            
            # Description
            if svc["description"]:
                print(f"      Description   : {svc['description']}")
            
            # Service Classes
            if svc["service_classes"]:
                print(f"      Service Classes:")
                for sc in svc["service_classes"]:
                    print(f"        - {sc.get('name', 'Unknown')} ({sc.get('uuid', '-')})")
            
            # Protocols
            if svc["protocols"]:
                print(f"      Protocols:")
                for proto in svc["protocols"]:
                    print(f"        - {proto.get('name', 'Unknown')} ({proto.get('uuid', '-')})")
            
            # Channel/PSM
            if svc["channel"]:
                print(f"      {C.YELLOW}RFCOMM Channel : {svc['channel']}{C.RESET}")
            if svc["psm"]:
                print(f"      {C.YELLOW}L2CAP PSM      : {svc['psm']}{C.RESET}")
            
            # Profiles
            if svc["profiles"]:
                print(f"      Profiles:")
                for prof in svc["profiles"]:
                    ver = prof.get('version', '-')
                    print(f"        - {prof.get('name', 'Unknown')} v{ver}")
            
            print()
        
        # ========== ATTACK SURFACE ==========
        rfcomm_services = [s for s in services if s["channel"]]
        obex_services = [s for s in services if any("obex" in p.get("name", "").lower() for p in s["protocols"])]
        hid_services = [s for s in services if any("hid" in c.get("name", "").lower() for c in s["service_classes"])]
        
        print(f"  {C.CYAN}{'-'*110}{C.RESET}")
        print(f"  {C.BOLD}ATTACK SURFACE ANALYSIS{C.RESET}")
        print(f"  {C.CYAN}{'-'*110}{C.RESET}")
        
        if rfcomm_services:
            print(f"\n  {C.YELLOW}RFCOMM Services (potential serial access):{C.RESET}")
            for svc in rfcomm_services:
                print(f"    {C.YELLOW}>{C.RESET} {svc['name']} - Channel {svc['channel']}")
        
        if obex_services:
            print(f"\n  {C.GREEN}OBEX Services (file transfer):{C.RESET}")
            for svc in obex_services:
                print(f"    {C.GREEN}>{C.RESET} {svc['name']}")
        
        if hid_services:
            print(f"\n  {C.RED}HID Services (input devices - HIGH RISK):{C.RESET}")
            for svc in hid_services:
                print(f"    {C.RED}>{C.RESET} {svc['name']}")
        
        # ========== SUMMARY ==========
        print(f"\n  {C.CYAN}{'-'*110}{C.RESET}")
        print(f"  {C.BOLD}SUMMARY{C.RESET}")
        print(f"  {C.CYAN}{'-'*110}{C.RESET}")
        print(f"  Total Services: {len(services)}   RFCOMM: {len(rfcomm_services)}   OBEX: {len(obex_services)}   HID: {len(hid_services)}")
        
        # Quick exploitation hints
        if rfcomm_services:
            print(f"\n  {C.DARK_GREY}Hint: Try 'rfcomm connect' to channel {rfcomm_services[0]['channel']} for serial access{C.RESET}")
        if obex_services:
            print(f"  {C.DARK_GREY}Hint: Try 'obexftp' or 'ussp-push' for file operations{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*110}{C.RESET}\n")
    
    def _save_results(self, results: Dict[str, Any], filename: str) -> None:
        """Save results to JSON file"""
        import json
        try:
            # Convert to serializable format
            output = {
                "target": results["target"],
                "service_count": len(results["services"]),
                "services": []
            }
            
            for svc in results["services"]:
                output["services"].append({
                    "name": svc["name"],
                    "record_handle": svc["record_handle"],
                    "provider": svc["provider"],
                    "description": svc["description"],
                    "channel": svc["channel"],
                    "psm": svc["psm"],
                    "service_classes": svc["service_classes"],
                    "protocols": svc["protocols"],
                    "profiles": svc["profiles"]
                })
            
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            print_success(f"Saved: {filename}")
        except Exception as e:
            print_error(f"Save failed: {e}")
    
    def run(self) -> bool:
        """Execute SDP enumeration"""
        
        # Check sdptool availability
        if not self._check_sdptool():
            print_error("sdptool not found!")
            print_info("Install BlueZ: sudo apt install bluez")
            return False
        
        target = self.target
        mode = self.get_option("mode")
        search = self.get_option("search")
        timeout = int(self.get_option("timeout"))
        xml_output = self.get_option("xml_output")
        output_file = self.get_option("output_file")
        
        # Validate BD_ADDR
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        print_info(f"SDP Enumeration - Target: {target}")
        print_info(f"Mode: {mode}\n")
        
        services = []
        
        try:
            # Handle different modes
            if search:
                # Search specific service
                services = self._search_service(target, search, timeout)
            elif mode == "browse":
                # Standard browse
                services = self._browse_services(target, timeout)
            elif mode == "records":
                # Get raw records
                output = self._get_records(target, timeout)
                if output:
                    print(output)
                return bool(output)
            elif mode == "tree":
                # Get tree view
                output = self._get_tree(target, timeout)
                if output:
                    print(output)
                return bool(output)
            
            # XML output if requested
            if xml_output:
                xml = self._get_xml(target, timeout)
                if xml:
                    print_info("XML Output:")
                    print(xml)
            
            if not services:
                print_warning("No SDP services found")
                print_info("Device may be out of range or not discoverable")
                return False
            
            print_success(f"Found {len(services)} service(s)")
            
            # Store results
            results = {
                "target": target,
                "services": services
            }
            self.add_result(results)
            
            # Print table output
            self._print_results_table(services, target)
            
            # Save if requested
            if output_file:
                self._save_results(results, output_file)
            
            # Add discovered services as targets
            for svc in services:
                self.add_device(Target(
                    address=target,
                    name=svc["name"],
                    device_type="Bluetooth Classic",
                    metadata={
                        "channel": svc["channel"],
                        "psm": svc["psm"],
                        "service_classes": svc["service_classes"]
                    }
                ))
            
            return True
            
        except KeyboardInterrupt:
            print_warning("\nInterrupted")
            return False
        except Exception as e:
            print_error(f"Enumeration failed: {e}")
            return False
