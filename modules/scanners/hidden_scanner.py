"""
BlueSploit Module: Hidden Device Scanner
Find Non-Discoverable Bluetooth Devices

Detects Bluetooth devices that have disabled discovery mode
using various techniques including direct connection attempts,
name requests, and BD_ADDR brute-forcing.

Author: v33ru
"""

import subprocess
import time
import threading
import random
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


# Common OUI prefixes for Bluetooth devices
COMMON_OUIS = [
    # Apple
    "00:03:93", "00:0A:27", "00:0A:95", "00:11:24", "00:14:51",
    "00:16:CB", "00:17:F2", "00:19:E3", "00:1B:63", "00:1C:B3",
    "00:1D:4F", "00:1E:52", "00:1F:5B", "00:21:E9", "00:22:41",
    "00:23:12", "00:23:6C", "00:24:36", "00:25:00", "00:25:BC",
    "00:26:08", "00:26:BB", "28:CF:DA", "34:C0:59", "38:C9:86",
    "40:33:1A", "44:D8:84", "48:A1:95", "4C:57:CA", "50:7A:55",
    "54:4E:90", "5C:F9:38", "60:C5:47", "64:A3:CB", "68:5B:35",
    "6C:4D:73", "70:DE:E2", "74:E1:B6", "78:31:C1", "7C:D1:C3",
    "80:E6:50", "84:78:8B", "88:66:A5", "8C:85:90", "90:84:0D",
    
    # Samsung  
    "00:00:F0", "00:07:AB", "00:12:47", "00:15:99", "00:16:32",
    "00:17:C9", "00:18:AF", "00:1A:8A", "00:1D:25", "00:1E:E2",
    "00:21:19", "00:23:39", "00:24:54", "00:25:66", "00:26:37",
    "08:37:3D", "10:D5:42", "14:49:E0", "18:3A:2D", "1C:62:B8",
    "20:13:E0", "24:4B:81", "28:CC:01", "2C:AE:2B", "30:96:FB",
    "34:23:BA", "38:01:95", "3C:5A:37", "40:0E:85", "44:4E:1A",
    
    # Xiaomi
    "04:CF:8C", "0C:1D:AF", "10:2A:B3", "14:F6:5A", "18:59:36",
    "20:34:FB", "28:6C:07", "34:80:B3", "38:A4:ED", "3C:BD:3E",
    "50:64:2B", "58:44:98", "64:09:80", "64:B4:73", "68:DF:DD",
    "74:23:44", "7C:1C:4E", "84:F3:EB", "8C:BE:BE", "98:FA:E3",
    
    # Google
    "00:1A:11", "3C:5A:B4", "54:60:09", "94:EB:2C", "F4:F5:D8",
    
    # Intel
    "00:02:B3", "00:03:47", "00:0C:F1", "00:13:02", "00:15:00",
    "00:16:6F", "00:16:EA", "00:18:DE", "00:19:D1", "00:1B:21",
    "00:1C:BF", "00:1D:E0", "00:1E:64", "00:1F:3B", "00:21:5C",
    
    # Broadcom
    "00:03:19", "00:10:18", "00:1A:2B", "00:23:76", "00:24:D7",
    "00:25:56", "00:27:19", "20:16:D8", "34:BB:26", "40:F4:09",
    
    # CSR/Qualcomm
    "00:02:5B", "00:02:72", "00:11:67", "00:13:04", "00:19:63",
    "00:1A:7D", "00:1B:DC", "00:1E:A4", "00:23:3D", "00:24:03",
    
    # Espressif (ESP32)
    "24:0A:C4", "24:62:AB", "30:AE:A4", "3C:71:BF", "5C:CF:7F",
    "84:CC:A8", "A4:CF:12", "CC:50:E3", "EC:FA:BC",
]


class Module(ScannerModule):
    """
    Hidden Device Scanner
    
    Detects non-discoverable Bluetooth devices using:
    
    1. Direct Name Requests
       - Send HCI_Remote_Name_Request to target BD_ADDR
       - Works even if device is non-discoverable
    
    2. Direct Connection Attempts
       - Try to connect to common services (SDP, RFCOMM)
       - Connection refusal still confirms device exists
    
    3. OUI-Based Discovery
       - Scan specific manufacturer ranges
       - Target common Bluetooth chip vendors
    
    4. Sequential Scanning
       - Scan a range around known addresses
       - Find multiple devices in same location
    
    5. Ping Sweep
       - L2CAP ping to check device presence
    """
    
    info = ModuleInfo(
        name="scanners/hidden_scanner",
        description="Find Non-Discoverable Bluetooth Devices",
        author=["v33ru"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=False,
                description="Specific BD_ADDR or OUI prefix to scan",
                default=None
            ),
            "mode": ModuleOption(
                name="mode",
                required=False,
                description="Mode: name_req, connect, oui, range, or all",
                default="name_req"
            ),
            "oui": ModuleOption(
                name="oui",
                required=False,
                description="Specific OUI to scan (XX:XX:XX)",
                default=None
            ),
            "range_start": ModuleOption(
                name="range_start",
                required=False,
                description="Start of range (last 3 bytes, e.g., 00:00:00)",
                default="00:00:00"
            ),
            "range_count": ModuleOption(
                name="range_count",
                required=False,
                description="Number of addresses to scan in range",
                default=256
            ),
            "threads": ModuleOption(
                name="threads",
                required=False,
                description="Number of concurrent threads",
                default=10
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Timeout per device in seconds",
                default=5
            )
        }
    
    def _name_request(self, target: str, timeout: int) -> Tuple[bool, Optional[str]]:
        """Send name request to device"""
        try:
            result = subprocess.run(
                ["hcitool", "name", target],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return True, result.stdout.strip()
            return False, None
            
        except subprocess.TimeoutExpired:
            return False, None
        except Exception:
            return False, None
    
    def _try_connect(self, target: str, timeout: int) -> Tuple[bool, str]:
        """Try to connect to device"""
        if not BLUETOOTH_AVAILABLE:
            return False, "PyBluez not available"
        
        try:
            # Try SDP connection
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(timeout)
            
            try:
                sock.connect((target, 1))  # SDP PSM
                sock.close()
                return True, "SDP connection successful"
            except Exception as e:
                err = str(e).lower()
                if "connection refused" in err:
                    return True, "Connection refused (device exists)"
                elif "host is down" in err:
                    return False, "Host down"
                elif "no route" in err:
                    return False, "No route"
                else:
                    return False, str(e)
                    
        except Exception as e:
            return False, str(e)
    
    def _l2ping(self, target: str, timeout: int) -> bool:
        """L2CAP ping device"""
        try:
            result = subprocess.run(
                ["l2ping", "-c", "1", "-t", str(timeout), target],
                capture_output=True,
                text=True,
                timeout=timeout + 2
            )
            return result.returncode == 0
        except:
            return False
    
    def _scan_worker(self, addresses: List[str], mode: str, timeout: int,
                     results: Dict, lock: threading.Lock,
                     progress: Dict) -> None:
        """Worker thread for scanning"""
        for addr in addresses:
            found = False
            name = None
            method = ""
            
            if mode in ["name_req", "all"]:
                found, name = self._name_request(addr, timeout)
                if found:
                    method = "name_request"
            
            if not found and mode in ["connect", "all"]:
                found, reason = self._try_connect(addr, timeout)
                if found:
                    method = f"connect ({reason})"
            
            if found:
                with lock:
                    results[addr] = {
                        "name": name,
                        "method": method
                    }
            
            with lock:
                progress["scanned"] += 1
    
    def _generate_range(self, oui: str, start: str, count: int) -> List[str]:
        """Generate BD_ADDR range"""
        addresses = []
        
        # Parse start
        start_parts = [int(x, 16) for x in start.split(":")]
        start_val = (start_parts[0] << 16) | (start_parts[1] << 8) | start_parts[2]
        
        for i in range(count):
            val = start_val + i
            if val > 0xFFFFFF:
                break
            
            suffix = f"{(val >> 16) & 0xFF:02X}:{(val >> 8) & 0xFF:02X}:{val & 0xFF:02X}"
            addresses.append(f"{oui}:{suffix}")
        
        return addresses
    
    def _scan_single(self, target: str, timeout: int) -> Dict[str, Any]:
        """Scan single device"""
        result = {
            "address": target,
            "found": False,
            "name": None,
            "methods_tried": [],
            "success_method": None
        }
        
        C = Colors
        
        # Try name request
        print_info(f"Trying name request to {target}...")
        found, name = self._name_request(target, timeout)
        result["methods_tried"].append("name_request")
        
        if found:
            result["found"] = True
            result["name"] = name
            result["success_method"] = "name_request"
            print_success(f"Found! Name: {name or 'Unknown'}")
            return result
        
        # Try connection
        print_info(f"Trying connection to {target}...")
        found, reason = self._try_connect(target, timeout)
        result["methods_tried"].append("connect")
        
        if found:
            result["found"] = True
            result["success_method"] = f"connect ({reason})"
            print_success(f"Found! {reason}")
            return result
        
        # Try L2CAP ping
        print_info(f"Trying L2CAP ping to {target}...")
        if self._l2ping(target, timeout):
            result["found"] = True
            result["success_method"] = "l2ping"
            print_success("Found! L2CAP ping successful")
            return result
        
        result["methods_tried"].append("l2ping")
        print_warning("Device not found or not responding")
        
        return result
    
    def _scan_oui(self, oui: str, count: int, threads: int,
                  timeout: int, mode: str) -> List[Dict]:
        """Scan OUI range"""
        addresses = self._generate_range(oui, "00:00:00", count)
        return self._scan_range(addresses, threads, timeout, mode)
    
    def _scan_range(self, addresses: List[str], threads: int,
                    timeout: int, mode: str) -> List[Dict]:
        """Scan address range with threading"""
        results: Dict[str, Dict] = {}
        lock = threading.Lock()
        progress = {"scanned": 0}
        
        # Split addresses among threads
        chunk_size = (len(addresses) + threads - 1) // threads
        chunks = [addresses[i:i+chunk_size] for i in range(0, len(addresses), chunk_size)]
        
        thread_list = []
        
        C = Colors
        print_info(f"Scanning {len(addresses)} addresses with {len(chunks)} threads...")
        
        for chunk in chunks:
            t = threading.Thread(
                target=self._scan_worker,
                args=(chunk, mode, timeout, results, lock, progress),
                daemon=True
            )
            t.start()
            thread_list.append(t)
        
        # Progress monitoring
        total = len(addresses)
        start_time = time.time()
        
        try:
            while any(t.is_alive() for t in thread_list):
                with lock:
                    scanned = progress["scanned"]
                    found = len(results)
                
                elapsed = time.time() - start_time
                rate = scanned / elapsed if elapsed > 0 else 0
                pct = scanned * 100 // total if total > 0 else 0
                
                print(f"\r  {C.CYAN}[{pct:3d}%] Scanned: {scanned}/{total} | Found: {found} | Rate: {rate:.1f}/s{C.RESET}    ", end='', flush=True)
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            print()
            print_warning("Scan interrupted")
        
        # Wait for threads
        for t in thread_list:
            t.join(timeout=1)
        
        print()
        
        return [{"address": addr, **info} for addr, info in results.items()]
    
    def _scan_common_ouis(self, count_per_oui: int, threads: int,
                         timeout: int, mode: str) -> List[Dict]:
        """Scan common OUI prefixes"""
        all_results = []
        
        # Randomly select OUIs
        ouis = random.sample(COMMON_OUIS, min(20, len(COMMON_OUIS)))
        
        C = Colors
        print_info(f"Scanning {len(ouis)} common OUI prefixes...")
        
        for i, oui in enumerate(ouis):
            print_info(f"[{i+1}/{len(ouis)}] Scanning OUI {oui}...")
            results = self._scan_oui(oui, count_per_oui, threads, timeout, mode)
            all_results.extend(results)
            
            if results:
                print_success(f"Found {len(results)} devices in {oui}")
        
        return all_results
    
    def _print_results(self, results: List[Dict], mode: str) -> None:
        """Print scan results"""
        C = Colors
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}HIDDEN DEVICE SCAN RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*70}{C.RESET}")
        
        print(f"\n  Mode: {mode}")
        print(f"  Devices Found: {C.GREEN}{len(results)}{C.RESET}")
        
        if results:
            print(f"\n  {C.BOLD}DISCOVERED DEVICES{C.RESET}")
            print(f"  {C.CYAN}{'-'*70}{C.RESET}")
            
            for i, device in enumerate(results, 1):
                addr = device.get("address", "Unknown")
                name = device.get("name", "Unknown")
                method = device.get("method", device.get("success_method", "Unknown"))
                
                print(f"\n  {C.GREEN}[{i}]{C.RESET} {C.WHITE}{addr}{C.RESET}")
                print(f"      Name   : {name or 'N/A'}")
                print(f"      Method : {method}")
            
            print(f"\n  {C.BOLD}RECOMMENDATIONS{C.RESET}")
            print(f"  {C.CYAN}{'-'*70}{C.RESET}")
            print(f"  • Use 'scanners/version_fingerprint' for detailed analysis")
            print(f"  • Use 'scanners/vuln_scanner' to check vulnerabilities")
            print(f"  • Use 'scanners/sdp_enum' for service discovery")
        else:
            print(f"\n  {C.YELLOW}No hidden devices found in scanned range{C.RESET}")
            print(f"  Try different OUI prefixes or expand range")
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute hidden device scan"""
        
        target = self.get_option("target")
        mode = self.get_option("mode")
        oui = self.get_option("oui")
        range_start = self.get_option("range_start")
        range_count = int(self.get_option("range_count"))
        threads = int(self.get_option("threads"))
        timeout = int(self.get_option("timeout"))
        
        if mode not in ["name_req", "connect", "oui", "range", "all"]:
            print_error(f"Invalid mode: {mode}")
            return False
        
        C = Colors
        print(f"\n  {C.CYAN}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET} {C.BOLD}Hidden Device Scanner{C.RESET}                                 {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═'*55}╝{C.RESET}")
        
        print_info(f"Mode: {mode}")
        print_info(f"Threads: {threads}")
        print_info(f"Timeout: {timeout}s per device")
        
        print()
        print_warning("This scan may take a long time depending on range")
        print_info("Press Ctrl+C to stop")
        
        results = []
        
        try:
            # Single target scan
            if target and self.validate_bd_addr(target):
                print_info(f"\nScanning specific target: {target}")
                result = self._scan_single(target, timeout)
                if result["found"]:
                    results.append(result)
            
            # OUI-based scan
            elif oui or mode == "oui":
                if not oui:
                    # Scan common OUIs
                    results = self._scan_common_ouis(
                        count_per_oui=min(256, range_count),
                        threads=threads,
                        timeout=timeout,
                        mode="name_req" if mode == "oui" else mode
                    )
                else:
                    # Scan specific OUI
                    if len(oui.split(":")) != 3:
                        print_error("OUI must be in format XX:XX:XX")
                        return False
                    
                    print_info(f"\nScanning OUI: {oui}")
                    results = self._scan_oui(oui, range_count, threads, timeout, mode)
            
            # Range scan
            elif mode == "range":
                if not oui:
                    print_error("Range mode requires --oui option")
                    return False
                
                print_info(f"\nScanning range {oui}:{range_start} ({range_count} addresses)")
                addresses = self._generate_range(oui, range_start, range_count)
                results = self._scan_range(addresses, threads, timeout, "name_req")
            
            # Default: scan common OUIs
            else:
                results = self._scan_common_ouis(
                    count_per_oui=100,
                    threads=threads,
                    timeout=timeout,
                    mode=mode
                )
                
        except KeyboardInterrupt:
            print()
            print_warning("Scan interrupted by user")
        
        # Print results
        self._print_results(results, mode)
        
        # Store results
        for result in results:
            self.add_result(result)
        
        return len(results) > 0
