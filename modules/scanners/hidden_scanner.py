"""
BlueSploit Module: Hidden Device Scanner (v2)
Find Non-Discoverable Bluetooth Devices

Detects Bluetooth devices that have disabled discovery mode using:
  - Raw HCI Remote_Name_Request (Classic / BR-EDR)
  - L2CAP CID 0x0001 connect probe (Classic)
  - HCI LE active scan + scan request harvesting (LE)

Backend prefers raw HCI sockets (AF_BLUETOOTH/BTPROTO_HCI). Falls
back to deprecated `hcitool`/`l2ping` only if HCI socket binding
fails (non-root, missing CAP_NET_RAW, etc.).
"""

import errno
import os
import random
import shutil
import socket
import struct
import subprocess
import threading
import time
from contextlib import contextmanager
from typing import Dict, Any, List, Optional, Tuple

from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

# =====================================================================
# HCI socket constants (from <bluetooth/bluetooth.h>, <bluetooth/hci.h>)
# =====================================================================
AF_BLUETOOTH         = 31
BTPROTO_HCI          = 1
SOL_HCI              = 0
HCI_FILTER           = 2
HCI_COMMAND_PKT      = 0x01
HCI_EVENT_PKT        = 0x04

# OGF/OCF for the commands we send
OGF_LINK_CTL                  = 0x01
OCF_REMOTE_NAME_REQ           = 0x0019
OGF_LE_CTL                    = 0x08
OCF_LE_SET_SCAN_PARAMETERS    = 0x000B
OCF_LE_SET_SCAN_ENABLE        = 0x000C

# Event codes
EVT_CMD_COMPLETE              = 0x0E
EVT_CMD_STATUS                = 0x0F
EVT_REMOTE_NAME_REQ_COMPLETE  = 0x07
EVT_LE_META                   = 0x3E
EVT_LE_ADVERTISING_REPORT     = 0x02

# Default page scan repetition mode used in name requests
PSRM_R1 = 0x01

# OUI list trimmed for clarity; load from ouis.txt in production.
COMMON_OUIS = [
    # Apple
    "00:03:93", "00:0A:27", "00:1B:63", "28:CF:DA", "34:C0:59", "40:33:1A",
    "60:C5:47", "78:31:C1", "8C:85:90", "A4:B1:97", "B8:E8:56", "F0:DB:E2",
    # Samsung
    "00:07:AB", "00:12:47", "08:37:3D", "1C:62:B8", "2C:AE:2B", "3C:5A:37",
    "5C:0A:5B", "78:25:AD", "8C:77:12", "A0:0B:BA", "C8:19:F7", "E8:50:8B",
    # Xiaomi
    "04:CF:8C", "0C:1D:AF", "28:6C:07", "50:64:2B", "64:09:80", "98:FA:E3",
    # Google / Nest
    "00:1A:11", "3C:5A:B4", "94:EB:2C", "F4:F5:D8",
    # Intel
    "00:13:02", "00:1B:21", "00:1F:3B", "94:65:9C", "AC:9E:17", "F8:59:71",
    # Broadcom
    "00:10:18", "00:23:76", "20:16:D8", "34:BB:26", "40:F4:09",
    # CSR / Qualcomm
    "00:02:5B", "00:11:67", "00:1B:DC", "00:1E:A4", "98:7B:F3",
    # Espressif (BR/EDR-capable ESP32 only; ESP32-C/-S BLE-only excluded)
    "24:0A:C4", "30:AE:A4", "84:CC:A8", "A4:CF:12", "CC:50:E3",
]


# =====================================================================
# Raw HCI backend
# =====================================================================
class HCIError(Exception):
    """Raised for HCI-level failures (timeout, bad status, no socket)."""


@contextmanager
def hci_socket(dev_id: int):
    """Open a raw HCI socket bound to hciN, yield it, close on exit."""
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
    try:
        s.bind((dev_id,))
        # Filter: accept all event packets. struct hci_filter is 14 bytes:
        # type_mask(4) + event_mask(8) + opcode(2). 0xFFFFFFFF allows all.
        flt = struct.pack("<LLLH", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
        s.setsockopt(SOL_HCI, HCI_FILTER, flt)
        yield s
    finally:
        try:
            s.close()
        except OSError:
            pass


def _bdaddr_to_le_bytes(bdaddr: str) -> bytes:
    """Convert 'AA:BB:CC:DD:EE:FF' to little-endian 6-byte sequence."""
    parts = [int(x, 16) for x in bdaddr.split(":")]
    if len(parts) != 6 or any(p > 0xFF for p in parts):
        raise ValueError(f"invalid BD_ADDR: {bdaddr}")
    return bytes(reversed(parts))


def _build_hci_cmd(ogf: int, ocf: int, params: bytes) -> bytes:
    opcode = (ogf << 10) | ocf
    return struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params


def hci_remote_name_request(sock: socket.socket, bdaddr: str,
                             timeout: float = 10.0) -> Optional[str]:
    """
    Send Remote_Name_Request and wait for Remote_Name_Request_Complete.

    Returns the device name on success, None if the controller reported
    an error or status != 0x00. Raises HCIError on socket-level issues.
    """
    params = (_bdaddr_to_le_bytes(bdaddr) +
              bytes([PSRM_R1, 0x00, 0x00, 0x00]))   # PSRM, reserved, clock_offset
    cmd = _build_hci_cmd(OGF_LINK_CTL, OCF_REMOTE_NAME_REQ, params)

    sock.settimeout(timeout)
    try:
        sock.send(cmd)
    except OSError as e:
        raise HCIError(f"send failed: {e}") from e

    target_addr_le = _bdaddr_to_le_bytes(bdaddr)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            pkt = sock.recv(260)
        except socket.timeout:
            return None
        except OSError as e:
            raise HCIError(f"recv failed: {e}") from e

        if len(pkt) < 3 or pkt[0] != HCI_EVENT_PKT:
            continue

        event_code, plen = pkt[1], pkt[2]
        body = pkt[3:3 + plen]

        if event_code == EVT_REMOTE_NAME_REQ_COMPLETE:
            if len(body) < 7:
                continue
            status = body[0]
            evt_addr = body[1:7]
            if evt_addr != target_addr_le:
                continue            # event for a different request
            if status != 0x00:
                return None         # page timeout, no name, etc.
            name_bytes = body[7:].split(b'\x00', 1)[0]
            try:
                return name_bytes.decode('utf-8')
            except UnicodeDecodeError:
                return name_bytes.decode('latin-1', errors='replace')

        if event_code == EVT_CMD_STATUS and len(body) >= 4:
            status = body[0]
            if status != 0x00:
                # 0x12 = invalid params, 0x0C = command disallowed, etc.
                return None

    return None


def hci_le_active_scan(sock: socket.socket, duration: float = 5.0,
                        interval: int = 0x0010, window: int = 0x0010
                        ) -> List[Dict[str, Any]]:
    """
    Run an LE active scan for `duration` seconds and return a list of
    {addr, addr_type, rssi, data, scan_response} entries.

    Active scan triggers SCAN_REQ -> SCAN_RSP, which surfaces device
    names that beacons hide behind ADV_NONCONN_IND.
    """
    # Set scan parameters: active scan, own_addr_type=public, no whitelist
    set_params = struct.pack("<BHHBB", 0x01, interval, window, 0x00, 0x00)
    sock.send(_build_hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_PARAMETERS, set_params))
    _drain_for_command_complete(sock, OCF_LE_SET_SCAN_PARAMETERS, 1.0)

    # Enable scan, no filter duplicates
    sock.send(_build_hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                              struct.pack("<BB", 0x01, 0x00)))
    _drain_for_command_complete(sock, OCF_LE_SET_SCAN_ENABLE, 1.0)

    seen: Dict[str, Dict[str, Any]] = {}
    deadline = time.monotonic() + duration

    while time.monotonic() < deadline:
        try:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            pkt = sock.recv(260)
        except socket.timeout:
            break

        if len(pkt) < 3 or pkt[0] != HCI_EVENT_PKT:
            continue
        if pkt[1] != EVT_LE_META:
            continue
        body = pkt[3:3 + pkt[2]]
        if not body or body[0] != EVT_LE_ADVERTISING_REPORT:
            continue

        # num_reports + per-report: evt_type, addr_type, addr(6), len, data..., rssi
        try:
            num = body[1]
            off = 2
            for _ in range(num):
                evt_type = body[off]; off += 1
                addr_type = body[off]; off += 1
                addr_le = body[off:off + 6]; off += 6
                dlen = body[off]; off += 1
                data = body[off:off + dlen]; off += dlen
                rssi = struct.unpack("<b", body[off:off + 1])[0]; off += 1

                addr = ":".join(f"{b:02X}" for b in reversed(addr_le))
                entry = seen.setdefault(addr, {
                    "addr": addr, "addr_type": addr_type,
                    "rssi": rssi, "data": b"", "scan_response": b"",
                })
                if evt_type == 0x04:        # SCAN_RSP
                    entry["scan_response"] = data
                else:
                    entry["data"] = data
                entry["rssi"] = rssi
        except (IndexError, struct.error):
            continue

    # Disable scan
    sock.send(_build_hci_cmd(OGF_LE_CTL, OCF_LE_SET_SCAN_ENABLE,
                              struct.pack("<BB", 0x00, 0x00)))
    _drain_for_command_complete(sock, OCF_LE_SET_SCAN_ENABLE, 1.0)

    return list(seen.values())


def _drain_for_command_complete(sock: socket.socket, ocf: int,
                                  timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock.settimeout(max(0.05, deadline - time.monotonic()))
            pkt = sock.recv(260)
        except socket.timeout:
            return
        if len(pkt) < 4 or pkt[0] != HCI_EVENT_PKT:
            continue
        if pkt[1] == EVT_CMD_COMPLETE:
            return


# =====================================================================
# L2CAP probe (errno-based, no string matching)
# =====================================================================
def l2cap_probe(bdaddr: str, psm: int = 1, timeout: float = 4.0) -> Tuple[bool, str]:
    """
    Try to connect L2CAP to (bdaddr, psm). Returns (device_present, reason).

    A device is considered present if connect() succeeds OR is refused
    with ECONNREFUSED, the controller had to talk to it to refuse.
    EHOSTDOWN / EHOSTUNREACH / ETIMEDOUT mean the device didn't respond.
    """
    BTPROTO_L2CAP = 0
    try:
        s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    except OSError as e:
        return False, f"socket: {os.strerror(e.errno)}"

    try:
        s.settimeout(timeout)
        try:
            s.connect((bdaddr, psm))
            return True, "L2CAP connect succeeded"
        except OSError as e:
            ec = e.errno
            if ec == errno.ECONNREFUSED:
                return True, "device present (ECONNREFUSED)"
            if ec in (errno.EHOSTDOWN, errno.EHOSTUNREACH, errno.ETIMEDOUT):
                return False, os.strerror(ec)
            if ec == errno.EBUSY:
                return False, "controller busy"
            return False, f"errno {ec}: {os.strerror(ec) if ec else e}"
        except socket.timeout:
            return False, "timeout"
    finally:
        try:
            s.close()
        except OSError:
            pass


# =====================================================================
# Module
# =====================================================================
class Module(ScannerModule):
    """Hidden Device Scanner v2."""

    info = ModuleInfo(
        name="scanners/hidden_scanner",
        description="Find non-discoverable Bluetooth devices (BR/EDR + LE)",
        author=["BlueSploit", "@mr-iot"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
        cve=[],   # removed: non-discoverable != non-connectable is spec behavior, not a CVE
        references=[
            "Bluetooth Core 5.4 Vol 2 Part E (HCI)",
            "Bluetooth Core 5.4 Vol 6 Part B (LL)",
            "BlueZ source: lib/hci.c, lib/l2cap.c",
        ]
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption("target", False,
                "Specific BD_ADDR for single-target probe", None),
            "strategy": ModuleOption("strategy", False,
                "How to generate addresses: single | range | oui | common_ouis | le_scan",
                "common_ouis"),
            "method": ModuleOption("method", False,
                "BR/EDR detection: name_req | l2cap | both", "name_req"),
            "oui": ModuleOption("oui", False,
                "OUI prefix XX:XX:XX (required for strategy=oui|range)", None),
            "range_start": ModuleOption("range_start", False,
                "Suffix start XX:XX:XX (used by strategy=range)", "00:00:00"),
            "range_count": ModuleOption("range_count", False,
                "Number of addresses to scan", 256),
            "hci_dev": ModuleOption("hci_dev", False,
                "HCI adapter index (0 for hci0)", 0),
            "timeout": ModuleOption("timeout", False,
                "Per-device timeout (seconds)", 5),
            "le_duration": ModuleOption("le_duration", False,
                "LE scan duration (seconds, strategy=le_scan)", 10),
            "seed": ModuleOption("seed", False,
                "RNG seed for reproducible OUI ordering (default: time-based, logged)",
                None),
            "use_subprocess_fallback": ModuleOption("use_subprocess_fallback", False,
                "Fall back to hcitool/l2ping if HCI sockets unavailable", True),
        }

    # ------------------------------------------------------------------
    # Backend selection
    # ------------------------------------------------------------------
    def _open_backend(self, dev_id: int):
        """
        Returns (kind, handle) where kind is 'hci' (socket) or 'subprocess'.
        Raises if no backend is usable.
        """
        try:
            sock = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
            sock.bind((dev_id,))
            flt = struct.pack("<LLLH", 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
            sock.setsockopt(SOL_HCI, HCI_FILTER, flt)
            return "hci", sock
        except OSError as e:
            print_warning(f"raw HCI unavailable ({os.strerror(e.errno)}); "
                          f"need CAP_NET_RAW or root")
            if not self.get_option("use_subprocess_fallback"):
                raise
            if not shutil.which("hcitool"):
                raise HCIError("no HCI socket and hcitool not on PATH")
            print_warning("falling back to deprecated hcitool/l2ping")
            return "subprocess", None

    # ------------------------------------------------------------------
    # Probe primitives
    # ------------------------------------------------------------------
    def _probe_name_req(self, backend, addr: str, timeout: float
                         ) -> Tuple[bool, Optional[str]]:
        kind, handle = backend
        if kind == "hci":
            try:
                name = hci_remote_name_request(handle, addr, timeout)
                return (name is not None), name
            except HCIError:
                return False, None
        # subprocess fallback
        try:
            r = subprocess.run(["hcitool", "name", addr],
                               capture_output=True, text=True, timeout=timeout)
            name = r.stdout.strip() if r.returncode == 0 else ""
            return (bool(name), name or None)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False, None

    def _probe_l2cap(self, addr: str, timeout: float) -> Tuple[bool, str]:
        return l2cap_probe(addr, psm=1, timeout=timeout)

    # ------------------------------------------------------------------
    # Single-target probe, every method tried gets recorded, in order
    # ------------------------------------------------------------------
    def _scan_single(self, backend, addr: str, method: str, timeout: float
                      ) -> Dict[str, Any]:
        result = {
            "address": addr, "found": False, "name": None,
            "methods_tried": [], "success_method": None,
        }

        if method in ("name_req", "both"):
            result["methods_tried"].append("name_req")
            ok, name = self._probe_name_req(backend, addr, timeout)
            if ok:
                result.update(found=True, name=name, success_method="name_req")
                return result

        if method in ("l2cap", "both"):
            result["methods_tried"].append("l2cap")
            ok, reason = self._probe_l2cap(addr, timeout)
            if ok:
                result.update(found=True, success_method=f"l2cap ({reason})")
                return result

        return result

    # ------------------------------------------------------------------
    # Address generation
    # ------------------------------------------------------------------
    @staticmethod
    def _gen_range(oui: str, start: str, count: int) -> List[str]:
        if len(oui.split(":")) != 3:
            raise ValueError(f"OUI must be XX:XX:XX, got {oui!r}")
        sp = [int(x, 16) for x in start.split(":")]
        base = (sp[0] << 16) | (sp[1] << 8) | sp[2]
        out = []
        for i in range(count):
            v = base + i
            if v > 0xFFFFFF:
                break
            out.append(f"{oui}:{(v >> 16) & 0xFF:02X}:"
                       f"{(v >> 8) & 0xFF:02X}:{v & 0xFF:02X}")
        return out

    # ------------------------------------------------------------------
    # Sequential scan over an address list (HCI is single-threaded by
    # design, one Remote_Name_Request in flight per controller).
    # ------------------------------------------------------------------
    def _scan_sequential(self, backend, addresses: List[str],
                          method: str, timeout: float) -> List[Dict]:
        C = Colors
        found: List[Dict] = []
        total = len(addresses)
        start = time.time()
        stop_flag = threading.Event()

        def progress():
            i = 0
            while not stop_flag.is_set() and i < total:
                elapsed = time.time() - start
                rate = (i / elapsed) if elapsed else 0.0
                pct = (i * 100 // total) if total else 0
                print(f"\r  {C.CYAN}[{pct:3d}%] {i}/{total} | "
                      f"found {len(found)} | {rate:.1f}/s{C.RESET}    ",
                      end='', flush=True)
                time.sleep(0.5)
                # i is captured by closure below
                i = self._scanned

        self._scanned = 0
        prog = threading.Thread(target=progress, daemon=True)
        prog.start()

        try:
            for addr in addresses:
                r = self._scan_single(backend, addr, method, timeout)
                self._scanned += 1
                if r["found"]:
                    found.append(r)
        except KeyboardInterrupt:
            print()
            print_warning("interrupted")
        finally:
            stop_flag.set()
            prog.join(timeout=1)
            print()

        return found

    # ------------------------------------------------------------------
    # LE scan strategy
    # ------------------------------------------------------------------
    def _scan_le(self, dev_id: int, duration: float) -> List[Dict]:
        try:
            with hci_socket(dev_id) as s:
                print_info(f"LE active scan on hci{dev_id} for {duration}s "
                           f"(harvests SCAN_RSP from non-connectable adv)")
                reports = hci_le_active_scan(s, duration=duration)
        except OSError as e:
            print_error(f"LE scan failed: {os.strerror(e.errno)}")
            return []

        results = []
        for r in reports:
            name = self._extract_le_name(r["data"]) or \
                   self._extract_le_name(r["scan_response"])
            results.append({
                "address": r["addr"],
                "found": True,
                "name": name,
                "success_method": "le_active_scan",
                "rssi": r["rssi"],
                "addr_type": ("public" if r["addr_type"] == 0 else "random"),
            })
        return results

    @staticmethod
    def _extract_le_name(adv: bytes) -> Optional[str]:
        i = 0
        while i < len(adv):
            ln = adv[i]
            if ln == 0 or i + 1 + ln > len(adv):
                break
            ad_type = adv[i + 1]
            if ad_type in (0x08, 0x09):     # Shortened/Complete Local Name
                return adv[i + 2:i + 1 + ln].decode('utf-8', errors='replace')
            i += 1 + ln
        return None

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    def _report(self, results: List[Dict], strategy: str) -> None:
        C = Colors
        print(f"\n  {C.CYAN}{'=' * 70}{C.RESET}")
        print(f"  {C.BOLD}HIDDEN DEVICE SCAN, strategy={strategy}{C.RESET}")
        print(f"  {C.CYAN}{'=' * 70}{C.RESET}")
        print(f"  Found: {C.GREEN}{len(results)}{C.RESET}")
        if not results:
            print(f"\n  {C.YELLOW}No devices located in scanned range.{C.RESET}")
            return
        for i, d in enumerate(results, 1):
            print(f"\n  {C.GREEN}[{i}]{C.RESET} {d.get('address')}")
            if d.get("name"):
                print(f"      name   : {d['name']}")
            if d.get("success_method"):
                print(f"      method : {d['success_method']}")
            if d.get("rssi") is not None:
                print(f"      rssi   : {d['rssi']} dBm")
            if d.get("addr_type"):
                print(f"      type   : {d['addr_type']}")

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def run(self) -> bool:
        target       = self.get_option("target")
        strategy     = self.get_option("strategy")
        method       = self.get_option("method")
        oui          = self.get_option("oui")
        range_start  = self.get_option("range_start")
        range_count  = int(self.get_option("range_count"))
        hci_dev      = int(self.get_option("hci_dev"))
        timeout      = float(self.get_option("timeout"))
        le_duration  = float(self.get_option("le_duration"))
        seed_opt     = self.get_option("seed")

        if strategy not in ("single", "range", "oui", "common_ouis", "le_scan"):
            print_error(f"invalid strategy: {strategy}"); return False
        if method not in ("name_req", "l2cap", "both"):
            print_error(f"invalid method: {method}"); return False

        # Header
        C = Colors
        print(f"\n  {C.CYAN}╔{'═' * 55}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET} {C.BOLD}Hidden Device Scanner v2{C.RESET}                              {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═' * 55}╝{C.RESET}")
        print_info(f"strategy={strategy} method={method} hci=hci{hci_dev} timeout={timeout}s")

        # LE strategy doesn't need the BR/EDR backend
        if strategy == "le_scan":
            results = self._scan_le(hci_dev, le_duration)
            self._report(results, strategy)
            for r in results:
                self.add_result(r)
            return bool(results)

        # Open BR/EDR backend
        try:
            backend = self._open_backend(hci_dev)
        except (OSError, HCIError) as e:
            print_error(f"no usable backend: {e}")
            return False

        kind, handle = backend
        print_info(f"backend: {kind}")

        try:
            results: List[Dict] = []

            if strategy == "single":
                if not target:
                    print_error("strategy=single requires target"); return False
                if not self.validate_bd_addr(target):
                    print_error(f"invalid BD_ADDR: {target}"); return False
                r = self._scan_single(backend, target, method, timeout)
                if r["found"]:
                    results.append(r)
                else:
                    print_warning(f"{target} did not respond "
                                  f"(tried: {','.join(r['methods_tried'])})")

            elif strategy == "range":
                if not oui:
                    print_error("strategy=range requires oui"); return False
                addrs = self._gen_range(oui, range_start, range_count)
                print_info(f"scanning {len(addrs)} addresses "
                           f"({oui}:{range_start} → +{range_count})")
                results = self._scan_sequential(backend, addrs, method, timeout)

            elif strategy == "oui":
                if not oui:
                    print_error("strategy=oui requires oui"); return False
                addrs = self._gen_range(oui, range_start, range_count)
                results = self._scan_sequential(backend, addrs, method, timeout)

            elif strategy == "common_ouis":
                seed = int(seed_opt) if seed_opt is not None else int(time.time())
                rng = random.Random(seed)
                ouis = COMMON_OUIS[:]
                rng.shuffle(ouis)
                ouis = ouis[:20]
                print_info(f"common_ouis seed={seed} (record this for reproducibility)")
                print_info(f"OUIs: {', '.join(ouis)}")
                per_oui = max(1, range_count // len(ouis))
                for i, o in enumerate(ouis, 1):
                    print_info(f"[{i}/{len(ouis)}] {o}, {per_oui} addresses")
                    addrs = self._gen_range(o, "00:00:00", per_oui)
                    results.extend(self._scan_sequential(backend, addrs, method, timeout))

        finally:
            if kind == "hci" and handle is not None:
                try: handle.close()
                except OSError: pass

        self._report(results, strategy)
        for r in results:
            self.add_result(r)
        return bool(results)