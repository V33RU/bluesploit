"""
BlueSploit Module: Incoming Connection Monitor

Listens on a raw HCI socket for incoming Bluetooth connection attempts
from nearby devices and prints them in real time. Catches both BR/EDR
(HCI_Connection_Request, HCI_Connection_Complete) and BLE
(LE_Connection_Complete) inbound events.

Useful for passive discovery of devices that scan/probe the host -
e.g. catching a phone that auto-connects to a known SSP-bonded peer,
or a peripheral that connects in to push a notification.
"""

import os
import select
import socket
import struct
import time
from datetime import datetime
from typing import Optional

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

AF_BLUETOOTH    = 31
BTPROTO_HCI     = 1
HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT   = 0x04

EVT_CONN_REQUEST     = 0x04
EVT_CONN_COMPLETE    = 0x03
EVT_DISCONN_COMPLETE = 0x05
EVT_LE_META          = 0x3E
LE_CONN_COMPLETE     = 0x01
LE_ENH_CONN_COMPLETE = 0x0A

# Class of Device → device class string
COD_MAJOR = {
    0x00: "Misc", 0x01: "Computer", 0x02: "Phone", 0x03: "LAN/Network",
    0x04: "Audio/Video", 0x05: "Peripheral", 0x06: "Imaging", 0x07: "Wearable",
    0x08: "Toy", 0x09: "Health",
}

LINK_TYPE = {0x00: "SCO", 0x01: "ACL", 0x02: "eSCO"}


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Incoming Connection Monitor",
        description="Print incoming BR/EDR + BLE connection attempts from nearby devices",
        author=["BlueSploit"],
        protocol=BTProtocol.DUAL,
        severity=Severity.INFO,
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter to monitor",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Monitor window in seconds (0 = run until Ctrl+C)",
            default=0,
        ))
        self.add_option(ModuleOption(
            name="discoverable",
            required=False,
            description="Make adapter discoverable + connectable to attract probes",
            default="true",
        ))
        self.add_option(ModuleOption(
            name="auto_reject",
            required=False,
            description="Auto-reject incoming BR/EDR connections (passive listen)",
            default="true",
        ))

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root required for raw HCI socket access")
            return False

        iface       = self.get_option("interface") or "hci0"
        duration    = int(self.get_option("duration") or 0)
        discoverable= (self.get_option("discoverable") or "true").lower() == "true"
        auto_reject = (self.get_option("auto_reject") or "true").lower() == "true"

        print_info(f"Interface  : {iface}")
        print_info(f"Duration   : {'∞ (Ctrl+C to stop)' if duration == 0 else f'{duration}s'}")
        print_info(f"Discoverable: {discoverable}")
        print_info(f"Auto-reject : {auto_reject}")

        if discoverable:
            self._set_discoverable(iface)

        hci = self._open_hci(iface)
        if not hci:
            return False

        # Set HCI filter to receive all events
        hci_filter = struct.pack("<IIIH",
            0x00000010,  # type mask: events only
            0xFFFFFFFF,  # event mask: all
            0xFFFFFFFF,
            0x0000)
        try:
            hci.setsockopt(0, 1, hci_filter)  # SOL_HCI=0, HCI_FILTER=1
        except Exception:
            pass  # filter is optional; kernel default usually delivers events

        print_success("Listening for incoming connections...\n")
        deadline = time.time() + duration if duration > 0 else None
        events_seen = 0

        try:
            while True:
                if deadline and time.time() > deadline:
                    break
                r, _, _ = select.select([hci], [], [], 1.0)
                if not r:
                    continue
                pkt = hci.recv(512)
                if not pkt or pkt[0] != HCI_EVENT_PKT or len(pkt) < 3:
                    continue
                ev = pkt[1]
                params = pkt[3:]

                if ev == EVT_CONN_REQUEST and len(params) >= 10:
                    self._handle_conn_request(hci, params, auto_reject)
                    events_seen += 1
                elif ev == EVT_CONN_COMPLETE and len(params) >= 11:
                    self._handle_conn_complete(params)
                    events_seen += 1
                elif ev == EVT_DISCONN_COMPLETE and len(params) >= 4:
                    self._handle_disconn(params)
                elif ev == EVT_LE_META and len(params) >= 1:
                    sub = params[0]
                    if sub in (LE_CONN_COMPLETE, LE_ENH_CONN_COMPLETE):
                        self._handle_le_conn(params, sub)
                        events_seen += 1

        except KeyboardInterrupt:
            print()
            print_warning("Interrupted")
        finally:
            hci.close()

        print_info(f"\nTotal incoming events captured: {events_seen}")
        self.add_result({"events_seen": events_seen})
        return True

    # ── handlers ──────────────────────────────────────────────────────────

    def _handle_conn_request(self, hci, params: bytes, auto_reject: bool):
        addr = ':'.join(f'{b:02X}' for b in reversed(params[0:6]))
        cod  = int.from_bytes(params[6:9], "little")
        ltype = params[9]
        major = (cod >> 8) & 0x1F
        ts = datetime.now().strftime("%H:%M:%S")

        print(f"  {Colors.YELLOW}[{ts}]{Colors.RESET} "
              f"{Colors.RED}◀ CONN_REQUEST{Colors.RESET}  "
              f"from {Colors.CYAN}{addr}{Colors.RESET}  "
              f"link={LINK_TYPE.get(ltype, '?')}  "
              f"CoD=0x{cod:06X} ({COD_MAJOR.get(major, 'Unknown')})")

        self.add_result({
            "type": "conn_request",
            "timestamp": ts, "peer": addr,
            "link_type": LINK_TYPE.get(ltype, hex(ltype)),
            "cod": f"0x{cod:06X}",
            "device_class": COD_MAJOR.get(major, "Unknown"),
        })

        if auto_reject:
            # HCI_Reject_Connection_Request (OGF=0x01, OCF=0x000A)
            addr_rev = params[0:6]
            reject = addr_rev + bytes([0x0F])  # reason: unacceptable BD_ADDR
            self._hci_cmd(hci, 0x01, 0x000A, reject)
            print(f"      {Colors.DARK_GREY}↳ rejected{Colors.RESET}")

    def _handle_conn_complete(self, params: bytes):
        status = params[0]
        handle = struct.unpack_from("<H", params, 1)[0] & 0x0FFF
        addr   = ':'.join(f'{b:02X}' for b in reversed(params[3:9]))
        ltype  = params[9] if len(params) > 9 else 0xFF
        ts = datetime.now().strftime("%H:%M:%S")

        if status == 0x00:
            print(f"  {Colors.YELLOW}[{ts}]{Colors.RESET} "
                  f"{Colors.GREEN}◀ CONN_COMPLETE{Colors.RESET} "
                  f"{Colors.CYAN}{addr}{Colors.RESET}  "
                  f"handle=0x{handle:04x} link={LINK_TYPE.get(ltype, '?')}")
        else:
            print(f"  {Colors.YELLOW}[{ts}]{Colors.RESET} "
                  f"{Colors.RED}✗ CONN_FAILED{Colors.RESET}  "
                  f"{Colors.CYAN}{addr}{Colors.RESET}  status=0x{status:02x}")

    def _handle_disconn(self, params: bytes):
        status = params[0]
        handle = struct.unpack_from("<H", params, 1)[0] & 0x0FFF
        reason = params[3]
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"  {Colors.YELLOW}[{ts}]{Colors.RESET} "
              f"{Colors.DARK_GREY}◀ DISCONN{Colors.RESET}        "
              f"handle=0x{handle:04x} reason=0x{reason:02x}")

    def _handle_le_conn(self, params: bytes, sub: int):
        if params[1] != 0x00:
            return
        handle = struct.unpack_from("<H", params, 2)[0] & 0x0FFF
        role   = params[4]   # 0=master 1=slave
        peer_t = params[5]
        addr   = ':'.join(f'{b:02X}' for b in reversed(params[6:12]))
        ts = datetime.now().strftime("%H:%M:%S")

        role_s = "we_are_master" if role == 0 else "we_are_slave (incoming!)"
        at_s   = "public" if peer_t == 0 else "random"
        kind   = "LE_ENH_CONN" if sub == LE_ENH_CONN_COMPLETE else "LE_CONN"

        color = Colors.GREEN if role == 1 else Colors.YELLOW
        print(f"  {Colors.YELLOW}[{ts}]{Colors.RESET} "
              f"{color}◀ {kind}_COMPLETE{Colors.RESET}  "
              f"{Colors.CYAN}{addr}{Colors.RESET} ({at_s})  "
              f"handle=0x{handle:04x} role={role_s}")

        self.add_result({
            "type": "le_conn_complete",
            "timestamp": ts, "peer": addr,
            "addr_type": at_s, "role": role_s,
            "handle": f"0x{handle:04x}",
        })

    # ── adapter helpers ───────────────────────────────────────────────────

    def _set_discoverable(self, iface: str):
        import subprocess
        try:
            subprocess.run(["hciconfig", iface, "piscan"], timeout=3)
            print_success(f"{iface} set to page+inquiry scan (discoverable + connectable)")
        except Exception as e:
            print_warning(f"hciconfig piscan failed: {e}")

    def _open_hci(self, iface: str) -> Optional[socket.socket]:
        try:
            hci = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
            dev_id = int(iface.replace("hci", ""))
            hci.bind((dev_id,))
            return hci
        except OSError as e:
            print_error(f"HCI open failed on {iface}: {e}")
            return None

    def _hci_cmd(self, hci, ogf, ocf, params=b''):
        opcode = (ogf << 10) | ocf
        pkt = struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params
        hci.setblocking(True); hci.send(pkt); hci.setblocking(False)
