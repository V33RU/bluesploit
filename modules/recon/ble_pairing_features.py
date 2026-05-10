"""
BlueSploit Module: BLE Pairing Features Probe

Sends an SMP Pairing Request to a remote BLE device and parses the
Pairing Response to expose the peer's pairing capabilities — IO
Capability, OOB data flag, AuthReq (Bonding / MITM / Secure Connections /
Keypress / CT2), Maximum Encryption Key Size, and Initiator/Responder
Key Distribution flags.

This is a passive intelligence probe — the connection is dropped
before any actual key exchange takes place.
"""

import os
import select
import socket
import struct
import time
from typing import Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

AF_BLUETOOTH    = 31
BTPROTO_HCI     = 1
HCI_COMMAND_PKT = 0x01
HCI_ACL_PKT     = 0x02
HCI_EVENT_PKT   = 0x04
HCI_LE_META     = 0x3E
LE_CONN_COMPLETE= 0x01

SMP_CID             = 0x0006
SMP_PAIRING_REQ     = 0x01
SMP_PAIRING_RSP     = 0x02
SMP_PAIRING_FAILED  = 0x05

IO_NAMES = {
    0x00: "DisplayOnly", 0x01: "DisplayYesNo", 0x02: "KeyboardOnly",
    0x03: "NoInputNoOutput", 0x04: "KeyboardDisplay",
}

KEY_DIST_BITS = [
    "EncKey (LTK + EDIV + Rand)",
    "IdKey (IRK + Identity Address)",
    "Sign (CSRK)",
    "LinkKey (BR/EDR derived via CTKD)",
]


class Module(ReconModule):

    info = ModuleInfo(
        name="BLE Pairing Features Probe",
        description="Read SMP Pairing Features (IO cap, AuthReq, key dist) from a remote LE device",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BLE BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="addr_type",
            required=False,
            description="Peer address type: auto, public, or random",
            default="auto",
        ))
        self.add_option(ModuleOption(
            name="claim_io",
            required=False,
            description="IO capability we claim (0=DisplayOnly..4=KeyboardDisplay)",
            default=3,
        ))
        self.add_option(ModuleOption(
            name="claim_auth",
            required=False,
            description="auth_req we claim (hex; default Bonding|MITM|SC = 0x0D)",
            default="0x0D",
        ))

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root required for raw HCI socket access")
            return False

        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        iface     = self.get_option("interface") or "hci0"
        addr_type = (self.get_option("addr_type") or "auto").lower()
        claim_io  = max(0, min(4, int(self.get_option("claim_io") or 3)))
        try:
            claim_ar = int(self.get_option("claim_auth") or "0x0D", 16)
        except ValueError:
            claim_ar = 0x0D

        if addr_type == "auto":
            msb = int(target.split(":")[0], 16) >> 6
            if msb in (0b11, 0b01):
                addr_type = "random"
                print_info(f"Auto-detected address type: random "
                           f"({'Static Random' if msb == 0b11 else 'Resolvable Private'})")
            else:
                addr_type = "public"
                print_info("Auto-detected address type: public")

        peer_at = 0x01 if addr_type == "random" else 0x00

        print_info(f"Target   : {target} ({addr_type})")
        print_info(f"Interface: {iface}")
        print_info(f"We claim : IO={IO_NAMES.get(claim_io)}  auth_req=0x{claim_ar:02X}")

        hci = self._open_hci(iface)
        if not hci:
            return False

        handle = None
        try:
            handle = self._le_create_connection(hci, target, peer_at)
            if handle is None:
                print_error("LE connection failed")
                return False
            print_success(f"LE connected (handle=0x{handle:04x})")

            # Build Pairing Request: opcode + io_cap + oob + auth_req
            #                       + max_key_size + init_key_dist + resp_key_dist
            pairing_req = struct.pack("BBBBBBB",
                SMP_PAIRING_REQ, claim_io, 0x00, claim_ar,
                16, 0x0F, 0x0F)
            print_info(f"Sending SMP Pairing Request: {pairing_req.hex()}")
            self._send_smp(hci, handle, pairing_req)

            resp = self._recv_smp(hci, timeout=8)
            if resp is None:
                print_error("No SMP response")
                return False

            if resp[0] == SMP_PAIRING_FAILED:
                reason = resp[1] if len(resp) > 1 else 0xFF
                print_warning(f"Peer rejected probe: SMP_FAILED reason=0x{reason:02x}")
                self.add_result({"target": target, "rejected": True,
                                 "reason": f"0x{reason:02x}"})
                return False

            if resp[0] != SMP_PAIRING_RSP or len(resp) < 7:
                print_error(f"Unexpected SMP 0x{resp[0]:02x}")
                return False

            self._decode_pairing_response(resp, target)

            return True

        finally:
            if handle is not None:
                self._disconnect(hci, handle)
            hci.close()

    def _decode_pairing_response(self, resp: bytes, target: str):
        io       = resp[1]
        oob      = resp[2]
        auth_req = resp[3]
        max_key  = resp[4]
        init_kd  = resp[5]
        resp_kd  = resp[6]

        bonding  = bool(auth_req & 0x01)
        mitm     = bool(auth_req & 0x04)
        sc       = bool(auth_req & 0x08)
        keypress = bool(auth_req & 0x10)
        ct2      = bool(auth_req & 0x20)

        print_success("Pairing Response decoded:")
        print(f"    IO Capability  : {Colors.WHITE}{IO_NAMES.get(io, f'0x{io:02x}')}{Colors.RESET}")
        print(f"    OOB Data       : {'yes' if oob else 'no'}")
        print(f"    Bonding        : {self._yn(bonding)}")
        print(f"    MITM           : {self._yn(mitm)}")
        print(f"    Secure Conn    : {self._yn(sc)}")
        print(f"    Keypress       : {self._yn(keypress)}")
        print(f"    CT2 (CTKD)     : {self._yn(ct2)}")
        print(f"    Max key size   : {max_key} bytes")

        print(f"    Initiator key dist (0x{init_kd:02x}):")
        self._print_keydist(init_kd)
        print(f"    Responder key dist (0x{resp_kd:02x}):")
        self._print_keydist(resp_kd)

        if not sc and (mitm or bonding):
            print_warning("Peer accepts Legacy Pairing — vulnerable to passive eavesdrop "
                          "(crackle / KNOB-style downgrade)")
        if not mitm:
            print_warning("Peer does NOT require MITM protection — JustWorks attack possible")
        if max_key < 16:
            print_warning(f"Peer accepts {max_key}-byte key — KNOB-style downgrade possible")

        self.add_result({
            "target": target,
            "io_capability": IO_NAMES.get(io, f"0x{io:02x}"),
            "oob": bool(oob),
            "auth_req": f"0x{auth_req:02X}",
            "bonding": bonding, "mitm": mitm, "sc": sc,
            "keypress": keypress, "ct2": ct2,
            "max_key_size": max_key,
            "init_key_dist": f"0x{init_kd:02x}",
            "resp_key_dist": f"0x{resp_kd:02x}",
        })

    def _print_keydist(self, mask: int):
        any_set = False
        for bit, name in enumerate(KEY_DIST_BITS):
            if mask & (1 << bit):
                any_set = True
                print(f"      {Colors.GREEN}✓{Colors.RESET} {name}")
        if not any_set:
            print(f"      {Colors.DARK_GREY}(none){Colors.RESET}")

    @staticmethod
    def _yn(b: bool) -> str:
        c = Colors.GREEN if b else Colors.DARK_GREY
        return f"{c}{'yes' if b else 'no'}{Colors.RESET}"

    # ── HCI / SMP socket plumbing ─────────────────────────────────────────

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

    def _le_create_connection(self, hci, target, peer_at, timeout=12.0):
        addr = bytes(int(x, 16) for x in reversed(target.split(":")))
        params = struct.pack("<HHBB6sBHHHHHH",
            0x0060, 0x0030, 0x00, peer_at, addr, 0x00,
            0x0006, 0x000C, 0x0000, 0x00C8, 0x0000, 0x0000)
        self._hci_cmd(hci, 0x08, 0x000D, params)
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([hci], [], [], 0.5)
            if not r:
                continue
            pkt = hci.recv(255)
            if (pkt and pkt[0] == HCI_EVENT_PKT and pkt[1] == HCI_LE_META
                    and len(pkt) >= 7 and pkt[3] == LE_CONN_COMPLETE
                    and pkt[4] == 0x00):
                return struct.unpack_from("<H", pkt, 5)[0] & 0x0FFF
        return None

    def _send_smp(self, hci, handle, data):
        l2cap = struct.pack("<HH", len(data), SMP_CID) + data
        acl   = struct.pack("<HH", handle | (0x00 << 12), len(l2cap)) + l2cap
        hci.setblocking(True); hci.send(bytes([HCI_ACL_PKT]) + acl); hci.setblocking(False)

    def _recv_smp(self, hci, timeout=5.0) -> Optional[bytes]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([hci], [], [], 0.5)
            if not r:
                continue
            pkt = hci.recv(512)
            if not pkt or pkt[0] != HCI_ACL_PKT or len(pkt) < 10:
                continue
            l2_off = 5
            if len(pkt) < l2_off + 4:
                continue
            l2_cid = struct.unpack_from("<H", pkt, l2_off + 2)[0]
            if l2_cid == SMP_CID and len(pkt) > l2_off + 4:
                return pkt[l2_off + 4:]
        return None

    def _disconnect(self, hci, handle: int):
        params = struct.pack("<HB", handle, 0x13)
        try:
            self._hci_cmd(hci, 0x01, 0x0006, params)
        except Exception:
            pass
