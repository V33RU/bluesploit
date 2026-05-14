"""
BlueSploit Module: BLE Pairing Features Probe

Sends an SMP Pairing Request to a remote BLE device and parses the
Pairing Response to expose the peer's pairing capabilities, IO
Capability, OOB data flag, AuthReq (Bonding / MITM / Secure Connections /
Keypress / CT2), Maximum Encryption Key Size, and Initiator/Responder
Key Distribution flags.

This is a passive intelligence probe, the connection is dropped
before any actual key exchange takes place.
"""

import struct

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.utils.bt import (
    HCIError,
    SMP_CID,
    auto_addr_type,
    disconnect,
    le_create_connection,
    open_hci,
    recv_l2cap,
    require_root,
    send_acl_l2cap,
)
from core.utils.printer import (
    Colors,
    print_error,
    print_info,
    print_success,
    print_warning,
)

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
        try:
            require_root()
        except PermissionError as e:
            print_error(str(e))
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
            addr_type = auto_addr_type(target)
            print_info(f"Auto-detected address type: {addr_type}")

        peer_at = 0x01 if addr_type == "random" else 0x00

        print_info(f"Target   : {target} ({addr_type})")
        print_info(f"Interface: {iface}")
        print_info(f"We claim : IO={IO_NAMES.get(claim_io)}  auth_req=0x{claim_ar:02X}")

        try:
            hci = open_hci(iface)
        except HCIError as e:
            print_error(str(e))
            return False

        handle = None
        try:
            handle = le_create_connection(hci, target, peer_at)
            if handle is None:
                print_error("LE connection failed")
                return False
            print_success(f"LE connected (handle=0x{handle:04x})")

            pairing_req = struct.pack(
                "BBBBBBB",
                SMP_PAIRING_REQ, claim_io, 0x00, claim_ar,
                16, 0x0F, 0x0F,
            )
            print_info(f"Sending SMP Pairing Request: {pairing_req.hex()}")
            send_acl_l2cap(hci, handle, SMP_CID, pairing_req)

            resp = recv_l2cap(hci, SMP_CID, timeout=8)
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
                disconnect(hci, handle)
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
            print_warning("Peer accepts Legacy Pairing, vulnerable to passive eavesdrop "
                          "(crackle / KNOB-style downgrade)")
        if not mitm:
            print_warning("Peer does NOT require MITM protection, JustWorks attack possible")
        if max_key < 16:
            print_warning(f"Peer accepts {max_key}-byte key, KNOB-style downgrade possible")

        fp = {
            "target": target,
            "io_capability": IO_NAMES.get(io, f"0x{io:02x}"),
            "oob": bool(oob),
            "auth_req": f"0x{auth_req:02X}",
            "bonding": bonding, "mitm": mitm, "sc": sc,
            "keypress": keypress, "ct2": ct2,
            "max_key_size": max_key,
            "init_key_dist": f"0x{init_kd:02x}",
            "resp_key_dist": f"0x{resp_kd:02x}",
        }
        self.add_result(fp)
        self._persist_fingerprint(target, fp)

    def _persist_fingerprint(self, target: str, result: dict) -> None:
        """Store this fingerprint so the CVE-matching scanner can read it.

        Best-effort: any store failure prints a one-line warning and
        does not affect the recon module's primary return value.
        """
        try:
            self.store.add_host(address=target)
            self.store.add_fingerprint(
                host=target,
                kind="smp_pairing",
                data=result,
                source_module="recon/ble_pairing_features",
            )
            print_info("fingerprint recorded (smp_pairing)")
        except Exception as e:
            print_warning(f"fingerprint store skipped: {e}")

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
