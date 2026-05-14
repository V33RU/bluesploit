"""
BlueSploit raw Bluetooth helpers.

Low-level primitives that pure-Python pybluez/bleak don't expose:

  * Raw HCI socket (AF_BLUETOOTH / BTPROTO_HCI), send vendor commands,
    receive every event including LE Meta and SMP-bearing ACL frames.

  * L2CAP raw socket (BTPROTO_L2CAP) with SO_BTPROTO_L2CAP_FLUSHABLE so we
    can ship malformed packets a normal socket would refuse.

  * SMP / ATT / L2CAP signalling builders & parsers, enough to do
    real protocol-level attacks (KeySize=7 downgrade, invalid-curve,
    confirm reflection, signed-write forgery, …).

Everything here is deliberately permissive: callers are pentest modules,
they want to send broken packets on purpose. We do NOT validate fields.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from typing import Optional, Tuple

# ── socket level constants ───────────────────────────────────────────────────

AF_BLUETOOTH       = 31
BTPROTO_HCI        = 1
BTPROTO_L2CAP      = 0
SOL_HCI            = 0
HCI_FILTER         = 2
HCI_CHANNEL_RAW    = 0
HCI_CHANNEL_USER   = 1
HCI_DEV_NONE       = 0xFFFF

# ── HCI packet types ─────────────────────────────────────────────────────────

HCI_COMMAND_PKT    = 0x01
HCI_ACL_DATA_PKT   = 0x02
HCI_SCO_DATA_PKT   = 0x03
HCI_EVENT_PKT      = 0x04

# ── HCI events of interest ───────────────────────────────────────────────────

EVT_CONN_COMPLETE       = 0x03
EVT_DISCONN_COMPLETE    = 0x05
EVT_AUTH_COMPLETE       = 0x06
EVT_CMD_COMPLETE        = 0x0E
EVT_CMD_STATUS          = 0x0F
EVT_LINK_KEY_REQ        = 0x17
EVT_LINK_KEY_NOTIFY     = 0x18
EVT_IO_CAP_REQ          = 0x31
EVT_IO_CAP_RSP          = 0x32
EVT_USER_CONFIRM_REQ    = 0x33
EVT_USER_PASSKEY_REQ    = 0x34
EVT_SIMPLE_PAIR_COMPL   = 0x36
EVT_LE_META             = 0x3E

# LE Meta sub-events
EVT_LE_CONN_COMPLETE    = 0x01
EVT_LE_ENH_CONN_COMPLETE = 0x0A
EVT_LE_ADV_REPORT       = 0x02
EVT_LE_LTK_REQ          = 0x05

# ── HCI commands (OGF | OCF) ─────────────────────────────────────────────────

OGF_LINK_CTL    = 0x01
OGF_LINK_POLICY = 0x02
OGF_HOST_CTL    = 0x03
OGF_INFO_PARAM  = 0x04
OGF_LE_CTL      = 0x08
OGF_VENDOR      = 0x3F

def opcode(ogf: int, ocf: int) -> int:
    return (ogf << 10) | ocf

OCF_INQUIRY                 = 0x0001
OCF_CREATE_CONN             = 0x0005
OCF_DISCONNECT              = 0x0006
OCF_AUTH_REQUESTED          = 0x0011
OCF_LINK_KEY_REPLY          = 0x000B
OCF_LINK_KEY_NEG_REPLY      = 0x000C
OCF_PIN_CODE_REPLY          = 0x000D
OCF_USER_CONFIRM_REPLY      = 0x002C
OCF_USER_CONFIRM_NEG_REPLY  = 0x002D
OCF_IO_CAP_REPLY            = 0x002B
OCF_IO_CAP_NEG_REPLY        = 0x0034
OCF_LE_SET_SCAN_PARAMS      = 0x000B
OCF_LE_SET_SCAN_ENABLE      = 0x000C
OCF_LE_CREATE_CONN          = 0x000D
OCF_LE_LTK_REPLY            = 0x001A
OCF_LE_LTK_NEG_REPLY        = 0x001B

# ── L2CAP signalling channels & opcodes ──────────────────────────────────────

L2CAP_CID_SIGNALING     = 0x0001
L2CAP_CID_LE_SIGNALING  = 0x0005
L2CAP_CID_ATT           = 0x0004
L2CAP_CID_SMP           = 0x0006

L2CAP_CMD_REJ           = 0x01
L2CAP_CONN_REQ          = 0x02
L2CAP_CONN_RSP          = 0x03
L2CAP_CONFIG_REQ        = 0x04
L2CAP_CONFIG_RSP        = 0x05
L2CAP_DISCONN_REQ       = 0x06
L2CAP_DISCONN_RSP       = 0x07
L2CAP_INFO_REQ          = 0x0A
L2CAP_INFO_RSP          = 0x0B

# ── SMP opcodes (BT Core 5.x Vol 3 Part H §3.3) ──────────────────────────────

SMP_PAIRING_REQ         = 0x01
SMP_PAIRING_RSP         = 0x02
SMP_PAIRING_CONFIRM     = 0x03
SMP_PAIRING_RANDOM      = 0x04
SMP_PAIRING_FAILED      = 0x05
SMP_ENCRYPTION_INFO     = 0x06
SMP_MASTER_IDENT        = 0x07
SMP_IDENT_INFO          = 0x08
SMP_IDENT_ADDR_INFO     = 0x09
SMP_SIGNING_INFO        = 0x0A
SMP_SECURITY_REQ        = 0x0B
SMP_PAIRING_PUBLIC_KEY  = 0x0C
SMP_PAIRING_DHKEY_CHECK = 0x0D
SMP_KEYPRESS_NOTIF      = 0x0E

# SMP IO caps
IO_DISPLAY_ONLY     = 0x00
IO_DISPLAY_YESNO    = 0x01
IO_KEYBOARD_ONLY    = 0x02
IO_NO_INPUT_NO_OUT  = 0x03
IO_KEYBOARD_DISPLAY = 0x04

# SMP AuthReq bits
AUTH_BOND       = 0x01
AUTH_MITM       = 0x04
AUTH_SC         = 0x08
AUTH_KEYPRESS   = 0x10
AUTH_CT2        = 0x20

# SMP key-distribution mask bits
KD_ENC_KEY  = 0x01
KD_ID_KEY   = 0x02
KD_SIGN_KEY = 0x04
KD_LINK_KEY = 0x08

# SMP failure reasons
SMP_FAIL_PASSKEY_ENTRY      = 0x01
SMP_FAIL_OOB_NOT_AVAIL      = 0x02
SMP_FAIL_AUTH_REQS          = 0x03
SMP_FAIL_CONFIRM_VAL        = 0x04
SMP_FAIL_PAIRING_NOT_SUPP   = 0x05
SMP_FAIL_ENC_KEY_SIZE       = 0x06
SMP_FAIL_CMD_NOT_SUPP       = 0x07
SMP_FAIL_UNSPEC             = 0x08
SMP_FAIL_REPEATED_ATTEMPTS  = 0x09
SMP_FAIL_INVALID_PARAMS     = 0x0A
SMP_FAIL_DHKEY_CHECK        = 0x0B
SMP_FAIL_NUMERIC_COMPAR     = 0x0C
SMP_FAIL_BREDR_PAIR_INPROG  = 0x0D
SMP_FAIL_CTKD_NOT_ALLOWED   = 0x0E

# ── ATT opcodes ─────────────────────────────────────────────────────────────

ATT_ERROR_RSP            = 0x01
ATT_EXCHANGE_MTU_REQ     = 0x02
ATT_EXCHANGE_MTU_RSP     = 0x03
ATT_FIND_INFO_REQ        = 0x04
ATT_FIND_INFO_RSP        = 0x05
ATT_FIND_BY_TYPE_REQ     = 0x06
ATT_FIND_BY_TYPE_RSP     = 0x07
ATT_READ_BY_TYPE_REQ     = 0x08
ATT_READ_BY_TYPE_RSP     = 0x09
ATT_READ_REQ             = 0x0A
ATT_READ_RSP             = 0x0B
ATT_READ_BLOB_REQ        = 0x0C
ATT_READ_BLOB_RSP        = 0x0D
ATT_READ_MULTI_REQ       = 0x0E
ATT_READ_MULTI_RSP       = 0x0F
ATT_READ_BY_GROUP_REQ    = 0x10
ATT_READ_BY_GROUP_RSP    = 0x11
ATT_WRITE_REQ            = 0x12
ATT_WRITE_RSP            = 0x13
ATT_WRITE_CMD            = 0x52
ATT_SIGNED_WRITE_CMD     = 0xD2
ATT_HANDLE_VALUE_NOTIF   = 0x1B
ATT_HANDLE_VALUE_IND     = 0x1D
ATT_HANDLE_VALUE_CONF    = 0x1E


# ── helpers ──────────────────────────────────────────────────────────────────

def bdaddr_to_bytes(addr: str) -> bytes:
    """'AA:BB:CC:DD:EE:FF' -> 6 bytes little-endian."""
    return bytes(int(b, 16) for b in addr.split(":")[::-1])


def bytes_to_bdaddr(buf: bytes) -> str:
    return ":".join(f"{b:02X}" for b in buf[::-1])


def hci_dev_id(iface: str) -> int:
    """'hci0' -> 0, 'hci3' -> 3."""
    if not iface.startswith("hci"):
        raise ValueError(f"invalid hci iface {iface!r}")
    return int(iface[3:])


# ── Raw HCI socket ───────────────────────────────────────────────────────────

class HCIRawSocket:
    """
    Raw HCI socket bound to an adapter. Sends commands, receives every event.

    Usage:
        with HCIRawSocket("hci0") as s:
            s.send_cmd(opcode(OGF_LINK_CTL, OCF_INQUIRY), b"\\x33\\x8b\\x9e\\x10\\x00")
            evt = s.recv_event(timeout=2)
    """

    def __init__(self, iface: str = "hci0"):
        self.dev_id = hci_dev_id(iface)
        self.sock: Optional[socket.socket] = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *_):
        self.close()

    def open(self) -> None:
        s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        # Bind: struct sockaddr_hci { sa_family_t family; uint16_t hci_dev; uint16_t hci_channel; }
        s.bind((self.dev_id,))
        # All-events filter (type-mask=event, event-mask=all-set)
        flt = struct.pack(
            "IIIH2x",
            1 << HCI_EVENT_PKT,   # type_mask
            0xFFFFFFFF,           # event_mask[0]
            0xFFFFFFFF,           # event_mask[1]
            0,                    # opcode
        )
        try:
            s.setsockopt(SOL_HCI, HCI_FILTER, flt)
        except OSError:
            pass
        s.settimeout(2.0)
        self.sock = s

    def close(self) -> None:
        if self.sock:
            try: self.sock.close()
            except Exception: pass
            self.sock = None

    def send_cmd(self, op: int, params: bytes = b"") -> None:
        """Send an HCI command. op = opcode(OGF, OCF)."""
        pkt = struct.pack("<BHB", HCI_COMMAND_PKT, op, len(params)) + params
        assert self.sock
        self.sock.send(pkt)

    def send_acl(self, handle: int, flags: int, data: bytes) -> None:
        """Send an HCI ACL data packet. flags are PB+BC (typically 0b00 for first frag)."""
        h = (handle & 0x0FFF) | ((flags & 0x000F) << 12)
        pkt = struct.pack("<BHH", HCI_ACL_DATA_PKT, h, len(data)) + data
        assert self.sock
        self.sock.send(pkt)

    def recv_event(self, timeout: float = 2.0) -> Optional[Tuple[int, bytes]]:
        """Receive next HCI event. Returns (event_code, params) or None on timeout."""
        if not self.sock:
            return None
        self.sock.settimeout(timeout)
        try:
            buf = self.sock.recv(2048)
        except socket.timeout:
            return None
        except OSError:
            return None
        if len(buf) < 3 or buf[0] != HCI_EVENT_PKT:
            return None
        evt_code = buf[1]
        plen = buf[2]
        return evt_code, buf[3:3 + plen]

    def fileno(self) -> int:
        return self.sock.fileno() if self.sock else -1


# ── L2CAP signalling builder ─────────────────────────────────────────────────

def l2cap_pdu(cid: int, payload: bytes) -> bytes:
    """Wrap payload in L2CAP B-frame (length, channel-id, payload)."""
    return struct.pack("<HH", len(payload), cid) + payload


def l2cap_conn_req(psm: int, scid: int, ident: int = 1) -> bytes:
    """Build a complete L2CAP signalling Connection Request frame."""
    code = L2CAP_CONN_REQ
    data = struct.pack("<HH", psm, scid)
    sig = struct.pack("<BBH", code, ident, len(data)) + data
    return l2cap_pdu(L2CAP_CID_SIGNALING, sig)


def l2cap_disconn_req(dcid: int, scid: int, ident: int = 1) -> bytes:
    data = struct.pack("<HH", dcid, scid)
    sig = struct.pack("<BBH", L2CAP_DISCONN_REQ, ident, len(data)) + data
    return l2cap_pdu(L2CAP_CID_SIGNALING, sig)


# ── SMP packet builders ──────────────────────────────────────────────────────

def smp_pairing_req(
    io_cap: int = IO_NO_INPUT_NO_OUT,
    oob: int = 0,
    auth_req: int = AUTH_BOND,
    max_key_size: int = 16,
    init_key_dist: int = KD_ENC_KEY | KD_ID_KEY | KD_SIGN_KEY,
    rsp_key_dist: int = KD_ENC_KEY | KD_ID_KEY | KD_SIGN_KEY,
) -> bytes:
    """Build a Pairing Request PDU (SMP opcode 0x01)."""
    return struct.pack("BBBBBBB",
                       SMP_PAIRING_REQ, io_cap, oob, auth_req,
                       max_key_size, init_key_dist, rsp_key_dist)


def smp_pairing_rsp(*args, **kwargs) -> bytes:
    """Same fields as Pairing Request, opcode 0x02."""
    pkt = bytearray(smp_pairing_req(*args, **kwargs))
    pkt[0] = SMP_PAIRING_RSP
    return bytes(pkt)


def smp_pairing_confirm(value: bytes) -> bytes:
    """Pairing Confirm: 16-byte cnf value."""
    if len(value) != 16:
        raise ValueError("Confirm must be 16 bytes")
    return bytes([SMP_PAIRING_CONFIRM]) + value


def smp_pairing_random(value: bytes) -> bytes:
    if len(value) != 16:
        raise ValueError("Random must be 16 bytes")
    return bytes([SMP_PAIRING_RANDOM]) + value


def smp_pairing_failed(reason: int) -> bytes:
    return bytes([SMP_PAIRING_FAILED, reason & 0xFF])


def smp_public_key(x: bytes, y: bytes) -> bytes:
    """LE Secure Connections Pairing Public Key (opcode 0x0C)."""
    if len(x) != 32 or len(y) != 32:
        raise ValueError("Public key X/Y must be 32 bytes each")
    return bytes([SMP_PAIRING_PUBLIC_KEY]) + x + y


def smp_dhkey_check(value: bytes) -> bytes:
    if len(value) != 16:
        raise ValueError("DHKey Check must be 16 bytes")
    return bytes([SMP_PAIRING_DHKEY_CHECK]) + value


def smp_security_request(auth_req: int = AUTH_BOND | AUTH_SC) -> bytes:
    return bytes([SMP_SECURITY_REQ, auth_req & 0xFF])


def parse_smp(pkt: bytes) -> Optional[Tuple[int, bytes]]:
    """Return (opcode, body) or None if too short."""
    if not pkt:
        return None
    return pkt[0], pkt[1:]


# ── ATT helpers ──────────────────────────────────────────────────────────────

def att_write_cmd(handle: int, value: bytes) -> bytes:
    """ATT Write Command (opcode 0x52)."""
    return struct.pack("<BH", ATT_WRITE_CMD, handle) + value


def att_signed_write_cmd(handle: int, value: bytes, signature: bytes,
                         counter: int) -> bytes:
    """
    ATT Signed Write Command (opcode 0xD2).
    Frame: opcode | handle | value | counter (4 LE) | sig (8 bytes, MSB of CMAC)
    """
    if len(signature) != 8:
        raise ValueError("signature must be 8 bytes (truncated AES-CMAC)")
    return (struct.pack("<BH", ATT_SIGNED_WRITE_CMD, handle)
            + value + struct.pack("<I", counter & 0xFFFFFFFF) + signature)


def att_read_req(handle: int) -> bytes:
    return struct.pack("<BH", ATT_READ_REQ, handle)


def att_write_req(handle: int, value: bytes) -> bytes:
    return struct.pack("<BH", ATT_WRITE_REQ, handle) + value


# ── AES-CMAC for signed-write forgery (RFC 4493) ─────────────────────────────

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_cmac(key: bytes, msg: bytes) -> bytes:
    """
    Pure RFC 4493 AES-CMAC. Used by ATT signed writes (CSRK).
    16-byte key, returns 16-byte MAC.
    """
    try:
        from Crypto.Cipher import AES
    except ImportError:
        from cryptography.hazmat.backends import default_backend

        # cryptography path: build CMAC directly
        from cryptography.hazmat.primitives import cmac as _cmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = _cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(msg)
        return c.finalize()
    # PyCryptodome path
    if len(key) != 16:
        raise ValueError("AES-CMAC key must be 16 bytes")

    def _aes_encrypt(k: bytes, b: bytes) -> bytes:
        return AES.new(k, AES.MODE_ECB).encrypt(b)

    Rb = 0x87
    L = _aes_encrypt(key, b"\x00" * 16)
    L_int = int.from_bytes(L, "big")
    K1_int = (L_int << 1) & ((1 << 128) - 1)
    if L_int >> 127:
        K1_int ^= Rb
    K2_int = (K1_int << 1) & ((1 << 128) - 1)
    if K1_int >> 127:
        K2_int ^= Rb
    K1 = K1_int.to_bytes(16, "big")
    K2 = K2_int.to_bytes(16, "big")

    n = (len(msg) + 15) // 16 if msg else 1
    last_complete = (len(msg) > 0) and (len(msg) % 16 == 0)

    if last_complete:
        last = _xor_bytes(msg[-16:], K1)
        body = msg[:-16]
    else:
        rem = len(msg) % 16
        padded = msg[-rem:] if rem else b""
        padded = padded + b"\x80" + b"\x00" * (15 - len(padded))
        last = _xor_bytes(padded, K2)
        body = msg[:-rem] if rem else msg

    X = b"\x00" * 16
    for i in range(n - 1):
        block = body[i * 16:(i + 1) * 16]
        X = _aes_encrypt(key, _xor_bytes(X, block))
    return _aes_encrypt(key, _xor_bytes(X, last))


# ── L2CAP raw socket convenience ─────────────────────────────────────────────

def l2cap_connect(target_bdaddr: str, psm: int, src_iface: str = "hci0",
                  timeout: float = 5.0) -> socket.socket:
    """
    Open an L2CAP socket to (target, PSM). Caller closes.
    Raises OSError on failure.
    """
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    s.settimeout(timeout)
    # Bind to specific source adapter
    try:
        src = (b"\x00" * 6, 0)  # any
        s.bind((b"\x00" * 6, 0))
    except OSError:
        pass
    # struct sockaddr_l2 { family; psm; bdaddr; cid; bdaddr_type; }
    addr = (target_bdaddr, psm)
    s.connect(addr)
    return s


# ── L2CAP raw ATT channel (CID 4) for signed-write etc ──────────────────────

# struct sockaddr_l2 {
#   sa_family_t   l2_family;
#   __le16        l2_psm;
#   bdaddr_t      l2_bdaddr;
#   __le16        l2_cid;
#   __u8          l2_bdaddr_type;
# };
# 14 bytes total.

BDADDR_BREDR      = 0x00
BDADDR_LE_PUBLIC  = 0x01
BDADDR_LE_RANDOM  = 0x02

SOL_BLUETOOTH = 274
BT_SECURITY   = 4
BT_SECURITY_LOW = 1


def _pack_sockaddr_l2(bdaddr: str, psm: int = 0, cid: int = 0,
                      addr_type: int = BDADDR_LE_PUBLIC) -> bytes:
    """Pack a struct sockaddr_l2 for AF_BLUETOOTH/L2CAP."""
    addr_bytes = bdaddr_to_bytes(bdaddr)
    return struct.pack("<HH6sHB", AF_BLUETOOTH, psm, addr_bytes, cid, addr_type)


def l2cap_att_connect(target: str, src_iface: str = "hci0",
                      addr_type: int = BDADDR_LE_PUBLIC,
                      timeout: float = 8.0) -> socket.socket:
    """
    Open an L2CAP socket on the fixed ATT channel (CID 4) to a BLE peer.

    Linux BlueZ supports this since 3.x; the connection rides over the LE link.
    Caller can then send raw ATT PDUs (incl. opcode 0xD2 Signed Write) and
    read responses.
    """
    s = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
    s.settimeout(timeout)

    # Bind to local adapter, ATT CID, matching addr_type
    src_dev = hci_dev_id(src_iface)
    # Get the local BD_ADDR of src_iface
    try:
        out = os.popen(f"hciconfig {src_iface}").read()
        m = None
        for line in out.splitlines():
            if "BD Address:" in line:
                m = line.split("BD Address:")[1].strip().split()[0]
                break
        local_bdaddr = m or "00:00:00:00:00:00"
    except Exception:
        local_bdaddr = "00:00:00:00:00:00"

    bind_addr = _pack_sockaddr_l2(local_bdaddr, psm=0, cid=L2CAP_CID_ATT,
                                  addr_type=addr_type)
    try:
        s.bind(bind_addr)
    except OSError:
        # Some kernels reject explicit bind on ATT, try anonymous
        s.bind(_pack_sockaddr_l2("00:00:00:00:00:00", psm=0, cid=L2CAP_CID_ATT,
                                 addr_type=addr_type))

    # BT_SECURITY = LOW so the kernel doesn't insist on encryption (we want
    # to send unencrypted signed writes)
    try:
        s.setsockopt(SOL_BLUETOOTH, BT_SECURITY,
                     struct.pack("II", BT_SECURITY_LOW, 0))
    except OSError:
        pass

    connect_addr = _pack_sockaddr_l2(target, psm=0, cid=L2CAP_CID_ATT,
                                     addr_type=addr_type)
    s.connect(connect_addr)
    return s


def att_send_pdu(target: str, pdu: bytes, src_iface: str = "hci0",
                 addr_type: int = BDADDR_LE_PUBLIC,
                 expect_response: bool = False, timeout: float = 4.0
                 ) -> Tuple[bool, Optional[bytes], Optional[str]]:
    """
    Send a single ATT PDU on a fresh L2CAP CID-4 connection.
    Returns (ok, response_or_none, error_or_none).
    """
    sock: Optional[socket.socket] = None
    try:
        sock = l2cap_att_connect(target, src_iface, addr_type, timeout)
        sock.send(pdu)
        if not expect_response:
            return True, None, None
        sock.settimeout(timeout)
        try:
            rsp = sock.recv(4096)
            return True, rsp, None
        except socket.timeout:
            return True, None, None
    except OSError as e:
        return False, None, f"{e.__class__.__name__}: {e}"
    finally:
        if sock:
            try: sock.close()
            except Exception: pass


# ── verifying running as root ────────────────────────────────────────────────

def require_root() -> bool:
    return os.geteuid() == 0
