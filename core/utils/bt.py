"""
BlueSploit shared Bluetooth helpers.

A single home for the low-level plumbing that was duplicated across
the recon / scanner / DoS modules: raw HCI socket open, BD_ADDR parse,
LE address-type auto-detection, HCI command framing, ACL/L2CAP/SMP
framing, and feature-bit decoding.

Importable from any module under modules/ as:

    from core.utils.bt import (
        AF_BLUETOOTH, BTPROTO_HCI,
        HCI_COMMAND_PKT, HCI_ACL_PKT, HCI_EVENT_PKT, HCI_LE_META,
        LE_CONN_COMPLETE, LE_READ_FEATURES_COMPL,
        SMP_CID, ATT_CID,
        validate_bd_addr, parse_bd_addr, bd_addr_bytes,
        auto_addr_type, open_hci, hci_cmd,
        send_acl_l2cap, recv_l2cap, le_create_connection, disconnect,
        decode_bitmap,
    )

This module makes no I/O at import time; nothing here requires root or
a real adapter unless the function is actually called.
"""

from __future__ import annotations

import os
import re
import select
import socket
import struct
import time
from typing import Iterable, List, Optional, Tuple

# ── HCI socket family / packet type constants ─────────────────────────────

AF_BLUETOOTH    = 31
BTPROTO_HCI     = 1

HCI_COMMAND_PKT = 0x01
HCI_ACL_PKT     = 0x02
HCI_SCO_PKT     = 0x03
HCI_EVENT_PKT   = 0x04

# ── Common HCI event codes ────────────────────────────────────────────────

EVT_CMD_COMPLETE          = 0x0E
EVT_CMD_STATUS            = 0x0F
EVT_CONN_COMPLETE         = 0x03
EVT_DISCONN_COMPLETE      = 0x05
EVT_REMOTE_FEATURES_COMPL = 0x0B
EVT_REMOTE_EXT_FEAT_COMPL = 0x23
HCI_LE_META               = 0x3E

# ── LE meta sub-events ────────────────────────────────────────────────────

LE_CONN_COMPLETE       = 0x01
LE_READ_FEATURES_COMPL = 0x04

# ── L2CAP CIDs ────────────────────────────────────────────────────────────

ATT_CID         = 0x0004
SMP_CID         = 0x0006
L2CAP_SIG_CID   = 0x0005

# ── BD_ADDR helpers ───────────────────────────────────────────────────────

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def validate_bd_addr(address: str) -> bool:
    """Return True if `address` is a well-formed BD_ADDR (XX:XX:XX:XX:XX:XX)."""
    if not isinstance(address, str):
        return False
    return bool(_BD_ADDR_RE.match(address.strip()))


def parse_bd_addr(address: str) -> Tuple[int, int, int, int, int, int]:
    """Parse a BD_ADDR string into a 6-tuple of ints (high to low octet)."""
    if not validate_bd_addr(address):
        raise ValueError(f"Invalid BD_ADDR: {address!r}")
    parts = address.strip().split(":")
    return tuple(int(x, 16) for x in parts)  # type: ignore[return-value]


def bd_addr_bytes(address: str) -> bytes:
    """
    Return the 6-byte little-endian BD_ADDR encoding used on the HCI wire
    (least significant octet first).
    """
    octets = parse_bd_addr(address)
    return bytes(reversed(octets))


def auto_addr_type(address: str) -> str:
    """
    Heuristic LE address-type detection from the address bits alone.

    Per BT Core Spec Vol 6 Part B §1.3.2, the top two bits of the MSB
    classify random BLE addresses:
        11 -> Static Random
        01 -> Resolvable Private
        00 -> Non-Resolvable Private
    Anything else is treated as a public address.
    """
    if not validate_bd_addr(address):
        raise ValueError(f"Invalid BD_ADDR: {address!r}")
    msb = int(address.split(":")[0], 16) >> 6
    if msb in (0b11, 0b01, 0b00):
        # 00 is technically non-resolvable private (still random), but real
        # public addresses fall here too. We bias toward 'public' for 00
        # because true non-resolvable randoms are vanishingly rare in the
        # wild and treating them as public still succeeds for OUI lookup.
        return "random" if msb in (0b11, 0b01) else "public"
    return "public"


# ── Raw HCI socket helpers ────────────────────────────────────────────────


class HCIError(OSError):
    """Raised by helpers that need an HCI socket but cannot get one."""


def require_root() -> None:
    """Raise PermissionError if not running as root (Linux only)."""
    if hasattr(os, "geteuid") and os.geteuid() != 0:  # type: ignore[attr-defined]
        raise PermissionError("Root required for raw HCI socket access")


def open_hci(iface: str = "hci0") -> socket.socket:
    """
    Open a raw HCI socket bound to `iface` ("hci0", "hci1", ...).

    Raises HCIError with a useful message on failure.
    """
    try:
        dev_id = int(iface.replace("hci", ""))
    except ValueError as e:
        raise HCIError(f"invalid HCI interface name {iface!r}") from e

    try:
        s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
        s.bind((dev_id,))
        return s
    except OSError as e:
        raise HCIError(f"HCI open failed on {iface}: {e}") from e


def hci_cmd(hci: socket.socket, ogf: int, ocf: int, params: bytes = b"") -> None:
    """Send a single HCI command packet."""
    opcode = (ogf << 10) | ocf
    pkt = struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params
    hci.setblocking(True)
    try:
        hci.send(pkt)
    finally:
        hci.setblocking(False)


def wait_event(hci: socket.socket, event_code: int, timeout: float = 10.0,
               max_pkt: int = 255) -> Optional[bytes]:
    """
    Wait for an HCI event with the given event code.

    Returns the event payload (everything after the 3-byte HCI header),
    or None on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([hci], [], [], 0.5)
        if not r:
            continue
        pkt = hci.recv(max_pkt)
        if pkt and pkt[0] == HCI_EVENT_PKT and len(pkt) >= 3 and pkt[1] == event_code:
            return pkt[3:]
    return None


def wait_le_meta(hci: socket.socket, sub_event: int, timeout: float = 12.0,
                 max_pkt: int = 255) -> Optional[bytes]:
    """
    Wait for an HCI LE Meta event with the given sub-event code.

    Returns the full packet (header included) so callers can use the same
    offsets the spec describes, or None on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([hci], [], [], 0.5)
        if not r:
            continue
        pkt = hci.recv(max_pkt)
        if (
            pkt
            and pkt[0] == HCI_EVENT_PKT
            and len(pkt) >= 4
            and pkt[1] == HCI_LE_META
            and pkt[3] == sub_event
        ):
            return pkt
    return None


# ── LE connection lifecycle ───────────────────────────────────────────────


def le_create_connection(hci: socket.socket, target: str, peer_at: int,
                         timeout: float = 12.0) -> Optional[int]:
    """
    Issue HCI_LE_Create_Connection and wait for LE Connection Complete.

    Returns the 12-bit connection handle on success, or None on timeout/error.
    """
    addr = bd_addr_bytes(target)
    params = struct.pack(
        "<HHBB6sBHHHHHH",
        0x0060,  # scan interval
        0x0030,  # scan window
        0x00,    # init filter policy (use peer addr)
        peer_at, # peer address type
        addr,
        0x00,    # own address type (public)
        0x0006,  # conn interval min
        0x000C,  # conn interval max
        0x0000,  # conn latency
        0x00C8,  # supervision timeout
        0x0000,  # min CE length
        0x0000,  # max CE length
    )
    hci_cmd(hci, 0x08, 0x000D, params)
    pkt = wait_le_meta(hci, LE_CONN_COMPLETE, timeout=timeout)
    if pkt and len(pkt) >= 7 and pkt[4] == 0x00:
        return struct.unpack_from("<H", pkt, 5)[0] & 0x0FFF
    return None


def disconnect(hci: socket.socket, handle: int, reason: int = 0x13) -> None:
    """HCI_Disconnect on a given connection handle. Ignores errors."""
    params = struct.pack("<HB", handle, reason)
    try:
        hci_cmd(hci, 0x01, 0x0006, params)
    except Exception:
        pass


# ── ACL / L2CAP framing ───────────────────────────────────────────────────


def send_acl_l2cap(hci: socket.socket, handle: int, cid: int, payload: bytes) -> None:
    """Wrap `payload` in L2CAP+ACL and send it on the given handle."""
    l2cap = struct.pack("<HH", len(payload), cid) + payload
    acl = struct.pack("<HH", handle | (0x00 << 12), len(l2cap)) + l2cap
    hci.setblocking(True)
    try:
        hci.send(bytes([HCI_ACL_PKT]) + acl)
    finally:
        hci.setblocking(False)


def recv_l2cap(hci: socket.socket, cid: int, timeout: float = 5.0,
               max_pkt: int = 512) -> Optional[bytes]:
    """
    Wait for an inbound ACL packet whose L2CAP CID matches `cid` and return
    the payload (after the 4-byte L2CAP header). None on timeout.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        r, _, _ = select.select([hci], [], [], 0.5)
        if not r:
            continue
        pkt = hci.recv(max_pkt)
        if not pkt or pkt[0] != HCI_ACL_PKT or len(pkt) < 10:
            continue
        l2_off = 5
        if len(pkt) < l2_off + 4:
            continue
        l2_cid = struct.unpack_from("<H", pkt, l2_off + 2)[0]
        if l2_cid == cid and len(pkt) > l2_off + 4:
            return pkt[l2_off + 4:]
    return None


# ── Feature bitmap decoding ───────────────────────────────────────────────


def decode_bitmap(data: bytes, names: Iterable[str]) -> List[Tuple[int, str]]:
    """
    Walk `data` MSB-LSB-friendly and yield (bit_index, name) for every set
    bit whose label is not "Reserved".
    """
    names = list(names)
    out: List[Tuple[int, str]] = []
    for byte_idx, byte in enumerate(data):
        for bit in range(8):
            idx = byte_idx * 8 + bit
            if idx >= len(names) or names[idx] == "Reserved":
                continue
            if byte & (1 << bit):
                out.append((idx, names[idx]))
    return out


def bitmap_to_dict(data: bytes, names: Iterable[str]) -> dict:
    """Same as decode_bitmap but returns a {name: True} dict for JSON output."""
    return {name: True for _idx, name in decode_bitmap(data, names)}
