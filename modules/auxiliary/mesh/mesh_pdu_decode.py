"""
Mesh Network PDU Decoder - offline K2 + PECB + AES-CCM decoder.

Ref: Mesh Profile v1.1 3.4 (Network Layer), 3.8 (Security)
"""

from __future__ import annotations

import re

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.mesh import (
    decrypt_network_payload,
    deobfuscate_network_header,
    k2,
    network_nonce,
)

_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def parse_hex_blob(value: str) -> bytes:
    """Local hex parser; same shape as core.crypto.parse_hex_blob.

    Accepts colon-, space-, or 0x-prefixed hex strings.
    """
    if value is None:
        raise ValueError("empty hex blob")
    s = value.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    s = _HEX_RE.sub("", s)
    if not s:
        raise ValueError("empty hex blob")
    if len(s) % 2:
        raise ValueError(f"odd-length hex blob ({len(s)} chars)")
    return bytes.fromhex(s)
from core.ui.tables import Column, render_table
from core.utils.printer import print_error, print_info, print_success, print_warning


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Mesh Network PDU Decoder",
        description="Offline decoder for a captured Bluetooth Mesh Network PDU using K2 and AES-CCM",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/mesh-protocol/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="pdu",
            required=True,
            description="Encrypted Mesh Network PDU as hex (IVI || NID || obfuscated header || encrypted DST/TransportPDU || NetMIC)",
        ))
        self.add_option(ModuleOption(
            name="netkey",
            required=True,
            description="16-byte NetKey as hex",
        ))
        self.add_option(ModuleOption(
            name="iv_index",
            required=False,
            description="32-bit IV Index (hex or decimal). Defaults to 0x12345678.",
            default="0x12345678",
        ))

    def run(self) -> bool:
        raw_pdu = self.get_option("pdu") or ""
        raw_key = self.get_option("netkey") or ""
        raw_iv  = self.get_option("iv_index") or "0x12345678"

        try:
            pdu = parse_hex_blob(raw_pdu)
            netkey = parse_hex_blob(raw_key)
        except ValueError as e:
            print_error(f"Could not parse hex: {e}")
            return False
        if len(netkey) != 16:
            print_error(f"NetKey must be 16 bytes, got {len(netkey)}")
            return False
        if len(pdu) < 14:
            print_error(
                f"Network PDU too short ({len(pdu)} bytes). Minimum is "
                "1 IVI/NID + 6 obfuscated header + 2 DST + 1 TransportPDU + 4 NetMIC."
            )
            return False

        try:
            iv_index = int(raw_iv, 0)
        except (TypeError, ValueError):
            print_error(f"iv_index {raw_iv!r} is not a number")
            return False

        result = decode_pdu(pdu, netkey, iv_index)
        if result.get("error"):
            print_error(result["error"])
            self._render(result)
            return False

        self._render(result)
        self.add_result(result)
        return True

    def _render(self, r: dict) -> None:
        cols = [Column("Field", style="cyan"), Column("Value")]
        rows = [
            ("IVI",            f"{r.get('ivi', '?')}"),
            ("PDU NID",        f"0x{r.get('pdu_nid', 0):02x}"),
            ("K2 NID",         f"0x{r.get('k2_nid', 0):02x}"),
            ("NID match",      "yes" if r.get("nid_match") else "NO"),
            ("CTL",            f"{r.get('ctl', '?')}"),
            ("TTL",            f"{r.get('ttl', '?')}"),
            ("SEQ",            f"0x{r.get('seq', 0):06x}"),
            ("SRC",            f"0x{r.get('src', 0):04x}"),
            ("DST",            f"0x{r.get('dst', 0):04x}"),
            ("TransportPDU",   r.get('transport_pdu_hex', '')),
            ("NetMIC (size)",  f"{r.get('net_mic_size', '?')} bytes"),
        ]
        render_table(cols, rows, title="Mesh Network PDU")
        if r.get("decrypted"):
            print_success("Network MIC verified; payload decrypted")
        elif "error" not in r:
            print_warning("Decryption failed (MIC mismatch)")


def decode_pdu(pdu: bytes, netkey: bytes, iv_index: int) -> dict:
    """Decode a Mesh Network PDU offline. Returns a dict with every
    field we can recover, plus an `error` key on failure.

    Wire format (Mesh Profile 3.4.4):
        byte 0       : IVI (1 bit) || NID (7 bits)
        bytes 1..6   : obfuscated CTL||TTL||SEQ||SRC
        bytes 7..    : encrypted DST || TransportPDU || NetMIC
    """
    ivi  = (pdu[0] >> 7) & 0x01
    nid  = pdu[0] & 0x7F
    obfuscated = pdu[1:7]
    encrypted_with_mic = pdu[7:]

    k2_nid, enc_key, priv_key = k2(netkey, b"\x00")
    if nid != k2_nid:
        return {
            "ivi": ivi, "pdu_nid": nid, "k2_nid": k2_nid,
            "nid_match": False,
            "error": (
                f"PDU NID 0x{nid:02x} does not match K2(NetKey) NID "
                f"0x{k2_nid:02x}. Wrong NetKey, or PDU is from a "
                f"different subnet."
            ),
        }

    # Deobfuscate the privacy header.
    pecb = deobfuscate_network_header(priv_key, iv_index, encrypted_with_mic)
    plain_hdr = bytes(a ^ b for a, b in zip(obfuscated, pecb))
    ctl = (plain_hdr[0] >> 7) & 0x01
    ttl = plain_hdr[0] & 0x7F
    seq = int.from_bytes(plain_hdr[1:4], "big")
    src = int.from_bytes(plain_hdr[4:6], "big")

    net_mic_size = 8 if ctl else 4

    nonce = network_nonce(ctl, ttl, seq, src, iv_index)
    try:
        plain = decrypt_network_payload(enc_key, nonce, encrypted_with_mic, net_mic_size)
    except Exception as e:
        return {
            "ivi": ivi, "pdu_nid": nid, "k2_nid": k2_nid, "nid_match": True,
            "ctl": ctl, "ttl": ttl, "seq": seq, "src": src,
            "net_mic_size": net_mic_size,
            "decrypted": False,
            "error": f"AES-CCM verify failed: {e}",
        }

    dst = int.from_bytes(plain[:2], "big")
    transport_pdu = plain[2:]
    return {
        "ivi": ivi, "pdu_nid": nid, "k2_nid": k2_nid, "nid_match": True,
        "ctl": ctl, "ttl": ttl, "seq": seq, "src": src,
        "dst": dst, "transport_pdu_hex": transport_pdu.hex(),
        "net_mic_size": net_mic_size,
        "decrypted": True,
    }
