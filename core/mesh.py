"""
Bluetooth Mesh cryptographic primitives.

Implements only the building blocks Bluesploit's Mesh modules need.
Every function is paired with the Mesh Profile spec section it
implements and a published test vector covered by the test suite.

Spec reference: Bluetooth Mesh Profile v1.1, section 3.8 (Security).
"""

from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Mesh Profile constants (section 3.8.2 et seq.).
SALT_S1_INPUT_NID = b"smk2"   # used in K2 derivation
SALT_S1_INPUT_BK  = b"smk3"   # used in K3 (Network ID)
SALT_S1_INPUT_AID = b"smk4"   # used in K4


# ---------------------------------------------------------------------------
# Mesh Profile 3.8.2.1: s1 = AES-CMAC(ZERO_KEY, M)
# ---------------------------------------------------------------------------


def s1(m: bytes) -> bytes:
    """Mesh `s1` salt function. Returns 16 bytes."""
    return aes_cmac(b"\x00" * 16, m)


# ---------------------------------------------------------------------------
# Mesh Profile 3.8.2.2: AES-CMAC
# ---------------------------------------------------------------------------


def aes_cmac(key: bytes, message: bytes) -> bytes:
    """AES-CMAC over `message` with the 128-bit `key`. Returns 16 bytes."""
    if len(key) != 16:
        raise ValueError(f"CMAC key must be 16 bytes, got {len(key)}")
    c = cmac.CMAC(algorithms.AES(key))
    c.update(message)
    return c.finalize()


# ---------------------------------------------------------------------------
# Mesh Profile 3.8.2.3: K1 = AES-CMAC(T, P) where T = AES-CMAC(SALT, N)
# ---------------------------------------------------------------------------


def k1(n: bytes, salt: bytes, p: bytes) -> bytes:
    """Mesh K1 derivation. Returns 16 bytes."""
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)


# ---------------------------------------------------------------------------
# Mesh Profile 3.8.2.4: K2 derives NID + EncryptionKey + PrivacyKey
#   T   = AES-CMAC(SALT, NetKey) where SALT = s1("smk2")
#   T1  = AES-CMAC(T,    P || 0x01)
#   T2  = AES-CMAC(T,    T1 || P || 0x02)
#   T3  = AES-CMAC(T,    T2 || P || 0x03)
#   NID = T1[15] & 0x7F   (low 7 bits)
#   EncryptionKey = T2
#   PrivacyKey    = T3
# ---------------------------------------------------------------------------


def k2(net_key: bytes, p: bytes) -> Tuple[int, bytes, bytes]:
    """Mesh K2 derivation. Returns `(NID, EncryptionKey, PrivacyKey)`."""
    if len(net_key) != 16:
        raise ValueError(f"NetKey must be 16 bytes, got {len(net_key)}")
    salt = s1(SALT_S1_INPUT_NID)
    t  = aes_cmac(salt, net_key)
    t1 = aes_cmac(t, p + b"\x01")
    t2 = aes_cmac(t, t1 + p + b"\x02")
    t3 = aes_cmac(t, t2 + p + b"\x03")
    nid = t1[-1] & 0x7F
    return nid, t2, t3


# ---------------------------------------------------------------------------
# Mesh Profile 3.8.2.5: K3 derives the 64-bit Network ID
#   T  = AES-CMAC(SALT, NetKey) where SALT = s1("smk3")
#   K3 = AES-CMAC(T,  "id64\x01") truncated to low 8 bytes
# ---------------------------------------------------------------------------


def k3(net_key: bytes) -> bytes:
    """Mesh K3 derivation. Returns 8-byte Network ID."""
    if len(net_key) != 16:
        raise ValueError(f"NetKey must be 16 bytes, got {len(net_key)}")
    salt = s1(SALT_S1_INPUT_BK)
    t = aes_cmac(salt, net_key)
    out = aes_cmac(t, b"id64\x01")
    return out[-8:]


# ---------------------------------------------------------------------------
# Mesh Profile 3.8.2.6: K4 derives 6-bit AID from AppKey
#   T  = AES-CMAC(SALT, AppKey) where SALT = s1("smk4")
#   K4 = AES-CMAC(T,  "id6\x01")  AID = low 6 bits of K4[15]
# ---------------------------------------------------------------------------


def k4(app_key: bytes) -> int:
    """Mesh K4 derivation. Returns 6-bit AID (0..0x3F)."""
    if len(app_key) != 16:
        raise ValueError(f"AppKey must be 16 bytes, got {len(app_key)}")
    salt = s1(SALT_S1_INPUT_AID)
    t = aes_cmac(salt, app_key)
    out = aes_cmac(t, b"id6\x01")
    return out[-1] & 0x3F


# ---------------------------------------------------------------------------
# Network PDU decryption.
#
# Mesh Profile 3.4.4 / 3.8.7:
#   Obfuscation:
#     PECB = e(PrivacyKey, 0x0000000000 || IVIndex || EncDST||TransportPDU[0..6])
#            then PrivacyHeader = (CTL||TTL||SEQ||SRC) XOR PECB[0..5]
#   Network MIC + encryption:
#     CCM(EncryptionKey, Nonce, DST||TransportPDU)
#     where Nonce = 00 || (CTL << 7 | TTL) || SEQ || SRC || 0x0000 || IVIndex
# ---------------------------------------------------------------------------


def deobfuscate_network_header(
    privacy_key: bytes,
    iv_index: int,
    encrypted_data: bytes,
) -> bytes:
    """Return the 6-byte plaintext (CTL||TTL||SEQ||SRC) given the privacy
    key, IV index, and the encrypted payload (DST||TransportPDU portion).

    `encrypted_data` must be at least 7 bytes (the spec uses the first
    7 bytes of the encrypted Network PDU payload as PECB input).
    """
    if len(privacy_key) != 16:
        raise ValueError(f"PrivacyKey must be 16 bytes, got {len(privacy_key)}")
    if len(encrypted_data) < 7:
        raise ValueError("need >=7 bytes of encrypted data for PECB input")
    privacy_random = encrypted_data[:7]
    pecb_input = b"\x00" * 5 + iv_index.to_bytes(4, "big") + privacy_random
    enc = Cipher(algorithms.AES(privacy_key), modes.ECB()).encryptor()
    pecb = enc.update(pecb_input) + enc.finalize()
    return pecb[:6]


def network_nonce(
    ctl: int, ttl: int, seq: int, src: int, iv_index: int,
) -> bytes:
    """Construct the 13-byte Network Nonce per Mesh Profile 3.8.5.1."""
    pad = ((ctl & 0x01) << 7) | (ttl & 0x7F)
    return bytes([
        0x00,                           # Nonce Type = Network
        pad,
        (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF,
        (src >> 8) & 0xFF, src & 0xFF,
        0x00, 0x00,                     # padding
    ]) + iv_index.to_bytes(4, "big")


def decrypt_network_payload(
    encryption_key: bytes,
    nonce: bytes,
    encrypted_with_mic: bytes,
    net_mic_size: int,
) -> bytes:
    """Decrypt the (DST||TransportPDU)||NetMIC blob. Returns the
    plaintext DST||TransportPDU on success; raises on MIC failure.

    `net_mic_size` is 4 for access messages (CTL=0) and 8 for control
    messages (CTL=1), per Mesh Profile 3.4.4.3.
    """
    if len(encryption_key) != 16:
        raise ValueError(f"EncryptionKey must be 16 bytes, got {len(encryption_key)}")
    aead = AESCCM(encryption_key, tag_length=net_mic_size)
    # Mesh Network PDUs have no Associated Data.
    return aead.decrypt(nonce, encrypted_with_mic, None)
