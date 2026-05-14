"""
Bluetooth-specific cryptographic primitives.

Implements only what the framework needs for key analysis and
Resolvable Private Address verification. No new crypto math; we use
`cryptography.hazmat` for AES-128. Each function is annotated with
the spec section it implements so reviewers can audit against the
Core Spec.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, List, Optional, Tuple  # noqa: F401

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------------------------------------------------------------------
# Byte parsing helpers
# ---------------------------------------------------------------------------


_HEX_RE = re.compile(r"[^0-9a-fA-F]")


def parse_hex_blob(value: str) -> bytes:
    """Accept a hex string in any of:
        'aabbccdd'
        'AA:BB:CC:DD'
        'aa bb cc dd'
        '0xAABBCCDD'
    and return the bytes. Raises ValueError if non-hex chars remain
    after stripping separators and the result is odd-length.
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


def parse_bd_addr(addr: str) -> bytes:
    """Parse 'AA:BB:CC:DD:EE:FF' into 6 bytes in transmission order
    (most-significant first as written). Raises ValueError on bad
    input."""
    parts = addr.strip().split(":")
    if len(parts) != 6:
        raise ValueError(f"BD_ADDR must be 6 octets, got {addr!r}")
    out = bytearray()
    for p in parts:
        if len(p) != 2:
            raise ValueError(f"BD_ADDR octet must be 2 hex chars: {p!r}")
        out.append(int(p, 16))
    return bytes(out)


# ---------------------------------------------------------------------------
# AES primitives
# ---------------------------------------------------------------------------


def aes128_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Single-block AES-128 ECB. Both inputs must be 16 bytes."""
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if len(plaintext) != 16:
        raise ValueError(f"AES block must be 16 bytes, got {len(plaintext)}")
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(plaintext) + enc.finalize()


# ---------------------------------------------------------------------------
# Core Spec primitive: ah (random address hash)
# ---------------------------------------------------------------------------
#
# Defined in Core Spec v5.4 Vol 3 Part H section 2.2.2.
#
#   ah(k, r) = e(k, r') mod 2^24
#
# where:
#   - k  is the 128-bit IRK
#   - r  is a 24-bit (3 octet) random value, the upper half of the RPA
#   - r' is r zero-padded to 128 bits on the most-significant side
#   - e  is single-block AES-128 ECB
#
# The output is the low 24 bits of the AES ciphertext.


def ah(irk: bytes, prand: bytes) -> bytes:
    """Compute the BLE Random Address Hash function `ah` per Core Spec
    Vol 3 Part H 2.2.2.

    Args:
        irk:   16 bytes, the Identity Resolving Key.
        prand: 3 bytes, the random part of an RPA.

    Returns:
        3 bytes, the low 24 bits of e(irk, r').
    """
    if len(irk) != 16:
        raise ValueError(f"IRK must be 16 bytes, got {len(irk)}")
    if len(prand) != 3:
        raise ValueError(f"prand must be 3 bytes, got {len(prand)}")
    # r' = 0^104 || prand   (big-endian per spec)
    r_padded = b"\x00" * 13 + prand
    ct = aes128_ecb(irk, r_padded)
    return ct[-3:]   # low 24 bits


def is_resolvable_private(addr_bytes: bytes) -> bool:
    """True iff the address has top two bits 01 (RPA format).

    Per Core Spec Vol 6 Part B 1.3.2.2 the random part bits 47:46
    are '01' for a Resolvable Private Address. addr_bytes is in
    transmission order, so byte 0 holds the MSB.
    """
    if len(addr_bytes) != 6:
        return False
    return (addr_bytes[0] >> 6) == 0b01


def rpa_resolves(irk: bytes, addr: str) -> bool:
    """Test whether `irk` resolves the Resolvable Private Address `addr`.

    The RPA layout (Core Spec Vol 6 Part B 1.3.2.2) splits the 48-bit
    address into:
        addr[47:24] = prand  (top 3 bytes; bits 47:46 = 01)
        addr[23: 0] = hash   (low 3 bytes)

    The check is `ah(irk, prand) == hash`.

    Args:
        irk:  16 bytes.
        addr: 'AA:BB:CC:DD:EE:FF' colon-separated.

    Returns:
        True iff the IRK resolves the address. Returns False (does
        not raise) if the address is not in RPA form, so callers can
        bulk-test mixed lists.
    """
    try:
        ab = parse_bd_addr(addr)
    except ValueError:
        return False
    if not is_resolvable_private(ab):
        return False
    prand = ab[:3]
    expect_hash = ab[3:]
    return ah(irk, prand) == expect_hash


# ---------------------------------------------------------------------------
# Key-quality statistics
# ---------------------------------------------------------------------------


def shannon_entropy_bits(data: bytes) -> float:
    """Shannon entropy in bits per byte. Range 0..8.

    A uniformly random 128-bit key is expected close to 8.0 over
    many samples, though for short blobs (16 bytes) the empirical
    value is typically 3.5..4.5 due to limited sample size. We
    surface the raw number; the caller decides the threshold.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    h = 0.0
    for c in counts.values():
        p = c / n
        h -= p * math.log2(p)
    return h


def chi_square_uniform_bytes(data: bytes) -> Tuple[float, int]:
    """Pearson chi-square statistic of `data` against the uniform
    256-bin byte distribution.

    Returns:
        (statistic, degrees_of_freedom).

    For 16 bytes the degrees of freedom is 16 (one less than the
    sample size) and the expected statistic for true uniform is
    around 16; values >> 30 suggest non-uniformity. The caller is
    responsible for thresholding given the small sample.
    """
    if not data:
        return (0.0, 0)
    n = len(data)
    counts = Counter(data)
    # We collapse to the bins that actually occurred + zero-count
    # bins, but the chi-square test for small samples has limited
    # power. The statistic is informative, not a hard pass/fail.
    expected = n / 256
    chi = 0.0
    for byte in range(256):
        observed = counts.get(byte, 0)
        chi += (observed - expected) ** 2 / expected
    return (chi, n - 1)


def repeated_byte_runs(data: bytes) -> List[Tuple[int, int]]:
    """Find runs of >=3 identical consecutive bytes.

    Returns:
        List of (start_offset, run_length).
    """
    out: List[Tuple[int, int]] = []
    if len(data) < 3:
        return out
    i = 0
    while i < len(data):
        j = i
        while j < len(data) and data[j] == data[i]:
            j += 1
        if j - i >= 3:
            out.append((i, j - i))
        i = max(j, i + 1)
    return out


KNOWN_WEAK_KEYS: Dict[bytes, str] = {
    b"\x00" * 16:                                            "all-zero",
    b"\xFF" * 16:                                            "all-ones",
    bytes(range(16)):                                        "00..0F sequential",
    bytes(range(16, 32)):                                    "10..1F sequential",
    bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeef"):       "deadbeef test pattern",
    bytes.fromhex("00112233445566778899aabbccddeeff"):       "00..ff classic test",
    b"A" * 16:                                               "all 0x41 (ASCII A)",
    b"\x01" * 16:                                            "all 0x01",
}


def known_weak_match(data: bytes) -> Optional[str]:
    """Return a description if `data` matches a known weak/test key,
    else None."""
    return KNOWN_WEAK_KEYS.get(data)


def analyze_key(data: bytes) -> Dict[str, object]:
    """Run every key-quality check on `data` and return a verdict dict.

    The verdict is a short string suitable for a one-line summary.
    A 'PASS' verdict means no automatic red flag was found; it does
    NOT certify the key is secret or unguessable.

    Keys in the returned dict:
        raw, length, entropy_bits, chi_square, unique_bytes,
        repeated_runs, known_weak, all_ascii_printable, verdict.
    """
    weak = known_weak_match(data)
    entropy = shannon_entropy_bits(data)
    chi, _df = chi_square_uniform_bytes(data)
    runs = repeated_byte_runs(data)
    unique = len(set(data))
    ascii_only = all(0x20 <= b < 0x7F for b in data) if data else False

    verdict = _key_verdict(
        weak=weak, length=len(data), unique=unique,
        runs=runs, ascii_only=ascii_only, entropy=entropy,
    )

    return {
        "raw": data,
        "length": len(data),
        "entropy_bits": entropy,
        "chi_square": chi,
        "unique_bytes": unique,
        "repeated_runs": runs,
        "known_weak": weak,
        "all_ascii_printable": ascii_only,
        "verdict": verdict,
    }


def _key_verdict(
    *,
    weak: Optional[str],
    length: int,
    unique: int,
    runs: List[Tuple[int, int]],
    ascii_only: bool,
    entropy: float,
) -> str:
    if weak is not None:
        return f"FAIL: matches known weak key ({weak})"
    if length == 0:
        return "FAIL: empty key"
    if length < 7:
        return f"FAIL: key too short ({length} bytes)"
    if unique <= 2:
        return f"FAIL: only {unique} distinct byte value(s)"
    if ascii_only:
        return "WARN: key bytes are all ASCII printable; likely a passphrase, not random"
    if runs:
        worst = max(r[1] for r in runs)
        if worst >= length // 2:
            return f"FAIL: single byte repeats for {worst} of {length} positions"
        return f"WARN: repeated-byte run(s) detected (longest={worst})"
    if entropy < 2.5 and length >= 8:
        return f"WARN: low Shannon entropy ({entropy:.2f} bits/byte) for {length}-byte key"
    return "PASS: no automatic red flag"
