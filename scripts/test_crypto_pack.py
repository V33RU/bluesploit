"""Tests for the crypto auxiliary pack:
  - core/crypto.py (primitives, ah, RPA resolution, key stats)
  - modules/auxiliary/crypto/key_quality.py
  - modules/auxiliary/crypto/irk_entropy.py
  - modules/auxiliary/crypto/passkey_check.py
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from core.crypto import (
    KNOWN_WEAK_KEYS,
    aes128_ecb,
    ah,
    chi_square_uniform_bytes,
    is_resolvable_private,
    known_weak_match,
    parse_bd_addr,
    parse_hex_blob,
    repeated_byte_runs,
    rpa_resolves,
    shannon_entropy_bits,
)
from core.loader import ModuleLoader
from core.store import get_store, reset_default_store

# ---------------------------------------------------------------------------
# core/crypto primitives
# ---------------------------------------------------------------------------


class TestParseHexBlob:
    def test_plain(self):
        assert parse_hex_blob("aabbccdd") == b"\xaa\xbb\xcc\xdd"

    def test_with_colons(self):
        assert parse_hex_blob("AA:BB:CC:DD") == b"\xaa\xbb\xcc\xdd"

    def test_with_0x_prefix(self):
        assert parse_hex_blob("0xAABB") == b"\xaa\xbb"

    def test_spaces(self):
        assert parse_hex_blob("aa bb cc dd") == b"\xaa\xbb\xcc\xdd"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            parse_hex_blob("")

    def test_rejects_odd_length(self):
        with pytest.raises(ValueError):
            parse_hex_blob("aab")


class TestParseBdAddr:
    def test_canonical(self):
        assert parse_bd_addr("AA:BB:CC:DD:EE:FF") == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_rejects_short(self):
        with pytest.raises(ValueError):
            parse_bd_addr("AA:BB:CC:DD:EE")

    def test_rejects_bad_octet(self):
        with pytest.raises(ValueError):
            parse_bd_addr("AA:BBB:CC:DD:EE:FF")


class TestAes128Ecb:
    def test_zero_key_zero_block(self):
        out = aes128_ecb(b"\x00" * 16, b"\x00" * 16)
        # NIST FIPS-197 test vector for AES-128 encryption of zero block under zero key.
        assert out.hex() == "66e94bd4ef8a2c3b884cfa59ca342b2e"

    def test_rejects_short_key(self):
        with pytest.raises(ValueError):
            aes128_ecb(b"\x00" * 15, b"\x00" * 16)

    def test_rejects_short_block(self):
        with pytest.raises(ValueError):
            aes128_ecb(b"\x00" * 16, b"\x00" * 15)


class TestAhFunctionRoundTrip:
    """Property-based: ah is deterministic; the IRK that resolves an
    address it generated must round-trip."""

    def test_self_resolve(self):
        irk = os.urandom(16)
        prand_int = 0b01 << 22 | 0x012345   # top 2 bits = 01 (RPA marker)
        prand = prand_int.to_bytes(3, "big")
        hash_bytes = ah(irk, prand)
        rpa = (prand + hash_bytes).hex(":").upper()
        # Reformat into canonical AA:BB:... shape.
        rpa = ":".join([rpa[i:i + 2] for i in range(0, len(rpa), 3)])
        # ":hex():" returns a colon-separated string; build the canonical form.
        addr = ":".join(f"{b:02X}" for b in prand + hash_bytes)
        assert rpa_resolves(irk, addr) is True

    def test_wrong_irk_does_not_resolve(self):
        irk = os.urandom(16)
        other = os.urandom(16)
        prand_int = 0b01 << 22 | 0xABCDEF
        prand = prand_int.to_bytes(3, "big")
        hash_bytes = ah(irk, prand)
        addr = ":".join(f"{b:02X}" for b in prand + hash_bytes)
        assert rpa_resolves(other, addr) is False


class TestIsResolvablePrivate:
    def test_rpa_top_bits_01(self):
        # 0x40 has top two bits 01.
        assert is_resolvable_private(bytes([0x40, 0, 0, 0, 0, 0])) is True

    def test_static_random_top_bits_11_rejected(self):
        assert is_resolvable_private(bytes([0xC0, 0, 0, 0, 0, 0])) is False

    def test_public_top_bits_00_rejected(self):
        assert is_resolvable_private(bytes([0x00, 0, 0, 0, 0, 0])) is False

    def test_short_input_rejected(self):
        assert is_resolvable_private(b"\x40\x00") is False


class TestRpaResolves:
    def test_non_rpa_returns_false(self):
        # Public address.
        assert rpa_resolves(b"\x00" * 16, "01:02:03:04:05:06") is False

    def test_bad_addr_returns_false(self):
        assert rpa_resolves(b"\x00" * 16, "not-an-address") is False


# ---------------------------------------------------------------------------
# Key statistics
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    def test_all_zeros(self):
        assert shannon_entropy_bits(b"\x00" * 16) == pytest.approx(0.0)

    def test_two_distinct_values(self):
        assert shannon_entropy_bits(b"\xaa\xbb" * 8) == pytest.approx(1.0)

    def test_empty(self):
        assert shannon_entropy_bits(b"") == 0.0


class TestRepeatedByteRuns:
    def test_finds_a_run(self):
        assert repeated_byte_runs(b"\x01\xaa\xaa\xaa\x02") == [(1, 3)]

    def test_short_run_ignored(self):
        assert repeated_byte_runs(b"\x01\xaa\xaa\x02") == []


class TestKnownWeak:
    def test_all_zeros_caught(self):
        assert known_weak_match(b"\x00" * 16) == "all-zero"

    def test_all_ones_caught(self):
        assert known_weak_match(b"\xff" * 16) == "all-ones"

    def test_unknown_returns_none(self):
        assert known_weak_match(os.urandom(16)) is None


class TestChiSquare:
    def test_zero_for_uniform_ish(self):
        # Single byte at every position; max chi-square (extremely
        # non-uniform). Just confirm the stat is large.
        chi, _df = chi_square_uniform_bytes(b"\x00" * 16)
        assert chi > 100


# ---------------------------------------------------------------------------
# key_quality module
# ---------------------------------------------------------------------------


@pytest.fixture
def key_quality_mod():
    loader = ModuleLoader()
    mod = loader.load("auxiliary/crypto/key_quality")
    assert mod is not None
    return mod


class TestKeyQualityModule:
    def test_all_zeros_fails(self, key_quality_mod, capsys):
        key_quality_mod.set_option("key", "00" * 16)
        assert key_quality_mod.run() is True
        out = capsys.readouterr().out
        assert "FAIL" in out
        assert "all-zero" in out

    def test_random_key_passes(self, key_quality_mod, capsys):
        key_quality_mod.set_option("key", os.urandom(16).hex())
        assert key_quality_mod.run() is True
        out = capsys.readouterr().out
        assert "PASS" in out

    def test_ascii_passphrase_warns(self, key_quality_mod, capsys):
        key_quality_mod.set_option("key", b"passwordpassword".hex())
        assert key_quality_mod.run() is True
        out = capsys.readouterr().out
        assert "WARN" in out or "passphrase" in out

    def test_rejects_empty(self, key_quality_mod, capsys):
        key_quality_mod.set_option("key", "")
        assert key_quality_mod.run() is False

    def test_rejects_bad_hex(self, key_quality_mod, capsys):
        key_quality_mod.set_option("key", "zz")
        assert key_quality_mod.run() is False

    def test_expected_length_mismatch_warns(self, key_quality_mod, capsys):
        key_quality_mod.set_option("key", "aabbcc")
        key_quality_mod.set_option("expected_length", 16)
        assert key_quality_mod.run() is True


# ---------------------------------------------------------------------------
# irk_entropy module
# ---------------------------------------------------------------------------


@pytest.fixture
def irk_mod():
    loader = ModuleLoader()
    mod = loader.load("auxiliary/crypto/irk_entropy")
    assert mod is not None
    return mod


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    yield get_store()
    reset_default_store()


class TestIrkModule:
    def test_resolves_self_generated_rpa(self, irk_mod, capsys):
        irk = os.urandom(16)
        prand_int = 0b01 << 22 | 0x010203
        prand = prand_int.to_bytes(3, "big")
        hash_bytes = ah(irk, prand)
        rpa = ":".join(f"{b:02X}" for b in prand + hash_bytes)

        irk_mod.set_option("irk", irk.hex())
        irk_mod.set_option("rpas", rpa)
        assert irk_mod.run() is True
        out = capsys.readouterr().out
        assert "resolves 1 of 1" in out

    def test_unrelated_irk_does_not_resolve(self, irk_mod, capsys):
        irk = os.urandom(16)
        prand_int = 0b01 << 22 | 0x040506
        prand = prand_int.to_bytes(3, "big")
        hash_bytes = ah(irk, prand)
        rpa = ":".join(f"{b:02X}" for b in prand + hash_bytes)

        other = os.urandom(16)
        irk_mod.set_option("irk", other.hex())
        irk_mod.set_option("rpas", rpa)
        assert irk_mod.run() is True
        out = capsys.readouterr().out
        assert "did not resolve" in out

    def test_rejects_wrong_irk_length(self, irk_mod, capsys):
        irk_mod.set_option("irk", "aabb")
        irk_mod.set_option("rpas", "AA:BB:CC:DD:EE:FF")
        assert irk_mod.run() is False

    def test_rejects_missing_irk(self, irk_mod, capsys):
        irk_mod.set_option("irk", "")
        assert irk_mod.run() is False

    def test_uses_store_when_rpas_empty(self, irk_mod, isolated_store, capsys):
        irk = os.urandom(16)
        prand_int = 0b01 << 22 | 0x070809
        prand = prand_int.to_bytes(3, "big")
        hash_bytes = ah(irk, prand)
        rpa = ":".join(f"{b:02X}" for b in prand + hash_bytes)
        isolated_store.add_host(rpa)

        irk_mod.set_option("irk", irk.hex())
        # No rpas option = read from store.
        assert irk_mod.run() is True
        out = capsys.readouterr().out
        assert "workspace hosts" in out

    def test_lsb_byte_order_path(self, irk_mod, capsys):
        # Pass an IRK and explicitly use lsb byte order; without a
        # matching RPA we just verify the option is accepted.
        irk_mod.set_option("irk", os.urandom(16).hex())
        irk_mod.set_option("byte_order", "lsb")
        irk_mod.set_option("rpas", "AA:BB:CC:DD:EE:FF")
        assert irk_mod.run() is True


# ---------------------------------------------------------------------------
# passkey_check module
# ---------------------------------------------------------------------------


@pytest.fixture
def passkey_mod():
    loader = ModuleLoader()
    mod = loader.load("auxiliary/crypto/passkey_check")
    assert mod is not None
    return mod


class TestPasskeyAudit:
    def test_all_zeros_fail(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "000000")
        assert passkey_mod.run() is True
        out = capsys.readouterr().out
        assert "FAIL" in out

    def test_sequential_fail_or_warn(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "123456")
        assert passkey_mod.run() is True
        out = capsys.readouterr().out
        assert "FAIL" in out or "WARN" in out
        assert "ascending" in out.lower() or "weak passkey" in out.lower()

    def test_random_passes(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "473829")
        assert passkey_mod.run() is True
        out = capsys.readouterr().out
        assert "PASS" in out

    def test_repeat_block_warns(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "121212")
        assert passkey_mod.run() is True
        out = capsys.readouterr().out
        # 121212 is in the weak table (FAIL) and also matches block-repeat.
        assert "FAIL" in out or "WARN" in out

    def test_palindrome_warns(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "428824")
        assert passkey_mod.run() is True
        out = capsys.readouterr().out
        assert "WARN" in out
        assert "Palindrome" in out

    def test_rejects_too_short(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "12345")
        assert passkey_mod.run() is False

    def test_rejects_letters(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "abcdef")
        assert passkey_mod.run() is False

    def test_rejects_empty(self, passkey_mod, capsys):
        passkey_mod.set_option("passkey", "")
        assert passkey_mod.run() is False
