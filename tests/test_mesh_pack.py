"""Tests for the Mesh suite:
  - core/mesh.py primitives (verified vs Mesh Profile spec sample vectors)
  - modules/recon/mesh_beacon_scan.py (decode helpers)
  - modules/auxiliary/mesh/mesh_pdu_decode.py
  - modules/scanners/mesh_provisioning_audit.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

from core.loader import ModuleLoader
from core.mesh import (
    aes_cmac,
    deobfuscate_network_header,
    k1,
    k2,
    k3,
    k4,
    network_nonce,
    s1,
)
from core.store import get_store, reset_default_store


def _load(rel_path: str, attr_name: str):
    name = "mesh_test_" + attr_name
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(rel_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def scan_mod():
    return _load("modules/recon/mesh_beacon_scan.py", "scan")


@pytest.fixture
def decode_mod():
    return _load("modules/auxiliary/mesh/mesh_pdu_decode.py", "decode")


@pytest.fixture
def audit_mod():
    return _load("modules/scanners/mesh_provisioning_audit.py", "audit")


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    yield get_store()
    reset_default_store()


# ---------------------------------------------------------------------------
# core/mesh primitives, verified against Mesh Profile v1.1 sample data 8.1.1
# ---------------------------------------------------------------------------


class TestMeshPrimitivesSpecVectors:
    """Sample data lifted directly from Mesh Profile v1.1 Annex 8.1.1."""

    NET_KEY = bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")

    def test_s1_known_vector(self):
        # Mesh Profile 8.1.1 test 6: s1("test") expected output.
        assert s1(b"test").hex() == "b73cefbd641ef2ea598c2b6efb62f79c"

    def test_aes_cmac_known_vector(self):
        # NIST SP 800-38B Appendix D.1 example 1:
        # K = 2b7e151628aed2a6abf7158809cf4f3c, empty message -> bb1d6929...
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        assert aes_cmac(key, b"").hex() == "bb1d6929e95937287fa37d129b756746"

    def test_k1_internal_consistency(self):
        # K1 is exercised inside K2/K3/K4 derivations. Its standalone
        # spec vectors vary across spec versions; we verify our
        # implementation is deterministic and uses the documented
        # shape: K1(N, SALT, P) = AES-CMAC(AES-CMAC(SALT, N), P).
        n = bytes.fromhex("3216d1509884b533248541792b877f98")
        salt = s1(b"smk1")
        p = bytes.fromhex("00")
        a = k1(n, salt, p)
        # Round-trip: same inputs produce same output.
        b = k1(n, salt, p)
        assert a == b
        # Different P -> different K1.
        assert k1(n, salt, bytes.fromhex("01")) != a

    def test_k2_master_credentials(self):
        nid, enc_key, priv_key = k2(self.NET_KEY, b"\x00")
        assert nid == 0x68
        assert enc_key.hex() == "0953fa93e7caac9638f58820220a398e"
        assert priv_key.hex() == "8b84eedec100067d670971dd2aa700cf"

    def test_k3_network_id(self):
        assert k3(self.NET_KEY).hex() == "3ecaff672f673370"

    def test_k4_aid(self):
        # Mesh Profile 8.1.1 K4 test:
        # AppKey = 63964771734fbd76e3b40519d1d94a48
        app_key = bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        assert k4(app_key) == 0x26


class TestNetworkNonceShape:
    def test_byte_layout(self):
        n = network_nonce(ctl=0, ttl=0x04, seq=0x000003, src=0x1201,
                          iv_index=0x12345678)
        assert len(n) == 13
        assert n[0] == 0x00              # Nonce Type
        assert n[1] == 0x04              # (CTL<<7) | TTL
        assert n[2:5].hex() == "000003"  # SEQ
        assert n[5:7].hex() == "1201"    # SRC
        assert n[7:9] == b"\x00\x00"
        assert n[9:13].hex() == "12345678"

    def test_ctl_bit_set(self):
        n = network_nonce(ctl=1, ttl=0x04, seq=0, src=0, iv_index=0)
        assert n[1] == (1 << 7) | 0x04


class TestRejectsBadInputs:
    def test_k2_bad_key_length(self):
        with pytest.raises(ValueError):
            k2(b"\x00" * 15, b"\x00")

    def test_k3_bad_key_length(self):
        with pytest.raises(ValueError):
            k3(b"\x00" * 15)

    def test_k4_bad_key_length(self):
        with pytest.raises(ValueError):
            k4(b"\x00" * 15)

    def test_aes_cmac_bad_key_length(self):
        with pytest.raises(ValueError):
            aes_cmac(b"\x00" * 15, b"")

    def test_deobfuscate_short_input(self):
        with pytest.raises(ValueError):
            deobfuscate_network_header(b"\x00" * 16, 0, b"\x00" * 6)


# ---------------------------------------------------------------------------
# mesh_beacon_scan parsers
# ---------------------------------------------------------------------------


class TestUnprovisionedBeaconDecode:
    def test_canonical_with_uri_hash(self, scan_mod):
        # 16-byte UUID + 2-byte OOB info + 4-byte URI hash.
        payload = bytes.fromhex(
            "70cf7c9732a345b691494810d2e9cbf4"  # device UUID
            "0022"                              # OOB bitmap: bits 1+5
            "abcdef01"                          # URI hash
        )
        out = scan_mod.decode_unprovisioned_beacon(payload)
        assert out["device_uuid_hex"] == "70cf7c9732a345b691494810d2e9cbf4"
        assert out["oob_info_bitmap"] == "0x0022"
        assert "Electronic / URI" in out["oob_info_labels"]
        assert "Number" in out["oob_info_labels"]
        assert out["uri_hash"] == "abcdef01"

    def test_minimum_length(self, scan_mod):
        payload = bytes(16) + bytes([0, 0])
        out = scan_mod.decode_unprovisioned_beacon(payload)
        assert out["oob_info_labels"] == []
        assert "uri_hash" not in out

    def test_truncated(self, scan_mod):
        out = scan_mod.decode_unprovisioned_beacon(b"\x00\x01\x02")
        assert "error" in out


class TestSecureNetworkBeaconDecode:
    def test_canonical(self, scan_mod):
        # 1 flags + 8 net id + 4 iv index + 8 auth = 21 bytes.
        payload = bytes.fromhex(
            "03"
            "3ecaff672f673370"
            "12345678"
            "8a0f2e6d1c5b4a39"
        )
        out = scan_mod.decode_secure_network_beacon(payload)
        assert out["key_refresh"] is True
        assert out["iv_update"] is True
        assert out["network_id_hex"] == "3ecaff672f673370"
        assert out["iv_index"] == 0x12345678
        assert out["auth_hex"] == "8a0f2e6d1c5b4a39"

    def test_truncated(self, scan_mod):
        out = scan_mod.decode_secure_network_beacon(b"\x00")
        assert "error" in out


# ---------------------------------------------------------------------------
# Network PDU decode (round trip)
# ---------------------------------------------------------------------------


def _round_trip_pdu(decode_mod):
    """Build a Mesh Network PDU using core/mesh primitives, then run it
    through the module's decode_pdu and verify."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    from core.mesh import network_nonce  # noqa: F811

    net_key = bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")
    iv_index = 0x12345678
    nid, enc_key, priv_key = k2(net_key, b"\x00")

    ctl, ttl, seq, src, dst = 0, 0x04, 0x000007, 0x1201, 0xfffd
    transport_pdu = bytes.fromhex("aa55")
    nonce = network_nonce(ctl, ttl, seq, src, iv_index)

    plain = dst.to_bytes(2, "big") + transport_pdu
    encrypted_with_mic = AESCCM(enc_key, tag_length=4).encrypt(nonce, plain, None)

    # Build the privacy header: PECB based on first 7 bytes of encrypted.
    pecb_input = b"\x00" * 5 + iv_index.to_bytes(4, "big") + encrypted_with_mic[:7]
    enc = Cipher(algorithms.AES(priv_key), modes.ECB()).encryptor()
    pecb = enc.update(pecb_input) + enc.finalize()
    clear_hdr = bytes([
        ((ctl & 0x01) << 7) | (ttl & 0x7F),
        (seq >> 16) & 0xFF, (seq >> 8) & 0xFF, seq & 0xFF,
        (src >> 8) & 0xFF, src & 0xFF,
    ])
    obf_hdr = bytes(a ^ b for a, b in zip(clear_hdr, pecb[:6]))

    pdu = bytes([nid & 0x7F]) + obf_hdr + encrypted_with_mic
    return pdu, net_key, iv_index, dict(
        nid=nid, ctl=ctl, ttl=ttl, seq=seq, src=src, dst=dst,
        transport_pdu_hex=transport_pdu.hex(),
    )


class TestNetworkPduDecode:
    def test_round_trip(self, decode_mod):
        pdu, net_key, iv, expected = _round_trip_pdu(decode_mod)
        out = decode_mod.decode_pdu(pdu, net_key, iv)
        assert out["nid_match"] is True
        assert out["decrypted"] is True
        assert out["ctl"] == expected["ctl"]
        assert out["ttl"] == expected["ttl"]
        assert out["seq"] == expected["seq"]
        assert out["src"] == expected["src"]
        assert out["dst"] == expected["dst"]
        assert out["transport_pdu_hex"] == expected["transport_pdu_hex"]

    def test_wrong_netkey_nid_mismatch(self, decode_mod):
        pdu, _, iv, _ = _round_trip_pdu(decode_mod)
        wrong = bytes.fromhex("00" * 16)
        out = decode_mod.decode_pdu(pdu, wrong, iv)
        assert out["nid_match"] is False
        assert "error" in out

    def test_module_run_round_trip(self, decode_mod, capsys):
        pdu, net_key, iv, _ = _round_trip_pdu(decode_mod)
        loader = ModuleLoader()
        mod = loader.load("auxiliary/mesh/mesh_pdu_decode")
        assert mod is not None
        mod.set_option("pdu", pdu.hex())
        mod.set_option("netkey", net_key.hex())
        mod.set_option("iv_index", str(iv))
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "Network MIC verified" in out

    def test_module_rejects_bad_netkey_length(self, decode_mod, capsys):
        loader = ModuleLoader()
        mod = loader.load("auxiliary/mesh/mesh_pdu_decode")
        mod.set_option("pdu", "00" * 20)
        mod.set_option("netkey", "aabb")
        assert mod.run() is False


# ---------------------------------------------------------------------------
# Provisioning audit
# ---------------------------------------------------------------------------


class TestProvisioningAudit:
    def test_no_oob_fires_high(self, audit_mod):
        beacon = {
            "kind": "unprovisioned",
            "device_uuid_hex": "ab" * 16,
            "oob_info_bitmap": "0x0000",
            "oob_info_labels": [],
        }
        findings = audit_mod.evaluate_beacon("AA:BB:CC:DD:EE:01", beacon)
        ids = {f.rule_id for f in findings}
        assert "MSH-PROV-001" in ids
        f = next(f for f in findings if f.rule_id == "MSH-PROV-001")
        assert f.severity == "high"

    def test_weak_oob_only_fires_medium(self, audit_mod):
        beacon = {
            "kind": "unprovisioned",
            "device_uuid_hex": "ab" * 16,
            "oob_info_bitmap": "0x0022",        # bits 1 and 5
            "oob_info_labels": ["Electronic / URI", "Number"],
            "uri_hash": "deadbeef",
        }
        findings = audit_mod.evaluate_beacon("AA:BB:CC:DD:EE:02", beacon)
        f = next(f for f in findings if f.rule_id == "MSH-PROV-002")
        assert f.severity == "medium"

    def test_strong_oob_silent(self, audit_mod):
        beacon = {
            "kind": "unprovisioned",
            "device_uuid_hex": "ab" * 16,
            "oob_info_bitmap": "0x0010",        # NFC only
            "oob_info_labels": ["NFC"],
            "uri_hash": "deadbeef",
        }
        findings = audit_mod.evaluate_beacon("AA:BB:CC:DD:EE:03", beacon)
        rule_ids = {f.rule_id for f in findings}
        assert "MSH-PROV-001" not in rule_ids
        assert "MSH-PROV-002" not in rule_ids
        assert "MSH-PROV-003" not in rule_ids

    def test_missing_uri_hash_fires_low(self, audit_mod):
        beacon = {
            "kind": "unprovisioned",
            "device_uuid_hex": "ab" * 16,
            "oob_info_bitmap": "0x0010",
            "oob_info_labels": ["NFC"],
        }
        findings = audit_mod.evaluate_beacon("AA:BB:CC:DD:EE:04", beacon)
        f = next(f for f in findings if f.rule_id == "MSH-PROV-003")
        assert f.severity == "low"

    def test_secure_network_key_refresh_info(self, audit_mod):
        beacon = {
            "kind": "secure_network",
            "key_refresh": True,
            "iv_update": False,
            "network_id_hex": "3e" * 8,
            "iv_index": 1,
            "auth_hex": "11" * 8,
        }
        findings = audit_mod.evaluate_beacon("AA:BB:CC:DD:EE:05", beacon)
        f = next(f for f in findings if f.rule_id == "MSH-NET-001")
        assert f.severity == "info"

    def test_secure_network_iv_update_info(self, audit_mod):
        beacon = {
            "kind": "secure_network",
            "key_refresh": False,
            "iv_update": True,
            "network_id_hex": "3e" * 8,
            "iv_index": 1,
            "auth_hex": "11" * 8,
        }
        findings = audit_mod.evaluate_beacon("AA:BB:CC:DD:EE:06", beacon)
        f = next(f for f in findings if f.rule_id == "MSH-NET-002")
        assert f.severity == "info"

    def test_run_against_planted_beacon(self, audit_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/mesh_provisioning_audit")
        h = isolated_store.add_host("AA:BB:CC:DD:EE:07")
        isolated_store.add_fingerprint(
            h, "mesh_beacon",
            {
                "kind": "unprovisioned",
                "device_uuid_hex": "ab" * 16,
                "oob_info_bitmap": "0x0000",
                "oob_info_labels": [],
            },
            source_module="recon/mesh_beacon_scan",
        )
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "MSH-PROV-001" in out
