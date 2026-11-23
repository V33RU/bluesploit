"""Tests for the CVE-matching engine in core/cve.py.

Exercises the rule evaluator with synthesized fingerprint dicts that
match the shape the recon modules actually produce, so a regression
in either side surfaces here.
"""

from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent

import pytest

from core.cve import (
    Finding,
    MissingFingerprint,
    Signature,
    default_signatures_path,
    evaluate_signature,
    filter_by_min_confidence,
    load_signatures,
    scan_host,
)

# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


class TestLoadSignatures:
    def test_shipped_file_loads(self):
        sigs = load_signatures()
        assert len(sigs) >= 3
        ids = {s.id for s in sigs}
        assert "CVE-2019-9506" in ids   # KNOB
        assert "CVE-2020-10135" in ids  # BIAS
        assert "CVE-2023-24023" in ids  # BLUFFS

    def test_default_path_resolves(self):
        p = default_signatures_path()
        assert p.is_file()
        assert p.name == "bluetooth_cves.json"

    def test_custom_path(self, tmp_path: Path):
        body = {
            "schema_version": 1,
            "entries": [{
                "id": "CVE-2099-9999",
                "name": "Test",
                "severity": "info",
                "confidence": "low",
                "applies_to": {"protocol": "classic"},
                "match": {
                    "fingerprint": "lmp_features",
                    "rules": [],
                    "rationale": "test only",
                },
                "description": "Test entry",
                "related_modules": [],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2099-9999"],
                "disclosed": "2099-01-01",
            }],
        }
        p = tmp_path / "test.json"
        p.write_text(json.dumps(body))
        sigs = load_signatures(p)
        assert len(sigs) == 1
        assert sigs[0].id == "CVE-2099-9999"


# ---------------------------------------------------------------------------
# Rule evaluation: LMP version comparisons
# ---------------------------------------------------------------------------


def _sig_lmp(rule: dict, *, confidence: str = "medium") -> Signature:
    """Helper: build a one-rule lmp_features signature."""
    return Signature(
        id="CVE-XXXX-0001", name="Test", severity="high",
        confidence=confidence, protocol="classic",
        fingerprint_kind="lmp_features",
        rules=[rule],
        rationale="test", description="test",
    )


class TestLMPVersionRules:
    def test_max_inclusive_matches_when_below(self):
        sig = _sig_lmp({"lmp_version_max_inclusive": "5.0"})
        fp = {"lmp_version": 0x06}  # 4.0
        assert evaluate_signature(sig, {"lmp_features": fp}) is not None

    def test_max_inclusive_matches_at_boundary(self):
        sig = _sig_lmp({"lmp_version_max_inclusive": "5.0"})
        fp = {"lmp_version": 0x09}  # 5.0
        assert evaluate_signature(sig, {"lmp_features": fp}) is not None

    def test_max_inclusive_misses_when_above(self):
        sig = _sig_lmp({"lmp_version_max_inclusive": "5.0"})
        fp = {"lmp_version": 0x0A}  # 5.1
        assert evaluate_signature(sig, {"lmp_features": fp}) is None

    def test_missing_lmp_version_does_not_match(self):
        sig = _sig_lmp({"lmp_version_max_inclusive": "5.0"})
        fp = {"page_0_bits": {"Encryption": True}}
        assert evaluate_signature(sig, {"lmp_features": fp}) is None

    def test_min_inclusive(self):
        sig = _sig_lmp({"lmp_version_min_inclusive": "5.0"})
        assert evaluate_signature(sig, {"lmp_features": {"lmp_version": 0x09}}) is not None
        assert evaluate_signature(sig, {"lmp_features": {"lmp_version": 0x08}}) is None

    def test_unknown_version_label_treated_as_no_match(self):
        sig = _sig_lmp({"lmp_version_max_inclusive": "99.0"})
        fp = {"lmp_version": 0x09}
        assert evaluate_signature(sig, {"lmp_features": fp}) is None


# ---------------------------------------------------------------------------
# Rule evaluation: feature bits
# ---------------------------------------------------------------------------


class TestFeatureBitRules:
    def test_encryption_supported_match(self):
        sig = _sig_lmp({"encryption_supported": True})
        fp = {"page_0_bits": {"Encryption": True}}
        assert evaluate_signature(sig, {"lmp_features": fp}) is not None

    def test_encryption_supported_miss(self):
        sig = _sig_lmp({"encryption_supported": True})
        fp = {"page_0_bits": {}}
        assert evaluate_signature(sig, {"lmp_features": fp}) is None

    def test_sc_controller_on_page2(self):
        sig = _sig_lmp({"secure_connections_controller": True})
        fp = {"page_2_bits": {"Secure Connections (Controller)": True}}
        assert evaluate_signature(sig, {"lmp_features": fp}) is not None

    def test_sc_host_on_page1(self):
        sig = _sig_lmp({"secure_connections_host": True})
        fp = {"page_1_bits": {"Secure Connections (Host)": True}}
        assert evaluate_signature(sig, {"lmp_features": fp}) is not None

    def test_explicit_false_matches_absent_bit(self):
        # A rule asking for `encryption_supported: false` should match a
        # fingerprint whose page_0 has no Encryption bit set.
        sig = _sig_lmp({"encryption_supported": False})
        fp = {"page_0_bits": {}}
        assert evaluate_signature(sig, {"lmp_features": fp}) is not None


# ---------------------------------------------------------------------------
# Rule evaluation: combined conditions (logical AND)
# ---------------------------------------------------------------------------


class TestCombinedConditions:
    def test_both_required(self):
        sig = _sig_lmp({
            "lmp_version_max_inclusive": "5.0",
            "encryption_supported": True,
        })
        fp_match = {
            "lmp_version": 0x08,
            "page_0_bits": {"Encryption": True},
        }
        fp_miss_version = {
            "lmp_version": 0x0A,
            "page_0_bits": {"Encryption": True},
        }
        fp_miss_feature = {
            "lmp_version": 0x08,
            "page_0_bits": {},
        }
        assert evaluate_signature(sig, {"lmp_features": fp_match}) is not None
        assert evaluate_signature(sig, {"lmp_features": fp_miss_version}) is None
        assert evaluate_signature(sig, {"lmp_features": fp_miss_feature}) is None

    def test_or_across_rules(self):
        sig = Signature(
            id="X", name="X", severity="high", confidence="low",
            protocol="classic", fingerprint_kind="lmp_features",
            rules=[
                {"lmp_version_max_inclusive": "4.2"},
                {"encryption_supported": True},
            ],
            rationale="test", description="test",
        )
        # Hits second rule only.
        fp = {"lmp_version": 0x0A, "page_0_bits": {"Encryption": True}}
        result = evaluate_signature(sig, {"lmp_features": fp})
        assert result is not None
        rule_idx, observed = result
        assert rule_idx == 1


# ---------------------------------------------------------------------------
# Rule evaluation: SMP / LE
# ---------------------------------------------------------------------------


class TestLEAndSMP:
    def test_legacy_pairing_when_sc_false(self):
        sig = Signature(
            id="X", name="X", severity="medium", confidence="medium",
            protocol="ble", fingerprint_kind="smp_pairing",
            rules=[{"legacy_pairing_accepted": True}],
            rationale="t", description="t",
        )
        assert evaluate_signature(sig, {"smp_pairing": {"sc": False}}) is not None
        assert evaluate_signature(sig, {"smp_pairing": {"sc": True}}) is None

    def test_max_key_size_max(self):
        sig = Signature(
            id="X", name="X", severity="medium", confidence="medium",
            protocol="ble", fingerprint_kind="smp_pairing",
            rules=[{"max_key_size_max": 7}],
            rationale="t", description="t",
        )
        assert evaluate_signature(sig, {"smp_pairing": {"max_key_size": 7}}) is not None
        assert evaluate_signature(sig, {"smp_pairing": {"max_key_size": 16}}) is None

    def test_ll_features_bit(self):
        sig = Signature(
            id="X", name="X", severity="info", confidence="low",
            protocol="ble", fingerprint_kind="ll_features",
            rules=[{"le_2m_phy": True}],
            rationale="t", description="t",
        )
        fp = {"ll_features_bits": {"LE 2M PHY": True}}
        assert evaluate_signature(sig, {"ll_features": fp}) is not None


# ---------------------------------------------------------------------------
# Empty-rules signature is informational only
# ---------------------------------------------------------------------------


class TestEmptyRules:
    def test_empty_rules_never_matches(self):
        sig = _sig_lmp({})  # empty dict still iterates 0 conditions
        # The current evaluator treats {} as "0 conditions, all met by
        # vacuous truth", so it WOULD match. We pin the expected
        # behavior: the explicit "rules: []" case must not match.
        sig.rules = []
        assert evaluate_signature(sig, {"lmp_features": {}}) is None


# ---------------------------------------------------------------------------
# scan_host: gaps surface as MissingFingerprint
# ---------------------------------------------------------------------------


class TestScanHost:
    def test_missing_kind_produces_gap(self):
        sigs = [
            Signature(id="A", name="A", severity="high", confidence="low",
                      protocol="classic", fingerprint_kind="lmp_features",
                      rules=[{"encryption_supported": True}],
                      rationale="t", description="t",
                      related_modules=["exploits/knob"]),
        ]
        findings, gaps = scan_host(sigs, fingerprints_by_kind={})
        assert findings == []
        assert len(gaps) == 1
        assert isinstance(gaps[0], MissingFingerprint)
        assert gaps[0].fingerprint_kind == "lmp_features"
        assert gaps[0].suggested_recon_module == "recon/lmp_features"

    def test_finding_carries_full_context(self):
        sigs = [
            Signature(id="CVE-2019-9506", name="KNOB", severity="high",
                      confidence="medium", protocol="classic",
                      fingerprint_kind="lmp_features",
                      rules=[{"lmp_version_max_inclusive": "5.0",
                              "encryption_supported": True}],
                      rationale="rationale string", description="d",
                      related_modules=["exploits/knob"],
                      references=["https://nvd.nist.gov/vuln/detail/CVE-2019-9506"]),
        ]
        fp_by_kind = {"lmp_features": {
            "lmp_version": 0x08,
            "page_0_bits": {"Encryption": True},
        }}
        findings, gaps = scan_host(sigs, fp_by_kind, target_address="AA:BB:CC:DD:EE:01")
        assert gaps == []
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, Finding)
        assert f.cve_id == "CVE-2019-9506"
        assert f.severity == "high"
        assert f.confidence == "medium"
        assert f.target_address == "AA:BB:CC:DD:EE:01"
        assert f.related_modules == ["exploits/knob"]
        # observed matched fields are captured
        assert f.matched_fields["lmp_version_max_inclusive"] == 0x08
        assert f.matched_fields["encryption_supported"] is True


# ---------------------------------------------------------------------------
# filter_by_min_confidence
# ---------------------------------------------------------------------------


class TestFilterByMinConfidence:
    def _f(self, confidence: str) -> Finding:
        return Finding(
            cve_id="X", name="X", severity="x", confidence=confidence,
            matched_rule_index=0, fingerprint_kind="lmp_features",
            target_address=None, related_modules=[], references=[],
            rationale="", matched_fields={},
        )

    def test_low_threshold_keeps_all(self):
        out = filter_by_min_confidence(
            [self._f("low"), self._f("medium"), self._f("high")], "low"
        )
        assert [f.confidence for f in out] == ["low", "medium", "high"]

    def test_medium_threshold_drops_low(self):
        out = filter_by_min_confidence(
            [self._f("low"), self._f("medium"), self._f("high")], "medium"
        )
        assert [f.confidence for f in out] == ["medium", "high"]

    def test_high_threshold_keeps_only_high(self):
        out = filter_by_min_confidence(
            [self._f("low"), self._f("medium"), self._f("high")], "high"
        )
        assert [f.confidence for f in out] == ["high"]


# ---------------------------------------------------------------------------
# Integration: shipped signatures match real-shape fingerprints
# ---------------------------------------------------------------------------


class TestShippedSignaturesEndToEnd:
    def test_knob_matches_pre_5_1_with_encryption(self):
        """KNOB rule fires on a real-shape LMP fingerprint."""
        sigs = [s for s in load_signatures() if s.id == "CVE-2019-9506"]
        assert len(sigs) == 1
        fp = {
            "lmp_version": 0x09,            # 5.0
            "lmp_version_label": "5.0",
            "manufacturer_id": 0x004C,
            "manufacturer_label": "Apple",
            "lmp_subversion": 0x0001,
            "page_0_hex": "bfeeff_cfdbff_7b87",
            "page_0_bits": {"Encryption": True},
        }
        findings, gaps = scan_host(sigs, {"lmp_features": fp},
                                   target_address="AA:BB:CC:DD:EE:01")
        assert len(findings) == 1
        assert findings[0].confidence == "medium"
        assert "exploits/knob" in findings[0].related_modules

    def test_knob_skips_patched_5_2(self):
        sigs = [s for s in load_signatures() if s.id == "CVE-2019-9506"]
        fp = {"lmp_version": 0x0B, "page_0_bits": {"Encryption": True}}
        findings, gaps = scan_host(sigs, {"lmp_features": fp})
        assert findings == []

    def test_bluffs_matches_pre_5_4_with_sc(self):
        sigs = [s for s in load_signatures() if s.id == "CVE-2023-24023"]
        fp = {
            "lmp_version": 0x0C,            # 5.3
            "page_0_bits": {"Encryption": True},
            "page_2_bits": {"Secure Connections (Controller)": True},
        }
        findings, gaps = scan_host(sigs, {"lmp_features": fp})
        assert len(findings) == 1
        assert findings[0].confidence == "medium"

    def test_no_fingerprint_means_no_finding(self):
        """The honesty test: with empty fingerprints, nothing matches."""
        sigs = load_signatures()
        findings, gaps = scan_host(sigs, {})
        assert findings == []
        # Catalog has lmp_features-keyed and smp_pairing-keyed signatures.
        # Every signature whose required fingerprint is missing should
        # appear as a gap.
        kinds = {g.fingerprint_kind for g in gaps}
        assert "lmp_features" in kinds
        assert "smp_pairing" in kinds
        assert len(gaps) == len(sigs)
