"""Tests for modules/scanners/ble_pairing_audit.

Covers the pure rule engine on hand-crafted smp_pairing fingerprint
dicts, plus an end-to-end run through the ModuleLoader against an
isolated SQLite store. No hardware is touched.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from core.loader import ModuleLoader
from core.store import get_store, reset_default_store

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_mod():
    """Import the module file directly so the rule engine functions
    are addressable without booting the loader machinery."""
    import importlib.util
    import sys

    name = "audit_under_test_ble_pairing_audit"
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, Path("modules/scanners/ble_pairing_audit.py")
    )
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so @dataclass can resolve cls.__module__.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def loaded(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    loader = ModuleLoader()
    mod = loader.load("scanners/ble_pairing_audit")
    assert mod is not None, "ble_pairing_audit module did not load"
    store = get_store()
    yield mod, store
    reset_default_store()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fp(
    mitm: bool = True,
    sc: bool = True,
    oob: bool = False,
    bonding: bool = True,
    ct2: bool = False,
    max_key: int = 16,
    init_kd: str = "0x00",
    resp_kd: str = "0x00",
    io_capability: str = "DisplayYesNo",
) -> Dict[str, Any]:
    """Build a smp_pairing fingerprint dict matching the shape that
    recon/ble_pairing_features writes."""
    auth_req = 0
    if bonding: auth_req |= 0x01
    if mitm:    auth_req |= 0x04
    if sc:      auth_req |= 0x08
    if ct2:     auth_req |= 0x20
    return {
        "target": "AA:BB:CC:DD:EE:FF",
        "io_capability": io_capability,
        "oob": oob,
        "auth_req": f"0x{auth_req:02X}",
        "bonding": bonding, "mitm": mitm, "sc": sc,
        "keypress": False, "ct2": ct2,
        "max_key_size": max_key,
        "init_key_dist": init_kd,
        "resp_key_dist": resp_kd,
    }


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class TestRuleLegacyJustWorks:
    """Rule BSA-PAIR-001: no MITM + no OOB + no SC."""

    def test_fires_on_full_legacy_justworks(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:01",
            _fp(mitm=False, sc=False, oob=False),
        )
        ids = {f.rule_id for f in findings}
        assert "BSA-PAIR-001" in ids
        f = next(f for f in findings if f.rule_id == "BSA-PAIR-001")
        assert f.severity == "high"
        assert f.confidence == "high"
        assert "Core Spec" in f.reference

    def test_does_not_fire_when_mitm_required(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:02",
            _fp(mitm=True, sc=False),
        )
        assert "BSA-PAIR-001" not in {f.rule_id for f in findings}

    def test_does_not_fire_when_oob_present(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:03",
            _fp(mitm=False, sc=False, oob=True),
        )
        assert "BSA-PAIR-001" not in {f.rule_id for f in findings}


class TestRuleJustWorksSC:
    """Rule BSA-PAIR-002: no MITM + no OOB but SC=True."""

    def test_fires_when_only_sc_present(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:04",
            _fp(mitm=False, sc=True, oob=False),
        )
        f = next(f for f in findings if f.rule_id == "BSA-PAIR-002")
        assert f.severity == "medium"

    def test_001_and_002_are_mutually_exclusive(self, audit_mod):
        """The two JustWorks rules differentiate on the SC bit."""
        no_sc = audit_mod.evaluate_pairing_features(
            "X", _fp(mitm=False, sc=False, oob=False))
        yes_sc = audit_mod.evaluate_pairing_features(
            "Y", _fp(mitm=False, sc=True, oob=False))
        assert "BSA-PAIR-001" in {f.rule_id for f in no_sc}
        assert "BSA-PAIR-002" not in {f.rule_id for f in no_sc}
        assert "BSA-PAIR-002" in {f.rule_id for f in yes_sc}
        assert "BSA-PAIR-001" not in {f.rule_id for f in yes_sc}


class TestRuleLegacyAccepted:
    """Rule BSA-PAIR-003: SC bit not set in AuthReq."""

    def test_fires_when_sc_false_even_with_mitm(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:05",
            _fp(mitm=True, sc=False),
        )
        assert "BSA-PAIR-003" in {f.rule_id for f in findings}

    def test_silent_when_sc_required(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:06",
            _fp(mitm=True, sc=True),
        )
        assert "BSA-PAIR-003" not in {f.rule_id for f in findings}


class TestRuleWeakKey:
    """Rule BSA-PAIR-004: max_key_size < 16."""

    def test_severity_high_when_tiny(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:07", _fp(max_key=7))
        f = next(f for f in findings if f.rule_id == "BSA-PAIR-004")
        assert f.severity == "high"
        assert "CVE-2019-9506" in f.reference

    def test_severity_medium_above_10(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:08", _fp(max_key=12))
        f = next(f for f in findings if f.rule_id == "BSA-PAIR-004")
        assert f.severity == "medium"

    def test_silent_at_full_key_size(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:09", _fp(max_key=16))
        assert "BSA-PAIR-004" not in {f.rule_id for f in findings}

    def test_silent_when_field_missing(self, audit_mod):
        data = _fp()
        data.pop("max_key_size", None)
        findings = audit_mod.evaluate_pairing_features("X", data)
        assert "BSA-PAIR-004" not in {f.rule_id for f in findings}


class TestRuleCSRKUnauth:
    """Rule BSA-PAIR-005: CSRK (Sign bit) distributed without MITM."""

    def test_fires_on_init_csrk_no_mitm(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:0A",
            _fp(mitm=False, sc=True, init_kd="0x04"),
        )
        assert "BSA-PAIR-005" in {f.rule_id for f in findings}

    def test_fires_on_resp_csrk_no_mitm(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:0B",
            _fp(mitm=False, sc=True, resp_kd="0x04"),
        )
        assert "BSA-PAIR-005" in {f.rule_id for f in findings}

    def test_silent_when_mitm_required(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:0C",
            _fp(mitm=True, sc=True, init_kd="0x04"),
        )
        assert "BSA-PAIR-005" not in {f.rule_id for f in findings}

    def test_silent_without_csrk_bit(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:0D",
            _fp(mitm=False, sc=True, init_kd="0x03", resp_kd="0x03"),
        )
        assert "BSA-PAIR-005" not in {f.rule_id for f in findings}


class TestRuleCT2Downgrade:
    """Rule BSA-PAIR-006: CT2 set without SC (BLURtooth surface)."""

    def test_fires_on_ct2_without_sc(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:0E",
            _fp(ct2=True, sc=False),
        )
        f = next(f for f in findings if f.rule_id == "BSA-PAIR-006")
        assert f.severity == "high"
        assert "CVE-2020-15802" in f.reference

    def test_silent_when_sc_present(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:0F",
            _fp(ct2=True, sc=True),
        )
        assert "BSA-PAIR-006" not in {f.rule_id for f in findings}


class TestRuleBondingNoMITM:
    """Rule BSA-PAIR-007: Bonding without MITM (info severity)."""

    def test_fires(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:10",
            _fp(bonding=True, mitm=False, sc=True),
        )
        f = next(f for f in findings if f.rule_id == "BSA-PAIR-007")
        assert f.severity == "low"

    def test_silent_when_mitm(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:11",
            _fp(bonding=True, mitm=True, sc=True),
        )
        assert "BSA-PAIR-007" not in {f.rule_id for f in findings}


class TestCleanPeer:
    """A well-configured peer should produce zero findings."""

    def test_zero_findings_when_clean(self, audit_mod):
        findings = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:12",
            _fp(mitm=True, sc=True, oob=False, max_key=16,
                bonding=True, ct2=False),
        )
        assert findings == []


# ---------------------------------------------------------------------------
# Filter helpers
# ---------------------------------------------------------------------------


class TestFilters:
    def test_filter_drops_below_min_severity(self, audit_mod):
        all_f = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:13",
            _fp(mitm=False, sc=False, oob=False, max_key=7),
        )
        kept = audit_mod._filter(all_f, min_sev="high", min_conf="low")
        assert all(f.severity in ("high", "critical") for f in kept)
        assert any(f.rule_id == "BSA-PAIR-001" for f in kept)

    def test_filter_drops_below_min_confidence(self, audit_mod):
        all_f = audit_mod.evaluate_pairing_features(
            "AA:BB:CC:DD:EE:14",
            _fp(mitm=False, sc=True, init_kd="0x04"),
        )
        kept = audit_mod._filter(all_f, min_sev="info", min_conf="high")
        # BSA-PAIR-005 is medium confidence, should be dropped.
        assert "BSA-PAIR-005" not in {f.rule_id for f in kept}


# ---------------------------------------------------------------------------
# End-to-end via ModuleLoader + isolated store
# ---------------------------------------------------------------------------


class TestRunEndToEnd:
    def _plant(self, store, address: str, data: Dict[str, Any]):
        h = store.add_host(address)
        store.add_fingerprint(
            h, "smp_pairing", data,
            source_module="recon/ble_pairing_features",
        )
        return h

    def test_run_finds_legacy_justworks(self, loaded, capsys):
        mod, store = loaded
        self._plant(store, "AA:BB:CC:DD:EE:20",
                    _fp(mitm=False, sc=False, oob=False))
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "BSA-PAIR-001" in out
        # add_result captured the finding.
        results = mod.results
        rules = {r["rule"] for r in results}
        assert "BSA-PAIR-001" in rules

    def test_run_targets_specific_host(self, loaded, capsys):
        mod, store = loaded
        self._plant(store, "AA:BB:CC:DD:EE:21",
                    _fp(mitm=False, sc=False))
        self._plant(store, "AA:BB:CC:DD:EE:22",
                    _fp(mitm=True, sc=True))  # clean
        mod.set_option("target", "AA:BB:CC:DD:EE:22")
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "AA:BB:CC:DD:EE:21" not in out
        assert "No pairing weaknesses" in out

    def test_run_reports_missing_fingerprint_gap(self, loaded, capsys):
        mod, store = loaded
        # Host exists, but no smp_pairing fingerprint planted.
        store.add_host("AA:BB:CC:DD:EE:23")
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "Missing smp_pairing fingerprint" in out
        assert "recon/ble_pairing_features" in out

    def test_run_with_empty_workspace(self, loaded, capsys):
        mod, store = loaded
        assert mod.run() is False
        out = capsys.readouterr().out
        assert "No hosts" in out

    def test_unknown_target_returns_false(self, loaded, capsys):
        mod, store = loaded
        self._plant(store, "AA:BB:CC:DD:EE:24", _fp(mitm=False, sc=False))
        mod.set_option("target", "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ")
        assert mod.run() is False
        out = capsys.readouterr().out
        assert "No stored host matches" in out

    def test_min_severity_filter_drops_low(self, loaded, capsys):
        mod, store = loaded
        # bonding without MITM (low) + SC=True so no other rules fire.
        self._plant(store, "AA:BB:CC:DD:EE:25",
                    _fp(mitm=False, sc=True, oob=True, bonding=True))
        mod.set_option("min_severity", "high")
        assert mod.run() is True
        out = capsys.readouterr().out
        # BSA-PAIR-007 is low; should be filtered out.
        assert "BSA-PAIR-007" not in out
