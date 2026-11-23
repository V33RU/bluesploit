"""Tests for the BLE 5.x + IoT audit batch:
  - modules/scanners/ll_features_audit.py
  - modules/scanners/iot_profile_audit.py
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.loader import ModuleLoader
from core.store import get_store, reset_default_store


def _load(rel_path: str, attr_name: str):
    name = "le5_iot_test_" + attr_name
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(rel_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def ll_mod():
    return _load("modules/scanners/ll_features_audit.py", "ll")


@pytest.fixture
def iot_mod():
    return _load("modules/scanners/iot_profile_audit.py", "iot")


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    yield get_store()
    reset_default_store()


# ---------------------------------------------------------------------------
# LL features audit
# ---------------------------------------------------------------------------


def _ll(**bits) -> Dict[str, Any]:
    """Default to a clean modern 5.4 peer; flip bits via kwargs."""
    base = {
        "LL Privacy": True,
        "LE Data Packet Length Extension": True,
        "LE Encryption": True,
        "Remote Public Key Validation": True,
        "LE Periodic Advertising": False,
        "Connected Isochronous Stream Master": False,
        "Connected Isochronous Stream Slave": False,
        "LE Power Control Request": False,
        "LE Power Change Indication": False,
        "Connection Subrating": False,
        "LE Coded PHY": False,
        "Periodic Advertising Sync Transfer Sender": False,
        "Periodic Advertising Sync Transfer Recipient": False,
    }
    base.update(bits)
    return {"ll_features_bits": base, "ll_features_hex": "00" * 8}


class TestLLPrivacyRule:
    def test_fires_when_off(self, ll_mod):
        findings = ll_mod.evaluate_ll_features("AA:BB:CC:DD:EE:01",
                                                _ll(**{"LL Privacy": False}))
        ids = {f.rule_id for f in findings}
        assert "BSA-LL-001" in ids

    def test_silent_when_on(self, ll_mod):
        findings = ll_mod.evaluate_ll_features("AA:BB:CC:DD:EE:02", _ll())
        assert "BSA-LL-001" not in {f.rule_id for f in findings}


class TestEncryptionRule:
    def test_fires_when_off(self, ll_mod):
        findings = ll_mod.evaluate_ll_features(
            "AA:BB:CC:DD:EE:03", _ll(**{"LE Encryption": False}))
        f = next(f for f in findings if f.rule_id == "BSA-LL-003")
        assert f.severity == "high"

    def test_silent_when_on(self, ll_mod):
        findings = ll_mod.evaluate_ll_features("AA:BB:CC:DD:EE:04", _ll())
        assert "BSA-LL-003" not in {f.rule_id for f in findings}


class TestPubKeyValidationRule:
    def test_fires_when_off(self, ll_mod):
        findings = ll_mod.evaluate_ll_features(
            "AA:BB:CC:DD:EE:05",
            _ll(**{"Remote Public Key Validation": False}),
        )
        assert "BSA-LL-004" in {f.rule_id for f in findings}


class TestCapabilityProfiling:
    def test_periodic_adv_info(self, ll_mod):
        findings = ll_mod.evaluate_ll_features(
            "AA:BB:CC:DD:EE:06",
            _ll(**{"LE Periodic Advertising": True,
                   "Periodic Advertising Sync Transfer Sender": True}),
        )
        f = next(f for f in findings if f.rule_id == "BSA-LL-CAP-001")
        assert f.severity == "info"
        assert "PAST Sender" in str(f.matched)

    def test_cis_info(self, ll_mod):
        findings = ll_mod.evaluate_ll_features(
            "AA:BB:CC:DD:EE:07",
            _ll(**{"Connected Isochronous Stream Master": True}),
        )
        f = next(f for f in findings if f.rule_id == "BSA-LL-CAP-002")
        assert f.severity == "info"

    def test_power_control_info(self, ll_mod):
        findings = ll_mod.evaluate_ll_features(
            "AA:BB:CC:DD:EE:08",
            _ll(**{"LE Power Control Request": True}),
        )
        assert "BSA-LL-CAP-003" in {f.rule_id for f in findings}

    def test_coded_phy_info(self, ll_mod):
        findings = ll_mod.evaluate_ll_features(
            "AA:BB:CC:DD:EE:09",
            _ll(**{"LE Coded PHY": True}),
        )
        assert "BSA-LL-CAP-005" in {f.rule_id for f in findings}


class TestLLAuditEndToEnd:
    def test_run_against_planted(self, ll_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/ll_features_audit")
        assert mod is not None
        h = isolated_store.add_host("AA:BB:CC:DD:EE:0A")
        isolated_store.add_fingerprint(
            h, "ll_features",
            _ll(**{"LL Privacy": False, "LE Encryption": False,
                   "LE Periodic Advertising": True}),
            source_module="recon/ll_features",
        )
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "BSA-LL-001" in out
        assert "BSA-LL-003" in out
        assert "BSA-LL-CAP-001" in out


# ---------------------------------------------------------------------------
# IoT profile audit
# ---------------------------------------------------------------------------


def _topo(*service_uuids: str) -> Dict[str, Any]:
    return {
        "services": [{"uuid": u, "characteristics": []} for u in service_uuids],
    }


def _adv(**mfg) -> Dict[str, Any]:
    return {
        "address_type": "Resolvable Random",
        "name": "",
        "service_uuids": [],
        "manufacturer_data": dict(mfg),
        "service_data": {},
    }


class TestIotClassification:
    def test_heart_rate_service_to_wearable(self, iot_mod):
        topo = _topo("0000180d-0000-1000-8000-00805f9b34fb")
        findings = iot_mod.classify("AA:BB:CC:DD:EE:10", None, topo)
        cats = [f.category for f in findings]
        assert any("wearable" in c for c in cats)

    def test_hid_service_to_hid_category(self, iot_mod):
        topo = _topo("00001812-0000-1000-8000-00805f9b34fb")
        findings = iot_mod.classify("AA:BB:CC:DD:EE:11", None, topo)
        assert any("HID" in f.category for f in findings)
        keystroke_module_listed = any(
            "keystroke_injection" in m
            for f in findings for m in f.suggested_modules
        )
        assert keystroke_module_listed

    def test_smart_lock_prefix(self, iot_mod):
        topo = _topo("0000fcf6-0000-1000-8000-00805f9b34fb")  # Yale prefix
        findings = iot_mod.classify("AA:BB:CC:DD:EE:12", None, topo)
        assert any("smart lock" in f.category for f in findings)

    def test_apple_continuity_classified(self, iot_mod):
        adv = _adv(**{"0x004C (Apple)": "0a01"})
        findings = iot_mod.classify("AA:BB:CC:DD:EE:13", adv, None)
        assert any("Apple" in f.category or "iOS" in f.category for f in findings)

    def test_ibeacon_classified(self, iot_mod):
        # Build a valid iBeacon payload.
        payload = "0215" + "f1" * 16 + "0001" + "0002" + "c5"
        adv = _adv(**{"0x004C (Apple)": payload})
        findings = iot_mod.classify("AA:BB:CC:DD:EE:14", adv, None)
        cats = [f.category for f in findings]
        assert any("iBeacon" in c for c in cats)

    def test_findmy_classified(self, iot_mod):
        adv = _adv(**{"0x004C (Apple)": "1200112233"})
        findings = iot_mod.classify("AA:BB:CC:DD:EE:15", adv, None)
        assert any("FindMy" in f.category for f in findings)

    def test_no_recognised_data_empty(self, iot_mod):
        findings = iot_mod.classify("AA:BB:CC:DD:EE:16", None, None)
        assert findings == []

    def test_dedup_categories(self, iot_mod):
        # Heart Rate service twice -> still one wearable category.
        topo = _topo(
            "0000180d-0000-1000-8000-00805f9b34fb",
            "0000180d-0000-1000-8000-00805f9b34fb",
        )
        findings = iot_mod.classify("AA:BB:CC:DD:EE:17", None, topo)
        cats = [f.category for f in findings]
        # Exactly one Heart Rate wearable emission.
        assert cats.count("wearable / health (Heart Rate)") == 1


class TestIotEndToEnd:
    def test_run_against_planted(self, iot_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/iot_profile_audit")
        h = isolated_store.add_host("AA:BB:CC:DD:EE:18")
        isolated_store.add_fingerprint(
            h, "gatt_topology",
            _topo("0000180f-0000-1000-8000-00805f9b34fb"),
            source_module="recon/ble_target_enum",
        )
        isolated_store.add_fingerprint(
            h, "adv",
            _adv(**{"0x0157 (Fitbit)": "01"}),
            source_module="recon/ble_scan_full",
        )
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "wearable" in out.lower() or "Fitbit" in out

    def test_empty_workspace(self, iot_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/iot_profile_audit")
        # Empty workspace causes run() to return False (consistent
        # with sibling scanners) and print a recon-pointer message.
        assert mod.run() is False
        out = capsys.readouterr().out
        assert "No hosts" in out
