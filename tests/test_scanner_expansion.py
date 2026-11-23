"""Tests for scanner expansion batch:
  - modules/scanners/char_permission_audit
  - modules/scanners/adv_anomaly_audit
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
    name = "scanner_test_" + attr_name
    if name in sys.modules:
        del sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, Path(rel_path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def char_mod():
    return _load("modules/scanners/char_permission_audit.py", "char_perm")


@pytest.fixture
def adv_mod():
    return _load("modules/scanners/adv_anomaly_audit.py", "adv_anom")


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    yield get_store()
    reset_default_store()


# ---------------------------------------------------------------------------
# char_permission_audit rule engine
# ---------------------------------------------------------------------------


def _char(uuid: str, props: List[str], descriptors: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "uuid": uuid,
        "properties": props,
        "descriptors": descriptors or [],
    }


def _topology(*chars: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target": "AA:BB:CC:DD:EE:FF",
        "services": [{
            "uuid": "00001800-0000-1000-8000-00805f9b34fb",
            "characteristics": list(chars),
        }],
    }


class TestCharRules:
    def test_writable_device_name_fires(self, char_mod):
        topo = _topology(_char(
            "00002a00-0000-1000-8000-00805f9b34fb",
            ["read", "write"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:01", topo)
        ids = {f.rule_id for f in findings}
        assert "BSA-CHAR-001" in ids
        f = next(f for f in findings if f.rule_id == "BSA-CHAR-001")
        assert f.severity == "medium"

    def test_readonly_device_name_silent(self, char_mod):
        topo = _topology(_char(
            "00002a00-0000-1000-8000-00805f9b34fb",
            ["read"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:02", topo)
        assert "BSA-CHAR-001" not in {f.rule_id for f in findings}

    def test_writable_serial_number_fires(self, char_mod):
        topo = _topology(_char(
            "00002a25-0000-1000-8000-00805f9b34fb",
            ["read", "write"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:03", topo)
        f = next(f for f in findings if f.rule_id == "BSA-CHAR-002")
        assert f.severity == "high"
        assert "Serial Number" in f.title

    def test_writable_pnp_id_fires(self, char_mod):
        topo = _topology(_char(
            "00002a50-0000-1000-8000-00805f9b34fb",
            ["read", "write-without-response"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:04", topo)
        assert "BSA-CHAR-002" in {f.rule_id for f in findings}

    def test_control_point_write_without_response_fires(self, char_mod):
        topo = _topology(_char(
            "00002a39-0000-1000-8000-00805f9b34fb",  # Heart Rate Control Point
            ["write-without-response"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:05", topo)
        f = next(f for f in findings if f.rule_id == "BSA-CHAR-003")
        assert f.severity == "high"

    def test_control_point_plain_write_silent(self, char_mod):
        topo = _topology(_char(
            "00002a39-0000-1000-8000-00805f9b34fb",
            ["write"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:06", topo)
        assert "BSA-CHAR-003" not in {f.rule_id for f in findings}

    def test_notify_without_cccd_fires(self, char_mod):
        topo = _topology(_char(
            "00002a37-0000-1000-8000-00805f9b34fb",
            ["notify"],
            descriptors=[],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:07", topo)
        assert "BSA-CHAR-004" in {f.rule_id for f in findings}

    def test_notify_with_cccd_silent(self, char_mod):
        topo = _topology(_char(
            "00002a37-0000-1000-8000-00805f9b34fb",
            ["notify"],
            descriptors=[{"uuid": "00002902-0000-1000-8000-00805f9b34fb"}],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:08", topo)
        assert "BSA-CHAR-004" not in {f.rule_id for f in findings}

    def test_hid_report_map_info(self, char_mod):
        topo = _topology(_char(
            "00002a4b-0000-1000-8000-00805f9b34fb",
            ["read"],
        ))
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:09", topo)
        f = next(f for f in findings if f.rule_id == "BSA-CHAR-005")
        assert f.severity == "info"

    def test_clean_topology_zero_findings(self, char_mod):
        # Device Name read-only, with CCCD on the notify, no control points.
        topo = _topology(
            _char("00002a00-0000-1000-8000-00805f9b34fb", ["read"]),
            _char(
                "00002a37-0000-1000-8000-00805f9b34fb",
                ["notify"],
                descriptors=[{"uuid": "00002902-0000-1000-8000-00805f9b34fb"}],
            ),
        )
        findings = char_mod.evaluate_topology("AA:BB:CC:DD:EE:0A", topo)
        assert findings == []


class TestCharEndToEnd:
    def test_run_against_planted_topology(self, char_mod, isolated_store, capsys, tmp_path, monkeypatch):
        # Load via loader so we get the real Module class.
        loader = ModuleLoader()
        mod = loader.load("scanners/char_permission_audit")
        assert mod is not None
        h = isolated_store.add_host("AA:BB:CC:DD:EE:20")
        isolated_store.add_fingerprint(
            h, "gatt_topology",
            _topology(_char(
                "00002a00-0000-1000-8000-00805f9b34fb",
                ["read", "write"],
            )),
            source_module="recon/ble_target_enum",
        )
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "BSA-CHAR-001" in out

    def test_run_reports_missing_fingerprint(self, char_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/char_permission_audit")
        isolated_store.add_host("AA:BB:CC:DD:EE:21")
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "Missing gatt_topology" in out


# ---------------------------------------------------------------------------
# adv_anomaly_audit rule engine
# ---------------------------------------------------------------------------


def _adv(
    address_type: str = "Resolvable Random",
    name: str = "phone",
    manufacturer_data: Dict[str, str] = None,
    service_data: Dict[str, str] = None,
) -> Dict[str, Any]:
    return {
        "address_type": address_type,
        "name": name,
        "rssi": -55,
        "tx_power": None,
        "service_uuids": [],
        "manufacturer_data": manufacturer_data or {},
        "service_data": service_data or {},
        "platform_data": {},
    }


class TestAdvRules:
    def test_public_address_fires(self, adv_mod):
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:30",
            _adv(address_type="Public"),
        )
        ids = {f.rule_id for f in findings}
        assert "BSA-ADV-001" in ids

    def test_resolvable_random_silent(self, adv_mod):
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:31",
            _adv(address_type="Resolvable Random"),
        )
        assert "BSA-ADV-001" not in {f.rule_id for f in findings}

    def test_apple_continuity_handoff_fires(self, adv_mod):
        # Sub-type 0x0C = Handoff. Manufacturer key includes "0x004C".
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:32",
            _adv(manufacturer_data={"0x004C (Apple)": "0c0102030405"}),
        )
        f = next(f for f in findings if f.rule_id == "BSA-ADV-002")
        assert "Handoff" in f.title

    def test_apple_continuity_findmy_fires(self, adv_mod):
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:33",
            _adv(manufacturer_data={"0x004C (Apple)": "12001122334455"}),
        )
        f = next(f for f in findings if f.rule_id == "BSA-ADV-002")
        assert "FindMy" in f.title

    def test_apple_non_continuity_silent(self, adv_mod):
        # Sub-type 0xFF is not in the leaky table.
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:34",
            _adv(manufacturer_data={"0x004C (Apple)": "ff00"}),
        )
        assert "BSA-ADV-002" not in {f.rule_id for f in findings}

    def test_eddystone_uid_fires(self, adv_mod):
        # Frame byte 0x00 = UID.
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:35",
            _adv(service_data={
                "0000feaa-0000-1000-8000-00805f9b34fb":
                    "00ee" + "00" * 10 + "11" * 6 + "0000",
            }),
        )
        assert "BSA-ADV-003" in {f.rule_id for f in findings}

    def test_eddystone_url_fires_low(self, adv_mod):
        # Frame byte 0x10 = URL.
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:36",
            _adv(service_data={
                "0000feaa-0000-1000-8000-00805f9b34fb":
                    "10ee00" + "676f6f676c65",  # "google"
            }),
        )
        f = next(f for f in findings if f.rule_id == "BSA-ADV-004")
        assert f.severity == "low"

    def test_eddystone_unknown_frame_silent(self, adv_mod):
        # Frame byte 0xA0 not mapped.
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:37",
            _adv(service_data={
                "0000feaa-0000-1000-8000-00805f9b34fb": "a000",
            }),
        )
        ids = {f.rule_id for f in findings}
        assert "BSA-ADV-003" not in ids
        assert "BSA-ADV-004" not in ids

    def test_oversized_name_fires(self, adv_mod):
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:38",
            _adv(name="VendorModel-XYZ-12345-fw9.9.9"),
        )
        f = next(f for f in findings if f.rule_id == "BSA-ADV-005")
        assert f.severity == "low"

    def test_short_name_silent(self, adv_mod):
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:39",
            _adv(name="lamp"),
        )
        assert "BSA-ADV-005" not in {f.rule_id for f in findings}

    def test_ibeacon_fires(self, adv_mod):
        # iBeacon: sub-type 0x02, length 0x15, then 16 UUID + 2 major + 2 minor + 1 TX.
        proximity = "f1" * 16
        major = "0001"
        minor = "0002"
        tx = "c5"
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:3A",
            _adv(manufacturer_data={"0x004C (Apple)": "0215" + proximity + major + minor + tx}),
        )
        f = next(f for f in findings if f.rule_id == "BSA-ADV-006")
        assert f.matched["proximity_uuid"] == proximity
        assert f.matched["major"] == 1
        assert f.matched["minor"] == 2

    def test_clean_resolvable_random_zero_findings(self, adv_mod):
        findings = adv_mod.evaluate_adv(
            "AA:BB:CC:DD:EE:3B",
            _adv(address_type="Resolvable Random", name="lamp"),
        )
        assert findings == []


class TestAdvEndToEnd:
    def test_run_against_planted_adv(self, adv_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/adv_anomaly_audit")
        h = isolated_store.add_host("AA:BB:CC:DD:EE:40")
        isolated_store.add_fingerprint(
            h, "adv",
            _adv(
                address_type="Public",
                manufacturer_data={"0x004C (Apple)": "0c01"},
            ),
            source_module="recon/ble_scan_full",
        )
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "BSA-ADV-001" in out
        assert "BSA-ADV-002" in out

    def test_min_severity_filter(self, adv_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/adv_anomaly_audit")
        h = isolated_store.add_host("AA:BB:CC:DD:EE:41")
        # Only low-severity finding.
        isolated_store.add_fingerprint(
            h, "adv", _adv(address_type="Public"),
            source_module="recon/ble_scan_full",
        )
        mod.set_option("min_severity", "high")
        assert mod.run() is True
        out = capsys.readouterr().out
        assert "BSA-ADV-001" not in out

    def test_run_empty_workspace(self, adv_mod, isolated_store, capsys):
        loader = ModuleLoader()
        mod = loader.load("scanners/adv_anomaly_audit")
        assert mod.run() is False
        out = capsys.readouterr().out
        assert "No hosts" in out
