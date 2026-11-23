"""Tests for the two new BLE recon modules:
  - modules/recon/ble_scan_full.py
  - modules/recon/ble_target_enum.py

Hardware paths are NOT exercised. We unit-test the helper functions
and the persistence + rendering logic by feeding bleak-shaped stub
objects directly into the methods that consume them.
"""

from __future__ import annotations

import importlib.util as _util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.store import get_store, reset_default_store

# ---------------------------------------------------------------------------
# Module loading helpers
# ---------------------------------------------------------------------------


def _load(rel_path: str):
    name = "recon_test_" + rel_path.replace("/", "_").replace(".", "_")
    if name in sys.modules:
        del sys.modules[name]
    spec = _util.spec_from_file_location(name, Path(rel_path))
    mod = _util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def isolated_store(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    yield get_store()
    reset_default_store()


# ---------------------------------------------------------------------------
# ble_scan_full helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def scan_mod():
    return _load("modules/recon/ble_scan_full.py")


class TestAddrTypeHeuristic:
    def test_static_random(self, scan_mod):
        assert scan_mod._addr_type("FF:00:00:00:00:01") == "Static Random"

    def test_resolvable_random(self, scan_mod):
        # Top two bits 01 -> 0x40..0x7F prefix.
        assert scan_mod._addr_type("60:00:00:00:00:01") == "Resolvable Random"

    def test_public_address(self, scan_mod):
        assert scan_mod._addr_type("00:11:22:33:44:55") == "Public"

    def test_invalid_returns_empty(self, scan_mod):
        assert scan_mod._addr_type("not-an-address") == ""


class TestBuildRow:
    def _stub_adv(self, **fields):
        defaults = dict(
            local_name="laptop",
            rssi=-42,
            tx_power=4,
            service_uuids=["00001800-0000-1000-8000-00805f9b34fb"],
            manufacturer_data={0x004C: b"\x01\x02\x03"},
            service_data={"180a": b"\xab"},
            platform_data=None,
        )
        defaults.update(fields)
        return SimpleNamespace(**defaults)

    def test_row_captures_every_field(self, scan_mod):
        m = scan_mod.Module()
        # 0xD0 -> top two bits 11 -> Static Random per the helper.
        dev = SimpleNamespace(address="D0:BB:CC:DD:EE:01", name="hw-name")
        adv = self._stub_adv()
        row = m._build_row(dev, adv)
        assert row["address"] == "D0:BB:CC:DD:EE:01"
        assert row["address_type"] == "Static Random"
        assert row["name"] == "laptop"        # local_name beats device.name
        assert row["rssi"] == -42
        assert row["tx_power"] == 4
        assert row["service_uuids"] == ["00001800-0000-1000-8000-00805f9b34fb"]
        # Manufacturer data was decoded to "0x004C (Apple)" key.
        assert any("Apple" in k for k in row["manufacturer_data"])
        # Service data preserved as hex.
        assert row["service_data"]["180a"] == "ab"

    def test_name_falls_back_to_device_name(self, scan_mod):
        m = scan_mod.Module()
        dev = SimpleNamespace(address="AA:BB:CC:DD:EE:01", name="hw-name")
        adv = self._stub_adv(local_name=None)
        row = m._build_row(dev, adv)
        assert row["name"] == "hw-name"

    def test_name_empty_when_both_missing(self, scan_mod):
        m = scan_mod.Module()
        dev = SimpleNamespace(address="AA:BB:CC:DD:EE:01", name=None)
        adv = self._stub_adv(local_name=None)
        row = m._build_row(dev, adv)
        assert row["name"] == ""


class TestScanPersist:
    def test_writes_hosts_and_adv_fingerprints(self, scan_mod, isolated_store):
        m = scan_mod.Module()
        rows = [
            {
                "address": "AA:BB:CC:DD:EE:01",
                "address_type": "Public",
                "name": "alpha",
                "rssi": -30,
                "tx_power": None,
                "service_uuids": [],
                "manufacturer_data": {},
                "service_data": {},
                "platform_data": {},
            },
            {
                "address": "FF:11:22:33:44:55",
                "address_type": "Static Random",
                "name": "bravo",
                "rssi": -55,
                "tx_power": None,
                "service_uuids": ["00001800-0000-1000-8000-00805f9b34fb"],
                "manufacturer_data": {},
                "service_data": {},
                "platform_data": {},
            },
        ]
        m._persist(rows)
        hosts = isolated_store.list_hosts()
        assert len(hosts) == 2
        # Both hosts have an adv fingerprint.
        fps = isolated_store.list_fingerprints(kind="adv")
        assert len(fps) == 2
        sources = {fp.source_module for fp in fps}
        assert sources == {"recon/ble_scan_full"}


# ---------------------------------------------------------------------------
# ble_target_enum helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def enum_mod():
    return _load("modules/recon/ble_target_enum.py")


class TestEnumHelpers:
    def test_coerce_bool(self, enum_mod):
        assert enum_mod._coerce_bool(True, default=False) is True
        assert enum_mod._coerce_bool(False, default=True) is False
        assert enum_mod._coerce_bool(None, default=True) is True
        assert enum_mod._coerce_bool("true", default=False) is True
        assert enum_mod._coerce_bool("FALSE", default=True) is False
        assert enum_mod._coerce_bool("yes", default=False) is True
        assert enum_mod._coerce_bool("nope", default=False) is False

    def test_uuid16_hex_for_short_uuid(self, enum_mod):
        assert enum_mod._uuid16_hex("00001800-0000-1000-8000-00805f9b34fb") == "0x1800"
        assert enum_mod._uuid16_hex("0000180f-0000-1000-8000-00805f9b34fb") == "0x180f"

    def test_uuid16_hex_for_vendor_uuid(self, enum_mod):
        assert enum_mod._uuid16_hex("6e400001-b5a3-f393-e0a9-77656c6f6f70") == ""

    def test_strip_uuid_removes_dashes(self, enum_mod):
        out = enum_mod._strip_uuid("00001800-0000-1000-8000-00805f9b34fb")
        assert out == "0000180000001000800000805f9b34fb"

    def test_handle_renders_4_hex_digits(self, enum_mod):
        assert enum_mod._h(0x0001) == "0x0001"
        assert enum_mod._h(0x003c) == "0x003c"
        assert enum_mod._h(None) == ""


class TestEnumPersist:
    def test_writes_gatt_topology_fingerprint(self, enum_mod, isolated_store):
        m = enum_mod.Module()
        topology = {
            "target": "AA:BB:CC:DD:EE:01",
            "services": [
                {"start_handle": 0x0001, "end_handle": 0x0005,
                 "uuid": "00001800-0000-1000-8000-00805f9b34fb",
                 "uuid16": "0x1800", "name": "Generic Access",
                 "characteristics": []},
            ],
        }
        m._persist("AA:BB:CC:DD:EE:01", topology)
        fps = isolated_store.list_fingerprints(kind="gatt_topology")
        assert len(fps) == 1
        assert fps[0].source_module == "recon/ble_target_enum"
        # Host was auto-created.
        assert isolated_store.get_host("AA:BB:CC:DD:EE:01") is not None


class TestEnumRenderSmoke:
    """The render methods should not raise on representative input. We
    intentionally do not pin the exact table layout because rich's
    output adapts to terminal width; we just confirm content lands."""

    def test_services_summary(self, enum_mod, capsys):
        m = enum_mod.Module()
        services = [
            {"start_handle": 0x0001, "end_handle": 0x0005,
             "uuid": "00001800-0000-1000-8000-00805f9b34fb",
             "uuid16": "0x1800", "name": "Generic Access",
             "characteristics": []},
        ]
        m._render_services_summary(services)
        out = capsys.readouterr().out
        assert "Generic Access" in out
        assert "0x0001" in out
        assert "0x0005" in out
        # The mirage-style UUID128 form with no dashes is present.
        assert "0000180000001000800000805f9b34fb" in out

    def test_service_detail_with_characteristics(self, enum_mod, capsys):
        m = enum_mod.Module()
        svc = {
            "start_handle": 0x0001, "end_handle": 0x0005,
            "uuid": "00001800-0000-1000-8000-00805f9b34fb",
            "uuid16": "0x1800", "name": "Generic Access",
            "characteristics": [
                {
                    "decl_handle": 0x0002, "value_handle": 0x0003,
                    "uuid": "00002a00-0000-1000-8000-00805f9b34fb",
                    "uuid16": "0x2a00", "name": "Device Name",
                    "properties": ["read"], "permissions": ["Read"],
                    "value_hex": "434f524f53",  # "COROS" bytes
                    "descriptors": [],
                },
            ],
        }
        m._render_service_detail(svc)
        out = capsys.readouterr().out
        assert "Generic Access" in out
        assert "Device Name" in out
        assert "Read" in out
        assert "434f524f53" in out

    def test_service_detail_with_vendor_uuid_no_name(self, enum_mod, capsys):
        """Vendor UUIDs should render as the raw UUID128 form with no
        name, exactly like the mirage example."""
        m = enum_mod.Module()
        svc = {
            "start_handle": 0x0014, "end_handle": 0x0019,
            "uuid": "6e400001-b5a3-f393-e0a9-77656c6f6f70",
            "uuid16": "", "name": "",
            "characteristics": [],
        }
        m._render_service_detail(svc)
        out = capsys.readouterr().out
        # Title contains the raw UUID128 form, no SIG name.
        assert "6e400001b5a3f393e0a977656c6f6f70" in out
