"""Tests for the fingerprints table in the Store and the
`_persist_fingerprint` hook in the three recon feature modules.

Hardware paths are NOT exercised. We unit-test the persistence step
directly by calling each module's `_persist_fingerprint(target, result)`
helper, which is what the real `run()` method calls after a successful
probe.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

from core.store import (
    DEFAULT_WORKSPACE,
    Fingerprint,
    Store,
    get_store,
    reset_default_store,
)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(path=tmp_path / "fp.db")
    yield s
    s.close()


# Store API -----------------------------------------------------------------


class TestAddFingerprint:
    def test_round_trip_with_dict(self, store: Store):
        h = store.add_host("AA:11:22:33:44:55")
        fp = store.add_fingerprint(
            h, kind="lmp_features",
            data={"version": "5.0", "secure_connections_controller": False},
            source_module="recon/lmp_features",
        )
        assert isinstance(fp, Fingerprint)
        assert fp.host_id == h.id
        assert fp.kind == "lmp_features"
        # Stored value is JSON-encoded dict.
        decoded = json.loads(fp.data)
        assert decoded["version"] == "5.0"
        assert decoded["secure_connections_controller"] is False

    def test_accepts_pre_encoded_json_string(self, store: Store):
        fp = store.add_fingerprint(
            None, kind="ll_features",
            data='{"x":1}',
        )
        assert fp.data == '{"x":1}'

    def test_auto_creates_host_when_given_address(self, store: Store):
        fp = store.add_fingerprint(
            "CC:DD:EE:FF:00:11", kind="lmp_features", data={}
        )
        assert fp.host_id is not None
        h = store.get_host("CC:DD:EE:FF:00:11")
        assert h is not None and h.id == fp.host_id

    def test_empty_kind_rejected(self, store: Store):
        with pytest.raises(ValueError):
            store.add_fingerprint(None, kind="", data={})

    def test_source_module_recorded(self, store: Store):
        fp = store.add_fingerprint(
            None, kind="lmp_features", data={},
            source_module="recon/lmp_features",
        )
        assert fp.source_module == "recon/lmp_features"

    def test_workspace_is_active_one(self, tmp_path: Path):
        s = Store(path=tmp_path / "ws.db", workspace="alpha")
        try:
            fp = s.add_fingerprint(None, kind="lmp_features", data={})
            assert fp.workspace == "alpha"
        finally:
            s.close()


class TestListAndLatest:
    def test_list_returns_recent_first(self, store: Store):
        h = store.add_host("AA:11:22:33:44:55")
        a = store.add_fingerprint(h, "lmp_features", {"x": 1})
        b = store.add_fingerprint(h, "lmp_features", {"x": 2})
        rows = store.list_fingerprints(host=h, kind="lmp_features")
        assert [r.id for r in rows] == [b.id, a.id]

    def test_filter_by_host(self, store: Store):
        h1 = store.add_host("AA:11:22:33:44:55")
        h2 = store.add_host("BB:11:22:33:44:55")
        store.add_fingerprint(h1, "lmp_features", {})
        store.add_fingerprint(h2, "lmp_features", {})
        store.add_fingerprint(None, "lmp_features", {})
        assert len(store.list_fingerprints(host=h1)) == 1
        assert len(store.list_fingerprints(host=h2)) == 1

    def test_filter_by_kind(self, store: Store):
        store.add_fingerprint(None, "lmp_features", {})
        store.add_fingerprint(None, "ll_features", {})
        store.add_fingerprint(None, "smp_pairing", {})
        assert len(store.list_fingerprints(kind="ll_features")) == 1
        assert len(store.list_fingerprints()) == 3

    def test_latest_picks_most_recent(self, store: Store):
        h = store.add_host("AA:11:22:33:44:55")
        store.add_fingerprint(h, "ll_features", {"v": "old"})
        store.add_fingerprint(h, "ll_features", {"v": "new"})
        latest = store.latest_fingerprint(h, "ll_features")
        assert latest is not None
        assert json.loads(latest.data)["v"] == "new"

    def test_latest_returns_none_when_missing(self, store: Store):
        h = store.add_host("AA:11:22:33:44:55")
        assert store.latest_fingerprint(h, "ll_features") is None


class TestWorkspaceIsolation:
    def test_fingerprints_scoped_per_workspace(self, tmp_path: Path):
        path = tmp_path / "ws.db"
        a = Store(path=path, workspace="alpha")
        b = Store(path=path, workspace="beta")
        try:
            a.add_fingerprint(None, "lmp_features", {"x": 1})
            assert len(a.list_fingerprints()) == 1
            assert len(b.list_fingerprints()) == 0
        finally:
            a.close()
            b.close()


# Recon module integration ---------------------------------------------------


def _load_module(rel_path: str):
    """Load a module file fresh, bypassing any cached state."""
    name = "recon_test_" + rel_path.replace("/", "_").replace(".", "_")
    if name in sys.modules:
        del sys.modules[name]
    import importlib.util as _util
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


class TestPersistFromReconModules:
    def test_lmp_features_writes_fingerprint(self, isolated_store, capsys):
        mod = _load_module("modules/recon/lmp_features.py")
        m = mod.Module()
        m._persist_fingerprint(
            "AA:BB:CC:DD:EE:01",
            {"target": "AA:BB:CC:DD:EE:01", "page_0_hex": "deadbeef"},
        )
        rows = isolated_store.list_fingerprints(kind="lmp_features")
        assert len(rows) == 1
        decoded = json.loads(rows[0].data)
        assert decoded["page_0_hex"] == "deadbeef"
        assert rows[0].source_module == "recon/lmp_features"
        # Host was created.
        assert isolated_store.get_host("AA:BB:CC:DD:EE:01") is not None
        out = capsys.readouterr().out
        assert "fingerprint recorded" in out

    def test_ll_features_writes_fingerprint(self, isolated_store):
        mod = _load_module("modules/recon/ll_features.py")
        m = mod.Module()
        m._persist_fingerprint(
            "AA:BB:CC:DD:EE:02",
            {"target": "AA:BB:CC:DD:EE:02", "ll_features_hex": "01"},
        )
        rows = isolated_store.list_fingerprints(kind="ll_features")
        assert len(rows) == 1
        assert rows[0].source_module == "recon/ll_features"

    def test_ble_pairing_writes_fingerprint(self, isolated_store):
        mod = _load_module("modules/recon/ble_pairing_features.py")
        m = mod.Module()
        m._persist_fingerprint(
            "AA:BB:CC:DD:EE:03",
            {"target": "AA:BB:CC:DD:EE:03", "sc": False, "max_key_size": 16},
        )
        rows = isolated_store.list_fingerprints(kind="smp_pairing")
        assert len(rows) == 1
        assert rows[0].source_module == "recon/ble_pairing_features"

    def test_persist_failure_does_not_raise(self, isolated_store, monkeypatch, capsys):
        mod = _load_module("modules/recon/lmp_features.py")
        m = mod.Module()
        # Force the store call to blow up. The module must swallow and warn.
        class BrokenStore:
            def add_host(self, *a, **kw):
                raise RuntimeError("simulated store outage")
            def add_fingerprint(self, *a, **kw):  # not reached
                raise AssertionError("should not be called")
        monkeypatch.setattr(type(m), "store", property(lambda self: BrokenStore()))
        m._persist_fingerprint("AA:BB:CC:DD:EE:09", {"x": 1})
        out = capsys.readouterr().out
        assert "fingerprint store skipped" in out
