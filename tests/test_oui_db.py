"""Tests for the OUI database loader and recon/oui_lookup integration.

Uses a temp gzipped CSV in most cases, never patches the real bundled
snapshot at data/oui/oui.csv.gz. The shipped snapshot is still
exercised by `test_shipped_snapshot_loads_and_resolves` at the bottom.
"""

from __future__ import annotations

import gzip
import importlib
import sys
from pathlib import Path

import pytest


@pytest.fixture
def oui_module(tmp_path: Path, monkeypatch):
    """Yield a freshly reloaded copy of `modules.recon.oui_lookup` whose
    bundled OUI snapshot path points at a tmp file. The module's
    process-wide cache is reset between tests so the path stays fresh.
    """
    # Make a tmp gz file pretending to be the IEEE snapshot.
    csv_text = (
        "oui,vendor\n"
        "ABCDEF,Test Vendor Inc\n"
        "112233,Another Vendor Corp\n"
        "00CAFE,Builtin Will Win Co  Ltd\n"
    )
    tmp_gz = tmp_path / "oui.csv.gz"
    with gzip.open(tmp_gz, "wt", encoding="utf-8") as f:
        f.write(csv_text)

    # Reload the module so the module-level _OUI_CSV_GZ constant can be
    # overridden cleanly.
    if "modules.recon.oui_lookup" in sys.modules:
        del sys.modules["modules.recon.oui_lookup"]

    import importlib.util as _util
    spec = _util.spec_from_file_location(
        "modules.recon.oui_lookup_test_copy",
        Path("modules/recon/oui_lookup.py"),
    )
    mod = _util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    monkeypatch.setattr(mod, "_OUI_CSV_GZ", tmp_gz)
    monkeypatch.setattr(mod, "_oui_db_cache", None)

    # Plant a builtin entry that should beat the CSV entry on conflict.
    monkeypatch.setitem(mod.BUILTIN_OUI_DB, "00:CA:FE", ("BuiltinName", "Builtin full name"))

    yield mod


# _load_oui_db ---------------------------------------------------------------


class TestLoadOuiDB:
    def test_csv_entries_loaded(self, oui_module):
        db = oui_module._load_oui_db()
        assert ("Test", "Test Vendor Inc") == db["AB:CD:EF"]
        assert ("Another", "Another Vendor Corp") == db["11:22:33"]

    def test_builtin_overrides_csv(self, oui_module):
        # CSV had 00CAFE -> "Builtin Will Win Co  Ltd"; the BUILTIN entry
        # we planted has short_name="BuiltinName". Builtin must win.
        db = oui_module._load_oui_db()
        assert db["00:CA:FE"] == ("BuiltinName", "Builtin full name")

    def test_cached_across_calls(self, oui_module):
        first = oui_module._load_oui_db()
        second = oui_module._load_oui_db()
        # The cache returns the same dict object, not a copy.
        assert first is second

    def test_falls_back_when_csv_missing(self, oui_module, tmp_path, monkeypatch):
        # Point the path at a file that doesn't exist; cache reset so the
        # next load actually runs.
        monkeypatch.setattr(oui_module, "_OUI_CSV_GZ", tmp_path / "nope.csv.gz")
        monkeypatch.setattr(oui_module, "_oui_db_cache", None)
        db = oui_module._load_oui_db()
        # Builtin entries still present.
        sample_oui = next(iter(oui_module.BUILTIN_OUI_DB))
        assert sample_oui in db

    def test_bad_csv_header_falls_back(self, oui_module, tmp_path, monkeypatch):
        bad = tmp_path / "bad.csv.gz"
        with gzip.open(bad, "wt", encoding="utf-8") as f:
            f.write("not_a_proper_header\n")
            f.write("ABCDEF,Should be ignored\n")
        monkeypatch.setattr(oui_module, "_OUI_CSV_GZ", bad)
        monkeypatch.setattr(oui_module, "_oui_db_cache", None)
        db = oui_module._load_oui_db()
        # AB:CD:EF must NOT be present, since we bailed on the header check.
        assert "AB:CD:EF" not in db

    def test_short_name_is_first_word(self, oui_module):
        # CSV row "ABCDEF,Test Vendor Inc" -> short name "Test".
        assert oui_module._load_oui_db()["AB:CD:EF"][0] == "Test"

    def test_garbage_rows_skipped(self, tmp_path, monkeypatch):
        # Reload module fresh for this odd-fixture case.
        if "modules.recon.oui_lookup" in sys.modules:
            del sys.modules["modules.recon.oui_lookup"]
        import importlib.util as _util
        spec = _util.spec_from_file_location(
            "modules.recon.oui_lookup_test_copy_garbage",
            Path("modules/recon/oui_lookup.py"),
        )
        mod = _util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        bad = tmp_path / "garbage.csv.gz"
        with gzip.open(bad, "wt", encoding="utf-8") as f:
            f.write("oui,vendor\n")
            f.write("short,too short\n")           # wrong length
            f.write("ABCDEF,\n")                   # empty vendor
            f.write("FFEEDD,Real Vendor Co\n")     # the keeper
        monkeypatch.setattr(mod, "_OUI_CSV_GZ", bad)
        monkeypatch.setattr(mod, "_oui_db_cache", None)
        db = mod._load_oui_db()
        assert "FF:EE:DD" in db
        assert db["FF:EE:DD"] == ("Real", "Real Vendor Co")
        assert "AB:CD:EF" not in db  # empty vendor dropped


# Integration: shipped snapshot ---------------------------------------------


def test_shipped_snapshot_loads_and_resolves():
    """End-to-end against the real snapshot committed at data/oui/oui.csv.gz.

    Pins a specific known-good OUI that has been assigned to Apple in
    the IEEE registry for years; if this ever fails the snapshot has
    been regenerated and something went wrong upstream.
    """
    # Reload module fresh, default path.
    if "modules.recon.oui_lookup" in sys.modules:
        del sys.modules["modules.recon.oui_lookup"]
    import importlib.util as _util
    spec = _util.spec_from_file_location(
        "modules.recon.oui_lookup_shipped",
        Path("modules/recon/oui_lookup.py"),
    )
    mod = _util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._oui_db_cache = None
    db = mod._load_oui_db()
    # Snapshot should be much larger than the inline curated dict.
    assert len(db) > 5_000
    # Apple OUI 003065 (Apple Computer) has been in IEEE since the 90s.
    apple_short, apple_full = db["00:30:65"]
    assert "Apple" in apple_full or "Apple" in apple_short
