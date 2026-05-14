"""Tests for core/loader.py module index, search, partial-match, stats."""

import pytest

from core.base import ModuleType
from core.loader import ModuleLoader


@pytest.fixture(scope="module")
def loader():
    """A loader pointed at the real modules/ tree."""
    return ModuleLoader()


def test_indexes_modules(loader):
    assert loader.module_count > 0


def test_stats_returns_counts_per_type(loader):
    stats = loader.stats()
    assert isinstance(stats, dict)
    # We expect at least exploits/scanners/recon to be present.
    expected_types = {"exploits", "scanners", "recon", "dos", "auxiliary", "post"}
    present = expected_types & set(stats.keys())
    assert present, f"expected at least one of {expected_types} in stats, got {stats}"


def test_list_by_type_filters_by_directory_prefix(loader):
    exploits = loader.list_by_type(ModuleType.EXPLOIT)
    assert all(p.startswith("exploits/") for p in exploits)


def test_search_path_match(loader):
    # 'll_features' is a known recon module
    results = loader.search("ll_features")
    assert any("ll_features" in r for r in results)


def test_load_known_recon_module(loader):
    """The three recon modules we touched in Phase 0 must instantiate."""
    for name in ("recon/ble_pairing_features", "recon/ll_features", "recon/lmp_features"):
        mod = loader.load(name)
        assert mod is not None, f"failed to load {name}"
        assert mod.info.name
        assert "target" in mod.options


def test_partial_match_basename_resolves(loader):
    """`load("ll_features")` should resolve to `recon/ll_features`."""
    mod = loader.load("ll_features")
    assert mod is not None
    assert mod.info.name == "BLE LL FeatureSet Reader"


def test_load_unknown_returns_none(loader, capsys):
    assert loader.load("not/a/real/module_xyz") is None


def test_refresh_repopulates_index(loader):
    before = loader.module_count
    loader.refresh()
    assert loader.module_count == before
