"""End-to-end test for modules/scanners/cve_match.py.

Loads the module via the project's ModuleLoader, plants fingerprints
in an isolated store, runs the module, and inspects the side effects
(self.add_result entries + stdout for confidence and gap messages).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from core.loader import ModuleLoader
from core.store import get_store, reset_default_store


@pytest.fixture
def loaded(tmp_path: Path, monkeypatch):
    """Yield (module_instance, store) with isolated store + populated hosts."""
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    loader = ModuleLoader()
    mod = loader.load("scanners/cve_match")
    assert mod is not None, "cve_match module did not load"
    store = get_store()
    yield mod, store
    reset_default_store()


def _plant_knob_vulnerable_host(store):
    h = store.add_host("AA:11:22:33:44:55", name="knob-target")
    store.add_fingerprint(
        h, "lmp_features",
        {
            "target": h.address,
            "lmp_version": 0x09,             # 5.0
            "lmp_version_label": "5.0",
            "manufacturer_id": 0x004C,
            "manufacturer_label": "Apple",
            "lmp_subversion": 0x0001,
            "page_0_hex": "bfeeff",
            "page_0_bits": {"Encryption": True},
        },
        source_module="recon/lmp_features",
    )
    return h


def _plant_patched_host(store):
    h = store.add_host("BB:11:22:33:44:55", name="patched")
    store.add_fingerprint(
        h, "lmp_features",
        {
            "lmp_version": 0x0B,             # 5.2, post-KNOB
            "page_0_bits": {"Encryption": True},
        },
    )
    return h


class TestModuleRun:
    def test_no_hosts_yields_info_and_returns_false(self, loaded, capsys):
        mod, _store = loaded
        ok = mod.run()
        assert ok is False
        out = capsys.readouterr().out
        assert "No hosts in workspace" in out

    def test_vulnerable_host_produces_finding(self, loaded, capsys):
        mod, store = loaded
        _plant_knob_vulnerable_host(store)
        ok = mod.run()
        assert ok is True
        out = capsys.readouterr().out
        # Output contains the CVE id, the matched host, the confidence.
        assert "CVE-2019-9506" in out
        assert "AA:11:22:33:44:55" in out
        assert "medium" in out      # KNOB confidence
        # add_result captured the finding.
        results = mod.results
        cve_ids = [r["cve"] for r in results]
        assert "CVE-2019-9506" in cve_ids

    def test_patched_host_yields_no_findings(self, loaded, capsys):
        mod, store = loaded
        _plant_patched_host(store)
        mod.run()
        out = capsys.readouterr().out
        # No KNOB / BIAS / BLUFFS table rows.
        assert "CVE matches" not in out or "Total: 0" in out
        assert "No matching CVEs" in out or len(mod.results) == 0

    def test_gap_reported_when_no_fingerprint(self, loaded, capsys):
        mod, store = loaded
        store.add_host("CC:11:22:33:44:55", name="no-fingerprint")
        mod.run()
        out = capsys.readouterr().out
        # The honesty message: tell the operator what recon to run.
        assert "Missing lmp_features fingerprint" in out
        assert "recon/lmp_features" in out

    def test_target_filter_only_scans_that_host(self, loaded, capsys):
        mod, store = loaded
        _plant_knob_vulnerable_host(store)
        _plant_patched_host(store)
        mod.set_option("target", "AA:11:22:33:44:55")
        mod.run()
        results = mod.results
        for r in results:
            assert r["host"] == "AA:11:22:33:44:55"

    def test_min_confidence_filter(self, loaded, capsys):
        mod, store = loaded
        # The host that triggers BIAS (CVE-2020-10135, confidence=low) too.
        h = store.add_host("DD:11:22:33:44:55")
        store.add_fingerprint(
            h, "lmp_features",
            {
                "lmp_version": 0x09,
                "page_0_bits": {"Encryption": True},
                "page_2_bits": {"Secure Connections (Controller)": True},
            },
        )
        mod.set_option("min_confidence", "medium")
        mod.run()
        # BIAS (low) should be filtered out; KNOB / BLUFFS (medium) stay.
        confidences = {r["confidence"] for r in mod.results}
        assert "low" not in confidences

    def test_unknown_target_errors_cleanly(self, loaded, capsys):
        mod, _store = loaded
        mod.set_option("target", "00:00:00:00:00:00")
        ok = mod.run()
        assert ok is False
        out = capsys.readouterr().out
        assert "No stored host matches" in out
