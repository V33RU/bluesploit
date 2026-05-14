"""Tests for the `hosts` command, `set target` store resolution, and
tab completion of host addresses on `set target`.

Uses a tmp_path-backed Store via BLUESPLOIT_HOME so the real
~/.bluesploit/store.db is never touched.
"""

from pathlib import Path

import pytest

from core.base import (
    AuxiliaryModule,
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    Severity,
)
from core.interpreter import BlueSploitInterpreter
from core.store import reset_default_store


class _StubModule(AuxiliaryModule):
    info = ModuleInfo(
        name="stub", description="stub for testing",
        author=["pytest"], protocol=BTProtocol.BLE, severity=Severity.INFO,
    )

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="target", required=False, description="BD_ADDR",
        ))

    def run(self) -> bool:
        return True


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    """A BlueSploitInterpreter with an isolated Store and a stub module loaded."""
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    reset_default_store()
    # Use cwd as history dir so we don't pollute the user's home.
    monkeypatch.chdir(tmp_path)
    sh = BlueSploitInterpreter()
    sh.current_module = _StubModule()
    sh._module_path = "test/stub"
    yield sh
    reset_default_store()


# do_hosts -------------------------------------------------------------------


class TestDoHosts:
    def test_empty_store_prints_hint(self, shell, capsys):
        shell.do_hosts("")
        out = capsys.readouterr().out
        assert "No hosts recorded yet" in out

    def test_lists_stored_hosts(self, shell, capsys):
        from core.store import get_store
        s = get_store()
        s.add_host("AA:BB:CC:DD:EE:01", name="alpha", manufacturer="Apple", rssi=-30)
        s.add_host("AA:BB:CC:DD:EE:02", name="bravo")

        shell.do_hosts("")
        out = capsys.readouterr().out
        assert "AA:BB:CC:DD:EE:01" in out
        assert "AA:BB:CC:DD:EE:02" in out
        assert "alpha" in out
        assert "bravo" in out
        assert "Apple" in out
        assert "Total: 2 host(s)" in out

    def test_filter_by_substring(self, shell, capsys):
        from core.store import get_store
        s = get_store()
        s.add_host("AA:BB:CC:DD:EE:01", name="alpha")
        s.add_host("AA:BB:CC:DD:EE:02", name="bravo")

        shell.do_hosts("alpha")
        out = capsys.readouterr().out
        assert "alpha" in out
        assert "bravo" not in out

    def test_filter_no_match(self, shell, capsys):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01", name="alpha")
        shell.do_hosts("nothing-matches-this")
        out = capsys.readouterr().out
        assert "No hosts match" in out


# do_set target resolution ---------------------------------------------------


class TestSetTargetResolution:
    def test_full_bd_addr_passes_through(self, shell):
        shell.do_set("target AA:BB:CC:DD:EE:FF")
        assert shell.current_module.get_option("target") == "AA:BB:CC:DD:EE:FF"

    def test_numeric_id_resolves_to_address(self, shell, capsys):
        from core.store import get_store
        h = get_store().add_host("AA:BB:CC:DD:EE:01", name="alpha")
        shell.do_set(f"target {h.id}")
        assert shell.current_module.get_option("target") == "AA:BB:CC:DD:EE:01"
        out = capsys.readouterr().out
        assert "Resolved" in out

    def test_numeric_id_unknown_keeps_original(self, shell, capsys):
        shell.do_set("target 99999")
        # No store match; value stays as the raw string.
        assert shell.current_module.get_option("target") == "99999"
        out = capsys.readouterr().out
        assert "No host with id 99999" in out

    def test_substring_unique_resolves(self, shell, capsys):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01", name="alpha-laptop")
        get_store().add_host("AA:BB:CC:DD:EE:02", name="bravo-phone")

        shell.do_set("target alpha")
        assert shell.current_module.get_option("target") == "AA:BB:CC:DD:EE:01"

    def test_substring_ambiguous_does_not_set(self, shell, capsys):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01", name="alpha-1")
        get_store().add_host("AA:BB:CC:DD:EE:02", name="alpha-2")

        shell.do_set("target alpha")
        # Ambiguous, target stays unset.
        assert shell.current_module.get_option("target") in (None, "")
        out = capsys.readouterr().out
        assert "Ambiguous" in out
        assert "AA:BB:CC:DD:EE:01" in out
        assert "AA:BB:CC:DD:EE:02" in out

    def test_substring_no_match_keeps_original(self, shell):
        shell.do_set("target nothing")
        assert shell.current_module.get_option("target") == "nothing"


# complete_set ---------------------------------------------------------------


class TestCompleteSetTarget:
    def test_option_name_completion_unchanged(self, shell):
        # First word completion: "set <tab>" returns option names.
        out = shell.complete_set("", "set ", 4, 4)
        assert "target" in out

    def test_value_completion_returns_store_addresses(self, shell):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01")
        get_store().add_host("AA:BB:CC:DD:EE:02")

        out = shell.complete_set("", "set target ", 11, 11)
        assert set(out) >= {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}

    def test_value_completion_filters_by_prefix(self, shell):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01")
        get_store().add_host("FF:11:22:33:44:55")

        out = shell.complete_set("AA", "set target AA", 11, 13)
        assert out == ["AA:BB:CC:DD:EE:01"]

    def test_value_completion_for_non_target_option_is_empty(self, shell):
        # We only special-case `target`. Other options return [] for value position.
        out = shell.complete_set("", "set interface ", 14, 14)
        assert out == []
