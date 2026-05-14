"""Tests for the upgraded `help` command: categorized overview, per-command
detail with example, and module-info rendering."""

from pathlib import Path

import pytest

from core.interpreter import BlueSploitInterpreter
from core.store import reset_default_store


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()
    sh = BlueSploitInterpreter()
    yield sh
    reset_default_store()


# Overview -------------------------------------------------------------------


class TestHelpOverview:
    def test_groups_present(self, shell, capsys):
        shell.do_help("")
        out = capsys.readouterr().out
        # Each category appears as a table title.
        assert "Module navigation" in out
        assert "Module options" in out
        assert "Engagement state" in out
        assert "Persistence" in out
        assert "Automation" in out
        assert "Utility" in out

    def test_new_commands_listed(self, shell, capsys):
        """The Phase 1 verbs should all be reachable from `help`."""
        shell.do_help("")
        out = capsys.readouterr().out
        for command in ("hosts", "creds", "workspace", "setg", "unsetg", "resource"):
            assert command in out, f"missing {command} in help overview"

    def test_examples_rendered(self, shell, capsys):
        shell.do_help("")
        out = capsys.readouterr().out
        # A representative example string from the catalog.
        assert "use exploits/knob" in out
        assert "workspace use clientA" in out

    def test_trailing_hint_present(self, shell, capsys):
        shell.do_help("")
        out = capsys.readouterr().out
        assert "help <command>" in out
        assert "help <module/path>" in out


# Command detail -------------------------------------------------------------


class TestHelpCommand:
    def test_known_command_shows_summary_and_example(self, shell, capsys):
        shell.do_help("workspace")
        out = capsys.readouterr().out
        assert "workspace" in out
        assert "Example:" in out
        assert "workspace use clientA" in out

    def test_known_command_shows_docstring(self, shell, capsys):
        shell.do_help("hosts")
        out = capsys.readouterr().out
        # `do_hosts` docstring covers the `hosts` and `hosts <filter>` forms.
        assert "List all hosts" in out or "current workspace" in out

    def test_case_insensitive(self, shell, capsys):
        shell.do_help("HOSTS")
        out = capsys.readouterr().out
        # Same content as the lowercase form.
        assert "hosts" in out

    def test_unknown_command_falls_through_without_raising(self, shell):
        # `cmd.Cmd.do_help` writes "*** No help on <arg>" to its own
        # `self.stdout` for unknown args. We do not own that path, so the
        # behavior worth pinning is just that we route to it cleanly:
        # do_help returns None and does not raise.
        assert shell.do_help("flarp-not-a-command") is None


# Module info ----------------------------------------------------------------


class TestHelpModule:
    def test_help_on_full_module_path(self, shell, capsys):
        # recon/discovery is one of the modules guaranteed to exist.
        shell.do_help("recon/discovery")
        out = capsys.readouterr().out
        # Module name + section headers should land in the output.
        assert "Options" in out
        assert "Protocol" in out
        assert "Severity" in out

    def test_help_renders_options_table(self, shell, capsys):
        shell.do_help("recon/discovery")
        out = capsys.readouterr().out
        # Options table headers from core/ui/tables.
        assert "Option" in out
        assert "Required" in out
        assert "Current" in out
        # Most recon modules expose `interface`.
        assert "interface" in out

    def test_help_on_partial_module_path(self, shell, capsys):
        # Substring match against the indexed module list. `ll_features`
        # is a unique substring that resolves to `recon/ll_features`.
        shell.do_help("ll_features")
        out = capsys.readouterr().out
        assert "FeatureSet" in out or "ll_features" in out
        assert "Options" in out

    def test_help_module_takes_priority_over_command_lookup(self, shell, capsys):
        # `discovery` is a substring of `recon/discovery`; ensure we
        # route to module-info rather than command-help fallback.
        shell.do_help("discovery")
        out = capsys.readouterr().out
        # Module-info renders a "Protocol :" line which `help <command>`
        # never would.
        assert "Protocol" in out
