"""Tests for the `workspace` command in the BlueSploit interpreter.

Uses an isolated tmp_path-backed Store via BLUESPLOIT_HOME.
"""

from pathlib import Path

import pytest

from core.interpreter import BlueSploitInterpreter
from core.store import DEFAULT_WORKSPACE, get_store, reset_default_store


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()
    sh = BlueSploitInterpreter()
    yield sh
    reset_default_store()


class TestDoWorkspaceShow:
    def test_no_args_prints_active(self, shell, capsys):
        shell.do_workspace("")
        out = capsys.readouterr().out
        assert "Active workspace" in out
        assert DEFAULT_WORKSPACE in out


class TestDoWorkspaceList:
    def test_list_shows_default(self, shell, capsys):
        shell.do_workspace("list")
        out = capsys.readouterr().out
        assert DEFAULT_WORKSPACE in out
        assert "Total:" in out

    def test_list_shows_row_counts(self, shell, capsys):
        s = get_store()
        s.add_host("AA:11:22:33:44:55")
        s.add_host("BB:11:22:33:44:55")
        s.add_credential(None, kind="LinkKey", value="abc")

        shell.do_workspace("list")
        out = capsys.readouterr().out
        # active workspace row should show counts in the same line
        lines = [ln for ln in out.splitlines() if DEFAULT_WORKSPACE in ln]
        assert any("2" in ln for ln in lines), f"expected 2 hosts in: {lines}"
        # active marker present
        assert any(ln.strip().startswith("*") for ln in lines)


class TestDoWorkspaceUse:
    def test_use_switches_active(self, shell, capsys):
        shell.do_workspace("use engagement-x")
        out = capsys.readouterr().out
        assert "engagement-x" in out
        assert get_store().workspace == "engagement-x"

    def test_use_persists_across_get_store(self, shell, tmp_path, monkeypatch):
        shell.do_workspace("use engagement-x")
        # Drop the singleton and reopen against the same DB.
        reset_default_store()
        # Re-pin env so the same store.db is used.
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
        assert get_store().workspace == "engagement-x"

    def test_use_with_no_name_errors(self, shell, capsys):
        shell.do_workspace("use")
        out = capsys.readouterr().out
        assert "Usage" in out
        assert get_store().workspace == DEFAULT_WORKSPACE

    def test_use_isolates_hosts(self, shell, capsys):
        s = get_store()
        s.add_host("AA:11:22:33:44:55", name="default-host")
        shell.do_workspace("use engagement-x")
        assert s.get_host("AA:11:22:33:44:55") is None
        s.add_host("BB:11:22:33:44:55", name="x-host")
        # Switch back.
        shell.do_workspace("use " + DEFAULT_WORKSPACE)
        assert s.get_host("AA:11:22:33:44:55").name == "default-host"


class TestDoWorkspaceDelete:
    def test_delete_purges_rows(self, shell, capsys):
        s = get_store()
        # plant rows in target workspace
        shell.do_workspace("use to-purge")
        s.add_host("AA:11:22:33:44:55")
        s.add_credential(None, kind="LinkKey", value="abc")
        # switch back and delete
        shell.do_workspace("use " + DEFAULT_WORKSPACE)
        shell.do_workspace("delete to-purge")
        out = capsys.readouterr().out
        assert "Deleted workspace" in out or "had no rows" in out
        # ensure rows are gone
        shell.do_workspace("use to-purge")
        assert s.list_hosts() == []
        assert s.list_credentials() == []

    def test_delete_active_rejected(self, shell, capsys):
        shell.do_workspace("use engagement-x")
        shell.do_workspace("delete engagement-x")
        out = capsys.readouterr().out
        assert "active" in out.lower()

    def test_delete_default_rejected(self, shell, capsys):
        shell.do_workspace("use engagement-x")
        shell.do_workspace(f"delete {DEFAULT_WORKSPACE}")
        out = capsys.readouterr().out
        assert "default" in out.lower()

    def test_delete_with_no_name_errors(self, shell, capsys):
        shell.do_workspace("delete")
        out = capsys.readouterr().out
        assert "Usage" in out


class TestUnknownSubcommand:
    def test_unknown_prints_help_hint(self, shell, capsys):
        shell.do_workspace("flarp")
        out = capsys.readouterr().out
        assert "Unknown subcommand" in out
        assert "list" in out and "use" in out


class TestCompleteWorkspace:
    def test_subcommand_completion(self, shell):
        out = shell.complete_workspace("", "workspace ", 10, 10)
        assert set(out) >= {"list", "use", "delete"}

    def test_use_value_completes_workspace_names(self, shell):
        s = get_store()
        s.set_workspace("engagement-x")
        s.set_workspace("default")  # back to default so 'engagement-x' is just a name now

        out = shell.complete_workspace("", "workspace use ", 14, 14)
        assert "engagement-x" in out
        assert DEFAULT_WORKSPACE in out

    def test_use_value_prefix_filter(self, shell):
        s = get_store()
        s.set_workspace("engagement-x")
        s.set_workspace("engagement-y")
        s.set_workspace(DEFAULT_WORKSPACE)

        out = shell.complete_workspace(
            "engagement-x", "workspace use engagement-x", 14, 26
        )
        assert "engagement-x" in out
        assert "engagement-y" not in out

    def test_unknown_subcommand_value_completion_empty(self, shell):
        out = shell.complete_workspace("", "workspace flarp ", 16, 16)
        assert out == []
