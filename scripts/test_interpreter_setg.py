"""Tests for `setg` / `unsetg` persistence and tab completion."""

from pathlib import Path

import pytest

from core.interpreter import BlueSploitInterpreter
from core.store import get_store, reset_default_store


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()
    sh = BlueSploitInterpreter()
    yield sh
    reset_default_store()


# Store-level API ------------------------------------------------------------


class TestStoreGlobals:
    def test_set_and_list(self, tmp_path):
        from core.store import Store
        s = Store(path=tmp_path / "g.db")
        try:
            s.set_global("interface", "hci1")
            s.set_global("timeout", 99)
            persisted = s.list_globals()
            assert persisted == {"interface": "hci1", "timeout": "99"}
        finally:
            s.close()

    def test_unset_returns_true_only_if_existed(self, tmp_path):
        from core.store import Store
        s = Store(path=tmp_path / "g.db")
        try:
            s.set_global("interface", "hci1")
            assert s.unset_global("interface") is True
            assert s.unset_global("interface") is False
        finally:
            s.close()

    def test_set_empty_name_rejected(self, tmp_path):
        from core.store import Store
        s = Store(path=tmp_path / "g.db")
        try:
            with pytest.raises(ValueError):
                s.set_global("", "x")
        finally:
            s.close()


# do_setg --------------------------------------------------------------------


class TestDoSetg:
    def test_no_args_lists_current(self, shell, capsys):
        shell.do_setg("")
        out = capsys.readouterr().out
        assert "interface" in out
        assert "hci0" in out
        assert "verbose" in out

    def test_set_string_persists(self, shell, capsys, tmp_path, monkeypatch):
        shell.do_setg("interface hci2")
        assert shell.global_options["interface"] == "hci2"
        # New interpreter instance picks up persisted value.
        reset_default_store()
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
        fresh = BlueSploitInterpreter()
        assert fresh.global_options["interface"] == "hci2"

    def test_set_bool_coerces(self, shell):
        shell.do_setg("verbose true")
        assert shell.global_options["verbose"] is True
        shell.do_setg("verbose no")
        assert shell.global_options["verbose"] is False

    def test_set_int_coerces(self, shell):
        shell.do_setg("timeout 42")
        assert shell.global_options["timeout"] == 42

    def test_set_int_rejects_non_numeric(self, shell, capsys):
        shell.do_setg("timeout abc")
        out = capsys.readouterr().out
        assert "Invalid integer" in out
        # Live value untouched.
        assert shell.global_options["timeout"] == 10

    def test_unknown_option_rejected(self, shell, capsys):
        shell.do_setg("nope hello")
        out = capsys.readouterr().out
        assert "Unknown global option" in out

    def test_int_persists_as_int_after_reload(self, shell, tmp_path, monkeypatch):
        shell.do_setg("timeout 99")
        reset_default_store()
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
        fresh = BlueSploitInterpreter()
        assert fresh.global_options["timeout"] == 99
        assert isinstance(fresh.global_options["timeout"], int)


# do_unsetg ------------------------------------------------------------------


class TestDoUnsetg:
    def test_unsetg_resets_to_default(self, shell, capsys):
        shell.do_setg("interface hci2")
        shell.do_unsetg("interface")
        assert shell.global_options["interface"] == "hci0"

    def test_unsetg_persists_removal(self, shell, tmp_path, monkeypatch):
        shell.do_setg("interface hci2")
        shell.do_unsetg("interface")
        reset_default_store()
        monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
        fresh = BlueSploitInterpreter()
        assert fresh.global_options["interface"] == "hci0"

    def test_unsetg_unknown_rejected(self, shell, capsys):
        shell.do_unsetg("nope")
        out = capsys.readouterr().out
        assert "Unknown" in out

    def test_unsetg_no_arg_rejected(self, shell, capsys):
        shell.do_unsetg("")
        out = capsys.readouterr().out
        assert "Usage" in out

    def test_unsetg_when_never_set_is_idempotent(self, shell, capsys):
        shell.do_unsetg("interface")
        out = capsys.readouterr().out
        assert "no persisted value" in out
        assert shell.global_options["interface"] == "hci0"


# Tab completion -------------------------------------------------------------


class TestCompletion:
    def test_complete_setg_option_names(self, shell):
        out = shell.complete_setg("", "setg ", 5, 5)
        assert "interface" in out and "verbose" in out

    def test_complete_setg_prefix(self, shell):
        out = shell.complete_setg("ti", "setg ti", 5, 7)
        assert out == ["timeout"]

    def test_complete_setg_value_position_empty(self, shell):
        out = shell.complete_setg("", "setg interface ", 15, 15)
        assert out == []

    def test_complete_unsetg_option_names(self, shell):
        out = shell.complete_unsetg("", "unsetg ", 7, 7)
        assert set(out) >= {"interface", "verbose", "timeout", "pcap_file"}


# Integration with restart ---------------------------------------------------


def test_persisted_values_survive_reset(tmp_path: Path, monkeypatch):
    """Run a full setg, drop the singleton, re-open: values should stick."""
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()

    sh1 = BlueSploitInterpreter()
    sh1.do_setg("interface hci3")
    sh1.do_setg("timeout 7")
    sh1.do_setg("verbose true")

    reset_default_store()
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))

    sh2 = BlueSploitInterpreter()
    assert sh2.global_options["interface"] == "hci3"
    assert sh2.global_options["timeout"] == 7
    assert sh2.global_options["verbose"] is True

    reset_default_store()
