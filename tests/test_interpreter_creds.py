"""Tests for the `creds` command and credential auto-fill on `set target`.

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
from core.store import get_store, reset_default_store


class _CredAwareModule(AuxiliaryModule):
    """A stub module that declares credential-shaped options."""

    info = ModuleInfo(
        name="cred-stub", description="stub for credential autofill tests",
        author=["pytest"], protocol=BTProtocol.BLE, severity=Severity.INFO,
    )

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="target", required=False, description="BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="link_key", required=False, description="LinkKey hex",
        ))
        self.add_option(ModuleOption(
            name="ltk", required=False, description="LTK hex",
        ))
        self.add_option(ModuleOption(
            name="irk", required=False, description="IRK hex",
        ))
        self.add_option(ModuleOption(
            name="pin", required=False, description="PIN",
        ))

    def run(self) -> bool:
        return True


class _PlainModule(AuxiliaryModule):
    """A stub module with no credential-shaped options."""

    info = ModuleInfo(
        name="plain-stub", description="stub without credential autofill",
        author=["pytest"], protocol=BTProtocol.BLE, severity=Severity.INFO,
    )

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="target", required=False, description="BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="timeout", required=False, description="seconds", default=10,
        ))

    def run(self) -> bool:
        return True


@pytest.fixture
def shell(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("BLUESPLOIT_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    reset_default_store()
    sh = BlueSploitInterpreter()
    yield sh
    reset_default_store()


# do_creds -------------------------------------------------------------------


class TestDoCreds:
    def test_empty_store_prints_hint(self, shell, capsys):
        shell.do_creds("")
        out = capsys.readouterr().out
        assert "No credentials recorded" in out

    def test_lists_credentials(self, shell, capsys):
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01", name="alpha")
        s.add_credential(h, kind="LinkKey", value="DEADBEEFCAFEBABE")
        s.add_credential(h, kind="LTK", value="01234567")
        s.add_credential(None, kind="PIN", value="1234")

        shell.do_creds("")
        out = capsys.readouterr().out
        assert "LinkKey" in out
        assert "LTK" in out
        assert "PIN" in out
        assert "DEADBEEFCAFEBABE" in out
        assert "AA:BB:CC:DD:EE:01" in out
        assert "(orphan)" in out
        assert "Total: 3 credential(s)" in out

    def test_filter_by_kind(self, shell, capsys):
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LinkKey", value="aaaa")
        s.add_credential(h, kind="LTK", value="bbbb")
        shell.do_creds("ltk")
        out = capsys.readouterr().out
        assert "LTK" in out
        assert "LinkKey" not in out

    def test_filter_by_host_address(self, shell, capsys):
        s = get_store()
        h1 = s.add_host("AA:BB:CC:DD:EE:01", name="alpha")
        h2 = s.add_host("CC:DD:EE:FF:00:11", name="bravo")
        s.add_credential(h1, kind="LinkKey", value="aaaa")
        s.add_credential(h2, kind="LinkKey", value="bbbb")
        shell.do_creds("AA:BB")
        out = capsys.readouterr().out
        assert "aaaa" in out
        assert "bbbb" not in out

    def test_filter_by_host_name(self, shell, capsys):
        s = get_store()
        h1 = s.add_host("AA:BB:CC:DD:EE:01", name="alpha")
        h2 = s.add_host("CC:DD:EE:FF:00:11", name="bravo")
        s.add_credential(h1, kind="LinkKey", value="aaaa")
        s.add_credential(h2, kind="LinkKey", value="bbbb")
        shell.do_creds("bravo")
        out = capsys.readouterr().out
        assert "bbbb" in out
        assert "aaaa" not in out

    def test_filter_no_match(self, shell, capsys):
        s = get_store()
        s.add_credential(None, kind="LinkKey", value="aaaa")
        shell.do_creds("nothing-matches")
        out = capsys.readouterr().out
        assert "No credentials match" in out

    def test_long_value_truncated(self, shell, capsys):
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LinkKey", value="a" * 64)
        shell.do_creds("")
        out = capsys.readouterr().out
        assert ".." in out


# Credential auto-fill on set target -----------------------------------------


class TestAutofillOnSetTarget:
    def _load(self, shell, module_cls=_CredAwareModule):
        shell.current_module = module_cls()
        shell._module_path = "test/cred-stub"

    def test_autofill_link_key(self, shell, capsys):
        self._load(shell)
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LinkKey", value="DEADBEEFCAFEBABE")
        shell.do_set(f"target {h.id}")
        assert shell.current_module.get_option("link_key") == "DEADBEEFCAFEBABE"
        out = capsys.readouterr().out
        assert "auto-filled link_key" in out

    def test_autofill_ltk_and_irk(self, shell):
        self._load(shell)
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LTK", value="aaaa1111")
        s.add_credential(h, kind="IRK", value="bbbb2222")
        shell.do_set(f"target {h.id}")
        assert shell.current_module.get_option("ltk") == "aaaa1111"
        assert shell.current_module.get_option("irk") == "bbbb2222"

    def test_no_autofill_when_no_credential(self, shell, capsys):
        self._load(shell)
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")  # no credentials
        shell.do_set(f"target {h.id}")
        assert shell.current_module.get_option("link_key") is None
        assert shell.current_module.get_option("ltk") is None
        out = capsys.readouterr().out
        assert "auto-filled" not in out

    def test_autofill_picks_most_recent(self, shell, capsys):
        self._load(shell)
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LinkKey", value="OLDKEY")
        s.add_credential(h, kind="LinkKey", value="NEWKEY")
        shell.do_set(f"target {h.id}")
        # `latest_credential` orders by created_at DESC then id DESC, so
        # the second insert wins.
        assert shell.current_module.get_option("link_key") == "NEWKEY"

    def test_autofill_skipped_when_address_not_in_store(self, shell, capsys):
        self._load(shell)
        # Operator typed a fresh address never seen before. No host row,
        # so no autofill, no error.
        shell.do_set("target FF:FF:FF:FF:FF:FF")
        assert shell.current_module.get_option("target") == "FF:FF:FF:FF:FF:FF"
        assert shell.current_module.get_option("link_key") is None

    def test_autofill_skipped_when_module_lacks_cred_options(self, shell):
        self._load(shell, _PlainModule)
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LinkKey", value="aaaa")
        shell.do_set(f"target {h.id}")
        # PlainModule has only `target` and `timeout`; nothing else
        # should sneak in.
        assert "link_key" not in shell.current_module.options

    def test_manual_set_after_autofill_overrides(self, shell):
        self._load(shell)
        s = get_store()
        h = s.add_host("AA:BB:CC:DD:EE:01")
        s.add_credential(h, kind="LinkKey", value="AUTOFILLED")
        shell.do_set(f"target {h.id}")
        assert shell.current_module.get_option("link_key") == "AUTOFILLED"
        shell.do_set("link_key MANUAL_OVERRIDE")
        assert shell.current_module.get_option("link_key") == "MANUAL_OVERRIDE"
