"""Tests for the smarter tab completion: `set interface`, `set addr_type`,
bool options, and the shared dispatcher used by `setg`."""

from pathlib import Path

import pytest

from core.base import (
    AuxiliaryModule,
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    Severity,
)
from core.interpreter import BlueSploitInterpreter, _list_hci_interfaces
from core.store import reset_default_store


class _StubModule(AuxiliaryModule):
    """Stub module with the option shapes the completer cares about."""

    info = ModuleInfo(
        name="stub", description="completion stub",
        author=["pytest"], protocol=BTProtocol.BLE, severity=Severity.INFO,
    )

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="target", required=False, description="BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="interface", required=False, description="HCI",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="addr_type", required=False, description="LE address type",
            default="auto",
        ))
        self.add_option(ModuleOption(
            name="verbose", required=False, description="loud", default=False,
        ))
        self.add_option(ModuleOption(
            name="quiet", required=False, description="silent", default=True,
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
    sh.current_module = _StubModule()
    sh._module_path = "test/stub"
    yield sh
    reset_default_store()


# _list_hci_interfaces -------------------------------------------------------


class TestListHCIInterfaces:
    def test_returns_sorted_hci_dirs(self, monkeypatch):
        monkeypatch.setattr(
            "core.interpreter.os.listdir",
            lambda _: ["hci1", "hci0", "hci10", "something-else"],
        )
        assert _list_hci_interfaces() == ["hci0", "hci1", "hci10"]

    def test_filters_non_hci_entries(self, monkeypatch):
        monkeypatch.setattr(
            "core.interpreter.os.listdir",
            lambda _: ["hciX", "hci0", "not-bluetooth", "hci2"],
        )
        # 'hciX' fails the all-digits suffix check; 'not-bluetooth' is ignored.
        assert _list_hci_interfaces() == ["hci0", "hci2"]

    def test_fallback_when_sysfs_missing(self, monkeypatch):
        def boom(_):
            raise FileNotFoundError("no sysfs")
        monkeypatch.setattr("core.interpreter.os.listdir", boom)
        assert _list_hci_interfaces() == ["hci0"]


# complete_set value position ------------------------------------------------


class TestCompleteSetValues:
    def test_interface_lists_detected_adapters(self, shell, monkeypatch):
        monkeypatch.setattr(
            "core.interpreter.os.listdir",
            lambda _: ["hci0", "hci1", "hci2"],
        )
        out = shell.complete_set("", "set interface ", 14, 14)
        assert out == ["hci0", "hci1", "hci2"]

    def test_interface_prefix_filter(self, shell, monkeypatch):
        monkeypatch.setattr(
            "core.interpreter.os.listdir",
            lambda _: ["hci0", "hci1", "hci2"],
        )
        out = shell.complete_set("hci1", "set interface hci1", 14, 18)
        assert out == ["hci1"]

    def test_addr_type_completes(self, shell):
        out = shell.complete_set("", "set addr_type ", 14, 14)
        assert set(out) == {"auto", "public", "random"}

    def test_addr_type_prefix(self, shell):
        out = shell.complete_set("p", "set addr_type p", 14, 15)
        assert out == ["public"]

    def test_bool_option_completes_true_false(self, shell):
        # `verbose` defaults to False; `quiet` defaults to True. Both should
        # complete to the true/false pair regardless of the default's value.
        out_v = shell.complete_set("", "set verbose ", 12, 12)
        assert set(out_v) == {"true", "false"}
        out_q = shell.complete_set("", "set quiet ", 10, 10)
        assert set(out_q) == {"true", "false"}

    def test_bool_prefix_filter(self, shell):
        out = shell.complete_set("t", "set verbose t", 12, 13)
        assert out == ["true"]

    def test_int_option_returns_empty(self, shell):
        # No completion offered for free-form int options.
        out = shell.complete_set("", "set timeout ", 12, 12)
        assert out == []

    def test_unknown_option_returns_empty(self, shell):
        out = shell.complete_set("", "set nosuch ", 11, 11)
        assert out == []


# complete_setg value position -----------------------------------------------


class TestCompleteSetgValues:
    def test_interface_completes(self, shell, monkeypatch):
        monkeypatch.setattr(
            "core.interpreter.os.listdir",
            lambda _: ["hci0", "hci1"],
        )
        out = shell.complete_setg("", "setg interface ", 15, 15)
        assert out == ["hci0", "hci1"]

    def test_verbose_global_completes_true_false(self, shell):
        out = shell.complete_setg("", "setg verbose ", 13, 13)
        assert set(out) == {"true", "false"}

    def test_timeout_global_returns_empty(self, shell):
        out = shell.complete_setg("", "setg timeout ", 13, 13)
        assert out == []

    def test_pcap_file_global_returns_empty(self, shell):
        # pcap_file default is None; no completer wired in. Returns [].
        out = shell.complete_setg("", "setg pcap_file ", 15, 15)
        assert out == []

    def test_option_name_completion_unchanged(self, shell):
        out = shell.complete_setg("", "setg ", 5, 5)
        assert "interface" in out and "verbose" in out


# Existing target completion still works -------------------------------------


class TestTargetStillWorks:
    """Regression: the rework around the shared dispatcher must not break
    the existing `set target <TAB>` -> stored host addresses behavior."""

    def test_stored_hosts_complete(self, shell):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01")
        get_store().add_host("FF:11:22:33:44:55")
        out = shell.complete_set("", "set target ", 11, 11)
        assert set(out) == {"AA:BB:CC:DD:EE:01", "FF:11:22:33:44:55"}

    def test_stored_host_prefix(self, shell):
        from core.store import get_store
        get_store().add_host("AA:BB:CC:DD:EE:01")
        get_store().add_host("FF:11:22:33:44:55")
        out = shell.complete_set("AA", "set target AA", 11, 13)
        assert out == ["AA:BB:CC:DD:EE:01"]
