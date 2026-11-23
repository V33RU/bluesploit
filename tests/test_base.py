"""Tests for core/base.py: option handling, validation, BD_ADDR check."""

import pytest

from core.base import (
    BaseModule,
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    ModuleType,
    Severity,
)


class _StubModule(BaseModule):
    """Minimal concrete BaseModule for testing option machinery."""

    module_type = ModuleType.AUXILIARY
    info = ModuleInfo(
        name="Stub",
        description="A stub used only by the test suite",
        author=["pytest"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target", required=True, description="BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="count", required=False, description="loops", default=3,
        ))
        self.add_option(ModuleOption(
            name="enabled", required=False, description="flag", default=True,
        ))
        self.add_option(ModuleOption(
            name="ratio", required=False, description="float", default=1.5,
        ))

    def run(self) -> bool:
        return True


@pytest.fixture
def mod():
    return _StubModule()


def test_global_pcap_option_is_injected(mod):
    assert "pcap_file" in mod.options
    assert mod.options["pcap_file"].required is False


def test_set_and_get_round_trip(mod):
    mod.set_option("target", "AA:BB:CC:DD:EE:FF")
    assert mod.get_option("target") == "AA:BB:CC:DD:EE:FF"


def test_set_is_case_insensitive(mod):
    mod.set_option("TARGET", "AA:BB:CC:DD:EE:FF")
    assert mod.get_option("target") == "AA:BB:CC:DD:EE:FF"
    assert mod.get_option("TaRgEt") == "AA:BB:CC:DD:EE:FF"


def test_int_coercion_from_string(mod):
    mod.set_option("count", "42")
    assert mod.get_option("count") == 42
    assert isinstance(mod.get_option("count"), int)


def test_float_coercion_from_string(mod):
    mod.set_option("ratio", "3.14")
    assert mod.get_option("ratio") == pytest.approx(3.14)


def test_bool_coercion_from_string(mod):
    mod.set_option("enabled", "false")
    assert mod.get_option("enabled") is False
    mod.set_option("enabled", "yes")
    assert mod.get_option("enabled") is True


def test_set_returns_false_for_unknown_option(mod):
    assert mod.set_option("does_not_exist", "x") is False


def test_validate_options_requires_target(mod, capsys):
    assert mod.validate_options() is False  # target unset
    mod.set_option("target", "AA:BB:CC:DD:EE:FF")
    assert mod.validate_options() is True


def test_validate_bd_addr_helper(mod):
    assert mod.validate_bd_addr("AA:BB:CC:DD:EE:FF") is True
    assert mod.validate_bd_addr("not an address") is False


def test_results_collection(mod):
    assert mod.results == []
    mod.add_result({"k": 1})
    mod.add_result({"k": 2})
    assert mod.results == [{"k": 1}, {"k": 2}]
    mod.clear_results()
    assert mod.results == []


def test_target_property_reads_option(mod):
    mod.set_option("target", "AA:BB:CC:DD:EE:FF")
    assert mod.target == "AA:BB:CC:DD:EE:FF"
