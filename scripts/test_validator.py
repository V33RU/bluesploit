"""Tests for scripts/validate_modules.py."""

import importlib.util
from pathlib import Path

import pytest

VALIDATOR_PATH = Path(__file__).resolve().parent / "validate_modules.py"


@pytest.fixture(scope="module")
def validator():
    spec = importlib.util.spec_from_file_location("validate_modules", VALIDATOR_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write(tmp_path: Path, source: str) -> Path:
    p = tmp_path / "mod.py"
    p.write_text(source)
    return p


def test_minimal_valid_module(validator, tmp_path):
    src = '''
from core.base import ModuleInfo, ReconModule, BTProtocol, Severity

class Module(ReconModule):
    info = ModuleInfo(
        name="Test",
        description="A description",
        author=["me"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[],
    )

    def _setup_options(self):
        pass

    def run(self):
        return True
'''
    assert validator.validate_file(_write(tmp_path, src)) == []


def test_missing_required_kwargs(validator, tmp_path):
    src = '''
from core.base import ModuleInfo, ReconModule

class Module(ReconModule):
    info = ModuleInfo(
        name="Test",
        description="A description",
    )

    def _setup_options(self):
        pass

    def run(self):
        return True
'''
    errs = validator.validate_file(_write(tmp_path, src))
    assert any("missing required kwargs" in e for e in errs)


def test_wrong_class_name(validator, tmp_path):
    src = '''
from core.base import ModuleInfo, ReconModule, BTProtocol, Severity

class NotModule(ReconModule):
    info = ModuleInfo(
        name="Test",
        description="A description",
        author=["me"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
    )

    def _setup_options(self):
        pass

    def run(self):
        return True
'''
    errs = validator.validate_file(_write(tmp_path, src))
    assert any("expected 'Module'" in e for e in errs)


def test_missing_methods(validator, tmp_path):
    src = '''
from core.base import ModuleInfo, ReconModule, BTProtocol, Severity

class Module(ReconModule):
    info = ModuleInfo(
        name="Test",
        description="A description",
        author=["me"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
    )
'''
    errs = validator.validate_file(_write(tmp_path, src))
    assert any("_setup_options" in e for e in errs)
    assert any("run(self)" in e for e in errs)


def test_no_module_info_at_all(validator, tmp_path):
    src = '''
class Module:
    pass
'''
    errs = validator.validate_file(_write(tmp_path, src))
    assert errs and "no Module class" in errs[0]


def test_all_real_modules_pass(validator):
    """Regression gate: every module in the repo must pass the validator."""
    failures = []
    for path in validator.walk_modules():
        errs = validator.validate_file(path)
        if errs:
            failures.append((path, errs))
    assert not failures, f"validator regression: {failures}"
