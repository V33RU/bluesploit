"""Tests for core/capture.py: PCAP backend selection and lifecycle.

Subprocess calls are stubbed; no real btmon/tcpdump invocation.
"""

import os

import pytest

from core import capture as capture_mod
from core.capture import PCAPCapture


def test_available_backends_returns_list(monkeypatch):
    monkeypatch.setattr(capture_mod.shutil, "which", lambda b: "/usr/bin/" + b)
    assert set(PCAPCapture.available_backends()) == {"btmon", "tcpdump"}

    monkeypatch.setattr(capture_mod.shutil, "which", lambda b: None)
    assert PCAPCapture.available_backends() == []


def test_start_picks_first_available_backend(monkeypatch, tmp_path):
    """If only tcpdump is on PATH, that's what we use."""
    monkeypatch.setattr(capture_mod.shutil, "which",
                        lambda b: "/usr/bin/tcpdump" if b == "tcpdump" else None)

    class FakeProc:
        pid = 4242
        def poll(self):
            return None
        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(capture_mod.subprocess, "Popen", lambda *a, **kw: FakeProc())
    monkeypatch.setattr(capture_mod.time, "sleep", lambda *_: None)

    cap = PCAPCapture(str(tmp_path / "out.pcap"))
    assert cap.start() is True
    assert cap.backend == "tcpdump"
    assert cap.is_running is True


def test_start_returns_false_when_no_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(capture_mod.shutil, "which", lambda b: None)
    cap = PCAPCapture(str(tmp_path / "out.pcap"))
    assert cap.start() is False


def test_stop_idempotent_when_never_started(tmp_path):
    cap = PCAPCapture(str(tmp_path / "out.pcap"))
    # stop() must not raise even if start() was never called
    assert cap.stop() is False


def test_file_size_zero_when_missing(tmp_path):
    cap = PCAPCapture(str(tmp_path / "does_not_exist.pcap"))
    assert cap.file_size == 0


def test_file_size_reflects_real_file(tmp_path):
    path = tmp_path / "out.pcap"
    path.write_bytes(b"x" * 128)
    cap = PCAPCapture(str(path))
    assert cap.file_size == 128


def test_start_backend_immediate_exit_falls_through(monkeypatch, tmp_path):
    """A backend that exits immediately should be skipped, not retained."""
    monkeypatch.setattr(capture_mod.shutil, "which", lambda b: "/usr/bin/" + b)

    class ExitedProc:
        pid = 1
        def poll(self):
            return 1  # already exited

    monkeypatch.setattr(capture_mod.subprocess, "Popen", lambda *a, **kw: ExitedProc())
    monkeypatch.setattr(capture_mod.time, "sleep", lambda *_: None)

    cap = PCAPCapture(str(tmp_path / "out.pcap"))
    # Both backends fake-exit, so start should ultimately fail
    assert cap.start() is False
    assert cap.backend is None
