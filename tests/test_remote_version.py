"""Tests for `core/utils/bt.read_remote_version` plus the LMP version
and Bluetooth SIG Company Identifier decoders.

The reader is unit-tested with a stand-in socket so the HCI plumbing
gets exercised without real hardware.
"""

from __future__ import annotations

import struct

import pytest

from core.utils import bt

# Decoders ------------------------------------------------------------------


class TestDecodeLMPVersion:
    @pytest.mark.parametrize("byte,expected", [
        (0x06, "4.0"),
        (0x09, "5.0"),
        (0x0A, "5.1"),
        (0x0C, "5.3"),
        (0x0D, "5.4"),
    ])
    def test_known_version(self, byte, expected):
        assert bt.decode_lmp_version(byte) == expected

    def test_unknown_version_marks_explicitly(self):
        assert bt.decode_lmp_version(0xEF) == "Unknown (0xEF)"


class TestDecodeCompanyID:
    @pytest.mark.parametrize("cid,expected", [
        (0x004C, "Apple"),
        (0x0006, "Microsoft"),
        (0x000F, "Broadcom"),
        (0x0059, "Nordic Semiconductor"),
        (0x015D, "Espressif"),
    ])
    def test_known_company(self, cid, expected):
        assert bt.decode_company_id(cid) == expected

    def test_unknown_company_marks_explicitly(self):
        assert bt.decode_company_id(0xFFFE) == "Unknown (0xFFFE)"


# read_remote_version -------------------------------------------------------


class _FakeHCI:
    """A minimal stand-in for the HCI socket that records sends and
    queues a single canned event for the next `wait_event` call.

    Wired by patching `core.utils.bt.wait_event` and `core.utils.bt.hci_cmd`
    so the helper's logic runs end to end without touching a real socket.
    """

    def __init__(self):
        self.sent: list[bytes] = []

    # The real socket exposes setblocking/send/recv etc.; the helper
    # only goes through bt.hci_cmd / bt.wait_event, which we monkeypatch.


@pytest.fixture
def hci_with_version(monkeypatch):
    """Patch `wait_event` to return a synthesized
    Read_Remote_Version_Information_Complete payload."""
    sock = _FakeHCI()

    def fake_hci_cmd(_sock, ogf, ocf, params):
        # Capture the command for later assertions; do nothing else.
        sock.sent.append((ogf, ocf, bytes(params)))

    def fake_wait_event(_sock, event_code, timeout=10.0, max_pkt=255):
        if event_code == bt.EVT_REMOTE_VERSION_COMPL:
            # payload: status(1) + handle(2) + version(1) + manufacturer(2) + subversion(2)
            return struct.pack(
                "<BHBHH",
                0x00,    # status = success
                0x0040,  # connection handle
                0x09,    # LMP version 5.0
                0x004C,  # Apple
                0x1234,  # subversion
            )
        return None

    monkeypatch.setattr(bt, "hci_cmd", fake_hci_cmd)
    monkeypatch.setattr(bt, "wait_event", fake_wait_event)
    return sock


class TestReadRemoteVersion:
    def test_parses_canned_response(self, hci_with_version):
        out = bt.read_remote_version(hci_with_version, 0x0040)
        assert out == (0x09, 0x004C, 0x1234)

    def test_emits_correct_hci_command(self, hci_with_version):
        bt.read_remote_version(hci_with_version, 0x00AB)
        assert len(hci_with_version.sent) == 1
        ogf, ocf, params = hci_with_version.sent[0]
        assert ogf == 0x01            # Link Control
        assert ocf == 0x001D          # Read_Remote_Version_Information
        # handle 0x00AB encoded little-endian
        assert params == struct.pack("<H", 0x00AB)

    def test_returns_none_on_status_failure(self, monkeypatch):
        def fake_hci_cmd(*a, **kw): pass
        def fake_wait_event(_sock, ec, timeout=10.0, max_pkt=255):
            # status = 0x01 (UNKNOWN_HCI_COMMAND)
            return struct.pack("<BHBHH", 0x01, 0x0040, 0x09, 0x004C, 0x1234)
        monkeypatch.setattr(bt, "hci_cmd", fake_hci_cmd)
        monkeypatch.setattr(bt, "wait_event", fake_wait_event)
        assert bt.read_remote_version(object(), 0x0040) is None

    def test_returns_none_on_timeout(self, monkeypatch):
        def fake_hci_cmd(*a, **kw): pass
        def fake_wait_event(*a, **kw): return None
        monkeypatch.setattr(bt, "hci_cmd", fake_hci_cmd)
        monkeypatch.setattr(bt, "wait_event", fake_wait_event)
        assert bt.read_remote_version(object(), 0x0040) is None

    def test_returns_none_on_truncated_payload(self, monkeypatch):
        def fake_hci_cmd(*a, **kw): pass
        def fake_wait_event(*a, **kw): return b"\x00\x40\x00\x09"  # too short
        monkeypatch.setattr(bt, "hci_cmd", fake_hci_cmd)
        monkeypatch.setattr(bt, "wait_event", fake_wait_event)
        assert bt.read_remote_version(object(), 0x0040) is None
