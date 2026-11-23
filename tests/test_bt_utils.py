"""Tests for core/utils/bt.py shared helpers.

Pure-Python: no HCI socket, no root, no hardware. These cover BD_ADDR
parsing, LE address-type auto-detection, and bitmap decoding.
"""

import pytest

from core.utils import bt


class TestBDAddr:
    def test_validate_accepts_upper_and_lower(self):
        assert bt.validate_bd_addr("AA:BB:CC:DD:EE:FF") is True
        assert bt.validate_bd_addr("aa:bb:cc:dd:ee:ff") is True
        assert bt.validate_bd_addr("Aa:Bb:Cc:Dd:Ee:Ff") is True

    def test_validate_rejects_garbage(self):
        for bad in [
            "",
            "AA:BB:CC:DD:EE",          # too short
            "AA:BB:CC:DD:EE:FF:00",    # too long
            "AA-BB-CC-DD-EE-FF",       # wrong sep
            "GG:BB:CC:DD:EE:FF",       # non-hex
            "AABBCCDDEEFF",            # no separators
            None,                      # wrong type
            12345,                     # wrong type
        ]:
            assert bt.validate_bd_addr(bad) is False, f"should reject {bad!r}"

    def test_parse_returns_msb_first_tuple(self):
        assert bt.parse_bd_addr("AA:BB:CC:DD:EE:FF") == (0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF)

    def test_parse_raises_on_invalid(self):
        with pytest.raises(ValueError):
            bt.parse_bd_addr("not-an-address")

    def test_bytes_are_little_endian(self):
        """HCI wire format is least-significant-octet first."""
        assert bt.bd_addr_bytes("AA:BB:CC:DD:EE:FF") == bytes.fromhex("ffeeddccbbaa")


class TestAutoAddrType:
    @pytest.mark.parametrize("addr,expected", [
        ("FF:00:00:00:00:01", "random"),   # top 2 bits = 11, Static Random
        ("D0:00:00:00:00:01", "random"),   # top 2 bits = 11
        ("50:00:00:00:00:01", "random"),   # top 2 bits = 01, Resolvable Private
        ("00:11:22:33:44:55", "public"),   # top 2 bits = 00
        ("28:11:22:33:44:55", "public"),   # top 2 bits = 00 (0x28 = 00101000)
        ("8C:00:11:22:33:44", "public"),   # top 2 bits = 10 -> public per helper
    ])
    def test_classification(self, addr, expected):
        assert bt.auto_addr_type(addr) == expected

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            bt.auto_addr_type("nope")


class TestBitmap:
    def test_decode_returns_set_bits_in_order(self):
        # Byte 0: 0b00010101 -> bits 0, 2, 4 set
        data = bytes([0b00010101, 0])
        names = ["a", "b", "c", "d", "e", "f", "g", "h",
                 "i", "j", "k", "l", "m", "n", "o", "p"]
        assert bt.decode_bitmap(data, names) == [(0, "a"), (2, "c"), (4, "e")]

    def test_decode_skips_reserved_labels(self):
        data = bytes([0b11111111])
        names = ["a", "Reserved", "c", "Reserved", "e", "Reserved", "g", "Reserved"]
        assert bt.decode_bitmap(data, names) == [(0, "a"), (2, "c"), (4, "e"), (6, "g")]

    def test_decode_handles_short_names_list(self):
        """Bits past the end of `names` are ignored, not an error."""
        data = bytes([0xFF, 0xFF])
        names = ["a", "b", "c"]  # only 3 labels for 16 bits
        assert bt.decode_bitmap(data, names) == [(0, "a"), (1, "b"), (2, "c")]

    def test_bitmap_to_dict_round_trip(self):
        data = bytes([0b00000101])
        names = ["a", "b", "c", "d", "e", "f", "g", "h"]
        assert bt.bitmap_to_dict(data, names) == {"a": True, "c": True}


class TestRequireRoot:
    def test_non_root_raises(self, monkeypatch):
        monkeypatch.setattr("os.geteuid", lambda: 1000)
        with pytest.raises(PermissionError):
            bt.require_root()

    def test_root_is_silent(self, monkeypatch):
        monkeypatch.setattr("os.geteuid", lambda: 0)
        bt.require_root()  # must not raise


class TestOpenHCIErrors:
    def test_invalid_iface_name_raises_hci_error(self):
        with pytest.raises(bt.HCIError):
            bt.open_hci("not-an-iface")

    def test_unbindable_iface_raises_hci_error(self, monkeypatch):
        """Even with a valid name, a missing kernel iface should surface as HCIError."""
        class FakeSocket:
            def __init__(self, *a, **kw): pass
            def bind(self, _addr):
                raise OSError("No such device")
            def close(self): pass

        monkeypatch.setattr(bt.socket, "socket", lambda *a, **kw: FakeSocket())
        with pytest.raises(bt.HCIError) as exc:
            bt.open_hci("hci99")
        assert "hci99" in str(exc.value)
