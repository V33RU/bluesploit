"""Tests for core/ble_meta.py UUID resolution and properties decoding."""

import pytest

from core.ble_meta import (
    CHARACTERISTIC_NAMES,
    DESCRIPTOR_NAMES,
    SERVICE_NAMES,
    name_for_characteristic,
    name_for_descriptor,
    name_for_service,
    permissions_from_bitmap,
    properties_to_permissions,
    short_uuid,
)

# UUID handling -------------------------------------------------------------


class TestShortUUID:
    def test_standard_service_with_dashes(self):
        # Generic Access, 0x1800.
        assert short_uuid("00001800-0000-1000-8000-00805f9b34fb") == 0x1800

    def test_standard_service_without_dashes(self):
        assert short_uuid("0000180000001000800000805f9b34fb") == 0x1800

    def test_characteristic_uuid(self):
        # Device Name characteristic, 0x2A00.
        assert short_uuid("00002a00-0000-1000-8000-00805f9b34fb") == 0x2A00

    def test_descriptor_uuid(self):
        # CCCD, 0x2902.
        assert short_uuid("00002902-0000-1000-8000-00805f9b34fb") == 0x2902

    def test_vendor_uuid_returns_none(self):
        # Nordic UART base UUID (from mirage example output).
        assert short_uuid("6e400001-b5a3-f393-e0a9-77656c6f6f70") is None

    def test_case_insensitive(self):
        # Some BLE stacks emit upper-case UUID strings.
        assert short_uuid("0000180F-0000-1000-8000-00805F9B34FB") == 0x180F

    def test_malformed_returns_none(self):
        assert short_uuid("not a uuid") is None
        assert short_uuid("") is None


# Name resolution -----------------------------------------------------------


class TestNameForService:
    def test_generic_access(self):
        assert name_for_service("00001800-0000-1000-8000-00805f9b34fb") == "Generic Access"

    def test_battery_service(self):
        assert name_for_service("0000180f-0000-1000-8000-00805f9b34fb") == "Battery Service"

    def test_running_speed_and_cadence(self):
        assert name_for_service("00001814-0000-1000-8000-00805f9b34fb") == "Running Speed and Cadence"

    def test_vendor_service_empty(self):
        # From the mirage example, the Nordic UART UUID has no SIG name.
        assert name_for_service("6e400001-b5a3-f393-e0a9-77656c6f6f70") == ""

    def test_unknown_short_uuid_empty(self):
        # Not currently mapped. Empty string, never invented.
        assert name_for_service("0000ffff-0000-1000-8000-00805f9b34fb") == ""


class TestNameForCharacteristic:
    def test_device_name(self):
        assert name_for_characteristic("00002a00-0000-1000-8000-00805f9b34fb") == "Device Name"

    def test_battery_level(self):
        assert name_for_characteristic("00002a19-0000-1000-8000-00805f9b34fb") == "Battery Level"

    def test_heart_rate_measurement(self):
        assert (
            name_for_characteristic("00002a37-0000-1000-8000-00805f9b34fb")
            == "Heart Rate Measurement"
        )

    def test_model_number(self):
        assert (
            name_for_characteristic("00002a24-0000-1000-8000-00805f9b34fb")
            == "Model Number String"
        )

    def test_vendor_characteristic_empty(self):
        assert name_for_characteristic("6e400002-b5a3-f393-e0a9-77656c6f6f70") == ""


class TestNameForDescriptor:
    def test_cccd(self):
        assert (
            name_for_descriptor("00002902-0000-1000-8000-00805f9b34fb")
            == "Client Characteristic Configuration"
        )

    def test_user_description(self):
        assert (
            name_for_descriptor("00002901-0000-1000-8000-00805f9b34fb")
            == "Characteristic User Description"
        )


# Properties decoding -------------------------------------------------------


class TestPropertiesToPermissions:
    def test_read_only(self):
        assert properties_to_permissions(["read"]) == ["Read"]

    def test_notify_read_combination(self):
        # From mirage example: many chars have Notify,Read.
        out = properties_to_permissions(["read", "notify"])
        # Order preserved by input.
        assert out == ["Read", "Notify"]

    def test_write_without_response_normalized(self):
        out = properties_to_permissions(["write-without-response"])
        assert out == ["Write Without Response"]

    def test_indicate_write_read(self):
        out = properties_to_permissions(["indicate", "write", "read"])
        assert out == ["Indicate", "Write", "Read"]

    def test_duplicates_collapsed(self):
        out = properties_to_permissions(["read", "READ", "Read"])
        assert out == ["Read"]

    def test_passthrough_unknown(self):
        # An unknown property string is not silently dropped.
        out = properties_to_permissions(["some-future-prop"])
        assert out == ["some-future-prop"]


class TestPermissionsFromBitmap:
    def test_read_only_bit(self):
        # 0x02 = Read.
        assert permissions_from_bitmap(0x02) == ["Read"]

    def test_notify_read(self):
        out = permissions_from_bitmap(0x12)  # 0x10 Notify + 0x02 Read
        # Order: Read (0x02) comes before Notify (0x10) in the bitmap walk.
        assert "Read" in out and "Notify" in out

    def test_all_bits(self):
        out = permissions_from_bitmap(0xFF)
        assert "Read" in out
        assert "Write" in out
        assert "Notify" in out
        assert "Indicate" in out
        assert "Broadcast" in out
        assert "Extended Properties" in out


# Coverage sanity -----------------------------------------------------------


class TestTableCoverage:
    def test_mirage_example_services_all_named(self):
        """The services shown in the user's mirage example (the standard
        ones) must all resolve to a name. Vendor UUIDs are excluded."""
        examples = [0x1800, 0x1801, 0x180F, 0x180A, 0x180D, 0x1814]
        for short in examples:
            assert short in SERVICE_NAMES, f"missing SIG service 0x{short:04x}"

    def test_mirage_example_characteristics_all_named(self):
        examples = [0x2A00, 0x2A01, 0x2A19, 0x2A24, 0x2A25, 0x2A27, 0x2A28, 0x2A37, 0x2A53, 0x2A54]
        for short in examples:
            assert short in CHARACTERISTIC_NAMES, f"missing SIG char 0x{short:04x}"

    def test_cccd_in_descriptor_table(self):
        assert 0x2902 in DESCRIPTOR_NAMES
