"""
Minimal IOKit ctypes bindings for the macOS IOBluetooth* DoS modules.

Provides just enough to:
  - locate IOBluetoothHCIController via IOServiceGetMatchingService
  - open a user client (type 0 = IOBluetoothHCIUserClient,
                       type 1 = IOBluetoothHCIPacketLogUserClient)
  - send malformed structInputs via IOConnectCallMethod

Returns None / raises RuntimeError on non-macOS hosts so callers can
fail cleanly without crashing the framework.
"""

import ctypes
import ctypes.util
import platform
from typing import Optional, Tuple


def is_macos() -> bool:
    return platform.system() == "Darwin"


def _load() -> Tuple[ctypes.CDLL, ctypes.CDLL]:
    iokit = ctypes.CDLL("/System/Library/Frameworks/IOKit.framework/IOKit")
    cf    = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    return iokit, cf


def open_iobluetooth(client_type: int = 0) -> Optional[int]:
    """
    Return an io_connect_t for IOBluetoothHCIController, or None on failure.
    Caller must call close_connection() when finished.
    """
    if not is_macos():
        raise RuntimeError("macOS-only module")
    iokit, cf = _load()

    # CFDict / CString helpers
    iokit.IOServiceMatching.argtypes  = [ctypes.c_char_p]
    iokit.IOServiceMatching.restype   = ctypes.c_void_p
    iokit.IOServiceGetMatchingService.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
    iokit.IOServiceGetMatchingService.restype  = ctypes.c_uint32
    iokit.IOServiceOpen.argtypes  = [ctypes.c_uint32, ctypes.c_uint32,
                                     ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
    iokit.IOServiceOpen.restype   = ctypes.c_int

    matching = iokit.IOServiceMatching(b"IOBluetoothHCIController")
    if not matching:
        return None
    # kIOMasterPortDefault = 0
    service = iokit.IOServiceGetMatchingService(0, matching)
    if service == 0:
        return None

    # mach_task_self() — task port for current process
    libsystem = ctypes.CDLL(ctypes.util.find_library("System"))
    libsystem.mach_task_self_.argtypes = []
    libsystem.mach_task_self_.restype  = ctypes.c_uint32
    task = libsystem.mach_task_self_()

    conn = ctypes.c_uint32(0)
    kr = iokit.IOServiceOpen(service, task, client_type, ctypes.byref(conn))
    iokit.IOObjectRelease.argtypes = [ctypes.c_uint32]
    iokit.IOObjectRelease.restype  = ctypes.c_int
    iokit.IOObjectRelease(service)
    if kr != 0 or conn.value == 0:
        return None
    return conn.value


def call_method(conn: int, selector: int, struct_in: bytes) -> int:
    """
    Wrapper around IOConnectCallMethod with no scalars / no output.
    Returns the kern_return_t.
    """
    if not is_macos():
        raise RuntimeError("macOS-only module")
    iokit, _cf = _load()
    iokit.IOConnectCallMethod.argtypes = [
        ctypes.c_uint32,      # connection
        ctypes.c_uint32,      # selector
        ctypes.c_void_p,      # input scalar
        ctypes.c_uint32,      # input scalar count
        ctypes.c_void_p,      # input struct
        ctypes.c_size_t,      # input struct cnt
        ctypes.c_void_p,      # output scalar
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    iokit.IOConnectCallMethod.restype = ctypes.c_int

    buf = ctypes.create_string_buffer(struct_in, len(struct_in))
    out_scalar_cnt = ctypes.c_uint32(0)
    out_struct_cnt = ctypes.c_size_t(0)
    return iokit.IOConnectCallMethod(
        conn, selector,
        None, 0,
        buf, len(struct_in),
        None, ctypes.byref(out_scalar_cnt),
        None, ctypes.byref(out_struct_cnt),
    )


def close_connection(conn: int) -> None:
    if not is_macos():
        return
    iokit, _ = _load()
    iokit.IOServiceClose.argtypes = [ctypes.c_uint32]
    iokit.IOServiceClose.restype  = ctypes.c_int
    iokit.IOServiceClose(conn)
