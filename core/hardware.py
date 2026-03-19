"""
BlueSploit Hardware Abstraction Layer
Detects, validates, and manages all Bluetooth testing hardware.

Supported hardware families
───────────────────────────
HCI adapters (standard):
  Any USB Bluetooth dongle or built-in adapter visible to BlueZ (hci0, hci1 …)
  e.g. CSR8510, BCM20702, BCM20703, Intel AX200/201/210, Realtek RTL8761

Passive sniffers:
  Ubertooth One      — kismet/ubertooth suite; BLE + Classic sniffing
  nRF Sniffer        — Nordic nRF52840 dongle running Sniffer firmware (BLE only)
  BTLEJack Sniffer   — BBC micro:bit / nRF52840 running BTLEJack firmware (BLE hijack)

Packet injection hardware:
  HackRF One         — SDR; gr-bluetooth or BTLE plugin for passive capture
  YARD Stick One     — Sub-GHz SDR; useful for ZigBee/BTLE experiments

Each HardwareDevice object exposes:
  .name          human-readable name
  .hw_type       HardwareType enum
  .interface     OS-level name (hci0, /dev/ttyUSB0, …)
  .capabilities  set of Capability enum values
  .available     True if confirmed present and usable
  .info          dict of extra metadata (address, firmware, …)
"""

import os
import re
import subprocess
import shutil
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Any, Set


# ──────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────

class HardwareType(Enum):
    HCI_ADAPTER   = "hci_adapter"     # Standard BlueZ HCI
    UBERTOOTH     = "ubertooth"       # Ubertooth One
    NRF_SNIFFER   = "nrf_sniffer"     # Nordic nRF52840 Sniffer
    BTLEJACK      = "btlejack"        # BTLEJack (micro:bit / nRF52840)
    HACKRF        = "hackrf"          # HackRF One / SDR
    YARD_STICK    = "yard_stick"      # YARD Stick One
    UNKNOWN       = "unknown"


class Capability(Enum):
    BLE_SCAN        = auto()   # BLE advertisement scanning
    BLE_CONNECT     = auto()   # BLE GATT connections
    BLE_SNIFF       = auto()   # Passive BLE traffic capture
    BLE_INJECT      = auto()   # BLE packet injection
    BLE_HIJACK      = auto()   # BLE connection hijacking
    CLASSIC_SCAN    = auto()   # BR/EDR device discovery
    CLASSIC_CONNECT = auto()   # BR/EDR L2CAP connections
    CLASSIC_SNIFF   = auto()   # BR/EDR passive capture
    CLASSIC_INJECT  = auto()   # BR/EDR packet injection
    RAW_CAPTURE     = auto()   # Raw pcap capture
    LONG_RANGE      = auto()   # Class 1 / extended range


# Capabilities by hardware type
_HW_CAPS: Dict[HardwareType, Set[Capability]] = {
    HardwareType.HCI_ADAPTER: {
        Capability.BLE_SCAN, Capability.BLE_CONNECT,
        Capability.CLASSIC_SCAN, Capability.CLASSIC_CONNECT,
    },
    HardwareType.UBERTOOTH: {
        Capability.BLE_SNIFF, Capability.BLE_INJECT,
        Capability.CLASSIC_SNIFF, Capability.RAW_CAPTURE,
    },
    HardwareType.NRF_SNIFFER: {
        Capability.BLE_SNIFF, Capability.RAW_CAPTURE,
    },
    HardwareType.BTLEJACK: {
        Capability.BLE_SNIFF, Capability.BLE_HIJACK,
        Capability.BLE_INJECT, Capability.RAW_CAPTURE,
    },
    HardwareType.HACKRF: {
        Capability.BLE_SNIFF, Capability.CLASSIC_SNIFF,
        Capability.RAW_CAPTURE,
    },
    HardwareType.YARD_STICK: {
        Capability.BLE_SNIFF, Capability.BLE_INJECT,
        Capability.RAW_CAPTURE,
    },
}


# ──────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────

@dataclass
class HardwareDevice:
    name:         str
    hw_type:      HardwareType
    interface:    str                       # hci0, /dev/ttyUSB0, hackrf#0 …
    capabilities: Set[Capability]           = field(default_factory=set)
    available:    bool                      = False
    info:         Dict[str, Any]            = field(default_factory=dict)

    def has(self, cap: Capability) -> bool:
        return cap in self.capabilities

    def supports_ble(self) -> bool:
        return any(c in self.capabilities for c in (
            Capability.BLE_SCAN, Capability.BLE_CONNECT,
            Capability.BLE_SNIFF, Capability.BLE_INJECT,
            Capability.BLE_HIJACK,
        ))

    def supports_classic(self) -> bool:
        return any(c in self.capabilities for c in (
            Capability.CLASSIC_SCAN, Capability.CLASSIC_CONNECT,
            Capability.CLASSIC_SNIFF, Capability.CLASSIC_INJECT,
        ))


# ──────────────────────────────────────────────────────────────
# Detection helpers
# ──────────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 5) -> Optional[str]:
    """Run a subprocess, return stdout or None on error."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout if result.returncode == 0 else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _lsusb() -> str:
    """Return raw lsusb output (empty string on failure)."""
    return _run(["lsusb"]) or ""


def _sys_bt_path() -> str:
    """Return contents of /sys/class/bluetooth (one iface per line)."""
    path = "/sys/class/bluetooth"
    if os.path.isdir(path):
        return "\n".join(os.listdir(path))
    return ""


# USB VID:PID signatures for known hardware
_USB_SIGNATURES: Dict[str, tuple] = {
    # (HardwareType, friendly_name)
    "1d50:6002": (HardwareType.UBERTOOTH,  "Ubertooth One"),
    "0451:16b6": (HardwareType.NRF_SNIFFER,"Nordic nRF52840 Sniffer"),
    "0d28:0204": (HardwareType.BTLEJACK,   "BTLEJack (BBC micro:bit)"),
    "1d50:6089": (HardwareType.HACKRF,     "HackRF One"),
    "1d50:605b": (HardwareType.YARD_STICK, "YARD Stick One"),
    # Common HCI dongles
    "0a12:0001": (HardwareType.HCI_ADAPTER,"CSR8510 Bluetooth adapter"),
    "0b05:17cb": (HardwareType.HCI_ADAPTER,"ASUS USB-BT400"),
    "0bda:8771": (HardwareType.HCI_ADAPTER,"Realtek RTL8761"),
    "8087:0029": (HardwareType.HCI_ADAPTER,"Intel Wireless Bluetooth"),
    "8087:0026": (HardwareType.HCI_ADAPTER,"Intel Wireless Bluetooth"),
    "0a5c:21e8": (HardwareType.HCI_ADAPTER,"BCM20702A0"),
    "0a5c:6412": (HardwareType.HCI_ADAPTER,"BCM20702B0 (HP)"),
}


# ──────────────────────────────────────────────────────────────
# Per-hardware detection functions
# ──────────────────────────────────────────────────────────────

def _detect_hci_adapters() -> List[HardwareDevice]:
    """Detect all HCI adapters visible to BlueZ."""
    devices: List[HardwareDevice] = []

    # Primary: parse hciconfig -a output
    hciconfig_out = _run(["hciconfig", "-a"]) or ""
    lsusb_out = _lsusb()

    # Also fall back to /sys/class/bluetooth
    sys_ifaces = _sys_bt_path().split()
    ifaces_from_sys = [i for i in sys_ifaces if i.startswith("hci")]

    # Collect all hci interfaces mentioned in hciconfig
    iface_blocks = re.split(r'\n(?=hci\d)', hciconfig_out)
    seen = set()

    for block in iface_blocks:
        m = re.match(r'(hci\d+)', block)
        if not m:
            continue
        iface = m.group(1)
        seen.add(iface)

        bd_addr  = re.search(r'BD Address:\s*([\w:]+)', block)
        name     = re.search(r'Name:\s*\'(.+?)\'', block)
        mfr      = re.search(r'Manufacturer:\s*(.+)', block)
        firmware = re.search(r'HCI\s+Ver:\s*(.+)', block)
        is_up    = "UP" in block

        # Extra caps for Class 1 adapters (long range)
        caps = set(_HW_CAPS[HardwareType.HCI_ADAPTER])
        if mfr and "class 1" in (mfr.group(1) or "").lower():
            caps.add(Capability.LONG_RANGE)

        devices.append(HardwareDevice(
            name=name.group(1) if name else f"Bluetooth adapter ({iface})",
            hw_type=HardwareType.HCI_ADAPTER,
            interface=iface,
            capabilities=caps,
            available=is_up,
            info={
                "bd_addr":  bd_addr.group(1) if bd_addr else "unknown",
                "manufacturer": mfr.group(1).strip() if mfr else "unknown",
                "firmware": firmware.group(1).strip() if firmware else "unknown",
                "up": is_up,
            }
        ))

    # Add any ifaces present in /sys but not in hciconfig output
    for iface in ifaces_from_sys:
        if iface not in seen:
            devices.append(HardwareDevice(
                name=f"Bluetooth adapter ({iface})",
                hw_type=HardwareType.HCI_ADAPTER,
                interface=iface,
                capabilities=set(_HW_CAPS[HardwareType.HCI_ADAPTER]),
                available=False,
                info={"note": "Found in /sys but not in hciconfig output"}
            ))

    return devices


def _detect_ubertooth() -> List[HardwareDevice]:
    """Detect Ubertooth One via USB VID:PID and ubertooth-util."""
    devices: List[HardwareDevice] = []
    lsusb_out = _lsusb()

    if "1d50:6002" not in lsusb_out:
        return devices

    # Check ubertooth-util is present and device responds
    util_out = _run(["ubertooth-util", "-v"], timeout=6)
    firmware = "unknown"
    if util_out:
        m = re.search(r'Firmware version:\s*(.+)', util_out)
        firmware = m.group(1).strip() if m else "present"

    devices.append(HardwareDevice(
        name="Ubertooth One",
        hw_type=HardwareType.UBERTOOTH,
        interface="ubertooth0",
        capabilities=set(_HW_CAPS[HardwareType.UBERTOOTH]),
        available=bool(util_out),
        info={
            "firmware": firmware,
            "tool": "ubertooth-util",
            "install_hint": "sudo apt install ubertooth" if not shutil.which("ubertooth-util") else "",
        }
    ))
    return devices


def _detect_nrf_sniffer() -> List[HardwareDevice]:
    """Detect Nordic nRF52840 Sniffer dongle."""
    devices: List[HardwareDevice] = []
    lsusb_out = _lsusb()

    # Nordic nRF52840 USB composite device (VID 0x1915 or 0x0451 depending on firmware)
    nrf_vids = ["0451:16b6", "1915:521f", "1915:0004"]
    found_vid = next((v for v in nrf_vids if v in lsusb_out), None)
    if not found_vid:
        return devices

    # Find the associated serial port
    serial_port = None
    for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
        if os.path.exists(candidate):
            serial_port = candidate
            break

    devices.append(HardwareDevice(
        name="Nordic nRF52840 Sniffer",
        hw_type=HardwareType.NRF_SNIFFER,
        interface=serial_port or "ttyACM?",
        capabilities=set(_HW_CAPS[HardwareType.NRF_SNIFFER]),
        available=serial_port is not None,
        info={
            "usb_id": found_vid,
            "serial_port": serial_port or "not found",
            "wireshark_plugin": "nrf_sniffer_for_bluetooth_le",
            "install_hint": "Flash nRF Sniffer firmware and install Wireshark plugin",
        }
    ))
    return devices


def _detect_btlejack() -> List[HardwareDevice]:
    """Detect BTLEJack hardware (micro:bit / nRF52840)."""
    devices: List[HardwareDevice] = []
    lsusb_out = _lsusb()

    microbit_vids = ["0d28:0204", "0d28:0205"]
    found_vid = next((v for v in microbit_vids if v in lsusb_out), None)
    if not found_vid:
        return devices

    btlejack_cmd = shutil.which("btlejack")
    serial_port = None
    for candidate in ["/dev/ttyACM0", "/dev/ttyACM1"]:
        if os.path.exists(candidate):
            serial_port = candidate
            break

    devices.append(HardwareDevice(
        name="BTLEJack (BBC micro:bit / nRF52840)",
        hw_type=HardwareType.BTLEJACK,
        interface=serial_port or "ttyACM?",
        capabilities=set(_HW_CAPS[HardwareType.BTLEJACK]),
        available=serial_port is not None,
        info={
            "usb_id": found_vid,
            "serial_port": serial_port or "not found",
            "tool": "btlejack" if btlejack_cmd else "NOT installed",
            "install_hint": "pip install btlejack" if not btlejack_cmd else "",
            "firmware_hint": "Flash BTLEJack firmware to micro:bit",
        }
    ))
    return devices


def _detect_hackrf() -> List[HardwareDevice]:
    """Detect HackRF One via hackrf_info."""
    devices: List[HardwareDevice] = []

    hackrf_out = _run(["hackrf_info"], timeout=6)
    if not hackrf_out or "No HackRF" in hackrf_out:
        return devices

    firmware = "unknown"
    serial = "unknown"
    m_fw  = re.search(r'Firmware Version:\s*(.+)', hackrf_out)
    m_ser = re.search(r'Serial number:\s*(.+)', hackrf_out)
    if m_fw:  firmware = m_fw.group(1).strip()
    if m_ser: serial   = m_ser.group(1).strip()

    devices.append(HardwareDevice(
        name="HackRF One",
        hw_type=HardwareType.HACKRF,
        interface="hackrf0",
        capabilities=set(_HW_CAPS[HardwareType.HACKRF]),
        available=True,
        info={
            "firmware": firmware,
            "serial": serial,
            "note": "Use gr-bluetooth or BTLE Scapy layer for BT sniffing",
            "install_hint": "sudo apt install hackrf gr-bluetooth",
        }
    ))
    return devices


def _detect_yard_stick() -> List[HardwareDevice]:
    """Detect YARD Stick One via lsusb VID:PID."""
    devices: List[HardwareDevice] = []
    lsusb_out = _lsusb()

    if "1d50:605b" not in lsusb_out:
        return devices

    rfcat_cmd = shutil.which("rfcat")
    serial_port = None
    for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
        if os.path.exists(candidate):
            serial_port = candidate
            break

    devices.append(HardwareDevice(
        name="YARD Stick One",
        hw_type=HardwareType.YARD_STICK,
        interface=serial_port or "ttyACM?",
        capabilities=set(_HW_CAPS[HardwareType.YARD_STICK]),
        available=serial_port is not None,
        info={
            "serial_port": serial_port or "not found",
            "tool": "rfcat" if rfcat_cmd else "NOT installed",
            "install_hint": "pip install rfcat" if not rfcat_cmd else "",
        }
    ))
    return devices


# ──────────────────────────────────────────────────────────────
# HardwareManager — main public API
# ──────────────────────────────────────────────────────────────

class HardwareManager:
    """
    Singleton-style manager that detects and tracks all BT hardware.

    Usage
    -----
    mgr = HardwareManager()
    mgr.detect()                          # populate device list
    mgr.list_devices()                    # -> List[HardwareDevice]
    mgr.best_for(Capability.BLE_SNIFF)    # -> HardwareDevice | None
    mgr.get_hci(index=0)                  # -> HardwareDevice | None
    mgr.summary()                         # -> formatted string
    """

    def __init__(self):
        self._devices: List[HardwareDevice] = []
        self._detected: bool = False

    def detect(self, verbose: bool = False) -> "HardwareManager":
        """Run detection for all hardware families."""
        self._devices.clear()

        detectors = [
            ("HCI adapters",     _detect_hci_adapters),
            ("Ubertooth One",    _detect_ubertooth),
            ("nRF Sniffer",      _detect_nrf_sniffer),
            ("BTLEJack",         _detect_btlejack),
            ("HackRF One",       _detect_hackrf),
            ("YARD Stick One",   _detect_yard_stick),
        ]

        for label, fn in detectors:
            try:
                found = fn()
                self._devices.extend(found)
            except Exception:
                pass

        self._detected = True
        return self

    # ── Queries ──────────────────────────────────────────────

    def list_devices(self) -> List[HardwareDevice]:
        return list(self._devices)

    def available_devices(self) -> List[HardwareDevice]:
        return [d for d in self._devices if d.available]

    def by_type(self, hw_type: HardwareType) -> List[HardwareDevice]:
        return [d for d in self._devices if d.hw_type == hw_type]

    def best_for(self, cap: Capability) -> Optional[HardwareDevice]:
        """Return the first available device that has the given capability."""
        for d in self._devices:
            if d.available and d.has(cap):
                return d
        return None

    def get_hci(self, index: int = 0) -> Optional[HardwareDevice]:
        """Return the Nth available HCI adapter."""
        hci = [d for d in self._devices
               if d.hw_type == HardwareType.HCI_ADAPTER and d.available]
        return hci[index] if index < len(hci) else None

    def hci_interfaces(self) -> List[str]:
        """Return names of all available HCI interfaces (hci0, hci1, …)."""
        return [d.interface for d in self._devices
                if d.hw_type == HardwareType.HCI_ADAPTER and d.available]

    def has_sniffer(self) -> bool:
        sniffer_types = {
            HardwareType.UBERTOOTH,
            HardwareType.NRF_SNIFFER,
            HardwareType.BTLEJACK,
            HardwareType.HACKRF,
        }
        return any(d.available and d.hw_type in sniffer_types
                   for d in self._devices)

    # ── Summary ──────────────────────────────────────────────

    def summary(self) -> str:
        if not self._detected:
            return "Hardware detection has not been run yet. Call detect() first."

        lines: List[str] = []
        lines.append(f"{'Hardware':<35} {'Interface':<15} {'Available':<10} Capabilities")
        lines.append("─" * 90)

        for d in self._devices:
            caps_short = ", ".join(
                c.name.lower().replace("_", "-") for c in sorted(d.capabilities, key=lambda x: x.name)
            )
            avail = "YES" if d.available else "no"
            lines.append(f"{d.name:<35} {d.interface:<15} {avail:<10} {caps_short}")

        total = len(self._devices)
        avail = len(self.available_devices())
        lines.append("─" * 90)
        lines.append(f"Total: {total} device(s) detected, {avail} available")
        return "\n".join(lines)


# ── Module-level singleton ────────────────────────────────────

_manager: Optional[HardwareManager] = None


def get_hardware_manager(auto_detect: bool = True) -> HardwareManager:
    """Return the global HardwareManager, auto-detecting on first call."""
    global _manager
    if _manager is None:
        _manager = HardwareManager()
        if auto_detect:
            _manager.detect()
    return _manager
