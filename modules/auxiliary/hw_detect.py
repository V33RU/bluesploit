"""
BlueSploit Module: Hardware Detector
Detects all Bluetooth testing hardware connected to this machine and
shows each device's capabilities, interface name, and install hints.

Usage (in bluesploit REPL):
    use auxiliary/hw_detect
    run
"""

import subprocess
import shutil
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import print_info, print_success, print_warning, Colors
from core.hardware import (
    get_hardware_manager, HardwareType, Capability,
    _detect_hci_adapters, _detect_ubertooth,
    _detect_nrf_sniffer, _detect_btlejack,
    _detect_hackrf, _detect_yard_stick,
)


# Capability → short description used in the table
_CAP_LABEL = {
    Capability.BLE_SCAN:        "BLE scan",
    Capability.BLE_CONNECT:     "BLE connect",
    Capability.BLE_SNIFF:       "BLE sniff",
    Capability.BLE_INJECT:      "BLE inject",
    Capability.BLE_HIJACK:      "BLE hijack",
    Capability.CLASSIC_SCAN:    "Classic scan",
    Capability.CLASSIC_CONNECT: "Classic connect",
    Capability.CLASSIC_SNIFF:   "Classic sniff",
    Capability.CLASSIC_INJECT:  "Classic inject",
    Capability.RAW_CAPTURE:     "Raw pcap",
    Capability.LONG_RANGE:      "Long range",
}

# Tools / Python packages required for each hardware type
_HW_DEPS = {
    HardwareType.HCI_ADAPTER: {
        "system": ["bluez", "hciconfig", "hcitool"],
        "python": ["bleak", "pybluez2"],
    },
    HardwareType.UBERTOOTH: {
        "system": ["ubertooth", "ubertooth-util", "wireshark"],
        "python": [],
    },
    HardwareType.NRF_SNIFFER: {
        "system": ["wireshark"],
        "python": ["pyserial"],
        "note": "Requires nRF Sniffer for Bluetooth LE Wireshark plugin",
    },
    HardwareType.BTLEJACK: {
        "system": [],
        "python": ["btlejack", "pyserial"],
        "note": "Flash BTLEJack firmware to BBC micro:bit or nRF52840 dongle",
    },
    HardwareType.HACKRF: {
        "system": ["hackrf", "gr-bluetooth"],
        "python": ["scapy"],
        "note": "Use gr-bluetooth or BTLE Scapy plugin for BT traffic capture",
    },
    HardwareType.YARD_STICK: {
        "system": [],
        "python": ["rfcat"],
        "note": "Primary use-case is sub-GHz; BLE support is limited",
    },
}


class Module(AuxiliaryModule):
    """
    Hardware Detector

    Scans the host system for connected Bluetooth testing hardware:
    - Standard HCI adapters (built-in or USB dongle)
    - Ubertooth One (passive BLE + Classic sniffer)
    - Nordic nRF52840 Sniffer dongle (passive BLE sniffer)
    - BTLEJack dongle (BLE connection hijacking)
    - HackRF One (SDR; raw BLE/Classic capture)
    - YARD Stick One (sub-GHz / BLE injection)

    Also checks which system tools and Python packages are installed
    for each detected device.
    """

    info = ModuleInfo(
        name="auxiliary/hw_detect",
        description="Detect connected Bluetooth testing hardware and check dependencies",
        author=["v33ru"],
        protocol=BTProtocol.DUAL,
        severity=Severity.INFO,
        references=[
            "https://ubertooth.readthedocs.io/",
            "https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Sniffer-for-Bluetooth-LE",
            "https://github.com/virtualabs/btlejack",
        ],
        cve=[]
    )

    def _setup_options(self) -> None:
        self.options = {
            "verbose": ModuleOption(
                name="verbose",
                required=False,
                description="Show detailed info including install hints",
                default=True
            ),
            "check_deps": ModuleOption(
                name="check_deps",
                required=False,
                description="Check system tools and Python packages for each device",
                default=True
            ),
        }

    # ──────────────────────────────────────────────────────
    # Dependency checker
    # ──────────────────────────────────────────────────────

    def _check_system_tool(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def _check_python_pkg(self, pkg: str) -> bool:
        try:
            __import__(pkg.replace("-", "_").replace("pybluez2", "bluetooth"))
            return True
        except ImportError:
            return False

    def _dep_status(self, hw_type: HardwareType) -> dict:
        deps = _HW_DEPS.get(hw_type, {})
        system_results = {}
        python_results = {}

        for tool in deps.get("system", []):
            system_results[tool] = self._check_system_tool(tool)

        for pkg in deps.get("python", []):
            python_results[pkg] = self._check_python_pkg(pkg)

        return {
            "system": system_results,
            "python": python_results,
            "note": deps.get("note", ""),
        }

    # ──────────────────────────────────────────────────────
    # Printer helpers
    # ──────────────────────────────────────────────────────

    def _print_device_block(self, device, dep_status: dict, verbose: bool) -> None:
        C = Colors

        avail_color = C.GREEN if device.available else C.RED
        avail_text  = "AVAILABLE" if device.available else "NOT AVAILABLE"

        print(f"\n  {C.BOLD}{C.WHITE}{'─'*70}{C.RESET}")
        print(f"  {C.BOLD}{device.name}{C.RESET}")
        print(f"  Type       : {device.hw_type.value}")
        print(f"  Interface  : {C.CYAN}{device.interface}{C.RESET}")
        print(f"  Status     : {avail_color}{avail_text}{C.RESET}")

        # Capabilities
        caps = sorted(device.capabilities, key=lambda c: c.name)
        cap_strs = [_CAP_LABEL.get(c, c.name) for c in caps]
        print(f"  Capabilities: {', '.join(cap_strs)}")

        # Extra info
        for key, val in device.info.items():
            if key == "install_hint":
                continue
            print(f"  {key.replace('_', ' ').title():<12}: {val}")

        if not verbose:
            return

        # Dependency status
        sys_deps = dep_status.get("system", {})
        py_deps  = dep_status.get("python", {})
        note     = dep_status.get("note", "")

        if sys_deps:
            print(f"\n  {C.BOLD}System tools:{C.RESET}")
            for tool, ok in sys_deps.items():
                icon  = f"{C.GREEN}✓{C.RESET}" if ok else f"{C.RED}✗{C.RESET}"
                hint  = "" if ok else f"  {C.DARK_GREY}→ sudo apt install {tool}{C.RESET}"
                print(f"    {icon} {tool}{hint}")

        if py_deps:
            print(f"\n  {C.BOLD}Python packages:{C.RESET}")
            for pkg, ok in py_deps.items():
                icon = f"{C.GREEN}✓{C.RESET}" if ok else f"{C.RED}✗{C.RESET}"
                hint = "" if ok else f"  {C.DARK_GREY}→ pip install {pkg}{C.RESET}"
                print(f"    {icon} {pkg}{hint}")

        if note:
            print(f"\n  {C.YELLOW}Note: {note}{C.RESET}")

        install_hint = device.info.get("install_hint", "")
        if install_hint:
            print(f"  {C.YELLOW}Hint: {install_hint}{C.RESET}")

    def _print_capability_matrix(self, devices) -> None:
        C = Colors
        all_caps = [
            Capability.BLE_SCAN,
            Capability.BLE_CONNECT,
            Capability.BLE_SNIFF,
            Capability.BLE_INJECT,
            Capability.BLE_HIJACK,
            Capability.CLASSIC_SCAN,
            Capability.CLASSIC_CONNECT,
            Capability.CLASSIC_SNIFF,
            Capability.RAW_CAPTURE,
        ]
        col_labels = [_CAP_LABEL[c] for c in all_caps]
        col_w = 13

        print(f"\n  {C.BOLD}{C.WHITE}CAPABILITY MATRIX{C.RESET}")
        print(f"\n  {'Hardware':<32}", end="")
        for lbl in col_labels:
            print(f"{lbl[:col_w-1]:<{col_w}}", end="")
        print()

        print("  " + "─" * (32 + col_w * len(col_labels)))

        for d in devices:
            avail_color = C.GREEN if d.available else C.DIM if hasattr(C, 'DIM') else C.DARK_GREY
            name_str = d.name[:31]
            print(f"  {avail_color}{name_str:<32}{C.RESET}", end="")
            for cap in all_caps:
                if d.has(cap):
                    sym = f"{C.GREEN}  ✓{C.RESET}"
                else:
                    sym = f"{C.DARK_GREY}  -{C.RESET}"
                print(f"{sym:<{col_w}}", end="")
            print()

    def _print_quick_start(self, devices) -> None:
        C = Colors
        available = [d for d in devices if d.available]
        if not available:
            return

        print(f"\n  {C.BOLD}{C.WHITE}QUICK START — recommended hardware per task{C.RESET}")
        print(f"  {'─'*60}")

        tasks = [
            ("BLE device scan",       Capability.BLE_SCAN),
            ("BLE GATT attacks",      Capability.BLE_CONNECT),
            ("BLE passive capture",   Capability.BLE_SNIFF),
            ("BLE connection hijack", Capability.BLE_HIJACK),
            ("Classic attacks",       Capability.CLASSIC_CONNECT),
            ("Classic passive sniff", Capability.CLASSIC_SNIFF),
            ("Raw pcap recording",    Capability.RAW_CAPTURE),
        ]

        for task, cap in tasks:
            best = next((d for d in available if d.has(cap)), None)
            if best:
                print(f"  {C.CYAN}{task:<28}{C.RESET} → {C.GREEN}{best.name}{C.RESET} ({best.interface})")
            else:
                print(f"  {C.CYAN}{task:<28}{C.RESET} → {C.RED}No available hardware{C.RESET}")

    # ──────────────────────────────────────────────────────
    # run()
    # ──────────────────────────────────────────────────────

    def run(self) -> bool:
        verbose    = bool(self.get_option("verbose"))
        check_deps = bool(self.get_option("check_deps"))

        C = Colors
        print(f"\n  {C.CYAN}╔{'═'*68}╗{C.RESET}")
        print(f"  {C.CYAN}║{C.RESET} {C.BOLD}BlueSploit Hardware Detector{C.RESET}                                    {C.CYAN}║{C.RESET}")
        print(f"  {C.CYAN}╚{'═'*68}╝{C.RESET}\n")

        print_info("Scanning for connected Bluetooth testing hardware...")

        # Force fresh detection
        from core import hardware as hw_mod
        hw_mod._manager = None
        mgr = hw_mod.get_hardware_manager(auto_detect=True)
        devices = mgr.list_devices()

        if not devices:
            print_warning("No Bluetooth hardware detected.")
            print_info("Make sure BlueZ is installed: sudo apt install bluez")
            return False

        # Per-device blocks
        for device in devices:
            dep_status = self._dep_status(device.hw_type) if check_deps else {}
            self._print_device_block(device, dep_status, verbose)

        # Capability matrix
        self._print_capability_matrix(devices)

        # Quick-start guide
        self._print_quick_start(devices)

        # Global summary
        available = mgr.available_devices()
        hci_ifaces = mgr.hci_interfaces()
        has_sniffer = mgr.has_sniffer()

        print(f"\n  {C.CYAN}{'═'*70}{C.RESET}")
        print(f"  {C.BOLD}{C.WHITE}SUMMARY{C.RESET}")
        print(f"  {'─'*70}")
        print(f"  Devices detected   : {len(devices)}")
        print(f"  Available          : {C.GREEN}{len(available)}{C.RESET}")
        print(f"  HCI interfaces     : {', '.join(hci_ifaces) if hci_ifaces else C.RED+'none'+C.RESET}")
        print(f"  Passive sniffer    : {C.GREEN+'YES'+C.RESET if has_sniffer else C.RED+'NO'+C.RESET}")
        print()

        if hci_ifaces:
            default_iface = hci_ifaces[0]
            print(f"  {C.YELLOW}Tip: run  setg interface {default_iface}  to use the first HCI adapter globally{C.RESET}")

        if not has_sniffer:
            print(f"\n  {C.YELLOW}Tip: For passive sniffing add one of:{C.RESET}")
            print(f"    • Ubertooth One    → sudo apt install ubertooth")
            print(f"    • nRF52840 Sniffer → flash nRF Sniffer firmware + Wireshark plugin")
            print(f"    • BTLEJack dongle  → pip install btlejack  (micro:bit firmware)")

        print(f"\n  {C.CYAN}{'═'*70}{C.RESET}\n")

        self.add_result({
            "devices": len(devices),
            "available": len(available),
            "hci_interfaces": hci_ifaces,
            "has_sniffer": has_sniffer,
        })

        return len(available) > 0
