"""
BlueSploit Module: Bluetooth Discovery Scanner
Discovers nearby BLE and Classic BR/EDR devices with detailed information
"""

import asyncio
import re
import subprocess
import threading
from typing import Dict, Any, List
from core.base import (
    ScannerModule, ModuleInfo, ModuleOption,
    BTProtocol, Severity, Target
)
from core.utils.printer import (
    print_success, print_error, print_info,
    print_warning, print_device, Colors, progress_bar
)

try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


class Module(ScannerModule):
    """
    Bluetooth Discovery Scanner

    Scans for nearby BLE and Classic BR/EDR devices and extracts:
    - Device address (BD_ADDR)
    - Device type: BLE / BR/EDR (Classic) / DUAL
    - Device name
    - RSSI signal strength
    - Manufacturer / Vendor
    - Service UUIDs (BLE)
    """

    info = ModuleInfo(
        name="scanners/ble/discovery",
        description="Discover nearby BLE and Classic BR/EDR devices",
        author=["BlueSploit"],
        protocol=BTProtocol.BOTH,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification/"
        ]
    )

    def _setup_options(self) -> None:
        self.options = {
            "timeout": ModuleOption(
                name="timeout",
                required=False,
                description="Scan duration in seconds",
                default=10
            ),
            "mode": ModuleOption(
                name="mode",
                required=False,
                description="Protocol to scan: all | ble | classic",
                default="all"
            ),
            "interface": ModuleOption(
                name="interface",
                required=False,
                description="HCI adapter for Classic scan (e.g. hci0)",
                default="hci0"
            ),
            "filter_name": ModuleOption(
                name="filter_name",
                required=False,
                description="Filter devices by name (substring match)",
                default=None
            ),
            "filter_rssi": ModuleOption(
                name="filter_rssi",
                required=False,
                description="Minimum RSSI threshold for BLE (e.g. -70)",
                default=None
            ),
            "show_duplicates": ModuleOption(
                name="show_duplicates",
                required=False,
                description="Show duplicate BLE advertisements",
                default=False
            ),
            "live_output": ModuleOption(
                name="live_output",
                required=False,
                description="Show devices as they are found",
                default=True
            ),
            "output_file": ModuleOption(
                name="output_file",
                required=False,
                description="Save results to file (JSON format)",
                default=None
            )
        }

    # ── Manufacturer lookup ───────────────────────────────────────────────────

    def _get_manufacturer_name(self, company_id: int) -> str:
        manufacturers = {
            0x004C: "Apple",        0x0006: "Microsoft",   0x000F: "Broadcom",
            0x0075: "Samsung",      0x00E0: "Google",       0x0059: "Nordic Semi",
            0x000D: "Texas Instr",  0x0131: "Huawei",       0x0157: "Xiaomi",
            0x038F: "Espressif",    0x0087: "Garmin",       0x00D2: "Fitbit",
            0x0310: "Wyze",         0x0171: "Amazon",       0x02FF: "Meta",
            0x0002: "Intel",        0x001D: "Qualcomm",     0x0078: "Nike",
            0x0822: "Govee",        0x0969: "Tuya",
        }
        return manufacturers.get(company_id, f"0x{company_id:04X}")

    # ── RSSI helpers ─────────────────────────────────────────────────────────

    def _get_rssi_bar(self, rssi: int) -> str:
        if rssi is None:
            return f"{Colors.DARK_GREY}─────{Colors.RESET}"
        strength = min(5, max(0, (rssi + 100) // 14))
        bar = "█" * strength + "░" * (5 - strength)
        if strength >= 4:
            return f"{Colors.GREEN}{bar}{Colors.RESET}"
        elif strength >= 2:
            return f"{Colors.YELLOW}{bar}{Colors.RESET}"
        return f"{Colors.RED}{bar}{Colors.RESET}"

    # ── Classic BR/EDR scan ───────────────────────────────────────────────────

    def _scan_classic(self, iface: str, timeout: int) -> List[Dict[str, Any]]:
        """Run hcitool scan to find discoverable BR/EDR devices."""
        found: Dict[str, Dict[str, Any]] = {}
        inq_units = min(48, max(4, timeout * 100 // 128))

        try:
            r = subprocess.run(
                ["hcitool", "-i", iface, "scan", "--flush",
                 "--length", str(inq_units)],
                capture_output=True, text=True, timeout=timeout + 8,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                m = re.match(r'([0-9A-Fa-f:]{17})\s*(.*)', line)
                if m:
                    addr = m.group(1).upper()
                    name = m.group(2).strip() or None
                    found[addr] = {
                        "address":          addr,
                        "name":             name,
                        "rssi":             None,
                        "type":             "BR/EDR",
                        "services":         [],
                        "manufacturer":     None,
                        "manufacturer_data": {},
                        "tx_power":         None,
                    }
        except FileNotFoundError:
            print_warning("hcitool not found — Classic scan skipped (apt install bluez)")
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return list(found.values())

    # ── BLE scan ─────────────────────────────────────────────────────────────

    def _parse_advertisement(self, device: 'BLEDevice',
                             adv_data: 'AdvertisementData') -> Dict[str, Any]:
        result = {
            "address":          device.address,
            "name":             adv_data.local_name or device.name or None,
            "rssi":             adv_data.rssi if hasattr(adv_data, 'rssi') else None,
            "type":             "BLE",
            "services":         [],
            "manufacturer":     None,
            "manufacturer_data": {},
            "tx_power":         adv_data.tx_power,
        }
        if adv_data.service_uuids:
            result["services"] = list(adv_data.service_uuids)
        if adv_data.manufacturer_data:
            for company_id, data in adv_data.manufacturer_data.items():
                result["manufacturer"] = self._get_manufacturer_name(company_id)
                result["manufacturer_data"][f"0x{company_id:04X}"] = data.hex()
        return result

    async def _scan_ble_async(self) -> Dict[str, Dict[str, Any]]:
        timeout        = self.get_option("timeout")
        filter_name    = self.get_option("filter_name")
        filter_rssi    = self.get_option("filter_rssi")
        show_duplicates = self.get_option("show_duplicates")
        live_output    = self.get_option("live_output")

        devices: Dict[str, Dict[str, Any]] = {}

        def detection_callback(device: 'BLEDevice', adv_data: 'AdvertisementData'):
            if device.address in devices and not show_duplicates:
                current_rssi = adv_data.rssi if hasattr(adv_data, 'rssi') else -100
                if current_rssi and current_rssi > devices[device.address].get("rssi", -100):
                    devices[device.address]["rssi"] = current_rssi
                return

            parsed = self._parse_advertisement(device, adv_data)

            if filter_name and filter_name.lower() not in (parsed["name"] or "").lower():
                return
            if filter_rssi:
                rssi = parsed.get("rssi")
                if rssi is None or rssi < int(filter_rssi):
                    return

            devices[device.address] = parsed

            if live_output:
                extra = f"[BLE]"
                if parsed["manufacturer"]:
                    extra += f" {parsed['manufacturer']}"
                if parsed["services"]:
                    extra += f" | {len(parsed['services'])} svc"
                print_device(parsed["address"], parsed["name"], parsed.get("rssi"), extra)

        print_info(f"Scanning for BLE devices ({timeout}s)...")

        try:
            scanner = BleakScanner(detection_callback=detection_callback)
            await scanner.start()
            for i in range(timeout):
                await asyncio.sleep(1)
                progress_bar(i + 1, timeout, prefix="BLE scan",
                             suffix=f"Found: {len(devices)}")
            await scanner.stop()
        except Exception as e:
            print_error(f"BLE scan error: {e}")

        return devices

    # ── Merge ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _merge(ble: Dict[str, Dict], classic: List[Dict]) -> Dict[str, Dict]:
        merged = dict(ble)
        for dev in classic:
            addr = dev["address"]
            if addr in merged:
                merged[addr]["type"] = "DUAL"
            else:
                merged[addr] = dev
        return merged

    # ── Table output ──────────────────────────────────────────────────────────

    def _type_colored(self, dev_type: str) -> str:
        C = Colors
        if dev_type == "BLE":
            return f"{C.GREEN}{'BLE':<8}{C.RESET}"
        elif dev_type == "BR/EDR":
            return f"{C.BLUE}{'BR/EDR':<8}{C.RESET}"
        elif dev_type == "DUAL":
            return f"{C.CYAN}{'DUAL':<8}{C.RESET}"
        return f"{'?':<8}"

    def _print_table(self, devices: Dict[str, Dict[str, Any]]) -> None:
        if not devices:
            print_warning("No devices found")
            return

        C = Colors

        sorted_devices = sorted(
            devices.values(),
            key=lambda x: (
                {"BR/EDR": 0, "DUAL": 1, "BLE": 2}.get(x.get("type", "BLE"), 3),
                -(x.get("rssi") or -999)
            )
        )

        # Column widths:  #(4) TYPE(8) ADDRESS(20) NAME(22) RSSI(8) SIGNAL(9) VENDOR(14) SVC(4)
        # Content total = 89 → separator = 93
        SEP = 93

        print(f"\n  {C.CYAN}{'═'*SEP}{C.RESET}")
        print(f"  {C.CYAN}SCAN RESULTS{C.RESET} — {len(devices)} device(s) found")
        print(f"  {C.CYAN}{'═'*SEP}{C.RESET}\n")

        print(
            f"  {C.BOLD}"
            f"{'#':<4}{'TYPE':<8}{'ADDRESS':<20}{'NAME':<22}"
            f"{'RSSI':<8}{'SIGNAL':<9}{'VENDOR':<14}{'SVC':<4}"
            f"{C.RESET}"
        )
        print(f"  {'─'*4}{'─'*8}{'─'*20}{'─'*22}{'─'*8}{'─'*9}{'─'*14}{'─'*4}")

        for idx, dev in enumerate(sorted_devices, 1):
            address  = dev["address"]
            dev_type = dev.get("type", "BLE")

            name = dev.get("name") or f"{C.DARK_GREY}Unknown{C.RESET}"
            if dev.get("name") and len(dev["name"]) > 20:
                name = dev["name"][:17] + "..."

            rssi      = dev.get("rssi")
            rssi_str  = f"{rssi} dBm" if rssi is not None else "N/A"
            signal    = self._get_rssi_bar(rssi)

            vendor = dev.get("manufacturer") or "—"
            if len(vendor) > 12:
                vendor = vendor[:9] + "..."

            svc_count = len(dev.get("services", []))
            svc_str   = str(svc_count) if svc_count > 0 else "—"

            print(
                f"  {idx:<4}"
                f"{self._type_colored(dev_type)}"
                f"{address:<20}"
                f"{name:<22}"
                f"{rssi_str:<8}"
                f"{signal}  "
                f"{vendor:<14}"
                f"{svc_str:<4}"
            )

        print(f"\n  {C.CYAN}{'═'*SEP}{C.RESET}")

        ble_n    = sum(1 for d in devices.values() if d.get("type") == "BLE")
        bredr_n  = sum(1 for d in devices.values() if d.get("type") == "BR/EDR")
        dual_n   = sum(1 for d in devices.values() if d.get("type") == "DUAL")
        named_n  = sum(1 for d in devices.values() if d.get("name"))
        svc_n    = sum(1 for d in devices.values() if d.get("services"))

        print(f"\n  {C.BOLD}SUMMARY{C.RESET}")
        print(f"  ├─ {C.GREEN}BLE{C.RESET}          : {ble_n}")
        print(f"  ├─ {C.BLUE}BR/EDR (Classic){C.RESET} : {bredr_n}")
        print(f"  ├─ {C.CYAN}Dual-mode{C.RESET}    : {dual_n}")
        print(f"  ├─ Named         : {named_n}")
        print(f"  └─ With Services : {svc_n}")
        print()

    # ── Save ─────────────────────────────────────────────────────────────────

    def _save_results(self, devices: Dict[str, Dict[str, Any]], filename: str) -> None:
        import json
        output = {
            "scan_info": {
                "module":       self.info.name,
                "timeout":      self.get_option("timeout"),
                "device_count": len(devices),
            },
            "devices": list(devices.values())
        }
        try:
            with open(filename, 'w') as f:
                json.dump(output, f, indent=2)
            print_success(f"Results saved to: {filename}")
        except Exception as e:
            print_error(f"Failed to save results: {e}")

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self) -> bool:
        mode      = (self.get_option("mode") or "all").lower()
        timeout   = int(self.get_option("timeout"))
        iface     = self.get_option("interface") or "hci0"

        if mode not in ("all", "ble", "classic"):
            print_error("mode must be: all, ble, or classic")
            return False

        print_info(f"Mode: {mode.upper()}  |  Interface: {iface}  |  Duration: {timeout}s")
        print_info("Press Ctrl+C to stop early\n")

        ble_devices:     Dict[str, Dict] = {}
        classic_devices: List[Dict]      = []
        _classic_result: List[List[Dict]] = [[]]

        try:
            # ── Classic in background thread ──
            if mode in ("all", "classic"):
                def _classic_worker():
                    print_info(f"{Colors.BLUE}[BR/EDR]{Colors.RESET} Inquiry started on {iface}...")
                    _classic_result[0] = self._scan_classic(iface, timeout)

                classic_thread = threading.Thread(target=_classic_worker, daemon=True)
                classic_thread.start()

            # ── BLE in main thread (asyncio) ──
            if mode in ("all", "ble"):
                if not BLEAK_AVAILABLE:
                    print_warning("BLE scan skipped — install bleak: pip install bleak")
                else:
                    try:
                        ble_devices = asyncio.run(self._scan_ble_async())
                    except RuntimeError as e:
                        if "running event loop" not in str(e):
                            raise
                        loop = asyncio.get_event_loop()
                        ble_devices = loop.run_until_complete(self._scan_ble_async())
                    print_success(f"BLE done — {len(ble_devices)} device(s)")

            # ── Wait for Classic ──
            if mode in ("all", "classic"):
                classic_thread.join(timeout=timeout + 15)
                classic_devices = _classic_result[0]
                print_success(f"BR/EDR done — {len(classic_devices)} device(s)")

        except KeyboardInterrupt:
            print_warning("\nScan interrupted — showing partial results")

        all_devices = self._merge(ble_devices, classic_devices)

        for addr, dev in all_devices.items():
            self.add_device(Target(
                address=addr,
                name=dev.get("name"),
                rssi=dev.get("rssi"),
                manufacturer=dev.get("manufacturer"),
                services=dev.get("services", [])
            ))

        self._print_table(all_devices)

        output_file = self.get_option("output_file")
        if output_file:
            self._save_results(all_devices, output_file)

        return len(all_devices) > 0
