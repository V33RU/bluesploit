"""
BlueSploit Module: LMP Features Reader

Reads the Link Manager Protocol (LMP) feature page(s) of a remote BR/EDR
device via HCI Read_Remote_Features and Read_Remote_Extended_Features
commands. Decodes each bit against the Bluetooth Core Specification
(Vol 2 Part C §3.3), useful for fingerprinting controller capabilities,
BT version, supported encryption modes, Secure Simple Pairing, eSCO,
LE-side support, and more.

Modes:
  basic     Read only the standard 8-byte LMP feature page (default)
  extended  Read all extended feature pages (page 1, 2, ...)
  full      basic + extended + decoded summary
"""

import struct
from typing import List, Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.utils.bt import (
    EVT_CONN_COMPLETE,
    EVT_DISCONN_COMPLETE,
    EVT_REMOTE_EXT_FEAT_COMPL,
    EVT_REMOTE_FEATURES_COMPL,
    HCIError,
    bd_addr_bytes,
    bitmap_to_dict,
    decode_bitmap,
    decode_company_id,
    decode_lmp_version,
    disconnect,
    hci_cmd,
    open_hci,
    read_remote_version,
    require_root,
    wait_event,
)
from core.utils.printer import (
    Colors,
    print_error,
    print_info,
    print_success,
    print_warning,
)

# Per BT Core Spec Vol 2 Part C §3.3, Page 0 LMP features
LMP_FEATURES_PAGE0 = [
    # Byte 0
    "3-slot packets", "5-slot packets", "Encryption", "Slot offset",
    "Timing accuracy", "Role switch", "Hold mode", "Sniff mode",
    # Byte 1
    "Park state (deprecated)", "Power control requests", "CQDDR",
    "SCO link", "HV2 packets", "HV3 packets", "u-law log", "A-law log",
    # Byte 2
    "CVSD", "Paging param negotiation", "Power control",
    "Transparent SCO data", "Flow control lag (LSB)",
    "Flow control lag", "Flow control lag (MSB)", "Broadcast Encryption",
    # Byte 3
    "Reserved", "EDR ACL 2 Mbps mode", "EDR ACL 3 Mbps mode",
    "Enhanced inquiry scan", "Interlaced inquiry scan",
    "Interlaced page scan", "RSSI w/ inquiry results", "Extended SCO (EV3)",
    # Byte 4
    "EV4 packets", "EV5 packets", "Reserved", "AFH capable slave",
    "AFH classification slave", "BR/EDR Not Supported",
    "LE Supported (Controller)", "3-slot EDR ACL packets",
    # Byte 5
    "5-slot EDR ACL packets", "Sniff subrating", "Pause encryption",
    "AFH capable master", "AFH classification master", "EDR eSCO 2 Mbps mode",
    "EDR eSCO 3 Mbps mode", "3-slot EDR eSCO packets",
    # Byte 6
    "Extended Inquiry Response", "Simultaneous LE & BR/EDR (Controller)",
    "Reserved", "Secure Simple Pairing (Controller)", "Encapsulated PDU",
    "Erroneous Data Reporting", "Non-flushable Packet Boundary Flag",
    "Reserved",
    # Byte 7
    "Link Supervision Timeout Changed Event", "Inquiry TX Power Level",
    "Enhanced Power Control", "Reserved", "Reserved", "Reserved", "Reserved",
    "Extended features",
]

# Page 1, host features
LMP_FEATURES_PAGE1 = [
    "Secure Simple Pairing (Host)",
    "LE Supported (Host)",
    "Simultaneous LE & BR/EDR (Host)",
    "Secure Connections (Host)",
] + ["Reserved"] * 60

# Page 2, controller extended
LMP_FEATURES_PAGE2 = [
    "Connectionless Slave Broadcast Master Operation",
    "Connectionless Slave Broadcast Slave Operation",
    "Synchronization Train", "Synchronization Scan",
    "Inquiry Response Notification Event", "Generalized interlaced scan",
    "Coarse Clock Adjustment", "Reserved",
    "Secure Connections (Controller)", "Ping",
    "Reserved", "Train nudging", "Slot Availability Mask",
] + ["Reserved"] * 51


class Module(ReconModule):

    info = ModuleInfo(
        name="LMP Features Reader",
        description="Read LMP feature pages of a remote BR/EDR device via HCI",
        author=["BlueSploit"],
        protocol=BTProtocol.CLASSIC,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BR/EDR BD_ADDR (XX:XX:XX:XX:XX:XX)",
        ))
        self.add_option(ModuleOption(
            name="mode",
            required=False,
            description="Mode: basic, extended, full",
            default="full",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="max_pages",
            required=False,
            description="Max extended feature pages to query (1-3)",
            default=2,
        ))

    def run(self) -> bool:
        try:
            require_root()
        except PermissionError as e:
            print_error(str(e))
            return False

        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        # Hint: top 2 bits = 11 strongly suggests a BLE Static Random address
        # (LMP only exists on BR/EDR, these connections always fail).
        msb = int(target.split(":")[0], 16)
        ble_random_static = (msb >> 6) == 0b11

        mode      = (self.get_option("mode") or "full").lower()
        iface     = self.get_option("interface") or "hci0"
        max_pages = max(1, min(3, int(self.get_option("max_pages") or 2)))

        if mode not in ("basic", "extended", "full"):
            print_error(f"Invalid mode: {mode}")
            return False

        print_info(f"Target   : {target}")
        print_info(f"Mode     : {mode}")
        print_info(f"Interface: {iface}")

        try:
            hci = open_hci(iface)
        except HCIError as e:
            print_error(str(e))
            return False

        handle = None
        try:
            print_info("Creating BR/EDR ACL connection...")
            handle = self._create_acl_connection(hci, target)
            if handle is None:
                print_error("ACL connection failed (target unreachable, BR/EDR off, or BLE-only)")
                if ble_random_static:
                    print_warning(f"{target} looks like a BLE Static Random address "
                                  "(top 2 bits = 11). LMP features only exist on BR/EDR.")
                    print_warning("Try 'use recon/ll_features' for this target instead.")
                return False
            print_success(f"Connected (handle=0x{handle:04x})")

            result = {"target": target}

            # Read_Remote_Version_Information. Some controllers reject this
            # for unauthenticated ACL; tolerate failure and continue.
            version_info = read_remote_version(hci, handle)
            if version_info is not None:
                lmp_v, manuf, subv = version_info
                v_label = decode_lmp_version(lmp_v)
                m_label = decode_company_id(manuf)
                print_success(
                    f"LMP version: {v_label} (0x{lmp_v:02X})  "
                    f"manufacturer: {m_label} (0x{manuf:04X})  "
                    f"subversion: 0x{subv:04X}"
                )
                result["lmp_version"] = lmp_v
                result["lmp_version_label"] = v_label
                result["manufacturer_id"] = manuf
                result["manufacturer_label"] = m_label
                result["lmp_subversion"] = subv
            else:
                print_info("Read_Remote_Version_Information unavailable, continuing")

            page0 = self._read_remote_features(hci, handle)
            if page0 is None:
                print_error("Read_Remote_Features failed")
                return False

            print_success(f"LMP features (page 0): {page0.hex()}")
            self._decode_features(page0, LMP_FEATURES_PAGE0, "Page 0")
            result["page_0_hex"] = page0.hex()
            result["page_0_bits"] = bitmap_to_dict(page0, LMP_FEATURES_PAGE0)

            if mode in ("extended", "full"):
                ext = page0[7] & 0x80  # extended features bit
                if not ext:
                    print_info("Target does not advertise extended feature pages")
                else:
                    for page in range(1, max_pages + 1):
                        epage = self._read_remote_extended_features(hci, handle, page)
                        if epage is None:
                            print_warning(f"Page {page} read failed (or not supported)")
                            continue
                        print_success(f"LMP features (page {page}): {epage.hex()}")
                        decoder = LMP_FEATURES_PAGE1 if page == 1 else LMP_FEATURES_PAGE2
                        self._decode_features(epage, decoder, f"Page {page}")
                        result[f"page_{page}_hex"] = epage.hex()
                        result[f"page_{page}_bits"] = bitmap_to_dict(epage, decoder)

            self.add_result(result)
            self._persist_fingerprint(target, result)
            return True

        finally:
            if handle is not None:
                self._classic_disconnect(hci, handle)
            hci.close()

    def _create_acl_connection(self, hci, target: str) -> Optional[int]:
        """HCI_Create_Connection (BR/EDR), returns connection handle."""
        addr = bd_addr_bytes(target)
        # bdaddr(6) + packet_type(2) + page_scan_repetition_mode(1)
        # + reserved(1) + clock_offset(2) + allow_role_switch(1)
        params = struct.pack("<6sHBBHB", addr, 0xCC18, 0x02, 0x00, 0x0000, 0x01)
        hci_cmd(hci, 0x01, 0x0005, params)
        ev = wait_event(hci, EVT_CONN_COMPLETE, timeout=15.0)
        if ev and len(ev) >= 11 and ev[0] == 0x00:
            return struct.unpack_from("<H", ev, 1)[0] & 0x0FFF
        return None

    def _read_remote_features(self, hci, handle: int) -> Optional[bytes]:
        """HCI_Read_Remote_Supported_Features."""
        hci_cmd(hci, 0x01, 0x001B, struct.pack("<H", handle))
        ev = wait_event(hci, EVT_REMOTE_FEATURES_COMPL, timeout=10.0)
        if ev and len(ev) >= 11 and ev[0] == 0x00:
            return ev[3:11]
        return None

    def _read_remote_extended_features(self, hci, handle: int, page: int) -> Optional[bytes]:
        """HCI_Read_Remote_Extended_Features."""
        hci_cmd(hci, 0x01, 0x001C, struct.pack("<HB", handle, page))
        ev = wait_event(hci, EVT_REMOTE_EXT_FEAT_COMPL, timeout=10.0)
        if ev and len(ev) >= 13 and ev[0] == 0x00:
            return ev[5:13]
        return None

    def _classic_disconnect(self, hci, handle: int):
        disconnect(hci, handle)
        wait_event(hci, EVT_DISCONN_COMPLETE, timeout=3.0)

    def _decode_features(self, data: bytes, names: List[str], label: str):
        print_info(f"  {label} decoded:")
        decoded = decode_bitmap(data, names)
        if not decoded:
            print(f"    {Colors.DARK_GREY}(none){Colors.RESET}")
            return
        for _idx, name in decoded:
            print(f"    {Colors.GREEN}✓{Colors.RESET} {name}")

    def _persist_fingerprint(self, target: str, result: dict) -> None:
        """Store this fingerprint so the CVE-matching scanner can read it.

        Best-effort: any store failure prints a one-line warning and
        does not affect the recon module's primary return value.
        """
        try:
            self.store.add_host(address=target)
            self.store.add_fingerprint(
                host=target,
                kind="lmp_features",
                data=result,
                source_module="recon/lmp_features",
            )
            print_info("fingerprint recorded (lmp_features)")
        except Exception as e:
            print_warning(f"fingerprint store skipped: {e}")
