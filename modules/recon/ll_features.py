"""
BlueSploit Module: BLE Link Layer FeatureSet Reader

Reads the Link Layer (LL) FeatureSet of a remote BLE device via the
HCI LE_Read_Remote_Used_Features command. Decodes each feature bit
against the Bluetooth Core Specification (Vol 6 Part B §4.6) — useful
for fingerprinting BLE controller version, supported PHYs, extended
advertising support, periodic advertising, channel selection algo #2,
LE 2M / Coded PHY, LE Power Control, etc.
"""

import os
import select
import socket
import struct
import time
from typing import Optional, List

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

AF_BLUETOOTH    = 31
BTPROTO_HCI     = 1
HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT   = 0x04
HCI_LE_META     = 0x3E
LE_CONN_COMPLETE       = 0x01
LE_READ_FEATURES_COMPL = 0x04

# Per BT Core Spec Vol 6 Part B §4.6 — LE LL features (8 bytes = 64 bits)
LL_FEATURES = [
    # Byte 0
    "LE Encryption", "Connection Parameters Request",
    "Extended Reject Indication", "Slave-initiated Features Exchange",
    "LE Ping", "LE Data Packet Length Extension", "LL Privacy",
    "Extended Scanner Filter Policies",
    # Byte 1
    "LE 2M PHY", "Stable Modulation Index — Transmitter",
    "Stable Modulation Index — Receiver", "LE Coded PHY",
    "LE Extended Advertising", "LE Periodic Advertising",
    "Channel Selection Algorithm #2", "LE Power Class 1",
    # Byte 2
    "Minimum Number of Used Channels Procedure", "Connection CTE Request",
    "Connection CTE Response", "Connectionless CTE Transmitter",
    "Connectionless CTE Receiver", "AoD (Antenna Switching during CTE Tx)",
    "AoA (Antenna Switching during CTE Rx)",
    "Receiving Constant Tone Extensions",
    # Byte 3
    "Periodic Advertising Sync Transfer — Sender",
    "Periodic Advertising Sync Transfer — Recipient",
    "Sleep Clock Accuracy Updates", "Remote Public Key Validation",
    "Connected Isochronous Stream — Master",
    "Connected Isochronous Stream — Slave",
    "Isochronous Broadcaster", "Synchronized Receiver",
    # Byte 4
    "Connected Isochronous Stream (Host Support)",
    "LE Power Control Request", "LE Power Change Indication",
    "LE Path Loss Monitoring", "Periodic Advertising ADI support",
    "Connection Subrating", "Connection Subrating (Host Support)",
    "Channel Classification",
    # Byte 5..7 reserved / future
] + ["Reserved"] * 24


class Module(ReconModule):

    info = ModuleInfo(
        name="BLE LL FeatureSet Reader",
        description="Read BLE Link Layer FeatureSet of a remote LE device",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=True,
            description="Target BLE BD_ADDR",
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="addr_type",
            required=False,
            description="Peer address type: public or random",
            default="public",
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="LE connect timeout (s)",
            default=12,
        ))

    def run(self) -> bool:
        if os.geteuid() != 0:
            print_error("Root required for raw HCI socket access")
            return False

        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        iface     = self.get_option("interface") or "hci0"
        addr_type = (self.get_option("addr_type") or "public").lower()
        timeout   = float(self.get_option("timeout") or 12)
        peer_at   = 0x01 if addr_type == "random" else 0x00

        print_info(f"Target   : {target} ({addr_type})")
        print_info(f"Interface: {iface}")

        hci = self._open_hci(iface)
        if not hci:
            return False

        handle = None
        try:
            print_info("Opening LE connection...")
            handle = self._le_create_connection(hci, target, peer_at, timeout)
            if handle is None:
                print_error("LE connection failed")
                return False
            print_success(f"LE connected (handle=0x{handle:04x})")

            features = self._read_le_features(hci, handle)
            if features is None:
                print_error("LE_Read_Remote_Used_Features failed")
                return False

            print_success(f"LL FeatureSet: {features.hex()}")
            self._decode(features)

            self.add_result({
                "target": target,
                "addr_type": addr_type,
                "ll_features_hex": features.hex(),
                "ll_features_bits": self._extract_bits(features),
            })
            return True

        finally:
            if handle is not None:
                self._disconnect(hci, handle)
            hci.close()

    def _open_hci(self, iface: str) -> Optional[socket.socket]:
        try:
            hci = socket.socket(AF_BLUETOOTH, socket.SOCK_RAW, BTPROTO_HCI)
            dev_id = int(iface.replace("hci", ""))
            hci.bind((dev_id,))
            return hci
        except OSError as e:
            print_error(f"HCI open failed on {iface}: {e}")
            return None

    def _hci_cmd(self, hci, ogf, ocf, params=b''):
        opcode = (ogf << 10) | ocf
        pkt = struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params
        hci.setblocking(True); hci.send(pkt); hci.setblocking(False)

    def _le_create_connection(self, hci, target, peer_at, timeout):
        addr = bytes(int(x, 16) for x in reversed(target.split(":")))
        params = struct.pack("<HHBB6sBHHHHHH",
            0x0060, 0x0030, 0x00, peer_at,
            addr, 0x00,
            0x0006, 0x000C, 0x0000, 0x00C8, 0x0000, 0x0000)
        self._hci_cmd(hci, 0x08, 0x000D, params)
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([hci], [], [], 0.5)
            if not r:
                continue
            pkt = hci.recv(255)
            if (pkt and pkt[0] == HCI_EVENT_PKT and pkt[1] == HCI_LE_META
                    and len(pkt) >= 7 and pkt[3] == LE_CONN_COMPLETE
                    and pkt[4] == 0x00):
                return struct.unpack_from("<H", pkt, 5)[0] & 0x0FFF
        return None

    def _read_le_features(self, hci, handle: int) -> Optional[bytes]:
        """HCI_LE_Read_Remote_Used_Features (OGF=0x08, OCF=0x0016)."""
        self._hci_cmd(hci, 0x08, 0x0016, struct.pack("<H", handle))
        deadline = time.time() + 8
        while time.time() < deadline:
            r, _, _ = select.select([hci], [], [], 0.5)
            if not r:
                continue
            pkt = hci.recv(255)
            if (pkt and pkt[0] == HCI_EVENT_PKT and pkt[1] == HCI_LE_META
                    and len(pkt) >= 14 and pkt[3] == LE_READ_FEATURES_COMPL
                    and pkt[4] == 0x00):
                # status(1) + handle(2) + features(8)
                return pkt[6:14]
        return None

    def _disconnect(self, hci, handle: int):
        params = struct.pack("<HB", handle, 0x13)
        try:
            self._hci_cmd(hci, 0x01, 0x0006, params)
        except Exception:
            pass

    def _extract_bits(self, data: bytes) -> dict:
        bits = {}
        for byte_idx, byte in enumerate(data):
            for bit in range(8):
                idx = byte_idx * 8 + bit
                if idx >= len(LL_FEATURES) or LL_FEATURES[idx] == "Reserved":
                    continue
                if byte & (1 << bit):
                    bits[LL_FEATURES[idx]] = True
        return bits

    def _decode(self, data: bytes):
        print_info("LL feature flags:")
        any_set = False
        for byte_idx, byte in enumerate(data):
            for bit in range(8):
                idx = byte_idx * 8 + bit
                if idx >= len(LL_FEATURES) or LL_FEATURES[idx] == "Reserved":
                    continue
                if byte & (1 << bit):
                    any_set = True
                    print(f"    {Colors.GREEN}✓{Colors.RESET} {LL_FEATURES[idx]}")
        if not any_set:
            print(f"    {Colors.DARK_GREY}(none){Colors.RESET}")
