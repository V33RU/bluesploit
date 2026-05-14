"""
BlueSploit Module: BLE Link Layer FeatureSet Reader

Reads the Link Layer (LL) FeatureSet of a remote BLE device via the
HCI LE_Read_Remote_Used_Features command. Decodes each feature bit
against the Bluetooth Core Specification (Vol 6 Part B §4.6), useful
for fingerprinting BLE controller version, supported PHYs, extended
advertising support, periodic advertising, channel selection algo #2,
LE 2M / Coded PHY, LE Power Control, etc.
"""

import struct
import time
from typing import Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.utils.bt import (
    HCIError,
    LE_READ_FEATURES_COMPL,
    auto_addr_type,
    bitmap_to_dict,
    decode_bitmap,
    decode_company_id,
    decode_lmp_version,
    disconnect,
    hci_cmd,
    le_create_connection,
    open_hci,
    read_remote_version,
    require_root,
    wait_le_meta,
)
from core.utils.printer import (
    Colors,
    print_error,
    print_info,
    print_success,
)

# Per BT Core Spec Vol 6 Part B §4.6, LE LL features (8 bytes = 64 bits)
LL_FEATURES = [
    # Byte 0
    "LE Encryption", "Connection Parameters Request",
    "Extended Reject Indication", "Slave-initiated Features Exchange",
    "LE Ping", "LE Data Packet Length Extension", "LL Privacy",
    "Extended Scanner Filter Policies",
    # Byte 1
    "LE 2M PHY", "Stable Modulation Index Transmitter",
    "Stable Modulation Index Receiver", "LE Coded PHY",
    "LE Extended Advertising", "LE Periodic Advertising",
    "Channel Selection Algorithm #2", "LE Power Class 1",
    # Byte 2
    "Minimum Number of Used Channels Procedure", "Connection CTE Request",
    "Connection CTE Response", "Connectionless CTE Transmitter",
    "Connectionless CTE Receiver", "AoD (Antenna Switching during CTE Tx)",
    "AoA (Antenna Switching during CTE Rx)",
    "Receiving Constant Tone Extensions",
    # Byte 3
    "Periodic Advertising Sync Transfer Sender",
    "Periodic Advertising Sync Transfer Recipient",
    "Sleep Clock Accuracy Updates", "Remote Public Key Validation",
    "Connected Isochronous Stream Master",
    "Connected Isochronous Stream Slave",
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
            description="Peer address type: auto, public, or random",
            default="auto",
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="LE connect timeout (s)",
            default=12,
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

        iface     = self.get_option("interface") or "hci0"
        addr_type = (self.get_option("addr_type") or "auto").lower()
        timeout   = float(self.get_option("timeout") or 12)

        if addr_type == "auto":
            addr_type = auto_addr_type(target)
            print_info(f"Auto-detected address type: {addr_type}")

        peer_at = 0x01 if addr_type == "random" else 0x00

        print_info(f"Target   : {target} ({addr_type})")
        print_info(f"Interface: {iface}")

        try:
            hci = open_hci(iface)
        except HCIError as e:
            print_error(str(e))
            return False

        handle = None
        try:
            print_info("Opening LE connection...")
            handle = le_create_connection(hci, target, peer_at, timeout=timeout)
            if handle is None:
                print_error("LE connection failed")
                return False
            print_success(f"LE connected (handle=0x{handle:04x})")

            fp = {
                "target": target,
                "addr_type": addr_type,
            }

            # Read_Remote_Version_Information on the LE link returns the
            # LE LL controller version. Same HCI opcode as BR/EDR; some
            # peripherals reject it before encryption, tolerate failure.
            version_info = read_remote_version(hci, handle)
            if version_info is not None:
                ll_v, manuf, subv = version_info
                v_label = decode_lmp_version(ll_v)
                m_label = decode_company_id(manuf)
                print_success(
                    f"LE controller version: {v_label} (0x{ll_v:02X})  "
                    f"manufacturer: {m_label} (0x{manuf:04X})  "
                    f"subversion: 0x{subv:04X}"
                )
                fp["ll_version"] = ll_v
                fp["ll_version_label"] = v_label
                fp["manufacturer_id"] = manuf
                fp["manufacturer_label"] = m_label
                fp["ll_subversion"] = subv
            else:
                print_info("Read_Remote_Version_Information unavailable, continuing")

            features = self._read_le_features(hci, handle)
            if features is None:
                print_error("LE_Read_Remote_Used_Features failed")
                return False

            print_success(f"LL FeatureSet: {features.hex()}")
            self._decode(features)

            fp["ll_features_hex"] = features.hex()
            fp["ll_features_bits"] = bitmap_to_dict(features, LL_FEATURES)
            self.add_result(fp)
            self._persist_fingerprint(target, fp)
            return True

        finally:
            if handle is not None:
                disconnect(hci, handle)
            hci.close()

    def _read_le_features(self, hci, handle: int) -> Optional[bytes]:
        """HCI_LE_Read_Remote_Used_Features (OGF=0x08, OCF=0x0016)."""
        hci_cmd(hci, 0x08, 0x0016, struct.pack("<H", handle))
        pkt = wait_le_meta(hci, LE_READ_FEATURES_COMPL, timeout=8.0)
        if pkt and len(pkt) >= 14 and pkt[4] == 0x00:
            # status(1) + handle(2) + features(8)
            return pkt[6:14]
        return None

    def _decode(self, data: bytes):
        print_info("LL feature flags:")
        decoded = decode_bitmap(data, LL_FEATURES)
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
                kind="ll_features",
                data=result,
                source_module="recon/ll_features",
            )
            print_info("fingerprint recorded (ll_features)")
        except Exception as e:
            print_warning(f"fingerprint store skipped: {e}")
