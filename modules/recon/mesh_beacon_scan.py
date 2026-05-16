"""
Bluetooth Mesh Beacon Scanner - passive Mesh advertising decoder.

Ref: Mesh Profile v1.1 3.10 (Beaconing)
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ReconModule, Severity
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning

MESH_PROVISIONING_SVC = "00001827-0000-1000-8000-00805f9b34fb"
MESH_PROXY_SVC        = "00001828-0000-1000-8000-00805f9b34fb"

# OOB info bit positions, Mesh Profile 3.10.2.1.
OOB_BITS = {
    0: "Other",
    1: "Electronic / URI",
    2: "2D machine-readable code",
    3: "Barcode",
    4: "NFC",
    5: "Number",
    6: "String",
    11: "On box",
    12: "Inside box",
    13: "On piece of paper",
    14: "Inside manual",
    15: "On device",
}


class Module(ReconModule):

    info = ModuleInfo(
        name="Bluetooth Mesh Beacon Scanner",
        description="Passive scan for Mesh Unprovisioned Device Beacons (UUID 0x1827) and Secure Network Beacons (UUID 0x1828) with full PDU decoding",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/mesh-protocol/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Scan duration in seconds",
            default=20,
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter (Linux only, e.g. hci0)",
            default="hci0",
        ))

    def run(self) -> bool:
        try:
            from bleak import BleakScanner  # noqa: F401
        except ImportError:
            print_error("bleak is not installed. `pip install bleak`.")
            return False

        timeout = float(self.get_option("timeout") or 20)
        interface = (self.get_option("interface") or "hci0").strip()

        print_info(f"Mesh scan on {interface} for {timeout:.0f}s")
        try:
            beacons = asyncio.run(self._scan(timeout, interface))
        except KeyboardInterrupt:
            print_warning("Scan interrupted")
            return False
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False

        if not beacons:
            print_info(
                "No Mesh beacons heard. Either no Mesh nodes in range or "
                "the adapter is filtering passive adv."
            )
            return False

        self._render(beacons)
        self._persist(beacons)
        print_success(f"Captured {len(beacons)} Mesh beacon(s)")
        return True

    async def _scan(self, timeout: float, interface: str) -> List[Dict[str, Any]]:
        from bleak import BleakScanner

        captured: Dict[str, Dict[str, Any]] = {}

        def _callback(device, adv_data):
            svc_data = dict(getattr(adv_data, "service_data", {}) or {})
            for uuid_str, raw in svc_data.items():
                u = uuid_str.lower()
                if MESH_PROVISIONING_SVC in u or u == "1827" or "00001827" in u:
                    decoded = decode_unprovisioned_beacon(bytes(raw))
                    decoded.update({
                        "address": getattr(device, "address", "?"),
                        "rssi": getattr(adv_data, "rssi", None),
                        "kind": "unprovisioned",
                    })
                    captured[(decoded["address"], "u")] = decoded
                elif MESH_PROXY_SVC in u or u == "1828" or "00001828" in u:
                    decoded = decode_secure_network_beacon(bytes(raw))
                    decoded.update({
                        "address": getattr(device, "address", "?"),
                        "rssi": getattr(adv_data, "rssi", None),
                        "kind": "secure_network",
                    })
                    captured[(decoded["address"], "s")] = decoded

        scanner = BleakScanner(
            detection_callback=_callback,
            adapter=interface if interface else None,
        )
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return list(captured.values())

    def _render(self, beacons: List[Dict[str, Any]]) -> None:
        cols = [
            Column("Address",   style="cyan",   no_wrap=True),
            Column("Kind",      style="dim",    no_wrap=True),
            Column("RSSI",      justify="right"),
            Column("Identifier"),
            Column("Extras"),
        ]
        rows = []
        for b in beacons:
            if b["kind"] == "unprovisioned":
                ident = b.get("device_uuid_hex", "")[:16] + "..."
                extras = f"OOB={','.join(b.get('oob_info_labels') or []) or '-'}"
            else:
                ident = b.get("network_id_hex", "")
                extras = (
                    f"IVI={b.get('iv_update')} keyref={b.get('key_refresh')} "
                    f"IVIndex=0x{b.get('iv_index', 0):08x}"
                )
            rows.append((
                b["address"], b["kind"],
                "" if b["rssi"] is None else b["rssi"],
                ident, extras,
            ))
        render_table(
            cols, rows,
            title="Mesh beacons",
            footer=total_footer("beacon", len(beacons)),
        )
        print()
        for b in beacons:
            print(f"  {b['address']} ({b['kind']})")
            for k, v in b.items():
                if k in ("address", "kind", "rssi"):
                    continue
                print(f"    {k}: {v}")
            print()

    def _persist(self, beacons: List[Dict[str, Any]]) -> None:
        try:
            store = self.store
        except Exception as e:
            print_warning(f"Store unavailable: {e}")
            return
        for b in beacons:
            try:
                store.add_host(address=b["address"], rssi=b.get("rssi"))
                store.add_fingerprint(
                    host=b["address"],
                    kind="mesh_beacon",
                    data=b,
                    source_module="recon/mesh_beacon_scan",
                )
                self.add_result(b)
            except Exception as e:
                print_warning(f"Store write skipped for {b['address']}: {e}")


# Parsers ----------------------------------------------------------------


def decode_unprovisioned_beacon(payload: bytes) -> Dict[str, Any]:
    """Decode an Unprovisioned Device Beacon AD payload.

    Layout (Mesh Profile 3.10.2):
        Device UUID    16 bytes
        OOB Information 2 bytes (bitmap)
        URI Hash       0 or 4 bytes (optional)
    """
    out: Dict[str, Any] = {}
    if len(payload) < 18:
        out["error"] = f"truncated unprovisioned beacon ({len(payload)} bytes)"
        return out
    device_uuid = payload[:16]
    oob_info    = int.from_bytes(payload[16:18], "big")
    out["device_uuid_hex"] = device_uuid.hex()
    out["oob_info_bitmap"] = f"0x{oob_info:04x}"
    out["oob_info_labels"] = [name for bit, name in OOB_BITS.items() if oob_info & (1 << bit)]
    if len(payload) >= 22:
        out["uri_hash"] = payload[18:22].hex()
    return out


def decode_secure_network_beacon(payload: bytes) -> Dict[str, Any]:
    """Decode a Secure Network Beacon AD payload.

    Layout (Mesh Profile 3.10.3):
        Flags          1 byte  (bit 0 = KeyRefresh, bit 1 = IVUpdate)
        Network ID     8 bytes
        IV Index       4 bytes
        Authentication 8 bytes  (truncated AES-CMAC over the above)
    """
    out: Dict[str, Any] = {}
    if len(payload) < 21:
        out["error"] = f"truncated secure network beacon ({len(payload)} bytes)"
        return out
    flags = payload[0]
    out["key_refresh"] = bool(flags & 0x01)
    out["iv_update"]   = bool(flags & 0x02)
    out["network_id_hex"] = payload[1:9].hex()
    out["iv_index"] = int.from_bytes(payload[9:13], "big")
    out["auth_hex"] = payload[13:21].hex()
    return out
