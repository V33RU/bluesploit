"""
BlueSploit Module: BLE Full Scanner

Captures every advertising payload field that bleak exposes, decodes
manufacturer-specific data via the Bluetooth SIG Company Identifier
table in `core/utils/bt.py`, and stores the result so downstream
modules (cve_match, exploits) can read it without re-scanning.

REQUIRES bleak + a working Bluetooth adapter (Linux BlueZ, macOS
CoreBluetooth, or supported USB dongle). No demo mode: if bleak cannot
talk to the controller, the module fails with a clear error.

Output is a rich ASCII table, one row per device, plus a per-device
details block that prints the raw manufacturer / service-data
payloads in hex. Designed to be human-readable AND parseable by an
operator reviewing the engagement store later.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional

from core.base import (
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    ReconModule,
    Severity,
)
from core.ui.tables import Column, render_table, total_footer
from core.utils.bt import decode_company_id
from core.utils.printer import (
    print_error,
    print_info,
    print_success,
    print_warning,
)


class Module(ReconModule):

    info = ModuleInfo(
        name="BLE Full Scanner",
        description="Active BLE scan with full advertising payload decoding (address type, flags, service UUIDs, manufacturer data, service data, TX power, appearance)",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://bleak.readthedocs.io/en/latest/api/scanner.html",
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Scan duration in seconds",
            default=10,
        ))
        self.add_option(ModuleOption(
            name="interface",
            required=False,
            description="HCI adapter (Linux only, e.g. hci0)",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="min_rssi",
            required=False,
            description="Drop devices weaker than this RSSI (e.g. -85). Empty = keep all.",
            default=None,
        ))

    def run(self) -> bool:
        try:
            from bleak import BleakScanner  # noqa: F401
        except ImportError:
            print_error(
                "bleak is not installed. `pip install bleak` (already a "
                "declared runtime dep; the install.sh script handles it)."
            )
            return False

        timeout = float(self.get_option("timeout") or 10)
        interface = (self.get_option("interface") or "hci0").strip()
        raw_min_rssi = self.get_option("min_rssi")
        min_rssi: Optional[int] = None
        if raw_min_rssi not in (None, "", "None"):
            try:
                min_rssi = int(raw_min_rssi)
            except ValueError:
                print_warning(f"min_rssi {raw_min_rssi!r} is not an integer, ignored")

        print_info(
            f"Active scan on {interface} for {timeout:.0f}s "
            f"(min_rssi={min_rssi})"
        )

        try:
            results = asyncio.run(self._scan(timeout, interface))
        except KeyboardInterrupt:
            print_warning("Scan interrupted by operator")
            return False
        except Exception as e:
            print_error(f"Scan failed: {e}")
            return False

        if min_rssi is not None:
            kept = [r for r in results if r["rssi"] is not None and r["rssi"] >= min_rssi]
            dropped = len(results) - len(kept)
            results = kept
            if dropped:
                print_info(f"Dropped {dropped} device(s) below RSSI {min_rssi}")

        if not results:
            print_info("No advertising devices found")
            return False

        self._render(results)
        self._persist(results)
        return True

    # -- bleak interaction --------------------------------------------------

    async def _scan(self, timeout: float, interface: str) -> List[Dict[str, Any]]:
        """Run an active scan and collect every advertising payload field
        bleak exposes. One row per address; later advertisements for the
        same address replace the earlier snapshot so the latest payload
        wins."""
        from bleak import BleakScanner

        seen: Dict[str, Dict[str, Any]] = {}

        def _callback(device, adv_data):
            entry = self._build_row(device, adv_data)
            # Keep the strongest RSSI seen for each address (some
            # devices vary by several dBm across packets).
            existing = seen.get(entry["address"])
            if (
                existing is None
                or (entry["rssi"] is not None and existing["rssi"] is not None
                    and entry["rssi"] > existing["rssi"])
                or existing["rssi"] is None
            ):
                seen[entry["address"]] = entry
            else:
                # Still capture anything new even if RSSI weaker.
                for k, v in entry.items():
                    if v and not existing.get(k):
                        existing[k] = v

        scanner = BleakScanner(
            detection_callback=_callback,
            adapter=interface if interface else None,
        )
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()
        return list(seen.values())

    def _build_row(self, device, adv_data) -> Dict[str, Any]:
        """Translate one (BLEDevice, AdvertisementData) tuple from bleak
        into a flat dict suitable for our table renderer."""
        # Service UUIDs come back as full 128-bit strings. Sort them for
        # stable output.
        service_uuids = sorted(getattr(adv_data, "service_uuids", []) or [])

        # Manufacturer data is dict[int, bytes]. Decode the vendor name.
        mfg = dict(getattr(adv_data, "manufacturer_data", {}) or {})
        mfg_decoded = {
            f"0x{cid:04X} ({decode_company_id(cid)})": data.hex()
            for cid, data in mfg.items()
        }

        # Service data is dict[uuid_str, bytes].
        svc_data = {
            uuid: data.hex()
            for uuid, data in (getattr(adv_data, "service_data", {}) or {}).items()
        }

        return {
            "address": getattr(device, "address", "?"),
            "address_type": _addr_type(getattr(device, "address", "")),
            "name": getattr(adv_data, "local_name", None) or getattr(device, "name", "") or "",
            "rssi": getattr(adv_data, "rssi", None),
            "tx_power": getattr(adv_data, "tx_power", None),
            "service_uuids": service_uuids,
            "manufacturer_data": mfg_decoded,
            "service_data": svc_data,
            "platform_data": _platform_summary(adv_data),
        }

    # -- output -------------------------------------------------------------

    def _render(self, results: List[Dict[str, Any]]) -> None:
        cols = [
            Column("Address",      style="cyan",    no_wrap=True),
            Column("Type",         style="dim",     no_wrap=True),
            Column("Name"),
            Column("RSSI",         justify="right", no_wrap=True),
            Column("TX Pwr",       justify="right", no_wrap=True),
            Column("Services",     justify="right", no_wrap=True),
            Column("Mfg",          justify="right", no_wrap=True),
        ]
        rows = [
            (
                r["address"],
                r["address_type"],
                r["name"],
                "" if r["rssi"] is None else r["rssi"],
                "" if r["tx_power"] is None else r["tx_power"],
                len(r["service_uuids"]),
                len(r["manufacturer_data"]),
            )
            for r in sorted(results, key=lambda r: r["rssi"] or -999, reverse=True)
        ]
        render_table(
            cols, rows,
            title="BLE devices",
            footer=total_footer("device", len(results)),
        )

        # Per-device details, only printed when there's something to say
        # beyond what the table already shows.
        for r in sorted(results, key=lambda r: r["rssi"] or -999, reverse=True):
            extras = []
            if r["service_uuids"]:
                extras.append(("Service UUIDs", "\n      ".join(r["service_uuids"])))
            if r["manufacturer_data"]:
                lines = [f"{vendor}: {hexed}" for vendor, hexed in r["manufacturer_data"].items()]
                extras.append(("Manufacturer data", "\n      ".join(lines)))
            if r["service_data"]:
                lines = [f"{uuid}: {hexed}" for uuid, hexed in r["service_data"].items()]
                extras.append(("Service data", "\n      ".join(lines)))
            if not extras:
                continue
            print(f"\n  {r['address']} ({r['name'] or 'unnamed'})")
            for label, value in extras:
                print(f"    {label}: {value}")

    # -- persistence --------------------------------------------------------

    def _persist(self, results: List[Dict[str, Any]]) -> None:
        """Store discovered hosts plus a per-host `adv` fingerprint so
        downstream modules see the full payload, not just the address."""
        saved_hosts = 0
        saved_fps = 0
        try:
            store = self.store
        except Exception as e:
            print_warning(f"Store unavailable, results not persisted: {e}")
            return

        for r in results:
            try:
                store.add_host(
                    address=r["address"],
                    name=r["name"] or None,
                    rssi=r["rssi"],
                )
                saved_hosts += 1
                store.add_fingerprint(
                    host=r["address"],
                    kind="adv",
                    data={k: v for k, v in r.items() if k != "address"},
                    source_module="recon/ble_scan_full",
                )
                saved_fps += 1
                self.add_result(r)
            except Exception as e:
                print_warning(f"Store write skipped for {r['address']}: {e}")

        if saved_hosts:
            print_success(
                f"Recorded {saved_hosts} host(s) and {saved_fps} adv fingerprint(s)"
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _addr_type(addr: str) -> str:
    """BLE address type heuristic from the top two bits of the MSB.

    Per Core Spec Vol 6 Part B §1.3.2:
        11 -> Static Random
        01 -> Resolvable Private
        00 -> Non-Resolvable Private (rare) or public
    """
    if not addr or ":" not in addr:
        return ""
    try:
        msb = int(addr.split(":")[0], 16)
    except ValueError:
        return ""
    bits = msb >> 6
    if bits == 0b11:
        return "Static Random"
    if bits == 0b01:
        return "Resolvable Random"
    return "Public"


def _platform_summary(adv_data) -> Dict[str, Any]:
    """bleak's `platform_data` is backend-specific. Return a small
    summary if present so we don't drop info on the floor."""
    plat = getattr(adv_data, "platform_data", None)
    if plat is None:
        return {}
    # platform_data is usually a tuple of (device, props_dict) on
    # BlueZ. Reduce to a JSON-safe view.
    try:
        return {"repr": repr(plat)[:200]}
    except Exception:
        return {}
