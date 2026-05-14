"""
BlueSploit Module: BLE Target Enumeration

Connects to a single BLE target via bleak and walks the entire GATT
topology: services, characteristics with both declaration and value
handles, descriptors, and (when readable + opted in) the current
values. Output mirrors the mirage `ble_connect|ble_discover` table
shape so the operator sees one row per characteristic with full
context.

REQUIRES bleak + a working Bluetooth adapter. No demo mode.

The output is intentionally chatty: one summary services table, then
one detailed table per service. Standard SIG-assigned UUIDs are
resolved to their short names via `core/ble_meta`; vendor-defined
UUIDs render as the raw UUID128 (matching mirage).
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple

from core.base import (
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    ReconModule,
    Severity,
)
from core.ble_meta import (
    name_for_characteristic,
    name_for_descriptor,
    name_for_service,
    properties_to_permissions,
    short_uuid,
)
from core.ui.tables import Column, render_table
from core.utils.printer import (
    print_error,
    print_info,
    print_success,
    print_warning,
)


class Module(ReconModule):

    info = ModuleInfo(
        name="BLE Target Enumeration",
        description="Connect to one BLE target and walk every service / characteristic / descriptor, mirage-style",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://bleak.readthedocs.io/en/latest/api/client.html",
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
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
            description="HCI adapter (Linux only, e.g. hci0)",
            default="hci0",
        ))
        self.add_option(ModuleOption(
            name="timeout",
            required=False,
            description="Connect + discover timeout in seconds",
            default=20,
        ))
        self.add_option(ModuleOption(
            name="read_values",
            required=False,
            description="Read every readable characteristic value (true/false)",
            default=True,
        ))
        self.add_option(ModuleOption(
            name="read_descriptors",
            required=False,
            description="Read every descriptor value (true/false)",
            default=True,
        ))

    def run(self) -> bool:
        try:
            from bleak import BleakClient  # noqa: F401
        except ImportError:
            print_error("bleak is not installed. `pip install bleak`.")
            return False

        target = self.get_option("target")
        if not self.validate_bd_addr(target):
            print_error(f"Invalid BD_ADDR: {target}")
            return False

        interface = (self.get_option("interface") or "hci0").strip()
        timeout = float(self.get_option("timeout") or 20)
        read_values = _coerce_bool(self.get_option("read_values"), default=True)
        read_descs = _coerce_bool(self.get_option("read_descriptors"), default=True)

        print_info(f"Connecting to {target} on {interface} (timeout={timeout:.0f}s)")

        try:
            topology = asyncio.run(self._enumerate(
                target=target,
                interface=interface,
                timeout=timeout,
                read_values=read_values,
                read_descs=read_descs,
            ))
        except KeyboardInterrupt:
            print_warning("Enumeration interrupted")
            return False
        except Exception as e:
            print_error(f"Enumeration failed: {e}")
            return False

        if topology is None or not topology["services"]:
            print_warning("No services discovered (target may have refused, or has no GATT)")
            return False

        print_success(
            f"Connected and discovered {len(topology['services'])} service(s)"
        )

        self._render_services_summary(topology["services"])
        for svc in topology["services"]:
            self._render_service_detail(svc)

        self._persist(target, topology)
        return True

    # -- bleak interaction --------------------------------------------------

    async def _enumerate(
        self,
        target: str,
        interface: str,
        timeout: float,
        read_values: bool,
        read_descs: bool,
    ) -> Optional[Dict[str, Any]]:
        from bleak import BleakClient

        client_kwargs: Dict[str, Any] = {"timeout": timeout}
        if interface:
            client_kwargs["adapter"] = interface

        async with BleakClient(target, **client_kwargs) as client:
            if not client.is_connected:
                return None

            services_view: List[Dict[str, Any]] = []
            # bleak.services is a BleakGATTServiceCollection; iterate
            # in handle order so output is stable.
            services_sorted = sorted(
                list(client.services), key=lambda s: getattr(s, "handle", 0)
            )
            for svc in services_sorted:
                chars = []
                for char in svc.characteristics:
                    descs = []
                    for desc in char.descriptors:
                        value_hex: Optional[str] = None
                        if read_descs:
                            try:
                                raw = await client.read_gatt_descriptor(desc.handle)
                                value_hex = bytes(raw).hex()
                            except Exception:
                                value_hex = None
                        descs.append({
                            "handle": desc.handle,
                            "uuid": str(desc.uuid),
                            "name": name_for_descriptor(str(desc.uuid)),
                            "value": value_hex,
                        })

                    value_hex_char: Optional[str] = None
                    if read_values and "read" in [p.lower() for p in char.properties]:
                        try:
                            raw = await client.read_gatt_char(char.uuid)
                            value_hex_char = bytes(raw).hex()
                        except Exception:
                            value_hex_char = None

                    value_handle = getattr(char, "handle", None)
                    # BLE convention: declaration handle is value handle minus one.
                    decl_handle = value_handle - 1 if value_handle is not None else None

                    chars.append({
                        "decl_handle": decl_handle,
                        "value_handle": value_handle,
                        "uuid": str(char.uuid),
                        "uuid16": _uuid16_hex(str(char.uuid)),
                        "name": name_for_characteristic(str(char.uuid)),
                        "properties": list(char.properties),
                        "permissions": properties_to_permissions(char.properties),
                        "value_hex": value_hex_char,
                        "descriptors": descs,
                    })

                # Service handle range: start is the service's own
                # handle, end is the highest descriptor / char value
                # handle inside it (matches mirage's display).
                start_handle = getattr(svc, "handle", None)
                end_handle = start_handle
                for c in chars:
                    if c["value_handle"] is not None:
                        end_handle = max(end_handle or 0, c["value_handle"])
                    for d in c["descriptors"]:
                        end_handle = max(end_handle or 0, d["handle"])

                services_view.append({
                    "start_handle": start_handle,
                    "end_handle": end_handle,
                    "uuid": str(svc.uuid),
                    "uuid16": _uuid16_hex(str(svc.uuid)),
                    "name": name_for_service(str(svc.uuid)),
                    "characteristics": chars,
                })

            return {
                "target": target,
                "services": services_view,
            }

    # -- output -------------------------------------------------------------

    def _render_services_summary(self, services: List[Dict[str, Any]]) -> None:
        cols = [
            Column("Start Handle", style="dim",     justify="right", no_wrap=True),
            Column("End Handle",   style="dim",     justify="right", no_wrap=True),
            Column("UUID16",       style="magenta", no_wrap=True),
            Column("UUID128",      style="cyan",    no_wrap=True),
            Column("Name"),
        ]
        rows = []
        for s in services:
            rows.append((
                _h(s["start_handle"]),
                _h(s["end_handle"]),
                s["uuid16"],
                _strip_uuid(s["uuid"]),
                s["name"],
            ))
        render_table(cols, rows, title="Services")

    def _render_service_detail(self, svc: Dict[str, Any]) -> None:
        title = (
            f"Service '{svc['name']}'(start Handle = {_h(svc['start_handle'])} "
            f"/ end Handle = {_h(svc['end_handle'])})"
            if svc["name"]
            else f"Service {_strip_uuid(svc['uuid'])}(start Handle = {_h(svc['start_handle'])} "
                 f"/ end Handle = {_h(svc['end_handle'])})"
        )
        cols = [
            Column("Declaration Handle", style="dim",     justify="right", no_wrap=True),
            Column("Value Handle",       style="dim",     justify="right", no_wrap=True),
            Column("UUID16",             style="magenta", no_wrap=True),
            Column("UUID128",            style="cyan",    no_wrap=True),
            Column("Name"),
            Column("Permissions",        style="yellow"),
            Column("Value"),
            Column("Descriptors"),
        ]
        rows = []
        for c in svc["characteristics"]:
            descs_str = ""
            if c["descriptors"]:
                lines = []
                for d in c["descriptors"]:
                    name = d["name"] or _strip_uuid(d["uuid"])
                    val = d["value"] or ""
                    lines.append(f"{name} : {val}")
                descs_str = "\n".join(lines)
            rows.append((
                _h(c["decl_handle"]),
                _h(c["value_handle"]),
                c["uuid16"],
                _strip_uuid(c["uuid"]),
                c["name"],
                ",".join(c["permissions"]),
                c["value_hex"] or "",
                descs_str,
            ))
        render_table(cols, rows, title=title)

    # -- persistence --------------------------------------------------------

    def _persist(self, target: str, topology: Dict[str, Any]) -> None:
        try:
            store = self.store
            store.add_host(address=target)
            store.add_fingerprint(
                host=target,
                kind="gatt_topology",
                data=topology,
                source_module="recon/ble_target_enum",
            )
            print_success("GATT topology fingerprint recorded")
        except Exception as e:
            print_warning(f"Store write skipped: {e}")
        self.add_result(topology)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "y", "on")
    return default


def _uuid16_hex(uuid128: str) -> str:
    """Return `0xNNNN` for a SIG short UUID, empty string otherwise."""
    s = short_uuid(uuid128)
    if s is None:
        return ""
    return f"0x{s:04x}"


def _strip_uuid(uuid128: str) -> str:
    """Hex-only form of the UUID, no dashes, matching mirage's display."""
    return uuid128.replace("-", "").lower()


def _h(handle: Optional[int]) -> str:
    if handle is None:
        return ""
    return f"0x{handle:04x}"
