"""
BLE Target Enumeration - GATT topology walker, mirage-style output.

Ref: bleak (https://bleak.readthedocs.io); Core Spec Vol 3 Part G
"""

from __future__ import annotations

import asyncio
import json
import re
import struct
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from core.base import (
    BTProtocol,
    ModuleInfo,
    ModuleOption,
    ReconModule,
    Severity,
)
from core.ble_meta import (
    CHIPSET_VENDORS as _CHIPSET_VENDORS,
)
from core.ble_meta import (
    LMP_SUBVER_CHIPSET as _LMP_SUBVER_CHIPSET,
)
from core.ble_meta import (
    MFR_CHIPSET_HINTS as _MFR_CHIPSET_HINTS,
)
from core.ble_meta import (
    OUI_CHIPSET as _OUI_CHIPSET,
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
    Colors,
    print_error,
    print_info,
    print_success,
    print_warning,
)

# ---------------------------------------------------------------------------
# Device-identity capture helpers (merged from recon/gatt_enum)
# ---------------------------------------------------------------------------

# SIG 16-bit characteristic UUIDs that feed the identity block.
_IDENTITY_CHARS: Dict[str, str] = {
    "2a00": "device_name",
    "2a23": "system_id",
    "2a24": "model",
    "2a25": "serial",
    "2a26": "firmware",
    "2a27": "hardware",
    "2a28": "software",
    "2a29": "manufacturer",
    "2a50": "pnp_id_raw",
}

def _decode_pnp_id(raw: bytes) -> Dict[str, Any]:
    """Parse PnP ID (0x2A50, 7 bytes) per GATT spec and return a
    structured dict including chipset vendor if known."""
    if len(raw) < 7:
        return {}
    src, vid, pid, ver = struct.unpack_from("<BHHH", raw)
    src_label = "BT SIG" if src == 1 else "USB" if src == 2 else f"src={src}"
    vendor = _CHIPSET_VENDORS.get(vid, f"0x{vid:04X}")
    major, minor, patch = (ver >> 8) & 0xFF, (ver >> 4) & 0x0F, ver & 0x0F
    return {
        "vendor_id_source": src_label,
        "vendor_id":        vid,
        "vendor_name":      vendor,
        "product_id":       pid,
        "version":          f"{major}.{minor}.{patch}",
        "chipset":          vendor,
    }


def _infer_chipset(manufacturer: Optional[str], addr: str) -> Optional[str]:
    """Infer BLE chipset from manufacturer name string or address OUI."""
    if manufacturer:
        mlow = manufacturer.lower()
        for hint, label in _MFR_CHIPSET_HINTS.items():
            if hint in mlow:
                return label
    oui = addr.replace(":", "").upper()[:6]
    return _OUI_CHIPSET.get(oui)


def _parse_hci_version_lines(lines: List[str], info: Dict[str, Any]) -> None:
    """Extract LMP Version / Subversion / Manufacturer from hcitool output."""
    for line in lines:
        ls = line.strip()
        if ls.startswith("LMP Version:"):
            m = re.search(
                r"(\d+\.\d+)\s+\(0x[0-9a-fA-F]+\)\s+LMP Subversion:\s+0x([0-9a-fA-F]+)", ls
            )
            if m:
                info["lmp_version"]  = m.group(1)
                raw_sub              = int(m.group(2), 16)
                info["lmp_subver"]   = f"0x{raw_sub:04X}"
                if raw_sub in _LMP_SUBVER_CHIPSET:
                    info["chipset_exact"] = _LMP_SUBVER_CHIPSET[raw_sub]
        elif ls.startswith("Manufacturer:"):
            info["ll_manufacturer"] = ls.split(":", 1)[1].strip()


def _get_ll_info(addr: str) -> Dict[str, Any]:
    """Query hcitool and bluetoothctl for cached LL/LMP version and name.

    Tries in order: hcitool leinfo -> hcitool info -> bluetoothctl info.
    All subprocess calls are best-effort; failures are silently ignored.
    """
    info: Dict[str, Any] = {
        "lmp_version": None, "lmp_subver": None,
        "ll_manufacturer": None, "bt_name": None,
        "appearance": None, "chipset_exact": None,
    }
    for cmd in (["hcitool", "leinfo", addr], ["hcitool", "info", addr]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and "LMP Version" in r.stdout:
                _parse_hci_version_lines(r.stdout.splitlines(), info)
                break
        except Exception:
            pass
    try:
        r = subprocess.run(
            ["bluetoothctl", "info", addr],
            capture_output=True, text=True, timeout=6,
        )
        for line in r.stdout.splitlines():
            ls = line.strip()
            if ls.startswith(("Name:", "Alias:")) and not info["bt_name"]:
                info["bt_name"] = ls.split(":", 1)[1].strip()
            elif ls.startswith("Appearance:"):
                info["appearance"] = ls.split(":", 1)[1].strip()
    except Exception:
        pass
    return info


def _read_str(raw: bytes) -> str:
    try:
        return raw.decode("utf-8").strip("\x00").strip()
    except Exception:
        return raw.hex()


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class Module(ReconModule):

    info = ModuleInfo(
        name="BLE Target Enumeration",
        description="Connect to one BLE target and walk every service / characteristic / descriptor, mirage-style, with device identity header (manufacturer, chipset, LL version)",
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
        self.add_option(ModuleOption(
            name="capture_identity",
            required=False,
            description="Capture device identity header (manufacturer, chipset, LL version) from Device Information + system tools (true/false)",
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
        cap_ident = _coerce_bool(self.get_option("capture_identity"), default=True)

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

        # Build and display device identity header.
        if cap_ident:
            identity = self._capture_identity(target, topology)
            topology["identity"] = identity
            self._render_identity(identity)

        self._render_services_summary(topology["services"])
        for svc in topology["services"]:
            self._render_service_detail(svc)

        self._render_stats(topology["services"])
        if cap_ident:
            self._render_attack_surface(topology["services"])

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
        from bleak import BleakClient, BleakScanner

        # Pre-connect adv probe. Confirms the target is on the air and
        # seeds device_name + adv_addr_type from a live advertisement.
        # Caps at 5s so a missing target fails fast.
        pre: Dict[str, Any] = {"device_name": None, "adv_addr_type": None}
        try:
            adv_dev = await BleakScanner.find_device_by_address(
                target, timeout=5.0
            )
            if adv_dev is not None:
                pre["device_name"] = getattr(adv_dev, "name", None)
                details = getattr(adv_dev, "details", None) or {}
                if isinstance(details, dict):
                    props = details.get("props") or {}
                    pre["adv_addr_type"] = props.get("AddressType")
        except Exception:
            pass

        client_kwargs: Dict[str, Any] = {"timeout": timeout}
        if interface:
            client_kwargs["adapter"] = interface

        async with BleakClient(target, **client_kwargs) as client:
            if not client.is_connected:
                return None

            # Address type from the BlueZ backend (public / random / RPA).
            # Best-effort, private attribute; absence is not an error.
            addr_type: Optional[str] = pre.get("adv_addr_type")
            try:
                backend = getattr(client, "_backend", None)
                if backend is not None:
                    info = getattr(backend, "_device_info", None) or {}
                    if isinstance(info, dict):
                        addr_type = info.get("AddressType") or addr_type
            except Exception:
                pass

            services_view: List[Dict[str, Any]] = []
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
                "addr_type": addr_type,
                "adv_device_name": pre.get("device_name"),
            }

    # -- device identity capture --------------------------------------------

    def _capture_identity(
        self, target: str, topology: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build the device identity dict from GATT characteristic values
        already in `topology` (read during enumeration) plus system tools."""
        identity: Dict[str, Any] = {
            "bd_addr": target.upper(),
            "addr_type": topology.get("addr_type"),
            "device_name": topology.get("adv_device_name"),
            "manufacturer": None,
            "model": None, "serial": None,
            "firmware": None, "hardware": None,
            "software": None, "system_id": None,
            "pnp": None, "chipset": None,
            "ll_version": None, "ll_subver": None,
            "ll_manufacturer": None, "appearance": None,
        }

        # Pull values already captured during GATT walk.
        for svc in topology.get("services") or []:
            for char in svc.get("characteristics") or []:
                u16 = short_uuid(str(char.get("uuid", "")))
                if u16 is None:
                    continue
                key = _IDENTITY_CHARS.get(f"{u16:04x}")
                if not key:
                    continue
                hex_val = char.get("value_hex")
                if not hex_val:
                    continue
                try:
                    raw = bytes.fromhex(hex_val)
                except ValueError:
                    continue
                if key == "pnp_id_raw":
                    pnp = _decode_pnp_id(raw)
                    if pnp:
                        identity["pnp"] = pnp
                        identity["chipset"] = pnp.get("chipset")
                else:
                    identity[key] = _read_str(raw)

        # Supplement with system-tool data (best-effort).
        ll = _get_ll_info(target)
        if ll.get("bt_name") and not identity["device_name"]:
            identity["device_name"] = ll["bt_name"]
        if ll.get("lmp_version"):
            identity["ll_version"]      = ll["lmp_version"]
            identity["ll_subver"]       = ll.get("lmp_subver")
            identity["ll_manufacturer"] = ll.get("ll_manufacturer")
        if ll.get("chipset_exact") and not identity["chipset"]:
            identity["chipset"] = ll["chipset_exact"]
        if ll.get("appearance"):
            identity["appearance"] = ll["appearance"]

        # OUI / manufacturer-string chipset inference fallback.
        if not identity["chipset"]:
            identity["chipset"] = _infer_chipset(
                identity.get("manufacturer"), target
            )

        return identity

    # -- output -------------------------------------------------------------

    def _render_identity(self, identity: Dict[str, Any]) -> None:
        C = Colors
        print(f"\n  {C.BOLD}DEVICE IDENTITY{C.RESET}")
        print(f"  {C.CYAN}{'─' * 70}{C.RESET}")

        def row(label: str, value: Any, color: str = "") -> None:
            if value is None or value == "":
                return
            v = str(value)
            print(f"  {label:<16}: {color}{v}{C.RESET if color else ''}")

        row("BD_ADDR",      identity["bd_addr"],             C.WHITE)
        row("Address Type", identity.get("addr_type"))
        row("Device Name",  identity.get("device_name"),     C.GREEN)
        row("Appearance",   identity.get("appearance"))
        row("Manufacturer", identity.get("manufacturer"))
        row("Model",        identity.get("model"))
        row("Serial",       identity.get("serial"))
        row("Firmware",     identity.get("firmware"),         C.YELLOW)
        row("Hardware",     identity.get("hardware"))
        row("Software",     identity.get("software"))
        row("System ID",    identity.get("system_id"))

        pnp = identity.get("pnp")
        if pnp:
            row(
                "PnP ID",
                f"VID={pnp['vendor_id_source']} 0x{pnp['vendor_id']:04X} "
                f"({pnp['vendor_name']})  "
                f"PID=0x{pnp['product_id']:04X}  "
                f"Ver={pnp['version']}",
            )

        row("Chipset",      identity.get("chipset"),          C.CYAN)

        if identity.get("ll_version"):
            ver = identity["ll_version"]
            if identity.get("ll_subver"):
                ver += f"  (subver {identity['ll_subver']})"
            if identity.get("ll_manufacturer"):
                ver += f"  / {identity['ll_manufacturer']}"
            row("LL/LMP Ver",   ver,                          C.CYAN)

        print(f"  {C.CYAN}{'─' * 70}{C.RESET}\n")

    def _render_attack_surface(self, services: List[Dict[str, Any]]) -> None:
        """Print a short attack-surface summary: writable + notify chars."""
        writable, notifiable = [], []
        for svc in services:
            for c in svc.get("characteristics") or []:
                props = [p.lower() for p in c.get("properties") or []]
                if "write" in props or "write-without-response" in props:
                    writable.append(c)
                if "notify" in props or "indicate" in props:
                    notifiable.append(c)

        if not writable and not notifiable:
            return

        C = Colors
        if writable:
            print(f"\n  {C.YELLOW}WRITABLE ({len(writable)}):{C.RESET}")
            for c in writable:
                perm = ",".join(c.get("permissions") or [])
                uuid_label = c.get("uuid16") or _strip_uuid(c.get("uuid", ""))[:16]
                name = c.get("name") or "(vendor)"
                print(f"    {C.YELLOW}>{C.RESET} {uuid_label}  [{perm}]  {name}")

        if notifiable:
            print(f"\n  {C.MAGENTA}NOTIFY/INDICATE ({len(notifiable)}):{C.RESET}")
            for c in notifiable:
                uuid_label = c.get("uuid16") or _strip_uuid(c.get("uuid", ""))[:16]
                name = c.get("name") or "(vendor)"
                print(f"    {C.MAGENTA}>{C.RESET} {uuid_label}  {name}")

    def _render_stats(self, services: List[Dict[str, Any]]) -> None:
        """Print a one-line summary of totals after all service detail tables."""
        total_chars = readable = writable = notify = 0
        for svc in services:
            for c in svc.get("characteristics") or []:
                total_chars += 1
                props = [p.lower() for p in c.get("properties") or []]
                if "read" in props:
                    readable += 1
                if "write" in props or "write-without-response" in props:
                    writable += 1
                if "notify" in props or "indicate" in props:
                    notify += 1
        C = Colors
        print(
            f"\n  {C.CYAN}{'─' * 70}{C.RESET}\n"
            f"  Services: {len(services)}   "
            f"Characteristics: {total_chars}   "
            f"{C.GREEN}Readable: {readable}{C.RESET}   "
            f"{C.YELLOW}Writable: {writable}{C.RESET}   "
            f"{C.MAGENTA}Notify/Indicate: {notify}{C.RESET}"
        )

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
    s = short_uuid(uuid128)
    if s is None:
        return ""
    return f"0x{s:04x}"


def _strip_uuid(uuid128: str) -> str:
    return uuid128.replace("-", "").lower()


def _h(handle: Optional[int]) -> str:
    if handle is None:
        return ""
    return f"0x{handle:04x}"
