"""
BlueSploit Module: IoT Device Profile Audit

Classifies stored `gatt_topology` and `adv` fingerprints into known
IoT device categories (smart lock, wearable, beacon tracker, medical
sensor) by matching SIG service UUIDs + manufacturer-data prefixes.
For each match, prints a category note and a pointer to the right
class of attack module.

This is NOT a vulnerability finding generator. It is an inventory
classifier on top of the existing recon data. Severity is fixed at
'info' for every emission. Operators use this to decide which other
modules to run.

References
    Bluetooth Assigned Numbers, Service UUIDs
    Fitbit BLE protocol documentation (public)
    Apple Watch GATT services (public)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

from core.base import BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity
from core.ble_meta import short_uuid
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Service-UUID -> category mapping. Every short UUID here is in the
# SIG Assigned Numbers list, with the IoT category that uses it most
# often listed alongside. Vendor-specific 128-bit UUIDs are added
# separately below.
SIG_CATEGORY_HINTS = {
    # Smart locks rarely use a standard service UUID; they're vendor-
    # specific. We surface them via vendor-data prefix below.
    0x180D: "wearable / health (Heart Rate)",
    0x180F: "wearable / health (Battery)",
    0x1810: "medical (Blood Pressure)",
    0x1816: "wearable / fitness (Running Speed and Cadence)",
    0x1818: "wearable / fitness (Cycling Power)",
    0x1819: "wearable / fitness (Location and Navigation)",
    0x181A: "medical (Environmental Sensing)",
    0x181D: "wearable / fitness (Weight Scale)",
    0x181F: "medical (Continuous Glucose Monitoring)",
    0x1820: "medical (Internet Protocol Support)",
    0x1826: "wearable / fitness (Fitness Machine)",
    0x1812: "wearable / HID (HID over GATT)",
    0xFE2C: "wearable (Google Fast Pair)",
    0xFE9F: "wearable (Google Eddystone)",
}

# Vendor manufacturer-data prefixes. Sourced from the published
# Bluetooth SIG Company Identifier list plus public protocol RE
# documentation.
VENDOR_CATEGORY_HINTS = {
    "0x004C": "iOS / Apple device family",         # Apple
    "0x0006": "Microsoft Surface / Swift Pair",    # Microsoft
    "0x0075": "Samsung wearable / mobile",          # Samsung Electronics
    "0x010C": "Apple wearable (Watch family)",
    "0x0157": "Fitbit / Anhui Huami Information Technology",
    "0x00C4": "Garmin",
    "0x0E59": "JBL audio device",
    "0x0186": "BMW / automotive",
}

# Known smart-lock vendor 128-bit service prefixes (first 4 bytes of
# the UUID128 hex, lowercase). Each entry is sourced from a public
# vendor whitepaper or app store listing.
SMART_LOCK_SERVICE_PREFIXES = {
    "0000fd34": "Schlage Encode",
    "0000fcf6": "Yale Smart Lock",
    "00001523": "August Smart Lock (legacy GATT range)",
    "00007575": "Sesame / CANDY HOUSE",
}


@dataclass
class IoTFinding:
    target: str
    category: str
    evidence: str
    suggested_modules: List[str] = field(default_factory=list)


class Module(ScannerModule):

    info = ModuleInfo(
        name="IoT Device Profile Audit",
        description="Classify stored BLE devices into IoT categories (wearable, lock, medical, beacon) based on service UUIDs and manufacturer-data prefixes",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/assigned-numbers/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or host id. Default audits every host in the workspace.",
        ))

    def run(self) -> bool:
        try:
            from core.store import get_store
            store = get_store()
        except Exception as e:
            print_error(f"Store unavailable: {e}")
            return False

        target_arg = (self.get_option("target") or "").strip()
        if target_arg:
            host = self._resolve_target(store, target_arg)
            if host is None:
                print_error(f"No stored host matches {target_arg!r}")
                return False
            hosts = [host]
        else:
            hosts = store.list_hosts()
            if not hosts:
                print_info("No hosts in workspace. Run a recon module first.")
                return False

        all_findings: List[IoTFinding] = []
        for h in hosts:
            adv = store.latest_fingerprint(h, "adv")
            topo = store.latest_fingerprint(h, "gatt_topology")
            adv_d = json.loads(adv.data) if adv else None
            topo_d = json.loads(topo.data) if topo else None
            findings = classify(h.address, adv_d, topo_d)
            all_findings.extend(findings)

        self._render(all_findings)
        for f in all_findings:
            self.add_result({
                "host": f.target, "category": f.category,
                "evidence": f.evidence,
                "suggested_modules": f.suggested_modules,
            })
        if not all_findings:
            print_info(
                "No IoT categories matched. Either devices are not in "
                "our table or recon fingerprints are not present "
                "(run recon/ble_scan_full and recon/ble_target_enum)."
            )
        return True

    def _resolve_target(self, store, value: str):
        if _BD_ADDR_RE.match(value):
            return store.get_host(value)
        if value.isdigit():
            return store.get_host_by_id(int(value))
        q = value.lower()
        candidates = [
            h for h in store.list_hosts()
            if q in h.address.lower() or (h.name and q in h.name.lower())
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _render(self, findings: List[IoTFinding]) -> None:
        if not findings:
            return
        cols = [
            Column("Host",        style="cyan",    no_wrap=True),
            Column("Category",    style="green"),
            Column("Evidence",    style="dim"),
            Column("Suggested modules"),
        ]
        rows = [
            (f.target, f.category, f.evidence, ", ".join(f.suggested_modules))
            for f in findings
        ]
        render_table(
            cols, rows,
            title="IoT inventory",
            footer=total_footer("classification", len(findings)),
        )
        print_success(f"{len(findings)} classification(s) emitted")


def classify(
    target: str,
    adv: Dict[str, Any] | None,
    topology: Dict[str, Any] | None,
) -> List[IoTFinding]:
    """Run every classifier on whatever fingerprints exist for this host.

    Each emission is an info-level inventory item, never a vulnerability
    claim. The `suggested_modules` field points operators at the right
    follow-up.
    """
    out: List[IoTFinding] = []
    seen_categories: Set[str] = set()

    def _emit(category: str, evidence: str, modules: List[str]) -> None:
        if category in seen_categories:
            return
        seen_categories.add(category)
        out.append(IoTFinding(
            target=target,
            category=category,
            evidence=evidence,
            suggested_modules=modules,
        ))

    # --- SIG service-UUID match (from gatt_topology) ---------------------
    if topology:
        for svc in topology.get("services") or []:
            u16 = short_uuid(str(svc.get("uuid", "")))
            if u16 in SIG_CATEGORY_HINTS:
                _emit(
                    SIG_CATEGORY_HINTS[u16],
                    f"SIG service 0x{u16:04X}",
                    suggested_modules_for(u16),
                )

    # --- Smart-lock 128-bit service prefix ------------------------------
    if topology:
        for svc in topology.get("services") or []:
            uuid_hex = str(svc.get("uuid", "")).replace("-", "").lower()
            prefix = uuid_hex[:8]
            if prefix in SMART_LOCK_SERVICE_PREFIXES:
                _emit(
                    f"smart lock ({SMART_LOCK_SERVICE_PREFIXES[prefix]})",
                    f"vendor service prefix {prefix}",
                    ["exploits/ble_replay", "scanners/char_permission_audit"],
                )

    # --- Manufacturer-data vendor prefix (from adv) ---------------------
    if adv:
        for key in (adv.get("manufacturer_data") or {}).keys():
            for prefix, label in VENDOR_CATEGORY_HINTS.items():
                if prefix in key:
                    _emit(
                        label,
                        f"manufacturer key {key}",
                        suggested_modules_for_vendor(prefix),
                    )

    # --- iBeacon / Eddystone tracker detection --------------------------
    if adv:
        mfg = adv.get("manufacturer_data") or {}
        for key, hexed in mfg.items():
            if "0x004C" in key:
                try:
                    raw = bytes.fromhex(hexed)
                except (ValueError, TypeError):
                    continue
                if len(raw) >= 23 and raw[0] == 0x02 and raw[1] == 0x15:
                    _emit(
                        "beacon (iBeacon)",
                        "Apple manufacturer payload type 0x02/0x15",
                        ["exploits/ble_tracker_spoof"],
                    )

    # --- Apple FindMy adv -----------------------------------------------
    if adv:
        for key, hexed in (adv.get("manufacturer_data") or {}).items():
            if "0x004C" in key:
                try:
                    raw = bytes.fromhex(hexed)
                except (ValueError, TypeError):
                    continue
                if raw and raw[0] == 0x12:
                    _emit(
                        "tracker (Apple FindMy offline finding)",
                        "Apple Continuity sub-type 0x12",
                        ["scanners/adv_anomaly_audit"],
                    )

    return out


def suggested_modules_for(short_uuid_int: int) -> List[str]:
    """Suggest follow-up modules for a SIG service UUID match."""
    if short_uuid_int == 0x1812:
        return [
            "exploits/keystroke_injection_android_linux",
            "exploits/keystroke_injection_apple",
            "scanners/cve_match",
        ]
    if short_uuid_int in (0x1810, 0x181F, 0x181A, 0x180D):
        return [
            "modules/recon/ble_target_enum",
            "scanners/char_permission_audit",
        ]
    if short_uuid_int in (0x1816, 0x1818, 0x1819, 0x181D, 0x1826):
        return [
            "scanners/char_permission_audit",
            "post/ble_gatt_exfil",
        ]
    return ["scanners/char_permission_audit"]


def suggested_modules_for_vendor(prefix: str) -> List[str]:
    """Suggest follow-up modules for a vendor manufacturer-data hit."""
    if prefix == "0x004C":
        return [
            "scanners/adv_anomaly_audit",
            "auxiliary/crypto/irk_entropy",
        ]
    if prefix in ("0x0157", "0x00C4"):
        return [
            "scanners/char_permission_audit",
            "post/ble_gatt_exfil",
        ]
    return ["scanners/adv_anomaly_audit"]
