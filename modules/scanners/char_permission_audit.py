"""
GATT Characteristic Permission Audit - flags risky GATT property combos.

Ref: Bluetooth Assigned Numbers; Core Spec Vol 3 Part F 3.3.1
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity
from core.ble_meta import name_for_characteristic, short_uuid
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Characteristics whose value reveals a stable hardware identity.
# Reading them is normal, but exposing them under no-auth permission
# combined with a connectable advertiser turns them into stable
# fingerprints for passive tracking.
_IDENTITY_UUIDS = {
    0x2A23: "System ID",
    0x2A24: "Model Number String",
    0x2A25: "Serial Number String",
    0x2A29: "Manufacturer Name String",
    0x2A50: "PnP ID",
}

# Characteristics where a write should never be world-writable: writing
# to them either changes device identity or triggers a side effect
# (alarm, reset, time set) that should require authenticated bonding.
_SENSITIVE_WRITE_UUIDS = {
    0x2A00: "Device Name",
    0x2A06: "Alert Level",
    0x2A39: "Heart Rate Control Point",
    0x2A2B: "Current Time",
    0x2A16: "Time Update Control Point",
    0x2A40: "Ringer Control Point",
    0x2A55: "SC Control Point",
    0x2A52: "Record Access Control Point",
    0x2A66: "Cycling Power Control Point",
    0x2A6B: "LN Control Point",
    0x2A4C: "HID Control Point",
}

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class CharFinding:
    target: str
    rule_id: str
    title: str
    severity: str
    char_uuid: str
    char_name: str
    properties: List[str] = field(default_factory=list)
    rationale: str = ""
    reference: str = ""


class Module(ScannerModule):

    info = ModuleInfo(
        name="GATT Characteristic Permission Audit",
        description="Audit stored gatt_topology fingerprints for over-permissive GATT characteristics (writable Device Name, world-readable identity strings, unauthenticated control points)",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/assigned-numbers/",
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or stored host id. Default audits every host with a gatt_topology fingerprint.",
        ))
        self.add_option(ModuleOption(
            name="min_severity",
            required=False,
            description="Drop findings below this severity (info|low|medium|high|critical)",
            default="info",
        ))

    def run(self) -> bool:
        try:
            from core.store import get_store
            store = get_store()
        except Exception as e:
            print_error(f"Store unavailable: {e}")
            return False

        min_sev = (self.get_option("min_severity") or "info").lower()
        if min_sev not in _SEV_ORDER:
            print_warning(f"Unknown min_severity {min_sev!r}, defaulting to 'info'")
            min_sev = "info"

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
                print_info(
                    "No hosts in workspace. Run a recon module first "
                    "(e.g. recon/ble_target_enum)."
                )
                return False

        all_findings: List[CharFinding] = []
        missing: List[str] = []
        for h in hosts:
            fp = store.latest_fingerprint(h, "gatt_topology")
            if fp is None:
                missing.append(h.address)
                continue
            try:
                topology = json.loads(fp.data)
            except (json.JSONDecodeError, TypeError):
                print_warning(f"Corrupt gatt_topology for {h.address}, skipped")
                continue
            findings = evaluate_topology(h.address, topology)
            findings = [f for f in findings if _SEV_ORDER.get(f.severity, 0) >= _SEV_ORDER[min_sev]]
            all_findings.extend(findings)

        self._render(all_findings)
        self._print_gaps(missing, len(hosts))
        for f in all_findings:
            self.add_result({
                "host": f.target, "rule": f.rule_id, "title": f.title,
                "severity": f.severity, "char_uuid": f.char_uuid,
                "char_name": f.char_name, "properties": f.properties,
                "rationale": f.rationale, "reference": f.reference,
            })
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
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            print_warning(f"Ambiguous target {value!r}; candidates:")
            for h in candidates:
                print_warning(f"  [{h.id}] {h.address} {h.name or ''}")
        return None

    def _render(self, findings: List[CharFinding]) -> None:
        if not findings:
            print_info(
                "No characteristic permission issues surfaced against the "
                "gatt_topology fingerprints currently in the store."
            )
            return
        cols = [
            Column("Host",       style="cyan",    no_wrap=True),
            Column("Rule",       style="magenta", no_wrap=True),
            Column("UUID16",     style="yellow",  no_wrap=True),
            Column("Name"),
            Column("Properties", style="dim"),
            Column("Severity",   style="red",     no_wrap=True),
        ]
        rows = [
            (f.target, f.rule_id, f.char_uuid, f.char_name,
             ",".join(f.properties), f.severity)
            for f in findings
        ]
        render_table(
            cols, rows,
            title="GATT characteristic audit",
            footer=total_footer("finding", len(findings)),
        )
        print()
        for f in findings:
            print(f"  [{f.rule_id}] {f.target} {f.char_name} ({f.char_uuid}): {f.rationale}")
            print(f"    reference: {f.reference}")
            print()
        print_success(f"{len(findings)} finding(s) emitted")

    def _print_gaps(self, missing: List[str], total: int) -> None:
        if not missing:
            return
        print_info(
            f"Missing gatt_topology fingerprint for {len(missing)} of "
            f"{total} host(s). Run `recon/ble_target_enum` against them."
        )


def evaluate_topology(target: str, topology: Dict[str, Any]) -> List[CharFinding]:
    """Walk every characteristic in `topology` and apply the rules.

    Topology shape mirrors what recon/ble_target_enum writes:
        services: [{uuid, characteristics: [{uuid, properties: [...], ...}]}]
    """
    out: List[CharFinding] = []
    for svc in topology.get("services") or []:
        for char in svc.get("characteristics") or []:
            uuid128 = str(char.get("uuid", ""))
            props = [p.lower() for p in char.get("properties") or []]
            u16 = short_uuid(uuid128)
            char_name = name_for_characteristic(uuid128) or uuid128
            uuid_label = f"0x{u16:04X}" if u16 is not None else uuid128[:8]

            # Rule 1: Device Name writable. Allows passive trackers to
            # rename the peripheral and break user UX or impersonate.
            if u16 == 0x2A00 and ("write" in props or "write-without-response" in props):
                out.append(CharFinding(
                    target=target, rule_id="BSA-CHAR-001",
                    title="Device Name characteristic is writable",
                    severity="medium",
                    char_uuid=uuid_label, char_name=char_name, properties=props,
                    rationale=(
                        "The standard Device Name (0x2A00) is advertising "
                        "metadata; a writable Device Name lets any peer "
                        "rename the device, defeating user-visible pairing "
                        "checks and aiding impersonation."
                    ),
                    reference="Assigned Numbers 0x2A00; Core Spec Vol 3 Part C 12.1",
                ))

            # Rule 2: Identity strings writable. System ID, Serial,
            # Model, Manufacturer, PnP ID are read-only by spec.
            if u16 in _IDENTITY_UUIDS and any(p in props for p in ("write", "write-without-response", "authenticated-signed-writes")):
                out.append(CharFinding(
                    target=target, rule_id="BSA-CHAR-002",
                    title=f"Identity characteristic {_IDENTITY_UUIDS[u16]} is writable",
                    severity="high",
                    char_uuid=uuid_label, char_name=char_name, properties=props,
                    rationale=(
                        f"{_IDENTITY_UUIDS[u16]} is defined by the SIG as a "
                        "read-only identity attribute. Allowing writes "
                        "permits trivial impersonation of the device's "
                        "advertised identity in fleet or attestation flows."
                    ),
                    reference=f"Assigned Numbers 0x{u16:04X}",
                ))

            # Rule 3: Sensitive control point with write-without-response
            # exposed. Control points should require Write Request (so
            # the peer ACKs and authorisation can be enforced); Write
            # Command sidesteps that and is unauthenticated by design.
            if u16 in _SENSITIVE_WRITE_UUIDS and "write-without-response" in props:
                out.append(CharFinding(
                    target=target, rule_id="BSA-CHAR-003",
                    title=f"{_SENSITIVE_WRITE_UUIDS[u16]} accepts Write Without Response",
                    severity="high",
                    char_uuid=uuid_label, char_name=char_name, properties=props,
                    rationale=(
                        "Control-point characteristics should expose only "
                        "Write (ATT Write Request) so the peer's stack can "
                        "ACK and apply authorisation. Write Without Response "
                        "is unconfirmed and lets an unauthenticated peer "
                        "issue control commands silently."
                    ),
                    reference="Core Spec Vol 3 Part F 3.4.5",
                ))

            # Rule 4: Notify or Indicate WITHOUT a CCCD. Without a
            # Client Characteristic Configuration Descriptor (0x2902),
            # subscribers cannot be tracked, and the spec says these
            # properties REQUIRE a CCCD.
            if ("notify" in props or "indicate" in props):
                has_cccd = any(
                    short_uuid(str(d.get("uuid", ""))) == 0x2902
                    for d in char.get("descriptors") or []
                )
                if not has_cccd:
                    out.append(CharFinding(
                        target=target, rule_id="BSA-CHAR-004",
                        title="Notify/Indicate characteristic missing CCCD",
                        severity="low",
                        char_uuid=uuid_label, char_name=char_name, properties=props,
                        rationale=(
                            "Notify and Indicate require a Client "
                            "Characteristic Configuration Descriptor "
                            "(0x2902) for subscribers to manage delivery. "
                            "Missing CCCD violates the spec and prevents "
                            "operators from disabling unwanted streams."
                        ),
                        reference="Core Spec Vol 3 Part G 3.3.1.4",
                    ))

            # Rule 5: HID Report Map readable without auth context. The
            # standard HID-over-GATT flow requires the peer to be
            # bonded; a read-only Report Map without bonding lets any
            # scanner profile the device input surface.
            # We can only assert "readable", not "bonding-required",
            # from the topology, so this is info severity.
            if u16 == 0x2A4B and "read" in props:
                out.append(CharFinding(
                    target=target, rule_id="BSA-CHAR-005",
                    title="HID Report Map readable",
                    severity="info",
                    char_uuid=uuid_label, char_name=char_name, properties=props,
                    rationale=(
                        "HID Report Map (0x2A4B) is readable. The HOGP "
                        "profile requires bonding before exposing this; "
                        "the fingerprint cannot confirm bonding state, so "
                        "this is informational. Verify with a real read "
                        "attempt as an unbonded peer."
                    ),
                    reference="HID over GATT Profile 1.0 section 5.2",
                ))

    return out
