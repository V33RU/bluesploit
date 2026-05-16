"""
Mesh Provisioning Audit - OOB / URI hash / IV-update auditor.

Ref: Mesh Profile v1.1 3.10.2 (Unprovisioned Beacon), 5.4 (Provisioning Auth)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List

from core.base import BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# OOB methods that are "weak" by Mesh Profile 5.4.2.4: Output, Number,
# and String allow a passive attacker who observes the screen / hears
# the prompt to recover the auth value.
_WEAK_OOB_BITS = {1, 5, 6}     # Electronic-URI, Number, String


@dataclass
class MeshFinding:
    target: str
    rule_id: str
    title: str
    severity: str
    rationale: str
    reference: str
    matched: Dict[str, Any] = field(default_factory=dict)


class Module(ScannerModule):

    info = ModuleInfo(
        name="Mesh Provisioning Audit",
        description="Audit stored mesh_beacon fingerprints for weak OOB configurations and missing URI integrity",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/mesh-protocol/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or host id. Default audits every host with a mesh_beacon fingerprint.",
        ))
        self.add_option(ModuleOption(
            name="min_severity",
            required=False,
            description="Drop findings below this severity",
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
                    "No hosts in workspace. Run `recon/mesh_beacon_scan` first."
                )
                return False

        all_findings: List[MeshFinding] = []
        missing: List[str] = []
        for h in hosts:
            fp = store.latest_fingerprint(h, "mesh_beacon")
            if fp is None:
                missing.append(h.address)
                continue
            try:
                beacon = json.loads(fp.data)
            except (json.JSONDecodeError, TypeError):
                print_warning(f"Corrupt mesh_beacon for {h.address}, skipped")
                continue
            findings = evaluate_beacon(h.address, beacon)
            findings = [f for f in findings if _SEV_ORDER.get(f.severity, 0) >= _SEV_ORDER[min_sev]]
            all_findings.extend(findings)

        self._render(all_findings)
        self._print_gaps(missing, len(hosts))
        for f in all_findings:
            self.add_result({
                "host": f.target, "rule": f.rule_id, "title": f.title,
                "severity": f.severity, "rationale": f.rationale,
                "reference": f.reference, "matched": f.matched,
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
        return candidates[0] if len(candidates) == 1 else None

    def _render(self, findings: List[MeshFinding]) -> None:
        if not findings:
            print_info(
                "No provisioning weaknesses surfaced against the "
                "mesh_beacon fingerprints currently in the store."
            )
            return
        cols = [
            Column("Host",     style="cyan",    no_wrap=True),
            Column("Rule",     style="magenta", no_wrap=True),
            Column("Title"),
            Column("Severity", style="red",     no_wrap=True),
        ]
        rows = [
            (f.target, f.rule_id, f.title, f.severity)
            for f in findings
        ]
        render_table(
            cols, rows,
            title="Mesh provisioning audit",
            footer=total_footer("finding", len(findings)),
        )
        print()
        for f in findings:
            print(f"  [{f.rule_id}] {f.target}: {f.rationale}")
            print(f"    reference: {f.reference}")
            if f.matched:
                pairs = ", ".join(f"{k}={v!r}" for k, v in f.matched.items())
                print(f"    matched: {pairs}")
            print()
        print_success(f"{len(findings)} finding(s) emitted")

    def _print_gaps(self, missing: List[str], total: int) -> None:
        if not missing:
            return
        print_info(
            f"Missing mesh_beacon fingerprint for {len(missing)} of "
            f"{total} host(s). Run `recon/mesh_beacon_scan` against them."
        )


def evaluate_beacon(target: str, beacon: Dict[str, Any]) -> List[MeshFinding]:
    out: List[MeshFinding] = []
    kind = beacon.get("kind")

    if kind == "unprovisioned":
        bitmap_str = beacon.get("oob_info_bitmap", "0x0000")
        try:
            bitmap = int(bitmap_str, 16) if isinstance(bitmap_str, str) else int(bitmap_str)
        except ValueError:
            bitmap = 0
        labels = beacon.get("oob_info_labels") or []

        # Rule MSH-PROV-001: no OOB advertised. Provisioner has no out-of-
        # band channel and must accept No-OOB or Output-OOB only, which
        # collapses to Number/String authentication, easily observed.
        if bitmap == 0:
            out.append(MeshFinding(
                target=target, rule_id="MSH-PROV-001",
                title="No OOB information advertised",
                severity="high",
                rationale=(
                    "The unprovisioned beacon advertises no OOB methods. "
                    "Provisioner must fall back to No-OOB or Output-OOB "
                    "authentication, both observable by a passive attacker "
                    "within radio range during the provisioning ceremony."
                ),
                reference="Mesh Profile 3.10.2.1, 5.4.2.4",
                matched={"oob_info_bitmap": bitmap_str},
            ))

        # Rule MSH-PROV-002: only weak OOB methods.
        bits_set = {b for b in range(16) if bitmap & (1 << b)}
        if bits_set and bits_set.issubset(_WEAK_OOB_BITS):
            out.append(MeshFinding(
                target=target, rule_id="MSH-PROV-002",
                title="Only weak OOB methods advertised",
                severity="medium",
                rationale=(
                    "Advertised OOB methods are limited to "
                    f"{sorted(labels)}, all of which are visible to a "
                    "passive observer (screen / spoken / printed). Static "
                    "OOB (NFC, 2D code) is stronger."
                ),
                reference="Mesh Profile 5.4.2.4",
                matched={"oob_info_labels": labels},
            ))

        # Rule MSH-PROV-003: URI Hash missing. The beacon optionally
        # carries a 4-byte hash of the URI it points at; without it
        # an attacker can substitute the URI.
        if "uri_hash" not in beacon:
            out.append(MeshFinding(
                target=target, rule_id="MSH-PROV-003",
                title="URI Hash field absent",
                severity="low",
                rationale=(
                    "Unprovisioned beacon does not include the optional "
                    "URI Hash (4-byte truncated AES-CMAC). If the device "
                    "documentation expects an out-of-band URI for OOB "
                    "data fetch, there is no integrity check binding the "
                    "beacon to that URI."
                ),
                reference="Mesh Profile 3.10.2.4",
            ))

    elif kind == "secure_network":
        # Informational findings about the network state observable from
        # the beacon's flags byte (Mesh Profile 3.10.3.1).
        if beacon.get("key_refresh"):
            out.append(MeshFinding(
                target=target, rule_id="MSH-NET-001",
                title="Network is in Key Refresh phase",
                severity="info",
                rationale=(
                    "Secure Network Beacon flags advertise a key refresh "
                    "in progress. Operationally relevant for an audit; "
                    "not a vulnerability by itself."
                ),
                reference="Mesh Profile 3.10.3.1",
            ))
        if beacon.get("iv_update"):
            out.append(MeshFinding(
                target=target, rule_id="MSH-NET-002",
                title="Network is in IV Update phase",
                severity="info",
                rationale=(
                    "Secure Network Beacon flags advertise an IV index "
                    "update. The Mesh Profile rate-limits IV updates to "
                    "once per 96 hours; rapid toggling would be suspicious."
                ),
                reference="Mesh Profile 3.10.5",
            ))

    return out
