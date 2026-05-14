"""
BlueSploit Module: BLE Link-Layer Features Audit

Reads `ll_features` fingerprints written by `recon/ll_features` and
surfaces the BLE 5.x capability profile of each peer plus security-
relevant gaps. Every rule cites the Bluetooth Core Spec section.

Pure consumer of the engagement store. No HCI, no scanning.

References
    Bluetooth Core Spec v5.4 Vol 6 Part B section 4.6 (LL Feature Set)
    Bluetooth Core Spec v5.4 Vol 6 Part B section 6 (Privacy)
    Erratum 11838 (key size negotiation, BLE side)
    CVE-2018-5383 (Invalid Curve Attack on LE Secure Connections)
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


@dataclass
class LLFinding:
    target: str
    rule_id: str
    title: str
    severity: str
    rationale: str
    reference: str
    matched: Dict[str, Any] = field(default_factory=dict)


class Module(ScannerModule):

    info = ModuleInfo(
        name="BLE LL Features Audit",
        description="Audit stored ll_features fingerprints for privacy gaps and BLE 5.x capability profiling (Periodic Adv, CIS, Power Control, Coded PHY)",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or host id. Default audits every host with an ll_features fingerprint.",
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
                print_info("No hosts in workspace. Run `recon/ll_features` first.")
                return False

        all_findings: List[LLFinding] = []
        missing: List[str] = []
        for h in hosts:
            fp = store.latest_fingerprint(h, "ll_features")
            if fp is None:
                missing.append(h.address)
                continue
            try:
                data = json.loads(fp.data)
            except (json.JSONDecodeError, TypeError):
                print_warning(f"Corrupt ll_features for {h.address}, skipped")
                continue
            findings = evaluate_ll_features(h.address, data)
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

    def _render(self, findings: List[LLFinding]) -> None:
        if not findings:
            print_info(
                "No LL-feature findings against the stored ll_features "
                "fingerprints. Targets either expose a complete 5.x "
                "feature set or have no profiled gaps."
            )
            return
        cols = [
            Column("Host",     style="cyan",    no_wrap=True),
            Column("Rule",     style="magenta", no_wrap=True),
            Column("Title"),
            Column("Severity", style="red",     no_wrap=True),
        ]
        rows = [(f.target, f.rule_id, f.title, f.severity) for f in findings]
        render_table(
            cols, rows,
            title="BLE LL features audit",
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
            f"Missing ll_features fingerprint for {len(missing)} of "
            f"{total} host(s). Run `recon/ll_features` against them."
        )


def evaluate_ll_features(target: str, data: Dict[str, Any]) -> List[LLFinding]:
    """Apply every rule to one ll_features fingerprint dict.

    The dict shape is defined by `modules/recon/ll_features.py`:
        ll_features_bits: dict[str, bool]    (named feature -> on/off)
        ll_features_hex:  str                (8-byte FeatureSet hex)
    """
    out: List[LLFinding] = []
    bits = dict(data.get("ll_features_bits") or {})

    def has(name: str) -> bool:
        return bool(bits.get(name, False))

    # Rule BSA-LL-001: LL Privacy not advertised. Without LL Privacy the
    # controller cannot use Resolvable Private Addresses; tracking
    # surface increases.
    if not has("LL Privacy"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-001",
            title="Controller does not advertise LL Privacy",
            severity="medium",
            rationale=(
                "LL Privacy controls how the controller handles "
                "Resolvable Private Addresses. Without it, the host must "
                "do address resolution which is slower and often skipped, "
                "exposing the peer to passive tracking via the random "
                "advertising address."
            ),
            reference="Core Spec Vol 6 Part B 6.4 (LL Privacy)",
            matched={"LL Privacy": False},
        ))

    # Rule BSA-LL-002: LE Data Packet Length Extension absent. Affects
    # throughput but also exposes some older controllers to L2CAP-edge
    # bugs (referenced by SweynTooth advisories).
    if not has("LE Data Packet Length Extension"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-002",
            title="LE Data Packet Length Extension absent",
            severity="info",
            rationale=(
                "DLE was introduced in BLE 4.2. Its absence indicates a "
                "controller predating 2014, which usually also lacks "
                "later security fixes. Informational by itself; combine "
                "with version capture (recon/lmp_features) for context."
            ),
            reference="Core Spec Vol 6 Part B 5.1.9 (DLE)",
        ))

    # Rule BSA-LL-003: Encryption support absent.
    if not has("LE Encryption"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-003",
            title="LE Encryption not supported",
            severity="high",
            rationale=(
                "Peer's FeatureSet does not advertise LE Encryption. "
                "Any session with this peer cannot be encrypted at the "
                "link layer; all GATT traffic is in the clear. Standard "
                "BLE 4.0+ peripherals always support this."
            ),
            reference="Core Spec Vol 6 Part B 4.6.1",
            matched={"LE Encryption": False},
        ))

    # Rule BSA-LL-004: Remote Public Key Validation absent. Mandatory
    # since the CVE-2018-5383 fix; controllers without this bit are
    # candidates for the Invalid Curve attack on LE Secure Connections.
    if not has("Remote Public Key Validation"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-004",
            title="Remote Public Key Validation not advertised",
            severity="medium",
            rationale=(
                "The LL FeatureSet bit for Remote Public Key Validation "
                "is unset. This bit was introduced after CVE-2018-5383 "
                "(Invalid Curve attack on LE Secure Connections). "
                "Absence does not prove vulnerability (many vendors "
                "patched without exposing the bit) but the peer should "
                "be cross-checked with scanners/ble_pairing_audit and "
                "scanners/cve_match."
            ),
            reference="Core Spec Vol 6 Part B 4.6 (bit 31); CVE-2018-5383",
            matched={"Remote Public Key Validation": False},
        ))

    # Capability profiling (info severity, no severity inflation).

    # Periodic Advertising present -> attack-surface flag for the
    # Periodic Advertising sync attack family (PAST abuse).
    if has("LE Periodic Advertising"):
        sources = []
        if has("Periodic Advertising Sync Transfer Sender"):
            sources.append("PAST Sender")
        if has("Periodic Advertising Sync Transfer Recipient"):
            sources.append("PAST Recipient")
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-CAP-001",
            title="Periodic Advertising supported",
            severity="info",
            rationale=(
                "Peer supports LE Periodic Advertising. "
                f"{'/'.join(sources) if sources else 'no PAST roles'}. "
                "Relevant attack surface: PAST sync spoof, broadcast "
                "isochronous channel reception. Recon only."
            ),
            reference="Core Spec Vol 6 Part B 4.4.3.10",
            matched={"PAST": sources},
        ))

    # Connected Isochronous Streams (BLE 5.2+)
    if has("Connected Isochronous Stream Master") or has("Connected Isochronous Stream Slave"):
        roles = [r for r in ("Connected Isochronous Stream Master",
                             "Connected Isochronous Stream Slave") if has(r)]
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-CAP-002",
            title="Connected Isochronous Streams (CIS) supported",
            severity="info",
            rationale=(
                "Peer supports CIS (BLE Audio / Auracast). Surface "
                "relevant to CIS sniff and ISO channel attacks. "
                f"Roles: {', '.join(roles)}."
            ),
            reference="Core Spec Vol 6 Part B 4.5.13",
            matched={"roles": roles},
        ))

    # LE Power Control (BLE 5.2)
    if has("LE Power Control Request") or has("LE Power Change Indication"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-CAP-003",
            title="LE Power Control supported",
            severity="info",
            rationale=(
                "Peer supports LE Power Control Request / Change "
                "Indication (BLE 5.2). Relevant to the LE Power Control "
                "hijack surface, where an attacker forces a target to "
                "transmit louder, easing sniffing range."
            ),
            reference="Core Spec Vol 6 Part B 5.1.17",
        ))

    # Connection Subrating (BLE 5.3)
    if has("Connection Subrating"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-CAP-004",
            title="Connection Subrating supported",
            severity="info",
            rationale=(
                "Peer supports Connection Subrating (BLE 5.3). "
                "Relevant for power-management bypass and supervision-"
                "timeout manipulation."
            ),
            reference="Core Spec Vol 6 Part B 5.1.19",
        ))

    # LE Coded PHY (long range)
    if has("LE Coded PHY"):
        out.append(LLFinding(
            target=target, rule_id="BSA-LL-CAP-005",
            title="LE Coded PHY (long-range) supported",
            severity="info",
            rationale=(
                "Peer supports LE Coded PHY. Extends BLE range up to "
                "~1km, which expands the MITM and tracking surface "
                "geographically. Pair with scanners/adv_anomaly_audit."
            ),
            reference="Core Spec Vol 6 Part B 4.6 (bit 11)",
        ))

    return out
