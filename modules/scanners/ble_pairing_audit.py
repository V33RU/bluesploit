"""
BLE Pairing Audit - SMP pairing-feature fingerprint analyzer.

CVE: CVE-2019-9506 (KNOB), CVE-2020-15802 (BLURtooth)
Ref: https://nvd.nist.gov/vuln/detail/CVE-2019-9506
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.base import BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# SMP key distribution bit positions (Core Spec Vol 3 Part H 3.6.1).
_KD_ENC_KEY = 0x01
_KD_ID_KEY  = 0x02
_KD_SIGN    = 0x04
_KD_LINK    = 0x08

# AuthReq bits (Core Spec Vol 3 Part H 3.5.1).
_AR_BONDING  = 0x01
_AR_MITM     = 0x04
_AR_SC       = 0x08
_AR_KEYPRESS = 0x10
_AR_CT2      = 0x20

_CONF_ORDER = {"low": 0, "medium": 1, "high": 2}
_SEV_ORDER  = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AuditFinding:
    target: str
    rule_id: str
    title: str
    severity: str
    confidence: str
    rationale: str
    reference: str
    matched: Dict[str, Any] = field(default_factory=dict)


class Module(ScannerModule):

    info = ModuleInfo(
        name="BLE Pairing Audit",
        description="Audit stored SMP pairing-feature fingerprints for JustWorks, legacy pairing, key-size downgrade, and CTKD weaknesses",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
            "https://www.usenix.org/conference/woot13/workshop-program/presentation/ryan",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-9506",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-15802",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or stored host id. Default audits every host in the workspace.",
        ))
        self.add_option(ModuleOption(
            name="min_severity",
            required=False,
            description="Drop findings below this severity (info|low|medium|high|critical)",
            default="info",
        ))
        self.add_option(ModuleOption(
            name="min_confidence",
            required=False,
            description="Drop findings below this confidence (low|medium|high)",
            default="low",
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
        min_conf = (self.get_option("min_confidence") or "low").lower()
        if min_conf not in _CONF_ORDER:
            print_warning(f"Unknown min_confidence {min_conf!r}, defaulting to 'low'")
            min_conf = "low"

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
                    "(e.g. recon/discovery, recon/ble_pairing_features)."
                )
                return False

        all_findings: List[AuditFinding] = []
        missing: List[str] = []
        for h in hosts:
            fp = store.latest_fingerprint(h, "smp_pairing")
            if fp is None:
                missing.append(h.address)
                continue
            try:
                data = json.loads(fp.data)
            except (json.JSONDecodeError, TypeError):
                print_warning(f"Corrupt smp_pairing fingerprint for {h.address}, skipped")
                continue
            findings = evaluate_pairing_features(h.address, data)
            findings = _filter(findings, min_sev=min_sev, min_conf=min_conf)
            all_findings.extend(findings)

        self._render(all_findings)
        self._print_gaps(missing, len(hosts))
        for f in all_findings:
            self.add_result({
                "host": f.target, "rule": f.rule_id, "title": f.title,
                "severity": f.severity, "confidence": f.confidence,
                "rationale": f.rationale, "reference": f.reference,
                "matched": f.matched,
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

    def _render(self, findings: List[AuditFinding]) -> None:
        if not findings:
            print_info(
                "No pairing weaknesses surfaced against the smp_pairing "
                "fingerprints currently in the store."
            )
            return
        cols = [
            Column("Host",       style="cyan",    no_wrap=True),
            Column("Rule",       style="magenta", no_wrap=True),
            Column("Title"),
            Column("Severity",   style="red",     no_wrap=True),
            Column("Confidence", style="yellow",  no_wrap=True),
        ]
        rows = [
            (f.target, f.rule_id, f.title, f.severity, f.confidence)
            for f in findings
        ]
        render_table(
            cols, rows,
            title="BLE pairing audit",
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
            f"Missing smp_pairing fingerprint for {len(missing)} of "
            f"{total} host(s). Run `recon/ble_pairing_features` against "
            f"them and re-run this audit."
        )


# Rule engine ----------------------------------------------------------------


def evaluate_pairing_features(target: str, data: Dict[str, Any]) -> List[AuditFinding]:
    """Apply every audit rule to one smp_pairing fingerprint dict.

    The dict shape is defined by `modules/recon/ble_pairing_features.py`:
        io_capability: str
        oob: bool
        auth_req: '0xNN' (hex)
        bonding, mitm, sc, keypress, ct2: bool
        max_key_size: int (bytes, 7..16 per spec)
        init_key_dist, resp_key_dist: '0xNN' (hex bitmap)
    """
    findings: List[AuditFinding] = []
    mitm = bool(data.get("mitm"))
    sc   = bool(data.get("sc"))
    oob  = bool(data.get("oob"))
    ct2  = bool(data.get("ct2"))
    bonding = bool(data.get("bonding"))
    max_key = data.get("max_key_size")
    init_kd = _parse_hex(data.get("init_key_dist"))
    resp_kd = _parse_hex(data.get("resp_key_dist"))

    # Rule 1: JustWorks (no MITM, no OOB). Confidence high if also no SC
    # (legacy unauthenticated), medium with SC (passive sniffing still
    # mitigated by the SC ECDH, but MITM is wide open during pairing).
    if not mitm and not oob:
        if not sc:
            findings.append(AuditFinding(
                target=target,
                rule_id="BSA-PAIR-001",
                title="JustWorks Legacy Pairing (no MITM, no OOB, no SC)",
                severity="high",
                confidence="high",
                rationale=(
                    "Peer's Pairing Response advertises no MITM protection, "
                    "no OOB material, and no Secure Connections support. The "
                    "session falls back to Legacy JustWorks, which Core Spec "
                    "Vol 3 Part H 2.3.5.1 explicitly states provides no "
                    "protection against an active man-in-the-middle. Passive "
                    "sniffing during pairing also recovers the LTK (Mike "
                    "Ryan, USENIX WOOT 2013)."
                ),
                reference="Core Spec Vol 3 Part H 2.3.5.1; Ryan, USENIX WOOT 2013",
                matched={"mitm": mitm, "oob": oob, "sc": sc},
            ))
        else:
            findings.append(AuditFinding(
                target=target,
                rule_id="BSA-PAIR-002",
                title="JustWorks under Secure Connections (no MITM, no OOB)",
                severity="medium",
                confidence="high",
                rationale=(
                    "Peer advertises Secure Connections but neither MITM "
                    "protection nor OOB. The ECDH exchange blocks passive "
                    "sniffing of the LTK, however no authentication method "
                    "is enforced, so an active MITM during pairing succeeds "
                    "by impersonating either side."
                ),
                reference="Core Spec Vol 3 Part H 2.3.5.1, 2.3.5.6.5",
                matched={"mitm": mitm, "oob": oob, "sc": sc},
            ))

    # Rule 2: Legacy pairing accepted at all (no SC). Even with MITM
    # claimed, Legacy SMP key exchange is recoverable from a passive
    # capture (crackle). This finding is independent of Rule 1.
    if not sc:
        findings.append(AuditFinding(
            target=target,
            rule_id="BSA-PAIR-003",
            title="Legacy Pairing accepted (LE Secure Connections not required)",
            severity="medium",
            confidence="high",
            rationale=(
                "Pairing Response does not set the SC bit in AuthReq, so "
                "the peer will accept LE Legacy Pairing. The Legacy STK / "
                "LTK exchange is recoverable from a passive sniff of the "
                "pairing phase (crackle). Recommendation: require SC and "
                "reject Legacy at the controller / GATT layer."
            ),
            reference="Core Spec Vol 3 Part H 2.3.6; Ryan, USENIX WOOT 2013",
            matched={"sc": sc},
        ))

    # Rule 3: max_key_size < 16 bytes. KNOB-style entropy downgrade is
    # specified for BR/EDR (CVE-2019-9506) but the same negotiation is
    # present in BLE SMP; a peer accepting 7-byte keys is a configuration
    # weakness regardless.
    if isinstance(max_key, int) and 7 <= max_key < 16:
        findings.append(AuditFinding(
            target=target,
            rule_id="BSA-PAIR-004",
            title=f"Encryption key size capped at {max_key} bytes",
            severity="high" if max_key <= 10 else "medium",
            confidence="high",
            rationale=(
                "Pairing Response advertises a Maximum Encryption Key Size "
                f"of {max_key} bytes. The spec allows 7..16; anything below "
                "16 reduces the effective entropy of the per-link key. "
                "An attacker negotiating the smallest mutual value lands "
                "at this ceiling. Same negotiation primitive that KNOB "
                "(CVE-2019-9506) abuses on BR/EDR."
            ),
            reference="Core Spec Vol 3 Part H 2.3.4; CVE-2019-9506",
            matched={"max_key_size": max_key},
        ))

    # Rule 4: CSRK distributed without MITM. Signed writes verified with
    # a CSRK established under JustWorks inherit JustWorks' lack of
    # authentication. Practical relevance: many vendors enable signed
    # writes on sensitive characteristics under the assumption pairing
    # was authenticated.
    distributes_csrk = bool((init_kd & _KD_SIGN) or (resp_kd & _KD_SIGN))
    if distributes_csrk and not mitm:
        findings.append(AuditFinding(
            target=target,
            rule_id="BSA-PAIR-005",
            title="CSRK distributed under an unauthenticated pairing",
            severity="medium",
            confidence="medium",
            rationale=(
                "Key Distribution flags include CSRK (Sign) but the pairing "
                "method does not require MITM protection. Any signed-write "
                "characteristic the peer exposes will be writable by an "
                "attacker who completed pairing as a MITM. Confidence is "
                "medium because the relevance depends on which "
                "characteristics actually accept signed writes."
            ),
            reference="Core Spec Vol 3 Part H 2.4.2.4, 3.6.1",
            matched={
                "mitm": mitm,
                "init_key_dist": data.get("init_key_dist"),
                "resp_key_dist": data.get("resp_key_dist"),
            },
        ))

    # Rule 5: CT2 (CTKD) set without SC. Cross-transport key derivation
    # from a Legacy-pairing LTK is the BLURtooth surface
    # (CVE-2020-15802): a weak LE pairing key gets promoted to a
    # BR/EDR link key.
    if ct2 and not sc:
        findings.append(AuditFinding(
            target=target,
            rule_id="BSA-PAIR-006",
            title="CT2 set without Secure Connections (BLURtooth surface)",
            severity="high",
            confidence="high",
            rationale=(
                "AuthReq advertises CT2 (cross-transport key derivation) "
                "but Secure Connections is not set. A weak LE Legacy LTK "
                "would be derived into a BR/EDR link key, which is the "
                "configuration BLURtooth (CVE-2020-15802) exploits."
            ),
            reference="Core Spec Vol 3 Part H 2.3.5.7; CVE-2020-15802",
            matched={"ct2": ct2, "sc": sc},
        ))

    # Rule 6: Bonding without MITM. The peer will persist an
    # unauthenticated LTK and reuse it on every reconnect. Informational
    # because the underlying weakness is captured by Rule 1 or 2; this
    # finding exists so the report explicitly calls out persistence.
    if bonding and not mitm:
        findings.append(AuditFinding(
            target=target,
            rule_id="BSA-PAIR-007",
            title="Bonding requested under unauthenticated pairing",
            severity="low",
            confidence="high",
            rationale=(
                "AuthReq sets Bonding without MITM, so the unauthenticated "
                "LTK is persisted and reused on every reconnect. A single "
                "successful MITM during the initial pairing yields a stable "
                "long-term foothold."
            ),
            reference="Core Spec Vol 3 Part H 2.3.5.1, 2.4.2",
            matched={"bonding": bonding, "mitm": mitm},
        ))

    return findings


# Helpers --------------------------------------------------------------------


def _parse_hex(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16)
        except ValueError:
            return 0
    return 0


def _filter(
    findings: List[AuditFinding],
    min_sev: str,
    min_conf: str,
) -> List[AuditFinding]:
    sev_floor = _SEV_ORDER.get(min_sev, 0)
    conf_floor = _CONF_ORDER.get(min_conf, 0)
    return [
        f for f in findings
        if _SEV_ORDER.get(f.severity, 0) >= sev_floor
        and _CONF_ORDER.get(f.confidence, 0) >= conf_floor
    ]
