"""
BLE Advertising Anomaly Audit - tracking-surface analyzer.

Ref: Core Spec Vol 3 Part C 11; Apple Continuity (Heinze et al. 2019);
     Eddystone (github.com/google/eddystone)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Apple Continuity (manufacturer 0x004C) sub-types that are well known
# to leak handoff / nearby / AirDrop activity.
_APPLE_CONTINUITY_LEAKY = {
    0x05: "AirDrop",
    0x07: "Proximity Pairing",
    0x09: "AirPlay Target",
    0x0A: "AirPlay Source",
    0x0B: "MagicSwitch",
    0x0C: "Handoff",
    0x0D: "Tethering Target",
    0x0E: "Tethering Source",
    0x10: "Nearby Info",
    0x12: "FindMy (offline finding)",
}

# Eddystone frame type byte (Eddystone-Common-Format octet 0 nibble).
_EDDYSTONE_UID    = 0x00
_EDDYSTONE_URL    = 0x10
_EDDYSTONE_TLM    = 0x20
_EDDYSTONE_EID    = 0x30


@dataclass
class AdvFinding:
    target: str
    rule_id: str
    title: str
    severity: str
    rationale: str
    reference: str
    matched: Dict[str, Any] = field(default_factory=dict)


class Module(ScannerModule):

    info = ModuleInfo(
        name="BLE Advertising Anomaly Audit",
        description="Audit stored adv fingerprints for tracking surface (Apple Continuity, Eddystone-UID, public-address peripherals, oversized local names)",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
            "https://github.com/google/eddystone",
            "https://owlink.org/wp-content/uploads/2019/10/Continuity.pdf",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or stored host id. Default audits every host with an adv fingerprint.",
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
                    "(e.g. recon/ble_scan_full)."
                )
                return False

        all_findings: List[AdvFinding] = []
        missing: List[str] = []
        for h in hosts:
            fp = store.latest_fingerprint(h, "adv")
            if fp is None:
                missing.append(h.address)
                continue
            try:
                adv = json.loads(fp.data)
            except (json.JSONDecodeError, TypeError):
                print_warning(f"Corrupt adv for {h.address}, skipped")
                continue
            findings = evaluate_adv(h.address, adv)
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
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            print_warning(f"Ambiguous target {value!r}; candidates:")
            for h in candidates:
                print_warning(f"  [{h.id}] {h.address} {h.name or ''}")
        return None

    def _render(self, findings: List[AdvFinding]) -> None:
        if not findings:
            print_info(
                "No advertising anomalies surfaced against the adv "
                "fingerprints currently in the store."
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
            title="BLE advertising audit",
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
            f"Missing adv fingerprint for {len(missing)} of {total} host(s). "
            f"Run `recon/ble_scan_full` against them."
        )


def evaluate_adv(target: str, adv: Dict[str, Any]) -> List[AdvFinding]:
    """Apply every rule to one `adv` fingerprint dict.

    Shape (from modules/recon/ble_scan_full.py):
        address_type: "Public" | "Static Random" | "Resolvable Random" | ""
        name: str
        rssi, tx_power: int | None
        service_uuids: list[str]
        manufacturer_data: dict[str, str]  (key = "0xCCCC (vendor)", value = hex)
        service_data: dict[uuid_str, hex_str]
        platform_data: dict
    """
    out: List[AdvFinding] = []
    addr_type = str(adv.get("address_type") or "")
    name      = str(adv.get("name") or "")
    mfg       = dict(adv.get("manufacturer_data") or {})
    svc_data  = dict(adv.get("service_data") or {})

    # Rule 1: Public address on a connectable peripheral. Public
    # addresses are immutable and OUI-identifiable, defeating any
    # privacy benefit of BLE. Core Spec recommends Resolvable Private
    # for peripherals that expect bonding.
    if addr_type == "Public":
        out.append(AdvFinding(
            target=target, rule_id="BSA-ADV-001",
            title="Peripheral advertises with a public address",
            severity="low",
            rationale=(
                "Public BD_ADDR is permanent and includes the vendor OUI. "
                "Any passive scanner can build a long-term tracking record. "
                "Privacy-conscious peripherals should advertise with a "
                "Resolvable Private Address rotated per Core Spec Vol 6 "
                "Part B section 6."
            ),
            reference="Core Spec Vol 6 Part B 6; Vanhoef and Pieters WiSec 2016",
            matched={"address_type": addr_type},
        ))

    # Rule 2: Apple Continuity manufacturer-data sub-type that leaks
    # nearby/handoff/AirDrop state. We look for the 0x004C key and
    # decode the first byte of the payload as the sub-type, per the
    # public reverse-engineering by Heinze et al.
    for key, hexed in mfg.items():
        if "0x004C" not in key:
            continue
        try:
            raw = bytes.fromhex(hexed)
        except ValueError:
            continue
        if len(raw) < 1:
            continue
        sub = raw[0]
        if sub in _APPLE_CONTINUITY_LEAKY:
            out.append(AdvFinding(
                target=target, rule_id="BSA-ADV-002",
                title=f"Apple Continuity {_APPLE_CONTINUITY_LEAKY[sub]} advertised",
                severity="medium",
                rationale=(
                    "The peripheral is broadcasting an Apple Continuity "
                    f"sub-type 0x{sub:02X} ({_APPLE_CONTINUITY_LEAKY[sub]}). "
                    "These payloads encode user activity state (Handoff, "
                    "AirDrop visibility, Nearby Info) and have been used "
                    "as side channels for device-tracking and presence "
                    "inference (Heinze et al., 2019)."
                ),
                reference="Apple Continuity public RE; CVE-2019-8531 area",
                matched={"manufacturer": key, "sub_type": f"0x{sub:02X}"},
            ))

    # Rule 3: Eddystone-UID frame. UID frames carry a namespace + an
    # instance and never rotate; in a connectable peripheral this is a
    # permanent global tracker.
    for uuid_str, hexed in svc_data.items():
        # Eddystone uses the 0xFEAA short service UUID, which in
        # 128-bit form is 0000feaa-0000-1000-8000-00805f9b34fb.
        if "feaa" not in uuid_str.lower():
            continue
        try:
            raw = bytes.fromhex(hexed)
        except ValueError:
            continue
        if not raw:
            continue
        frame = raw[0] & 0xF0
        if frame == _EDDYSTONE_UID:
            out.append(AdvFinding(
                target=target, rule_id="BSA-ADV-003",
                title="Eddystone-UID frame advertised",
                severity="medium",
                rationale=(
                    "Eddystone-UID frames carry a 10-byte Namespace ID and "
                    "a 6-byte Instance ID, both static. This is a global "
                    "permanent identifier broadcast in the clear. Consider "
                    "switching to Eddystone-EID, which rotates."
                ),
                reference="Eddystone-UID specification (github.com/google/eddystone)",
                matched={"service_data_uuid": uuid_str},
            ))
        elif frame == _EDDYSTONE_URL:
            out.append(AdvFinding(
                target=target, rule_id="BSA-ADV-004",
                title="Eddystone-URL frame advertised",
                severity="low",
                rationale=(
                    "Eddystone-URL broadcasts a URL to every nearby scanner. "
                    "Operationally low risk but the URL itself is a static "
                    "identifier and a phishing surface if scanners follow "
                    "it automatically."
                ),
                reference="Eddystone-URL specification",
                matched={"service_data_uuid": uuid_str},
            ))

    # Rule 4: Oversized local name. The Complete Local Name AD type
    # carries no length limit beyond the 31-byte advertising frame, but
    # a name string > 20 bytes is almost always a vendor leaking model
    # + firmware + serial. Past public examples include Fitbit and
    # Garmin advertising the full model + revision.
    if len(name.encode("utf-8")) > 20:
        out.append(AdvFinding(
            target=target, rule_id="BSA-ADV-005",
            title="Local name exceeds 20 bytes (likely model + serial leak)",
            severity="low",
            rationale=(
                f"Local name is {len(name.encode('utf-8'))} bytes "
                f"({name!r}). Names of this length usually concatenate "
                "model + firmware + serial, which fingerprints the "
                "individual unit, not just the vendor."
            ),
            reference="Core Spec Vol 3 Part C 11 (AD type 0x09)",
            matched={"name": name},
        ))

    # Rule 5: iBeacon major/minor pair advertised. Apple iBeacon
    # (manufacturer 0x004C sub-type 0x02 length 0x15) carries a fixed
    # 16-byte ProximityUUID + 2-byte Major + 2-byte Minor. The triple
    # is a stable global identifier broadcast in the clear.
    for key, hexed in mfg.items():
        if "0x004C" not in key:
            continue
        try:
            raw = bytes.fromhex(hexed)
        except ValueError:
            continue
        if len(raw) >= 23 and raw[0] == 0x02 and raw[1] == 0x15:
            proximity = raw[2:18].hex()
            major = int.from_bytes(raw[18:20], "big")
            minor = int.from_bytes(raw[20:22], "big")
            out.append(AdvFinding(
                target=target, rule_id="BSA-ADV-006",
                title="iBeacon broadcast (static ProximityUUID + Major/Minor)",
                severity="medium",
                rationale=(
                    "Peripheral advertises an iBeacon payload. The "
                    "ProximityUUID + Major + Minor triple is fixed and "
                    "broadcast continuously, making this a permanent "
                    "trackable identifier. iBeacon does not use rotation."
                ),
                reference="Apple iBeacon Spec (developer.apple.com)",
                matched={
                    "proximity_uuid": proximity,
                    "major": major,
                    "minor": minor,
                },
            ))

    return out
