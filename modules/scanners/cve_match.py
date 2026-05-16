"""
CVE Match Scanner - offline fingerprint matcher against the curated catalog.

Ref: data/signatures/bluetooth_cves.json
"""

import json
import re
from typing import Dict, List, Optional

from core.base import BTProtocol, ModuleInfo, ModuleOption, ScannerModule, Severity
from core.cve import (
    Finding,
    MissingFingerprint,
    filter_by_min_confidence,
    load_signatures,
    scan_host,
)
from core.utils.printer import print_error, print_info, print_success, print_warning

_BD_ADDR_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class Module(ScannerModule):

    info = ModuleInfo(
        name="CVE Match Scanner",
        description="Match stored fingerprints (lmp_features, ll_features, smp_pairing) against the curated Bluetooth CVE catalog",
        author=["BlueSploit"],
        protocol=BTProtocol.DUAL,
        severity=Severity.INFO,
        references=[
            "data/signatures/bluetooth_cves.json",
            "data/signatures/SOURCE.md",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="BD_ADDR or stored host id to scan. Default scans every host in the workspace.",
        ))
        self.add_option(ModuleOption(
            name="min_confidence",
            required=False,
            description="Filter findings by signature confidence: low | medium | high",
            default="low",
        ))

    def run(self) -> bool:
        try:
            signatures = load_signatures()
        except Exception as e:
            print_error(f"Could not load signatures: {e}")
            return False
        print_info(f"Loaded {len(signatures)} signature(s)")

        try:
            from core.store import get_store
            store = get_store()
        except Exception as e:
            print_error(f"Store unavailable: {e}")
            return False

        min_conf = (self.get_option("min_confidence") or "low").lower()
        if min_conf not in ("low", "medium", "high"):
            print_warning(f"Unknown min_confidence {min_conf!r}, defaulting to 'low'")
            min_conf = "low"

        # Resolve targets.
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
                    "(e.g. recon/discovery)."
                )
                return False

        all_findings: List[Finding] = []
        gap_summary: Dict[str, set] = {}   # kind -> set(host addresses)

        for host in hosts:
            fp_by_kind = self._collect_fingerprints(store, host)
            findings, gaps = scan_host(signatures, fp_by_kind, target_address=host.address)
            findings = filter_by_min_confidence(findings, min_conf)
            all_findings.extend(findings)
            for g in gaps:
                gap_summary.setdefault(g.fingerprint_kind, set()).add(host.address)

        self._print_findings(all_findings)
        self._print_gaps(gap_summary, len(hosts))
        for f in all_findings:
            self.add_result({
                "host": f.target_address,
                "cve": f.cve_id,
                "name": f.name,
                "severity": f.severity,
                "confidence": f.confidence,
                "fingerprint_kind": f.fingerprint_kind,
                "matched_fields": f.matched_fields,
                "related_modules": f.related_modules,
            })
        return True

    # ---- helpers -----------------------------------------------------------

    def _resolve_target(self, store, value: str):
        """Accepts a BD_ADDR, a numeric host id, or a substring matched
        against address or name. Returns the Host or None."""
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

    def _collect_fingerprints(self, store, host) -> Dict[str, dict]:
        """Pull the latest fingerprint of each kind for this host."""
        out: Dict[str, dict] = {}
        for kind in ("lmp_features", "ll_features", "smp_pairing"):
            fp = store.latest_fingerprint(host, kind)
            if fp is None:
                continue
            try:
                out[kind] = json.loads(fp.data)
            except json.JSONDecodeError:
                continue
        return out

    def _print_findings(self, findings: List[Finding]) -> None:
        if not findings:
            print_info(
                "No matching CVEs against the fingerprints currently in "
                "the store. Either the targets are not affected by the "
                "signatures we ship, or more recon is needed."
            )
            return

        from core.ui.tables import Column, render_table, total_footer
        columns = [
            Column("Host",       style="cyan",    no_wrap=True),
            Column("CVE",        style="magenta", no_wrap=True),
            Column("Name"),
            Column("Severity",   style="red",     no_wrap=True),
            Column("Confidence", style="yellow",  no_wrap=True),
            Column("Module",     style="dim",     no_wrap=True),
        ]
        rows = []
        for f in findings:
            mod = f.related_modules[0] if f.related_modules else ""
            rows.append((
                f.target_address or "",
                f.cve_id,
                f.name,
                f.severity,
                f.confidence,
                mod,
            ))
        render_table(
            columns, rows,
            title="CVE matches",
            footer=total_footer("finding", len(findings)),
        )

        # Surface confidence rationale per finding so the operator can
        # judge each match. Indented, dim coloring would be nice but
        # the printer keeps it plain so capsys + pipelines stay clean.
        print()
        for f in findings:
            print(f"  {f.cve_id} on {f.target_address}: {f.rationale}")
            if f.matched_fields:
                fields = ", ".join(f"{k}={v!r}" for k, v in f.matched_fields.items())
                print(f"    fields: {fields}")
            print()

    def _print_gaps(self, gap_summary: Dict[str, set], total_hosts: int) -> None:
        if not gap_summary:
            return
        print_info(
            "Some hosts are missing fingerprint data; the scanner could "
            "not evaluate every signature against them."
        )
        for kind, hosts in sorted(gap_summary.items()):
            recon = {
                "lmp_features": "recon/lmp_features",
                "ll_features":  "recon/ll_features",
                "smp_pairing":  "recon/ble_pairing_features",
            }.get(kind, "recon/?")
            print_info(
                f"  Missing {kind} fingerprint for "
                f"{len(hosts)} of {total_hosts} host(s). "
                f"Run `{recon}` against them and re-scan."
            )
