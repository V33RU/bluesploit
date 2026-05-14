"""
BlueSploit Module: IRK Entropy + RPA Resolution Test

Specialized analysis of a 16-byte Identity Resolving Key (IRK).
Combines two real checks:

  1. Statistical quality (delegates to core/crypto.analyze_key)
  2. Resolvable Private Address resolution (Core Spec Vol 3 Part H
     2.2.2 `ah` function). Given the IRK plus one or more observed
     RPAs, verifies which RPAs the IRK can resolve. This proves
     identity-level linkage when it succeeds.

Pure local analysis: no HCI, no network. The IRK must come from
the operator (paired session, captured pcap, or vendor key
material). RPAs come either from `--rpas` or from the engagement
store's hosts table (every host whose top two address bits are 01).

References
    Core Spec v5.4 Vol 3 Part H section 2.2.2 (ah function)
    Core Spec v5.4 Vol 6 Part B section 1.3.2.2 (RPA format)
    Vanhoef and Pieters, "Why MAC address randomization is not enough"
"""

from __future__ import annotations

from typing import List

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.crypto import (
    analyze_key,
    is_resolvable_private,
    parse_bd_addr,
    parse_hex_blob,
    rpa_resolves,
)
from core.ui.tables import Column, render_table, total_footer
from core.utils.printer import print_error, print_info, print_success, print_warning


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="IRK Entropy + RPA Resolution",
        description="Analyze a 16-byte IRK for entropy + run the Core Spec `ah` resolution against observed Resolvable Private Addresses",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="irk",
            required=True,
            description="16-byte IRK as hex (colons / 0x prefix accepted)",
        ))
        self.add_option(ModuleOption(
            name="byte_order",
            required=False,
            description="IRK byte order: msb (spec text) or lsb (over-the-air, common in btsnoop)",
            default="msb",
        ))
        self.add_option(ModuleOption(
            name="rpas",
            required=False,
            description="Comma-separated RPA list to test resolution against. Empty = use hosts from the workspace.",
            default=None,
        ))

    def run(self) -> bool:
        raw_irk = self.get_option("irk")
        if not raw_irk:
            print_error("`irk` option is required")
            return False
        try:
            irk_bytes = parse_hex_blob(raw_irk)
        except ValueError as e:
            print_error(f"Could not parse IRK: {e}")
            return False
        if len(irk_bytes) != 16:
            print_error(f"IRK must be 16 bytes, got {len(irk_bytes)}")
            return False

        byte_order = (self.get_option("byte_order") or "msb").lower()
        if byte_order not in ("msb", "lsb"):
            print_warning(f"Unknown byte_order {byte_order!r}, defaulting to 'msb'")
            byte_order = "msb"
        irk_for_ah = irk_bytes if byte_order == "msb" else bytes(reversed(irk_bytes))

        # --- entropy first ---------------------------------------------------
        analysis = analyze_key(irk_bytes)
        self._render_entropy(analysis)

        # --- resolution test -------------------------------------------------
        rpa_arg = (self.get_option("rpas") or "").strip()
        if rpa_arg:
            candidates = [r.strip() for r in rpa_arg.split(",") if r.strip()]
            source = "supplied list"
        else:
            candidates = self._candidates_from_store()
            source = "workspace hosts"

        if not candidates:
            print_info(
                "No RPAs to test. Pass them via the `rpas` option, or run a "
                "scan first so the workspace has hosts."
            )
            self.add_result({"entropy": analysis, "resolved": [], "tested": 0})
            return True

        results = self._test_resolution(irk_for_ah, candidates)
        self._render_resolution(results, source)

        self.add_result({
            "entropy": analysis,
            "resolved": [r for r in results if r["resolved"]],
            "tested": len(results),
            "byte_order": byte_order,
        })
        return True

    def _candidates_from_store(self) -> List[str]:
        try:
            from core.store import get_store
            store = get_store()
        except Exception as e:
            print_warning(f"Store unavailable: {e}")
            return []
        out: List[str] = []
        for h in store.list_hosts():
            try:
                ab = parse_bd_addr(h.address)
            except ValueError:
                continue
            if is_resolvable_private(ab):
                out.append(h.address)
        return out

    def _test_resolution(self, irk: bytes, addrs: List[str]) -> List[dict]:
        out: List[dict] = []
        for addr in addrs:
            try:
                parsed = parse_bd_addr(addr)
                rpa_form = is_resolvable_private(parsed)
            except ValueError:
                out.append({"address": addr, "rpa_form": False,
                            "resolved": False, "note": "bad BD_ADDR"})
                continue
            if not rpa_form:
                out.append({"address": addr, "rpa_form": False,
                            "resolved": False, "note": "not in RPA form"})
                continue
            resolved = rpa_resolves(irk, addr)
            out.append({
                "address": addr, "rpa_form": True,
                "resolved": resolved,
                "note": "matched" if resolved else "no match",
            })
        return out

    def _render_entropy(self, a: dict) -> None:
        print_info("IRK entropy analysis")
        cols = [Column("Property", style="cyan"), Column("Value")]
        rows = [
            ("Length",          f"{a['length']} bytes"),
            ("Shannon entropy", f"{a['entropy_bits']:.3f} bits/byte"),
            ("Chi-square",      f"{a['chi_square']:.2f}"),
            ("Unique bytes",    str(a["unique_bytes"])),
            ("Known weak",      a["known_weak"] or "(none)"),
            ("Verdict",         a["verdict"]),
        ]
        render_table(cols, rows, title="IRK quality")

    def _render_resolution(self, results: List[dict], source: str) -> None:
        cols = [
            Column("Address",  style="cyan",    no_wrap=True),
            Column("RPA form", style="dim",     no_wrap=True),
            Column("Resolved", style="green",   no_wrap=True),
            Column("Note",     style="yellow"),
        ]
        rows = [
            (r["address"], "yes" if r["rpa_form"] else "no",
             "YES" if r["resolved"] else "no", r["note"])
            for r in results
        ]
        resolved_n = sum(1 for r in results if r["resolved"])
        render_table(
            cols, rows,
            title=f"RPA resolution ({source})",
            footer=total_footer("address", len(results)),
        )
        if resolved_n:
            print_success(
                f"IRK resolves {resolved_n} of {len(results)} address(es). "
                f"Those targets are linkable to the IRK owner."
            )
        else:
            print_info(
                f"IRK did not resolve any of the {len(results)} tested "
                f"address(es). Either the IRK is for a different identity, "
                f"or the byte order is reversed (try byte_order=lsb)."
            )
