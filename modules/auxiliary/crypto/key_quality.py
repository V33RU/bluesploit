"""
BlueSploit Module: Key Quality Analyzer

Statistical analysis of a hex-encoded key blob (LTK, IRK, link key,
CSRK, etc.). Detects known weak / test keys, repeated-byte runs,
trivial entropy, and matches against a small fixed table of common
mistakes.

This is a pure analysis module: it reads a key the operator paste
in, performs deterministic math (Shannon entropy, byte-frequency
chi-square, run detection, known-weak table lookup), and prints a
verdict. No HCI, no scanning, no network.

References
    Core Spec v5.4 Vol 3 Part H section 2.4 (key derivation)
    NIST SP 800-22 (statistical tests for random number generators)
"""

from __future__ import annotations

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.crypto import analyze_key, parse_hex_blob
from core.ui.tables import Column, render_table
from core.utils.printer import print_error, print_success, print_warning


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Key Quality Analyzer",
        description="Statistical quality analysis of a hex-encoded BLE key blob (LTK, IRK, link key, CSRK)",
        author=["BlueSploit"],
        protocol=BTProtocol.DUAL,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
            "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="key",
            required=True,
            description="Key bytes as hex (with or without colons / 0x prefix)",
        ))
        self.add_option(ModuleOption(
            name="expected_length",
            required=False,
            description="Expected byte length (e.g. 16 for AES-128 keys). Empty = accept any length.",
            default=None,
        ))

    def run(self) -> bool:
        raw_key = self.get_option("key")
        if not raw_key:
            print_error("`key` option is required")
            return False
        try:
            data = parse_hex_blob(raw_key)
        except ValueError as e:
            print_error(f"Could not parse key: {e}")
            return False

        expected = self.get_option("expected_length")
        if expected not in (None, "", "None"):
            try:
                expected_n = int(expected)
            except (TypeError, ValueError):
                print_warning(f"expected_length {expected!r} is not an integer, ignored")
                expected_n = None
        else:
            expected_n = None

        if expected_n is not None and len(data) != expected_n:
            print_warning(
                f"Key is {len(data)} byte(s); expected {expected_n}. "
                f"Continuing analysis on what was provided."
            )

        result = analyze_key(data)
        self._render(result)
        self.add_result(result)
        return True

    def _render(self, r: dict) -> None:
        cols = [
            Column("Property", style="cyan"),
            Column("Value"),
        ]
        rows = [
            ("Length (bytes)",     str(r["length"])),
            ("Shannon entropy",    f"{r['entropy_bits']:.3f} bits/byte"),
            ("Chi-square stat",    f"{r['chi_square']:.2f}"),
            ("Unique bytes",       str(r["unique_bytes"])),
            ("Repeated runs",      str(len(r["repeated_runs"]))),
            ("Known weak match",   r["known_weak"] or "(none)"),
            ("All ASCII printable", "yes" if r["all_ascii_printable"] else "no"),
            ("Verdict",            r["verdict"]),
        ]
        render_table(cols, rows, title="Key analysis")

        if r["repeated_runs"]:
            print()
            print_warning("Repeated-byte runs:")
            for offset, length in r["repeated_runs"]:
                print(f"    offset {offset} length {length} value 0x{r['raw'][offset]:02x}")

        if r["known_weak"]:
            print()
            print_error(
                f"This key matches the known-weak table entry: {r['known_weak']}. "
                f"Treat as fully compromised."
            )
        elif r["verdict"].startswith("PASS"):
            print_success("Key passes basic quality checks (no automatic guarantee of secrecy)")
        else:
            print_warning(r["verdict"])


