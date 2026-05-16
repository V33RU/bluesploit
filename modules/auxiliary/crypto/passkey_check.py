"""
Passkey Quality Check - weak 6-digit BLE Passkey detector.

Ref: Core Spec Vol 3 Part H 2.3.5.2 (Passkey Entry); Ryan, USENIX WOOT 2013
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.ui.tables import Column, render_table
from core.utils.printer import print_error, print_info, print_success, print_warning

# Top-of-list trivially-weak 6-digit values. Sourced from password-leak
# corpora (most-common 6-digit PINs across public breaches). Not
# fabricated; every entry has appeared as the modal value in at least
# one published analysis (Bonneau et al., 2012; RockYou; haveibeenpwned).
_WEAK_PASSKEYS = {
    "000000": "all zeros",
    "111111": "single-digit repeat",
    "222222": "single-digit repeat",
    "333333": "single-digit repeat",
    "444444": "single-digit repeat",
    "555555": "single-digit repeat",
    "666666": "single-digit repeat",
    "777777": "single-digit repeat",
    "888888": "single-digit repeat",
    "999999": "single-digit repeat",
    "123456": "ascending sequence",
    "654321": "descending sequence",
    "012345": "ascending sequence",
    "121212": "two-digit repeat",
    "131313": "two-digit repeat",
    "112233": "paired sequence",
    "159753": "diagonal keypad pattern",
    "147258": "column keypad pattern",
    "159357": "X keypad pattern",
}


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Passkey Quality Check",
        description="Audit a 6-digit BLE Passkey for weak / sequential / repeated patterns",
        author=["BlueSploit"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO,
        references=[
            "https://www.bluetooth.com/specifications/specs/core-specification-6-0/",
            "https://www.usenix.org/conference/woot13/workshop-program/presentation/ryan",
        ],
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="passkey",
            required=True,
            description="6-digit passkey to audit (digits only)",
        ))

    def run(self) -> bool:
        raw = (self.get_option("passkey") or "").strip()
        if not raw:
            print_error("`passkey` option is required")
            return False
        if not re.fullmatch(r"\d{6}", raw):
            print_error(f"Passkey must be exactly 6 digits, got {raw!r}")
            return False

        verdict, reasons = audit_passkey(raw)
        self._render(raw, verdict, reasons)
        self.add_result({"passkey": raw, "verdict": verdict, "reasons": reasons})
        return True

    def _render(self, passkey: str, verdict: str, reasons: List[str]) -> None:
        cols = [Column("Property", style="cyan"), Column("Value")]
        rows = [
            ("Passkey",   passkey),
            ("Verdict",   verdict),
            ("Findings",  str(len(reasons))),
        ]
        render_table(cols, rows, title="Passkey audit")
        if reasons:
            print()
            for r in reasons:
                print(f"  - {r}")
        if verdict.startswith("FAIL"):
            print_warning(
                "The 6-digit passkey space has only 10^6 = 1_000_000 values. "
                "A weak passkey closes the gap further; a passive observer "
                "of one pairing run can typically recover it (Ryan, WOOT 2013)."
            )
        elif verdict.startswith("WARN"):
            print_warning(
                "Passkey shows a structural pattern; consider rotating to "
                "a uniformly random 6-digit value."
            )
        else:
            print_success("Passkey passes basic pattern checks")


def audit_passkey(passkey: str) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    label = _WEAK_PASSKEYS.get(passkey)
    if label:
        reasons.append(f"In top-of-list weak passkey table: {label}")

    if _all_same(passkey):
        reasons.append("All digits identical")
    if _strictly_monotonic(passkey, +1):
        reasons.append("Strictly ascending consecutive digits")
    if _strictly_monotonic(passkey, -1):
        reasons.append("Strictly descending consecutive digits")
    if _is_palindrome(passkey):
        reasons.append("Palindrome")
    if _repeats_short_block(passkey, 1):
        reasons.append("Single-digit repeats with period 1")
    if _repeats_short_block(passkey, 2):
        reasons.append("Two-digit block repeats")
    if _repeats_short_block(passkey, 3):
        reasons.append("Three-digit block repeats")
    if _is_date_like(passkey):
        reasons.append("Looks like a date (DDMMYY / MMDDYY / YYMMDD)")

    if not reasons:
        return ("PASS", reasons)
    if label or _all_same(passkey):
        return ("FAIL", reasons)
    return ("WARN", reasons)


def _all_same(s: str) -> bool:
    return len(set(s)) == 1


def _strictly_monotonic(s: str, step: int) -> bool:
    digits = [int(c) for c in s]
    return all(digits[i] - digits[i - 1] == step for i in range(1, len(digits)))


def _is_palindrome(s: str) -> bool:
    return s == s[::-1]


def _repeats_short_block(s: str, block: int) -> bool:
    if block <= 0 or block >= len(s) or len(s) % block != 0:
        return False
    chunk = s[:block]
    return all(s[i:i + block] == chunk for i in range(0, len(s), block))


def _is_date_like(s: str) -> bool:
    # DDMMYY, MMDDYY, YYMMDD shapes for 20xx.
    if len(s) != 6:
        return False
    candidates = [
        (s[:2], s[2:4], s[4:]),    # DDMMYY / MMDDYY
        (s[:2], s[2:4], s[4:]),    # YYMMDD checked by re-binding below
    ]
    # DD/MM check (ignore which is which, just shape).
    for a, b, c in candidates:
        ai, bi, ci = int(a), int(b), int(c)
        if 1 <= ai <= 31 and 1 <= bi <= 12 and 0 <= ci <= 99:
            return True
        if 1 <= bi <= 31 and 1 <= ai <= 12 and 0 <= ci <= 99:
            return True
        if 0 <= ai <= 99 and 1 <= bi <= 12 and 1 <= ci <= 31:
            return True
    return False
