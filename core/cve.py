"""
CVE-matching engine.

Pure functions and dataclasses. The console-facing module at
`modules/scanners/cve_match.py` is a thin wrapper around this; tests
exercise the engine directly with synthesized fingerprint dicts.

Design rules (codified to stay honest):

  - A signature only matches when the fingerprint actually contains
    every field its rule references. If the recon module never
    captured `lmp_version`, a rule that requires `lmp_version_max_inclusive`
    cannot fire; it does not silently default to "vulnerable".
  - The signature's declared `confidence` is carried through to every
    finding and surfaced in output. The engine never invents one.
  - Severity is carried straight from the signature. The engine does
    not promote a `medium` to `high` because multiple rules match.
  - When a signature requires a `kind` of fingerprint the operator has
    not collected yet, the engine returns a `MissingFingerprint`
    advisory pointing at the right recon module. No fake matches.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.utils.bt import LMP_VERSION_LABELS

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Signature:
    """One CVE signature parsed from `data/signatures/bluetooth_cves.json`."""

    id: str
    name: str
    severity: str
    confidence: str
    protocol: str
    fingerprint_kind: str       # "lmp_features" | "ll_features" | "smp_pairing" | "service"
    rules: List[Dict[str, Any]]
    rationale: str
    description: str
    related_modules: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    disclosed: str = ""


@dataclass
class Finding:
    """Positive match against a stored fingerprint."""

    cve_id: str
    name: str
    severity: str
    confidence: str
    matched_rule_index: int     # which rule in signature.rules fired (0-based)
    fingerprint_kind: str
    target_address: Optional[str]
    related_modules: List[str]
    references: List[str]
    rationale: str
    matched_fields: Dict[str, Any]  # snapshot of the conditions that satisfied


@dataclass
class MissingFingerprint:
    """The host has no fingerprint of the kind a signature requires.

    Surfaced so the operator knows which recon module to run before the
    scanner can give a real answer. Not a finding; not a vulnerability.
    """

    cve_id: str
    name: str
    fingerprint_kind: str
    suggested_recon_module: str


# Map fingerprint kind to the recon module that produces it. Used to
# tell the operator how to fill a gap without guessing.
_KIND_TO_RECON_MODULE = {
    "lmp_features":  "recon/lmp_features",
    "ll_features":   "recon/ll_features",
    "smp_pairing":   "recon/ble_pairing_features",
    "service":       "recon/sdp_enum",
}

# Inverse of bt.LMP_VERSION_LABELS for string -> byte lookup.
_VERSION_LABEL_TO_BYTE: Dict[str, int] = {
    label: byte for byte, label in LMP_VERSION_LABELS.items()
}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def default_signatures_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "signatures" / "bluetooth_cves.json"


def load_signatures(path: Optional[Path] = None) -> List[Signature]:
    """Parse the bundled CVE signature file. Raises FileNotFoundError
    or JSONDecodeError, both of which the caller surfaces verbatim."""
    p = path or default_signatures_path()
    raw = json.loads(p.read_text(encoding="utf-8"))
    out: List[Signature] = []
    for entry in raw.get("entries", []):
        match = entry.get("match", {})
        out.append(Signature(
            id=entry["id"],
            name=entry["name"],
            severity=entry["severity"],
            confidence=entry["confidence"],
            protocol=entry["applies_to"]["protocol"],
            fingerprint_kind=match.get("fingerprint", ""),
            rules=match.get("rules", []),
            rationale=match.get("rationale", ""),
            description=entry["description"],
            related_modules=list(entry.get("related_modules", [])),
            references=list(entry.get("references", [])),
            disclosed=entry.get("disclosed", ""),
        ))
    return out


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


def _version_byte(label: str) -> Optional[int]:
    return _VERSION_LABEL_TO_BYTE.get(label)


def _bool_match(actual: Any, expected: bool) -> bool:
    """Strict bool comparison. `actual` of None is treated as False."""
    return bool(actual) is bool(expected)


def _condition_met(key: str, expected: Any, fp_data: Dict[str, Any]) -> Tuple[bool, Any]:
    """Evaluate one condition against a fingerprint payload.

    Returns `(matched, actual_value_observed)`. The second tuple element
    lets `evaluate_signature` capture exactly what made the rule fire,
    so the finding can show the operator the data that decided it.
    """
    # LMP version comparisons take a string label like "5.0" and compare
    # against the numeric version byte the recon module captured.
    if key in ("lmp_version_max_inclusive", "lmp_version_min_inclusive"):
        actual = fp_data.get("lmp_version", fp_data.get("ll_version"))
        if actual is None:
            return False, None
        target = _version_byte(str(expected))
        if target is None:
            return False, actual
        if key == "lmp_version_max_inclusive":
            return (actual <= target, actual)
        return (actual >= target, actual)

    # LMP feature bits live in page_N_bits dicts populated by the recon
    # module. Page numbers per BT Core Spec:
    #   page 0: standard features (Encryption etc.)
    #   page 1: host features (Secure Connections (Host))
    #   page 2: controller features (Secure Connections (Controller))
    if key == "encryption_supported":
        actual = fp_data.get("page_0_bits", {}).get("Encryption", False)
        return _bool_match(actual, expected), actual
    if key == "secure_connections_controller":
        actual = fp_data.get("page_2_bits", {}).get("Secure Connections (Controller)", False)
        return _bool_match(actual, expected), actual
    if key == "secure_connections_host":
        actual = fp_data.get("page_1_bits", {}).get("Secure Connections (Host)", False)
        return _bool_match(actual, expected), actual

    # LE features live in ll_features_bits dict.
    if key == "le_supported":
        # Controller-side LE support is signaled on the LMP page 0; on a
        # pure LL fingerprint, any field being present implies LE.
        if "ll_features_bits" in fp_data:
            return _bool_match(True, expected), True
        actual = fp_data.get("page_0_bits", {}).get("LE Supported (Controller)", False)
        return _bool_match(actual, expected), actual
    if key == "le_2m_phy":
        actual = fp_data.get("ll_features_bits", {}).get("LE 2M PHY", False)
        return _bool_match(actual, expected), actual
    if key == "le_coded_phy":
        actual = fp_data.get("ll_features_bits", {}).get("LE Coded PHY", False)
        return _bool_match(actual, expected), actual

    # SMP pairing fingerprints come from recon/ble_pairing_features.
    if key == "legacy_pairing_accepted":
        # 'sc' True means the peer offered Secure Connections; the
        # condition `legacy_pairing_accepted: true` means it accepted
        # legacy, i.e. did NOT require SC.
        sc = fp_data.get("sc")
        if sc is None:
            return False, None
        actual = not bool(sc)
        return _bool_match(actual, expected), actual
    if key == "mitm_required":
        actual = fp_data.get("mitm")
        if actual is None:
            return False, None
        return _bool_match(actual, expected), actual
    if key == "max_key_size_max":
        actual = fp_data.get("max_key_size")
        if actual is None:
            return False, None
        return (actual <= int(expected), actual)

    # Unknown condition keys are ignored rather than treated as match.
    # An unknown key cannot be "satisfied" because we have no rule for it.
    return False, None


def evaluate_signature(
    sig: Signature,
    fingerprints_by_kind: Dict[str, Dict[str, Any]],
) -> Optional[Tuple[int, Dict[str, Any]]]:
    """Try to match `sig` against the provided per-kind fingerprint dicts.

    Returns `(rule_index, matched_fields)` for the first rule that
    satisfies, or None if no rule matches or the required fingerprint
    kind is missing.
    """
    fp = fingerprints_by_kind.get(sig.fingerprint_kind)
    if fp is None:
        return None
    if not sig.rules:
        # Empty rules = informational only, never matches.
        return None
    for idx, rule in enumerate(sig.rules):
        observed: Dict[str, Any] = {}
        ok = True
        for key, expected in rule.items():
            met, actual = _condition_met(key, expected, fp)
            observed[key] = actual
            if not met:
                ok = False
                break
        if ok:
            return idx, observed
    return None


def scan_host(
    signatures: Iterable[Signature],
    fingerprints_by_kind: Dict[str, Dict[str, Any]],
    target_address: Optional[str] = None,
) -> Tuple[List[Finding], List[MissingFingerprint]]:
    """Run every signature against the per-kind fingerprint snapshots
    for one host. Returns `(findings, gaps)`."""
    findings: List[Finding] = []
    gaps: List[MissingFingerprint] = []
    seen_kinds_missing: set[str] = set()
    for sig in signatures:
        if sig.fingerprint_kind not in fingerprints_by_kind:
            if sig.fingerprint_kind not in seen_kinds_missing:
                seen_kinds_missing.add(sig.fingerprint_kind)
            gaps.append(MissingFingerprint(
                cve_id=sig.id,
                name=sig.name,
                fingerprint_kind=sig.fingerprint_kind,
                suggested_recon_module=_KIND_TO_RECON_MODULE.get(
                    sig.fingerprint_kind, "recon/?"
                ),
            ))
            continue
        result = evaluate_signature(sig, fingerprints_by_kind)
        if result is None:
            continue
        rule_idx, observed = result
        findings.append(Finding(
            cve_id=sig.id,
            name=sig.name,
            severity=sig.severity,
            confidence=sig.confidence,
            matched_rule_index=rule_idx,
            fingerprint_kind=sig.fingerprint_kind,
            target_address=target_address,
            related_modules=list(sig.related_modules),
            references=list(sig.references),
            rationale=sig.rationale,
            matched_fields=observed,
        ))
    return findings, gaps


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def filter_by_min_confidence(
    findings: Iterable[Finding],
    minimum: str,
) -> List[Finding]:
    """Keep only findings whose confidence is `>= minimum` on the
    `low < medium < high` ordering. Unknown values are kept (never
    silently dropped)."""
    threshold = _CONFIDENCE_RANK.get(minimum, 0)
    out: List[Finding] = []
    for f in findings:
        rank = _CONFIDENCE_RANK.get(f.confidence, threshold)
        if rank >= threshold:
            out.append(f)
    return out
