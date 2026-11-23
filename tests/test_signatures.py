"""Validation tests for `data/signatures/bluetooth_cves.json`.

These do not test the future scanner. They check the data file's
shape and that every entry cites real sources and points at modules
that actually exist in the repo. Catches regressions when an entry is
edited carelessly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SIG_FILE = REPO_ROOT / "data" / "signatures" / "bluetooth_cves.json"
MODULES_DIR = REPO_ROOT / "modules"


@pytest.fixture(scope="module")
def doc():
    return json.loads(SIG_FILE.read_text(encoding="utf-8"))


# Top-level shape ------------------------------------------------------------


class TestTopLevel:
    def test_file_exists(self):
        assert SIG_FILE.is_file()

    def test_is_valid_json(self):
        # Parse explicitly to surface a syntax error message in the assertion
        # rather than via the fixture loader stack trace.
        json.loads(SIG_FILE.read_text(encoding="utf-8"))

    def test_required_top_level_fields(self, doc):
        assert "schema_version" in doc
        assert "entries" in doc
        assert isinstance(doc["entries"], list)

    def test_schema_version_is_int(self, doc):
        assert isinstance(doc["schema_version"], int)
        assert doc["schema_version"] >= 1

    def test_has_entries(self, doc):
        assert len(doc["entries"]) > 0


# Per-entry shape ------------------------------------------------------------


_REQUIRED_ENTRY_FIELDS = {
    "id", "name", "severity", "confidence", "applies_to", "match",
    "description", "related_modules", "references", "disclosed",
}
_ALLOWED_SEVERITY = {"info", "low", "medium", "high", "critical"}
_ALLOWED_CONFIDENCE = {"low", "medium", "high"}
_ALLOWED_PROTOCOLS = {"classic", "ble", "dual"}
_ALLOWED_FINGERPRINTS = {"lmp_features", "ll_features", "smp_pairing", "service"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class TestEachEntry:
    def test_required_fields_present(self, doc):
        for entry in doc["entries"]:
            missing = _REQUIRED_ENTRY_FIELDS - set(entry.keys())
            assert not missing, f"{entry.get('id')}: missing {missing}"

    def test_cve_id_format(self, doc):
        for entry in doc["entries"]:
            assert _CVE_RE.match(entry["id"]), f"invalid CVE id: {entry['id']!r}"

    def test_no_duplicate_ids(self, doc):
        ids = [e["id"] for e in doc["entries"]]
        assert len(ids) == len(set(ids)), f"duplicate CVE ids: {ids}"

    def test_severity_valid(self, doc):
        for entry in doc["entries"]:
            assert entry["severity"] in _ALLOWED_SEVERITY, (
                f"{entry['id']}: bad severity {entry['severity']!r}"
            )

    def test_confidence_valid(self, doc):
        for entry in doc["entries"]:
            assert entry["confidence"] in _ALLOWED_CONFIDENCE, (
                f"{entry['id']}: bad confidence {entry['confidence']!r}"
            )

    def test_applies_to_protocol_valid(self, doc):
        for entry in doc["entries"]:
            proto = entry["applies_to"].get("protocol")
            assert proto in _ALLOWED_PROTOCOLS, (
                f"{entry['id']}: bad protocol {proto!r}"
            )

    def test_match_block_shape(self, doc):
        for entry in doc["entries"]:
            m = entry["match"]
            assert m["fingerprint"] in _ALLOWED_FINGERPRINTS, (
                f"{entry['id']}: bad fingerprint {m['fingerprint']!r}"
            )
            assert isinstance(m["rules"], list)
            assert isinstance(m["rationale"], str) and m["rationale"].strip()

    def test_description_non_empty(self, doc):
        for entry in doc["entries"]:
            assert entry["description"].strip(), f"{entry['id']}: empty description"

    def test_disclosed_is_iso_date(self, doc):
        for entry in doc["entries"]:
            assert _DATE_RE.match(entry["disclosed"]), (
                f"{entry['id']}: disclosed not ISO YYYY-MM-DD: {entry['disclosed']!r}"
            )

    def test_references_present_and_include_nvd(self, doc):
        for entry in doc["entries"]:
            refs = entry["references"]
            assert isinstance(refs, list) and len(refs) >= 2, (
                f"{entry['id']}: need at least 2 references (NVD + primary source)"
            )
            assert any("nvd.nist.gov" in r for r in refs), (
                f"{entry['id']}: missing NVD reference"
            )

    def test_references_match_cve_id(self, doc):
        """NVD reference URL should embed the CVE id, catches copy-paste mistakes."""
        for entry in doc["entries"]:
            nvd_refs = [r for r in entry["references"] if "nvd.nist.gov" in r]
            assert any(entry["id"] in r for r in nvd_refs), (
                f"{entry['id']}: NVD reference URL does not contain the CVE id"
            )


# Cross-reference with the codebase -----------------------------------------


class TestRelatedModulesExist:
    def test_every_related_module_resolves_to_a_file(self, doc):
        for entry in doc["entries"]:
            for mod_path in entry["related_modules"]:
                file_path = MODULES_DIR / f"{mod_path}.py"
                assert file_path.is_file(), (
                    f"{entry['id']}: related_modules entry "
                    f"{mod_path!r} has no matching module file"
                )
