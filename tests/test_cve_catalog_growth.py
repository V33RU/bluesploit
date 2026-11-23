"""Tests for the CVE catalog additions (BLURtooth, CVE-2020-26555,
CVE-2018-5383, CVE-2023-45866) plus the new `ctkd_advertised`
condition key in core/cve.py.
"""

from __future__ import annotations

from core.cve import load_signatures, scan_host

# Fingerprint factory ---------------------------------------------------------


def _lmp(version: int, *, encryption: bool = True, sc_ctrl: bool = False) -> dict:
    return {
        "lmp_version": version,
        "page_0_bits": {"Encryption": encryption},
        "page_2_bits": {"Secure Connections (Controller)": sc_ctrl},
    }


def _smp(
    *,
    mitm: bool = True,
    sc: bool = True,
    ct2: bool = False,
    max_key_size: int = 16,
) -> dict:
    return {
        "mitm": mitm,
        "sc": sc,
        "ct2": ct2,
        "max_key_size": max_key_size,
    }


def _sig_by_id(cve_id: str):
    return next(s for s in load_signatures() if s.id == cve_id)


def _scan_one(sig, kind: str, data: dict):
    """Helper: scan a single signature against a single fingerprint and
    return whether it fired and the matched fields (if any)."""
    findings, _gaps = scan_host([sig], {kind: data})
    if findings:
        return True, findings[0].matched_fields
    return False, {}


# BLURtooth (CVE-2020-15802) --------------------------------------------------


class TestBlurtooth:
    def test_fires_when_ct2_and_legacy(self):
        sig = _sig_by_id("CVE-2020-15802")
        ok, matched = _scan_one(sig, "smp_pairing", _smp(sc=False, ct2=True))
        assert ok is True
        assert matched["ctkd_advertised"] is True
        assert matched["legacy_pairing_accepted"] is True

    def test_silent_when_sc_required(self):
        sig = _sig_by_id("CVE-2020-15802")
        ok, _ = _scan_one(sig, "smp_pairing", _smp(sc=True, ct2=True))
        assert ok is False

    def test_silent_when_no_ctkd(self):
        sig = _sig_by_id("CVE-2020-15802")
        ok, _ = _scan_one(sig, "smp_pairing", _smp(sc=False, ct2=False))
        assert ok is False

    def test_silent_when_field_missing(self):
        sig = _sig_by_id("CVE-2020-15802")
        ok, _ = _scan_one(sig, "smp_pairing", {})
        assert ok is False


# CVE-2020-26555 PIN-pairing impersonation -----------------------------------


class TestPinPairing:
    def test_fires_on_pre_5_2(self):
        sig = _sig_by_id("CVE-2020-26555")
        # LMP version 0x0A = 5.1, still vulnerable per signature.
        ok, _ = _scan_one(sig, "lmp_features", _lmp(0x0A, encryption=True))
        assert ok is True

    def test_silent_on_5_2(self):
        sig = _sig_by_id("CVE-2020-26555")
        # 0x0B = 5.2
        ok, _ = _scan_one(sig, "lmp_features", _lmp(0x0B, encryption=True))
        assert ok is False


# CVE-2018-5383 Invalid Curve -------------------------------------------------


class TestInvalidCurve:
    def test_fires_on_no_mitm_sc(self):
        sig = _sig_by_id("CVE-2018-5383")
        ok, matched = _scan_one(sig, "smp_pairing", _smp(mitm=False, sc=True))
        assert ok is True
        assert matched["legacy_pairing_accepted"] is False
        assert matched["mitm_required"] is False

    def test_silent_when_mitm_required(self):
        sig = _sig_by_id("CVE-2018-5383")
        ok, _ = _scan_one(sig, "smp_pairing", _smp(mitm=True, sc=True))
        assert ok is False

    def test_silent_when_legacy(self):
        sig = _sig_by_id("CVE-2018-5383")
        ok, _ = _scan_one(sig, "smp_pairing", _smp(mitm=False, sc=False))
        assert ok is False


# CVE-2023-45866 BlueDuck-style ---------------------------------------------


class TestBlueducky:
    def test_fires_on_no_mitm_legacy(self):
        sig = _sig_by_id("CVE-2023-45866")
        ok, _ = _scan_one(sig, "smp_pairing", _smp(mitm=False, sc=False))
        assert ok is True

    def test_silent_when_mitm_required(self):
        sig = _sig_by_id("CVE-2023-45866")
        ok, _ = _scan_one(sig, "smp_pairing", _smp(mitm=True, sc=False))
        assert ok is False


# Catalog hygiene -------------------------------------------------------------


class TestCatalogShape:
    def test_loaded_count(self):
        sigs = load_signatures()
        ids = [s.id for s in sigs]
        for needed in (
            "CVE-2019-9506", "CVE-2020-10135", "CVE-2023-24023",
            "CVE-2020-15802", "CVE-2020-26555", "CVE-2018-5383",
            "CVE-2023-45866",
        ):
            assert needed in ids, f"missing {needed} in shipped catalog"

    def test_every_entry_has_nvd_reference(self):
        for s in load_signatures():
            assert any("nvd.nist.gov" in r for r in s.references), (
                f"{s.id} missing NVD reference"
            )

    def test_every_smp_signature_uses_known_condition_keys(self):
        # If we add a new condition key but forget to wire it into
        # _condition_met, the signature would silently never fire.
        # Sanity test: scan two complementary fingerprints (one Legacy
        # worst-case, one SC-but-no-MITM) and assert every smp_pairing
        # signature fires for at least one of them.
        worst_legacy = _smp(mitm=False, sc=False, ct2=True, max_key_size=7)
        worst_sc = _smp(mitm=False, sc=True, ct2=False, max_key_size=16)
        all_ids = set()
        for fp in (worst_legacy, worst_sc):
            findings, _gaps = scan_host(load_signatures(), {"smp_pairing": fp})
            all_ids.update(f.cve_id for f in findings)
        smp_sig_ids = {
            s.id for s in load_signatures()
            if s.fingerprint_kind == "smp_pairing"
        }
        assert smp_sig_ids.issubset(all_ids), (
            f"smp_pairing signatures never fire: "
            f"{smp_sig_ids - all_ids}"
        )
