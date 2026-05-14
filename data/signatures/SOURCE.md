# Bluetooth CVE signatures

`bluetooth_cves.json` is a hand-curated catalog of public Bluetooth
CVEs that can be reasoned about from fingerprint data the recon
modules already extract (LMP feature pages, LL features, SMP pairing
capabilities). Future PRs will add `scanners/cve_match.py` that reads
this file and matches against fingerprints stored in the engagement
store.

## Why hand-curated

There is no machine-readable Bluetooth-specific CVE database. NVD has
generic CVE records but no structured indicator that ties to a
specific LMP feature bit or LL version. Tools that claim to scan for
Bluetooth CVEs either embed similar curated lists or run live probes.

This file leans on curated entries with explicit confidence levels:

- `confidence: high` , the fingerprint is a definitive indicator.
- `confidence: medium` , the fingerprint is a strong signal but
  vendors can backport fixes without bumping reported versions.
- `confidence: low` , the fingerprint is suggestive only; a live
  probe is required to confirm.

Severity is never inflated to match what an exploit "could" do. If
the detection cannot reliably distinguish patched from unpatched,
confidence drops; severity reflects worst case but the report will
always include the confidence level so the operator can judge.

## Adding a new entry

1. Find the NVD record: `https://nvd.nist.gov/vuln/detail/<CVE-ID>`.
2. Find the primary source (research paper, vendor advisory,
   Bluetooth SIG erratum). At least one URL must point to a
   non-aggregator source.
3. Identify the fingerprint indicator. If the only reliable detection
   needs a live probe, do not add a fingerprint rule yet; add the
   entry with `match.rules: []` and `confidence: low` so the future
   scanner reports it as informational.
4. Set `confidence` honestly. When unsure, use `low` and prefer a
   lower severity.
5. List `related_modules` so the future scanner can suggest a
   follow-up exploit module.
6. Run `python3 -m pytest scripts/test_signatures.py`.

## Format

See `SCHEMA.md` for field semantics.

## Maintainers

`Mr-IoT` (BlueSploit author). Pull requests adding signatures are
welcome as long as every entry cites a real public source and the
detection rule is defensible.
