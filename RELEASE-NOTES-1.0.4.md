# bluesploit v1.0.4 release notes

The Phase 3 milestone: real-data scanners, real-crypto auxiliary modules, a
growing CVE catalog, and the first slice of Bluetooth Mesh support. Built by
Mr-IoT.

## What is new

### Engagement store (Phase 1, recap)

The SQLite store under `~/.bluesploit/store.db` is now the persistence
backbone every new scanner feeds on:

- `hosts`, `loot`, `credentials`, `fingerprints`, `workspaces`
- `workspace`, `hosts`, `loot`, `creds`, `setg`, `unsetg`, `resource`,
  `whatsnew`, `tips` REPL commands
- `set target <addr>` resolves to a stored host and auto-fills any saved
  credentials

### New scanners (Phase 3)

All read from the store, all source-cited, all info/medium/high severity
fixed per rule (never inflated):

- `scanners/ble_pairing_audit` -- 7 rules over SMP pairing features:
  JustWorks legacy, JustWorks under SC, Legacy accepted, weak key size,
  CSRK unauth, CT2/BLURtooth surface, bonding without MITM.
- `scanners/char_permission_audit` -- 5 rules over GATT topology:
  writable Device Name, writable identity (System ID / Serial / Model /
  PnP ID), control point with Write Without Response, notify missing
  CCCD, HID Report Map readable.
- `scanners/adv_anomaly_audit` -- 6 rules over advertising data:
  public-address peripheral, Apple Continuity leaky sub-types
  (Handoff, FindMy, etc), Eddystone-UID, Eddystone-URL, oversized
  local name, iBeacon broadcast.
- `scanners/cve_match` -- offline CVE matcher consuming every stored
  fingerprint kind, citing NVD + a primary source per signature.
- `scanners/ll_features_audit` -- privacy gaps + BLE 5.x capability
  profile (Periodic Adv, CIS, Power Control, Coded PHY, Subrating).
- `scanners/iot_profile_audit` -- inventory classifier joining
  `gatt_topology` + `adv` fingerprints into IoT categories with
  suggested follow-up modules.
- `scanners/mesh_provisioning_audit` -- 5 rules over Mesh beacons:
  no OOB, weak OOB only, URI hash absent, key refresh / IV update
  in progress (info).

### New recon (Phase 3)

- `recon/ble_scan_full` -- full advertising payload capture via bleak
  with mirage-style table output. Decodes manufacturer data via the
  Bluetooth SIG Company Identifier table, persists `adv` fingerprints.
- `recon/ble_target_enum` -- bleak-based connect-and-walk of services,
  characteristics, descriptors, and (optionally) values. Mirage-style
  per-service detail tables. Persists `gatt_topology` fingerprints.
- `recon/mesh_beacon_scan` -- passive bleak scan for Mesh Provisioning
  Service (0x1827) and Mesh Proxy Service (0x1828). Decodes
  Unprovisioned Device Beacons and Secure Network Beacons. Persists
  `mesh_beacon` fingerprints.

Plus the recon writers from earlier in the milestone:
`recon/lmp_features`, `recon/ll_features`, `recon/ble_pairing_features`,
`recon/discovery`, `recon/oui_lookup` all persist real fingerprints
that downstream scanners consume.

### New auxiliary (Phase 3)

- `auxiliary/crypto/key_quality` -- statistical key audit using
  Shannon entropy + Pearson chi-square + known-weak table.
- `auxiliary/crypto/irk_entropy` -- entropy + Resolvable Private
  Address resolution via the Core Spec `ah` function.
- `auxiliary/crypto/passkey_check` -- 6-digit BLE Passkey weakness
  audit (top-N weak table + pattern checks).
- `auxiliary/mesh/mesh_pdu_decode` -- offline Mesh Network PDU
  decoder using real K2 + PECB + AES-CCM.

### Core libraries

- `core/crypto.py` -- AES primitives, Mesh-side hex parsing, BLE `ah`
  function and `rpa_resolves`, key statistics. Verified against NIST
  FIPS-197 and Core Spec test vectors.
- `core/mesh.py` -- Mesh Profile s1, AES-CMAC, K1, K2, K3, K4,
  Network Nonce, PECB deobfuscation, AES-CCM PDU decrypt. Verified
  against Mesh Profile v1.1 Annex 8.1.1 sample vectors.
- `core/ble_meta.py` -- SIG service / characteristic / descriptor
  UUID tables, property decoder.
- `core/store.py` -- engagement store schema and API.
- `core/cve.py` -- CVE matching engine with `ctkd_advertised`,
  `legacy_pairing_accepted`, `mitm_required`, `max_key_size_max`,
  feature-bit and version-bound conditions.

### Data files

- `data/oui/oui.csv.gz` -- 39,433 IEEE OUI records.
- `data/signatures/bluetooth_cves.json` -- 7 NVD-cited entries:
  CVE-2019-9506 (KNOB), CVE-2020-10135 (BIAS), CVE-2023-24023
  (BLUFFS), CVE-2020-15802 (BLURtooth), CVE-2020-26555 (PIN-pairing
  variant), CVE-2018-5383 (Invalid Curve), CVE-2023-45866 (BLE-HID
  forced pair / BlueDuck-style).

### Testing + CI

- 500+ unit tests under `scripts/`, every primitive verified against a
  spec test vector where one exists.
- CI workflow with `ruff`, `mypy` (lenient/advisory), `pytest` on
  Python 3.10 + 3.12, and module-metadata validation.
- Dependabot scoped to security + minor bumps (major bumps reviewed
  by hand).

## What is intentionally deferred

Per the no-fake-data rule, these were not shipped because they need a
real testbed to validate:

- BLE Mesh attack surface beyond audit: relay hijack, IV-index abuse,
  friendship attack, NetKey brute-force. The Mesh crypto primitives
  (`core/mesh.py`) are already in place to build them.
- Active BLE 5.x exploits: CIS isochronous sniff, Periodic Advertising
  Sync Transfer spoof, LE Power Control hijack, Connection Subrating
  bypass, LE Coded PHY MITM. The LL feature audit identifies the
  surface; the exploit half waits for hardware verification.
- Vendor-specific iOS / Windows / macOS additions beyond the existing
  coverage in `modules/exploits/`. The current set already covers the
  major published CVEs in each family.
- IoT device packs (smart locks, wearables, fobs, medical sensors,
  gateways) beyond the inventory classifier. The classifier points at
  the right follow-up modules; new device-specific exploits need real
  targets to ship honestly.

## Upgrading

Drop the existing `~/.bluesploit/` store, then:

    git pull origin main
    pip install -U .

The store schema migrates on first run. No prior workspace is read
into the new schema; if you need to preserve a v1.0.3 store, copy it
aside first.

## Tags in this milestone

dev0 -> dev12 led here. Every PR merged in Phase 3 has a dev tag
attached to its squash commit. The full list is in `git tag -l 'v1.0.4*'`.
