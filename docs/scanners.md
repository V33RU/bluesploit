# Scanners (5)

Auto-generated from `modules/scanners/`.  
Load any module with `use scanners/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | Protocol | Description |
|---|---|---|---|
| [`scanners/ble_debug_ecdh`](#scannersble_debug_ecdh) | 🟠 **HIGH** | BLE | Detect devices using the published BT SIG debug ECDH key pair |
| [`scanners/blueborne_scan`](#scannersblueborne_scan) | 🟠 **HIGH** | Classic | Scan for BlueBorne vulnerable devices (CVE-2017-\*) |
| [`scanners/hidden_scanner`](#scannershidden_scanner) | ℹ️ INFO | Both | Find non-discoverable Bluetooth devices |
| [`scanners/ibeacon_scanner`](#scannersibeacon_scanner) | ℹ️ INFO | BLE | iBeacon security tester — discovery, address classification, GATT exposure |
| [`scanners/vuln_scanner`](#scannersvuln_scanner) | 🟠 **HIGH** | Both | Unified 4-phase BLE+Classic vulnerability scanner |

---

## Modules

### `scanners/ble_debug_ecdh`

**BLE Debug ECDH Key Detection**

Detect Bluetooth devices that use the published BT SIG debug ECDH key pair — production-broken Secure Connections.

**Severity:** 🟠 **HIGH** · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `detect` | Mode: detect, exploit, audit |
| `target` | | | Target BD_ADDR (detect/exploit) or `any` for broadcast scan |
| `pcap_file` | | | PCAP to audit (audit mode) |
| `interface` | | `hci0` | Local HCI adapter |
| `duration` | | `120` | Sniff duration in seconds (detect mode) |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification-5-3/>
- <https://nvd.nist.gov/vuln/detail/CVE-2018-5383>

---

### `scanners/blueborne_scan`

**BlueBorne Vulnerability Scanner**

Scan for BlueBorne vulnerable devices across the Classic Bluetooth stack. Probes SDP services and checks OS fingerprint against the CVE-2017-\* family.

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `interface` | | `hci0` | Bluetooth interface |
| `timeout` | | `20` | Scan duration in seconds |
| `deep_scan` | | `True` | Enable SDP probing for detailed analysis |
| `target` | | | Specific target BD_ADDR (optional) |
| `output_file` | | | Save results to JSON |

**References:**
- <https://www.armis.com/blueborne/>
- CVE-2017-0785, CVE-2017-0781, CVE-2017-0782, CVE-2017-1000251

---

### `scanners/hidden_scanner`

**Hidden Device Scanner**

Find non-discoverable Bluetooth devices via name requests, targeted connection attempts, OUI prefix sweeps, or address range probing.

**Severity:** ℹ️ INFO · **Protocol:** BOTH · **CVE:** [CVE-2022-24695](https://nvd.nist.gov/vuln/detail/CVE-2022-24695)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | | | Specific BD_ADDR or OUI prefix |
| `mode` | | `name_req` | Mode: name_req, connect, oui, range, or all |
| `oui` | | | Specific OUI to scan (XX:XX:XX) |
| `range_start` | | `00:00:00` | Start of address range (last 3 bytes) |
| `range_count` | | `256` | Number of addresses to scan |
| `threads` | | `10` | Concurrent threads |
| `timeout` | | `5` | Timeout per device in seconds |

**References:**
- <https://nvd.nist.gov/vuln/detail/CVE-2022-24695>

---

### `scanners/ibeacon_scanner`

**iBeacon Security Tester**

Discover iBeacons in range, select a target, and run a focused security test pass covering address classification, identifier persistence, scan-response leakage, and GATT service exposure.

**Severity:** ℹ️ INFO · **Protocol:** BLE

!!! note "Privilege handling"
    Phase 1 discovery and the timing/scan-response tests use raw HCI sockets
    (`CAP_NET_RAW` or `root`). When raw HCI is unavailable the module
    automatically falls back to **BleakScanner** for discovery and skips the
    two HCI-only sub-tests, so it still runs unprivileged.

| Option | Required | Default | Description |
|---|---|---|---|
| `hci_dev` | | `0` | HCI adapter index (0 for hci0) |
| `discovery_duration` | | `12` | Phase 1 scan duration in seconds |
| `test_duration` | | `30` | Phase 3 persistence + timing window |
| `min_rssi` | | | Discovery RSSI floor (dBm); ignore weaker beacons |
| `auto_select` | | | Skip prompt and select beacon at this 1-based index |
| `skip_gatt` | | `False` | Skip GATT enumeration phase |
| `gatt_timeout` | | `8` | GATT connection timeout in seconds |

**Security tests performed:**

| Test | HCI required | Description |
|---|---|---|
| Default UUID check | No | Match UUID against known SDK-sample / demo defaults |
| Address classification | No | Public OUI vs random (static / RPA / NRPA) |
| Collision / spoofing | No | Same UUID+Major+Minor on multiple addresses |
| Persistence + timing | Yes | Advertising interval, jitter, event-type tracking |
| Scan-response harvest | Yes | Decode AD structures leaked in scan response |
| GATT exposure | No | DFU, NUS, Device Information, config services |

**References:**
- <https://developer.apple.com/ibeacon/>
- Bluetooth Core 5.4 Vol 6 Part B (LL advertising, address types)

---

### `scanners/vuln_scanner`

**Unified Vulnerability Scanner**

4-phase BLE + Classic scanner that fingerprints a target, dispatches specialized deep scans, runs GATT vulnerability analysis, and correlates findings against the live CVE × module catalogue.

**Severity:** 🟠 **HIGH** · **Protocol:** BOTH

#### How it works

```
Phase 1 — Base fingerprint
  • BLE passive advertisement scan (bleak)       → name, vendor, MFR IDs, services, RSSI
  • BLE GATT deep analysis (optional)            → service/char enumeration, vuln checks
  • Classic hcitool info                         → vendor, LMP version, features
  • GAP analysis                                 → address type, flags, pairing state

Phase 2 — Auto-dispatch (based on Phase 1 evidence)
  BLE / BOTH  → recon/adv_parser   (deep manufacturer data parsing)
  BLE / BOTH  → recon/gatt_enum    (if gatt_scan=False)
  CLASSIC / BOTH → recon/sdp_enum  (full SDP with risk scoring + L2CAP probe)
  OS = Linux or Android → scanners/blueborne_scan

Phase 3 — Module catalogue index
  Walks modules/{exploits,dos,auxiliary}/ and builds CVE → module map

Phase 4 — CVE scoring on enriched fingerprint
  Scores each CVE rule against evidence collected in Phases 1 + 2
  Prints confidence tier: CONFIRMED ≥75% / LIKELY ≥55% / POSSIBLE ≥35%
  Prints  ► use <module>  for every matching exploit / DoS / aux module
```

#### GATT vulnerability checks

When `gatt_scan=True` the scanner connects over BLE and checks every characteristic for:

- Risk services: Nordic DFU, HID, Mesh Provisioning, Xiaomi, NUS, and 20+ others
- 128-bit vendor UUIDs: NUS, Eddystone Config, ANCS, AMS, Dialog DFU, Nordic Legacy DFU
- Sensitive characteristics writable without authentication
- Write-without-response on known-risk services
- Notify / Indicate streams on personal data characteristics
- Info-disclosure reads (manufacturer, model, serial, firmware, hardware)
- Active unauthenticated write probes (when `test_writes=True`)

#### GAP analysis

Captured from BLE advertising and BlueZ D-Bus:

- Address kind: public (tracking risk), static random, RPA, NRPA
- Advertising flags: discoverable mode, cross-transport (BR/EDR + LE)
- Connectable / bondable / paired state
- Legacy pairing enabled
- Apple Continuity manufacturer data
- High TX power

#### Final findings table

All findings (GAP + GATT + CVE) are consolidated into a single severity-sorted
table at the end of the report, with tiers separated by divider lines.

#### Options

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ | | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `protocol` | | `auto` | Protocol: auto, ble, classic, both |
| `gatt_scan` | | `True` | Run BLE GATT deep analysis |
| `test_writes` | | `False` | Actively probe writable characteristics (modifies state!) |
| `deep_scan` | | `True` | Read sensitive readable characteristics (info-leak check) |
| `timeout` | | `20` | Per-phase timeout in seconds |
| `min_score` | | `35` | Hide CVE matches below this confidence score (0–100) |
| `output_file` | | | Save full report to JSON |

**References:**
- <https://nvd.nist.gov/>
- <https://www.bluetooth.com/security/>

---
