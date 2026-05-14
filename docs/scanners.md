# Scanners (5)

Auto-generated from `modules/scanners/`.  
Load any module with `use scanners/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | CVE | Description |
|---|---|---|---|
| [`scanners/ble_debug_ecdh`](#scannersble_debug_ecdh) | 🟠 **HIGH** | - | Detect Bluetooth devices that use the published BT SIG debug ECDH key pair, p… |
| [`scanners/blueborne_scan`](#scannersblueborne_scan) | 🟠 **HIGH** | - | Scan for BlueBorne vulnerable devices (CVE-2017-*) |
| [`scanners/hidden_scanner`](#scannershidden_scanner) | ℹ️ INFO | - | Find non-discoverable Bluetooth devices (BR/EDR + LE) |
| [`scanners/ibeacon_scanner`](#scannersibeacon_scanner) | ℹ️ INFO | - | Discover iBeacons, select a target, run focused security tests |
| [`scanners/vuln_scanner`](#scannersvuln_scanner) | 🟠 **HIGH** | - | Unified BLE+Classic vulnerability scanner, GATT deep analysis + CVE→module ma… |

---

## Modules

### `scanners/ble_debug_ecdh`

**BLE Debug ECDH Key Detection**

Detect Bluetooth devices that use the published BT SIG debug ECDH key pair, production-broken Secure Connections

**Severity:** 🟠 **HIGH** · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `detect` | Mode: detect, exploit, audit |
| `target` |  |  | Target BD_ADDR (detect/exploit) or 'any' for broadcast scan |
| `pcap_file` |  |  | PCAP to audit (audit mode) |
| `interface` |  | `hci0` | Local HCI adapter |
| `duration` |  | `120` | Sniff duration in seconds (detect mode) |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification-5-3/>
- <https://nvd.nist.gov/vuln/detail/CVE-2018-5383>

---

### `scanners/blueborne_scan`

**scanners/classic/blueborne_scan**

Scan for BlueBorne vulnerable devices (CVE-2017-*)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `interface` |  | `hci0` | Bluetooth interface (hci0) |
| `timeout` |  | `20` | Scan duration in seconds |
| `deep_scan` |  | `True` | Enable SDP probing for detailed analysis |
| `target` |  |  | Specific target BD_ADDR (optional) |
| `output_file` |  |  | Save results to JSON file |

**References:**
- <https://www.armis.com/blueborne/>
- <CVE-2017-0785>
- <CVE-2017-0781>
- <CVE-2017-0782>
- <CVE-2017-1000251>

---

### `scanners/hidden_scanner`

Find non-discoverable Bluetooth devices (BR/EDR + LE)

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |

**References:**
- <Bluetooth Core 5.4 Vol 2 Part E (HCI)>
- <Bluetooth Core 5.4 Vol 6 Part B (LL)>
- <BlueZ source: lib/hci.c, lib/l2cap.c>

---

### `scanners/ibeacon_scanner`

**scanners/ibeacon_sec_test**

Discover iBeacons, select a target, run focused security tests

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |
| `?` |  |  |  |

**References:**
- <https://developer.apple.com/ibeacon/>
- <Bluetooth Core 5.4 Vol 6 Part B (LL advertising, addr types)>

---

### `scanners/vuln_scanner`

Unified BLE+Classic vulnerability scanner, GATT deep analysis + CVE→module matcher

**Severity:** 🟠 **HIGH** · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `protocol` |  | `auto` | Protocol: auto, ble, classic, both |
| `gatt_scan` |  | `True` | Run BLE GATT deep analysis (services/characteristics) |
| `test_writes` |  | `False` | Actively probe writable characteristics (modifies state!) |
| `deep_scan` |  | `True` | Read sensitive readable characteristics (info-leak check) |
| `timeout` |  | `20` | Per-phase timeout in seconds |
| `min_score` |  | `35` | Hide CVE matches below this confidence score (0-100) |
| `output_file` |  |  | Save full report to JSON |

**References:**
- <https://nvd.nist.gov/>
- <https://www.bluetooth.com/security/>
- <https://www.usenix.org/conference/usenixsecurity19/presentation/wu-jianliang>

---
