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
| [`scanners/ble_debug_ecdh`](#scannersble_debug_ecdh) | 🟠 **HIGH** | — | Detect Bluetooth devices that use the published BT SIG debug ECDH key pair — … |
| [`scanners/blueborne_scan`](#scannersblueborne_scan) | 🟠 **HIGH** | — | Scan for BlueBorne vulnerable devices (CVE-2017-*) |
| [`scanners/hidden_scanner`](#scannershidden_scanner) | ℹ️ INFO | CVE-2022-24695 | Find Non-Discoverable Bluetooth Devices |
| [`scanners/vuln_scan`](#scannersvuln_scan) | 🟠 **HIGH** | — | BLE GATT vulnerability scanner — unauth writes, info leaks, sensitive UUIDs |
| [`scanners/vuln_scanner`](#scannersvuln_scanner) | ℹ️ INFO | — | Automatic Bluetooth Vulnerability Detection |

---

## Modules

### `scanners/ble_debug_ecdh`

**BLE Debug ECDH Key Detection**

Detect Bluetooth devices that use the published BT SIG debug ECDH key pair — production-broken Secure Connections

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

Find Non-Discoverable Bluetooth Devices

**Severity:** ℹ️ INFO · **Protocol:** BOTH · **CVE:** [CVE-2022-24695](https://nvd.nist.gov/vuln/detail/CVE-2022-24695)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` |  |  | Specific BD_ADDR or OUI prefix to scan |
| `mode` |  | `name_req` | Mode: name_req, connect, oui, range, or all |
| `oui` |  |  | Specific OUI to scan (XX:XX:XX) |
| `range_start` |  | `00:00:00` | Start of range (last 3 bytes, e.g., 00:00:00) |
| `range_count` |  | `256` | Number of addresses to scan in range |
| `threads` |  | `10` | Number of concurrent threads |
| `timeout` |  | `5` | Timeout per device in seconds |

**References:**
- <https://www.bluetooth.com/specifications/>
- <https://nvd.nist.gov/vuln/detail/CVE-2022-24695>

---

### `scanners/vuln_scan`

**scanners/ble_vuln_scan**

BLE GATT vulnerability scanner — unauth writes, info leaks, sensitive UUIDs

**Severity:** 🟠 **HIGH** · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `timeout` |  | `15` | Connection timeout in seconds |
| `test_writes` |  | `False` | Actually test write operations (may modify device state) |
| `deep_scan` |  | `True` | Perform deep analysis including info disclosure reads (slower) |
| `output_file` |  |  | Save results to JSON file |

**References:**
- <https://www.usenix.org/conference/usenixsecurity19/presentation/wu-jianliang>
- <https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/>

---

### `scanners/vuln_scanner`

Automatic Bluetooth Vulnerability Detection

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `thorough` |  | `True` | Perform thorough scan (slower) |
| `timeout` |  | `60` | Scan timeout in seconds |

**References:**
- <https://nvd.nist.gov/>
- <https://www.bluetooth.com/security/>

---
