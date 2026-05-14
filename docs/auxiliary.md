# Auxiliary (14)

Auto-generated from `modules/auxiliary/`.  
Load any module with `use auxiliary/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | CVE | Description |
|---|---|---|---|
| [`auxiliary/ble_fuzzer`](#auxiliaryble_fuzzer) | 🟡 MEDIUM | - | Fuzz BLE ATT/GATT/SMP layers to find crashes and vulnerabilities |
| [`auxiliary/ble_rpa_deanon`](#auxiliaryble_rpa_deanon) | 🟡 MEDIUM | CVE-2020-35473 | Exploit BLE RPA response side-channel to track and de-anonymize devices acros… |
| [`auxiliary/btlejack_capture`](#auxiliarybtlejack_capture) | 🟠 **HIGH** | - | BTLEJack BLE connection following, hijacking, and injection |
| [`auxiliary/btsnoop_collect`](#auxiliarybtsnoop_collect) | ℹ️ INFO | - | Enable, pull, or watch Android's Bluetooth HCI snoop log via ADB |
| [`auxiliary/crypto/irk_entropy`](#auxiliarycryptoirk_entropy) | ℹ️ INFO | - | Analyze a 16-byte IRK for entropy + run the Core Spec `ah` resolution against… |
| [`auxiliary/crypto/key_quality`](#auxiliarycryptokey_quality) | ℹ️ INFO | - | Statistical quality analysis of a hex-encoded BLE key blob (LTK, IRK, link ke… |
| [`auxiliary/crypto/passkey_check`](#auxiliarycryptopasskey_check) | ℹ️ INFO | - | Audit a 6-digit BLE Passkey for weak / sequential / repeated patterns |
| [`auxiliary/hw_detect`](#auxiliaryhw_detect) | ℹ️ INFO | - | Detect connected Bluetooth testing hardware and check dependencies |
| [`auxiliary/incoming_monitor`](#auxiliaryincoming_monitor) | ℹ️ INFO | - | Print incoming BR/EDR + BLE connection attempts from nearby devices |
| [`auxiliary/local_spoof`](#auxiliarylocal_spoof) | ℹ️ INFO | - | Spoof local adapter hostname, alias, Class of Device, or BD_ADDR |
| [`auxiliary/mesh/mesh_pdu_decode`](#auxiliarymeshmesh_pdu_decode) | ℹ️ INFO | - | Offline decoder for a captured Bluetooth Mesh Network PDU using K2 and AES-CCM |
| [`auxiliary/nrf_sniffer`](#auxiliarynrf_sniffer) | ℹ️ INFO | - | nRF52840 dongle BLE passive sniffer wrapper |
| [`auxiliary/stealtooth_breaktooth`](#auxiliarystealtooth_breaktooth) | 🟠 **HIGH** | - | Infer BT session state via l2ping RTT timing without pairing; auto-trigger re… |
| [`auxiliary/ubertooth_sniff`](#auxiliaryubertooth_sniff) | ℹ️ INFO | - | Ubertooth One BLE/Classic passive sniffing wrapper |

---

## Modules

### `auxiliary/ble_fuzzer`

**BLE Protocol Fuzzer**

Fuzz BLE ATT/GATT/SMP layers to find crashes and vulnerabilities

**Severity:** 🟡 MEDIUM · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BLE device MAC address |
| `protocol` |  | `att` | Protocol layer to fuzz: att, smp, l2cap, all |
| `strategy` |  | `smart` | Fuzzing strategy: random, smart, overflow, boundary |
| `iterations` |  | `100` | Number of fuzz iterations |
| `delay` |  | `0.1` | Delay between fuzz packets in seconds |
| `seed` |  |  | Random seed for reproducible fuzzing |
| `log_file` |  |  | Log file for fuzz results |
| `crash_detect` |  | `true` | Attempt to detect target crashes via reconnect (true/false) |

**References:**
- <https://asset-group.github.io/disclosures/sweyntooth/>
- <https://dl.acm.org/doi/10.1145/3395351.3399355>

---

### `auxiliary/ble_rpa_deanon`

**BLE RPA De-anonymization (CVE-2020-35473)**

Exploit BLE RPA response side-channel to track and de-anonymize devices across address rotations without knowing their IRK

**Severity:** 🟡 MEDIUM · **Protocol:** BLE · **CVE:** [CVE-2020-35473](https://nvd.nist.gov/vuln/detail/CVE-2020-35473)

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `observe` | Mode: observe, probe, correlate |
| `duration` |  | `120` | Observation/probe duration in seconds |
| `output_file` |  | `rpa_database.json` | JSON database file to save/load RPA fingerprints |
| `interface` |  | `hci0` | HCI adapter |
| `target_fingerprint` |  |  | Known fingerprint string to track (correlate mode) |
| `min_appearances` |  | `2` | Min RPA appearances to include in analysis |

**References:**
- <https://www.bluetooth.com/learn-about-bluetooth/key-attributes/bluetooth-security/report-vulnerability/>
- <https://arxiv.org/abs/2004.11196>
- <https://petsymposium.org/2021/files/papers/issue3/popets-2021-0036.pdf>

---

### `auxiliary/btlejack_capture`

**BTLEJack Capture**

BTLEJack BLE connection following, hijacking, and injection

**Severity:** 🟠 **HIGH** · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` |  | `scan` | Mode: scan, follow, hijack, inject |
| `target` |  |  | Target BLE MAC or access address |
| `access_address` |  |  | BLE connection access address (hex) |
| `duration` |  | `30` | Capture duration in seconds |
| `pcap_file` |  |  | PCAP output file |
| `inject_data` |  |  | Hex data to inject (for inject mode) |
| `channel_map` |  |  | Channel map for connection following (hex) |

**References:**
- <https://github.com/virtualabs/btlejack>
- <https://www.youtube.com/watch?v=wIGiZKiBmbg>

---

### `auxiliary/btsnoop_collect`

**Android btsnoop Collector**

Enable, pull, or watch Android's Bluetooth HCI snoop log via ADB

**Severity:** ℹ️ INFO · **Protocol:** DUAL

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `full` | Mode: enable, disable, pull, full, watch |
| `device` |  |  | ADB serial (default: first connected device) |
| `output` |  | `/tmp/btsnoop_hci.log` | Local output PCAP/log path |
| `remote_path` |  |  | Override remote snoop path (auto-detect if empty) |
| `capture_seconds` |  | `30` | Wait time after enable before pull (full mode) |

---

### `auxiliary/crypto/irk_entropy`

**IRK Entropy + RPA Resolution**

Analyze a 16-byte IRK for entropy + run the Core Spec `ah` resolution against observed Resolvable Private Addresses

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `irk` | ✓ |  | 16-byte IRK as hex (colons / 0x prefix accepted) |
| `byte_order` |  | `msb` | IRK byte order: msb (spec text) or lsb (over-the-air, common in btsnoop) |
| `rpas` |  |  | Comma-separated RPA list to test resolution against. Empty = use hosts from the workspace. |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification-6-0/>

---

### `auxiliary/crypto/key_quality`

**Key Quality Analyzer**

Statistical quality analysis of a hex-encoded BLE key blob (LTK, IRK, link key, CSRK)

**Severity:** ℹ️ INFO · **Protocol:** DUAL

| Option | Required | Default | Description |
|---|---|---|---|
| `key` | ✓ |  | Key bytes as hex (with or without colons / 0x prefix) |
| `expected_length` |  |  | Expected byte length (e.g. 16 for AES-128 keys). Empty = accept any length. |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification-6-0/>
- <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-22r1a.pdf>

---

### `auxiliary/crypto/passkey_check`

**Passkey Quality Check**

Audit a 6-digit BLE Passkey for weak / sequential / repeated patterns

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `passkey` | ✓ |  | 6-digit passkey to audit (digits only) |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification-6-0/>
- <https://www.usenix.org/conference/woot13/workshop-program/presentation/ryan>

---

### `auxiliary/hw_detect`

Detect connected Bluetooth testing hardware and check dependencies

**Severity:** ℹ️ INFO · **Protocol:** DUAL

| Option | Required | Default | Description |
|---|---|---|---|
| `verbose` |  | `True` | Show detailed info including install hints |
| `check_deps` |  | `True` | Check system tools and Python packages for each device |

**References:**
- <https://ubertooth.readthedocs.io/>
- <https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Sniffer-for-Bluetooth-LE>
- <https://github.com/virtualabs/btlejack>

---

### `auxiliary/incoming_monitor`

**Incoming Connection Monitor**

Print incoming BR/EDR + BLE connection attempts from nearby devices

**Severity:** ℹ️ INFO · **Protocol:** DUAL

| Option | Required | Default | Description |
|---|---|---|---|
| `interface` |  | `hci0` | HCI adapter to monitor |
| `duration` |  | `0` | Monitor window in seconds (0 = run until Ctrl+C) |
| `discoverable` |  | `true` | Make adapter discoverable + connectable to attract probes |
| `auto_reject` |  | `true` | Auto-reject incoming BR/EDR connections (passive listen) |

---

### `auxiliary/local_spoof`

**Local Adapter Spoof**

Spoof local adapter hostname, alias, Class of Device, or BD_ADDR

**Severity:** ℹ️ INFO · **Protocol:** DUAL

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `hostname` | What to spoof: hostname, alias, cod, bdaddr |
| `value` | ✓ |  | New value (string for hostname/alias, hex for CoD, MAC for bdaddr) |
| `interface` |  | `hci0` | HCI adapter |
| `restart` |  | `true` | Restart the adapter after spoof (true/false) |

---

### `auxiliary/mesh/mesh_pdu_decode`

**Mesh Network PDU Decoder**

Offline decoder for a captured Bluetooth Mesh Network PDU using K2 and AES-CCM

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `pdu` | ✓ |  | Encrypted Mesh Network PDU as hex (IVI \|\| NID \|\| obfuscated header \|\| encrypted DST/TransportPDU \|\| NetMIC) |
| `netkey` | ✓ |  | 16-byte NetKey as hex |
| `iv_index` |  | `0x12345678` | 32-bit IV Index (hex or decimal). Defaults to 0x12345678. |

**References:**
- <https://www.bluetooth.com/specifications/specs/mesh-protocol/>

---

### `auxiliary/nrf_sniffer`

**nRF52840 Sniffer**

nRF52840 dongle BLE passive sniffer wrapper

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` |  | `scan` | Mode: scan, follow, capture |
| `target` |  |  | Target BLE MAC to follow (AA:BB:CC:DD:EE:FF) |
| `serial_port` |  |  | nRF Sniffer serial port (e.g., /dev/ttyACM0) |
| `duration` |  | `30` | Capture duration in seconds |
| `pcap_file` |  |  | PCAP output file for Wireshark |
| `channel` |  | `all` | BLE channel to scan (37-39 for adv, 0-36 for data, 'all' for hopping) |
| `rssi_filter` |  |  | Minimum RSSI to report (e.g., -60) |

**References:**
- <https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le>
- <https://infocenter.nordicsemi.com/topic/ug_sniffer_ble/UG/sniffer_ble/intro.html>

---

### `auxiliary/stealtooth_breaktooth`

**Stealtooth + Breaktooth**

Infer BT session state via l2ping RTT timing without pairing; auto-trigger re-pair injection on state drop (arxiv 2507.00847)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `monitor` | Mode: monitor, trigger, breaktooth |
| `target` | ✓ |  | Target Bluetooth BD_ADDR to monitor |
| `duration` |  | `300` | Monitoring duration in seconds (0 = indefinite) |
| `probe_interval_ms` |  | `500` | Interval between l2ping probes in milliseconds |
| `window_size` |  | `8` | RTT samples per state classification window |
| `trigger_state` |  | `disconnected` | State transition that fires the trigger (e.g. 'disconnected', 'idle') |
| `impersonate_addr` |  |  | BD_ADDR to spoof when re-pair fires (breaktooth mode) |
| `interface` |  | `hci0` | Local HCI adapter (for breaktooth re-pair) |
| `output_file` |  |  | JSONL log of state transitions |

**References:**
- <https://arxiv.org/html/2507.00847v1>
- <https://www.scitepress.org/Papers/2024/128457/128457.pdf>

---

### `auxiliary/ubertooth_sniff`

**Ubertooth Sniffer**

Ubertooth One BLE/Classic passive sniffing wrapper

**Severity:** ℹ️ INFO · **Protocol:** DUAL

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` |  | `ble` | Sniff mode: ble, classic, follow, spectrum |
| `target` |  |  | Target MAC for follow mode (AA:BB:CC:DD:EE:FF) |
| `channel` |  | `37` | BLE advertising channel (37, 38, 39) or Classic channel (0-78) |
| `duration` |  | `30` | Capture duration in seconds (0 = indefinite) |
| `pcap_file` |  |  | PCAP output file for captured packets |
| `ubertooth_device` |  | `0` | Ubertooth device number (for multiple dongles) |
| `access_address` |  |  | BLE access address to follow (hex, e.g. 8e89bed6) |

**References:**
- <https://ubertooth.sourceforge.net/>
- <https://github.com/greatscottgadgets/ubertooth>

---
