# Reconnaissance (6)

Auto-generated from `modules/recon/`.  
Load any module with `use recon/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | CVE | Description |
|---|---|---|---|
| [`recon/adv_parser`](#reconadv_parser) | ℹ️ INFO | — | Deep BLE advertisement data analysis |
| [`recon/discovery`](#recondiscovery) | ℹ️ INFO | — | Passive full-spectrum Bluetooth discovery — Classic + BLE |
| [`recon/gatt_enum`](#recongatt_enum) | ℹ️ INFO | — | Enumerate GATT services and characteristics |
| [`recon/oui_lookup`](#reconoui_lookup) | ℹ️ INFO | — | Bluetooth MAC Address OUI Manufacturer Lookup |
| [`recon/sdp_enum`](#reconsdp_enum) | ℹ️ INFO | — | Enumerate SDP services on Bluetooth Classic devices |
| [`recon/version_fingerprint`](#reconversion_fingerprint) | ℹ️ INFO | — | Bluetooth Device OS/Firmware Fingerprinting |

---

## Modules

### `recon/adv_parser`

**scanners/ble/adv_parser**

Deep BLE advertisement data analysis

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` |  | `15` | Scan duration (seconds) |
| `target` |  |  | Filter by BD_ADDR |
| `filter_name` |  |  | Filter by name |
| `show_raw` |  | `False` | Show raw bytes |
| `output_file` |  |  | Save to JSON |

**References:**
- <https://www.bluetooth.com/specifications/assigned-numbers/>

---

### `recon/discovery`

Passive full-spectrum Bluetooth discovery — Classic + BLE

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` |  | `15` | Scan duration in seconds |
| `mode` |  | `all` | Protocol: all \| ble \| classic |
| `interface` |  | `hci0` | HCI adapter (e.g. hci0) |
| `min_rssi` |  |  | Ignore BLE devices below this RSSI (e.g. -85) |
| `live` |  | `True` | Print each new device as it is discovered |
| `output_file` |  |  | Save results to JSON |

---

### `recon/gatt_enum`

**scanners/ble/gatt_enum**

Enumerate GATT services and characteristics

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `timeout` |  | `15` | Connection timeout in seconds |
| `read_values` |  | `True` | Attempt to read characteristic values |
| `output_file` |  |  | Save results to JSON file |

**References:**
- <https://www.bluetooth.com/specifications/gatt/>

---

### `recon/oui_lookup`

**scanners/oui_lookup**

Bluetooth MAC Address OUI Manufacturer Lookup

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | BD_ADDR or comma-separated list (XX:XX:XX:XX:XX:XX) |
| `online` |  | `False` | Use online lookup if not in database |
| `verbose` |  | `True` | Show detailed output |

**References:**
- <https://standards-oui.ieee.org/>
- <https://www.wireshark.org/tools/oui-lookup.html>

---

### `recon/sdp_enum`

**scanners/classic/sdp_enum**

Enumerate SDP services on Bluetooth Classic devices

**Severity:** ℹ️ INFO · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `mode` |  | `browse` | Browse mode: browse, records, tree |
| `search` |  |  | Search specific service (e.g., SP, DUN, FAX, OPP, FTP, HS, HF, NAP, GN) |
| `timeout` |  | `30` | Command timeout in seconds |
| `xml_output` |  | `False` | Get raw XML output |
| `output_file` |  |  | Save results to JSON file |

**References:**
- <https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/>
- <https://www.bluez.org/>

---

### `recon/version_fingerprint`

**scanners/version_fingerprint**

Bluetooth Device OS/Firmware Fingerprinting

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `protocol` |  | `auto` | Protocol: auto, classic, or ble |
| `timeout` |  | `30` | Scan timeout in seconds |

**References:**
- <https://www.bluetooth.com/specifications/assigned-numbers/>

---
