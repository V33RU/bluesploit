# Reconnaissance (10)

Auto-generated from `modules/recon/`.  
Load any module with `use recon/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | CVE | Description |
|---|---|---|---|
| [`recon/adv_parser`](#reconadv_parser) | ℹ️ INFO | - | Deep BLE advertisement analysis, Apple Continuity, Eddystone, iBeacon, Fast P… |
| [`recon/ble_pairing_features`](#reconble_pairing_features) | ℹ️ INFO | - | Read SMP Pairing Features (IO cap, AuthReq, key dist) from a remote LE device |
| [`recon/ble_scan_full`](#reconble_scan_full) | ℹ️ INFO | - | Active BLE scan with full advertising payload decoding (address type, flags, … |
| [`recon/ble_target_enum`](#reconble_target_enum) | ℹ️ INFO | - | Connect to one BLE target and walk every service / characteristic / descripto… |
| [`recon/discovery`](#recondiscovery) | ℹ️ INFO | - | Passive full-spectrum Bluetooth discovery, Classic + BLE |
| [`recon/ll_features`](#reconll_features) | ℹ️ INFO | - | Read BLE Link Layer FeatureSet of a remote LE device |
| [`recon/lmp_features`](#reconlmp_features) | ℹ️ INFO | - | Read LMP feature pages of a remote BR/EDR device via HCI |
| [`recon/mesh_beacon_scan`](#reconmesh_beacon_scan) | ℹ️ INFO | - | Passive scan for Mesh Unprovisioned Device Beacons (UUID 0x1827) and Secure N… |
| [`recon/oui_lookup`](#reconoui_lookup) | ℹ️ INFO | - | Bluetooth MAC Address OUI Manufacturer Lookup |
| [`recon/sdp_enum`](#reconsdp_enum) | ℹ️ INFO | - | Advanced SDP enumerator, risk + CVE map, PnP decode, L2CAP probe |

---

## Modules

### `recon/adv_parser`

**BLE Advertisement Parser**

Deep BLE advertisement analysis, Apple Continuity, Eddystone, iBeacon, Fast Pair, risk scoring

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
- <https://www.bluetooth.com/specifications/assigned-numbers/>

---

### `recon/ble_pairing_features`

**BLE Pairing Features Probe**

Read SMP Pairing Features (IO cap, AuthReq, key dist) from a remote LE device

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BLE BD_ADDR |
| `interface` |  | `hci0` | HCI adapter |
| `addr_type` |  | `auto` | Peer address type: auto, public, or random |
| `claim_io` |  | `3` | IO capability we claim (0=DisplayOnly..4=KeyboardDisplay) |
| `claim_auth` |  | `0x0D` | auth_req we claim (hex; default Bonding\|MITM\|SC = 0x0D) |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification/>

---

### `recon/ble_scan_full`

**BLE Full Scanner**

Active BLE scan with full advertising payload decoding (address type, flags, service UUIDs, manufacturer data, service data, TX power, appearance)

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` |  | `10` | Scan duration in seconds |
| `interface` |  | `hci0` | HCI adapter (Linux only, e.g. hci0) |
| `min_rssi` |  |  | Drop devices weaker than this RSSI (e.g. -85). Empty = keep all. |

**References:**
- <https://bleak.readthedocs.io/en/latest/api/scanner.html>
- <https://www.bluetooth.com/specifications/specs/core-specification-6-0/>

---

### `recon/ble_target_enum`

**BLE Target Enumeration**

Connect to one BLE target and walk every service / characteristic / descriptor, mirage-style, with device identity header (manufacturer, chipset, LL version)

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BLE BD_ADDR |
| `interface` |  | `hci0` | HCI adapter (Linux only, e.g. hci0) |
| `timeout` |  | `20` | Connect + discover timeout in seconds |
| `read_values` |  | `True` | Read every readable characteristic value (true/false) |
| `read_descriptors` |  | `True` | Read every descriptor value (true/false) |
| `capture_identity` |  | `True` | Capture device identity header (manufacturer, chipset, LL version) from Device Information + system tools (true/false) |

**References:**
- <https://bleak.readthedocs.io/en/latest/api/client.html>
- <https://www.bluetooth.com/specifications/specs/core-specification-6-0/>

---

### `recon/discovery`

**Bluetooth Discovery**

Passive full-spectrum Bluetooth discovery, Classic + BLE

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` |  | `20` | Scan duration in seconds per phase (Classic name-resolution can be slow; bump to 30+ when many devices in range) |
| `mode` |  | `all` | Protocol: all \| ble \| classic |
| `interface` |  | `hci0` | HCI adapter (e.g. hci0) |
| `min_rssi` |  |  | Ignore BLE devices below this RSSI (e.g. -85) |
| `live` |  | `True` | Print each new device as it is discovered |
| `output_file` |  |  | Save results to JSON |

---

### `recon/ll_features`

**BLE LL FeatureSet Reader**

Read BLE Link Layer FeatureSet of a remote LE device

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BLE BD_ADDR |
| `interface` |  | `hci0` | HCI adapter |
| `addr_type` |  | `auto` | Peer address type: auto, public, or random |
| `timeout` |  | `12` | LE connect timeout (s) |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification/>

---

### `recon/lmp_features`

**LMP Features Reader**

Read LMP feature pages of a remote BR/EDR device via HCI

**Severity:** ℹ️ INFO · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BR/EDR BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `mode` |  | `full` | Mode: basic, extended, full |
| `interface` |  | `hci0` | HCI adapter |
| `max_pages` |  | `2` | Max extended feature pages to query (1-3) |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification/>

---

### `recon/mesh_beacon_scan`

**Bluetooth Mesh Beacon Scanner**

Passive scan for Mesh Unprovisioned Device Beacons (UUID 0x1827) and Secure Network Beacons (UUID 0x1828) with full PDU decoding

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` |  | `20` | Scan duration in seconds |
| `interface` |  | `hci0` | HCI adapter (Linux only, e.g. hci0) |

**References:**
- <https://www.bluetooth.com/specifications/specs/mesh-protocol/>

---

### `recon/oui_lookup`

**OUI Manufacturer Lookup**

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

**SDP Enumerator**

Advanced SDP enumerator, risk + CVE map, PnP decode, L2CAP probe

**Severity:** ℹ️ INFO · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `mode` |  | `full` | Mode: full \| browse \| records \| tree |
| `search` |  |  | Search a specific service (SP, DUN, OPP, FTP, HID, NAP, …) |
| `probe_l2cap` |  | `True` | Attempt L2CAP connect on each PSM to confirm reachability |
| `decode_pnp` |  | `True` | Decode PnP Information record (UUID 0x1200) |
| `xml_attrs` |  | `True` | Also fetch & parse XML attribute records |
| `dump_tree` |  | `False` | Append raw `sdptool records --tree` output (every attribute ID per record). Off by default; turn on for deep inspection. |
| `timeout` |  | `30` | Per-command timeout in seconds |
| `output_file` |  |  | Save the full structured report to JSON |

**References:**
- <https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/>
- <https://www.bluetooth.com/specifications/specs/device-identification-profile-1-3/>
- <https://www.bluez.org/>

---
