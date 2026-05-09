# Reconnaissance (5)

Auto-generated from `modules/recon/`.  
Load any module with `use recon/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | Protocol | Description |
|---|---|---|---|
| [`recon/adv_parser`](#reconadv_parser) | ℹ️ INFO | BLE | Deep BLE advertisement data analysis |
| [`recon/discovery`](#recondiscovery) | ℹ️ INFO | Both | Passive full-spectrum Bluetooth discovery — Classic + BLE |
| [`recon/gatt_enum`](#recongatt_enum) | ℹ️ INFO | BLE | GATT enumerator with device identity, chipset detection, LL version |
| [`recon/oui_lookup`](#reconoui_lookup) | ℹ️ INFO | Both | Bluetooth MAC address OUI manufacturer lookup |
| [`recon/sdp_enum`](#reconsdp_enum) | ℹ️ INFO | Classic | Advanced SDP enumerator — risk scoring, CVE map, PnP decode, L2CAP probe |

---

## Modules

### `recon/adv_parser`

**BLE Advertisement Parser**

Passive BLE scanner that decodes every advertisement packet in detail:
Apple Continuity sub-types, Microsoft Swift Pair, Google Fast Pair,
Eddystone-URL/UID, iBeacon, manufacturer data, service UUIDs, TX power,
and RSSI. Optionally filter by BD_ADDR or device name.

**Severity:** ℹ️ INFO · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` | | `15` | Scan duration in seconds |
| `target` | | | Filter by BD_ADDR |
| `filter_name` | | | Filter by device name |
| `show_raw` | | `False` | Show raw manufacturer data bytes |
| `output_file` | | | Save results to JSON |

**References:**
- <https://www.bluetooth.com/specifications/assigned-numbers/>

---

### `recon/discovery`

**Full-Spectrum Bluetooth Discovery Scanner**

Passive discovery for Classic BR/EDR and BLE. BLE and Classic scans run
**sequentially** on the same adapter to avoid BlueZ `Operation already in
progress` conflicts.

**Severity:** ℹ️ INFO · **Protocol:** BOTH

#### Scan sequence (mode = all)

```
[1/2] BLE scan   — bleak BleakScanner, duration seconds
      ↓ adapter released
[2/2] BR/EDR inquiry — hcitool inq + hcitool scan, duration seconds
```

With `mode=ble` or `mode=classic` only one phase runs.

#### What is extracted passively

| Source | Data extracted |
|---|---|
| Manufacturer data | Apple product type (AirPods, Watch, FindMy…), iBeacon UUID/Major/Minor, Microsoft Swift Pair |
| Service UUIDs | Device class (HeartRate, HID, DFU, Mesh…), risky service flags |
| Service data | Eddystone-URL / Eddystone-UID decoded |
| BLE flags byte | Discoverable mode, cross-transport (BR/EDR + LE) |
| RSSI 6-sample avg | Stable distance estimate via log-distance path-loss model |
| Address type | public / random (static / RPA / NRPA) |

Risky services (DFU, HID, Mesh Provisioning) are flagged with `!` in the live table.

#### Options

| Option | Required | Default | Description |
|---|---|---|---|
| `timeout` | | `15` | Scan duration per phase in seconds |
| `mode` | | `all` | Protocol: all \| ble \| classic |
| `interface` | | `hci0` | HCI adapter |
| `min_rssi` | | | Ignore BLE devices below this RSSI (dBm) |
| `live` | | `True` | Print each new device as it is discovered |
| `output_file` | | | Save results to JSON |

---

### `recon/gatt_enum`

**GATT Enumerator + Device Identity**

Connects over BLE GATT, prints a full device identity header, then
enumerates every service and characteristic with properties, handles,
and live-read values.

**Severity:** ℹ️ INFO · **Protocol:** BLE

#### Device identity header

Before the GATT table the module collects and displays:

| Field | Source |
|---|---|
| BD_ADDR | Target address |
| Address Type | BlueZ D-Bus device record |
| Device Name | `BleakScanner.find_device_by_address` → advertising `local_name`; fallback to `bluetoothctl info` |
| Appearance | `bluetoothctl info` cached record |
| Manufacturer | GATT 0x2A29 (Manufacturer Name characteristic) |
| Model | GATT 0x2A24 |
| Serial | GATT 0x2A25 |
| Firmware | GATT 0x2A26 |
| Hardware | GATT 0x2A27 |
| Software | GATT 0x2A28 |
| System ID | GATT 0x2A23 |
| PnP ID | GATT 0x2A50 — decoded: vendor ID source, vendor name, product ID, version |
| Chipset | PnP vendor ID → lookup table; fallback: manufacturer string pattern match; fallback: OUI prefix lookup |
| LL/LMP Version | `hcitool leinfo` (BLE LE connection) → `hcitool info` (Classic fallback) |

#### LL / chipset detection priority

```
1. hcitool leinfo <addr>   — LE connection, reads remote version (needs CAP_NET_RAW)
   Subversion 0x8762 → Realtek RTL8762
   Subversion 0x000D → Nordic nRF52840  … (12 known subversions)

2. hcitool info <addr>     — Classic BR/EDR inquiry (Dual devices)

3. bluetoothctl info <addr> — BlueZ cached record, no root needed
                              → device Name + Appearance
```

All three fall back silently. The LL version line only appears when at least one source succeeds.

#### GATT characteristics table

Each characteristic row shows: UUID, human-readable name, properties
(`R W WNR N I`), handle, and live-read value (when `read_values=True`).
Writable characteristics are highlighted yellow; notify/indicate magenta.

Summary sections at the bottom list:

- All writable characteristics (attack surface)
- All notify/indicate characteristics

#### Options

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ | | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `timeout` | | `15` | Connection timeout in seconds |
| `read_values` | | `True` | Attempt to read characteristic values |
| `output_file` | | | Save results to JSON |

**References:**
- <https://www.bluetooth.com/specifications/gatt/>

---

### `recon/oui_lookup`

**OUI Manufacturer Lookup**

Look up the IEEE OUI prefix of one or more Bluetooth BD_ADDRs to identify
the manufacturer. Supports optional online lookup for addresses not in the
local database.

**Severity:** ℹ️ INFO · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ | | BD_ADDR or comma-separated list |
| `online` | | `False` | Use online lookup if not in local database |
| `verbose` | | `True` | Show detailed output |

**References:**
- <https://standards-oui.ieee.org/>

---

### `recon/sdp_enum`

**Advanced SDP Enumerator**

Deep enumeration of the Classic Bluetooth SDP catalogue on a target device.
Goes well beyond plain `sdptool browse` — annotates every service with a
risk tier and CVE list, decodes PnP Information records, probes L2CAP PSMs
for reachability, and parses XML attribute records.

!!! note "Classic only"
    SDP runs over L2CAP PSM 0x0001 (BR/EDR). For BLE devices use
    `recon/gatt_enum` instead.

**Severity:** ℹ️ INFO · **Protocol:** CLASSIC

#### Risk annotation

Services are matched against a curated UUID → risk table covering:

HID (CVE-2023-45866), BNEP/PAN (BlueBorne CVE-2017-0781), OBEX FTP/OPP
(BlueSnarfing), HFP/HSP (AT-command RCE), PBAP/MAP/SIM Access (privacy
leak), A2DP/AVRCP (BlueFrag CVE-2020-0022), SDP itself (CVE-2017-0785),
and more.

#### Options

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ | | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `mode` | | `full` | Mode: full \| browse \| records \| tree |
| `search` | | | Search a specific service (SP, DUN, OPP, FTP, HID, NAP…) |
| `probe_l2cap` | | `True` | Attempt L2CAP connect on each PSM to confirm reachability |
| `decode_pnp` | | `True` | Decode PnP Information record (UUID 0x1200) |
| `xml_attrs` | | `True` | Parse XML attribute records |
| `timeout` | | `30` | Per-command timeout in seconds |
| `output_file` | | | Save structured report to JSON |

**References:**
- <https://www.bluetooth.com/specifications/assigned-numbers/service-discovery/>
- <https://www.bluetooth.com/specifications/specs/device-identification-profile-1-3/>
- <https://www.bluez.org/>

---
