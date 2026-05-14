# Denial of Service (29)

Auto-generated from `modules/dos/`.  
Load any module with `use dos/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | CVE | Description |
|---|---|---|---|
| [`dos/a2dp_flood`](#dosa2dp_flood) | 🟠 **HIGH** | - | Flood Bluetooth audio devices by opening and abandoning AVDTP signaling conne… |
| [`dos/ambicom_obex_bof`](#dosambicom_obex_bof) | 🟠 **HIGH** | - | AmbiCom Blue Neighbors OBEX Push buffer overflow (EDB-27094) |
| [`dos/blueborne_l2cap_dos`](#dosblueborne_l2cap_dos) | 🟠 **HIGH** | CVE-2017-1000251 | BlueBorne Linux L2CAP config DoS (CVE-2017-1000251 / EDB-42762) |
| [`dos/bluesmack`](#dosbluesmack) | 🟡 MEDIUM | - | BlueSmack - L2CAP Echo Flood DoS Attack |
| [`dos/bnep_setup_oob_read`](#dosbnep_setup_oob_read) | 🟠 **HIGH** | CVE-2017-13266 | Android BNEP setup-connection-request OOB read DoS (EDB-44327) |
| [`dos/bt_phy_jam`](#dosbt_phy_jam) | 🟠 **HIGH** | - | Radio-layer denial of Bluetooth/BLE channels via Ubertooth, HackRF, or Killer… |
| [`dos/denial_of_pleasure`](#dosdenial_of_pleasure) | 🟡 MEDIUM | - | Replay BLE advertisement control packets to DoS or activate devices using una… |
| [`dos/l2ping_flood`](#dosl2ping_flood) | 🟠 **HIGH** | - | L2CAP ping flood DoS attack (BlueSmack) |
| [`dos/linux_hci_signed_proto`](#doslinux_hci_signed_proto) | 🟢 LOW | - | Linux kernel AF_BLUETOOTH signed proto DoS (EDB-25287) |
| [`dos/macos_bluetoothd_mig`](#dosmacos_bluetoothd_mig) | 🟠 **HIGH** | - | macOS bluetoothd MIG add-callback session hijack (EDB-44215, native ObjC) |
| [`dos/macos_iobt_createconnection`](#dosmacos_iobt_createconnection) | 🟠 **HIGH** | - | macOS DispatchHCICreateConnection IOMalloc-fail panic (EDB-35771, native C) |
| [`dos/macos_iobt_oob_demux`](#dosmacos_iobt_oob_demux) | 🟠 **HIGH** | - | macOS IOBluetooth SimpleDispatchWL OOB demux (EDB-39372, native C) |
| [`dos/macos_iobt_packetlog_race`](#dosmacos_iobt_packetlog_race) | 🟠 **HIGH** | - | macOS PacketLog OSArray no-more-senders race (EDB-39371, native C) |
| [`dos/macos_iobt_readlocalname`](#dosmacos_iobt_readlocalname) | 🟠 **HIGH** | - | macOS DispatchHCIReadLocalName stack-canary overflow (EDB-35772, native C) |
| [`dos/macos_iobt_simpledispatch`](#dosmacos_iobt_simpledispatch) | 🟠 **HIGH** | - | macOS IOBluetoothHCI SimpleDispatchWL sign-check (EDB-35153, native C) |
| [`dos/macos_iobt_transferacl`](#dosmacos_iobt_transferacl) | 🟠 **HIGH** | - | macOS TransferACLPacketToHW panic (EDB-35773, native C) |
| [`dos/macos_iobt_uaf`](#dosmacos_iobt_uaf) | 🟠 **HIGH** | - | macOS IOBluetoothHCIUserClient task-struct UAF (EDB-40652, native C) |
| [`dos/macos_iobt_writestoredlinkkey`](#dosmacos_iobt_writestoredlinkkey) | 🟠 **HIGH** | - | macOS DispatchHCIWriteStoredLinkKey heap overflow (EDB-35774, native C) |
| [`dos/nest_cam_ble_bof`](#dosnest_cam_ble_bof) | 🟠 **HIGH** | - | Nest Cam BLE GATT setup-channel buffer overflow (EDB-41643) |
| [`dos/nokia_affix_signed_proto`](#dosnokia_affix_signed_proto) | 🟢 LOW | - | Nokia Affix BT stack signed-proto DoS (EDB-25525) |
| [`dos/nokia_bluetab_nickname`](#dosnokia_bluetab_nickname) | 🟢 LOW | - | Nokia/Symbian Bluetooth nickname crash file generator (EDB-856) |
| [`dos/notify_flood`](#dosnotify_flood) | 🟡 MEDIUM | - | BLE Notification/GATT Flood DoS Attack |
| [`dos/rfcomm_check_security_null`](#dosrfcomm_check_security_null) | 🟠 **HIGH** | CVE-2024-26903 | Remote kernel NULL pointer dereference in rfcomm_check_security() (CVE-2024-2… |
| [`dos/rfcomm_flood`](#dosrfcomm_flood) | 🟡 MEDIUM | - | RFCOMM Connection Exhaustion DoS Attack |
| [`dos/rfcomm_msc_flood`](#dosrfcomm_msc_flood) | 🟡 MEDIUM | - | High-rate MSC frame flood across HFP and auxiliary RFCOMM channels causing re… |
| [`dos/rfcomm_state_change_deadlock`](#dosrfcomm_state_change_deadlock) | 🟠 **HIGH** | CVE-2024-50044 | Triggers kernel RFCOMM worker thread deadlock via concurrent conflicting stat… |
| [`dos/sdp_flood`](#dossdp_flood) | 🟡 MEDIUM | - | SDP Service Discovery Flood DoS Attack |
| [`dos/sony_ericsson_reset_display`](#dossony_ericsson_reset_display) | 🟡 MEDIUM | - | Sony/Ericsson L2CAP ECHO_REQ display-fade DoS (EDB-1473) |
| [`dos/xiaomi_rfcomm_dlci_flood`](#dosxiaomi_rfcomm_dlci_flood) | 🟡 MEDIUM | CVE-2025-13328 | Firmware crash via RFCOMM DLCI 0 resource exhaustion on Xiaomi Redmi Buds (CV… |

---

## Modules

### `dos/a2dp_flood`

**A2DP / AVDTP Connection Flood**

Flood Bluetooth audio devices by opening and abandoning AVDTP signaling connections, disrupting audio streaming

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR of audio device (XX:XX:XX:XX:XX:XX) |
| `interface` |  | `hci0` | Local HCI adapter |
| `threads` |  | `8` | Concurrent flood threads |
| `iterations` |  | `150` | Open/abort cycles per thread |
| `flood_avctp` |  | `true` | Also flood AVCTP PSM 0x0017 (true/false) |
| `send_discover` |  | `true` | Send AVDTP Discover before aborting (true/false) |
| `timeout` |  | `5` | Per-connection timeout in seconds |

**References:**
- <https://www.bluetooth.com/specifications/specs/a2dp-1-3-2/>
- <https://www.bluetooth.com/specifications/specs/avdtp-1-3/>

---

### `dos/ambicom_obex_bof`

AmbiCom Blue Neighbors OBEX Push buffer overflow (EDB-27094)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR running AmbiCom OPUSH |
| `channel` |  | `1` | RFCOMM channel for OBEX Push (default 1) |
| `length` |  | `261` | Number of 'A' characters before the 'ZZ' overflow marker |

**References:**
- <https://www.exploit-db.com/exploits/27094>
- <https://www.securityfocus.com/bid/16258>

---

### `dos/blueborne_l2cap_dos`

BlueBorne Linux L2CAP config DoS (CVE-2017-1000251 / EDB-42762)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC · **CVE:** [CVE-2017-1000251](https://nvd.nist.gov/vuln/detail/CVE-2017-1000251)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (vulnerable Linux host) |
| `psm` |  | `1` | L2CAP PSM (default 1 = SDP) |
| `options_count` |  | `70` | Number of bogus options to pack into CONF_RSP |

**References:**
- <https://www.exploit-db.com/exploits/42762>
- <https://www.armis.com/blueborne/>
- <https://nvd.nist.gov/vuln/detail/CVE-2017-1000251>

---

### `dos/bluesmack`

**exploits/dos/classic/bluesmack**

BlueSmack - L2CAP Echo Flood DoS Attack

**Severity:** 🟡 MEDIUM · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `size` |  | `600` | Echo packet size in bytes (max 65535) |
| `count` |  | `1000` | Number of packets to send (0 = infinite) |
| `delay` |  | `0` | Delay between packets in ms (0 = no delay) |
| `timeout` |  | `10` | Connection timeout in seconds |

**References:**
- <https://trifinite.org/trifinite_stuff_bluesmack.html>
- <https://www.bluetooth.com/specifications/specs/core-specification/>

---

### `dos/bnep_setup_oob_read`

Android BNEP setup-connection-request OOB read DoS (EDB-44327)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC · **CVE:** [CVE-2017-13266](https://nvd.nist.gov/vuln/detail/CVE-2017-13266)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (Android < March 2018) |
| `src_bdaddr` |  | `` | Local source BD_ADDR (optional, pybluez auto-selects) |
| `count` |  | `1` | Number of malformed packets to send |

**References:**
- <https://www.exploit-db.com/exploits/44327>
- <https://source.android.com/security/bulletin/2018-03-01>

---

### `dos/bt_phy_jam`

**PHY-Level Bluetooth Jamming**

Radio-layer denial of Bluetooth/BLE channels via Ubertooth, HackRF, or KillerBee, kills connections and prevents new pairings

**Severity:** 🟠 **HIGH** · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `method` | ✓ | `ubertooth` | Jamming method: ubertooth, hackrf, killerbee, hci_loop |
| `mode` | ✓ | `adv_only` | Mode: adv_only, data_chan, full_band, follow |
| `channel` |  | `37` | BLE channel 0-39 (data_chan/follow mode) |
| `target` |  |  | Target BD_ADDR (follow mode) |
| `duration` |  | `60` | Jam duration in seconds (0 = until Ctrl+C) |
| `device` |  | `0` | Hardware device index (Ubertooth/HackRF index) |
| `tx_gain` |  | `40` | HackRF TX gain (0-47) |
| `interface` |  | `hci0` | HCI adapter (hci_loop method) |

**References:**
- <https://github.com/greatscottgadgets/ubertooth>
- <https://greatscottgadgets.com/hackrf/>
- <https://github.com/riverloopsec/killerbee>

---

### `dos/denial_of_pleasure`

**Denial of Pleasure**

Replay BLE advertisement control packets to DoS or activate devices using unauthenticated broadcast commands (CVE-less, protocol design flaw)

**Severity:** 🟡 MEDIUM · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `mode` | ✓ | `check` | Mode: check, scan, replay, stop |
| `interface` |  | `hci0` | Local HCI adapter |
| `payload_hex` |  |  | Captured advertisement payload hex (max 31 bytes). Example: 0201060e095645524f204352 ... |
| `duration` |  | `30` | Replay / scan duration in seconds |
| `interval_ms` |  | `100` | Advertisement interval in ms (lower = faster flood) |
| `filter_addr` |  |  | Scan mode: only print adverts from this BD_ADDR |

**References:**
- <https://mandomat.github.io/2023-11-13-denial-of-pleasure/>

---

### `dos/l2ping_flood`

**exploits/classic/l2ping_flood**

L2CAP ping flood DoS attack (BlueSmack)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `interface` |  | `hci0` | Bluetooth interface (hci0, hci1, etc.) |
| `size` |  | `600` | L2CAP packet size (bytes, max 65535) |
| `count` |  | `0` | Number of packets (0 = infinite until stopped) |
| `flood` |  | `True` | Enable flood mode (no delay between packets) |
| `threads` |  | `1` | Number of parallel flood threads |
| `mode` |  | `single` | Attack mode: single, multi, burst, adaptive |
| `duration` |  | `0` | Attack duration in seconds (0 = until Ctrl+C) |
| `burst_count` |  | `100` | Packets per burst (burst mode) |
| `burst_delay` |  | `500` | Delay between bursts in ms (burst mode) |
| `reverse` |  | `False` | Reverse ping (request echo from target) |
| `timeout` |  | `1` | Response timeout in seconds |

**References:**
- <https://trifinite.org/trifinite_stuff_bluesmack.html>
- <CVE-2006-6019>

---

### `dos/linux_hci_signed_proto`

Linux kernel AF_BLUETOOTH signed proto DoS (EDB-25287)

**Severity:** 🟢 LOW · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `proto` |  | `NEG_PROTO` | Negative protocol number to pass to socket() |

**References:**
- <https://www.exploit-db.com/exploits/25287>
- <https://www.securityfocus.com/bid/12911>

---

### `dos/macos_bluetoothd_mig`

macOS bluetoothd MIG add-callback session hijack (EDB-44215, native ObjC)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/44215>

---

### `dos/macos_iobt_createconnection`

macOS DispatchHCICreateConnection IOMalloc-fail panic (EDB-35771, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/35771>

---

### `dos/macos_iobt_oob_demux`

macOS IOBluetooth SimpleDispatchWL OOB demux (EDB-39372, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `iterations` |  | `1` | How many times to launch the binary (race amplification) |

**References:**
- <https://www.exploit-db.com/exploits/39372>
- <https://bugs.chromium.org/p/project-zero/issues/detail?id=569>

---

### `dos/macos_iobt_packetlog_race`

macOS PacketLog OSArray no-more-senders race (EDB-39371, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `iterations` |  | `200` | How many race attempts to fire (PoC says: while true) |

**References:**
- <https://www.exploit-db.com/exploits/39371>
- <https://bugs.chromium.org/p/project-zero/issues/detail?id=572>

---

### `dos/macos_iobt_readlocalname`

macOS DispatchHCIReadLocalName stack-canary overflow (EDB-35772, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/35772>

---

### `dos/macos_iobt_simpledispatch`

macOS IOBluetoothHCI SimpleDispatchWL sign-check (EDB-35153, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/35153>

---

### `dos/macos_iobt_transferacl`

macOS TransferACLPacketToHW panic (EDB-35773, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/35773>

---

### `dos/macos_iobt_uaf`

macOS IOBluetoothHCIUserClient task-struct UAF (EDB-40652, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/40652>
- <https://bugs.chromium.org/p/project-zero/issues/detail?id=830>

---

### `dos/macos_iobt_writestoredlinkkey`

macOS DispatchHCIWriteStoredLinkKey heap overflow (EDB-35774, native C)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC

**References:**
- <https://www.exploit-db.com/exploits/35774>

---

### `dos/nest_cam_ble_bof`

Nest Cam BLE GATT setup-channel buffer overflow (EDB-41643)

**Severity:** 🟠 **HIGH** · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (Nest Cam, advertises BLE) |
| `variant` |  | `ssid` | Overflow variant: ssid \| encpass |
| `handle` |  | `NEST_HANDLE` | GATT char handle (default 0xFFFD) |
| `length` |  | `16` | Number of overflow bytes for ssid variant |
| `timeout` |  | `15` | Connection timeout (seconds) |

**References:**
- <https://www.exploit-db.com/exploits/41643>
- <https://github.com/jasondoyle/Google-Nest-Cam-Bug-Disclosures>

---

### `dos/nokia_affix_signed_proto`

Nokia Affix BT stack signed-proto DoS (EDB-25525)

**Severity:** 🟢 LOW · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `proto` |  | `NEG_PROTO` | Negative proto value passed to socket() |

**References:**
- <https://www.exploit-db.com/exploits/25525>
- <https://www.securityfocus.com/bid/13347>

---

### `dos/nokia_bluetab_nickname`

Nokia/Symbian Bluetooth nickname crash file generator (EDB-856)

**Severity:** 🟢 LOW · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `nickname` | ✓ |  | Nickname string to wrap with the trigger trailer |
| `output_file` |  | `bluetab.txt` | Output file path |

**References:**
- <https://www.exploit-db.com/exploits/856>

---

### `dos/notify_flood`

**exploits/dos/ble/notify_flood**

BLE Notification/GATT Flood DoS Attack

**Severity:** 🟡 MEDIUM · **Protocol:** BLE

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `duration` |  | `60` | Attack duration in seconds |
| `mode` |  | `all` | Attack mode: notify, read, write, or all |
| `reconnect` |  | `True` | Auto-reconnect if disconnected |
| `timeout` |  | `15` | Connection timeout in seconds |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification/>

---

### `dos/rfcomm_check_security_null`

**Linux rfcomm_check_security() NULL Deref DoS**

Remote kernel NULL pointer dereference in rfcomm_check_security() (CVE-2024-26903), no authentication required

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC · **CVE:** [CVE-2024-26903](https://nvd.nist.gov/vuln/detail/CVE-2024-26903)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `interface` |  | `hci0` | Local HCI adapter |
| `threads` |  | `4` | Concurrent connection threads |
| `attempts` |  | `40` | Total connection attempts |
| `sabm_burst` |  | `8` | SABM frames per connection before teardown |

**References:**
- <https://nvd.nist.gov/vuln/detail/CVE-2024-26903>
- <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=CVE-2024-26903>

---

### `dos/rfcomm_flood`

**exploits/dos/classic/rfcomm_flood**

RFCOMM Connection Exhaustion DoS Attack

**Severity:** 🟡 MEDIUM · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `channel` |  | `0` | RFCOMM channel (1-30, 0 = scan all) |
| `threads` |  | `10` | Number of concurrent threads |
| `hold` |  | `True` | Hold connections open (exhaustion mode) |
| `duration` |  | `60` | Attack duration in seconds (0 = until Ctrl+C) |
| `timeout` |  | `5` | Connection timeout in seconds |

**References:**
- <https://www.bluetooth.com/specifications/specs/core-specification/>

---

### `dos/rfcomm_msc_flood`

**RFCOMM MSC Signaling Flood**

High-rate MSC frame flood across HFP and auxiliary RFCOMM channels causing resource exhaustion DoS (2025)

**Severity:** 🟡 MEDIUM · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `interface` |  | `hci0` | Local HCI adapter |
| `channels` |  | `1,2,3` | RFCOMM channels to flood (comma-separated) |
| `rate` |  | `500` | MSC frames per second per connection |
| `duration` |  | `15` | Flood duration in seconds |
| `v24_cycle` |  | `True` | Cycle through all V.24 signal variants (vs. fixed 0x8D) |
| `connections_per_channel` |  | `2` | Concurrent L2CAP connections per channel |

**References:**
- <https://www.bluetooth.com/specifications/specs/rfcomm-1-2/>
- <https://www.etsi.org/deliver/etsi_ts/107300_107399/107310/08.02.00_60/ts_107310v080200p.pdf>

---

### `dos/rfcomm_state_change_deadlock`

**Linux rfcomm_sk_state_change() Deadlock**

Triggers kernel RFCOMM worker thread deadlock via concurrent conflicting state-change events (CVE-2024-50044)

**Severity:** 🟠 **HIGH** · **Protocol:** CLASSIC · **CVE:** [CVE-2024-50044](https://nvd.nist.gov/vuln/detail/CVE-2024-50044)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `interface` |  | `hci0` | Local HCI adapter |
| `connections` |  | `6` | Concurrent L2CAP connections |
| `target_channel` |  | `1` | RFCOMM channel for shared DLC contention |
| `rounds` |  | `5` | Deadlock trigger rounds |

**References:**
- <https://nvd.nist.gov/vuln/detail/CVE-2024-50044>
- <https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/log/net/bluetooth/rfcomm>

---

### `dos/sdp_flood`

**exploits/dos/classic/sdp_flood**

SDP Service Discovery Flood DoS Attack

**Severity:** 🟡 MEDIUM · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `threads` |  | `5` | Number of concurrent threads |
| `duration` |  | `60` | Attack duration in seconds (0 = until Ctrl+C) |
| `method` |  | `sdptool` | Method: sdptool, pybluez, or both |

**References:**
- <https://www.bluetooth.com/specifications/specs/service-discovery-protocol/>

---

### `dos/sony_ericsson_reset_display`

Sony/Ericsson L2CAP ECHO_REQ display-fade DoS (EDB-1473)

**Severity:** 🟡 MEDIUM · **Protocol:** CLASSIC

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `count` |  | `1` | Number of malformed packets to send |
| `interval` |  | `2` | Seconds between packets |

**References:**
- <https://www.exploit-db.com/exploits/1473>

---

### `dos/xiaomi_rfcomm_dlci_flood`

**Xiaomi Redmi Buds RFCOMM DLCI 0 Flood**

Firmware crash via RFCOMM DLCI 0 resource exhaustion on Xiaomi Redmi Buds (CVE-2025-13328)

**Severity:** 🟡 MEDIUM · **Protocol:** CLASSIC · **CVE:** [CVE-2025-13328](https://nvd.nist.gov/vuln/detail/CVE-2025-13328)

| Option | Required | Default | Description |
|---|---|---|---|
| `target` | ✓ |  | Target Xiaomi Buds BD_ADDR (XX:XX:XX:XX:XX:XX) |
| `interface` |  | `hci0` | Local HCI adapter |
| `flood_rate` |  | `200` | SABM frames per second on DLCI 0 |
| `duration` |  | `10` | Flood duration in seconds |
| `dlci_all` |  | `True` | Also flood all 30 DLCIs simultaneously |
| `connections` |  | `3` | Concurrent L2CAP connections |

**References:**
- <https://nvd.nist.gov/vuln/detail/CVE-2025-13328>

---
