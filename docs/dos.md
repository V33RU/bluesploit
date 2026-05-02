# Denial of Service (11)

Auto-generated from `modules/dos/`.  
Load any module with `use dos/<name>`.

!!! warning "Authorization required"
    Use only against equipment you own or have explicit written
    authorization to test. The authors disclaim liability for misuse.

---

## Module index

| Module | Severity | CVE | Description |
|---|---|---|---|
| [`dos/a2dp_flood`](#dosa2dp_flood) | 🟠 **HIGH** | — | Flood Bluetooth audio devices by opening and abandoning AVDTP signaling conne… |
| [`dos/bluesmack`](#dosbluesmack) | 🟡 MEDIUM | — | BlueSmack - L2CAP Echo Flood DoS Attack |
| [`dos/bt_phy_jam`](#dosbt_phy_jam) | 🟠 **HIGH** | — | Radio-layer denial of Bluetooth/BLE channels via Ubertooth, HackRF, or Killer… |
| [`dos/l2ping_flood`](#dosl2ping_flood) | 🟠 **HIGH** | — | L2CAP ping flood DoS attack (BlueSmack) |
| [`dos/notify_flood`](#dosnotify_flood) | 🟡 MEDIUM | — | BLE Notification/GATT Flood DoS Attack |
| [`dos/rfcomm_check_security_null`](#dosrfcomm_check_security_null) | 🟠 **HIGH** | CVE-2024-26903 | Remote kernel NULL pointer dereference in rfcomm_check_security() (CVE-2024-2… |
| [`dos/rfcomm_flood`](#dosrfcomm_flood) | 🟡 MEDIUM | — | RFCOMM Connection Exhaustion DoS Attack |
| [`dos/rfcomm_msc_flood`](#dosrfcomm_msc_flood) | 🟡 MEDIUM | — | High-rate MSC frame flood across HFP and auxiliary RFCOMM channels causing re… |
| [`dos/rfcomm_state_change_deadlock`](#dosrfcomm_state_change_deadlock) | 🟠 **HIGH** | CVE-2024-50044 | Triggers kernel RFCOMM worker thread deadlock via concurrent conflicting stat… |
| [`dos/sdp_flood`](#dossdp_flood) | 🟡 MEDIUM | — | SDP Service Discovery Flood DoS Attack |
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

### `dos/bt_phy_jam`

**PHY-Level Bluetooth Jamming**

Radio-layer denial of Bluetooth/BLE channels via Ubertooth, HackRF, or KillerBee — kills connections and prevents new pairings

**Severity:** 🟠 **HIGH** · **Protocol:** BOTH

| Option | Required | Default | Description |
|---|---|---|---|
| `method` | ✓ | `ubertooth` | Jamming method: ubertooth, hackrf, killerbee, hci_loop |
| `mode` | ✓ | `adv_only` | Mode: adv_only, data_chan, full_band, follow |
| `channel` |  | `37` | BLE channel 0–39 (data_chan/follow mode) |
| `target` |  |  | Target BD_ADDR (follow mode) |
| `duration` |  | `60` | Jam duration in seconds (0 = until Ctrl+C) |
| `device` |  | `0` | Hardware device index (Ubertooth/HackRF index) |
| `tx_gain` |  | `40` | HackRF TX gain (0–47) |
| `interface` |  | `hci0` | HCI adapter (hci_loop method) |

**References:**
- <https://github.com/greatscottgadgets/ubertooth>
- <https://greatscottgadgets.com/hackrf/>
- <https://github.com/riverloopsec/killerbee>

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

Remote kernel NULL pointer dereference in rfcomm_check_security() (CVE-2024-26903) — no authentication required

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
