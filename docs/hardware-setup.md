# Hardware Setup

BlueSploit works with a built-in HCI adapter for most modules, plus optional sniffers/SDRs for capture and advanced attacks.

---

## Built-in HCI adapter (required)

Every Linux laptop with Bluetooth, plus any USB BT dongle exposing an HCI device, is enough for ~80% of modules.

```bash
hciconfig                 # should list hci0
sudo hciconfig hci0 up
```

Use `IFACE hci0` (or `hci1`, etc.) in module options.

---

## Ubertooth One

Open-source 2.4 GHz BT/BLE sniffer.

```bash
# Debian/Ubuntu
sudo apt install ubertooth wireshark
ubertooth-util -v          # verify firmware
```

Used by `auxiliary/ubertooth_sniff` and several recon helpers.

---

## HackRF One

Wide-band SDR — useful for baseband-layer attacks and replay.

```bash
sudo apt install hackrf gr-bluetooth
hackrf_info
```

Used by select advanced exploits (`ble_baseband_inject`, `ble_longrange`).

---

## nRF52840 Dongle (Nordic Sniffer)

Best-in-class BLE sniffer.

1. Flash the **nRF Sniffer for Bluetooth LE** firmware from Nordic.
2. Install the Wireshark plugin.
3. Plug into USB — typically appears as `/dev/ttyACM0`.

Used by `auxiliary/nrf_sniffer`.

---

## BTLEJack (micro:bit)

BLE connection following / hijacking.

```bash
pip install btlejack
# Flash firmware:
btlejack -i               # follow on-screen
```

Used by `auxiliary/btlejack_capture` and connection-hijack exploits.

---

## YARD Stick One

Sub-GHz SDR — handy for some exotic radio chains.

```bash
pip install git+https://github.com/atlas0fd00m/rfcat.git
rfcat -r                  # interactive
```

---

## Verify everything

```text
bsploit > use auxiliary/hw_detect
bsploit (auxiliary/hw_detect) > run
```

Output lists every backend BlueSploit can talk to, plus version strings.

---

## Permissions

- HCI raw access requires `CAP_NET_RAW` or root → run with `sudo`.
- USB sniffers may need a udev rule. Vendor packages typically install one; otherwise add your user to the `plugdev` group.
- On macOS, raw HCI is unavailable — only `bleak`-based BLE modules work.
