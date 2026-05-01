# Auxiliary (6)

Sniffers, fuzzers, and hardware utilities. Path: `modules/auxiliary/`.

| Module | Description |
|---|---|
| `hw_detect` | Enumerate connected adapters and SDR dongles (HCI, Ubertooth, HackRF, nRF, BTLEJack, YARD) |
| `nrf_sniffer` | Capture BLE traffic with the Nordic nRF52840 sniffer firmware |
| `ubertooth_sniff` | Capture BT/BLE traffic with Ubertooth One |
| `btlejack_capture` | Capture/follow BLE connections with BTLEJack (micro:bit) |
| `ble_fuzzer` | GATT/L2CAP/SMP layer fuzzer |
| `ble_rpa_deanon` | Resolve BLE Resolvable Private Addresses (RPA) given an IRK |

---

## Hardware-detect first

```text
bluesploit > use auxiliary/hw_detect
bluesploit(auxiliary/hw_detect) > run
```

This reports which sniffer/SDR backends are available before you try to use them. See [Hardware Setup](hardware-setup.md) for vendor-specific install steps.

---

## Sniffing example (nRF52840)

```text
bluesploit > use auxiliary/nrf_sniffer
bluesploit(auxiliary/nrf_sniffer) > set TARGET AA:BB:CC:DD:EE:FF
bluesploit(auxiliary/nrf_sniffer) > set OUTFILE captures/target.pcap
bluesploit(auxiliary/nrf_sniffer) > run
```

Open the resulting pcap in Wireshark with the nRF Sniffer plugin.

---

## RPA deanon

```text
bluesploit > use auxiliary/ble_rpa_deanon
bluesploit(auxiliary/ble_rpa_deanon) > set IRK <hex>
bluesploit(auxiliary/ble_rpa_deanon) > set CANDIDATES candidates.txt
bluesploit(auxiliary/ble_rpa_deanon) > run
```
