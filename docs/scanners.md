# Scanners (5)

Passive/active vulnerability identification. Path: `modules/scanners/`.

| Module | Description |
|---|---|
| `vuln_scanner` | Generic vuln scanner — matches device fingerprints against `data/signatures/` |
| `vuln_scan` | Lightweight alias / quick scan |
| `ble_vuln_scanner` | BLE-specific vuln scan (GATT-aware) |
| `blueborne_scan` | Detect BlueBorne-vulnerable Linux/Android targets |
| `hidden_scanner` | Discover non-discoverable Classic BT devices via known-MAC sweep |

---

## Example

```text
bsploit > use scanners/vuln_scanner
bsploit (scanners/vuln_scanner) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (scanners/vuln_scanner) > run
```

The scanner reports likely-applicable CVEs and recommends matching modules under `exploits/`.

---

## Hidden Classic-BT scan

`hidden_scanner` performs an inquiry-less sweep — useful when a target has hidden mode enabled. Provide an OUI prefix or a MAC range to bound the search:

```text
bsploit (scanners/hidden_scanner) > set OUI 00:1A:7D
bsploit (scanners/hidden_scanner) > set DURATION 60
bsploit (scanners/hidden_scanner) > run
```
