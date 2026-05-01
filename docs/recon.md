# Recon (6)

Discovery, fingerprinting, and protocol enumeration. Path: `modules/recon/`.

| Module | Description |
|---|---|
| `discovery` | Active inquiry + LE scan; lists MAC, name, RSSI, class-of-device |
| `adv_parser` | Parse and decode raw BLE advertisement payloads |
| `gatt_enum` | Enumerate GATT services, characteristics, descriptors |
| `sdp_enum` | Enumerate Classic SDP service records |
| `oui_lookup` | Resolve MAC → vendor via `data/oui/` |
| `version_fingerprint` | Identify BT version, manufacturer, likely chipset |

---

## Typical recon flow

```text
bsploit > use recon/discovery
bsploit (recon/discovery) > set DURATION 15
bsploit (recon/discovery) > run

bsploit > use recon/oui_lookup
bsploit (recon/oui_lookup) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (recon/oui_lookup) > run

bsploit > use recon/version_fingerprint
bsploit (recon/version_fingerprint) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (recon/version_fingerprint) > run

bsploit > use recon/gatt_enum
bsploit (recon/gatt_enum) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (recon/gatt_enum) > run
```

The output of `version_fingerprint` + `gatt_enum`/`sdp_enum` is what `scanners/vuln_scanner` consumes.
