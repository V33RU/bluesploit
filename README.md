# BlueSploit - Bluetooth Exploitation Framework

A Metasploit-style Bluetooth security testing framework supporting Classic BR/EDR and BLE.

## Quick Start

```bash
# Run the console
python bluesploit.py

# List all modules
python bluesploit.py --list
```

## Console Commands

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `use <module>` | Select a module |
| `set <opt> <val>` | Set option value |
| `options` | Show current options |
| `run` | Execute module |
| `back` | Deselect module |
| `show modules` | List all modules |
| `search <term>` | Search modules |
| `info <module>` | Show module info |
| `exit` | Exit |

## Modules (45)

### Exploits (20)
| Module | Description |
|--------|-------------|
| `exploits/bluefrag` | CVE-2020-0022 Android RCE |
| `exploits/blueborne_linux_rce` | CVE-2017-1000251 Linux RCE |
| `exploits/blueborne_leak` | CVE-2017-0781 Info Leak |
| `exploits/bnep_heap_disclosure` | CVE-2017-13258 Heap Disclosure |
| `exploits/knob` | CVE-2019-9506 Key Negotiation Check |
| `exploits/knob_active` | CVE-2019-9506 Active Key Downgrade |
| `exploits/bluffs` | CVE-2023-24023 Session Key Downgrade |
| `exploits/bluffs_mitm` | CVE-2023-24023 Active MITM |
| `exploits/bias` | BIAS Authentication Bypass |
| `exploits/sweyntooth` | SweynTooth BLE Exploits |
| `exploits/braktooth_esp32` | BrakTooth ESP32 LMP Crash |
| `exploits/badkarma` | BadKarma BLE Attack |
| `exploits/badchoice` | BadChoice BLE Attack |
| `exploits/keystroke_injection` | HID Keystroke Injection |
| `exploits/bluebugging` | Bluebugging AT Command Attack |
| `exploits/bluesnarfing` | Bluesnarfing File Theft |
| `exploits/unauth_write` | BLE Unauthenticated GATT Write |
| `exploits/ble_mitm` | BLE MITM Relay |
| `exploits/ble_pairing_downgrade` | BLE Pairing Downgrade |
| `exploits/ble_replay` | BLE Capture & Replay |
| `exploits/rfcomm_shell` | RFCOMM Reverse Shell |

### Scanners (5)
| Module | Description |
|--------|-------------|
| `scanners/vuln_scanner` | Vulnerability Scanner |
| `scanners/vuln_scan` | Quick Vuln Scan |
| `scanners/blueborne_scan` | BlueBorne Detection |
| `scanners/ble_vuln_scanner` | BLE Vulnerability Scanner |
| `scanners/hidden_scanner` | Hidden Device Finder |

### Recon (6)
| Module | Description |
|--------|-------------|
| `recon/discovery` | Device Discovery |
| `recon/gatt_enum` | BLE GATT Enumeration |
| `recon/sdp_enum` | SDP Service Enumeration |
| `recon/adv_parser` | BLE Advertisement Parser |
| `recon/oui_lookup` | OUI Manufacturer Lookup |
| `recon/version_fingerprint` | Version Fingerprinting |

### DoS (5)
| Module | Description |
|--------|-------------|
| `dos/bluesmack` | L2CAP Echo Flood |
| `dos/l2ping_flood` | L2CAP Ping Flood |
| `dos/sdp_flood` | SDP Query Flood |
| `dos/rfcomm_flood` | RFCOMM Connection Flood |
| `dos/notify_flood` | BLE Notification Flood |

### Auxiliary (4)
| Module | Description |
|--------|-------------|
| `auxiliary/hw_detect` | Hardware Detection |
| `auxiliary/ble_fuzzer` | BLE Protocol Fuzzer |
| `auxiliary/ubertooth_sniff` | Ubertooth One Sniffer |
| `auxiliary/btlejack_capture` | BTLEJack Capture & Inject |
| `auxiliary/nrf_sniffer` | nRF52840 BLE Sniffer |

### Post-Exploitation (2)
| Module | Description |
|--------|-------------|
| `post/link_key_dump` | Extract Stored Link Keys |
| `post/bt_impersonation` | Paired Device Impersonation |

## Requirements

- Python 3.7+
- Linux with BlueZ stack
- `pybluez` — Classic Bluetooth (L2CAP, RFCOMM, SDP)
- `bleak` — BLE (GATT, scanning)
- Hardware (optional): Ubertooth One, nRF52840, BTLEJack

## Author

v33ru (IOTSRG)

## Disclaimer

This tool is for educational and authorized security testing only. Unauthorized use against devices you do not own or have permission to test is illegal.
