# BlueSploit - Bluetooth Exploitation Framework

A Metasploit-style Bluetooth security testing framework for Classic BR/EDR and BLE, built for authorized penetration testing and security research.

```
  ██████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗
  ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
  ██████╔╝██║     ██║   ██║█████╗  ███████╗██████╔╝██║     ██║   ██║██║   ██║
  ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║
  ██████╔╝███████╗╚██████╔╝███████╗███████║██║     ███████╗╚██████╔╝██║   ██║
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
```

---

## Features

- **52 modules** across 6 categories: exploits, scanners, recon, DoS, auxiliary, post-exploitation
- **19+ CVEs** implemented with working proof-of-concept exploits
- **Hardware support** for Ubertooth One, nRF52840, BTLEJack, HackRF One, YARD Stick One
- **Interactive CLI** with Metasploit-style command interface (use/set/run/show)
- **PCAP capture** for all module runs via btmon/tcpdump
- **Dual-protocol** coverage: Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (BLE)

---

## Installation

### System Prerequisites (Debian/Ubuntu)

```bash
sudo apt install bluez bluetooth libbluetooth-dev python3-dev \
                 libglib2.0-dev libboost-python-dev libboost-thread-dev
```

### Hardware-Specific Packages (Optional)

```bash
# Ubertooth One
sudo apt install ubertooth wireshark

# HackRF One
sudo apt install hackrf gr-bluetooth

# nRF52840 — flash nRF Sniffer firmware, install Wireshark plugin

# BTLEJack — flash BTLEJack firmware to micro:bit

# YARD Stick One
pip install git+https://github.com/atlas0fd00m/rfcat.git
```

### Python Setup

```bash
git clone https://github.com/v33ru/bluesploit.git
cd bluesploit
pip install -r requirements.txt
```

Or install as a package:

```bash
pip install -e .
```

---

## Quick Start

```bash
# Launch the interactive console
sudo python bluesploit.py

# List all available modules
sudo python bluesploit.py --list
```

> **Note:** Most modules require root privileges for raw Bluetooth socket access.

### Example Usage

```
bluesploit > use exploits/keystroke_injection
bluesploit (keystroke_injection) > set target AA:BB:CC:DD:EE:FF
bluesploit (keystroke_injection) > set payload hello world
bluesploit (keystroke_injection) > options
bluesploit (keystroke_injection) > run
```

---

## Console Commands

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `use <module>` | Select a module |
| `set <opt> <val>` | Set module option |
| `options` | Show current module options |
| `run` / `exploit` | Execute the selected module |
| `back` | Deselect current module |
| `show modules` | List all modules |
| `search <term>` | Search modules by name/description |
| `info [module]` | Show detailed module info |
| `exit` / `quit` | Exit the framework |

---

## Modules (52)

### Exploits (30)

| Module | CVE | Description |
|--------|-----|-------------|
| `exploits/keystroke_injection` | CVE-2023-45866 | 0-click Bluetooth HID keystroke injection |
| `exploits/bluffs` | CVE-2023-24023 | BLUFFS session key downgrade |
| `exploits/bluffs_mitm` | CVE-2023-24023 | BLUFFS active MITM attack |
| `exploits/braktooth_esp32` | CVE-2021-28139 | BrakTooth ESP32 LMP crash / ACE |
| `exploits/bluefrag` | CVE-2020-0022 | Android Bluetooth A2DP RCE |
| `exploits/bias` | CVE-2020-10135 | BIAS authentication bypass |
| `exploits/badkarma` | CVE-2020-12351 | BleedingTooth L2CAP type confusion RCE |
| `exploits/badchoice` | CVE-2020-12352 | BleedingTooth A2MP info disclosure |
| `exploits/knob` | CVE-2019-9506 | Key negotiation entropy check |
| `exploits/knob_active` | CVE-2019-9506 | Active key entropy downgrade |
| `exploits/sweyntooth` | CVE-2019-16336+ | SweynTooth BLE link-layer exploits |
| `exploits/blueborne_linux_rce` | CVE-2017-1000251 | Linux BlueZ L2CAP stack overflow RCE |
| `exploits/blueborne_leak` | CVE-2017-0781 | Android Bluetooth info leak |
| `exploits/bnep_heap_disclosure` | CVE-2017-13258 | Android BNEP heap disclosure |
| `exploits/whisperpair` | CVE-2025-36911 | Google Fast Pair hijack — force-pair without pairing mode |
| `exploits/zephyr_ble_smp_crash` | CVE-2025-10456 | Zephyr RTOS BLE fixed-channel integer overflow DoS |
| `exploits/airoha_race_chain` | CVE-2025-20700/20701/20702 | Airoha 3-stage BLE→Classic→RACE RCE chain |
| `exploits/bluebugging` | - | AT command injection via RFCOMM |
| `exploits/bluesnarfing` | - | OBEX file theft (contacts, SMS, calendar) |
| `exploits/a2dp_inject` | - | A2DP audio injection & media control |
| `exploits/ble_mitm` | - | BLE man-in-the-middle relay |
| `exploits/ble_pairing_downgrade` | - | Force JustWorks/legacy pairing |
| `exploits/ble_replay` | - | BLE GATT capture & replay |
| `exploits/ble_sc_bypass` | - | BLE Secure Connections bypass |
| `exploits/ble_longrange` | - | BT 5.x coded PHY / long-range attacks |
| `exploits/mesh_attack` | - | BLE Mesh provisioning MITM & replay |
| `exploits/unauth_write` | - | Unauthenticated BLE GATT write |
| `exploits/rfcomm_shell` | - | RFCOMM reverse/bind shell |
| `exploits/obex_exploit` | - | OBEX OPP/FTP file push/pull |
| `exploits/pin_bruteforce` | - | Classic Bluetooth 4-digit PIN brute-force |

### Scanners (5)

| Module | Description |
|--------|-------------|
| `scanners/vuln_scanner` | Automatic CVE detection based on device profile |
| `scanners/vuln_scan` | Quick BLE vulnerability scan |
| `scanners/blueborne_scan` | BlueBorne vulnerability detection |
| `scanners/ble_vuln_scanner` | Comprehensive BLE security assessment |
| `scanners/hidden_scanner` | Find non-discoverable devices via brute-force |

### Recon (6)

| Module | Description |
|--------|-------------|
| `recon/discovery` | BLE device discovery with detailed info |
| `recon/gatt_enum` | BLE GATT service/characteristic enumeration |
| `recon/sdp_enum` | Classic SDP service enumeration |
| `recon/adv_parser` | BLE advertisement deep analysis & fingerprinting |
| `recon/oui_lookup` | MAC address manufacturer identification |
| `recon/version_fingerprint` | OS/firmware fingerprinting via Bluetooth |

### DoS (5)

| Module | Description |
|--------|-------------|
| `dos/bluesmack` | L2CAP echo flood |
| `dos/l2ping_flood` | L2CAP ping flood |
| `dos/sdp_flood` | SDP query flood |
| `dos/rfcomm_flood` | RFCOMM connection exhaustion |
| `dos/notify_flood` | BLE notification flood |

### Auxiliary (5)

| Module | Description |
|--------|-------------|
| `auxiliary/hw_detect` | Detect all connected Bluetooth hardware |
| `auxiliary/ble_fuzzer` | BLE ATT/GATT/SMP protocol fuzzer |
| `auxiliary/ubertooth_sniff` | Ubertooth One passive sniffer |
| `auxiliary/nrf_sniffer` | nRF52840 BLE packet capture |
| `auxiliary/btlejack_capture` | BTLEJack connection following & hijacking |

### Post-Exploitation (2)

| Module | Description |
|--------|-------------|
| `post/link_key_dump` | Extract stored link keys from BlueZ |
| `post/bt_impersonation` | Impersonate paired device with stolen link key |

---

## Supported Hardware

| Device | Protocol | Use Case |
|--------|----------|----------|
| USB Bluetooth Adapter (HCI) | Classic + BLE | Scanning, exploits, connections |
| Ubertooth One | Classic + BLE | Passive sniffing, spectrum analysis |
| nRF52840 Dongle | BLE | Passive BLE sniffing |
| BTLEJack (micro:bit) | BLE | Connection hijacking & injection |
| HackRF One | Classic | Raw Bluetooth baseband capture |
| YARD Stick One | Sub-GHz | RF analysis & injection |

---

## CVEs Covered

| CVE | Name | Impact |
|-----|------|--------|
| CVE-2023-45866 | HID Keystroke Injection | 0-click RCE via HID |
| CVE-2023-24023 | BLUFFS | Session key downgrade / MITM |
| CVE-2021-28139 | BrakTooth | ESP32 arbitrary code execution |
| CVE-2020-0022 | BlueFrag | Android RCE |
| CVE-2020-10135 | BIAS | Authentication bypass |
| CVE-2020-12351 | BadKarma | Linux RCE |
| CVE-2020-12352 | BadChoice | Linux info disclosure |
| CVE-2019-9506 | KNOB | Encryption key downgrade |
| CVE-2019-16336 | SweynTooth | BLE stack crashes |
| CVE-2017-1000251 | BlueBorne (Linux) | Linux RCE |
| CVE-2017-0781 | BlueBorne (Android) | Android info leak |
| CVE-2017-13258 | BNEP Heap Disclosure | Android memory leak |
| CVE-2025-36911 | WhisperPair | Google Fast Pair hijack |
| CVE-2025-10456 | Zephyr BLE Crash | Zephyr RTOS DoS / memory corruption |
| CVE-2025-20700/20701/20702 | Airoha RACE Chain | Airoha chipset RCE (Sony/Bose/JBL/29+ devices) |

---

## Project Structure

```
bluesploit/
├── bluesploit.py          # Main entry point
├── setup.py               # Package installation
├── requirements.txt       # Python dependencies
├── core/
│   ├── base.py            # Module base classes & data models
│   ├── interpreter.py     # Interactive CLI (Metasploit-style)
│   ├── loader.py          # Dynamic module loader
│   ├── hardware.py        # Hardware detection & abstraction
│   ├── capture.py         # PCAP capture (btmon/tcpdump)
│   ├── utils/
│   │   └── printer.py     # Colored output & banners
│   └── ui/
│       └── themes.py      # Color themes
├── modules/
│   ├── exploits/          # 30 exploit modules
│   ├── scanners/          # 5 scanner modules
│   ├── recon/             # 6 reconnaissance modules
│   ├── dos/               # 5 denial-of-service modules
│   ├── auxiliary/         # 5 auxiliary/hardware modules
│   └── post/              # 2 post-exploitation modules
└── data/
    ├── oui/               # MAC address OUI database
    ├── profiles/          # Device profile definitions
    ├── signatures/        # Vulnerability signatures
    └── wordlists/         # PIN wordlists for brute-force
```

---

## Requirements

- **Python** 3.8+
- **OS:** Linux with BlueZ stack (Debian/Ubuntu recommended)
- **Privileges:** Root access required for most modules (raw HCI sockets)

### Core Dependencies

| Package | Purpose |
|---------|---------|
| `bleak` | BLE scanning & GATT (cross-platform) |
| `pybluez2` | Classic Bluetooth L2CAP/RFCOMM/HCI |
| `scapy` | Packet crafting & injection |
| `cryptography` | Key derivation & crypto analysis |
| `bluepy` | Low-level BLE access (Linux) |
| `pyserial` | Hardware dongle communication |
| `btlejack` | BLE connection hijacking |
| `rich` | Terminal UI (tables, progress) |
| `cmd2` | Advanced REPL |

---

## Author

**v33ru** / Mr-IoT

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

**This tool is for educational purposes and authorized security testing only.**

- Only use against devices you own or have explicit written permission to test
- Unauthorized access to computer systems and networks is illegal
- The authors are not responsible for any misuse or damage caused by this tool
- Always comply with local laws and regulations regarding wireless security testing
