# BlueSploit - Bluetooth Exploitation Framework

![Project](https://img.shields.io/badge/Project-BlueSploit-1a1aff?style=for-the-badge&logo=bluetooth&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0.0-0099ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge&logo=github-actions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-555555?style=for-the-badge&logo=linux&logoColor=white)
![Modules](https://img.shields.io/badge/Modules-101-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

A Metasploit-style Bluetooth security testing framework for Classic BR/EDR and BLE, built for authorized penetration testing and security research.

```
  ██████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗
  ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
  ██████╔╝██║     ██║   ██║█████╗  ███████╗██████╔╝██║     ██║   ██║██║   ██║
  ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║
  ██████╔╝███████╗╚██████╔╝███████╗███████║██║     ███████╗╚██████╔╝██║   ██║
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
```

### Console preview

![BlueSploit interactive console](a.png)

---

## Features

- **101 modules** across 6 categories: exploits, scanners, recon, DoS, auxiliary, post-exploitation
- **40+ CVEs** implemented with working proof-of-concept exploits (2010 → 2026)
- **Cross-platform install** — Linux (apt/dnf/yum/pacman/zypper/apk/xbps/emerge) + macOS (CoreBluetooth)
- **Hardware support** for Ubertooth One, nRF52840, BTLEJack, HackRF One, YARD Stick One
- **Interactive CLI** with Metasploit-style command interface (use/set/run/show)
- **PCAP capture** for all module runs via btmon/tcpdump
- **Dual-protocol** coverage: Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (BLE)

---

## Installation

### One-line install (recommended)

`install.sh` auto-detects your distro / OS and installs everything:

```bash
git clone https://github.com/V33RU/bluesploit.git
cd bluesploit
./install.sh             # basic
./install.sh --full      # all extras (rich, cmd2, scapy, classic BT)
./install.sh --classic   # add Bluetooth Classic support (Linux only)
./install.sh --dev       # add dev tooling (pytest, black, flake8)
./install.sh --no-deps   # skip system packages (Python deps only)
```

Supported package managers: **apt, dnf, yum, pacman, zypper, apk, xbps, emerge** + macOS Homebrew.

### Manual install

```bash
git clone https://github.com/V33RU/bluesploit.git
cd bluesploit
pip install -r requirements.txt
# or as a package
pip install .
```

### System prerequisites by distro

| Distro | Command |
|--------|---------|
| Debian / Ubuntu / Kali | `sudo apt install bluez bluetooth libbluetooth-dev python3-dev libglib2.0-dev pkg-config build-essential` |
| Fedora / RHEL / Rocky | `sudo dnf install bluez bluez-libs-devel python3-devel glib2-devel pkgconf-pkg-config gcc gcc-c++ make` |
| Arch / Manjaro | `sudo pacman -S bluez bluez-utils glib2 pkgconf base-devel` |
| openSUSE | `sudo zypper install bluez bluez-devel python3-devel glib2-devel pkg-config gcc gcc-c++ make` |
| Alpine | `sudo apk add bluez bluez-dev python3-dev glib-dev pkgconfig build-base linux-headers` |
| Void | `sudo xbps-install -Sy bluez bluez-devel python3-devel glib-devel pkg-config base-devel` |
| macOS | nothing — CoreBluetooth is built-in (BLE only via `bleak`) |

### Hardware-specific packages (optional)

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

## Modules (101)

> Counts by category: **exploits 69 · dos 10 · recon 6 · auxiliary 6 · scanners 5 · post 2** (run `python3 bluesploit.py --list` for the full live list).

### Exploits (69)

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
| `exploits/rfcomm_privesc_race` | CVE-2026-23671 | Windows RFCOMM driver race condition — local EoP to SYSTEM |
| `exploits/apple_bt_dos` | CVE-2026-20650 | Apple BT subsystem crash via malformed packets |
| `exploits/harmonyos_bt_oob` | CVE-2026-28540 | Huawei HarmonyOS Bluetooth OOB heap info disclosure |
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

### DoS (10)

| Module | Description |
|--------|-------------|
| `dos/bluesmack` | L2CAP echo flood |
| `dos/l2ping_flood` | L2CAP ping flood |
| `dos/sdp_flood` | SDP query flood |
| `dos/rfcomm_flood` | RFCOMM connection exhaustion |
| `dos/notify_flood` | BLE notification flood |

### Auxiliary (6)

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
| CVE-2026-23671 | RFCOMM PrivEsc Race | Windows RFCOMM driver local EoP to SYSTEM |
| CVE-2026-20650 | Apple BT DoS | Apple BT subsystem crash (iOS/macOS/watchOS/tvOS) |
| CVE-2026-28540 | HarmonyOS BT OOB | Huawei HarmonyOS Bluetooth heap info disclosure |

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
│   ├── exploits/          # 69 exploit modules
│   ├── scanners/          # 5 scanner modules
│   ├── recon/             # 6 reconnaissance modules
│   ├── dos/               # 10 denial-of-service modules
│   ├── auxiliary/         # 6 auxiliary/hardware modules
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
- **OS:** Linux with BlueZ stack (all major distros — see install table) or macOS (BLE only via CoreBluetooth)
- **Privileges:** Root / sudo required for most Linux modules (raw HCI sockets)

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

**Mr-IoT** / Mr-IoT

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
