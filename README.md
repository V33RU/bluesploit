# BlueSploit, Bluetooth Exploitation Framework

![Project](https://img.shields.io/badge/Project-BlueSploit-1a1aff?style=for-the-badge&logo=bluetooth&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0.2-0099ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Scaffold%20%2F%20Not%20Battle--Tested-orange?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge&logo=github-actions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-555555?style=for-the-badge&logo=linux&logoColor=white)
![Modules](https://img.shields.io/badge/Modules-146-orange?style=for-the-badge)
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

Documentation: [v33ru.github.io/bluesploit](https://v33ru.github.io/bluesploit/)
Latest release: [v1.0.2](https://github.com/V33RU/bluesploit/releases/tag/v1.0.2)

---

## Features

- **146 modules** across 6 categories: exploits, DoS, scanners, recon, auxiliary, post-exploitation.
- **40+ CVEs** implemented with working proof-of-concept exploits (2010 to 2026).
- **Persistent engagement state** in `~/.bluesploit/store.db`: hosts, credentials, loot, and workspaces survive restarts.
- **Smart `set target`**: accepts a full BD_ADDR, a numeric host id from the store, or a substring matched against host address or name. Resolved hosts auto-fill `link_key`, `ltk`, `irk`, `csrk`, `pin` from the credentials table.
- **Workspaces** to isolate one engagement from another, with a persisted active workspace.
- **Resource scripts**: `resource <file>` replays a sequence of console commands.
- **Persistent `setg` / `unsetg`** for framework-wide options.
- **Cross-platform install**: Linux (apt/dnf/yum/pacman/zypper/apk/xbps/emerge) + macOS (CoreBluetooth).
- **Hardware support** for Ubertooth One, nRF52840, BTLEJack, HackRF One, YARD Stick One.
- **Metasploit-style REPL** with `use` / `set` / `run` / `check` / `back`.
- **PCAP capture** for individual module runs via `btmon` / `tcpdump`.
- **Dual-protocol** coverage: Bluetooth Classic (BR/EDR) and Bluetooth Low Energy (BLE).

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
./install.sh --dev       # add dev tooling (pytest, ruff, mypy)
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
| macOS | nothing, CoreBluetooth is built-in (BLE only via `bleak`) |

### Hardware-specific packages (optional)

```bash
# Ubertooth One
sudo apt install ubertooth wireshark

# HackRF One
sudo apt install hackrf gr-bluetooth

# nRF52840, flash nRF Sniffer firmware, install Wireshark plugin
# BTLEJack, flash BTLEJack firmware to micro:bit

# YARD Stick One
pip install git+https://github.com/atlas0fd00m/rfcat.git
```

---

## Quick Start

```bash
# Launch the interactive console
sudo python3 bluesploit.py

# Or just list every module
python3 bluesploit.py --list
```

> **Note:** Most modules require root for raw Bluetooth socket access.

### End-to-end example

```text
bluesploit > workspace use pentest-acme
bluesploit > use recon/discovery
bluesploit(recon/discovery) > run
bluesploit(recon/discovery) > back

bluesploit > hosts
  ID    Address             Name           RSSI   Vendor    Last seen
  ---------------------------------------------------------------------
  1     AA:BB:CC:DD:EE:01   alpha-laptop   -42    Apple     2026-05-14 20:30
  2     AA:BB:CC:DD:EE:02   wearable       -55    Garmin    2026-05-14 20:30

bluesploit > use post/link_key_dump
bluesploit(post/link_key_dump) > set target 1
bluesploit(post/link_key_dump) > run
... extracts LinkKey 0xDEADBEEF...

bluesploit > creds
  ID    Host                 Kind        Value                  Captured
  ------------------------------------------------------------------------
  1     AA:BB:CC:DD:EE:01    LinkKey     DEADBEEF...            2026-05-14 20:31

bluesploit > use post/bt_impersonation
bluesploit(post/bt_impersonation) > set target 1
[+] target => AA:BB:CC:DD:EE:01
[*] auto-filled link_key from credentials#1 (LinkKey)
bluesploit(post/bt_impersonation) > run
```

For the full walkthrough see the [Quick Start docs](https://v33ru.github.io/bluesploit/quick-start/).

---

## Console Commands

| Command                | Description                                                       |
|------------------------|-------------------------------------------------------------------|
| `help [cmd]`           | Show built-in help                                                |
| `use <module>`         | Load a module                                                     |
| `back`                 | Leave the current module                                          |
| `search <term>`        | Search modules by path, description, CVE, author                  |
| `show modules`         | List every loaded module                                          |
| `options`              | Show current module options                                       |
| `info`                 | Show detailed module metadata                                     |
| `set <opt> <val>`      | Set an option; `set target` resolves stored ids and auto-fills creds |
| `unset <opt>`          | Clear an option                                                   |
| `check`                | Run a non-destructive pre-flight                                  |
| `run` / `exploit`      | Execute the selected module                                       |
| `hosts [filter]`       | Show hosts stored in the active workspace                         |
| `creds [filter]`       | Show credentials stored in the active workspace                   |
| `workspace ...`        | `list` / `use <name>` / `delete <name>`                           |
| `setg [opt val]`       | List or set a persistent global option                            |
| `unsetg <opt>`         | Clear a persisted global, restore default                         |
| `resource <file>`      | Replay console commands from a file                               |
| `exit` / `quit`        | Leave BlueSploit                                                  |

---

## Modules (146)

| Category | Count |
|----------|-------|
| `exploits/`  | 87 |
| `dos/`       | 29 |
| `auxiliary/` | 10 |
| `recon/`     | 8 |
| `post/`      | 7 |
| `scanners/`  | 5 |

Run `python3 bluesploit.py --list` for the full live list, or see the per-category pages on the [documentation site](https://v33ru.github.io/bluesploit/exploits/).

A representative slice:

### Exploits (87)

| Module | CVE | Description |
|--------|-----|-------------|
| `exploits/keystroke_injection_windows` | CVE-2023-45866 | 0-click Bluetooth HID keystroke injection (Windows) |
| `exploits/bluffs` | CVE-2023-24023 | BLUFFS session key downgrade |
| `exploits/braktooth_esp32` | CVE-2021-28139 | BrakTooth ESP32 LMP crash / ACE |
| `exploits/bluefrag` | CVE-2020-0022 | Android Bluetooth A2DP RCE |
| `exploits/bias` | CVE-2020-10135 | BIAS authentication bypass |
| `exploits/badkarma` | CVE-2020-12351 | BleedingTooth L2CAP type confusion RCE |
| `exploits/knob` | CVE-2019-9506 | Key negotiation entropy check |
| `exploits/sweyntooth` | CVE-2019-16336+ | SweynTooth BLE link-layer exploits |
| `exploits/blueborne_linux_rce` | CVE-2017-1000251 | BlueZ L2CAP stack overflow RCE |
| `exploits/whisperpair` | CVE-2025-36911 | Google Fast Pair force-pair without pairing mode |
| `exploits/airoha_race_chain` | CVE-2025-20700/20701/20702 | Airoha 3-stage BLE -> Classic -> RACE RCE chain |

### Scanners (5)

| Module | Description |
|--------|-------------|
| `scanners/vuln_scanner` | Unified BLE+Classic vulnerability scanner with CVE matcher |
| `scanners/ble_debug_ecdh` | Detect devices using the published debug ECDH key pair |
| `scanners/blueborne_scan` | BlueBorne vulnerability detection |
| `scanners/ibeacon_scanner` | iBeacon discovery and focused security tests |
| `scanners/hidden_scanner` | Find non-discoverable BR/EDR + LE devices |

### Recon (8)

| Module | Description |
|--------|-------------|
| `recon/discovery` | Passive full-spectrum Bluetooth discovery (Classic + BLE), writes hosts |
| `recon/gatt_enum` | GATT service / characteristic enumeration + device identity |
| `recon/sdp_enum` | SDP service enumeration with CVE risk mapping |
| `recon/lmp_features` | LMP feature page reader for BR/EDR fingerprinting |
| `recon/ll_features` | BLE Link Layer feature set reader |
| `recon/ble_pairing_features` | SMP pairing features probe |
| `recon/adv_parser` | BLE advertisement deep analysis |
| `recon/oui_lookup` | OUI manufacturer lookup |

### DoS (29)

| Module | Description |
|--------|-------------|
| `dos/bluesmack` | L2CAP echo flood |
| `dos/l2ping_flood` | L2CAP ping flood |
| `dos/sdp_flood` | SDP query flood |
| `dos/rfcomm_flood` | RFCOMM connection exhaustion |
| `dos/notify_flood` | BLE notification flood |
| `dos/bt_phy_jam` | PHY-level Bluetooth jamming (Ubertooth / HackRF) |
| `dos/macos_iobt_*` | macOS IOBluetooth kernel crash family |

### Auxiliary (10)

| Module | Description |
|--------|-------------|
| `auxiliary/hw_detect` | Detect all connected Bluetooth hardware |
| `auxiliary/ble_fuzzer` | BLE ATT / GATT / SMP protocol fuzzer |
| `auxiliary/ubertooth_sniff` | Ubertooth One passive sniffer |
| `auxiliary/nrf_sniffer` | nRF52840 BLE packet capture |
| `auxiliary/btlejack_capture` | BTLEJack connection following and hijacking |
| `auxiliary/ble_rpa_deanon` | BLE RPA de-anonymization (CVE-2020-35473) |
| `auxiliary/btsnoop_collect` | Android btsnoop log collection over adb |
| `auxiliary/local_spoof` | Local adapter hostname / address spoofing |

### Post-Exploitation (7)

| Module | Description |
|--------|-------------|
| `post/link_key_dump` | Extract stored link keys from BlueZ; writes credentials |
| `post/apple_link_key_extract` | Extract link keys on macOS |
| `post/bt_impersonation` | Impersonate paired device with stolen link key |
| `post/bt_session_hijack` | Hijack an active BR/EDR session with a recovered key |
| `post/ble_gatt_exfil` | Read all accessible GATT characteristics from a target |
| `post/ble_notify_intercept` | Passive BLE notification interception |
| `post/gatt_cache_poison` | GATT characteristic cache poisoning |

---

## Engagement State

State persists in `~/.bluesploit/store.db` (override with the `BLUESPLOIT_HOME` environment variable). The store holds four tables, scoped by workspace:

| Table         | What                                                             |
|---------------|------------------------------------------------------------------|
| `hosts`       | Discovered BD_ADDRs, names, RSSI, vendor, first/last seen        |
| `credentials` | Link keys, LTKs, IRKs, CSRKs, PINs                               |
| `loot`        | Raw payloads (PCAP paths, GATT dumps, arbitrary bytes)           |
| `meta`        | Schema version, active workspace, persisted `setg` overrides    |

The active workspace is `default` unless the operator switches with `workspace use <name>`. See the [Engagement State docs](https://v33ru.github.io/bluesploit/engagement-state/) for the full model.

---

## Supported Hardware

| Device | Protocol | Use Case |
|--------|----------|----------|
| USB Bluetooth Adapter (HCI) | Classic + BLE | Scanning, exploits, connections |
| Ubertooth One | Classic + BLE | Passive sniffing, spectrum analysis |
| nRF52840 Dongle | BLE | Passive BLE sniffing |
| BTLEJack (micro:bit) | BLE | Connection hijacking and injection |
| HackRF One | Classic | Raw Bluetooth baseband capture |
| YARD Stick One | Sub-GHz | RF analysis and injection |

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
| CVE-2025-20700/20701/20702 | Airoha RACE Chain | Airoha chipset RCE (Sony / Bose / JBL / 29+ devices) |
| CVE-2026-23671 | RFCOMM PrivEsc Race | Windows RFCOMM driver local EoP to SYSTEM |
| CVE-2026-20650 | Apple BT DoS | Apple BT subsystem crash (iOS / macOS / watchOS / tvOS) |
| CVE-2026-28540 | HarmonyOS BT OOB | Huawei HarmonyOS Bluetooth heap info disclosure |

---

## Project Structure

```
bluesploit/
├── bluesploit.py          # Main entry point
├── setup.py               # Package installation
├── requirements.txt       # Python dependencies (pinned with ==)
├── requirements-docs.txt  # Hash-locked docs build deps
├── core/
│   ├── base.py            # Module base classes, BaseModule.store property
│   ├── interpreter.py     # Interactive REPL, all console verbs
│   ├── loader.py          # Dynamic module loader
│   ├── store.py           # SQLite-backed engagement state
│   ├── hardware.py        # Hardware detection and abstraction
│   ├── capture.py         # PCAP capture (btmon / tcpdump)
│   ├── bt_raw.py          # Low-level Bluetooth frame builders
│   ├── utils/
│   │   ├── bt.py          # Shared HCI / BD_ADDR / L2CAP helpers
│   │   ├── printer.py     # Colored output and banners
│   │   ├── c_runner.py    # macOS embedded C / Obj-C compile+run
│   │   └── iokit.py       # macOS IOKit bridge
│   └── ui/
│       └── themes.py      # Color themes
├── modules/
│   ├── exploits/          # 87 exploit modules
│   ├── dos/               # 29 denial-of-service modules
│   ├── auxiliary/         # 10 auxiliary / hardware modules
│   ├── recon/             # 8 reconnaissance modules
│   ├── post/              # 7 post-exploitation modules
│   └── scanners/          # 5 scanner modules
├── data/
│   ├── oui/               # MAC address OUI database
│   ├── profiles/          # Device profile definitions
│   ├── signatures/        # Vulnerability signatures
│   └── wordlists/         # PIN wordlists for brute-force
├── scripts/
│   ├── gen_module_docs.py # Auto-build the mkdocs module catalog
│   ├── validate_modules.py# AST metadata gate (run in CI)
│   └── test_*.py          # pytest suites for core/
└── docs/                  # mkdocs site (https://v33ru.github.io/bluesploit/)
```

---

## Requirements

- **Python** 3.8+
- **OS:** Linux with BlueZ stack (all major distros, see install table) or macOS (BLE only via CoreBluetooth)
- **Privileges:** Root / sudo required for most Linux modules (raw HCI sockets)

### Core Dependencies

All pinned with `==` in `pyproject.toml`. Bumped via Dependabot.

| Package | Purpose |
|---------|---------|
| `bleak` | BLE scanning and GATT (cross-platform) |
| `pybluez2` | Classic Bluetooth L2CAP / RFCOMM / HCI |
| `scapy` | Packet crafting and injection |
| `cryptography` | Key derivation and crypto analysis |
| `bluepy` | Low-level BLE access (Linux) |
| `pyserial` | Hardware dongle communication |
| `btlejack` | BLE connection hijacking |
| `rich` | Terminal UI helpers |
| `cmd2` | Advanced REPL |

---

## Releases

- **v1.0.2** (current): engagement state + supply chain hardening. [Release notes](https://github.com/V33RU/bluesploit/releases/tag/v1.0.2).
- v1.0.1: bluing parity + HCI bind/struct fixes.

The development branch is `dev`; merged PRs land on `main` and are tagged `vX.Y.Z.devN`. Tag, branch, and PR conventions live in [Contributing](https://v33ru.github.io/bluesploit/contributing/).

---

## Author

**Mr-IoT**

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Disclaimer

**This tool is for educational purposes and authorized security testing only.**

- Only use against devices you own or have explicit written permission to test.
- Unauthorized access to computer systems and networks is illegal.
- The authors are not responsible for any misuse or damage caused by this tool.
- Always comply with local laws and regulations regarding wireless security testing.
