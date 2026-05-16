# BlueSploit, Bluetooth Exploitation Framework

![Project](https://img.shields.io/badge/Project-BlueSploit-1a1aff?style=for-the-badge&logo=bluetooth&logoColor=white)
![Version](https://img.shields.io/badge/Version-1.0.5-0099ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Scaffold%20%2F%20Not%20Battle--Tested-orange?style=for-the-badge)
![Build](https://img.shields.io/badge/Build-Passing-success?style=for-the-badge&logo=github-actions&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-555555?style=for-the-badge&logo=linux&logoColor=white)
![Modules](https://img.shields.io/badge/Modules-160-orange?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-537%20passing-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

A Metasploit-style Bluetooth security testing framework for Classic BR/EDR and BLE, built by Mr-IoT for authorized penetration testing and security research.

```
  ██████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗
  ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
  ██████╔╝██║     ██║   ██║█████╗  ███████╗██████╔╝██║     ██║   ██║██║   ██║
  ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║
  ██████╔╝███████╗╚██████╔╝███████╗███████║██║     ███████╗╚██████╔╝██║   ██║
  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
```

Documentation: [v33ru.github.io/bluesploit](https://v33ru.github.io/bluesploit/)
Latest release: [v1.0.5](https://github.com/V33RU/bluesploit/releases/tag/v1.0.5)

---

## Features

- **160 modules** across 6 categories: exploits, DoS, scanners, recon, auxiliary, post-exploitation.
- **Store-driven scanners** that turn captured fingerprints (`adv`, `gatt_topology`, `lmp_features`, `ll_features`, `smp_pairing`, `mesh_beacon`) into actionable findings with citations.
- **Persistent engagement state** in `~/.bluesploit/store.db`: hosts, credentials, loot, fingerprints, and workspaces survive restarts.
- **40+ CVEs** implemented with working proof-of-concept exploits (2010 to 2026), plus a 7-entry NVD-cited signature catalog for offline matching.
- **Real BLE crypto** in `core/crypto.py`: AES-128, the Core Spec `ah` function for Resolvable Private Address resolution, Shannon entropy, weak-key tables.
- **Real Bluetooth Mesh crypto** in `core/mesh.py`: K1/K2/K3/K4 derivations, AES-CMAC, PECB header deobfuscation, AES-CCM Network PDU decrypt, verified against Mesh Profile v1.1 Annex 8.1.1 sample vectors.
- **Smart `set target`**: accepts a full BD_ADDR, a numeric host id, or a name substring. Auto-fills `link_key`, `ltk`, `irk`, `csrk`, `pin` from stored credentials.
- **Workspaces** to isolate engagements, with persisted active workspace.
- **Resource scripts**: `resource <file>` replays a sequence of console commands.
- **Persistent `setg` / `unsetg`** for framework-wide options.
- **Cross-platform install**: Linux (apt/dnf/yum/pacman/zypper/apk/xbps/emerge) + macOS (CoreBluetooth).
- **Hardware support** for Ubertooth One, nRF52840, BTLEJack, HackRF One, YARD Stick One, UD100.
- **Metasploit-style REPL** with `use` / `set` / `run` / `check` / `back`.
- **PCAP capture** for individual module runs via `btmon` / `tcpdump`.
- **Dual-protocol** coverage: Bluetooth Classic (BR/EDR), Bluetooth Low Energy (BLE), and Bluetooth Mesh.

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

> **Note:** Most modules require root for raw Bluetooth socket access. Bleak-based modules (`ble_scan_full`, `ble_target_enum`, `mesh_beacon_scan`) work as a regular user via the BlueZ D-Bus API.

### End-to-end example

```text
bluesploit > workspace use pentest-acme

# 1. Discover devices in range, capture full advertising payloads.
bluesploit > use recon/ble_scan_full
bluesploit(recon/ble_scan_full) > set interface hci1
bluesploit(recon/ble_scan_full) > run
... 10 devices captured, adv fingerprints stored ...

# 2. Enumerate the GATT topology of a target.
bluesploit > use recon/ble_target_enum
bluesploit(recon/ble_target_enum) > set target AA:BB:CC:DD:EE:01
bluesploit(recon/ble_target_enum) > run
... 8 services, 25 characteristics, gatt_topology fingerprint stored ...

# 3. Audit the stored fingerprints — no further hardware activity.
bluesploit > use scanners/char_permission_audit
bluesploit(scanners/char_permission_audit) > run
  [BSA-CHAR-003] AA:BB:CC:DD:EE:01 Alert Level: Write Without Response (HIGH)

bluesploit > use scanners/adv_anomaly_audit
bluesploit(scanners/adv_anomaly_audit) > run
  [BSA-ADV-002] ... Apple Continuity FindMy advertised (MEDIUM)

bluesploit > use scanners/cve_match
bluesploit(scanners/cve_match) > run
  ... matches every stored fingerprint against the curated CVE catalog ...

bluesploit > use scanners/iot_profile_audit
bluesploit(scanners/iot_profile_audit) > run
  ... classifies devices into wearable / lock / beacon / tracker categories ...
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
| `whatsnew`             | Show recent module additions from git log                         |
| `exit` / `quit`        | Leave BlueSploit                                                  |

---

## Modules (160)

| Category | Count |
|----------|-------|
| `exploits/`  | 87 |
| `dos/`       | 29 |
| `auxiliary/` | 14 |
| `scanners/`  | 12 |
| `recon/`     | 11 |
| `post/`      | 7  |

Run `python3 bluesploit.py --list` for the full live list, or see the per-category pages on the [documentation site](https://v33ru.github.io/bluesploit/exploits/).

### Scanners (12) — store-driven audits

| Module | Reads | Description |
|--------|-------|-------------|
| `scanners/cve_match` | every kind | Offline CVE matcher against 7 NVD-cited signatures (KNOB, BIAS, BLUFFS, BLURtooth, Invalid Curve, BlueDuck-style, PIN-pair variant) |
| `scanners/ble_pairing_audit` | `smp_pairing` | 7 rules: JustWorks, legacy pairing, weak key size, CSRK-no-MITM, CT2/BLURtooth surface, bonding-no-MITM |
| `scanners/char_permission_audit` | `gatt_topology` | 5 rules: writable Device Name, writable identity strings, control point Write-Without-Response, notify missing CCCD, HID Report Map exposure |
| `scanners/adv_anomaly_audit` | `adv` | 6 rules: public address peripherals, Apple Continuity leaks, Eddystone-UID/URL, oversized local names, iBeacon broadcasts |
| `scanners/ll_features_audit` | `ll_features` | LL Privacy gaps + BLE 5.x capability profile (PAST, CIS, Power Control, Subrating, Coded PHY) |
| `scanners/iot_profile_audit` | `adv` + `gatt_topology` | IoT device classifier (wearable, smart lock, beacon, tracker) with suggested follow-up modules |
| `scanners/mesh_provisioning_audit` | `mesh_beacon` | Mesh OOB / URI hash / key refresh / IV update audits |
| `scanners/vuln_scanner` | live | Unified BLE+Classic vulnerability scanner with live GATT analysis |
| `scanners/ble_debug_ecdh` | live | Detect devices using the published debug ECDH key pair |
| `scanners/blueborne_scan` | live | BlueBorne vulnerability detection |
| `scanners/ibeacon_scanner` | live | iBeacon discovery and focused security tests |
| `scanners/hidden_scanner` | live | Find non-discoverable BR/EDR + LE devices |

### Recon (11)

| Module | Description |
|--------|-------------|
| `recon/ble_scan_full` | Active BLE scan capturing full advertising payload (mirage-style output), persists `adv` fingerprints |
| `recon/ble_target_enum` | Connects to one target, walks every service/characteristic/descriptor, with device identity header (chipset, firmware, manufacturer), persists `gatt_topology` |
| `recon/gatt_enum` | Original GATT enumerator with consolidated flat characteristics table and stats summary |
| `recon/discovery` | Passive full-spectrum Bluetooth discovery (Classic + BLE), writes hosts |
| `recon/sdp_enum` | SDP service enumeration with CVE risk mapping |
| `recon/lmp_features` | LMP feature page reader for BR/EDR fingerprinting, persists `lmp_features` |
| `recon/ll_features` | BLE Link Layer feature set reader, persists `ll_features` |
| `recon/ble_pairing_features` | SMP pairing features probe, persists `smp_pairing` |
| `recon/adv_parser` | BLE advertisement deep analysis with risk scoring |
| `recon/mesh_beacon_scan` | Passive scan for Mesh Provisioning + Proxy beacons, persists `mesh_beacon` |
| `recon/oui_lookup` | OUI manufacturer lookup against the 39,433-entry IEEE registry |

### Auxiliary (14)

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
| `auxiliary/incoming_monitor` | Watch for incoming Bluetooth connections |
| `auxiliary/stealtooth_breaktooth` | StealthTooth + BrakTooth raw frame helpers |
| `auxiliary/crypto/key_quality` | Statistical key audit (Shannon entropy, chi-square, weak-key table) |
| `auxiliary/crypto/irk_entropy` | IRK entropy + Resolvable Private Address resolution via Core Spec `ah` |
| `auxiliary/crypto/passkey_check` | 6-digit BLE Passkey audit (weak table + pattern checks) |
| `auxiliary/mesh/mesh_pdu_decode` | Offline Mesh Network PDU decoder (K2 + PECB + AES-CCM) |

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

### Representative Exploits

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
| `exploits/blurtooth` | CVE-2020-15802 | Cross-Transport Key Derivation downgrade |
| `exploits/ble_invalid_curve` | CVE-2018-5383 | LE Secure Connections invalid curve attack |

---

## Engagement State

State persists in `~/.bluesploit/store.db` (override with the `BLUESPLOIT_HOME` environment variable). The store holds five tables, scoped by workspace:

| Table         | What                                                             |
|---------------|------------------------------------------------------------------|
| `hosts`       | Discovered BD_ADDRs, names, RSSI, vendor, first/last seen        |
| `credentials` | Link keys, LTKs, IRKs, CSRKs, PINs                               |
| `loot`        | Raw payloads (PCAP paths, GATT dumps, arbitrary bytes)           |
| `fingerprints`| Per-host probe results: `adv`, `gatt_topology`, `lmp_features`, `ll_features`, `smp_pairing`, `mesh_beacon` |
| `meta`        | Schema version, active workspace, persisted `setg` overrides     |

The active workspace is `default` unless the operator switches with `workspace use <name>`. Recon modules write fingerprints automatically; scanners read them. See the [Engagement State docs](https://v33ru.github.io/bluesploit/engagement-state/) for the full model.

---

## Core Libraries

| File | What |
|------|------|
| `core/store.py` | SQLite-backed engagement store (hosts, creds, loot, fingerprints, workspaces) |
| `core/crypto.py` | BLE crypto primitives: AES-128, `ah` function for RPA resolution, key statistics, weak-key tables |
| `core/mesh.py` | Mesh Profile primitives: s1, AES-CMAC, K1/K2/K3/K4, Network Nonce, PECB deobfuscation, AES-CCM PDU decrypt (verified vs spec test vectors) |
| `core/cve.py` | CVE signature engine with `lmp_version_max_inclusive`, `legacy_pairing_accepted`, `ctkd_advertised`, `max_key_size_max` conditions |
| `core/ble_meta.py` | Bluetooth SIG service / characteristic / descriptor UUID tables and property decoders |
| `core/utils/bt.py` | Shared HCI / BD_ADDR / L2CAP helpers, plus the SIG Company Identifier table |

---

## Supported Hardware

| Device | Protocol | Use Case |
|--------|----------|----------|
| USB Bluetooth Adapter (HCI) | Classic + BLE | Scanning, exploits, connections |
| Parani UD100 | Classic + BLE | Long-range USB adapter |
| Ubertooth One | Classic + BLE | Passive sniffing, spectrum analysis |
| nRF52840 Dongle | BLE | Passive BLE sniffing |
| BTLEJack (micro:bit) | BLE | Connection hijacking and injection |
| HackRF One | Classic | Raw Bluetooth baseband capture |
| YARD Stick One | Sub-GHz | RF analysis and injection |

---

## CVEs Covered

Working exploit modules:

| CVE | Name | Impact |
|-----|------|--------|
| CVE-2023-45866 | HID Keystroke Injection | 0-click RCE via HID |
| CVE-2023-24023 | BLUFFS | Session key downgrade / MITM |
| CVE-2021-28139 | BrakTooth | ESP32 arbitrary code execution |
| CVE-2020-0022 | BlueFrag | Android RCE |
| CVE-2020-15802 | BLURtooth | Cross-Transport Key Derivation downgrade |
| CVE-2020-10135 | BIAS | Authentication bypass |
| CVE-2020-12351 | BadKarma | Linux RCE |
| CVE-2020-12352 | BadChoice | Linux info disclosure |
| CVE-2019-9506 | KNOB | Encryption key downgrade |
| CVE-2019-16336 | SweynTooth | BLE stack crashes |
| CVE-2018-5383 | Invalid Curve | LE SC MITM |
| CVE-2017-1000251 | BlueBorne (Linux) | Linux RCE |
| CVE-2017-0781 | BlueBorne (Android) | Android info leak |
| CVE-2017-13258 | BNEP Heap Disclosure | Android memory leak |
| CVE-2025-36911 | WhisperPair | Google Fast Pair hijack |
| CVE-2025-10456 | Zephyr BLE Crash | Zephyr RTOS DoS / memory corruption |
| CVE-2025-20700/20701/20702 | Airoha RACE Chain | Airoha chipset RCE (Sony / Bose / JBL / 29+ devices) |
| CVE-2026-23671 | RFCOMM PrivEsc Race | Windows RFCOMM driver local EoP to SYSTEM |
| CVE-2026-20650 | Apple BT DoS | Apple BT subsystem crash (iOS / macOS / watchOS / tvOS) |
| CVE-2026-28540 | HarmonyOS BT OOB | Huawei HarmonyOS Bluetooth heap info disclosure |

Plus 7 NVD-cited entries in `data/signatures/bluetooth_cves.json` consumed by `scanners/cve_match`.

---

## Project Structure

```
bluesploit/
├── bluesploit.py          # Main entry point
├── setup.py               # Package installation
├── requirements.txt       # Python dependencies (pinned with ==)
├── core/
│   ├── base.py            # Module base classes, BaseModule.store property
│   ├── interpreter.py     # Interactive REPL, all console verbs
│   ├── loader.py          # Dynamic module loader
│   ├── store.py           # SQLite-backed engagement state
│   ├── crypto.py          # BLE crypto primitives (AES, ah, RPA resolution)
│   ├── mesh.py            # Mesh Profile primitives (K1/K2/K3/K4, AES-CCM)
│   ├── cve.py             # CVE signature matching engine
│   ├── ble_meta.py        # SIG UUID tables and property decoders
│   ├── banner.py          # REPL banner, tips, whatsnew
│   ├── hardware.py        # Hardware detection and abstraction
│   ├── capture.py         # PCAP capture (btmon / tcpdump)
│   ├── bt_raw.py          # Low-level Bluetooth frame builders
│   ├── utils/
│   │   ├── bt.py          # Shared HCI / BD_ADDR / L2CAP helpers
│   │   ├── printer.py     # Colored output and banners
│   │   ├── c_runner.py    # macOS embedded C / Obj-C compile+run
│   │   └── iokit.py       # macOS IOKit bridge
│   └── ui/
│       ├── tables.py      # rich-based table rendering
│       └── themes.py      # Color themes
├── modules/
│   ├── exploits/          # 87 exploit modules
│   ├── dos/               # 29 denial-of-service modules
│   ├── auxiliary/         # 14 auxiliary modules (crypto pack + mesh + hw)
│   ├── scanners/          # 12 scanner modules (store-driven + live)
│   ├── recon/             # 11 reconnaissance modules
│   └── post/              # 7 post-exploitation modules
├── data/
│   ├── oui/               # IEEE OUI registry (39,433 entries, gzipped)
│   ├── profiles/          # Device profile definitions
│   ├── signatures/        # CVE signatures (NVD-cited)
│   └── wordlists/         # PIN wordlists for brute-force
├── scripts/
│   ├── gen_module_docs.py # Auto-build the mkdocs module catalog
│   ├── validate_modules.py# AST metadata gate (run in CI)
│   ├── fetch_oui.py       # Refresh OUI database from IEEE
│   └── test_*.py          # 537 pytest suites for core/ and modules/
└── docs/                  # mkdocs site (https://v33ru.github.io/bluesploit/)
```

---

## Requirements

- **Python** 3.8+
- **OS:** Linux with BlueZ stack (all major distros, see install table) or macOS (BLE only via CoreBluetooth)
- **Privileges:** Root / sudo required for raw HCI socket modules. Bleak-based modules (`ble_scan_full`, `ble_target_enum`, `mesh_beacon_scan`) and all store-driven scanners run as a regular user.

### Core Dependencies

All pinned with `==` in `pyproject.toml`. Bumped via Dependabot.

| Package | Purpose |
|---------|---------|
| `bleak` | BLE scanning and GATT (cross-platform) |
| `pybluez2` | Classic Bluetooth L2CAP / RFCOMM / HCI |
| `scapy` | Packet crafting and injection |
| `cryptography` | AES-128, AES-CMAC, AES-CCM for BLE + Mesh crypto |
| `bluepy` | Low-level BLE access (Linux) |
| `pyserial` | Hardware dongle communication |
| `btlejack` | BLE connection hijacking |
| `rich` | Terminal UI helpers |
| `cmd2` | Advanced REPL |

---

## Testing

- **537 unit tests** under `scripts/`, every crypto primitive verified against published spec test vectors (NIST FIPS-197 for AES, Mesh Profile v1.1 Annex 8.1.1 for K2/K3/K4).
- **CI workflow**: `ruff`, `mypy` (lenient/advisory), `pytest` on Python 3.10 + 3.12, module metadata validation.
- **Dependabot** scoped to security + minor bumps; major bumps reviewed by hand.

Run the suite locally:

```bash
pytest scripts/                  # 537 tests
ruff check .                     # lint
python3 scripts/validate_modules.py  # module metadata gate
```

---

## Releases

- **v1.0.5** (current): module name display fix. [Release notes](https://github.com/V33RU/bluesploit/releases/tag/v1.0.5).
- **v1.0.4**: Phase 3 milestone — store-driven scanners, real crypto, Mesh foundations. [Release notes](https://github.com/V33RU/bluesploit/releases/tag/v1.0.4).
- **v1.0.2**: engagement state + supply chain hardening.
- **v1.0.1**: bluing parity + HCI bind/struct fixes.

Every merged PR is tagged `vX.Y.Z.devN`; formal releases happen on milestones. Tag, branch, and PR conventions live in [Contributing](https://v33ru.github.io/bluesploit/contributing/).

---

## Author

**Mr-IoT**

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Features at a glance

| Feature | Detail |
|---|---|
| Modules | 160 across exploits, DoS, scanners, recon, auxiliary, post |
| Store-driven scanners | Consume `adv`, `gatt_topology`, `lmp_features`, `ll_features`, `smp_pairing`, `mesh_beacon` fingerprints |
| Engagement state | `~/.bluesploit/store.db` — hosts, creds, loot, fingerprints, workspaces |
| CVEs | 40+ PoC exploits (2010-2026); 7 NVD-cited signatures for offline matching |
| BLE crypto | AES-128, `ah` for RPA resolution, key stats |
| Mesh crypto | K1/K2/K3/K4, AES-CMAC, PECB, AES-CCM (spec-verified) |
| `set target` | BD_ADDR / host id / name substring; auto-fills creds |
| Workspaces | Isolated engagements, persisted active workspace |
| Resource scripts | `resource <file>` replays console commands |
| Global options | Persistent `setg` / `unsetg` |
| Install | Linux (apt/dnf/yum/pacman/zypper/apk/xbps/emerge) + macOS |
| Hardware | Ubertooth One, nRF52840, BTLEJack, HackRF One, YARD Stick One, UD100 |
| REPL | `use` / `set` / `run` / `check` / `back` |
| PCAP | Per-run capture via `btmon` / `tcpdump` |
| Protocols | BR/EDR, BLE, Mesh |

---

## Disclaimer

**This tool is for educational purposes and authorized security testing only.**

- Only use against devices you own or have explicit written permission to test.
- Unauthorized access to computer systems and networks is illegal.
- The authors are not responsible for any misuse or damage caused by this tool.
- Always comply with local laws and regulations regarding wireless security testing.
