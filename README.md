# BlueSploit

![Version](https://img.shields.io/badge/Version-1.0.5-0099ff?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Scaffold%20%2F%20Not%20Battle--Tested-orange?style=for-the-badge)
![Modules](https://img.shields.io/badge/Modules-160-orange?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

Bluetooth framework for Classic BR/EDR and BLE. 160 modules, persistent store. By Mr-IoT.

Docs: [v33ru.github.io/bluesploit](https://v33ru.github.io/bluesploit/) · Latest: [v1.0.5](https://github.com/V33RU/bluesploit/releases/tag/v1.0.5)

## Install

```bash
git clone https://github.com/V33RU/bluesploit.git
cd bluesploit
./install.sh
```

Linux (apt/dnf/pacman/zypper/apk/xbps/emerge) or macOS. Use `--full` for all extras, `--dev` for test tooling.

## Run

```bash
sudo python3 bluesploit.py        # interactive REPL
python3 bluesploit.py --list      # list modules
```

Most live modules need root for raw HCI. Bleak-based recon (`ble_scan_full`, `ble_target_enum`, `mesh_beacon_scan`) and all store-driven scanners run as a regular user.

## Modules (160)

| Category | Count |
|---|---|
| `exploits/` | 87 |
| `dos/` | 29 |
| `auxiliary/` | 14 |
| `scanners/` | 12 |
| `recon/` | 11 |
| `post/` | 7 |

Full per-module docs at [v33ru.github.io/bluesploit](https://v33ru.github.io/bluesploit/).

## Engagement state

Persists in `~/.bluesploit/store.db` (override with `BLUESPLOIT_HOME`). Tables: `hosts`, `credentials`, `loot`, `fingerprints`, `meta`. Workspaces scope all of them.

## Core libraries

- `core/crypto.py` — AES-128, `ah` for RPA resolution, key stats
- `core/mesh.py` — Mesh K1/K2/K3/K4, AES-CMAC, AES-CCM (spec-verified)
- `core/cve.py` — CVE signature engine
- `core/store.py` — SQLite engagement store
- `core/ble_meta.py` — SIG UUID tables

## Author

Mr-IoT · [MIT License](LICENSE)

## Features

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

## Disclaimer

Authorized testing only. Use against equipment you own or have written permission to test. Authors disclaim liability for misuse.
