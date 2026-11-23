<div align="center">

# BlueSploit

**Bluetooth exploitation framework for Classic BR/EDR, BLE, and Mesh.**

![version](https://img.shields.io/badge/version-1.0.5-0099ff?style=flat-square)
![status](https://img.shields.io/badge/status-scaffold-orange?style=flat-square)
![modules](https://img.shields.io/badge/modules-159-5c6bc0?style=flat-square)
![python](https://img.shields.io/badge/python-3.8+-3776AB?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-yellow?style=flat-square)

[Docs](https://v33ru.github.io/bluesploit/) · [Releases](https://github.com/V33RU/bluesploit/releases)

</div>

---

## Install

```bash
git clone https://github.com/V33RU/bluesploit.git
cd bluesploit
./install.sh
```

Linux (apt/dnf/pacman/zypper/apk/xbps/emerge) or macOS. `--full` for all extras, `--dev` for tests.

## Run

```bash
sudo python3 bluesploit.py     # interactive REPL
python3 bluesploit.py --list   # list modules
```

Live modules need root for raw HCI. Bleak recon and store-driven scanners run as a regular user.

## Modules

| Category | Count |
|---|--:|
| `exploits/` | 87 |
| `dos/` | 29 |
| `auxiliary/` | 14 |
| `scanners/` | 12 |
| `recon/` | 10 |
| `post/` | 7 |
| **Total** | **159** |

Per-module docs: [v33ru.github.io/bluesploit](https://v33ru.github.io/bluesploit/).

## How it works

- **REPL** — `use` / `set` / `run` / `check` / `back`, plus `setg`, workspaces, and `resource` scripts.
- **Engagement store** — SQLite at `~/.bluesploit/store.db`: hosts, creds, loot, fingerprints. Recon writes fingerprints; scanners match CVEs against them offline.
- **Crypto** — AES-128, RPA resolution (`ah`), Mesh K1-K4 / AES-CMAC / AES-CCM (spec-verified).
- **Protocols** — BR/EDR, BLE, Mesh. PCAP per run via `btmon` / `tcpdump`.
- **Hardware** — Ubertooth One, nRF52840, BTLEJack, HackRF One, YARD Stick One, UD100.

## Disclaimer

Authorized testing only. Use against equipment you own or have written permission to test.

## License

[MIT](LICENSE)
