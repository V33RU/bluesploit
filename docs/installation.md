# Installation

BlueSploit runs on **Linux (all major distros)** and **macOS**. Windows is not supported (no HCI socket access).

---

## One-line install (recommended)

```bash
git clone https://github.com/v33ru/bluesploit.git
cd bluesploit
./install.sh           # basic
./install.sh --full    # + Classic BT (Linux), rich UI extras
./install.sh --dev     # + pytest, black, flake8, mypy
./install.sh --classic # + pybluez2 (Linux only)
```

`install.sh` auto-detects your package manager (apt, dnf, yum, pacman, zypper, apk, xbps, emerge) and installs system prerequisites before pip-installing the Python deps.

---

## Per-distro system prerequisites

| Distro family | Command |
|---|---|
| Debian / Ubuntu / Kali / Mint | `sudo apt install bluetooth bluez libbluetooth-dev python3-dev libglib2.0-dev pkg-config build-essential` |
| Fedora / RHEL / Rocky / Alma | `sudo dnf install bluez bluez-libs-devel python3-devel glib2-devel pkgconf-pkg-config gcc gcc-c++ make` |
| Arch / Manjaro | `sudo pacman -S bluez bluez-utils glib2 pkgconf base-devel` |
| openSUSE | `sudo zypper install bluez libbluetooth-devel python3-devel glib2-devel pkg-config gcc gcc-c++ make` |
| Alpine | `sudo apk add bluez bluez-dev python3-dev glib-dev pkgconfig build-base linux-headers` |
| Void | `sudo xbps-install -Sy bluez bluez-devel python3-devel glib-devel pkg-config base-devel` |
| Gentoo | `sudo emerge net-wireless/bluez dev-libs/glib dev-util/pkgconf` |
| macOS | (Bluetooth is built-in; install Homebrew if you want extras: `brew install python`) |

---

## Manual install

```bash
python3 -m pip install -r requirements.txt
# or as a package:
python3 -m pip install -e .
```

If you hit `error: externally-managed-environment` (PEP 668 on recent Debian/Ubuntu/Fedora), either use a venv or pass `--break-system-packages`:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

---

## Verify

```bash
python3 bluesploit.py --list      # should print 101 modules
python3 bluesploit.py             # launches the console
```

---

## Platform notes

- **Linux** has full coverage: HCI sockets, L2CAP/RFCOMM via pybluez2, raw BLE via bluepy, conn-hijacking via btlejack.
- **macOS** uses CoreBluetooth via `bleak` — BLE scanning + GATT works; raw HCI / Classic-BT modules are skipped (gated by `sys_platform == "linux"`).
- **WSL/WSL2** does not expose the host Bluetooth radio — use a USB-passthrough adapter or run on bare Linux.
- Many modules need **root/sudo** for raw HCI access.

See [Troubleshooting](troubleshooting.md) if install fails.
