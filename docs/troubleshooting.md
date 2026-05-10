# Troubleshooting

---

## `error: externally-managed-environment` (PEP 668)

Recent Debian/Ubuntu/Fedora block global pip installs. Use a venv:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

…or pass `--break-system-packages` to pip (also handled automatically by `install.sh`).

---

## `ImportError: No module named 'bluetooth'`

You need PyBluez/pybluez2 for Classic-BT modules:

```bash
pip install pybluez2
```

Requires `libbluetooth-dev` (Debian/Ubuntu) or `bluez-libs-devel` (Fedora). On macOS, this won't install — Classic BT isn't supported on macOS; only BLE via `bleak`.

---

## `Permission denied` on HCI

Raw HCI access needs `CAP_NET_RAW` or root:

```bash
sudo python3 bluesploit.py
# or grant the capability once:
sudo setcap 'cap_net_raw,cap_net_admin+eip' "$(readlink -f $(which python3))"
```

---

## `hci0` not found

```bash
rfkill list                     # ensure unblocked
sudo rfkill unblock bluetooth
sudo systemctl start bluetooth
hciconfig                       # should now show hci0
sudo hciconfig hci0 up
```

---

## `bleak` finds no devices on macOS

Grant Bluetooth permission to your Terminal app:
**System Settings → Privacy & Security → Bluetooth → enable Terminal/iTerm**.

---

## Module fails with `Bluetooth: Operation not permitted`

Either your adapter is rfkill-soft-blocked, or another process owns the HCI:

```bash
sudo systemctl stop bluetooth   # release BlueZ's grip for raw modules
sudo hciconfig hci0 down && sudo hciconfig hci0 up
```

After raw-HCI work, restart `bluetoothd` to restore normal pairing.

---

## `pybluez2` build fails

You're missing system headers. Install per-distro packages from [Installation](installation.md), then retry. On older Python (<3.8) it won't compile — upgrade Python.

---

## WSL/WSL2 — no Bluetooth

WSL doesn't expose the host radio. Either:

- Use a USB BT dongle via `usbipd-win` passthrough, **or**
- Run BlueSploit on bare Linux.

---

## Sniffer dongle not detected

```text
bluesploit > use auxiliary/hw_detect
bluesploit(auxiliary/hw_detect) > run
```

Check the output. If a backend is missing, see the matching section in [Hardware Setup](hardware-setup.md).

---

## Still stuck?

Open an issue: <https://github.com/V33RU/bluesploit/issues> with:
- OS + version
- `python3 --version`
- `pip list | grep -E 'bleak|pybluez|bluepy|btlejack|scapy'`
- `hciconfig` output
- The full traceback
