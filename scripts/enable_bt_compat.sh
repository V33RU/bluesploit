#!/bin/bash
# Enable BlueZ legacy SDP server (compat mode) — required for sdptool / HID
# injection / SDP record registration on modern BlueZ (≥5.50).
#
# Run once: sudo bash scripts/enable_bt_compat.sh

set -e

UNIT=/lib/systemd/system/bluetooth.service

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Run with sudo: sudo bash $0"
    exit 1
fi

echo "[*] Patching $UNIT to add --compat flag..."

if grep -q -- '--compat' "$UNIT"; then
    echo "[+] Compat flag already present"
else
    sed -i 's|ExecStart=/usr/libexec/bluetooth/bluetoothd|&  --compat|' "$UNIT"
    echo "[+] Patched"
fi

echo "[*] Reloading systemd..."
systemctl daemon-reload

echo "[*] Restarting bluetooth.service..."
systemctl restart bluetooth

# Wait for SDP socket
sleep 2

if [ -e /var/run/sdp ]; then
    chmod 777 /var/run/sdp
    echo "[+] /var/run/sdp permissions set"
else
    echo "[!] /var/run/sdp not present yet — start a Bluetooth-using app to create it"
fi

# Verify
echo "[*] Verifying SDP server reachable..."
if sdptool browse local >/dev/null 2>&1; then
    echo "[+] SUCCESS — bluetoothd compat mode active"
    echo "    You can now run keystroke_injection / SDP-registering modules"
else
    echo "[!] sdptool browse local still failing — check 'systemctl status bluetooth'"
    exit 1
fi
