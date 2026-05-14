"""
BlueSploit Module: Android btsnoop Collector

Collects the Bluetooth HCI snoop log (btsnoop_hci.log) from a connected
Android device via ADB. The log captures every HCI command, event, and
ACL/SCO data packet handled by the Android Bluetooth stack, equivalent
to a btmon trace of the phone's controller.

Modes:
  enable   , turn on Bluetooth HCI snoop logging (requires Developer Options)
  disable  , turn off Bluetooth HCI snoop logging
  pull     , pull the existing snoop log to local disk
  full     , enable + restart Bluetooth + wait + pull
  watch    , tail the snoop log in real time via adb shell

Notes:
  - Requires `adb` in PATH and the device with USB debugging enabled
  - On Android 4.4+ the path is usually /sdcard/btsnoop_hci.log,
    on Android 9+ /data/misc/bluetooth/logs/btsnoop_hci.log,
    on some OEMs /sdcard/Android/data/com.android.bluetooth/files/
"""

import os
import shutil
import subprocess
import time
from typing import Optional, List

from core.base import AuxiliaryModule, BTProtocol, ModuleInfo, ModuleOption, Severity
from core.utils.printer import (
    Colors, print_error, print_info, print_success, print_warning,
)

# Common locations across Android versions / OEM ROMs
SNOOP_PATHS = [
    "/sdcard/btsnoop_hci.log",
    "/sdcard/Android/data/com.android.bluetooth/files/btsnoop_hci.log",
    "/data/misc/bluetooth/logs/btsnoop_hci.log",
    "/data/misc/bluedroid/btsnoop_hci.log",
    "/data/log/bt/btsnoop_hci.log",
]


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Android btsnoop Collector",
        description="Enable, pull, or watch Android's Bluetooth HCI snoop log via ADB",
        author=["BlueSploit"],
        protocol=BTProtocol.DUAL,
        severity=Severity.INFO,
    )

    def _setup_options(self) -> None:
        self.add_option(ModuleOption(
            name="mode",
            required=True,
            description="Mode: enable, disable, pull, full, watch",
            default="full",
        ))
        self.add_option(ModuleOption(
            name="device",
            required=False,
            description="ADB serial (default: first connected device)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="output",
            required=False,
            description="Local output PCAP/log path",
            default="/tmp/btsnoop_hci.log",
        ))
        self.add_option(ModuleOption(
            name="remote_path",
            required=False,
            description="Override remote snoop path (auto-detect if empty)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="capture_seconds",
            required=False,
            description="Wait time after enable before pull (full mode)",
            default=30,
        ))

    def run(self) -> bool:
        if not shutil.which("adb"):
            print_error("adb not found in PATH, install android-tools-adb")
            return False

        mode    = (self.get_option("mode") or "full").lower()
        device  = self.get_option("device")
        output  = self.get_option("output") or "/tmp/btsnoop_hci.log"
        remote  = self.get_option("remote_path")
        wait_s  = int(self.get_option("capture_seconds") or 30)

        if mode not in ("enable", "disable", "pull", "full", "watch"):
            print_error(f"Invalid mode: {mode}")
            return False

        if not self._adb_check(device):
            return False

        print_info(f"Mode    : {mode}")
        if device:
            print_info(f"Device  : {device}")

        if mode == "enable":
            return self._enable_snoop(device)
        if mode == "disable":
            return self._disable_snoop(device)
        if mode == "pull":
            return self._pull_snoop(device, output, remote)
        if mode == "watch":
            return self._watch_snoop(device, remote)
        if mode == "full":
            if not self._enable_snoop(device):
                return False
            print_info(f"Capturing for {wait_s}s, exercise Bluetooth on the device now...")
            try:
                time.sleep(wait_s)
            except KeyboardInterrupt:
                print_warning("Interrupted")
            return self._pull_snoop(device, output, remote)
        return False

    # ── enable / disable ──────────────────────────────────────────────────

    def _enable_snoop(self, device: Optional[str]) -> bool:
        print_info("Enabling Bluetooth HCI snoop log...")
        rc = self._adb(device, "shell", "settings", "put", "global",
                       "bluetooth_hci_log", "1")
        if rc != 0:
            print_warning("settings put failed, trying setprop fallback")
            self._adb(device, "shell", "setprop",
                      "persist.bluetooth.btsnoopenable", "true")
            self._adb(device, "shell", "setprop",
                      "persist.bluetooth.btsnoopdefaultmode", "2")

        print_info("Restarting Bluetooth to apply the snoop setting...")
        self._adb(device, "shell", "svc", "bluetooth", "disable")
        time.sleep(2)
        self._adb(device, "shell", "svc", "bluetooth", "enable")
        time.sleep(3)

        print_success("Bluetooth HCI snoop logging enabled")
        print_warning("If logs are still empty, manually toggle the developer-options switch:")
        print_warning("  Settings → System → Developer options → Enable Bluetooth HCI snoop log")
        self.add_result({"mode": "enable", "success": True})
        return True

    def _disable_snoop(self, device: Optional[str]) -> bool:
        print_info("Disabling Bluetooth HCI snoop log...")
        self._adb(device, "shell", "settings", "put", "global",
                  "bluetooth_hci_log", "0")
        self._adb(device, "shell", "setprop",
                  "persist.bluetooth.btsnoopenable", "false")
        self._adb(device, "shell", "svc", "bluetooth", "disable")
        time.sleep(1)
        self._adb(device, "shell", "svc", "bluetooth", "enable")
        print_success("HCI snoop logging disabled")
        return True

    # ── pull ──────────────────────────────────────────────────────────────

    def _pull_snoop(self, device: Optional[str], output: str,
                     remote: Optional[str]) -> bool:
        candidates: List[str] = [remote] if remote else SNOOP_PATHS
        chosen = None
        for path in candidates:
            if not path:
                continue
            print_info(f"Probing {path}...")
            rc, out, _ = self._adb_capture(device, "shell", "ls", "-l", path)
            if rc == 0 and "No such file" not in out and path in out:
                chosen = path
                break

        if not chosen:
            print_error("No btsnoop log found at any known path.")
            print_info("Set 'remote_path' to a custom location, or run mode=enable first.")
            return False

        print_success(f"Found snoop log at {chosen}")
        print_info(f"Pulling → {output}")
        rc = self._adb(device, "pull", chosen, output)
        if rc != 0:
            # Snoop file may be in /data/, needs root
            print_warning("Pull failed (permission?), retrying via cat (root su required)")
            rc, out, _ = self._adb_capture(device, "shell", f"su -c 'cat {chosen}' 2>/dev/null")
            if rc == 0 and out:
                with open(output, "wb") as f:
                    f.write(out.encode("latin-1") if isinstance(out, str) else out)
            else:
                print_error("Could not pull snoop log, root access required for /data/")
                return False

        if os.path.exists(output):
            sz = os.path.getsize(output)
            print_success(f"Saved {sz:,} bytes to {output}")
            print_info("Open in Wireshark with the BTSNOOP plugin (built-in since Wireshark 1.6)")
            self.add_result({"mode": "pull", "remote": chosen, "local": output,
                             "bytes": sz, "success": True})
            return True
        print_error(f"Output file {output} not created")
        return False

    # ── live watch ────────────────────────────────────────────────────────

    def _watch_snoop(self, device: Optional[str], remote: Optional[str]) -> bool:
        path = remote
        if not path:
            for p in SNOOP_PATHS:
                rc, out, _ = self._adb_capture(device, "shell", "ls", p)
                if rc == 0 and p in out:
                    path = p
                    break
        if not path:
            print_error("No snoop log found to tail")
            return False

        print_success(f"Tailing {path} (Ctrl+C to stop)...")
        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += ["shell", "tail", "-f", "-c", "+1", path]
        try:
            subprocess.run(cmd)
        except KeyboardInterrupt:
            print_warning("\nStopped")
        return True

    # ── ADB plumbing ──────────────────────────────────────────────────────

    def _adb_check(self, device: Optional[str]) -> bool:
        rc, out, _ = self._adb_capture(None, "devices")
        if rc != 0:
            print_error("`adb devices` failed, is the daemon running?")
            return False
        lines = [l for l in out.strip().splitlines()[1:] if l.strip()]
        if not lines:
            print_error("No ADB devices connected")
            return False
        if device:
            if not any(device in l and "device" in l for l in lines):
                print_error(f"Device {device} not visible in `adb devices`")
                return False
        else:
            ready = [l for l in lines if l.endswith("device")]
            if not ready:
                print_error("No authorized device, accept the USB debugging prompt")
                return False
        return True

    def _adb(self, device: Optional[str], *args) -> int:
        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += list(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode != 0 and r.stderr:
                print_warning(f"  adb {args[0]}: {r.stderr.strip()[:120]}")
            return r.returncode
        except subprocess.TimeoutExpired:
            return -1

    def _adb_capture(self, device: Optional[str], *args):
        cmd = ["adb"]
        if device:
            cmd += ["-s", device]
        cmd += list(args)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return r.returncode, r.stdout, r.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "timeout"
