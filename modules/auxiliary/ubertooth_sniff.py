"""
Ubertooth One BLE/Classic Sniffer Wrapper
Wraps the ubertooth-btle and ubertooth-btbb tools for passive BLE and
Classic Bluetooth sniffing using the Ubertooth One hardware dongle.

Modes:
  - ble:       BLE advertisement and connection sniffing (ubertooth-btle)
  - classic:   Classic BT baseband sniffing (ubertooth-btbb)
  - follow:    Follow a specific BLE connection
  - spectrum:  Spectrum analysis (ubertooth-specan)
"""

import subprocess
import threading
import time
import os
import signal
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="Ubertooth Sniffer",
        description="Ubertooth One BLE/Classic passive sniffing wrapper",
        author="BlueSploit Team",
        protocol=BTProtocol.DUAL,
        references=[
            "https://ubertooth.sourceforge.net/",
            "https://github.com/greatscottgadgets/ubertooth",
        ],
        severity=Severity.INFO,
        cve=None,
    )

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="mode",
            required=False,
            description="Sniff mode: ble, classic, follow, spectrum",
            default="ble",
        ))
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="Target MAC for follow mode (AA:BB:CC:DD:EE:FF)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="channel",
            required=False,
            description="BLE advertising channel (37, 38, 39) or Classic channel (0-78)",
            default="37",
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Capture duration in seconds (0 = indefinite)",
            default="30",
        ))
        self.add_option(ModuleOption(
            name="pcap_file",
            required=False,
            description="PCAP output file for captured packets",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="ubertooth_device",
            required=False,
            description="Ubertooth device number (for multiple dongles)",
            default="0",
        ))
        self.add_option(ModuleOption(
            name="access_address",
            required=False,
            description="BLE access address to follow (hex, e.g. 8e89bed6)",
            default=None,
        ))

    def run(self) -> bool:
        mode = (self.get_option("mode") or "ble").lower()
        target = self.get_option("target")
        channel = self.get_option("channel") or "37"
        duration = int(self.get_option("duration") or 30)
        pcap_file = self.get_option("pcap_file")
        device = self.get_option("ubertooth_device") or "0"
        access_addr = self.get_option("access_address")

        valid_modes = ("ble", "classic", "follow", "spectrum")
        if mode not in valid_modes:
            self.print_error(f"Invalid mode '{mode}'. Valid: {', '.join(valid_modes)}")
            return False

        # Check Ubertooth tools
        if not self._check_ubertooth():
            return False

        self.print_status(f"Mode: {mode}")
        self.print_status(f"Channel: {channel}")
        self.print_status(f"Duration: {duration}s")
        self.print_status(f"Ubertooth device: {device}")

        if mode == "ble":
            return self._sniff_ble(channel, duration, pcap_file, device)
        elif mode == "classic":
            return self._sniff_classic(channel, duration, pcap_file, device)
        elif mode == "follow":
            if not target and not access_addr:
                self.print_error("follow mode requires target MAC or access_address")
                return False
            return self._follow_connection(target, access_addr, duration, pcap_file, device)
        elif mode == "spectrum":
            return self._spectrum_analysis(duration, device)

        return False

    def _check_ubertooth(self) -> bool:
        """Verify Ubertooth tools are installed and device is connected"""
        tools = ["ubertooth-btle", "ubertooth-btbb", "ubertooth-util"]
        missing = []
        for tool in tools:
            try:
                subprocess.run([tool, "-h"], capture_output=True, timeout=3)
            except FileNotFoundError:
                missing.append(tool)
            except Exception:
                pass  # -h may return non-zero

        if missing:
            self.print_error(f"Missing Ubertooth tools: {', '.join(missing)}")
            self.print_status("Install: sudo apt install ubertooth")
            return False

        # Check device presence
        try:
            result = subprocess.run(
                ["ubertooth-util", "-v"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
                self.print_success(f"Ubertooth detected: {version}")
                return True
            else:
                self.print_error("Ubertooth device not found — ensure dongle is plugged in")
                return False
        except subprocess.TimeoutExpired:
            self.print_warning("Ubertooth check timed out — proceeding anyway")
            return True
        except Exception as e:
            self.print_error(f"Ubertooth check failed: {e}")
            return False

    def _sniff_ble(self, channel: str, duration: int, pcap_file: str, device: str) -> bool:
        """Sniff BLE advertisements and connections"""
        self.print_status("Starting BLE advertisement sniffing...")

        cmd = ["ubertooth-btle", "-f", "-A", channel, "-U", device]
        if pcap_file:
            cmd.extend(["-c", pcap_file])
            self.print_status(f"PCAP output: {pcap_file}")

        return self._run_capture(cmd, duration)

    def _sniff_classic(self, channel: str, duration: int, pcap_file: str, device: str) -> bool:
        """Sniff Classic Bluetooth baseband"""
        self.print_status("Starting Classic BT baseband sniffing...")
        self.print_warning("Classic sniffing requires LAP discovery first")

        # First discover LAPs
        self.print_status("Scanning for Bluetooth LAPs (Lower Address Part)...")
        lap_cmd = ["ubertooth-btbb", "-U", device]
        if pcap_file:
            lap_cmd.extend(["-c", pcap_file])

        return self._run_capture(lap_cmd, duration)

    def _follow_connection(self, target: str, access_addr: str,
                          duration: int, pcap_file: str, device: str) -> bool:
        """Follow a specific BLE connection"""
        if access_addr:
            self.print_status(f"Following BLE connection with access address: 0x{access_addr}")
            cmd = ["ubertooth-btle", "-f", "-t", access_addr, "-U", device]
        elif target:
            self.print_status(f"Following BLE connections involving {target}...")
            cmd = ["ubertooth-btle", "-f", "-t", target.replace(":", ""), "-U", device]
        else:
            return False

        if pcap_file:
            cmd.extend(["-c", pcap_file])

        return self._run_capture(cmd, duration)

    def _spectrum_analysis(self, duration: int, device: str) -> bool:
        """Run spectrum analysis"""
        self.print_status("Starting 2.4GHz spectrum analysis...")
        self.print_status("This shows activity across all Bluetooth/WiFi channels")

        try:
            result = subprocess.run(
                ["which", "ubertooth-specan"],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                self.print_error("ubertooth-specan not found")
                return False
        except Exception:
            pass

        cmd = ["ubertooth-specan", "-U", device, "-d", "-"]
        return self._run_capture(cmd, duration)

    def _run_capture(self, cmd: list, duration: int) -> bool:
        """Run an Ubertooth capture command with timeout and live output"""
        self.print_status(f"Running: {' '.join(cmd)}")
        self.print_status(f"Capture will run for {duration} seconds...")

        packet_count = 0
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            deadline = time.time() + duration if duration > 0 else float("inf")
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    line = proc.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            packet_count += 1
                            if packet_count <= 20 or packet_count % 50 == 0:
                                self.print_status(f"  [{packet_count}] {line[:100]}")
                except Exception:
                    time.sleep(0.1)

            # Terminate capture
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            stderr = proc.stderr.read()
            if stderr:
                for err_line in stderr.strip().split("\n")[:5]:
                    if err_line.strip():
                        self.print_warning(f"  stderr: {err_line.strip()}")

            self.print_success(f"Capture complete — {packet_count} packets/lines captured")
            return packet_count > 0

        except FileNotFoundError:
            self.print_error(f"Command not found: {cmd[0]}")
            return False
        except Exception as e:
            self.print_error(f"Capture error: {e}")
            return False
