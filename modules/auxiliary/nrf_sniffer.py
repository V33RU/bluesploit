"""
nRF52840 Sniffer Wrapper
Wraps the Nordic Semiconductor nRF Sniffer for Bluetooth LE tool
for passive packet capture using nRF52840 dongle or development kit.

Features:
  - Passive BLE advertisement sniffing
  - Connection following without affecting the connection
  - PCAP output compatible with Wireshark
  - Multi-channel scanning
  - Device filtering
"""

import subprocess
import time
import signal
import struct
from core.base import AuxiliaryModule, ModuleInfo, ModuleOption, BTProtocol, Severity


class Module(AuxiliaryModule):

    info = ModuleInfo(
        name="nRF52840 Sniffer",
        description="nRF52840 dongle BLE passive sniffer wrapper",
        author="BlueSploit Team",
        protocol=BTProtocol.BLE,
        references=[
            "https://www.nordicsemi.com/Products/Development-tools/nrf-sniffer-for-bluetooth-le",
            "https://infocenter.nordicsemi.com/topic/ug_sniffer_ble/UG/sniffer_ble/intro.html",
        ],
        severity=Severity.INFO,
        cve=None,
    )

    # nRF Sniffer serial protocol constants
    SLIP_END = 0xC0
    SLIP_ESC = 0xDB
    SLIP_ESC_END = 0xDC
    SLIP_ESC_ESC = 0xDD

    REQ_FOLLOW = 0x00
    REQ_SCAN_CONT = 0x05
    REQ_SCAN_STOP = 0x06
    EVENT_PACKET = 0x06
    RESP_VERSION = 0x0C

    def _setup_options(self):
        self.add_option(ModuleOption(
            name="mode",
            required=False,
            description="Mode: scan, follow, capture",
            default="scan",
        ))
        self.add_option(ModuleOption(
            name="target",
            required=False,
            description="Target BLE MAC to follow (AA:BB:CC:DD:EE:FF)",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="serial_port",
            required=False,
            description="nRF Sniffer serial port (e.g., /dev/ttyACM0)",
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
            description="PCAP output file for Wireshark",
            default=None,
        ))
        self.add_option(ModuleOption(
            name="channel",
            required=False,
            description="BLE channel to scan (37-39 for adv, 0-36 for data, 'all' for hopping)",
            default="all",
        ))
        self.add_option(ModuleOption(
            name="rssi_filter",
            required=False,
            description="Minimum RSSI to report (e.g., -60)",
            default=None,
        ))

    def run(self) -> bool:
        mode = (self.get_option("mode") or "scan").lower()
        target = self.get_option("target")
        serial_port = self.get_option("serial_port")
        duration = int(self.get_option("duration") or 30)
        pcap_file = self.get_option("pcap_file")
        channel = self.get_option("channel") or "all"
        rssi_filter = self.get_option("rssi_filter")

        valid_modes = ("scan", "follow", "capture")
        if mode not in valid_modes:
            self.print_error(f"Invalid mode '{mode}'. Valid: {', '.join(valid_modes)}")
            return False

        # Auto-detect serial port if not specified
        if not serial_port:
            serial_port = self._detect_nrf_port()
            if not serial_port:
                self.print_error("nRF Sniffer not detected. Specify serial_port manually.")
                return False

        self.print_status(f"Mode: {mode}")
        self.print_status(f"Serial port: {serial_port}")
        self.print_status(f"Channel: {channel}")
        self.print_status(f"Duration: {duration}s")

        if mode == "follow" and not target:
            self.print_error("follow mode requires a target MAC address")
            return False

        # Try nrf_sniffer CLI tool first, fall back to direct serial
        if self._check_nrf_sniffer_cli():
            return self._run_cli_sniffer(mode, target, serial_port, duration,
                                         pcap_file, channel, rssi_filter)
        else:
            return self._run_serial_sniffer(mode, target, serial_port, duration,
                                            pcap_file, channel, rssi_filter)

    def _detect_nrf_port(self) -> str:
        """Auto-detect nRF52840 sniffer serial port"""
        import glob
        candidates = glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*")

        for port in sorted(candidates):
            try:
                # Check if it's an nRF device via udevadm
                result = subprocess.run(
                    ["udevadm", "info", "--name", port, "--query=property"],
                    capture_output=True, text=True, timeout=3
                )
                output = result.stdout.lower()
                if "nordic" in output or "nrf" in output or "1915:521f" in output:
                    self.print_success(f"nRF Sniffer detected at {port}")
                    return port
            except Exception:
                continue

        # Fallback: just use first ttyACM
        if candidates:
            self.print_warning(f"Using first available port: {candidates[0]}")
            return candidates[0]

        return None

    def _check_nrf_sniffer_cli(self) -> bool:
        """Check if nrf_sniffer CLI is available"""
        try:
            result = subprocess.run(
                ["nrf_sniffer_ble", "--help"],
                capture_output=True, timeout=3
            )
            return True
        except FileNotFoundError:
            return False
        except Exception:
            return False

    def _run_cli_sniffer(self, mode, target, serial_port, duration,
                         pcap_file, channel, rssi_filter) -> bool:
        """Run using the nrf_sniffer_ble CLI tool"""
        cmd = ["nrf_sniffer_ble", "--input-serial", serial_port]

        if pcap_file:
            cmd.extend(["--output-pcap", pcap_file])
        if target and mode == "follow":
            cmd.extend(["--device", target])

        self.print_status(f"Running: {' '.join(cmd)}")
        return self._run_capture_process(cmd, duration, rssi_filter)

    def _run_serial_sniffer(self, mode, target, serial_port, duration,
                            pcap_file, channel, rssi_filter) -> bool:
        """Direct serial communication with nRF Sniffer firmware"""
        try:
            import serial
        except ImportError:
            self.print_error("pyserial not installed, run: pip install pyserial")
            return False

        self.print_status(f"Opening serial port {serial_port}...")

        try:
            ser = serial.Serial(serial_port, baudrate=1000000, timeout=1)
        except Exception as e:
            self.print_error(f"Cannot open {serial_port}: {e}")
            return False

        packet_count = 0
        devices_seen = {}
        pcap_fd = None

        try:
            # Open PCAP file if requested
            if pcap_file:
                pcap_fd = open(pcap_file, "wb")
                # Write PCAP global header (link type 251 = BLUETOOTH_LE_LL)
                pcap_fd.write(struct.pack("<IHHiIII",
                    0xA1B2C3D4, 2, 4, 0, 0, 65535, 251))
                self.print_status(f"PCAP output: {pcap_file}")

            # Send scan/follow command
            if mode == "follow" and target:
                self.print_status(f"Following target: {target}")
                target_bytes = bytes(int(x, 16) for x in target.split(":"))
                self._send_nrf_cmd(ser, self.REQ_FOLLOW, target_bytes)
            else:
                self.print_status("Starting continuous scan...")
                self._send_nrf_cmd(ser, self.REQ_SCAN_CONT, b"")

            # Receive loop
            deadline = time.time() + duration
            buf = bytearray()

            while time.time() < deadline:
                data = ser.read(256)
                if not data:
                    continue
                buf.extend(data)

                # Process SLIP frames
                while self.SLIP_END in buf:
                    idx = buf.index(self.SLIP_END)
                    frame = bytes(buf[:idx])
                    buf = buf[idx + 1:]

                    if not frame:
                        continue

                    pkt = self._slip_decode(frame)
                    if not pkt or len(pkt) < 4:
                        continue

                    pkt_id = pkt[0]
                    if pkt_id == self.EVENT_PACKET and len(pkt) >= 10:
                        packet_count += 1
                        rssi = -(256 - pkt[2]) if pkt[2] > 127 else -pkt[2]
                        channel_num = pkt[3]
                        ble_payload = pkt[6:]

                        # Filter by RSSI
                        if rssi_filter and rssi < int(rssi_filter):
                            continue

                        # Extract advertiser address if available
                        if len(ble_payload) >= 8:
                            addr = ":".join(f"{b:02X}" for b in reversed(ble_payload[2:8]))
                            if addr not in devices_seen:
                                devices_seen[addr] = {"count": 0, "rssi": rssi}
                                self.print_status(f"  New device: {addr} (RSSI={rssi} ch={channel_num})")
                            devices_seen[addr]["count"] += 1
                            devices_seen[addr]["rssi"] = rssi

                        # Write to PCAP
                        if pcap_fd and ble_payload:
                            ts = time.time()
                            ts_sec = int(ts)
                            ts_usec = int((ts - ts_sec) * 1000000)
                            pcap_fd.write(struct.pack("<IIII",
                                ts_sec, ts_usec, len(ble_payload), len(ble_payload)))
                            pcap_fd.write(ble_payload)

                        if packet_count % 100 == 0:
                            self.print_status(f"  Captured {packet_count} packets, "
                                            f"{len(devices_seen)} unique devices")

            # Stop scanning
            self._send_nrf_cmd(ser, self.REQ_SCAN_STOP, b"")

        finally:
            ser.close()
            if pcap_fd:
                pcap_fd.close()

        self.print_success(f"Capture complete, {packet_count} packets, {len(devices_seen)} devices")
        if devices_seen:
            self.print_status("\nDevices discovered:")
            for addr, info in sorted(devices_seen.items(), key=lambda x: x[1]["count"], reverse=True)[:20]:
                self.print_status(f"  {addr}  packets={info['count']}  RSSI={info['rssi']}")

        return packet_count > 0

    def _send_nrf_cmd(self, ser, cmd_id: int, payload: bytes):
        """Send a SLIP-encoded command to the nRF Sniffer"""
        frame = bytes([cmd_id]) + payload
        encoded = self._slip_encode(frame)
        ser.write(encoded)
        ser.flush()

    def _slip_encode(self, data: bytes) -> bytes:
        """SLIP encode a frame"""
        out = bytearray([self.SLIP_END])
        for b in data:
            if b == self.SLIP_END:
                out.extend([self.SLIP_ESC, self.SLIP_ESC_END])
            elif b == self.SLIP_ESC:
                out.extend([self.SLIP_ESC, self.SLIP_ESC_ESC])
            else:
                out.append(b)
        out.append(self.SLIP_END)
        return bytes(out)

    def _slip_decode(self, data: bytes) -> bytes:
        """SLIP decode a frame"""
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] == self.SLIP_ESC and i + 1 < len(data):
                if data[i + 1] == self.SLIP_ESC_END:
                    out.append(self.SLIP_END)
                elif data[i + 1] == self.SLIP_ESC_ESC:
                    out.append(self.SLIP_ESC)
                i += 2
            else:
                out.append(data[i])
                i += 1
        return bytes(out)

    def _run_capture_process(self, cmd: list, duration: int, rssi_filter) -> bool:
        """Run an external capture process with timeout"""
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
                        packet_count += 1
                        if packet_count <= 20 or packet_count % 100 == 0:
                            self.print_status(f"  [{packet_count}] {line.strip()[:120]}")
                except Exception:
                    time.sleep(0.1)

            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

            self.print_success(f"Capture complete, {packet_count} lines")
            return packet_count > 0

        except Exception as e:
            self.print_error(f"Capture error: {e}")
            return False
