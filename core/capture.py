"""
BlueSploit PCAP Capture
Provides optional Bluetooth HCI packet capture for module execution.
Captured traffic can be analyzed in Wireshark or similar tools.

Backends (tried in order):
  1. btmon   - BlueZ HCI monitor (best for Bluetooth, captures full HCI layer)
  2. tcpdump - Network packet capture on bluetooth0 interface
"""

import os
import shutil
import signal
import subprocess
import time
from typing import Any, Dict, List, Optional


class PCAPCapture:
    """
    Manages Bluetooth packet capture via btmon or tcpdump subprocess.

    Usage:
        cap = PCAPCapture("/tmp/capture.pcap")
        if cap.start():
            # ... do Bluetooth operations ...
            cap.stop()

    Or as context manager:
        with PCAPCapture("/tmp/capture.pcap") as cap:
            if cap.is_running:
                # ... do Bluetooth operations ...
    """

    # Ordered list of capture backends to try.
    # Typed Any-of-str-or-callable; each dict mixes strings with an args callable.
    BACKENDS: List[Dict[str, Any]] = [
        {
            "name": "btmon",
            "binary": "btmon",
            "args": lambda f, iface: ["btmon", "-w", f],
            "description": "BlueZ HCI monitor",
        },
        {
            "name": "tcpdump",
            "binary": "tcpdump",
            "args": lambda f, iface: [
                "tcpdump", "-i", f"bluetooth{iface[-1] if iface else '0'}",
                "-w", f, "-q",
            ],
            "description": "tcpdump on bluetooth interface",
        },
    ]

    def __init__(self, filename: str, interface: str = "hci0"):
        """
        Args:
            filename:  Output PCAP file path
            interface: Bluetooth HCI interface (default: hci0)
        """
        self.filename = os.path.expanduser(filename)
        self.interface = interface
        self._process: Optional[subprocess.Popen] = None
        self._backend_name: Optional[str] = None

    @property
    def is_running(self) -> bool:
        """Check if capture process is still running"""
        return self._process is not None and self._process.poll() is None

    @staticmethod
    def available_backends():
        """Return list of available capture backends on this system"""
        available = []
        for backend in PCAPCapture.BACKENDS:
            if shutil.which(backend["binary"]):
                available.append(backend["name"])
        return available

    def start(self) -> bool:
        """
        Start packet capture using the first available backend.

        Returns:
            True if capture started successfully, False otherwise
        """
        if self._process is not None:
            return True  # Already running

        # Ensure output directory exists
        output_dir = os.path.dirname(self.filename)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError:
                return False

        # Try each backend in order
        for backend in self.BACKENDS:
            binary = backend["binary"]
            if not shutil.which(binary):
                continue

            cmd = backend["args"](self.filename, self.interface)

            try:
                self._process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,  # New process group for clean kill
                )

                # Give it a moment to start and check it didn't immediately fail
                time.sleep(0.3)
                if self._process.poll() is not None:
                    # Process exited immediately — try next backend
                    self._process = None
                    continue

                self._backend_name = backend["name"]
                return True

            except (OSError, PermissionError):
                self._process = None
                continue

        return False

    def stop(self) -> bool:
        """
        Stop the capture process gracefully.

        Returns:
            True if capture was stopped and PCAP file exists
        """
        if self._process is None:
            return False

        try:
            # Send SIGINT for graceful shutdown (btmon flushes on SIGINT)
            os.killpg(os.getpgid(self._process.pid), signal.SIGINT)

            # Wait up to 3 seconds for graceful exit
            try:
                self._process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # Force kill if it won't stop
                os.killpg(os.getpgid(self._process.pid), signal.SIGKILL)
                self._process.wait(timeout=2)

        except (ProcessLookupError, OSError):
            # Process already gone
            pass
        finally:
            self._process = None

        return os.path.exists(self.filename)

    @property
    def backend(self) -> Optional[str]:
        """Name of the backend currently in use"""
        return self._backend_name

    @property
    def file_size(self) -> int:
        """Current size of the PCAP file in bytes (0 if not exists)"""
        try:
            return os.path.getsize(self.filename)
        except OSError:
            return 0

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False  # Don't suppress exceptions

    def __del__(self):
        """Ensure capture process is cleaned up"""
        if self._process is not None:
            self.stop()
