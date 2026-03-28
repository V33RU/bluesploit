#!/usr/bin/env python3
"""
BlueSploit - Bluetooth Exploitation Framework
Setup / installation script
"""

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent

long_description = ""
readme_path = this_directory / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")


# ── All runtime dependencies ─────────────────────────────────────────────────
# System prerequisites (Debian/Ubuntu):
#   sudo apt install bluez bluetooth libbluetooth-dev python3-dev \
#                    libglib2.0-dev libboost-python-dev libboost-thread-dev
#
# Hardware-specific:
#   Ubertooth One  → sudo apt install ubertooth wireshark
#   HackRF One     → sudo apt install hackrf gr-bluetooth
#   nRF52840       → flash nRF Sniffer firmware, install Wireshark plugin
#   BTLEJack       → flash BTLEJack firmware to micro:bit
#   YARD Stick One → pip install git+https://github.com/atlas0fd00m/rfcat.git
install_requires = [
    # Core BLE
    "bleak>=0.21.0",               # BLE scanning + GATT (cross-platform)
    # Bluetooth Classic (BR/EDR)
    "pybluez2>=0.46",              # L2CAP / RFCOMM / HCI sockets
    # Packet crafting & crypto
    "scapy>=2.5.0",                # BT/BLE frame construction + injection
    "cryptography>=41.0.0",        # Key derivation (E0/E3), AES analysis
    # BLE low-level
    "bluepy>=1.3.0",               # Raw BLE + GATT handle access (Linux)
    # Hardware dongles
    "pyserial>=3.5",               # nRF Sniffer, BTLEJack, YARD Stick One
    "btlejack>=1.2",               # BLE connection hijacking (micro:bit)
    # UI
    "rich>=13.0.0",                # Colour tables, progress bars
    "cmd2>=2.4.0",                 # Advanced REPL (history, scripting)
    # Async
    "asyncio-dgram>=2.1.1",        # Async UDP/datagram support
]

extras_require = {
    "dev": [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "black>=23.0.0",
        "flake8>=6.0.0",
        "mypy>=1.5.0",
    ],
}


setup(
    name="bluesploit",
    version="1.1.0",
    author="v33ru",
    author_email="v33ru@mr-iot.dev",
    description="Bluetooth Exploitation Framework for Security Researchers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/v33ru/bluesploit",
    project_urls={
        "Bug Tracker":    "https://github.com/v33ru/bluesploit/issues",
        "Documentation":  "https://github.com/v33ru/bluesploit/wiki",
        "Source":         "https://github.com/v33ru/bluesploit",
    },

    # Package discovery
    packages=find_packages(exclude=["tests", "tests.*", "docs"]),
    include_package_data=True,
    package_data={
        "bluesploit": [
            "data/wordlists/*.txt",
            "data/oui/*.txt",
            "data/profiles/*.json",
        ],
    },

    # Dependencies
    python_requires=">=3.8",
    install_requires=install_requires,
    extras_require=extras_require,

    # CLI entry points
    entry_points={
        "console_scripts": [
            "bluesploit=bluesploit:main",
            "bsploit=bluesploit:main",
        ],
    },

    # PyPI classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Scientific/Engineering",
    ],

    keywords=[
        "bluetooth", "ble", "security", "exploitation",
        "pentest", "penetration-testing", "bluetooth-low-energy",
        "iot", "iot-security", "wireless", "hacking",
        "vulnerability-scanner", "bluebugging", "bluesnarfing",
        "sweyntooth", "bluffs", "ubertooth", "nrf-sniffer", "btlejack",
    ],

    license="MIT",
)
