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


# ── Minimum runtime requirement ──────────────────────────────────────────────
# Only bleak is strictly required (BLE scanning works out of the box).
# Everything else is opt-in via extras or the split requirements files.
install_requires = [
    "bleak>=0.21.0",           # BLE scanning + GATT (cross-platform, no root)
]


# ── Optional extras ───────────────────────────────────────────────────────────
#
# Install a specific extra:   pip install ".[classic]"
# Install everything:         pip install ".[full]"
#
# Mirrors the split requirements-*.txt files for pip install -e usage.
extras_require = {

    # ── Protocol extras ───────────────────────────────────────────────────
    # Bluetooth Classic (BR/EDR) — needed by most exploit modules:
    #   bluebugging, bluesnarfing, bluefrag, knob, bias, badchoice,
    #   badkarma, blueborne_*, braktooth_esp32, bluffs, keystroke_injection
    # Prereq: sudo apt install libbluetooth-dev
    "classic": [
        "pybluez2>=0.46",          # Maintained PyBluez fork; L2CAP/RFCOMM/HCI
        "scapy>=2.5.0",            # Packet crafting (KNOB, BadKarma, BLUFFS)
        "cryptography>=41.0.0",    # Key derivation / crypto analysis
    ],

    # ── Hardware dongle extras ────────────────────────────────────────────

    # Ubertooth One — passive BLE + Classic sniffer
    # No Python package; uses ubertooth-* system CLI tools.
    # Install: sudo apt install ubertooth wireshark
    "ubertooth": [],

    # Nordic nRF52840 Sniffer — passive BLE capture
    # Prereq: flash nRF Sniffer firmware, install Wireshark plugin
    "nrf_sniffer": [
        "pyserial>=3.5",           # Serial comms with the dongle
    ],

    # BTLEJack — BLE connection hijacking (micro:bit / nRF52840)
    # Prereq: flash BTLEJack firmware to a BBC micro:bit
    "btlejack": [
        "btlejack>=1.2",           # BTLEJack Python CLI + library
        "pyserial>=3.5",
    ],

    # HackRF One — SDR-based BLE + Classic passive capture
    # Prereq: sudo apt install hackrf gr-bluetooth
    "hackrf": [
        "scapy>=2.5.0",            # BLE/BT frame dissection
    ],

    # YARD Stick One — sub-GHz / BLE injection
    # rfcat is not on PyPI; install from source:
    #   pip install git+https://github.com/atlas0fd00m/rfcat.git
    "yard_stick": [],

    # SweynTooth / low-level BLE connections (Linux only)
    # Prereq: sudo apt install libglib2.0-dev
    "ble_advanced": [
        "bluepy>=1.3.0",           # Raw BLE + GATT handle access
        "scapy>=2.5.0",
    ],

    # ── UI extras ────────────────────────────────────────────────────────
    "ui": [
        "rich>=13.0.0",            # Colour tables, progress bars
        "cmd2>=2.4.0",             # Advanced REPL (history, scripting)
    ],

    # ── Development / CI ─────────────────────────────────────────────────
    "dev": [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "black>=23.0.0",
        "flake8>=6.0.0",
        "mypy>=1.5.0",
    ],

    # ── Full kitchen-sink install ─────────────────────────────────────────
    # pip install ".[full]"
    # System prereqs:
    #   sudo apt install bluez bluetooth libbluetooth-dev python3-dev \
    #                    libglib2.0-dev ubertooth hackrf gr-bluetooth wireshark
    "full": [
        # Core protocol
        "bleak>=0.21.0",
        "pybluez2>=0.46",
        # Packet crafting + crypto
        "scapy>=2.5.0",
        "cryptography>=41.0.0",
        # Hardware dongles
        "pyserial>=3.5",
        "btlejack>=1.2",
        # Low-level BLE
        "bluepy>=1.3.0",
        # UI
        "rich>=13.0.0",
        "cmd2>=2.4.0",
    ],
}


setup(
    name="bluesploit",
    version="1.1.0",
    author="v33ru",
    author_email="v33ru@iotsrg.org",
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
