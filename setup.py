#!/usr/bin/env python3
"""
BlueSploit - Bluetooth Exploitation Framework
Setup script for installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
this_directory = Path(__file__).parent
long_description = ""
readme_path = this_directory / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

# Read requirements
requirements = [
    "bleak>=0.21.0",           # BLE support (cross-platform)
]

# Optional dependencies
extras_require = {
    "classic": [
        "pybluez>=0.23",       # Bluetooth Classic support (Linux)
    ],
    "dev": [
        "pytest>=7.0.0",
        "pytest-asyncio>=0.21.0",
        "black>=23.0.0",
        "flake8>=6.0.0",
    ],
    "full": [
        "pybluez>=0.23",
        "scapy>=2.5.0",        # Packet crafting
        "rich>=13.0.0",        # Enhanced terminal UI
        "cmd2>=2.4.0",         # Advanced CLI features
    ]
}

setup(
    name="bluesploit",
    version="1.0.0",
    author="v33ru",
    author_email="v33ru@iotsrg.org",
    description="Bluetooth Exploitation Framework for Security Researchers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/v33ru/bluesploit",
    project_urls={
        "Bug Tracker": "https://github.com/v33ru/bluesploit/issues",
        "Documentation": "https://github.com/v33ru/bluesploit/wiki",
        "Source": "https://github.com/v33ru/bluesploit",
    },
    
    # Package configuration
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
    install_requires=requirements,
    extras_require=extras_require,
    
    # Entry points for CLI
    entry_points={
        "console_scripts": [
            "bluesploit=bluesploit:main",
            "bsploit=bluesploit:main",  # Short alias
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows :: Windows 10",
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
    
    # Keywords for PyPI
    keywords=[
        "bluetooth",
        "ble",
        "security",
        "exploitation",
        "pentest",
        "penetration-testing",
        "bluetooth-low-energy",
        "iot",
        "iot-security",
        "wireless",
        "hacking",
        "vulnerability-scanner",
    ],
    
    # License
    license="MIT",
)
