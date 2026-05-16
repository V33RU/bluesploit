#!/bin/bash
#
# BlueSploit Installation Script
# Bluetooth Exploitation Framework
#
# Usage: ./install.sh [--full|--dev|--classic]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║           BlueSploit Installation Script                  ║"
echo "║           Bluetooth Exploitation Framework                ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python version
echo -e "${YELLOW}[*] Checking Python version...${NC}"
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}[!] python3 is required but not found in PATH${NC}"
    exit 1
fi
PYTHON_VERSION=$(python3 -c 'import sys; print("{0}.{1}".format(sys.version_info[0], sys.version_info[1]))')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}[!] Python 3.8+ is required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python $PYTHON_VERSION detected${NC}"

# Check OS
OS="$(uname -s)"
echo -e "${YELLOW}[*] Detected OS: $OS${NC}"

# Pick a sudo command (use sudo only when not already root and sudo is present)
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
    echo -e "${YELLOW}[!] sudo not found and not running as root, system-package installs may fail${NC}"
fi

# Check if Bluetooth dev headers are already present so we can skip apt
deps_already_present() {
    # bluetooth.h alone is not enough: bluepy also needs glib-2.0 headers
    # and pkg-config to find them. Issue #46 (Ubuntu 24.04) hit this.
    command -v hcitool   >/dev/null 2>&1 || return 1
    command -v pkg-config >/dev/null 2>&1 || return 1
    [ -f /usr/include/bluetooth/bluetooth.h ] || return 1
    pkg-config --exists glib-2.0 || return 1
    return 0
}

# Install system dependencies based on OS / package manager
install_system_deps() {
    if deps_already_present; then
        echo -e "${GREEN}[+] System Bluetooth deps already present, skipping apt${NC}"
        return 0
    fi
    echo -e "${YELLOW}[*] Installing system dependencies...${NC}"

    if [ "$OS" = "Linux" ]; then
        if command -v apt-get >/dev/null 2>&1; then
            # Debian / Ubuntu / Kali / Mint / Pop!_OS
            $SUDO apt-get update || true
            $SUDO apt-get install -y bluetooth bluez libbluetooth-dev python3-dev \
                libglib2.0-dev pkg-config build-essential
        elif command -v dnf >/dev/null 2>&1; then
            # Fedora / RHEL 8+ / Rocky / Alma
            $SUDO dnf install -y bluez bluez-libs-devel python3-devel glib2-devel \
                pkgconf-pkg-config gcc gcc-c++ make
        elif command -v yum >/dev/null 2>&1; then
            # CentOS 7 / older RHEL
            $SUDO yum install -y bluez bluez-libs-devel python3-devel glib2-devel \
                pkgconfig gcc gcc-c++ make
        elif command -v pacman >/dev/null 2>&1; then
            # Arch / Manjaro / EndeavourOS
            $SUDO pacman -S --noconfirm --needed bluez bluez-utils glib2 pkgconf base-devel
        elif command -v zypper >/dev/null 2>&1; then
            # openSUSE / SLE
            $SUDO zypper install -y --no-confirm bluez libbluetooth-devel python3-devel \
                glib2-devel pkg-config gcc gcc-c++ make || \
            $SUDO zypper install -y bluez bluez-devel python3-devel glib2-devel \
                pkg-config gcc gcc-c++ make
        elif command -v apk >/dev/null 2>&1; then
            # Alpine
            $SUDO apk add --no-cache bluez bluez-dev python3-dev glib-dev \
                pkgconfig build-base linux-headers
        elif command -v xbps-install >/dev/null 2>&1; then
            # Void Linux
            $SUDO xbps-install -Sy bluez bluez-devel python3-devel glib-devel \
                pkg-config base-devel
        elif command -v emerge >/dev/null 2>&1; then
            # Gentoo
            $SUDO emerge --noreplace net-wireless/bluez dev-libs/glib dev-util/pkgconf
        else
            echo -e "${YELLOW}[!] Unknown Linux distro, install BlueZ + headers manually${NC}"
            return
        fi
        echo -e "${GREEN}[+] System packages installed${NC}"
    elif [ "$OS" = "Darwin" ]; then
        echo -e "${YELLOW}[*] macOS detected, Bluetooth (CoreBluetooth) is built-in${NC}"

        # Xcode CLI Tools, required for the modules/dos/macos_* embedded-C exploits.
        # The c_runner helper compiles each module's C / ObjC source at runtime
        # via clang and links against -framework IOKit / -framework Foundation.
        if xcode-select -p >/dev/null 2>&1 && command -v clang >/dev/null 2>&1; then
            echo -e "${GREEN}[+] Xcode CLI Tools present (clang available)${NC}"
        else
            echo -e "${YELLOW}[*] Xcode CLI Tools missing, required for macOS exploit modules${NC}"
            echo -e "${YELLOW}    Triggering installer (this opens a GUI prompt, accept it)${NC}"
            xcode-select --install 2>/dev/null || true
            echo -e "${YELLOW}    After the GUI installer finishes, re-run this script${NC}"
        fi

        if ! command -v brew >/dev/null 2>&1; then
            echo -e "${YELLOW}[!] Homebrew not found, skipping optional packages${NC}"
            echo -e "${YELLOW}    Install Homebrew from https://brew.sh if you need extras${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Unsupported OS: $OS, skipping system packages${NC}"
    fi
}

# Parse arguments
INSTALL_TYPE="basic"
while [[ $# -gt 0 ]]; do
    case $1 in
        --full)
            INSTALL_TYPE="full"
            shift
            ;;
        --dev)
            INSTALL_TYPE="dev"
            shift
            ;;
        --classic)
            INSTALL_TYPE="classic"
            shift
            ;;
        --no-deps)
            SKIP_SYSTEM_DEPS=1
            shift
            ;;
        -h|--help)
            echo "Usage: ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full      Install all dependencies including extras"
            echo "  --dev       Install development dependencies"
            echo "  --classic   Install Bluetooth Classic support (Linux)"
            echo "  --no-deps   Skip system dependency installation"
            echo "  -h, --help  Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Install system dependencies
if [ -z "$SKIP_SYSTEM_DEPS" ]; then
    install_system_deps
fi

# Create virtual environment (optional)
echo -e "${YELLOW}[*] Setting up Python environment...${NC}"

# Install Python dependencies
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"

# Pick pip command (prefer `python3 -m pip` for venv-correctness)
PIP="python3 -m pip"

# pip flags: PEP 668 ("externally-managed-environment") is enforced on
# recent Debian/Ubuntu/Fedora system Pythons. If we're not in a venv,
# add --break-system-packages so the install works as documented.
PIP_FLAGS=""
if ! python3 -c 'import sys; sys.exit(0 if sys.prefix != sys.base_prefix else 1)' 2>/dev/null; then
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
        # --break-system-packages: bypass PEP 668 lock
        # --ignore-installed:      skip uninstall of apt-managed packages that
        #                          have no RECORD file (rich, scapy, cryptography
        #                          on Debian/Ubuntu are commonly apt-installed)
        # --user:                  install into ~/.local so we don't need to
        #                          touch system dirs
        PIP_FLAGS="--break-system-packages --ignore-installed --user"
    fi
fi

# pybluez2 0.46 sdist on PyPI ships broken (missing btmodule.h header,
# fails to build). Try sources in order, all pinned for supply chain safety.
#
# Update the pinned SHA here when bumping. Look up current HEAD with:
#   curl -s https://api.github.com/repos/pybluez/pybluez/commits/master \
#       | python3 -c "import json,sys; print(json.load(sys.stdin)['sha'])"
PYBLUEZ_GIT_SHA="82cbba8a1ebd4c1e3442dfafd8581d58c50fa39e"  # 2023-12-21
PYBLUEZ2_PINNED_VERSION="0.30"

install_pybluez() {
    if [ "$OS" != "Linux" ]; then
        echo -e "${YELLOW}[!] Classic BT (pybluez) only supported on Linux${NC}"
        return 0
    fi
    echo -e "${YELLOW}[*] Installing pybluez (Classic BT bindings)...${NC}"

    # Source 1: maintained pybluez repo on GitHub, pinned to a commit SHA.
    # NEVER install from the moving 'master' ref, a takeover or commit
    # injection at upstream would yield code execution on every install.
    local pybluez_url="git+https://github.com/pybluez/pybluez.git@${PYBLUEZ_GIT_SHA}#egg=pybluez"
    if $PIP install $PIP_FLAGS "$pybluez_url" 2>/dev/null; then
        echo -e "${GREEN}[+] pybluez installed from GitHub (pinned @${PYBLUEZ_GIT_SHA:0:12})${NC}"
        return 0
    fi

    # Source 2: pinned older pybluez2 release (0.30 still builds cleanly).
    if $PIP install $PIP_FLAGS "pybluez2==${PYBLUEZ2_PINNED_VERSION}" 2>/dev/null; then
        echo -e "${GREEN}[+] pybluez2 ${PYBLUEZ2_PINNED_VERSION} installed${NC}"
        return 0
    fi

    # Source 3: system package (apt), install at OS level, signed by distro.
    # We deliberately skip "pip install pybluez2" without a version pin,
    # the risk of a hijacked future release at unknown version is too high
    # given how rarely this codepath is exercised.
    if command -v apt-get >/dev/null 2>&1; then
        echo -e "${YELLOW}[*] All pip sources failed, falling back to apt python3-bluez${NC}"
        if $SUDO apt-get install -y python3-bluez 2>/dev/null; then
            echo -e "${GREEN}[+] python3-bluez installed via apt${NC}"
            echo -e "${YELLOW}[!] You may need 'python3 -m venv --system-site-packages env' to use it${NC}"
            return 0
        fi
    fi

    echo -e "${RED}[!] pybluez install failed via all sources${NC}"
    echo -e "${YELLOW}    Classic BT modules (RFCOMM/L2CAP) will be unavailable${NC}"
    echo -e "${YELLOW}    BLE modules will still work via bleak${NC}"
    return 1
}

# All install paths read from requirements.txt or pyproject.toml ".[dev]".
# Both are version-pinned (see pyproject.toml), so transient pip installs
# of unpinned packages would only weaken supply chain protection. Don't
# add them here.
case $INSTALL_TYPE in
    basic)
        $PIP install $PIP_FLAGS -r requirements.txt
        ;;
    full)
        # requirements.txt already covers rich/cmd2/scapy (pinned).
        $PIP install $PIP_FLAGS -r requirements.txt
        install_pybluez
        ;;
    dev)
        # Pulls dev tools from the [dev] extra in pyproject.toml, all
        # pinned with == there.
        $PIP install $PIP_FLAGS -r requirements.txt
        $PIP install $PIP_FLAGS ".[dev]"
        ;;
    classic)
        $PIP install $PIP_FLAGS -r requirements.txt
        install_pybluez
        ;;
esac

echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Install BlueSploit
echo -e "${YELLOW}[*] Installing BlueSploit...${NC}"

# Make main script executable
chmod +x bluesploit.py

# Create symlink for global access (optional, best-effort)
SYMLINK_TARGET="/usr/local/bin/bluesploit"
if [ "$(id -u)" -eq 0 ] || [ -w "$(dirname "$SYMLINK_TARGET")" ]; then
    ln -sf "$(pwd)/bluesploit.py" "$SYMLINK_TARGET" 2>/dev/null && \
        echo -e "${GREEN}[+] Created symlink: $SYMLINK_TARGET${NC}" || \
        echo -e "${YELLOW}[!] Could not create symlink at $SYMLINK_TARGET${NC}"
elif [ -n "$SUDO" ]; then
    $SUDO ln -sf "$(pwd)/bluesploit.py" "$SYMLINK_TARGET" 2>/dev/null && \
        echo -e "${GREEN}[+] Created symlink: $SYMLINK_TARGET${NC}" || \
        echo -e "${YELLOW}[!] Could not create symlink (skip with --no-deps)${NC}"
fi

# Create data directories
mkdir -p data/wordlists
mkdir -p data/oui
mkdir -p data/profiles
mkdir -p data/signatures

# Create basic wordlist
if [ ! -f "data/wordlists/pins_4digit.txt" ]; then
    echo -e "${YELLOW}[*] Creating default PIN wordlist...${NC}"
    # macOS BSD seq doesn't support -w; use Python for portability
    python3 -c 'import sys
sys.stdout.writelines(f"{i:04d}\n" for i in range(10000))' \
        > data/wordlists/pins_4digit.txt
    echo -e "${GREEN}[+] Created 4-digit PIN wordlist${NC}"
fi

# Verify installation
echo -e "${YELLOW}[*] Verifying installation...${NC}"

python3 -c "from core.interpreter import BlueSploitInterpreter; print('Core module: OK')" 2>/dev/null && \
    echo -e "${GREEN}[+] Core modules loaded successfully${NC}" || \
    echo -e "${RED}[!] Failed to load core modules${NC}"

python3 -c "import bleak; print('Bleak: OK')" 2>/dev/null && \
    echo -e "${GREEN}[+] BLE support available${NC}" || \
    echo -e "${YELLOW}[!] BLE support not available (install bleak)${NC}"

if [ "$OS" = "Linux" ]; then
    python3 -c "import bluetooth; print('PyBluez: OK')" 2>/dev/null && \
        echo -e "${GREEN}[+] Bluetooth Classic support available${NC}" || \
        echo -e "${YELLOW}[!] Classic BT not available (optional)${NC}"
fi

if [ "$OS" = "Darwin" ]; then
    if command -v clang >/dev/null 2>&1; then
        echo -e "${GREEN}[+] clang found, macOS embedded-C exploit modules ready${NC}"
    else
        echo -e "${YELLOW}[!] clang missing, modules/dos/macos_* will be unavailable${NC}"
        echo -e "${YELLOW}    Run:  xcode-select --install${NC}"
    fi
fi

# Done
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation Complete!                          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Run BlueSploit:"
echo -e "  ${CYAN}python3 bluesploit.py${NC}"
echo ""
echo -e "Or if installed globally:"
echo -e "  ${CYAN}bluesploit${NC}"
echo ""
echo -e "${YELLOW}Note: Some features require root/sudo privileges${NC}"
echo ""
