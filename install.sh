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
    echo -e "${YELLOW}[!] sudo not found and not running as root — system-package installs may fail${NC}"
fi

# Install system dependencies based on OS / package manager
install_system_deps() {
    echo -e "${YELLOW}[*] Installing system dependencies...${NC}"

    if [ "$OS" = "Linux" ]; then
        if command -v apt-get >/dev/null 2>&1; then
            # Debian / Ubuntu / Kali / Mint / Pop!_OS
            $SUDO apt-get update
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
            echo -e "${YELLOW}[!] Unknown Linux distro — install BlueZ + headers manually${NC}"
            return
        fi
        echo -e "${GREEN}[+] System packages installed${NC}"
    elif [ "$OS" = "Darwin" ]; then
        echo -e "${YELLOW}[*] macOS detected — Bluetooth (CoreBluetooth) is built-in${NC}"
        if ! command -v brew >/dev/null 2>&1; then
            echo -e "${YELLOW}[!] Homebrew not found — skipping optional packages${NC}"
            echo -e "${YELLOW}    Install Homebrew from https://brew.sh if you need extras${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Unsupported OS: $OS — skipping system packages${NC}"
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
        PIP_FLAGS="--break-system-packages"
    fi
fi

case $INSTALL_TYPE in
    basic)
        $PIP install $PIP_FLAGS -r requirements.txt
        ;;
    full)
        $PIP install $PIP_FLAGS -r requirements.txt
        $PIP install $PIP_FLAGS rich cmd2 scapy
        if [ "$OS" = "Linux" ]; then
            $PIP install $PIP_FLAGS pybluez2 || \
                echo -e "${YELLOW}[!] pybluez2 install failed — Classic BT will be unavailable${NC}"
        fi
        ;;
    dev)
        $PIP install $PIP_FLAGS -r requirements.txt
        $PIP install $PIP_FLAGS pytest pytest-asyncio black flake8
        ;;
    classic)
        $PIP install $PIP_FLAGS -r requirements.txt
        if [ "$OS" = "Linux" ]; then
            $PIP install $PIP_FLAGS pybluez2 || \
                echo -e "${YELLOW}[!] pybluez2 install failed${NC}"
        else
            echo -e "${YELLOW}[!] Classic BT (pybluez2) only supported on Linux${NC}"
        fi
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
