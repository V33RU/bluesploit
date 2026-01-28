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
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}[!] Python 3.8+ is required. Found: $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}[+] Python $PYTHON_VERSION detected${NC}"

# Check OS
OS="$(uname -s)"
echo -e "${YELLOW}[*] Detected OS: $OS${NC}"

# Install system dependencies based on OS
install_system_deps() {
    echo -e "${YELLOW}[*] Installing system dependencies...${NC}"
    
    if [ "$OS" = "Linux" ]; then
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y bluetooth bluez libbluetooth-dev
            echo -e "${GREEN}[+] BlueZ installed${NC}"
        elif command -v dnf &> /dev/null; then
            # Fedora
            sudo dnf install -y bluez bluez-libs-devel
        elif command -v pacman &> /dev/null; then
            # Arch
            sudo pacman -S --noconfirm bluez bluez-utils
        fi
    elif [ "$OS" = "Darwin" ]; then
        echo -e "${YELLOW}[*] macOS detected - Bluetooth support is built-in${NC}"
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

case $INSTALL_TYPE in
    basic)
        pip3 install -r requirements.txt
        ;;
    full)
        pip3 install -r requirements.txt
        pip3 install rich cmd2 scapy
        if [ "$OS" = "Linux" ]; then
            pip3 install pybluez
        fi
        ;;
    dev)
        pip3 install -r requirements.txt
        pip3 install pytest pytest-asyncio black flake8
        ;;
    classic)
        pip3 install -r requirements.txt
        if [ "$OS" = "Linux" ]; then
            pip3 install pybluez
        else
            echo -e "${YELLOW}[!] PyBluez only supported on Linux${NC}"
        fi
        ;;
esac

echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Install BlueSploit
echo -e "${YELLOW}[*] Installing BlueSploit...${NC}"

# Make main script executable
chmod +x bluesploit.py

# Create symlink for global access (optional)
if [ "$EUID" -eq 0 ]; then
    ln -sf "$(pwd)/bluesploit.py" /usr/local/bin/bluesploit
    echo -e "${GREEN}[+] Created symlink: /usr/local/bin/bluesploit${NC}"
fi

# Create data directories
mkdir -p data/wordlists
mkdir -p data/oui
mkdir -p data/profiles
mkdir -p data/signatures

# Create basic wordlist
if [ ! -f "data/wordlists/pins_4digit.txt" ]; then
    echo -e "${YELLOW}[*] Creating default PIN wordlist...${NC}"
    for i in $(seq -w 0 9999); do echo "$i"; done > data/wordlists/pins_4digit.txt
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
