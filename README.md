# BlueSploit - Bluetooth Exploitation Framework

## Quick Start

```bash
# Run the console (default)
python bluesploit.py

# Run with hacker theme (green colors)
python bluesploit.py --theme hacker

# Run web interface (requires Flask)
python bluesploit.py --web

# List all modules
python bluesploit.py --list
```

## Console Commands

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `use <module>` | Select a module |
| `set <opt> <val>` | Set option value |
| `options` | Show current options |
| `run` | Execute module |
| `back` | Deselect module |
| `show modules` | List all modules |
| `show scanners` | List scanners |
| `show exploits` | List exploits |
| `search <term>` | Search modules |
| `info <module>` | Show module info |
| `theme <name>` | Change theme |
| `exit` | Exit |

## Available Themes

- `default` - Cyan/Red (default)
- `hacker` - Green Matrix style
- `ocean` - Blue tones
- `fire` - Red/Orange
- `purple` - Purple/Magenta

## Modules Included

### Scanners
- `scanners/ble_scanner` - BLE Device Discovery
- `scanners/classic_scanner` - Classic Bluetooth Scanner
- `scanners/hidden_scanner` - Find Hidden Devices

### Recon
- `recon/vuln_scanner` - CVE Vulnerability Detection
- `recon/gatt_enum` - BLE GATT Enumeration
- `recon/sdp_enum` - SDP Service Discovery
- `recon/oui_lookup` - Manufacturer Lookup

### Exploits
- `exploits/bluefrag` - CVE-2020-0022 (Android RCE)
- `exploits/keystroke_injection` - HID Injection
- `exploits/blueborne_rce` - CVE-2017-1000251

### DoS
- `dos/bluesmack` - L2CAP Ping Flood
- `dos/ble_flood` - BLE Connection Flood

## Example Session

```
$ python bluesploit.py

    ____  __           _____       __      _ __ 
   / __ )/ /_  _____  / ___/____  / /___  (_) /_
  / __  / / / / / _ \ \__ \/ __ \/ / __ \/ / __/
 / /_/ / / /_/ /  __/___/ / /_/ / / /_/ / / /_  
/_____/_/\__,_/\___//____/ .___/_/\____/_/\__/  
                        /_/                     

bluesploit > use scanners/ble_scanner
[+] Using: scanners/ble_scanner

bluesploit(scanners/ble_scanner) > options

  Name            Value                Req   Description
  ───────────────────────────────────────────────────────
  timeout         10                   No    Scan duration (seconds)
  rssi_filter     -100                 No    Min RSSI threshold

bluesploit(scanners/ble_scanner) > run
[*] Scanning for BLE devices (10s)...
  Scanning [████████████████████████████████████████] 100.0%

  ════════════════════════════════════════════════════════════
  BLE SCAN RESULTS
  ════════════════════════════════════════════════════════════
  Found: 4 devices

  ADDRESS              NAME            RSSI       TYPE
  ────────────────────────────────────────────────────────────
  AA:BB:CC:DD:EE:FF    iPhone 14       -45 dBm    Phone
  11:22:33:44:55:66    Galaxy S21      -62 dBm    Phone

bluesploit(scanners/ble_scanner) > back
[*] Module deselected

bluesploit > use exploits/bluefrag
[+] Using: exploits/bluefrag
[*] CVE: CVE-2020-0022

bluesploit(exploits/bluefrag) > set target AA:BB:CC:DD:EE:FF
[+] target => AA:BB:CC:DD:EE:FF

bluesploit(exploits/bluefrag) > run
[*] Target: AA:BB:CC:DD:EE:FF
[*] Mode: check
✓ Running check mode...
[+] Target appears VULNERABLE to CVE-2020-0022

bluesploit > exit
[*] Goodbye!
```

## Web Interface

```bash
# Install Flask (optional, for web UI)
pip install flask

# Start web interface
python bluesploit.py --web

# Open in browser
# http://127.0.0.1:5000
```

## Requirements

- Python 3.7+
- No external dependencies for console mode
- Flask (optional, for web interface)

## Author

v33ru (IOTSRG)

## Disclaimer

This tool is for educational and authorized security testing only.
