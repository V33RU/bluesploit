# Quick Start

A 60-second tour: scan → pick a module → run it.

---

## 1. Launch the console

```bash
sudo python3 bluesploit.py
```

You'll see the banner and a `bsploit >` prompt.

---

## 2. Discover nearby devices

```text
bsploit > use recon/discovery
bsploit (recon/discovery) > set DURATION 10
bsploit (recon/discovery) > run
```

Output lists MAC, name, RSSI, and class-of-device for every responder.

---

## 3. Fingerprint a target

```text
bsploit > use recon/version_fingerprint
bsploit (recon/version_fingerprint) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (recon/version_fingerprint) > run
```

This identifies BT version, manufacturer, and likely chipset — useful for matching to known CVEs.

---

## 4. Scan for known vulns

```text
bsploit > use scanners/vuln_scanner
bsploit (scanners/vuln_scanner) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (scanners/vuln_scanner) > run
```

The scanner cross-references discovered properties against signatures in `data/signatures/`.

---

## 5. Run an exploit

```text
bsploit > use exploits/knob
bsploit (exploits/knob) > show options
bsploit (exploits/knob) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (exploits/knob) > check     # safe pre-flight
bsploit (exploits/knob) > run
```

Use `back` to leave the module, `exit` to quit the console.

---

## CLI mode (no REPL)

```bash
python3 bluesploit.py --list                # list every module
```

---

Next: [Console Commands](console-commands.md) for the full REPL reference, or [Module Categories](module-categories.md) to browse what's available.
