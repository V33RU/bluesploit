# Quick Start

A 60-second tour: scan → pick a module → run it.

---

## 1. Launch the console

```bash
sudo python3 bluesploit.py
```

You'll see the banner and a `bluesploit >` prompt.

---

## 2. Discover nearby devices

```text
bluesploit > use recon/discovery
bluesploit(recon/discovery) > set DURATION 10
bluesploit(recon/discovery) > run
```

Output lists MAC, name, RSSI, and class-of-device for every responder.

---

## 3. Fingerprint a target

```text
bluesploit > use recon/version_fingerprint
bluesploit(recon/version_fingerprint) > set TARGET AA:BB:CC:DD:EE:FF
bluesploit(recon/version_fingerprint) > run
```

This identifies BT version, manufacturer, and likely chipset — useful for matching to known CVEs.

---

## 4. Scan for known vulns

```text
bluesploit > use scanners/vuln_scanner
bluesploit(scanners/vuln_scanner) > set TARGET AA:BB:CC:DD:EE:FF
bluesploit(scanners/vuln_scanner) > run
```

The scanner cross-references discovered properties against signatures in `data/signatures/`.

---

## 5. Run an exploit

```text
bluesploit > use exploits/knob
bluesploit(exploits/knob) > show options
bluesploit(exploits/knob) > set TARGET AA:BB:CC:DD:EE:FF
bluesploit(exploits/knob) > check     # safe pre-flight
bluesploit(exploits/knob) > run
```

Use `back` to leave the module, `exit` to quit the console.

---

## CLI mode (no REPL)

```bash
python3 bluesploit.py --list                # list every module
```

---

Next: [Console Commands](console-commands.md) for the full REPL reference, or [Module Categories](module-categories.md) to browse what's available.
