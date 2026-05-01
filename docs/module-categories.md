# Module Categories

BlueSploit ships **101 modules** across six categories. Module paths follow `category/name` (e.g. `exploits/knob`).

| Category | Count | Purpose |
|---|---:|---|
| [Exploits](exploits.md) | 69 | CVE-backed PoCs targeting BT/BLE stacks |
| [DoS](dos.md) | 10 | Denial-of-service / resource exhaustion |
| [Scanners](scanners.md) | 5 | Vulnerability identification |
| [Recon](recon.md) | 6 | Discovery, fingerprinting, enumeration |
| [Auxiliary](auxiliary.md) | 6 | Sniffers, fuzzers, hardware tools |
| [Post-Exploitation](post-exploitation.md) | 5 | Actions after a successful exploit |

---

## Listing modules

```bash
python3 bluesploit.py --list           # CLI: list every module
```

In the console:

```text
bluesploit > show modules         # everything
bluesploit > show exploits        # one category
bluesploit > search rfcomm        # name/description search
```

---

## Common option names

Most modules share a small option vocabulary:

| Option | Meaning |
|---|---|
| `TARGET` | Target MAC (`AA:BB:CC:DD:EE:FF`) |
| `IFACE` | Local HCI device (`hci0`, `hci1`) |
| `TIMEOUT` | Per-operation timeout in seconds |
| `DURATION` | Scan/run length in seconds |
| `THREADS` | Parallel workers (where applicable) |
| `WORDLIST` | Path to a wordlist (PIN/passkey modules) |
| `DEBUG` | Verbose output |

`show options` always lists the exact set for that module.
