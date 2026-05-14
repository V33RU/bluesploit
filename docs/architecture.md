# Architecture

```
bluesploit.py                # CLI entrypoint (--list / interactive)
core/
├── interpreter.py           # cmd2-based REPL, dispatches use/set/run/...
├── loader.py                # Recursively discovers modules under modules/
├── base.py                  # Base classes: ExploitBase, ScannerBase, DoSBase, ...
├── hardware.py              # Adapter abstraction (HCI / Ubertooth / nRF / ...)
├── capture.py               # PCAP write helpers
├── ui/                      # Rich-based tables, progress, banners
└── utils/
    └── printer.py           # print_info, print_ok, print_err, print_banner
modules/
├── exploits/                # 69 modules
├── dos/                     # 10
├── scanners/                # 5
├── recon/                   # 6
├── auxiliary/               # 6
└── post/                    # 5
data/
├── wordlists/               # PIN/passkey lists (e.g. pins_4digit.txt)
├── oui/                     # IEEE OUI vendor mapping
├── profiles/                # Vendor/firmware fingerprint profiles
└── signatures/              # CVE → fingerprint signatures (vuln_scanner)
```

---

## Module lifecycle

1. `core.loader.ModuleLoader` walks `modules/`, imports every `.py` file, and registers any class deriving from a base class.
2. `use <path>` instantiates the module class.
3. `set <opt> <val>` writes to the module's option dict.
4. `check()` runs a non-destructive pre-flight (optional, recommended).
5. `run()` (or `exploit()` alias) executes.

---

## Base class anatomy

```python
class ExploitBase:
    info = {
        "name":        "Human-readable name",
        "description": "...",
        "author":      ["..."],
        "cve":         ["CVE-2019-9506"],
        "references":  ["https://..."],
    }
    options = {
        "TARGET":  {"value": "", "required": True,  "desc": "Target MAC"},
        "IFACE":   {"value": "hci0", "required": False, "desc": "Local HCI device"},
    }

    def check(self): ...
    def run(self):   ...
```

Scanners, DoS, recon, auxiliary, and post modules each have an analogous base.

---

## Hardware abstraction

`core/hardware.py` exposes a single `get_adapter(kind)` factory. Modules that want a specific backend ask for it (`"hci"`, `"ubertooth"`, `"nrf"`, `"btlejack"`, `"hackrf"`, `"yard"`); generic BLE modules use `bleak` directly for cross-platform support.

---

## Where to look next

- [Writing Modules](writing-modules.md), author your own module
- [Hardware Setup](hardware-setup.md), backend installation
- [Module Categories](module-categories.md), what each category contains
