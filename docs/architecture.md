# Architecture

```
bluesploit.py                # CLI entrypoint (--list / interactive)
core/
├── interpreter.py           # cmd2-based REPL, dispatches use/set/run/...
├── loader.py                # Recursively discovers modules under modules/
├── base.py                  # Base classes: ExploitBase, ScannerBase, DoSBase, ...
├── hardware.py              # Adapter abstraction (HCI / Ubertooth / nRF / ...)
├── capture.py               # PCAP write helpers
├── store.py                 # SQLite-backed engagement state (hosts, creds, loot, workspaces)
├── bt_raw.py                # Low-level Bluetooth frame builders
├── ui/                      # Themes
└── utils/
    ├── bt.py                # Shared HCI / BD_ADDR / L2CAP helpers
    ├── printer.py           # print_info, print_ok, print_err, print_banner
    ├── c_runner.py          # macOS embedded C / Objective-C compile+run
    └── iokit.py             # macOS IOKit bridge
modules/
├── exploits/                # CVE-backed PoCs
├── dos/                     # Bluesmack, L2CAP/RFCOMM/SDP floods, kernel DoS
├── scanners/                # Vuln scan, BlueBorne scan, hidden device scan
├── recon/                   # Discovery, GATT/SDP enum, OUI lookup, fingerprint
├── auxiliary/               # Sniffers, fuzzers, RPA deanon
└── post/                    # Link-key dump, GATT exfil, session hijack
data/
├── wordlists/               # PIN / passkey lists (e.g. pins_4digit.txt)
├── oui/                     # IEEE OUI vendor mapping (drop-in CSV)
├── profiles/                # Vendor/firmware fingerprint profiles
└── signatures/              # CVE -> fingerprint signatures (vuln_scanner)
scripts/
├── gen_module_docs.py       # Auto-build the mkdocs catalog from module metadata
├── validate_modules.py      # AST gate over modules/ (run in CI)
└── test_*.py                # pytest suites for core/
```

---

## Module lifecycle

1. `core.loader.ModuleLoader` walks `modules/`, imports every `.py`
   file, and registers any class deriving from a base class.
2. `use <path>` instantiates the module class.
3. `set <opt> <val>` writes to the module's option dict. `target`
   resolves through the store and triggers credential autofill, see
   [Engagement State](engagement-state.md).
4. `check()` runs a non-destructive pre-flight (optional, recommended).
5. `run()` (or `exploit()` alias) executes.

---

## Persistent state

`core/store.py` exposes a small `Store` class backed by SQLite. Every
module receives a lazy `self.store` so it can record discovered hosts,
recovered credentials, and looted artifacts without rolling its own
output file. The REPL provides operator-facing verbs (`hosts`, `creds`,
`workspace`, `setg`) over the same store.

The file lives at `~/.bluesploit/store.db` or `$BLUESPLOIT_HOME/store.db`,
opened in WAL mode with foreign keys on. Schema version is recorded in
a `meta` table so future migrations have a path.

Workspaces are a single string column on every row; default workspace
is `default`. The active workspace and any persisted `setg` overrides
survive restarts.

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

Scanners, DoS, recon, auxiliary, and post modules each have an
analogous base class. All of them inherit `self.store` for engagement
state writes.

---

## Hardware abstraction

`core/hardware.py` exposes a single `get_adapter(kind)` factory.
Modules that want a specific backend ask for it (`"hci"`,
`"ubertooth"`, `"nrf"`, `"btlejack"`, `"hackrf"`, `"yard"`); generic
BLE modules use `bleak` directly for cross-platform support.

For raw HCI plumbing (BD_ADDR parsing, L2CAP framing, feature bitmap
decoding) modules should reach for `core/utils/bt.py` instead of
hand-rolling socket and struct code.

---

## Where to look next

- [Engagement State](engagement-state.md), how the persistent store works
- [Console Commands](console-commands.md), the full REPL reference
- [Writing Modules](writing-modules.md), author your own module
- [Hardware Setup](hardware-setup.md), backend installation
- [Module Categories](module-categories.md), what each category contains
