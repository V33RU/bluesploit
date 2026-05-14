# Writing Modules

Adding a module = drop a `.py` file under the right `modules/<category>/` directory. The loader auto-discovers it on next launch.

---

## Skeleton (Exploit)

```python
# modules/exploits/my_exploit.py
from core.base import ExploitBase
from core.utils.printer import print_info, print_ok, print_err


class Exploit(ExploitBase):
    info = {
        "name":        "My Exploit",
        "description": "One-line description of what it does.",
        "author":      ["yourhandle"],
        "cve":         ["CVE-2025-XXXXX"],
        "references":  ["https://example.com/advisory"],
        "platform":    ["linux"],          # or ["linux", "macos"]
    }

    options = {
        "TARGET":  {"value": "",    "required": True,  "desc": "Target MAC"},
        "IFACE":   {"value": "hci0","required": False, "desc": "HCI device"},
        "TIMEOUT": {"value": 10,    "required": False, "desc": "Seconds"},
    }

    def check(self):
        """Non-destructive pre-flight. Return True/False."""
        target = self.options["TARGET"]["value"]
        if not target:
            print_err("TARGET is required")
            return False
        print_ok(f"Target {target} reachable")
        return True

    def run(self):
        if not self.check():
            return
        target = self.options["TARGET"]["value"]
        print_info(f"Exploiting {target}...")
        # ... your logic ...
        print_ok("Done")
```

---

## Skeleton (Scanner / DoS / Recon / Auxiliary / Post)

Same pattern, different base class:

```python
from core.base import ScannerBase    # scanners/
from core.base import DoSBase        # dos/
from core.base import ReconBase      # recon/
from core.base import AuxiliaryBase  # auxiliary/
from core.base import PostBase       # post/
```

The class name should be `Scanner`, `DoS`, `Recon`, `Auxiliary`, or `Post` respectively.

---

## Conventions

- **One module per file.** File name = module name (`my_exploit.py` -> `exploits/my_exploit`).
- **Use `print_info` / `print_ok` / `print_err`** from `core.utils.printer`, never `print()` directly.
- **Validate inputs** in `check()`, not deep inside `run()`.
- **Gate platform-specific code** with `import sys; if sys.platform != "linux": ...`.
- **Reuse `core/utils/bt.py`** for raw HCI / BD_ADDR / L2CAP plumbing instead of hand-rolling socket and struct code in every module.
- **Reuse `core/hardware.py`** for adapter access, do not open raw HCI sockets directly unless you must.
- **Keep module options small.** If a module needs >8 options, it is probably two modules.

---

## Writing to the engagement store

Every module has a lazy `self.store` that points at the active workspace's
SQLite-backed state. Use it instead of inventing a per-module `output_file`
option, so downstream modules and the `hosts` / `creds` console commands
can see what you produced.

```python
# Recon module recording discovered devices
def run(self):
    for d in discovered_devices:
        self.store.add_host(
            address=d.address,
            name=d.name,
            rssi=d.rssi,
            manufacturer=d.vendor,
        )

# Post-exploitation module recording a recovered credential
def run(self):
    link_key = self._extract_link_key(...)
    self.store.add_credential(
        host=self.get_option("target"),    # address or stored host id
        kind="LinkKey",
        value=link_key.hex(),
        metadata=json.dumps({"pin_length": 4}),
    )
```

Available helpers on `self.store`:

| Method                                                            | Use                                       |
|-------------------------------------------------------------------|-------------------------------------------|
| `add_host(address, name=None, rssi=None, manufacturer=None)`      | Record / update a discovered device       |
| `add_credential(host, kind, value, metadata=None)`                | Persist a key/PIN tied to a host          |
| `add_loot(host, kind, data, source=None)`                         | Persist arbitrary bytes (PCAP, GATT dump) |
| `list_hosts() / list_credentials() / list_loot()`                 | Read back rows in the active workspace    |
| `latest_credential(host, kind)`                                   | Drives `set target` autofill              |

Recognized credential kinds: `LinkKey`, `LTK`, `IRK`, `CSRK`, `PIN`,
`PeripheralLTK`. Other strings are accepted and stored verbatim; only
the standard kinds trigger `set target` autofill on a downstream module.

---

## Testing

```bash
python3 bluesploit.py --list | grep my_exploit    # discovery works?

# Quick syntactic check:
python3 -c "from modules.exploits.my_exploit import Exploit; e = Exploit(); print(e.info['name'])"

# Full pytest (if you wrote a test):
pytest tests/exploits/test_my_exploit.py
```

---

## Submitting

1. Branch off `main`.
2. Add module + (optional) signature in `data/signatures/`.
3. Update [Exploits](exploits.md) / [DoS](dos.md) / etc. wiki page.
4. Open a PR, see [Contributing](contributing.md).
