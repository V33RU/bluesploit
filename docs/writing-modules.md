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

- **One module per file.** File name = module name (`my_exploit.py` → `exploits/my_exploit`).
- **Use `print_info` / `print_ok` / `print_err`** from `core.utils.printer` — never `print()` directly.
- **Validate inputs** in `check()`, not deep inside `run()`.
- **Gate platform-specific code** with `import sys; if sys.platform != "linux": ...`.
- **Reuse `core/hardware.py`** for adapter access — don't open raw HCI sockets directly unless you must.
- **Keep module options small.** If a module needs >8 options, it's probably two modules.

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
4. Open a PR — see [Contributing](contributing.md).
