# Contributing

Thanks for considering a contribution! BlueSploit is community-driven.

---

## Ground rules

- **Authorized use only.** Do not submit modules tested against equipment you don't own or have authorization to test.
- **Public CVEs / disclosed research only.** No 0-days.
- **Educational framing.** Every module should map to a public reference (CVE, advisory, paper, blog).
- **MIT-compatible.** All contributions are MIT-licensed.

---

## Workflow

```bash
# 1. Fork + clone
git clone https://github.com/<your-fork>/bluesploit.git
cd bluesploit

# 2. Install dev deps
./install.sh --dev

# 3. Branch
git checkout -b feat/my-module

# 4. Write code + (optional) tests
# 5. Format + lint
black .
flake8 .

# 6. Verify discovery
python3 bluesploit.py --list | grep my-module

# 7. Commit + push
git commit -am "exploits: add CVE-2025-XXXXX (my-module)"
git push origin feat/my-module

# 8. Open a PR against `main`
```

---

## Module checklist

- [ ] File under the right `modules/<category>/` directory
- [ ] Class name matches category (`Exploit`, `Scanner`, `DoS`, `Recon`, `Auxiliary`, `Post`)
- [ ] `info` dict includes `name`, `description`, `author`, `cve`, `references`
- [ ] `options` dict declares every settable parameter
- [ ] `check()` is non-destructive
- [ ] No hardcoded MACs or paths
- [ ] Cross-platform deps gated with `sys.platform`
- [ ] Wiki page updated ([Exploits](exploits.md) / [DoS](dos.md) / etc.)
- [ ] Manual test against real or emulated target

---

## Code style

- `black` (line length 100) + `flake8`
- Use type hints where they aid clarity
- Use `core.utils.printer` helpers, not bare `print()`
- Keep modules under ~300 lines — split helpers into `core/utils/` if needed

---

## Reporting bugs

Open an issue with:
- OS + Python version
- `pip list` excerpt for relevant packages
- Steps to reproduce
- Full traceback

For security bugs in BlueSploit itself, use the GitHub private advisory flow.
