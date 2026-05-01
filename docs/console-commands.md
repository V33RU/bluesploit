# Console Commands

The BlueSploit REPL is built on `cmd2` and follows Metasploit/RouterSploit conventions.

---

## Module navigation

| Command | Description |
|---|---|
| `use <path>` | Load a module (e.g. `use exploits/knob`) |
| `back` | Leave the current module |
| `search <term>` | Search modules by name/description |
| `show modules` | List every loaded module |
| `show <category>` | List modules in a category (`exploits`, `scanners`, `dos`, `recon`, `auxiliary`, `post`) |

---

## Inside a module

| Command | Description |
|---|---|
| `show options` | Print all settable options + current values |
| `show info` | Module metadata (CVE, author, references) |
| `set <opt> <val>` | Set an option (e.g. `set TARGET AA:BB:CC:DD:EE:FF`) |
| `unset <opt>` | Clear an option |
| `check` | Pre-flight safety check (no exploitation) |
| `run` / `exploit` | Execute the module |

---

## Global

| Command | Description |
|---|---|
| `help [cmd]` | Built-in help |
| `history` | Command history (saved to `.bluesploit_history`) |
| `!<shell-cmd>` | Run a shell command (e.g. `!hciconfig`) |
| `clear` | Clear the screen |
| `exit` / `quit` | Leave BlueSploit |

---

## Typical session

```text
bluesploit > search knob
bluesploit > use exploits/knob
bluesploit(exploits/knob) > show options
bluesploit(exploits/knob) > set TARGET AA:BB:CC:DD:EE:FF
bluesploit(exploits/knob) > set IFACE hci0
bluesploit(exploits/knob) > check
bluesploit(exploits/knob) > run
bluesploit(exploits/knob) > back
bluesploit > exit
```

---

## Tips

- Tab-completion works for commands, module paths, and option names.
- History persists across sessions in `~/.bluesploit_history` (or repo root, depending on launch).
- Prefix `!` runs anything in your shell — handy for `hciconfig`, `bluetoothctl`, `rfkill`.
