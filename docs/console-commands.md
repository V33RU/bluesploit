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
bsploit > search knob
bsploit > use exploits/knob
bsploit (exploits/knob) > show options
bsploit (exploits/knob) > set TARGET AA:BB:CC:DD:EE:FF
bsploit (exploits/knob) > set IFACE hci0
bsploit (exploits/knob) > check
bsploit (exploits/knob) > run
bsploit (exploits/knob) > back
bsploit > exit
```

---

## Tips

- Tab-completion works for commands, module paths, and option names.
- History persists across sessions in `~/.bluesploit_history` (or repo root, depending on launch).
- Prefix `!` runs anything in your shell — handy for `hciconfig`, `bluetoothctl`, `rfkill`.
