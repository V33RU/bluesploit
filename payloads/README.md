# BlueSploit DuckyScript Payloads

Plain-text DuckyScript files consumed by `modules/exploits/blueducky.py`
(CVE-2023-45866 HID injection over Bluetooth).

## Usage

```
sudo python3 bluesploit.py
use exploits/blueducky
set target AA:BB:CC:DD:EE:FF
set interface hci0
set payload payloads/blueducky_hello.txt
set mode inject
run
```

## Supported DuckyScript subset

```
REM <comment>            ignored
DELAY <ms>               sleep
STRING <text>            type literal text (auto-shift handling)
ENTER / TAB / ESCAPE / BACKSPACE / SPACE
UP / DOWN / LEFT / RIGHT
F1..F12
GUI <key> / WINDOWS <key> / COMMAND <key>
CTRL <key> / ALT <key>   / SHIFT <key>
CTRL-ALT <key>           dash- or space-joined chords
PRIVATE_BROWSER          shorthand for CTRL+SHIFT+N
```

## Files

| Payload | Purpose |
|---|---|
| `blueducky_hello.txt` | Minimal sanity-check payload, types `hello world` + Enter |
| `blueducky_hackertyper.txt` | Opens private browser, navigates to hackertyper.net |
| `blueducky_whatsapp_message.txt` | Opens browser to wa.me/<number>, sends a few messages |
| `blueducky_terminal_open.txt` | Linux/Gnome, Ctrl+Alt+T to open terminal, types `id` |
| `blueducky_windows_run.txt` | Windows, Win+R run-dialog, opens Notepad |
| `blueducky_mac_terminal.txt` | macOS, Cmd+Space → Spotlight → Terminal |

## Authoring tips

- Always start with a generous `DELAY 500` so the target finishes the
  unauth-pair race before keystrokes start landing.
- Verify the payload first: `set mode check` then `run`, the parser
  reports any UNSUPPORTED lines.
- Test on your own device before any engagement.

Originally inspired by pentestfunctions/BlueDucky payload set.
