# Console Commands

The BlueSploit REPL follows Metasploit/RouterSploit conventions: load a
module, set options, run. Engagement state (hosts, credentials, loot)
lives in a persistent store and feeds back into the REPL via a handful
of verbs introduced below.

For a conceptual tour see [Engagement State](engagement-state.md).

---

## Module navigation

| Command          | Description                                                                  |
|------------------|------------------------------------------------------------------------------|
| `use <path>`     | Load a module (e.g. `use exploits/knob`)                                     |
| `back`           | Leave the current module                                                     |
| `search <term>`  | Search modules by path, description, CVE, or author                          |
| `show modules`   | List every loaded module                                                     |
| `show <category>`| List modules in a category (`exploits`, `scanners`, `dos`, `recon`, `auxiliary`, `post`) |

---

## Inside a module

| Command          | Description                                                                  |
|------------------|------------------------------------------------------------------------------|
| `options`        | Print all settable options and current values                                |
| `info`           | Module metadata (CVE, author, references)                                    |
| `set <opt> <v>`  | Set an option. Special-case `target`, see below.                             |
| `unset <opt>`    | Clear an option                                                              |
| `check`          | Pre-flight safety check (no exploitation)                                    |
| `run` / `exploit`| Execute the module                                                           |

### `set target` resolution

The `target` option is smarter than other options. It accepts:

- A full BD_ADDR (`AA:BB:CC:DD:EE:FF`), passes through unchanged.
- A numeric host id (`3`), looked up in the store's `hosts` table.
- A substring (`alpha`), resolves when it matches exactly one stored
  host on either address or name. Ambiguous matches print candidates
  and leave the option unset.

When `set target` resolves to a stored host, any option on the loaded
module whose name is one of `link_key`, `linkkey`, `ltk`,
`long_term_key`, `irk`, `csrk`, `pin` gets auto-filled from the most
recent matching credential for that host. An origin line documents the
fill so the operator knows what came from where.

```text
bluesploit(post/bt_impersonation) > set target 1
[+] target => AA:BB:CC:DD:EE:01
[*] auto-filled link_key from credentials#3 (LinkKey)
```

Manual override after autofill still wins.

---

## Engagement state

These verbs read and write the persistent store at
`~/.bluesploit/store.db`. See [Engagement State](engagement-state.md)
for the conceptual model.

### `hosts`

| Command            | Description                                              |
|--------------------|----------------------------------------------------------|
| `hosts`            | Table of every host in the active workspace              |
| `hosts <filter>`   | Substring filter on address or name (case-insensitive)   |

Use the `ID` column with `set target <id>`.

### `creds`

| Command            | Description                                              |
|--------------------|----------------------------------------------------------|
| `creds`            | Table of every credential in the active workspace        |
| `creds <filter>`   | Substring filter on host address, host name, or kind     |

Credentials feed the `set target` autofill described above.

### `workspace`

| Command                     | Description                                       |
|-----------------------------|---------------------------------------------------|
| `workspace`                 | Show the active workspace                         |
| `workspace list`            | Tabular view with per-table row counts            |
| `workspace use <name>`      | Switch (or create) workspace; persisted           |
| `workspace delete <name>`   | Drop the workspace and all rows in it             |

The active workspace and `default` cannot be deleted.

---

## Persistent globals

| Command                | Description                                              |
|------------------------|----------------------------------------------------------|
| `setg`                 | List every global option and its current value           |
| `setg <opt> <value>`   | Persist a global option; applied to every module load    |
| `unsetg <opt>`         | Clear the persisted value; reset to framework default    |

Globals survive restarts via the store's `meta` table. Defaults:
`interface=hci0`, `verbose=false`, `timeout=10`, `pcap_file=None`.

---

## Automation

| Command            | Description                                              |
|--------------------|----------------------------------------------------------|
| `resource <file>`  | Execute every non-empty, non-comment line in `<file>`    |

The same dispatcher the REPL uses runs each line. Errors on one line
print and the rest of the script continues. Useful for repeatable
engagement setup and CI replay.

```text
# discover.rc
workspace use lab
use recon/discovery
set interface hci0
run
back
hosts
```

---

## Global

| Command            | Description                                              |
|--------------------|----------------------------------------------------------|
| `help [cmd]`       | Built-in help; pass a command name for details           |
| `history`          | Command history (saved to `.bluesploit_history`)         |
| `!<shell-cmd>`     | Run a shell command (e.g. `!hciconfig`)                  |
| `clear`            | Clear the screen                                         |
| `exit` / `quit`    | Leave BlueSploit                                         |

---

## Typical session

```text
bluesploit > workspace use clientA
bluesploit > use recon/discovery
bluesploit(recon/discovery) > run
bluesploit(recon/discovery) > back

bluesploit > hosts
bluesploit > use post/link_key_dump
bluesploit(post/link_key_dump) > set target 1
bluesploit(post/link_key_dump) > run

bluesploit > creds
bluesploit > use post/bt_impersonation
bluesploit(post/bt_impersonation) > set target 1
[*] auto-filled link_key from credentials#1 (LinkKey)
bluesploit(post/bt_impersonation) > run
bluesploit > exit
```

---

## Tips

- Tab-completion works for commands, module paths, option names, host
  addresses on `set target`, workspace names, and resource file paths.
- History persists across sessions in `~/.bluesploit_history`.
- Prefix `!` runs anything in your shell, handy for `hciconfig`,
  `bluetoothctl`, `rfkill`.
- The active workspace is persisted; the next launch resumes where you
  left off.
