# Engagement State

BlueSploit keeps the live state of an engagement, discovered hosts,
recovered credentials, captured loot, and global options, in a single
SQLite file. Everything an operator does in the console reads from and
writes to the same store, so state survives across restarts and a
follow-up module can use the results of an earlier one without manual
copy-paste.

This page is the conceptual overview. For the exact commands see
[Console Commands](console-commands.md); for how a module author plugs
into it, see [Writing Modules](writing-modules.md).

---

## Where it lives

`~/.bluesploit/store.db` by default. Override with the `BLUESPLOIT_HOME`
environment variable. The file is opened in WAL mode and the directory
is created on first run; nothing else needs setup.

---

## What it holds

Four tables, scoped by workspace:

| Table         | What                                                             |
|---------------|------------------------------------------------------------------|
| `hosts`       | Discovered BD_ADDRs, names, RSSI, vendor, first/last seen.       |
| `credentials` | Link keys, LTKs, IRKs, CSRKs, PINs, captured by post-ex modules. |
| `loot`        | Raw payloads (PCAP paths, GATT dumps, arbitrary bytes).          |
| `meta`        | Schema version, active workspace, persisted `setg` overrides.    |

Plus a `workspaces` table that records every workspace the operator has
activated so tab completion remembers it even when empty.

---

## Workspaces

A workspace is a single string label that scopes everything else. The
default workspace is `default`. Switch to a new engagement with:

```text
bluesploit > workspace use clientA
```

Subsequent `hosts`, `creds`, and module runs only see and write to
`clientA`. The choice is persisted: the next time the console starts,
the active workspace is still `clientA`.

Useful subcommands:

```text
workspace               # show active
workspace list          # tabular view with row counts
workspace use <name>    # switch (created on first use)
workspace delete <name> # drop a workspace and all its rows
```

The default workspace and the currently active one cannot be deleted.

---

## Hosts

Recon modules write into the hosts table. List them with:

```text
bluesploit > hosts
bluesploit > hosts alpha     # substring filter on address or name
```

The `ID` column is the killer feature. Once a host has an id, you can:

```text
bluesploit > use exploits/whatever
bluesploit(exploits/whatever) > set target 3
[+] target => AA:BB:CC:DD:EE:01
```

`set target` accepts:

- A full BD_ADDR (`AA:BB:CC:DD:EE:FF`), passes through unchanged.
- A numeric host id (`3`), resolved from the store.
- A substring (`alpha`), resolves if it matches exactly one host;
  prints a candidate list if ambiguous.

---

## Credentials and autofill

After a post-exploitation module like `post/link_key_dump` runs, every
extracted key lands in the credentials table tied to its host. View
them with:

```text
bluesploit > creds
bluesploit > creds LinkKey       # filter by kind
bluesploit > creds AA:BB         # filter by host address
```

The payoff: when a future module is pointed at the same host with
`set target`, any option whose name is `link_key`, `linkkey`, `ltk`,
`long_term_key`, `irk`, `csrk`, or `pin` gets pre-filled from the
latest matching credential. An origin line tells you what happened:

```text
bluesploit(post/bt_impersonation) > set target 1
[+] target => AA:BB:CC:DD:EE:01
[*] auto-filled link_key from credentials#3 (LinkKey)
```

Operator override still wins: an explicit `set link_key DEADBEEF...`
after the autofill replaces the value.

---

## Persistent globals

`setg <option> <value>` writes to both the in-memory dict and the meta
table, so values survive across restarts. `unsetg <option>` clears the
persisted row and resets the option to its framework default.

```text
bluesploit > setg interface hci1
bluesploit > setg timeout 30
bluesploit > setg                 # list all
bluesploit > unsetg interface     # back to default hci0
```

Defaults: `interface=hci0`, `verbose=false`, `timeout=10`, `pcap_file=None`.

---

## Resource scripts

Replay a sequence of console commands from a file. Comments start with
`#`, blank lines are ignored, errors on one line do not stop the rest.

```text
# discover.rc
workspace use lab
use recon/discovery
set interface hci0
run
back
hosts
```

```text
bluesploit > resource discover.rc
```

Useful for repeatable engagement setup, CI replay, and quick scripted
demos.

---

## End-to-end example

```text
bluesploit > workspace use pentest-acme
bluesploit > use recon/discovery
bluesploit(recon/discovery) > run
bluesploit(recon/discovery) > back

bluesploit > hosts
  ID    Address             Name           RSSI   Vendor   Last seen
  ---------------------------------------------------------------------
  1     AA:BB:CC:DD:EE:01   alpha-laptop   -42    Apple    2026-05-14 20:30
  2     AA:BB:CC:DD:EE:02   wearable       -55    Garmin   2026-05-14 20:30

bluesploit > use post/link_key_dump
bluesploit(post/link_key_dump) > set target 1
bluesploit(post/link_key_dump) > run
... extracts LinkKey 0xDEADBEEF...

bluesploit > creds
  ID    Host                 Kind        Value             Captured
  ------------------------------------------------------------------------
  1     AA:BB:CC:DD:EE:01    LinkKey     DEADBEEF...       2026-05-14 20:31

bluesploit > use post/bt_impersonation
bluesploit(post/bt_impersonation) > set target 1
[+] target => AA:BB:CC:DD:EE:01
[*] auto-filled link_key from credentials#1 (LinkKey)
bluesploit(post/bt_impersonation) > run
```

Everything lives in the active workspace; switch to another engagement
later with `workspace use <name>` and the data above stays cleanly
separated.
