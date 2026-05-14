# OUI database

`oui.csv.gz` is a compact, gzipped two-column CSV (`oui,vendor`) distilled
from the official IEEE registry:

```
https://standards-oui.ieee.org/oui/oui.csv
```

Read at lookup time by `modules/recon/oui_lookup.py`. The module's
inline `BUILTIN_OUI_DB` still wins on conflicts because the inline
entries carry hand-picked short names (e.g. `"Apple"` instead of
`"Apple, Inc."`). New OUIs picked up from this file get a synthetic
short name (the first word of the vendor string).

## Refresh

```
python3 scripts/fetch_oui.py
```

The script overwrites this file in place. Commit the result. Vendor
names are truncated to 80 characters and commas inside names are
flattened to spaces so the line parser stays simple.
