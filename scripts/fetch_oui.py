#!/usr/bin/env python3
"""
Refresh the bundled IEEE OUI vendor database.

Reads the official IEEE registry at:
    https://standards-oui.ieee.org/oui/oui.csv

and writes a compact gzipped two-column CSV to:
    data/oui/oui.csv.gz

The output drops the address column and trims vendor names to 80
chars so the snapshot is small enough to commit (around 400 KB).
The recon/oui_lookup module reads this file at lookup time and falls
back to its inline curated dict if the file is missing.

Usage:
    python3 scripts/fetch_oui.py
    python3 scripts/fetch_oui.py --timeout 90      # slow network
    python3 scripts/fetch_oui.py --quiet
"""

from __future__ import annotations

import argparse
import csv
import gzip
import sys
import urllib.error
import urllib.request
from io import StringIO
from pathlib import Path

URL = "https://standards-oui.ieee.org/oui/oui.csv"
OUT = Path(__file__).resolve().parent.parent / "data" / "oui" / "oui.csv.gz"


def fetch(url: str, timeout: float) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "BlueSploit/oui-fetch"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def distill(raw_csv: str) -> tuple[int, str]:
    """Return (rows_written, output_csv_text)."""
    out = StringIO()
    out.write("oui,vendor\n")
    reader = csv.reader(StringIO(raw_csv))
    next(reader, None)  # drop header
    seen: set[str] = set()
    for row in reader:
        if len(row) < 3:
            continue
        oui = row[1].strip().upper()
        if len(oui) != 6 or oui in seen:
            continue
        vendor = row[2].strip().strip('"').replace(",", " ")[:80]
        if not vendor:
            continue
        seen.add(oui)
        out.write(f"{oui},{vendor}\n")
    return len(seen), out.getvalue()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds")
    ap.add_argument("--quiet", action="store_true", help="suppress progress output")
    args = ap.parse_args()

    if not args.quiet:
        print(f"fetching {URL}")
    try:
        raw = fetch(URL, timeout=args.timeout)
    except urllib.error.URLError as e:
        print(f"fetch failed: {e}", file=sys.stderr)
        return 1

    rows, body = distill(raw)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(OUT, "wt", encoding="utf-8") as f:
        f.write(body)
    size = OUT.stat().st_size
    if not args.quiet:
        print(f"wrote {OUT} ({size:,} bytes, {rows:,} OUIs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
