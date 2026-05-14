"""
Banner extras: module-count stats line, recent additions list, and the
small curated tip pool that surfaces under the boot banner and through
the `whatsnew` / `tips` console commands.

Kept separate from `core/utils/printer.py` so the ASCII banner art there
stays untouched and the loader / git plumbing here is independently
testable.
"""

from __future__ import annotations

import random
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# Tip pool ------------------------------------------------------------------
#
# Operator hints. Short, practical, no marketing. One is picked at random
# under the boot banner; `tips` lists all of them.

TIPS: List[str] = [
    "Most modules need root for raw HCI sockets. Launch with sudo, or "
    "set the right CAPs on python.",
    "Tab-complete option values: try `set interface <TAB>` or "
    "`set target <TAB>`.",
    "`workspace use <name>` scopes hosts, creds, and globals to one "
    "engagement. Default is `default`.",
    "After discovery, target by id: `set target 3` resolves to the "
    "stored host's address.",
    "`link_key_dump` writes credentials to the store. The next module "
    "that needs a link_key gets it auto-filled.",
    "`setg` writes survive across restarts. Clear an override with "
    "`unsetg <option>`.",
    "Replay a saved workflow with `resource <file>`. Lines starting "
    "with `#` are skipped.",
    "`help <command>` for details, `help <module/path>` for metadata "
    "and the options table.",
    "`hosts <substring>` and `creds <substring>` filter on address, "
    "name, or kind.",
    "`workspace list` shows row counts per workspace. The active one "
    "carries a `*` marker.",
]


def pick_tip(seed: Optional[int] = None) -> str:
    """Return one tip. Deterministic when a seed is supplied (used by tests)."""
    rnd = random.Random(seed) if seed is not None else random
    return rnd.choice(TIPS)


# Stats ---------------------------------------------------------------------


@dataclass
class BannerStats:
    version: str
    module_total: int
    counts_by_category: Dict[str, int]
    last_update: str       # e.g. "3 days ago" or "unknown"


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _git_last_update(repo: Path) -> str:
    """Return a human-friendly relative time for the last commit, or
    'unknown' when git is not on PATH or the path is not a repo."""
    if shutil.which("git") is None:
        return "unknown"
    try:
        r = subprocess.run(
            ["git", "-C", str(repo), "log", "-1", "--format=%ar"],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return r.stdout.strip() or "unknown"


def collect_stats(loader, version: str) -> BannerStats:
    """Build a BannerStats from the live module loader."""
    return BannerStats(
        version=version,
        module_total=loader.module_count,
        counts_by_category=dict(loader.stats()),
        last_update=_git_last_update(_repo_root()),
    )


def format_stats_line(stats: BannerStats) -> str:
    """One-line text summary, for printing under the boot banner."""
    parts = [f"{n} {c}" for c, n in sorted(stats.counts_by_category.items())]
    by_cat = "  ".join(parts) if parts else "no modules"
    return (
        f"  v{stats.version}  |  {stats.module_total} modules: {by_cat}  |  "
        f"last update: {stats.last_update}"
    )


# Recent module additions ---------------------------------------------------


def collect_module_additions(repo: Optional[Path] = None, limit: int = 10) -> List[Dict[str, str]]:
    """Walk git history for newly-added files under `modules/` and return
    the most recent `limit` of them.

    Each item: `{date, hash, path}`. Empty list when git is unavailable
    or the path is not a repo. Adds from squashed merge commits show up
    on the merge date.
    """
    repo = repo or _repo_root()
    if shutil.which("git") is None:
        return []
    try:
        r = subprocess.run(
            [
                "git", "-C", str(repo), "log",
                "--diff-filter=A",
                "--pretty=format:__COMMIT__%h|%as",
                "--name-only",
                "--",
                "modules/",
            ],
            capture_output=True, text=True, timeout=4,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0:
        return []

    out: List[Dict[str, str]] = []
    cur_hash = ""
    cur_date = ""
    for line in r.stdout.splitlines():
        if not line.strip():
            continue
        if line.startswith("__COMMIT__"):
            head, _, rest = line[len("__COMMIT__"):].partition("|")
            cur_hash, cur_date = head, rest
            continue
        # Only count actual module files, ignore __init__ and category subdirs.
        if not line.endswith(".py"):
            continue
        if line.endswith("/__init__.py") or "/base.py" in line:
            continue
        out.append({"date": cur_date, "hash": cur_hash, "path": line})
        if len(out) >= limit:
            break
    return out
