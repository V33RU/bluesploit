"""
Thin wrapper around `rich.table.Table` for the console verbs.

Keeps three goals in tension:

  - Operator looking at a real terminal gets a nicely styled table with
    column-aware widths.
  - Output remains ASCII-only on the wire, no fancy box-drawing glyphs,
    so terminal logs and pipelines stay clean.
  - Tests can capture stdout with `capsys` and assert against substring
    content; rich's auto-detection strips styles when stdout is not a
    TTY, which is exactly what we want there.

Use `render_table(...)` for every persistent-store view. Pass a list of
Column specs, a list of row tuples, and an optional footer line.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence, cast

from rich import box
from rich.console import Console
from rich.table import Table


@dataclass
class Column:
    """One column spec for `render_table`."""

    header: str
    style: Optional[str] = None       # e.g. "cyan", "dim", "bold"
    justify: str = "left"             # "left" | "right" | "center"
    no_wrap: bool = False
    overflow: str = "fold"            # "fold" | "crop" | "ellipsis"


def _make_console() -> Console:
    """Build a fresh Console pointed at the current sys.stdout.

    Tests swap sys.stdout out per-call via pytest's capsys, so a
    module-level Console would cling to the original stream and break
    on second use. Constructing on demand is cheap and avoids that
    footgun.

    For non-TTY output (test capture, redirected pipelines, log files)
    rich would default to 80 columns and collapse cells. We bump that
    to 160 there so a typical row stays on one line. A real interactive
    terminal still uses whatever width it reports.
    """
    isatty = bool(getattr(sys.stdout, "isatty", lambda: False)())
    return Console(
        file=sys.stdout,
        highlight=False,
        soft_wrap=False,
        width=None if isatty else 160,
    )


def render_table(
    columns: Sequence[Column],
    rows: Iterable[Sequence[object]],
    title: Optional[str] = None,
    footer: Optional[str] = None,
) -> None:
    """Render an ASCII-style table to stdout.

    `columns` describes the layout; `rows` is an iterable of value tuples
    that line up with `columns`. None values render as empty strings so
    callers do not have to guard. A trailing `footer` line is printed
    after the table when supplied.
    """
    table = Table(
        title=title,
        box=box.ASCII,                # ASCII-only border characters
        header_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        title_justify="left",
        title_style="bold",
    )
    for col in columns:
        table.add_column(
            col.header,
            style=col.style,
            # rich types `justify` and `overflow` as Literal unions; the
            # dataclass uses plain `str` so callers can pass any of the
            # documented values without importing rich's enums.
            justify=cast(Any, col.justify),
            no_wrap=col.no_wrap,
            overflow=cast(Any, col.overflow),
        )
    for row in rows:
        table.add_row(*(_cell(v) for v in row))

    console = _make_console()
    console.print(table)
    if footer:
        console.print(footer)


def _cell(v: object) -> str:
    """Coerce a row value to a string in a predictable way."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


# Convenience: many of our existing prints want just a one-line footer in
# the same format. The `(s)` suffix is unconditional, matching the wording
# the console used before rich tables landed.
def total_footer(noun: str, count: int, workspace: Optional[str] = None) -> str:
    suffix = f" in workspace '{workspace}'" if workspace else ""
    return f"\nTotal: {count} {noun}(s){suffix}\n"


__all__: List[str] = ["Column", "render_table", "total_footer"]
