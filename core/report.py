"""
Engagement report rendering.

Walks a `Store` for the currently active workspace and produces a
self-contained artifact in one of three formats:

  - json  structured dump suitable for downstream tooling
  - md    GitHub-flavored markdown with tables
  - html  single-file HTML with inline CSS, no external assets

Loot byte payloads are summarized rather than embedded by default
(`kind`, size, source, hash prefix). The intent is a deliverable an
operator can hand off, not a binary archive.
"""

from __future__ import annotations

import hashlib
import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from core.store import Credential, Host, Loot, Store

SUPPORTED_FORMATS = ("json", "md", "html")
_BLUESPLOIT_VERSION = "1.0.2.dev"


# Snapshot model -------------------------------------------------------------


@dataclass
class LootSummary:
    id: int
    kind: str
    size: int
    source: Optional[str]
    sha256_prefix: str
    created_at: Optional[str]


@dataclass
class CredentialSummary:
    id: int
    kind: str
    value: str
    metadata: Optional[str]
    created_at: Optional[str]


@dataclass
class HostSnapshot:
    host: Host
    loot: List[LootSummary] = field(default_factory=list)
    credentials: List[CredentialSummary] = field(default_factory=list)


@dataclass
class ReportSnapshot:
    workspace: str
    generated_at: str
    hosts: List[HostSnapshot]
    orphan_loot: List[LootSummary]
    orphan_credentials: List[CredentialSummary]
    counts: Dict[str, int]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _summarize_loot(rows: List[Loot]) -> List[LootSummary]:
    out: List[LootSummary] = []
    for r in rows:
        digest = hashlib.sha256(r.data).hexdigest()[:16]
        out.append(
            LootSummary(
                id=r.id, kind=r.kind, size=len(r.data),
                source=r.source, sha256_prefix=digest,
                created_at=r.created_at,
            )
        )
    return out


def _summarize_credentials(rows: List[Credential]) -> List[CredentialSummary]:
    return [
        CredentialSummary(
            id=r.id, kind=r.kind, value=r.value,
            metadata=r.metadata, created_at=r.created_at,
        )
        for r in rows
    ]


def collect_snapshot(store: Store) -> ReportSnapshot:
    """Snapshot the active workspace's contents into pure dataclass form."""
    hosts = store.list_hosts()
    all_loot = store.list_loot()
    all_creds = store.list_credentials()

    by_host_loot: Dict[Optional[int], List[Loot]] = {}
    for loot_row in all_loot:
        by_host_loot.setdefault(loot_row.host_id, []).append(loot_row)
    by_host_cred: Dict[Optional[int], List[Credential]] = {}
    for cred_row in all_creds:
        by_host_cred.setdefault(cred_row.host_id, []).append(cred_row)

    host_snapshots: List[HostSnapshot] = []
    for h in hosts:
        host_snapshots.append(
            HostSnapshot(
                host=h,
                loot=_summarize_loot(by_host_loot.get(h.id, [])),
                credentials=_summarize_credentials(by_host_cred.get(h.id, [])),
            )
        )

    orphan_loot = _summarize_loot(by_host_loot.get(None, []))
    orphan_creds = _summarize_credentials(by_host_cred.get(None, []))

    return ReportSnapshot(
        workspace=store.workspace,
        generated_at=_now(),
        hosts=host_snapshots,
        orphan_loot=orphan_loot,
        orphan_credentials=orphan_creds,
        counts={
            "hosts": len(host_snapshots),
            "loot": len(all_loot),
            "credentials": len(all_creds),
        },
    )


# Renderers ------------------------------------------------------------------


def render_json(snap: ReportSnapshot) -> str:
    def hostdict(h: Host) -> dict:
        return {
            "id": h.id, "address": h.address, "name": h.name,
            "rssi": h.rssi, "manufacturer": h.manufacturer,
            "first_seen": h.first_seen, "last_seen": h.last_seen,
        }

    def lootdict(loot_list: List[LootSummary]) -> List[dict]:
        return [vars(x) for x in loot_list]

    def creddict(cred_list: List[CredentialSummary]) -> List[dict]:
        return [vars(x) for x in cred_list]

    payload = {
        "tool": "bluesploit",
        "tool_version": _BLUESPLOIT_VERSION,
        "workspace": snap.workspace,
        "generated_at": snap.generated_at,
        "counts": snap.counts,
        "hosts": [
            {
                **hostdict(hs.host),
                "loot": lootdict(hs.loot),
                "credentials": creddict(hs.credentials),
            }
            for hs in snap.hosts
        ],
        "orphan_loot": lootdict(snap.orphan_loot),
        "orphan_credentials": creddict(snap.orphan_credentials),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def render_md(snap: ReportSnapshot) -> str:
    lines: List[str] = []
    lines.append("# BlueSploit engagement report")
    lines.append("")
    lines.append(f"- Workspace: `{snap.workspace}`")
    lines.append(f"- Generated: {snap.generated_at}")
    lines.append(
        f"- Counts: {snap.counts['hosts']} host(s), "
        f"{snap.counts['loot']} loot row(s), "
        f"{snap.counts['credentials']} credential(s)"
    )
    lines.append("")

    lines.append("## Hosts")
    lines.append("")
    if not snap.hosts:
        lines.append("_No hosts recorded._")
        lines.append("")
    else:
        lines.append("| ID | Address | Name | RSSI | Vendor | Last seen |")
        lines.append("|----|---------|------|------|--------|-----------|")
        for hs in snap.hosts:
            h = hs.host
            lines.append(
                f"| {h.id} | `{h.address}` | {h.name or ''} | "
                f"{'' if h.rssi is None else h.rssi} | "
                f"{h.manufacturer or ''} | {h.last_seen or ''} |"
            )
        lines.append("")

    for hs in snap.hosts:
        if not hs.loot and not hs.credentials:
            continue
        lines.append(f"### Host `{hs.host.address}` ({hs.host.name or 'unnamed'})")
        lines.append("")
        if hs.credentials:
            lines.append("**Credentials**")
            lines.append("")
            lines.append("| Kind | Value | Metadata | Captured |")
            lines.append("|------|-------|----------|----------|")
            for c in hs.credentials:
                lines.append(
                    f"| {c.kind} | `{c.value}` | "
                    f"{c.metadata or ''} | {c.created_at or ''} |"
                )
            lines.append("")
        if hs.loot:
            lines.append("**Loot**")
            lines.append("")
            lines.append("| Kind | Size (bytes) | Source | SHA-256 (first 16) | Captured |")
            lines.append("|------|-------------:|--------|---------------------|----------|")
            for lt in hs.loot:
                lines.append(
                    f"| {lt.kind} | {lt.size} | {lt.source or ''} | "
                    f"`{lt.sha256_prefix}` | {lt.created_at or ''} |"
                )
            lines.append("")

    if snap.orphan_loot or snap.orphan_credentials:
        lines.append("## Unattributed")
        lines.append("")
        if snap.orphan_credentials:
            lines.append("**Credentials**")
            lines.append("")
            lines.append("| Kind | Value | Metadata | Captured |")
            lines.append("|------|-------|----------|----------|")
            for c in snap.orphan_credentials:
                lines.append(
                    f"| {c.kind} | `{c.value}` | "
                    f"{c.metadata or ''} | {c.created_at or ''} |"
                )
            lines.append("")
        if snap.orphan_loot:
            lines.append("**Loot**")
            lines.append("")
            lines.append("| Kind | Size (bytes) | Source | SHA-256 (first 16) | Captured |")
            lines.append("|------|-------------:|--------|---------------------|----------|")
            for lt in snap.orphan_loot:
                lines.append(
                    f"| {lt.kind} | {lt.size} | {lt.source or ''} | "
                    f"`{lt.sha256_prefix}` | {lt.created_at or ''} |"
                )
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


_HTML_CSS = """
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
       margin: 0; padding: 32px; color: #1a1a1a; background: #fafafa; }
h1 { margin: 0 0 8px 0; font-size: 28px; }
h2 { margin: 32px 0 12px 0; padding-bottom: 6px; border-bottom: 1px solid #ddd; }
h3 { margin: 24px 0 8px 0; font-size: 16px; color: #444; }
.meta { color: #555; margin-bottom: 24px; font-size: 14px; }
.meta code { background: #eee; padding: 2px 6px; border-radius: 3px; }
table { width: 100%; border-collapse: collapse; margin: 8px 0 16px 0;
        font-size: 13px; background: white;
        box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
th, td { padding: 8px 10px; text-align: left; border-bottom: 1px solid #eee; }
th { background: #f0f0f0; font-weight: 600; }
tr:last-child td { border-bottom: none; }
code, .mono { font-family: ui-monospace, "SF Mono", Consolas, monospace; }
.kind { display: inline-block; padding: 1px 7px; border-radius: 3px;
        background: #e3edff; color: #1948b8; font-size: 12px; }
.empty { color: #888; font-style: italic; }
.footer { color: #888; margin-top: 40px; font-size: 12px; text-align: center; }
""".strip()


def _h(s: Optional[str]) -> str:
    return html.escape("" if s is None else str(s))


def render_html(snap: ReportSnapshot) -> str:
    parts: List[str] = []
    parts.append("<!doctype html>")
    parts.append('<html lang="en"><head>')
    parts.append('<meta charset="utf-8">')
    parts.append(
        f'<title>BlueSploit engagement report '
        f'({_h(snap.workspace)})</title>'
    )
    parts.append(f"<style>{_HTML_CSS}</style>")
    parts.append("</head><body>")

    parts.append("<h1>BlueSploit engagement report</h1>")
    parts.append('<div class="meta">')
    parts.append(f"Workspace <code>{_h(snap.workspace)}</code> ")
    parts.append(f"&middot; generated {_h(snap.generated_at)} ")
    parts.append(
        f"&middot; {snap.counts['hosts']} host(s), "
        f"{snap.counts['loot']} loot row(s), "
        f"{snap.counts['credentials']} credential(s)"
    )
    parts.append("</div>")

    parts.append("<h2>Hosts</h2>")
    if not snap.hosts:
        parts.append('<p class="empty">No hosts recorded.</p>')
    else:
        parts.append("<table>")
        parts.append(
            "<tr><th>ID</th><th>Address</th><th>Name</th>"
            "<th>RSSI</th><th>Vendor</th><th>Last seen</th></tr>"
        )
        for hs in snap.hosts:
            h_ = hs.host
            parts.append(
                f"<tr><td>{h_.id}</td>"
                f"<td class='mono'>{_h(h_.address)}</td>"
                f"<td>{_h(h_.name)}</td>"
                f"<td>{'' if h_.rssi is None else h_.rssi}</td>"
                f"<td>{_h(h_.manufacturer)}</td>"
                f"<td>{_h(h_.last_seen)}</td></tr>"
            )
        parts.append("</table>")

    for hs in snap.hosts:
        if not hs.loot and not hs.credentials:
            continue
        parts.append(
            f"<h3>Host <span class='mono'>{_h(hs.host.address)}</span> "
            f"({_h(hs.host.name or 'unnamed')})</h3>"
        )
        if hs.credentials:
            parts.append("<p><strong>Credentials</strong></p>")
            parts.append("<table>")
            parts.append(
                "<tr><th>Kind</th><th>Value</th>"
                "<th>Metadata</th><th>Captured</th></tr>"
            )
            for c in hs.credentials:
                parts.append(
                    f"<tr><td><span class='kind'>{_h(c.kind)}</span></td>"
                    f"<td class='mono'>{_h(c.value)}</td>"
                    f"<td>{_h(c.metadata)}</td>"
                    f"<td>{_h(c.created_at)}</td></tr>"
                )
            parts.append("</table>")
        if hs.loot:
            parts.append("<p><strong>Loot</strong></p>")
            parts.append("<table>")
            parts.append(
                "<tr><th>Kind</th><th>Size (bytes)</th><th>Source</th>"
                "<th>SHA-256 (first 16)</th><th>Captured</th></tr>"
            )
            for lt in hs.loot:
                parts.append(
                    f"<tr><td><span class='kind'>{_h(lt.kind)}</span></td>"
                    f"<td>{lt.size}</td><td>{_h(lt.source)}</td>"
                    f"<td class='mono'>{_h(lt.sha256_prefix)}</td>"
                    f"<td>{_h(lt.created_at)}</td></tr>"
                )
            parts.append("</table>")

    if snap.orphan_loot or snap.orphan_credentials:
        parts.append("<h2>Unattributed</h2>")
        if snap.orphan_credentials:
            parts.append("<p><strong>Credentials</strong></p>")
            parts.append("<table>")
            parts.append(
                "<tr><th>Kind</th><th>Value</th>"
                "<th>Metadata</th><th>Captured</th></tr>"
            )
            for c in snap.orphan_credentials:
                parts.append(
                    f"<tr><td><span class='kind'>{_h(c.kind)}</span></td>"
                    f"<td class='mono'>{_h(c.value)}</td>"
                    f"<td>{_h(c.metadata)}</td>"
                    f"<td>{_h(c.created_at)}</td></tr>"
                )
            parts.append("</table>")
        if snap.orphan_loot:
            parts.append("<p><strong>Loot</strong></p>")
            parts.append("<table>")
            parts.append(
                "<tr><th>Kind</th><th>Size (bytes)</th><th>Source</th>"
                "<th>SHA-256 (first 16)</th><th>Captured</th></tr>"
            )
            for lt in snap.orphan_loot:
                parts.append(
                    f"<tr><td><span class='kind'>{_h(lt.kind)}</span></td>"
                    f"<td>{lt.size}</td><td>{_h(lt.source)}</td>"
                    f"<td class='mono'>{_h(lt.sha256_prefix)}</td>"
                    f"<td>{_h(lt.created_at)}</td></tr>"
                )
            parts.append("</table>")

    parts.append(
        f"<div class='footer'>bluesploit {_BLUESPLOIT_VERSION} "
        f"&middot; for authorized security research only</div>"
    )
    parts.append("</body></html>")
    return "\n".join(parts)


# Public entry point ---------------------------------------------------------


def write_report(store: Store, fmt: str, path: Path) -> int:
    """Render and write a report. Returns the number of bytes written."""
    fmt = fmt.lower()
    if fmt not in SUPPORTED_FORMATS:
        raise ValueError(
            f"unknown report format: {fmt!r}. "
            f"Supported: {', '.join(SUPPORTED_FORMATS)}"
        )
    snap = collect_snapshot(store)
    if fmt == "json":
        body = render_json(snap)
    elif fmt == "md":
        body = render_md(snap)
    else:
        body = render_html(snap)
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return len(body.encode("utf-8"))


def default_report_path(workspace: str, fmt: str) -> Path:
    """Pick a sane default filename when the operator didn't provide one."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_ws = "".join(c if c.isalnum() or c in "-_" else "_" for c in workspace)
    ext = "md" if fmt == "md" else fmt
    return Path(f"bluesploit-{safe_ws}-{stamp}.{ext}")
