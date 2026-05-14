#!/usr/bin/env python3
"""
Auto-generate per-category module documentation for mkdocs.

Scans modules/<category>/*.py, extracts ModuleInfo + ModuleOption fields via AST
(no import = no hardware/root required), and rewrites docs/<category>.md.

Usage: python3 scripts/gen_module_docs.py
Run from repo root. Produces files in-place; idempotent.
"""

import ast
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "modules"
DOCS_DIR = REPO_ROOT / "docs"

CATEGORIES = {
    "exploits":   ("Exploits",            "modules/exploits/",   "exploits.md"),
    "scanners":   ("Scanners",            "modules/scanners/",   "scanners.md"),
    "dos":        ("Denial of Service",   "modules/dos/",        "dos.md"),
    "auxiliary":  ("Auxiliary",           "modules/auxiliary/",  "auxiliary.md"),
    "post":       ("Post-Exploitation",   "modules/post/",       "post-exploitation.md"),
    "recon":      ("Reconnaissance",      "modules/recon/",      "recon.md"),
}

SEVERITY_BADGES = {
    "CRITICAL": "🔴 **CRITICAL**",
    "HIGH":     "🟠 **HIGH**",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🟢 LOW",
    "INFO":     "ℹ️ INFO",
}


def _literal(node) -> Any:
    """Best-effort AST → Python literal."""
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError):
        # Fallback: handle Severity.HIGH / BTProtocol.BLE / Colors.RED
        if isinstance(node, ast.Attribute):
            return node.attr
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.JoinedStr):
            # f-string, concatenate constant parts
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                else:
                    parts.append("…")
            return "".join(parts)
        if isinstance(node, ast.Call):
            return f"<{getattr(node.func, 'id', '?')}(...)>"
        if isinstance(node, ast.List):
            return [_literal(e) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(_literal(e) for e in node.elts)
        return None


def _kw_dict(call: ast.Call) -> Dict[str, Any]:
    return {kw.arg: _literal(kw.value) for kw in call.keywords if kw.arg}


def parse_module(path: Path) -> Optional[Dict]:
    """Extract ModuleInfo + ModuleOption metadata from a module file."""
    try:
        tree = ast.parse(path.read_text())
    except (OSError, SyntaxError):
        return None

    info: Dict[str, Any] = {}
    options: List[Dict] = []

    for node in ast.walk(tree):
        # ModuleInfo(...) call
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ModuleInfo":
            info = _kw_dict(node)

        # ModuleOption(...) call
        elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "ModuleOption":
            options.append(_kw_dict(node))

    if not info:
        return None

    # Module path = relative module path without .py
    rel = path.relative_to(REPO_ROOT / "modules")
    module_path = str(rel.with_suffix("")).replace(os.sep, "/")

    # Module-level docstring (first paragraph)
    docstring = ast.get_docstring(tree) or ""
    summary = docstring.strip().split("\n\n")[0].strip() if docstring else ""

    return {
        "module_path": module_path,
        "name": info.get("name") or module_path,
        "description": info.get("description") or "",
        "summary": summary,
        "author": info.get("author"),
        "protocol": info.get("protocol"),
        "severity": info.get("severity"),
        "cve": info.get("cve") or [],
        "references": info.get("references") or [],
        "options": options,
    }


def render_module_section(m: Dict) -> str:
    name = m["module_path"]
    title = m["name"] if m["name"] != name else name
    desc = m["description"] or ""

    lines = [f"### `{name}`", ""]
    if title and title != name:
        lines.append(f"**{title}**")
        lines.append("")
    if desc:
        lines.append(desc)
        lines.append("")

    # Metadata bullets
    meta = []
    sev = m.get("severity")
    if sev:
        meta.append(f"**Severity:** {SEVERITY_BADGES.get(str(sev).upper(), sev)}")
    proto = m.get("protocol")
    if proto:
        meta.append(f"**Protocol:** {proto}")
    cves = m.get("cve") or []
    if isinstance(cves, str):
        cves = [cves]
    if cves:
        cve_str = ", ".join(f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in cves)
        meta.append(f"**CVE:** {cve_str}")
    if meta:
        lines.append(" · ".join(meta))
        lines.append("")

    # Options table
    opts = m.get("options") or []
    if opts:
        lines.append("| Option | Required | Default | Description |")
        lines.append("|---|---|---|---|")
        for o in opts:
            n = o.get("name") or "?"
            req = "✓" if o.get("required") else ""
            default = o.get("default")
            default_str = "" if default is None else f"`{default}`"
            d = (o.get("description") or "").replace("|", "\\|")
            lines.append(f"| `{n}` | {req} | {default_str} | {d} |")
        lines.append("")

    # References
    refs = m.get("references") or []
    if refs:
        lines.append("**References:**")
        for r in refs:
            lines.append(f"- <{r}>")
        lines.append("")

    return "\n".join(lines)


def render_category_doc(category: str, title: str, mod_path: str,
                        modules: List[Dict]) -> str:
    n = len(modules)
    out = [
        f"# {title} ({n})",
        "",
        f"Auto-generated from `{mod_path}`.  ",
        f"Load any module with `use {category}/<name>`.",
        "",
        "!!! warning \"Authorization required\"",
        "    Use only against equipment you own or have explicit written",
        "    authorization to test. The authors disclaim liability for misuse.",
        "",
        "---",
        "",
        "## Module index",
        "",
        "| Module | Severity | CVE | Description |",
        "|---|---|---|---|",
    ]

    for m in sorted(modules, key=lambda x: x["module_path"]):
        sev = str(m.get("severity") or "").upper()
        sev_short = SEVERITY_BADGES.get(sev, sev or "-")
        cves = m.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]
        cve_str = ", ".join(cves) if cves else "-"
        desc = (m.get("description") or "").replace("|", "\\|")
        if len(desc) > 80:
            desc = desc[:77] + "…"
        out.append(f"| [`{m['module_path']}`](#{m['module_path'].replace('/', '')}) "
                   f"| {sev_short} | {cve_str} | {desc} |")

    out += ["", "---", "", "## Modules", ""]
    for m in sorted(modules, key=lambda x: x["module_path"]):
        out.append(render_module_section(m))
        out.append("---")
        out.append("")

    return "\n".join(out).rstrip() + "\n"


def main() -> int:
    if not MODULES_DIR.is_dir():
        print(f"ERR: {MODULES_DIR} not found", file=sys.stderr)
        return 1

    DOCS_DIR.mkdir(exist_ok=True)
    total = 0

    for cat, (title, mod_path, doc_file) in CATEGORIES.items():
        cat_dir = MODULES_DIR / cat
        if not cat_dir.is_dir():
            print(f"  skip {cat}: directory not found")
            continue

        modules = []
        for path in sorted(cat_dir.glob("*.py")):
            if path.name.startswith("_") or path.name == "__init__.py":
                continue
            m = parse_module(path)
            if m:
                modules.append(m)

        if not modules:
            print(f"  {cat}: no modules parsed")
            continue

        doc_text = render_category_doc(cat, title, mod_path, modules)
        out_path = DOCS_DIR / doc_file
        out_path.write_text(doc_text)
        print(f"  wrote {out_path.relative_to(REPO_ROOT)} ({len(modules)} modules)")
        total += len(modules)

    print(f"\nTotal modules documented: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
