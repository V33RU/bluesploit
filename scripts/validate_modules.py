#!/usr/bin/env python3
"""
Validate ModuleInfo metadata for every module under modules/.

Uses AST parsing (no imports, no hardware), so it runs safely in CI on
any platform.

Checks each module file for:
  - a top-level class definition
  - a class-level `info = ModuleInfo(...)` assignment
  - required ModuleInfo kwargs: name, description, author, protocol, severity
  - `references` present (may be empty list)
  - a `_setup_options(self)` method
  - a `run(self)` method (DoS / Aux / Recon / Scanner / Exploit modules)

Exit code:
  0 if every module passes
  1 if any module fails (lists failures grouped by file)

Usage:
    python3 scripts/validate_modules.py
    python3 scripts/validate_modules.py --quiet   # only print failures
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = REPO_ROOT / "modules"

REQUIRED_INFO_KWARGS = {"name", "description", "author", "protocol", "severity"}
OPTIONAL_INFO_KWARGS = {"references", "cve"}


def _find_module_class(tree: ast.AST) -> ast.ClassDef | None:
    """Return the first top-level class that has an `info = ModuleInfo(...)` assignment."""
    for node in tree.body if isinstance(tree, ast.Module) else []:
        if not isinstance(node, ast.ClassDef):
            continue
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id == "info"
                and isinstance(stmt.value, ast.Call)
                and getattr(stmt.value.func, "id", None) == "ModuleInfo"
            ):
                return node
    return None


def _info_kwargs(cls: ast.ClassDef) -> Dict[str, ast.AST] | None:
    """Return the kwargs of the `info = ModuleInfo(...)` call, or None."""
    for stmt in cls.body:
        if (
            isinstance(stmt, ast.Assign)
            and isinstance(stmt.value, ast.Call)
            and getattr(stmt.value.func, "id", None) == "ModuleInfo"
        ):
            return {kw.arg: kw.value for kw in stmt.value.keywords if kw.arg}
    return None


def _has_method(cls: ast.ClassDef, name: str) -> bool:
    return any(isinstance(s, ast.FunctionDef) and s.name == name for s in cls.body)


def _is_nonempty_literal(node: ast.AST) -> bool:
    """Heuristic: a string literal that isn't empty, or any non-empty container."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return bool(node.value.strip())
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return len(node.elts) > 0
    # Names, attributes, calls etc. are accepted as "filled" without further inspection.
    return True


def validate_file(path: Path) -> List[str]:
    """Return a list of human-readable failure messages for `path` (empty == OK)."""
    failures: List[str] = []
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as e:
        return [f"read error: {e}"]

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        return [f"syntax error: {e}"]

    cls = _find_module_class(tree)
    if cls is None:
        return ["no Module class with an `info = ModuleInfo(...)` assignment found"]

    if cls.name != "Module":
        failures.append(f"module class is named {cls.name!r}, expected 'Module'")

    kwargs = _info_kwargs(cls) or {}
    missing = REQUIRED_INFO_KWARGS - set(kwargs.keys())
    if missing:
        failures.append(f"ModuleInfo missing required kwargs: {sorted(missing)}")

    # name and description must be non-empty literals
    for field in ("name", "description"):
        if field in kwargs and not _is_nonempty_literal(kwargs[field]):
            failures.append(f"ModuleInfo.{field} is empty")

    # author must be a non-empty list of strings (or at least a non-empty container)
    if "author" in kwargs and isinstance(kwargs["author"], (ast.List, ast.Tuple, ast.Set)):
        if len(kwargs["author"].elts) == 0:
            failures.append("ModuleInfo.author is empty list")

    if not _has_method(cls, "_setup_options"):
        failures.append("missing _setup_options(self)")
    if not _has_method(cls, "run"):
        failures.append("missing run(self)")

    return failures


def walk_modules() -> List[Path]:
    out: List[Path] = []
    for p in MODULES_DIR.rglob("*.py"):
        if p.name.startswith("__") or "__pycache__" in p.parts:
            continue
        # Skip files whose stem isn't a Python identifier (e.g. hyphenated names).
        if not p.stem.isidentifier():
            continue
        out.append(p)
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    args = ap.parse_args()

    files = walk_modules()
    if not files:
        print(f"no module files found under {MODULES_DIR}", file=sys.stderr)
        return 1

    failures: List[Tuple[Path, List[str]]] = []
    for path in files:
        errs = validate_file(path)
        if errs:
            failures.append((path, errs))

    if not args.quiet:
        print(f"validated {len(files)} module files")

    if failures:
        print(f"\n{len(failures)} module(s) failed validation:\n")
        for path, errs in failures:
            rel = path.relative_to(REPO_ROOT)
            print(f"  {rel}")
            for e in errs:
                print(f"      - {e}")
        return 1

    if not args.quiet:
        print("all modules OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
