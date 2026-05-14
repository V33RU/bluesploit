"""
Runtime C/Objective-C exploit launcher.

Compiles an embedded C / Objective-C source string with the host's
clang or gcc, then executes the resulting binary. Used by modules
that ship the original researcher PoC verbatim instead of porting
it to Python (highest fidelity, no Mach-IPC / IOKit translation
errors).
"""

import os
import shutil
import subprocess
import tempfile
from typing import List, Optional, Tuple


def find_compiler() -> Optional[str]:
    return shutil.which("clang") or shutil.which("gcc") or shutil.which("cc")


def compile_and_run(
    source:    str,
    name:      str,
    args:      Optional[List[str]] = None,
    cflags:    Optional[List[str]] = None,
    ldflags:   Optional[List[str]] = None,
    extension: str = "c",
    timeout:   int = 60,
    sudo:      bool = False,
) -> Tuple[int, str, str]:
    """
    Write `source` to a temp file, compile with clang/gcc, run the binary.

    Returns (returncode, stdout, stderr). Returncode -1 means compilation
    or environment failure (compiler missing, etc.).
    """
    args    = args    or []
    cflags  = cflags  or []
    ldflags = ldflags or []

    cc = find_compiler()
    if not cc:
        return (-1, "", "No C compiler found (install clang or gcc)")

    tmpdir = tempfile.mkdtemp(prefix=f"bluesploit_{name}_")
    src    = os.path.join(tmpdir, f"{name}.{extension}")
    binary = os.path.join(tmpdir, name)

    try:
        with open(src, "w") as f:
            f.write(source)

        # Objective-C needs ObjC frontend
        if extension in ("m", "mm"):
            cflags = ["-x", "objective-c"] + cflags

        compile_cmd = [cc, "-Wno-everything", "-o", binary, src] + cflags + ldflags
        r = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return (-1, r.stdout, f"compile failed:\n{r.stderr}")

        run_cmd = ([shutil.which("sudo") or "sudo"] + [binary] + args) if sudo else ([binary] + args)
        try:
            r = subprocess.run(run_cmd, capture_output=True, text=True, timeout=timeout)
            return (r.returncode, r.stdout, r.stderr)
        except subprocess.TimeoutExpired as e:
            raw_partial = e.stdout
            partial: str
            if isinstance(raw_partial, (bytes, bytearray)):
                partial = raw_partial.decode("utf-8", errors="replace")
            elif isinstance(raw_partial, str):
                partial = raw_partial
            else:
                partial = ""
            return (-2, partial, f"timed out after {timeout}s")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
