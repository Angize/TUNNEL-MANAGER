#!/usr/bin/env python3
"""Guard: the browser JS embedded in the panel must actually parse.

The whole front end lives inside two triple-quoted Python strings (LOGIN_HTML, INDEX_HTML) -- ~290 KB of
JavaScript that `python3 -m py_compile` is perfectly happy with, because to Python it is just a string.
A stray brace or a truncated function there compiles, deploys, and only then blanks the dashboard.

There is a trap in checking it, and it is why this script imports the module instead of reading the file:

  * In `tnl-central.py` the JS is still SOURCE -- escape sequences are unresolved and the two
    `__..._JSON__` placeholders are still literal text. A checker that parses the .py bytes directly
    either chokes on that or, far worse, silently parses something that is not what the browser gets.
  * Importing the module runs the import-time `.replace("__TUNDEF_JSON__", ...)` wiring, so what we hand
    to `node --check` is byte-for-byte what the browser receives. (Both panel and node import with no
    side effects -- no file reads, no mkdir -- which is what makes this safe.)

Two things are checked per string constant:

  1. every `<script>` block parses (`node --check`);
  2. no `__NAME__` placeholder survived the import-time injection. An unresolved `__TUNDEF_JSON__` is a
     valid JS *identifier*, so it parses fine and then throws ReferenceError in the browser -- exactly
     the silent-failure shape tuning_consistency.py exists to prevent on the Python side.

Failures are reported as `tnl-central.py:<line>` where the line count of the decoded string matches its
source span (the normal case: no escape expands into an extra newline). When it does not match, the
script says so and falls back to a block-relative line rather than printing a number it cannot stand behind.

Exit 0 = every block parses. Exit 1 = a syntax error, a surviving placeholder, no `node` on PATH, or no
script blocks found at all -- a check that cannot read its subject must not report success.
"""
import argparse
import ast
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S)
PLACEHOLDER_RE = re.compile(r"__[A-Z][A-Z0-9_]*__")

fails = []


def check(ok, msg):
    print(("  ok  " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load_panel(path):
    """Import tnl-central.py under a legal module name (the filename has a hyphen)."""
    spec = importlib.util.spec_from_file_location("tnl_central_under_check", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def html_constants(src):
    """{name: (start_line, end_line)} for every module-level `NAME = "..."` string literal that holds
    a <script> block. Only the FIRST assignment counts -- the later `NAME = NAME.replace(...)` lines are
    the injection wiring, not the literal."""
    out = {}
    for node in ast.parse(src).body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, str) or "<script" not in node.value.value:
            continue
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id not in out:
                out[t.id] = (node.value.lineno, node.value.end_lineno)
    return out


def node_check(js, node_bin):
    """None if the snippet parses, else (line_within_snippet, message)."""
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "block.js"
        f.write_text(js, encoding="utf-8")
        r = subprocess.run([node_bin, "--check", str(f)], capture_output=True, text=True)
        if r.returncode == 0:
            return None
        err = (r.stderr or r.stdout).strip()
        line = None
        m = re.match(r"^.*?:(\d+)\s*$", err.splitlines()[0] if err else "")
        if m:
            line = int(m.group(1))
        detail = next((ln for ln in err.splitlines() if "Error" in ln), err.splitlines()[-1] if err else "?")
        return (line, detail.strip())


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=str(here.parent.parent / "tnl-central.py"))
    a = ap.parse_args()

    panel = Path(a.panel)
    node_bin = shutil.which("node")
    if not node_bin:
        print("FAIL: `node` is not on PATH -- cannot syntax-check the browser JS")
        return 1

    src = panel.read_text(encoding="utf-8")
    mod = load_panel(panel)
    spans = html_constants(src)
    if not spans:
        print("FAIL: no module-level HTML string constant with a <script> block -- THIS SCRIPT is out of date")
        return 1

    blocks = 0
    print("== 1) every <script> block parses (node --check on the DECODED string) ==")
    for name, (start_line, end_line) in spans.items():
        decoded = getattr(mod, name, None)
        if not isinstance(decoded, str):
            check(False, f"{name}: assigned in the source but not a string after import")
            continue
        # Exact source lines are only claimable when nothing in the string expanded or collapsed a newline.
        span = end_line - start_line + 1
        exact = decoded.count("\n") + 1 == span
        found = list(SCRIPT_RE.finditer(decoded))
        if not found:
            check(False, f"{name}: <script> in the source but none in the decoded string")
            continue
        for i, m in enumerate(found, 1):
            blocks += 1
            js = m.group(1)
            block_line = decoded[: m.start(1)].count("\n")   # 0-based offset of the block's first line
            bad = node_check(js, node_bin)
            label = f"{name} block {i} ({len(js)} chars, {js.count(chr(10)) + 1} lines)"
            if bad is None:
                check(True, label)
                continue
            line, detail = bad
            if line is None:
                where = "position not reported by node"
            elif exact:
                where = f"{panel.name}:{start_line + block_line + line - 1}"
            else:
                where = (f"{name} line {block_line + line} — approximate: the decoded string is "
                         f"{decoded.count(chr(10)) + 1} lines but its source span is {span}")
            check(False, f"{label}: {detail}  [{where}]")

    print("== 2) no import-time placeholder survived ==")
    for name in spans:
        decoded = getattr(mod, name, "")
        left = sorted(set(PLACEHOLDER_RE.findall(decoded))) if isinstance(decoded, str) else []
        check(not left, f"{name}: unresolved placeholder(s) {left}" if left else f"{name}: none left")

    print()
    if fails:
        print(f"{blocks} script block(s), {len(fails)} failure(s).")
        return 1
    print(f"{blocks} script block(s) across {len(spans)} constant(s) — all parse, no placeholders left.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
