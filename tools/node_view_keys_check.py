#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The browser may only read node fields that _node_view actually sends.

A renamed or dropped field does not break anything loudly: `n.proxy` on a view that now sends
`proxy_on` is just `undefined`, so the badge stops rendering and the details tile reads «—» forever.
Nothing throws, no test fails, and the panel quietly stops telling the operator something true. That
is how the «پروکسی» badge died when the per-node proxy became a registry.

This reads the keys out of _node_view's own returned dicts and every `n.<field>` the node-rendering
functions perform, and refuses any read that the view cannot answer.

    python3 tools/node_view_keys_check.py
"""
import argparse
import ast
import importlib.util
import re
import sys
from pathlib import Path

# Functions whose `n` IS a _node_view row. Each must exist, or this check has gone blind.
NODE_RENDERERS = ["nodeCard", "nodeDetails", "openNodeEdit", "upBar"]

# Read off the row but never sent by _node_view: the browser adds these itself.
BROWSER_OWNED = {
    "proxy",          # placeholder so a re-added n.proxy is a FAILURE, not a silent revival
}


def load_panel(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def view_keys(panel_text):
    """Every string key any `return {...}` in _node_view can put on the wire."""
    tree = ast.parse(panel_text)
    fn = next((f for f in ast.walk(tree)
               if isinstance(f, ast.FunctionDef) and f.name == "_node_view"), None)
    if fn is None:
        return None
    keys = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Dict):
            for k in node.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    keys.add(k.value)
    return keys


def js_body(js, fname):
    """The source of one browser function, brace-matched from its `function <name>(`.

    The counter does not know about string literals, so an unbalanced brace inside one would run the
    cut past the end of the function. That is checked for rather than assumed: every top-level function
    here starts at column 0, so finding one INSIDE the cut means the cut over-ran. Returns the body, or
    ('over-ran', text) so the caller fails loudly instead of silently reading another function's fields.
    """
    m = re.search(r"\b(?:async\s+)?function\s+%s\s*\(" % re.escape(fname), js)
    if not m:
        return None
    i = js.index("{", m.end() - 1)
    depth, j = 0, i
    while j < len(js):
        if js[j] == "{":
            depth += 1
        elif js[j] == "}":
            depth -= 1
            if depth == 0:
                body = js[i:j + 1]
                if re.search(r"\n(?:async\s+)?function\s+\w+\s*\(", body):
                    return ("over-ran", body)
                return body
        j += 1
    return ("over-ran", js[i:])


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()
    panel_path = Path(a.panel)

    failures = []
    sent = view_keys(panel_path.read_text(encoding="utf-8"))
    if sent is None:
        print("FAIL  _node_view is gone — this check cannot read its subject")
        return 1
    print("  ok  _node_view sends %d field(s): %s" % (len(sent), " ".join(sorted(sent))))

    js = getattr(load_panel(panel_path), "INDEX_HTML", "")
    if "<script" not in js:
        print("FAIL  INDEX_HTML did not decode to anything with a <script> in it")
        return 1

    for fname in NODE_RENDERERS:
        body = js_body(js, fname)
        if body is None:
            failures.append("%s() is gone (or renamed) — this check was watching it and is now blind "
                            "there; point NODE_RENDERERS at whatever replaced it" % fname)
            continue
        if isinstance(body, tuple):
            failures.append("%s(): could not tell where the function ends — the cut ran past it, so a "
                            "brace inside a string literal has broken this check's reader" % fname)
            continue
        read = set(re.findall(r"\bn\.([A-Za-z_][A-Za-z0-9_]*)", body))
        unknown = sorted(read - sent - BROWSER_OWNED)
        for key in unknown:
            failures.append("%s() reads n.%s, which _node_view never sends — it is `undefined` at "
                            "runtime, so that piece of UI silently renders nothing" % (fname, key))
        for key in sorted(read & BROWSER_OWNED):
            failures.append("%s() reads n.%s, a field that was DELETED from the node view — this is the "
                            "exact drift this check exists to catch" % (fname, key))
        print("  ok  %-14s reads %d node field(s), all of them sent" % (fname + "()", len(read)))

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nevery node field the browser reads is one the panel sends")
    return 0


if __name__ == "__main__":
    sys.exit(main())
