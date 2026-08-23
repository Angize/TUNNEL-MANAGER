#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: every call to a panel helper matches the signature it is calling.

Python does not check this until the line runs, so a wrong call sits quietly in a branch nobody has
taken yet and surfaces as «internal error: … missing 1 required positional argument» in front of the
operator. That is exactly how `log_event("core", "…")` shipped: the delete-blob endpoint was driven end
to end in a harness, but the harness had stubbed `log_event` out, so the one call that mattered was
replaced by a lambda that accepts anything.

Stubbing a helper in a test hides its call shape. Reading the source cannot be stubbed.

Checked here, from the AST of tnl-central.py itself:

  * every call to a module-level function defined in this file passes a count of positional arguments
    the definition can actually accept, and no keyword the definition does not name;
  * `log_event` is checked harder, because its first argument is a severity the events page renders and
    a typo there is invisible until someone reads the log: it must be one of the levels the UI knows.

Calls that splat (`f(*args)`) are skipped for arity -- the count is not knowable statically.

    python3 tools/call_shapes_check.py
"""
import argparse
import ast
import sys
from pathlib import Path

# The severities the events page paints. A level outside this set renders unstyled.
EVENT_LEVELS = {"ok", "warn", "bad"}


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    src = Path(a.panel).read_text(encoding="utf-8")
    tree = ast.parse(src)

    # every module-level def, and what its parameter list will accept
    sigs = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            args = node.args
            pos = args.posonlyargs + args.args
            required = len([p for p in pos if True]) - len(args.defaults)
            sigs[node.name] = {
                "min": required,
                "max": None if args.vararg else len(pos),
                "names": {p.arg for p in pos} | {p.arg for p in args.kwonlyargs},
                "kwargs": args.kwarg is not None,
                "line": node.lineno,
            }

    bad = []
    checked = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        sig = sigs.get(node.func.id)
        if not sig:
            continue                      # a builtin, an import, or a local -- not ours to judge
        splat = any(isinstance(x, ast.Starred) for x in node.args)
        kwsplat = any(k.arg is None for k in node.keywords)
        named = {k.arg for k in node.keywords if k.arg}
        checked += 1
        if not splat and not kwsplat:
            # A keyword only fills a slot the definition NAMES; one swallowed by **kwargs fills none,
            # so counting it against the positional ceiling is how a guard invents its own false alarm.
            npos = len(node.args)
            filled = npos + len(named & sig["names"])
            over = sig["max"] is not None and npos > sig["max"]
            if filled < sig["min"] or over:
                bad.append("line %d: %s(...) passes %d positional and %d named; the definition on line "
                           "%d takes %s"
                           % (node.lineno, node.func.id, npos, len(named), sig["line"],
                              "%d" % sig["min"] if sig["max"] == sig["min"]
                              else "%d..%s" % (sig["min"], sig["max"] if sig["max"] is not None else "any")))
        if not kwsplat and not sig["kwargs"]:
            for k in sorted(named - sig["names"]):
                bad.append("line %d: %s(...) passes keyword %r, which the definition on line %d does not name"
                           % (node.lineno, node.func.id, k, sig["line"]))

    # log_event's first argument is a severity, not free text
    levels = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "log_event" and node.args
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            levels.append((node.lineno, node.args[0].value))
    for lineno, lvl in levels:
        if lvl not in EVENT_LEVELS:
            bad.append("line %d: log_event(%r, ...) -- the first argument is the severity and must be one "
                       "of %s; a kind passed here shifts every later argument by one"
                       % (lineno, lvl, "/".join(sorted(EVENT_LEVELS))))

    print("  checked %d call(s) against %d definition(s); %d log_event level(s)"
          % (checked, len(sigs), len(levels)))
    if bad:
        print("\n%d wrong call(s):" % len(bad))
        for b in bad:
            print("  - " + b)
        return 1
    print("every call matches the definition it names, and every event carries a real severity")
    return 0


if __name__ == "__main__":
    sys.exit(main())
