#!/usr/bin/env python3
"""Guard: no function in the panel may reference a name that does not exist.

`py_compile` accepts an undefined name -- Python only resolves it when the line runs. So a name left
behind by an edit sits in a branch nobody takes locally, passes every syntax check, deploys, and then
raises NameError the first time a real fleet takes that branch. In `api_summary` that turns the whole
endpoint into a 500, and every sidebar counter the browser reads from it drops to zero.

The check is `symtable`, not a regex: for every function and class scope, a symbol that is REFERENCED
and resolves to module scope must be bound at module level (assigned, imported, or declared `global`
somewhere) or be a builtin. Module scope itself is checked the same way.

What it does NOT catch, deliberately -- saying so beats a guard that over-claims:
  * use-before-assignment inside one scope (`y = z` above `z = 1`): `z` IS a local, so this is an
    UnboundLocalError, which needs flow analysis, not a symbol table;
  * attributes (`x.missing`) and dict keys -- neither is a name;
  * anything reached only through `getattr`/`eval`.

A star-import would make the module's binding set unknowable, so one is a hard failure rather than a
silently weakened check.

Exit 1 on any undefined name, on a star-import, or on a file that cannot be parsed.
"""
import argparse
import ast
import builtins
import symtable
import sys
from pathlib import Path

BUILTINS = set(dir(builtins))
# bound by the import machinery, never written in the source
MODULE_DUNDERS = {"__file__", "__name__", "__doc__", "__package__", "__spec__", "__loader__", "__builtins__"}


def module_bindings(top):
    """Names bound at module level.

    `is_assigned`/`is_imported` cover the ordinary cases. The third case has neither flag and is not
    referenced either: a name some function declares `global` and assigns. It exists in the module
    table only because of that declaration, so its mere presence is the binding.
    """
    out = set()
    for s in top.get_symbols():
        if s.is_assigned() or s.is_imported() or not s.is_referenced():
            out.add(s.get_name())
    return out


def undefined_in(tbl, bound, trail):
    """(scope, name) for every referenced-but-unbound global in this scope and its children."""
    hits = []
    for s in tbl.get_symbols():
        if not s.is_referenced() or not s.is_global():
            continue
        if s.is_local() or s.is_parameter() or s.is_free() or s.is_imported():
            continue
        n = s.get_name()
        if n in bound or n in BUILTINS or n in MODULE_DUNDERS:
            continue
        hits.append((".".join(trail) or "<module>", n))
    for ch in tbl.get_children():
        hits += undefined_in(ch, bound, trail + [ch.get_name()])
    return hits


def star_imports(src, name):
    return [f"{name}:{n.lineno}" for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)]


def scan(path):
    """(findings, error) -- error is set when the file could not be checked at all."""
    src = path.read_text(encoding="utf-8")
    try:
        stars = star_imports(src, path.name)
        top = symtable.symtable(src, path.name, "exec")
    except SyntaxError as e:
        return [], f"{path.name}: cannot parse: {e}"
    if stars:
        return [], f"{path.name}: star-import at {', '.join(stars)} -- the binding set is unknowable"
    return undefined_in(top, module_bindings(top), []), None


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="python files to check (default: the panel + these tools)")
    a = ap.parse_args()

    if a.paths:
        targets = [Path(p) for p in a.paths]
    else:
        targets = [here.parent.parent / "tnl-central.py"] + sorted(here.parent.glob("*.py"))

    fails = []
    for p in targets:
        if not p.exists():
            print(f" FAIL  {p}: no such file")
            fails.append(str(p))
            continue
        hits, err = scan(p)
        if err:
            print(f" FAIL  {err}")
            fails.append(err)
            continue
        for scope, n in hits:
            print(f" FAIL  {p.name}: {scope}: `{n}` is not defined anywhere")
            fails.append(f"{p.name}:{scope}:{n}")
        if not hits:
            print(f"  ok   {p.name}")

    if fails:
        print(f"\n{len(fails)} undefined name(s) -- these raise NameError the moment the branch runs")
        return 1
    print(f"\nall clear: {len(targets)} file(s), no undefined names")
    return 0


if __name__ == "__main__":
    sys.exit(main())
