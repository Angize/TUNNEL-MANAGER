#!/usr/bin/env python3
"""No inline handler may carry a runtime value, because esc() cannot protect one there.

esc() is HTML escaping and it is correct nearly everywhere the panel uses it — text nodes and quoted
attributes both. There is exactly one context where it is the WRONG escaping and looks right anyway:
inside a JavaScript string literal in an inline handler. The browser resolves HTML character references
in an event-handler attribute BEFORE compiling it as script, so an esc()'d quote (&#39;) is turned back
into a real quote and closes the string. `onclick="f('<value>')"` is therefore an injection point no
matter how carefully the value was escaped.

The panel used to have 55 of these. They were held shut only by input validation elsewhere — the ids
were hex, the addresses matched an IPv4 regex — so the safety was in a regex two thousand lines away
and not at the sink. Wire one new field through the same pattern and it is stored XSS in the admin's
own session, with the CSP's 'unsafe-inline' making it script the moment it lands.

The values now travel in data-* attributes, where esc() IS correct, and are read back through the
hA/hB/hC bridge. That makes the rule mechanical, so this checks the rule and not the 55 sites:

    no inline handler attribute in the emitted page may contain an interpolation.

Two spellings both count, and only one of them was ever looked for: \\' quoting and &quot; quoting.
A bare numeric splice counts too — it is safe only for as long as the value stays a number.

Reads the DECODED INDEX_HTML, never the .py bytes: in the source the escapes are unresolved, so a
checker reading the file directly sees a different string than the browser does.

    python3 tools/handlers_carry_no_runtime_values_check.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load():
    spec = importlib.util.spec_from_file_location("panel_xss_guard",
                                                  os.path.join(PANEL_REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["panel_xss_guard"] = m
    spec.loader.exec_module(m)
    return m


HANDLER = re.compile(r'(?<!-)\b(on[a-z]+)\s*=\s*"')


def handlers(js):
    """Every inline handler attribute, with its body, from the emitted page."""
    out = []
    for mo in HANDLER.finditer(js):
        i = mo.end()
        body = ""
        while i < len(js) and js[i] != '"':
            body += js[i]
            i += 1
        out.append((mo.group(1), body, js.count("\n", 0, mo.start()) + 1))
    return out


def interpolates(body):
    """A leading '+fn+' is the function NAME, chosen in code. Anything after it is a value."""
    rest = re.sub(r"^'\+\w+\+'", "", body)
    return "'+" in rest or "&quot;" in body


def main():
    m = load()
    for label, html in (("INDEX_HTML", m.INDEX_HTML), ("LOGIN_HTML", m.LOGIN_HTML)):
        blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)
        js = html
        hs = handlers(js)
        bad = [(ev, b, ln) for ev, b, ln in hs if interpolates(b)]
        check("%s: no inline handler carries a runtime value (%d handlers)" % (label, len(hs)),
              not bad)
        for ev, b, ln in bad[:12]:
            print("        line %d  %s=\"%s\"" % (ln, ev, b[:110]))
        if not blocks:
            check("%s has a script block to check" % label, False)

    js = re.findall(r"<script[^>]*>(.*?)</script>", m.INDEX_HTML, re.S)[0]

    print("== the bridge the values travel through instead ==")
    for fn, slot in (("hA", "ha"), ("hB", "hb"), ("hC", "hc")):
        used = re.search(r"\b%s\(this\)" % fn, js)
        declared = re.search(r"function %s\(e\)\{return e\.getAttribute\('data-%s'\)\}" % (fn, slot), js)
        if used:
            check("%s is declared where it is used" % fn, bool(declared))

    pairs = re.findall(r'((?:data-h[abc]="[^"]*"\s*)+)(on[a-z]+)="([^"]*)"', js)
    check("the bridge is actually in use", len(pairs) > 0, len(pairs))
    orphan_arg = []
    for attrs, ev, body in pairs:
        have = set(re.findall(r"data-h([abc])=", attrs))
        need = set(x.lower() for x in re.findall(r"\bh([ABC])\(this\)", body))
        if need - have:
            orphan_arg.append((ev, body[:60], sorted(need - have)))
    check("every bridge argument has its attribute on the same element", not orphan_arg, orphan_arg[:4])

    orphan_attr = []
    for mo in re.finditer(r'data-h([abc])="', js):
        seg = js[mo.start():mo.start() + 400]
        stop = seg.find(">")
        seg = seg[:stop] if stop != -1 else seg
        if ("h%s(this)" % mo.group(1).upper()) not in seg:
            orphan_attr.append(seg[:90])
    check("no bridge attribute is emitted that nothing reads", not orphan_attr, orphan_attr[:4])

    print("== and the escaper it replaced is still the strict one ==")
    esc = re.search(r"function esc\(s\)\{return String\(s==null\?'':s\)\.replace\(/\[([^\]]*)\]/g", js)
    check("esc() still escapes both quote characters as well as & < >",
          bool(esc) and all(c in esc.group(1) for c in ("&", "<", ">", '"', "'")),
          esc.group(1) if esc else "esc() not found")

    if FAILED:
        print("\n%d failure(s):" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("\nno handler in the page carries a value; esc() is only ever used where it is correct.")


if __name__ == "__main__":
    main()
