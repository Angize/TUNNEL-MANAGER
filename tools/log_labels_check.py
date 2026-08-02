#!/usr/bin/env python3
"""Guard: every log-detail LABEL the backend emits must survive the browser's label gate.

A system-log card renders each detail line as one of two things:

    «key: value»      -> a labelled pill  (از: 8.8.8.8   /   کلیدِ ECH: AEX+DQ…)
    anything else     -> a plain grey sentence

`evDetail` in INDEX_HTML decides which, from the text alone — a HEURISTIC over labels written a
thousand lines away in Python. A rejected label does not break loudly; it just stops being a box, and a
long base64 value is dumped inline as a wall of grey text with its address mirrored by the RTL page.

This extracts every expression reaching log_event's `dfa` argument, reduces each to a TEMPLATE so a
label is recognised by shape rather than guesswork, and tests it against the gate's own constants read
out of the JS. Known prose lines must FAIL, or "accept everything" would pass.

Exit 1 = a label would render as a sentence, or the JS gate could not be parsed — a check that cannot
read its subject must not report success.
"""
import argparse
import ast
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")   # the labels are Persian; cp1252 can't print them

HOLE = "\x00"           # stands in for any interpolated value
LABEL_RE = re.compile(r"^(.{1,40}?): " + HOLE)

# Detail lines that are PROSE and must keep rendering as prose. Negative cases give the check teeth in
# the other direction: a gate widened until it accepts anything would still pass the positive list.
PROSE = [
    "اتصال ریست شد (RST — احتمالاً کشتنِ DPI)",
    "سشن کهنه شد (سرِ مقابل خاموش/ری‌استارت؟) — در حالِ دست‌دادنِ مجدد",
    "قطع بود؛ با کلیدِ تازه بازسازی شد",
    "داده روی این آی‌پی دوباره برقرار شد",
]


def index_html(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "INDEX_HTML":
                    return node.value.value
    return None


def js_gate(html):
    """Read the label test out of evDetail: (length cap, rejected characters).

    Deliberately strict — if the gate is rewritten in a shape this cannot read, say so instead of
    silently checking nothing (the failure mode tuning_consistency.py shipped with for months)."""
    m = re.search(r"k\.length<=(\d+)&&!/\[([^\]]*)\]/\.test\(k\)", html)
    if not m:
        return None
    return int(m.group(1)), m.group(2)


def templates(node):
    """Every string template reachable from a `dfa` expression, with values collapsed to HOLE."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.JoinedStr):
            out.append("".join(
                v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else HOLE
                for v in n.values))
        elif (isinstance(n, ast.BinOp) and isinstance(n.op, ast.Mod)
              and isinstance(n.left, ast.Constant) and isinstance(n.left.value, str)):
            out.append(re.sub(r"%[sdr]", HOLE, n.left.value))
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and "\n" in n.value:
            out.append(n.value)   # a multi-line literal detail with no interpolation
    return out


def detail_exprs(tree):
    """Expressions that end up as log_event's 4th argument, directly or through a `dfa` variable."""
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "log_event" and len(n.args) > 3:
            out.append(n.args[3])
        elif isinstance(n, (ast.Assign, ast.AugAssign)):
            tgts = n.targets if isinstance(n, ast.Assign) else [n.target]
            if any(getattr(t, "id", "") == "dfa" for t in tgts):
                out.append(n.value)
        elif isinstance(n, ast.FunctionDef) and n.name == "_ev_core_text":
            for r in ast.walk(n):
                if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple) and len(r.value.elts) > 3:
                    out.append(r.value.elts[3])
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=str(Path(__file__).resolve().parent.parent / "tnl-central.py"))
    a = ap.parse_args()

    src = Path(a.panel).read_text(encoding="utf-8")
    tree = ast.parse(src)
    html = index_html(tree)
    if html is None:
        print("FAIL: INDEX_HTML not found in %s" % a.panel)
        return 1
    gate = js_gate(html)
    if gate is None:
        print("FAIL: CANNOT PARSE the evDetail label gate out of INDEX_HTML — it was rewritten in a\n"
              "      shape this guard does not read. Update js_gate(); do not leave it passing blind.")
        return 1
    cap, bad = gate

    def passes(k):
        return bool(k) and len(k) <= cap and not any(c in k for c in bad)

    labels = []
    for e in detail_exprs(tree):
        for t in templates(e):
            for line in t.split("\n"):
                m = LABEL_RE.match(line)
                if m and m.group(1) not in labels:
                    labels.append(m.group(1))

    if not labels:
        print("FAIL: no detail labels found — the extraction broke, not the panel.")
        return 1

    print("gate: length <= %d, rejects %s" % (cap, " ".join(bad)))
    fails = 0
    for k in labels:
        ok = passes(k)
        fails += not ok
        print("  %-4s %-18s (%d chars)" % ("ok" if ok else "FAIL", k, len(k)))
    for s in PROSE:
        line = s.split("\n")[0]
        k = line.split(": ")[0] if ": " in line else ""
        ok = not passes(k)          # prose must NOT be chopped into a label
        fails += not ok
        print("  %-4s prose stays prose: %s…" % ("ok" if ok else "FAIL", line[:34]))

    print("%d label(s), %d prose case(s), %d failure(s)" % (len(labels), len(PROSE), fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
