#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An action that answers inside a list card must hold the list's repaint off while it waits.

The list refreshes on a timer and `refreshNodes`/`refreshProxies` rebuild EVERY card from scratch. An
action that looks up its `.msg` strip, awaits a POST, and then writes into the element it captured is
writing into a node that may already be detached: the «در حال تست…» it put there disappears with the old
card and the answer lands in an orphan. Nothing throws; the operator taps test and gets nothing.

`checkLink` has always held `CHECKING` across its whole body for exactly this reason -- `listBusy()`
makes both refreshes bail while it is non-zero. `testNode` did not, which is the bug the operator hit.

The rule this enforces: an async function that captures a PER-ROW element -- `el('prefix_'+id)`, an id a
card renderer builds -- before its first await, and writes a `.msg` class into it afterwards, must raise
CHECKING. A per-row id is the tell: those elements exist only for as long as their card does. Constant
ids (`c_msg`, `ag_msg`, `del_msg`) belong to a modal or to a panel built once by its skeleton, and no
refresh rebuilds them, so there is no allowlist here to keep in sync.

Known limit, stated rather than hidden: if some future refresh starts rebuilding a panel that holds a
constant-id strip, this check will not notice. Today none does -- refreshAgent updates fields in place
and agentSkel builds that panel once on entry.

    python3 tools/card_msg_survives_a_refresh_check.py
"""
import argparse
import importlib.util
import re
import sys
from pathlib import Path


def load_js(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "INDEX_HTML", "")


def bodies(js, want_async=True):
    """(name, body, line) for every function declaration, brace-matched."""
    pat = r"\basync\s+function\s+([A-Za-z_$][\w$]*)\s*\(" if want_async \
        else r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\("
    out = []
    for m in re.finditer(pat, js):
        i = js.index("{", m.end() - 1)
        depth, j = 0, i
        while j < len(js):
            if js[j] == "{":
                depth += 1
            elif js[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((m.group(1), js[i:j + 1], js[:m.start()].count("\n") + 1))
    return out


def card_id_prefixes(js):
    """Prefixes of per-row ids emitted by a CARD renderer -- the ones a list rebuild destroys.

    Derived, not listed: a `id="ntm_'+n.id` inside nodeCard() is at risk, the same shape inside a modal
    builder is not, because an open modal sets editingId and listBusy() already holds.
    """
    out = set()
    for name, body, _ in bodies(js, want_async=False) + bodies(js, want_async=True):
        if not name.endswith("Card"):
            continue
        for m in re.finditer(r"""id="([A-Za-z_][\w]*_)'\s*\+""", body):
            out.add(m.group(1))
    return out


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    js = load_js(Path(a.panel))
    if "<script" not in js:
        print("FAIL  INDEX_HTML did not decode to anything with a <script> in it")
        return 1

    # Holding CHECKING only helps because listBusy() consults it and both refreshes consult listBusy().
    lb = next((b for n, b, _ in bodies(js, want_async=False) if n == "listBusy"), "")
    if "CHECKING" not in lb:
        failures0 = ("listBusy() no longer consults CHECKING — every guard below still raises the flag "
                     "and nothing reads it, so the race is back with the code still looking correct")
        print("FAIL  " + failures0)
        return 1
    # TWICE, not once: the check before the fetch skips the work, and the one before setHTML is what
    # actually stops the paint. Removing only the second still passes a "does it mention listBusy" test
    # while the repaint lands again -- measured.
    for r in ("refreshNodes", "refreshProxies"):
        rb = next((b for n, b, _ in bodies(js) if n == r), "")
        n_lb = rb.count("listBusy()")
        paint = rb.find("setHTML(")
        if n_lb < 2 or paint < 0 or "listBusy()" not in rb[:paint]:
            print("FAIL  %s() reads listBusy() %d time(s) and %s re-check it before setHTML — a test "
                  "that started during its fetch loses its card to the repaint"
                  % (r, n_lb, "does not" if paint < 0 else "does not"))
            return 1
    print("  ok   listBusy() reads CHECKING, and both refreshes re-check it before painting")

    prefixes = card_id_prefixes(js)
    if not prefixes:
        print("FAIL  found no per-row ids emitted by any *Card() renderer — the shapes moved and this "
              "check has gone blind")
        return 1
    print("  ok   per-row ids a list rebuild destroys: %s" % " ".join(sorted(prefixes)))

    # Every id emitted anywhere, so a capture of a prefix NOTHING renders can be reported. Renaming the
    # strip in the renderer and leaving the action looking for the old name would otherwise drop that
    # action out of this check silently -- it would simply stop matching and stop being examined.
    emitted = set()
    for _n, b, _l in bodies(js, want_async=False) + bodies(js, want_async=True):
        emitted |= set(re.findall(r"""id="([A-Za-z_][\w]*_)'\s*\+""", b))

    failures, checked = [], 0
    per_row = re.compile(r"el\('(%s)'\s*\+" % "|".join(re.escape(p) for p in sorted(prefixes)))
    any_row = re.compile(r"el\('([A-Za-z_][\w]*_)'\s*\+")
    for name, body, line in bodies(js):
        if "className='msg" not in body or body.find("await ") < 0:
            continue
        for m in any_row.finditer(body[:body.find("await ")]):
            if m.group(1) not in emitted:
                failures.append("%s() (line %d) looks up el('%s'+…), an id NOTHING renders — either the "
                                "strip was renamed and this action still reaches for the old name, or "
                                "this check has quietly stopped covering it"
                                % (name, line, m.group(1)))
    for name, body, line in bodies(js):
        first_await = body.find("await ")
        if first_await < 0:
            continue
        head = body[:first_await]
        # a per-CARD element captured before waiting, and written to as a .msg afterwards
        if not per_row.search(head) or "className='msg" not in body:
            continue
        checked += 1
        if "CHECKING++" not in body:
            failures.append("%s() (line %d) captures a per-card element before its await and writes a "
                            ".msg into it afterwards, without raising CHECKING — a list refresh landing "
                            "mid-flight rebuilds the card, so the answer is painted into a detached node "
                            "and the operator sees nothing" % (name, line))
            continue
        if "finally{CHECKING--" not in body.replace(" ", ""):
            failures.append("%s() (line %d) raises CHECKING but does not release it in a finally — a "
                            "throw or an early return would freeze every list refresh from then on, "
                            "which is worse than the race it guards" % (name, line))
            continue
        print("  ok   %-16s holds CHECKING across its await, and releases it" % (name + "()"))

    if not checked:
        print("FAIL  found no card action to check — the shapes moved and this check has gone blind")
        return 1

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nall %d card action(s) survive a refresh landing mid-flight" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main())
