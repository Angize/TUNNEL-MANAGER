#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the fleet update's LAST poll carries the state every node ended in.

`api_push_status` answered `{"ok": true, "job": "", "idle": true, "done": true}` as soon as the last
job finished -- no `order`, no `nodes`. That payload is the only one the browser ever sees with
done=true, so it is the last thing pushPaint is given, and pushPaint walks `d.order` and reads
`d.nodes[nid]`: with neither, it repaints nothing and every bar keeps whatever the PREVIOUS poll left.

The audit called this "the last node's bar freezes at its last percentage". Driven here, it is worse:
the browser polls every 400ms, and on a push that finishes inside one interval the last painted state
is the one the job STARTED with. Measured on the old code, three nodes that all ended `ok` were last
painted `wait / 0%` -- an update that succeeded and looked like it never began.

`_push_merged` also hardcoded `"done": False`, so even the live payload could never say it was over;
`done` is computed from the jobs now, and the last merged view of a finished batch is kept so the final
poll has something true to paint.

Everything here drives the real `_push_start` / `_push_status` machinery and polls it the way
pushPoll does. What each node "does" is stubbed at `_push_one`, which is the seam the panel already
has, so the states are the panel's own.

    python3 tools/the_push_paints_its_last_state_check.py
"""
import importlib.util
import os
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
fails = []

POLL = 0.4          # what pushPoll sleeps between reads
TERMINAL = ("ok", "same", "err", "skip")


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "  -- %r" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel(state, tag):
    spec = importlib.util.spec_from_file_location("tnl_push_" + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    return m


def poll_like_the_browser(m, gap=POLL, limit=60):
    """Read push-status the way pushPoll does: every `gap` seconds, stop on done."""
    seen = []
    for _ in range(limit):
        r = m.api_push_status({"job": m.PUSH_ALL})
        seen.append(r)
        if r.get("done"):
            return seen
        time.sleep(gap)
    raise AssertionError("the push never reported done")


def run_push(m, ids, ends, per_step=0.12):
    """Start a push whose nodes finish in `ends` (nid -> final state), and poll it out."""
    def one(jid, nid, payload):
        for pct in (10, 50, 90):
            m._push_set(jid, nid, state="run", pct=pct, step="send", si=1, sn=2)
            time.sleep(per_step)
        st = ends[nid]
        m._push_set(jid, nid, state=st, pct=100, step="", si=0, sn=0,
                    err=("failed" if st == "err" else ""))
    m._push_one = one
    jid = m._push_start("agent", [{"id": i, "name": i.upper()} for i in ids],
                        [("send", lambda *a: None)])
    return jid, poll_like_the_browser(m)


def truth(m, jid):
    return {k: dict(v) for k, v in m._push_jobs[jid]["nodes"].items()}


def main():
    print("== a push that finishes inside one poll interval ==")
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, "fast")
        ids = ["n1", "n2", "n3"]
        jid, seen = run_push(m, ids, {"n1": "ok", "n2": "ok", "n3": "err"})
        fin = seen[-1]
        check(fin.get("done") is True, "the last poll says done", fin.get("done"))
        check("order" in fin and "nodes" in fin,
              "and it CARRIES the node states, so the final paint has something to paint",
              sorted(fin.keys()))
        check(list(fin.get("order") or []) == ids, "every node is in the final order", fin.get("order"))
        check((fin.get("nodes") or {}) == truth(m, jid),
              "and each one is exactly what the job ended as", fin.get("nodes"))
        states = {k: v["state"] for k, v in (fin.get("nodes") or {}).items()}
        check(all(s in TERMINAL for s in states.values()),
              "no node is left in a running state", states)
        check(states.get("n3") == "err" and (fin["nodes"]["n3"].get("err") or ""),
              "a node that FAILED says so, with its reason", fin.get("nodes", {}).get("n3"))

    print("== the same, with the push running long enough to be seen mid-flight ==")
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, "slow")
        ids = ["n1", "n2"]
        jid, seen = run_push(m, ids, {"n1": "ok", "n2": "same"}, per_step=0.35)
        check(len(seen) >= 3, "the poll saw the push in progress", len(seen))
        mid = [s for s in seen[:-1] if s.get("nodes")]
        check(bool(mid), "the in-flight polls carry node states too")
        check(all(s.get("done") is False for s in seen[:-1]),
              "and none of them claims to be done -- the live payload used to hardcode done=False, "
              "which was right by accident and wrong as a rule",
              [s.get("done") for s in seen[:-1]])
        check((seen[-1].get("nodes") or {}) == truth(m, jid),
              "the final payload still matches the job", seen[-1].get("nodes"))

    print("== a new push does not inherit the last one's final view ==")
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, "second")
        run_push(m, ["n1", "n2"], {"n1": "ok", "n2": "ok"})
        jid2, seen2 = run_push(m, ["n9"], {"n9": "same"})
        fin = seen2[-1]
        check(list(fin.get("order") or []) == ["n9"],
              "the second batch reports only its own node", fin.get("order"))
        check(set((fin.get("nodes") or {})) == {"n9"},
              "and none of the first batch's", sorted(fin.get("nodes") or {}))

    print("== and the browser still refuses to reattach to a finished one ==")
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, "adopt")
        jid, seen = run_push(m, ["n1"], {"n1": "ok"})
        again = m.api_push_status({"job": m.PUSH_ALL})
        check(again.get("done") is True,
              "polling after the batch ended still says done", again.get("done"))
        js = m.INDEX_HTML
        i = js.index("async function pushAdopt(")
        adopt = js[i:js.index("async function pushCancel(")]
        check("r.done" in adopt and "return" in adopt,
              "pushAdopt reads `done` and stays out of the way -- the guard that used to require "
              "_push_merged() to vanish was pinning the mechanism, and that mechanism is the defect",
              adopt.strip()[:160])

    print("== an idle panel that has never pushed still answers ==")
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, "idle")
        r = m.api_push_status({"job": m.PUSH_ALL})
        check(r.get("idle") is True and r.get("done") is True,
              "no job ever ran: idle and done, which is what pushAdopt reads to stay out of the way", r)

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
