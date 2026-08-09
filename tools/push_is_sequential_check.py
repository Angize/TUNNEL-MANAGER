#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The agent/core upload goes to ONE node at a time, reports real progress, and never gives up on the rest.

Three properties, all operator-stated, all easy to lose in a refactor back to parallel_map:

  * ONE AT A TIME -- node B's upload must not start before node A's finished. The old push fired every
    node at once and returned a single verdict at the end, so there was nothing per-node to show.
  * a node that FAILS or TIMES OUT is recorded and the queue MOVES ON. A dead node used to be able to
    take the whole sweep's result with it.
  * the progress a node reports is the bytes actually sent, not a phase guess, and it only ever moves
    forward.

Driven against the real _push_worker with node_push faked, so the ordering being tested is the ordering
the panel really performs.

    python3 tools/push_is_sequential_check.py
"""
import argparse
import importlib.util
import sys
import threading
import time
from pathlib import Path

NODES = [{"id": "n%d" % i, "name": "N%d" % i, "host": "10.0.0.%d" % i, "port": 8099, "token": "t"}
         for i in (1, 2, 3, 4)]


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    spec = importlib.util.spec_from_file_location("tnl_central", str(a.panel))
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    failures = []

    def chk(label, got, want):
        if got != want:
            failures.append("%s: got %r, expected %r" % (label, got, want))
        else:
            print("  ok   %-56s %r" % (label, got))

    P.get_node = lambda nid: next((n for n in NODES if n["id"] == nid), None)
    P._ensure_update_key = lambda n: None

    timeline, overlap = [], []
    active = set()
    lock = threading.Lock()

    def fake_push(node, endpoint, body, on_progress=None, timeout=200):
        nid = node["id"]
        with lock:
            if active:                       # someone else is mid-upload -> not sequential
                overlap.append((sorted(active), nid))
            active.add(nid)
        timeline.append(("start", nid))
        total = 1000
        for sent in (0, 250, 500, 1000):     # a real push reports bytes as they go
            on_progress(sent, total)
            time.sleep(0.002)
        with lock:
            active.discard(nid)
        timeline.append(("end", nid))
        if nid == "n2":
            return {"ok": False, "offline": True, "error": "timed out"}   # the dead node
        if nid == "n3":
            raise OSError("connection reset")                             # a surprise, mid-sweep
        return {"ok": True, "restarting": True}

    P.node_push = fake_push
    jid = P._push_job_new("agent", NODES)
    P._push_worker(jid, "agent", NODES, lambda n: ({"code": "x"}, "update", 60))

    st = P.api_push_status({"job": jid})
    chk("the job finishes", st["done"], True)
    chk("every node is reported", sorted(st["nodes"]), ["n1", "n2", "n3", "n4"])
    chk("no two uploads overlapped", overlap, [])
    chk("they ran in the order given",
        [nid for kind, nid in timeline if kind == "start"], ["n1", "n2", "n3", "n4"])
    chk("each one finished before the next began",
        timeline, [("start", "n1"), ("end", "n1"), ("start", "n2"), ("end", "n2"),
                   ("start", "n3"), ("end", "n3"), ("start", "n4"), ("end", "n4")])

    chk("a node that answers ok reaches 100", (st["nodes"]["n1"]["state"], st["nodes"]["n1"]["pct"]),
        ("ok", 100))
    chk("the node that TIMED OUT is marked, with its reason",
        (st["nodes"]["n2"]["state"], st["nodes"]["n2"]["error"]), ("err", "timed out"))
    chk("a node that RAISED mid-sweep is marked too", st["nodes"]["n3"]["state"], "err")
    chk("and the nodes AFTER the failures still went",
        (st["nodes"]["n4"]["state"], st["nodes"]["n4"]["pct"]), ("ok", 100))

    # progress must be real and monotonic: replay one node and watch the published pct
    seen = []
    P.node_push = lambda node, ep, body, on_progress=None, timeout=200: (
        [on_progress(s, 1000) or seen.append(P.api_push_status({"job": j2})["nodes"]["n1"]["pct"])
         for s in (0, 100, 500, 900, 1000)] and {"ok": True})
    j2 = P._push_job_new("agent", [NODES[0]])
    P._push_worker(j2, "agent", [NODES[0]], lambda n: ({"code": "x"}, "update", 60))
    chk("the bar tracks bytes, not phases", seen, [0, 9, 47, 85, 95])
    chk("it never goes backwards", seen == sorted(seen), True)
    chk("the last 5% belong to the node's own verify+swap",
        P.api_push_status({"job": j2})["nodes"]["n1"]["pct"], 100)

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\none node at a time, real byte progress, and a dead node cannot cancel the rest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
