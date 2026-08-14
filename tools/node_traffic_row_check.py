#!/usr/bin/env python3
"""The node's OWN traffic figure is on its list row, and the operator can zero it.

The figure the node card shows -- «ورودیِ کل» / «خروجیِ کل» -- is the "_node" key: the sum over that
machine's physical NICs. Three reset paths existed and none of them could reach it, so the reset button
reported success and the number never moved. It was not a broken button; there was no code path at all.

What this pins, driven through the REAL endpoints rather than the helpers under them:

  1. the row carries the node's own rate + totals, in the same shape a tunnel row gets;
  2. resetting the NODE zeroes that total and leaves its tunnels alone;
  3. resetting a TUNNEL still leaves the node's own figure alone -- the two are separate ledgers, and a
     reset that quietly took both would be a worse bug than the one being fixed;
  4. the live BASELINE survives a reset, so the next sample measures from the counter the node is on
     rather than re-counting its whole lifetime;
  5. a reset for a node that does not exist is refused.

    python3 tools/node_traffic_row_check.py
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(state):
    spec = importlib.util.spec_from_file_location("ntr_panel", os.path.join(REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["ntr_panel"] = m
    spec.loader.exec_module(m)
    # Re-point EVERY path under the real CENTRAL_DIR, not the handful anyone lists: on a machine that
    # happens to have that directory, a missed one writes the operator's own state.
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    m.log_event = lambda *a, **k: None
    return m


def main():
    state = tempfile.mkdtemp(prefix="ntr-")
    P = load(state)
    node = {"id": "n1", "name": "one", "host": "10.0.0.1", "port": 8099, "token": "t"}
    P.save_json(P.NODES_FILE, [node])
    P.save_json(P.LINKS_FILE, [{"id": "L1", "name": "core9", "type": "core",
                                "a_node": "n1", "b_node": "n2", "a_name": "one", "b_name": "two"}])

    # Two samples of the real ingest path, so the totals are ACCUMULATED the way a live node produces
    # them rather than written straight into the table.
    P._tf_ingest("n1", {"_node": [1000, 2000], "core9": [10, 20]}, 100.0, 1000.0)
    P._tf_ingest("n1", {"_node": [6000, 9000], "core9": [110, 320]}, 102.0, 1002.0)

    print("== the row carries the node's own figure ==")
    row = next(r for r in P.api_nodes({})["nodes"] if r["id"] == "n1")
    t = row.get("traffic")
    check("the node row has a traffic block at all", isinstance(t, dict), repr(t))
    if not isinstance(t, dict):
        return 1
    check("...and it is the NODE's own bytes, not a tunnel's",
          (t["rx_total"], t["tx_total"]) == (5000, 7000), repr(t))
    check("...with a live rate beside them", t["rx_bps"] > 0 and t["tx_bps"] > 0, repr(t))
    # 5000 bytes in 2 s = 20000 bit/s. Computed, not asserted loosely: a rate that silently came out in
    # bytes or per-sample would still be "> 0".
    check("...and the rate is bits per second over the real interval",
          abs(t["rx_bps"] - 20000.0) < 1.0, "%r" % t["rx_bps"])

    print("== resetting the NODE zeroes the node, and only the node ==")
    P.api_traffic_reset({"node": "n1"})
    row = next(r for r in P.api_nodes({})["nodes"] if r["id"] == "n1")
    check("the node's own total is zero", (row["traffic"]["rx_total"], row["traffic"]["tx_total"]) == (0, 0),
          repr(row["traffic"]))
    tun = P._tf_read("n1")["core9"]
    check("...and its tunnel's total is untouched", (tun["crx"], tun["ctx"]) == (100, 300),
          "%r/%r" % (tun["crx"], tun["ctx"]))

    print("== the baseline survives, so the next sample is not a re-count ==")
    # Without this the next reading would credit the node's WHOLE lifetime counter as one delta.
    P._tf_ingest("n1", {"_node": [6500, 9500]}, 104.0, 1004.0)
    row = next(r for r in P.api_nodes({})["nodes"] if r["id"] == "n1")
    check("only the bytes since the reset are counted",
          (row["traffic"]["rx_total"], row["traffic"]["tx_total"]) == (500, 500), repr(row["traffic"]))

    print("== and the tunnel reset still does not take the node's figure with it ==")
    P.api_traffic_reset({"id": "L1"})
    tun = P._tf_read("n1")["core9"]
    row = next(r for r in P.api_nodes({})["nodes"] if r["id"] == "n1")
    check("the tunnel's total is zero", (tun["crx"], tun["ctx"]) == (0, 0), "%r/%r" % (tun["crx"], tun["ctx"]))
    check("...and the node's own total is still what it was",
          (row["traffic"]["rx_total"], row["traffic"]["tx_total"]) == (500, 500), repr(row["traffic"]))

    print("== a node that does not exist is refused ==")
    try:
        P.api_traffic_reset({"node": "nope"})
        check("resetting an unknown node is refused", False, "it returned ok")
    except ValueError:
        check("resetting an unknown node is refused", True)

    # A node the panel has never sampled has no figure to show, and the row must say so with None
    # rather than inventing zeros -- zeros read as "this node moved nothing", which is a different claim.
    P.save_json(P.NODES_FILE, [node, {"id": "n9", "name": "cold", "host": "10.0.0.9", "port": 8099, "token": "t"}])
    cold = next(r for r in P.api_nodes({})["nodes"] if r["id"] == "n9")
    check("a never-sampled node reports no figure rather than zeros", cold.get("traffic") is None,
          repr(cold.get("traffic")))

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("the node's own traffic is on its row, and resetting it hits nothing else.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
