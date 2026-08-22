#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The ECH auto-heal must key on a signal the core CLEARS when the tunnel goes down.

`active` is a display label. The core writes it on a successful connect (and on a rotation or a pin)
and never clears it on a disconnect -- the disconnect block drops curConn / liveSNI / livePair / cur
and leaves `active` alone. So `down = not active` was False for the life of the core process once the
pool had connected once, and the whole ws-pool ECH auto-heal could never fire: a Cloudflare key
rotation left the tunnel down with nothing coming to rebuild it.

`ready` is the core's own "a carrier is up on this path right now", it is published in the same status
file, and `observe()` clears it the moment the connection goes. This pins two things:

  * _ech_pool_state reports down on the PRODUCTION shape -- ready False while `active` still holds the
    combination from the last successful connect;
  * api_edge_status actually carries `ready` through, because the node already returned it and the
    panel used to drop it on the floor, which is how the signal went missing in the first place.

    python3 tools/ech_heal_reads_a_live_signal_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


STALE_ACTIVE = "104.21.42.53:443 · cdn.spacefly.ir"


def main():
    P = load()
    real_edge_status = P.api_edge_status   # section 2 needs the real one back after section 1 stubs it

    print("== 1) the classifier reads the live signal, not the sticky label ==")
    # Exactly what a ws pool publishes while it is down: the label from the last successful connect,
    # ready False, and an edge on the naughty step.
    def status(ready, active=STALE_ACTIVE, bad=True, tls=True):
        return {"ok": True, "pool": True, "active": active, "ready": ready,
                "health": [{"key": "104.21.42.53:443", "kind": "ip",
                            "state": "suspect" if bad else "healthy"}],
                "events": ([{"kind": "down", "code": "tls", "ts": 1000}] if tls else []),
                "now": 1100, "ts": 1100}

    P.api_edge_status = lambda d: status(False)
    reachable, down, stalled = P._ech_pool_state("L1")
    check(reachable and down,
          "a pool with NO live carrier reads as down even though `active` still holds %r -- this is the "
          "case the auto-heal exists for, and it used to be invisible" % STALE_ACTIVE)

    P.api_edge_status = lambda d: status(True)
    _r, down_up, stalled_up = P._ech_pool_state("L1")
    check(not down_up,
          "a pool that IS carrying does not read as down (or every healthy tunnel would be rebuilt)")
    check(stalled_up,
          "a carrier still coasting while an edge is burned and TLS failed recently is `stalled` -- the "
          "stale-ECH-but-still-up window still has to rebuild")

    P.api_edge_status = lambda d: status(False, active="")
    _r, down_empty, _s = P._ech_pool_state("L1")
    check(down_empty, "and an empty label with no carrier is still down")

    # The signal must not be satisfiable by the label alone: if someone re-points this at `active`,
    # the production shape above goes quiet again.
    P.api_edge_status = lambda d: status(True, active="")
    _r, down_lbl, _s = P._ech_pool_state("L1")
    check(not down_lbl,
          "a carrier that is up is never down, whatever the label says -- keying on the label again "
          "would flip this")

    print("\n== 2) api_edge_status carries `ready` from the node ==")
    P.load_links = lambda: [{"id": "L1", "type": "core", "name": "core13", "ws_pool": True}]
    P._client_node = lambda L: {"id": "n1", "name": "IR01"}
    P.node_call = lambda node, op, method, body, timeout=10: {
        "ok": True, "active": STALE_ACTIVE, "ready": False, "epoch": 8,
        "health": [{"key": "104.21.42.53:443", "kind": "ip", "state": "suspect",
                    "fails": 0, "next_retest_unix": 0}],
        "events": [], "now": 1100, "ts": 1100,
        "pair": {"low": "", "high": "", "low_kind": "sni", "high_kind": "ip"}}
    out = real_edge_status({"id": "L1"})
    check("ready" in out,
          "the node returns `ready` and the panel must not drop it -- dropping it is exactly how the "
          "auto-heal lost its only truthful signal")
    check(out.get("ready") is False,
          "and it must carry the VALUE, got %r" % (out.get("ready"),))

    print("")
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the ECH auto-heal keys on a signal that goes false when the tunnel does.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
