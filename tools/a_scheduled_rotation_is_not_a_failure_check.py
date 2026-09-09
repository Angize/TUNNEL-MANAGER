#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the log must tell a rotation that was DUE from one the tunnel was FORCED into.

They are opposite news and they used to be the same line. The core published both as kind "down",
code "<axis>-rotate", with the same detail, so the panel painted the same green «چرخش آی‌پیِ مقصد»
whether the clock had come due on a healthy tunnel or the ladder had just walked off an endpoint that
stopped carrying traffic. An operator reading the log could not tell a tunnel that is working from one
that is limping — and the limping one is the whole reason to read the log.

The core knew all along: only the forced rotation sets wasDown, which is what arms the recovery line
on the next reconnect. It publishes that under kind "rot" now, and this pins the rendering.

This drives the REAL ingest loop (_events_once), stubbing only the node RPC. That matters here more
than usual: every rotation code is answered INSIDE that loop and `continue`s, so _ev_core_text is
never reached for one. A guard that called the formatter directly would go green against a panel
whose ingest loop had dropped the kind on the floor — which is exactly what the loop did to every
"rot" event before this change: no branch matched, so four events per sweep vanished silently.

Four things are pinned:

  * every axis renders BOTH kinds, and they differ in level as well as in words — a fix that only
    changed the sentence would leave the card green and the eye slides past it;
  * a scheduled rotation still carries its from/to pair, which lives in _ev_state["rotip"] and is
    only updated by the branch that renders the axis rotations. Route the new kind past that branch
    and the pair silently goes stale instead of disappearing;
  * the rotation codes that are NOT an axis — rehandshake, port-roll, edge-walk, ladder-revive —
    render exactly as before;
  * an unknown code under kind "rot" logs NOTHING rather than falling through to «قطع شد». A future
    core that invents a rot code this panel does not know must not report the tunnel as down.

    python3 tools/a_scheduled_rotation_is_not_a_failure_check.py
"""
import importlib.util
import os
import sys

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")
spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

DIRECT = {"id": "L1", "type": "core", "enabled": True, "name": "direct", "transport": "udp"}
POOL = {"id": "L2", "type": "core", "enabled": True, "name": "pool", "ws_pool": True}

CARDS = []
RING = {"L1": [], "L2": []}

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)
        if got is not None:
            print("        got: %r" % (got,))


def status(lid):
    return {"ok": True, "pool": lid == "L2", "ready": True, "health": [], "now": 0, "ts": 0,
            "active": "104.18.2.2 · front-a.example" if lid == "L2" else "",
            "pair": {"low": "", "high": "", "low_kind": "", "high_kind": ""},
            "events": list(RING[lid])}


def install():
    P.load_nodes = lambda: []
    P.load_links = lambda: [DIRECT, POOL]
    P._cache_get = lambda n: None
    P._node_online = lambda n: True
    P.api_peer_status = lambda d: None
    P.api_edge_status = lambda d: status(d["id"])
    P.log_event = lambda lvl, cat, fa, dfa="": CARDS.append({"lvl": lvl, "cat": cat, "fa": fa, "dfa": dfa})


def sweep(l1, l2=()):
    """One ingest pass over the rings given, returning the cards it wrote."""
    RING["L1"] = [{"seq": i + 1, "ts": 0, "kind": k, "code": c, "detail": d}
                  for i, (k, c, d) in enumerate(l1)]
    RING["L2"] = [{"seq": i + 1, "ts": 0, "kind": k, "code": c, "detail": d}
                  for i, (k, c, d) in enumerate(l2)]
    CARDS.clear()
    P._ev_state.update({"init": True, "nodes": {}, "links": {}, "edge": {},
                        "evseq": {"L1": 0, "L2": 0}, "rotip": {}, "links_coarse_down": set()})
    P._events_once()
    return list(CARDS)


install()

print("== 0) the two rotation tables do not overlap ==")
# _ev_rot reads the axis table FIRST, so a code in both would silently take the axis rendering and the
# level in _EV_ROT_CODE would be dead. Cheap to assert, and impossible to see by reading either table.
both = sorted(set(P._EV_ROT_AXIS) & set(P._EV_ROT_CODE))
check(not both, "no code is in both _EV_ROT_AXIS and _EV_ROT_CODE", both)

# The axis comes out of the table now. It used to be sniffed out of the code NAME -- `"src" in ecode`
# -- which worked only because the two direct codes happen to be spelled peer-rotate and src-rotate,
# and which silently answers "dst" for anything else. The loop keys the from/to pair state on it, so a
# wrong axis does not raise: it writes the destination it just learned into the source's slot.
stray = sorted({ax for ax, _ in P._EV_ROT_AXIS.values()} - set(P._HEAL_AXIS))
check(not stray, "every rotation axis is a name the burn and heal lines already use", stray)
check(all(P._ev_rot("down", c)[2] == ax for c, (ax, _) in P._EV_ROT_AXIS.items()),
      "_ev_rot hands the loop the axis from the table rather than one read off the code name")
check(all(P._ev_rot("down", c)[2] == "" for c in P._EV_ROT_CODE),
      "and a rotation that is not on an axis carries none, so it never touches the from/to state")

print("\n== 1) every axis renders both kinds, and they do not look alike ==")
AXES = [("peer-rotate", "ip:198.51.100.7:5555", "L1"),
        ("src-rotate", "ip:203.0.113.4", "L1"),
        ("edge-rotate", "ip:104.18.2.2", "L2"),
        ("sni-rotate", "sni:front-a.example", "L2")]
for code, det, lid in AXES:
    rows = sweep([("rot", code, det), ("down", code, det)] if lid == "L1" else [],
                 [("rot", code, det), ("down", code, det)] if lid == "L2" else [])
    rows = [c for c in rows if code.split("-")[0] in c["fa"] or "چرخش" in c["fa"]]
    check(len(rows) == 2, "%s: both kinds reach the log" % code, [c["fa"] for c in rows])
    if len(rows) != 2:
        continue
    sched = [c for c in rows if c["lvl"] == "ok"]
    forced = [c for c in rows if c["lvl"] == "warn"]
    check(len(sched) == 1 and len(forced) == 1,
          "%s: the scheduled one is informational and the forced one is a warning" % code,
          [(c["lvl"], c["fa"]) for c in rows])
    if len(sched) == 1 and len(forced) == 1:
        check(sched[0]["fa"] != forced[0]["fa"],
              "%s: and the sentences differ, so the two are readable apart" % code,
              sched[0]["fa"])
        check("زمان" in sched[0]["fa"], "%s: the scheduled one says it was due" % code, sched[0]["fa"])
        check("اجبار" in forced[0]["fa"], "%s: the forced one says it was not" % code, forced[0]["fa"])

print("\n== 2) a scheduled rotation still carries its from/to pair ==")
rows = sweep([("rot", "peer-rotate", "ip:198.51.100.7:5555"),
              ("rot", "peer-rotate", "ip:198.51.100.8:5555")])
check(len(rows) == 2, "two scheduled destination rotations, two cards", [c["fa"] for c in rows])
if len(rows) == 2:
    check("از:" in rows[1]["dfa"] and "198.51.100.7:5555" in rows[1]["dfa"],
          "the second card names where it came FROM — the kind must not bypass the pair state",
          rows[1]["dfa"])
    check("198.51.100.8:5555" in rows[1]["dfa"], "and where it went TO", rows[1]["dfa"])

print("\n== 3) the rotation codes that are not an axis are untouched ==")
OTHER = [("rehandshake", "udp", "warn"), ("port-roll", "tries:3 sport:41234", "ok"),
         ("ladder-revive", "", "warn")]
for code, det, want in OTHER:
    rows = sweep([("down", code, det)])
    check(len(rows) == 1 and rows[0]["lvl"] == want,
          "%s still renders once, at level %s" % (code, want),
          [(c["lvl"], c["fa"]) for c in rows])
rows = sweep([], [("down", "edge-walk", "ws")])
check(len(rows) == 1 and rows[0]["lvl"] == "warn", "edge-walk still renders once, at level warn",
      [(c["lvl"], c["fa"]) for c in rows])

print("\n== 4) an unknown rot code is silent, not «disconnected» ==")
rows = sweep([("rot", "a-code-this-panel-has-never-heard-of", "ip:1.2.3.4")])
check(not rows, "a rot code the panel does not know logs nothing at all", [c["fa"] for c in rows])
rows = sweep([("down", "ping_timeout", "")])
check(len(rows) == 1 and rows[0]["lvl"] == "bad",
      "while a real down is still reported as a disconnection", [(c["lvl"], c["fa"]) for c in rows])

print("\n%d failure(s)" % len(fails) if fails else "\na rotation says why it happened")
sys.exit(1 if fails else 0)
