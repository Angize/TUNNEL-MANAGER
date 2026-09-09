#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: one rotation is one log line, and it reads the same on every carrier.

The panel used to have TWO independent producers for a CDN edge rotation, and they raced:

  * the core's own event, fired the instant the pool moves (tcp.go rotateDestTCP ->
    coreStatus.rotated -> code "edge-rotate"), rendered as the CDN-edge line with only a
    "be:" half and no SNI beside it;
  * the panel noticing `active` changed, which for an edge pool happens LATER -- the core sets
    it only after the replacement connection is up (tcp.go setActive(combo)) -- rendered under a
    different title, a different event kind, and an "az:/be:" pair carrying "ip:port . sni".

Both land inside the same 15s poll only when the reconnect is fast. Straddle the boundary and the
operator sees the SAME rotation twice in two different wordings. The live panel log on 2026-09-09
held 26 of the first and 4 of the second for core13 alone, and both shapes for core15 and core49 --
which is why it looked like an http-vs-grpc difference and was not.

So the panel stopped guessing: the core reports every rotation, and the panel renders all four axes
(dst, src, ip, sni) through ONE branch and ONE formatter. This drives the real `_events_once` per
carrier and asserts it.

Exit 1 on any failure.
"""
import importlib.util
import io
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

ROT = "چرخش"
AZ = "از:"
BE = "به:"
ARROW = "←"
BY_CLOCK = "طبقِ زمان‌بندی"
FORCED = "اجباری"

fails = []


def fail(m):
    fails.append(m)
    print("FAIL: " + m)


def ok(m):
    print("  ok  " + m)


def load():
    spec = importlib.util.spec_from_file_location("tc", PANEL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["tc"] = m
    spec.loader.exec_module(m)
    return m


# One link per carrier family, each with the axis pair its core actually rotates.
#   name, link fields, (low axis, two values), (high axis, two values), the `active` core publishes
CASES = [
    ("udp", {"transport": "udp", "ip_rotate": True},
     ("dst", ["9.9.9.1:20000", "9.9.9.2:20000"]), ("src", ["10.0.0.1", "10.0.0.2"]),
     "udp · 9.9.9.1:20000"),
    ("tcp", {"transport": "tcp", "ip_rotate": True},
     ("dst", ["9.9.9.1:443", "9.9.9.2:443"]), ("src", ["10.0.0.1", "10.0.0.2"]),
     "tcp · 9.9.9.1:443"),
    ("raw", {"transport": "raw", "raw_profile": "tcp", "ip_rotate": True},
     ("dst", ["9.9.9.1", "9.9.9.2"]), ("src", ["10.0.0.1", "10.0.0.2"]),
     "raw:tcp · 9.9.9.1"),
    ("ws/ws", {"transport": "ws", "cdn_carrier": "ws", "ws_pool": True},
     ("ip", ["104.21.42.53:443", "172.67.157.31:443"]), ("sni", ["a.example.com", "b.example.com"]),
     "104.21.42.53:443 · a.example.com"),
    ("ws/http", {"transport": "ws", "cdn_carrier": "http", "ws_pool": True},
     ("ip", ["104.21.42.53:443", "172.67.157.31:443"]), ("sni", ["a.example.com", "b.example.com"]),
     "104.21.42.53:443 · a.example.com"),
    ("ws/grpc", {"transport": "ws", "cdn_carrier": "grpc", "ws_pool": True},
     ("ip", ["104.21.42.53:443", "172.67.157.31:443"]), ("sni", ["a.example.com", "b.example.com"]),
     "104.21.42.53:443 · a.example.com"),
]

AXIS_CODE = {"dst": "peer-rotate", "src": "src-rotate", "ip": "edge-rotate", "sni": "sni-rotate"}


def axis_prefix(axis):
    return "sni" if axis == "sni" else "ip"


def run(m, case, kind):
    """Drive the REAL _events_once twice: one settling pass, then the pass that moves both axes."""
    _name, fields, (lo_ax, lo_vals), (hi_ax, hi_vals), active = case
    link = dict({"id": "7", "type": "core", "name": "t1", "enabled": True,
                 "a_node": "1", "b_node": "2"}, **fields)
    lines = []
    state = {"seq": 0, "evs": [], "active": active}

    def ev(axis, val):
        state["seq"] += 1
        state["evs"].append({"seq": state["seq"], "kind": kind, "code": AXIS_CODE[axis],
                             "detail": axis_prefix(axis) + ":" + val, "ts": 1})

    saved = {k: getattr(m, k) for k in ("load_nodes", "load_links", "log_event", "_cache_get",
                                        "api_edge_status", "api_peer_status", "_node_online",
                                        "_link_side_health", "parallel_map")}
    m.load_nodes = lambda: [{"id": "1", "name": "n1"}, {"id": "2", "name": "n2"}]
    m.load_links = lambda: [link]
    m._cache_get = lambda nid: {"ok": True}
    m._node_online = lambda nid: True
    m._link_side_health = lambda L, side: ({"up": True}, "")
    m.parallel_map = lambda f, xs: [f(x) for x in xs]
    m.api_peer_status = lambda d: {"src": {"active": hi_vals[0] if hi_ax == "src" else ""},
                                   "dst": {"active": lo_vals[0] if lo_ax == "dst" else ""}}
    m.api_edge_status = lambda d: {"ok": True, "pool": bool(fields.get("ws_pool")),
                                   "active": state["active"], "health": [],
                                   "events": list(state["evs"])}
    m.log_event = lambda lvl, k, fa, dfa="": lines.append((lvl, k, fa, dfa))
    m._ev_state.update({"init": False, "nodes": {}, "links": {}, "evseq": {}, "rotip": {},
                        "links_coarse_down": set()})
    try:
        ev(lo_ax, lo_vals[0])
        ev(hi_ax, hi_vals[0])
        m._events_once()
        lines[:] = []
        ev(lo_ax, lo_vals[1])
        ev(hi_ax, hi_vals[1])
        if lo_ax == "ip":
            state["active"] = lo_vals[1] + " · " + hi_vals[1]
        m._events_once()
    finally:
        for k, v in saved.items():
            setattr(m, k, v)
    return [l for l in lines if ROT in l[2]]


def main():
    m = load()
    print("== 1) each axis rotation is ONE line, and its detail has the same shape everywhere ==")
    shapes = {}
    for case in CASES:
        name = case[0]
        for kind, want in (("rot", BY_CLOCK), ("down", FORCED)):
            got = run(m, case, kind)
            if len(got) != 2:
                fail("%-8s %-4s: %d rotation lines for 2 rotations -- %r"
                     % (name, kind, len(got), [g[2] for g in got]))
                continue
            for lvl, k, fa, dfa in got:
                if k != "rot":
                    fail("%-8s %-4s: event kind %r, want 'rot' -- a second kind splits one fact "
                         "across two filter chips" % (name, kind, k))
                if want not in fa:
                    fail("%-8s %-4s: %r never says WHY it rotated" % (name, kind, fa))
                shapes.setdefault((AZ in dfa, BE in dfa, ARROW in dfa), []).append(name + "/" + kind)
            ok("%-8s %-4s -> %s | %s" % (name, kind, got[0][3].replace("\n", " / "),
                                         got[1][3].replace("\n", " / ")))

    print("== 2) ...and it is ONE shape, not one per carrier ==")
    if len(shapes) == 1:
        sh = list(shapes)[0]
        ok("all %d cells render az=%s be=%s pair=%s"
           % (sum(len(v) for v in shapes.values()), sh[0], sh[1], sh[2]))
    else:
        for sh, who in sorted(shapes.items()):
            fail("shape az=%s be=%s pair=%s is produced only by %s" % (sh[0], sh[1], sh[2], who))

    print("== 3) the panel keeps no second producer that guesses a rotation from `active` ==")
    src = io.open(PANEL, encoding="utf-8").read()
    for dead in ("_ev_suppress", '_ev_state["edge"]'):
        if dead in src:
            fail("%s is back -- so is the second wording it existed to serve" % dead)
        else:
            ok("%s is gone" % dead)

    print()
    if fails:
        print("FAILURES (%d):" % len(fails))
        for f in fails:
            print("  - " + f)
        return 1
    print("one rotation is one line, and every carrier writes it the same way")
    return 0


if __name__ == "__main__":
    sys.exit(main())
