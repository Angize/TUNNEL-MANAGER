#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A released pin must say WHICH pin was released and WHY.

core sends the detail as `axis + ":" + reason` -- `dst:`/`src:` from the peer pool, `edge:`/`ip:`/
`sni:` from the ws pool. `_ev_core_text` stripped `dst:`/`src:`/`ip:`/`sni:` off the front for the
burn and heal branches BEFORE the pin_dropped branch ran its own partition, so four of the six
shapes lost their axis and read "لبهٔ" no matter what was actually released, and two of them
("dst:cannot-land", "ip:cannot-land") also lost the reason and told the operator the path was
blocked when in fact it had never come up at all.

This drives the real ingest loop, `_events_once`, not the text helper: the helper was always
callable with an unstripped detail, which is exactly why a helper-level test stayed green.

    python3 tools/the_dropped_pin_names_its_axis_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

spec = importlib.util.spec_from_file_location("tnlc", PANEL)
m = importlib.util.module_from_spec(spec)
sys.modules["tnlc"] = m
spec.loader.exec_module(m)

LAND = "\u0627\u0635\u0644\u0627\u064b \u0648\u0635\u0644 \u0646\u0634\u062f"
BLOCK = "\u0645\u0633\u062f\u0648\u062f \u0628\u0648\u062f"

CASES = [
    ("dst:cannot-land", m._PIN_AXIS["dst"], LAND),
    ("dst:tun-probe", m._PIN_AXIS["dst"], BLOCK),
    ("src:cannot-land", m._PIN_AXIS["src"], LAND),
    ("src:tun-probe", m._PIN_AXIS["src"], BLOCK),
    ("ip:cannot-land", m._PIN_AXIS["ip"], LAND),
    ("ip:tun-probe", m._PIN_AXIS["ip"], BLOCK),
    ("sni:cannot-land", m._PIN_AXIS["sni"], LAND),
    ("sni:tun-probe", m._PIN_AXIS["sni"], BLOCK),
    ("edge:cannot-land", m._PIN_AXIS["ip"], LAND),
    ("edge:tun-probe", m._PIN_AXIS["ip"], BLOCK),
]

LINK = {"id": "L1", "type": "core", "enabled": True, "name": "T1", "ws_pool": True,
        "transport": "ws", "a_node": "n1", "b_node": "n2"}

fails = []


def chk(ok, label, got=""):
    if ok:
        print("  ok   %s" % label)
    else:
        print(" FAIL  %s   %r" % (label, got))
        fails.append(label)


def run(detail):
    seen = []
    m._ev_state.update({"init": False, "nodes": {}, "links": {}, "links_coarse_down": set(),
                        "edge": {}, "evseq": {}, "rotip": {}})
    m.load_nodes = lambda: []
    m.load_links = lambda: [LINK]
    m._cache_get = lambda nid: {}
    m._node_online = lambda nid: True
    m.parallel_map = lambda f, xs: [f(x) for x in xs]
    m.api_peer_status = lambda a: None
    m.log_event = lambda lvl, cat, title, detail="": seen.append((lvl, cat, title, detail))
    m.api_edge_status = lambda a: {"active": "1.1.1.1", "events": []}
    m._events_once()
    m.api_edge_status = lambda a: {"active": "1.1.1.1", "events": [
        {"seq": 1, "kind": "pool", "code": "pin_dropped", "detail": detail}]}
    m._events_once()
    return [t for lvl, cat, t, d in seen if "\u067e\u06cc\u0646" in t]


print("a released pin, one row per shape core can send:\n")
for detail, want_axis, want_why in CASES:
    got = run(detail)
    line = got[0] if got else ""
    chk(len(got) == 1 and want_axis in line and want_why in line,
        "%-16s names %-14s and says %s" % (detail, want_axis, want_why), line)

spoken = set()
for detail, _, _ in CASES:
    got = run(detail)
    if got:
        head = got[0].split("پینِ ", 1)[-1].split(" — ", 1)[0]
        spoken.add(head)
chk(len(spoken) == 4, "the rendered lines really name four different things", sorted(spoken))

print()
if fails:
    print("FAILURES (%d):" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("a released pin names its axis and its reason on every shape core sends.")
