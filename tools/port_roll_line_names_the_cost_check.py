#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The port-roll line must name what the recovery COST, not just that it happened.

The core writes «sport:<p> tries:<n>» when the probe finds traffic crossing after a source-port draw.
The operator needs both halves: a tunnel that came back on its first draw and one that came back on
its last are not the same news.

This drives the REAL ingest loop (_events_once), not the renderer helper. That distinction is the
whole point of the file: every code in _EV_ROT_CODE is answered inside that loop and `continue`s, so
_ev_core_text is never reached for one — a fix written there renders nothing and the panel goes on
printing the old sentence.

    python3 tools/port_roll_line_names_the_cost_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = load_panel()

NODES = [{"id": "na", "name": "NODE-A", "host": "203.0.113.5", "port": 8099, "token": "x"},
         {"id": "nb", "name": "NODE-B", "host": "198.51.100.7", "port": 8099, "token": "y"}]
LINK = {"id": "L1", "name": "core12", "type": "core", "enabled": True, "transport": "raw",
        "raw_profile": "tcp", "a_node": "na", "b_node": "nb", "a_name": "NODE-A", "b_name": "NODE-B"}

ring, captured = [], []
P.load_nodes = lambda: NODES
P.load_links = lambda: [LINK]
P._cache_get = lambda nid: {"ok": True}
P._node_online = lambda nid: True
P._link_up = lambda L: True
P._link_side_health = lambda L, side: ({"up": True}, "")
P.api_edge_status = lambda d: {"ok": True, "active": "raw:tcp · 198.51.100.7", "health": [],
                               "events": list(ring)}
P.log_event = lambda lvl, kind, fa, dfa="": captured.append((lvl, kind, fa, dfa))

P._events_once()          # seed the high-water; logs nothing
captured[:] = []
ring[:] = [{"seq": 1, "kind": "down", "code": "port-roll", "detail": "sport:443 tries:3"},
           {"seq": 2, "kind": "down", "code": "port-roll", "detail": "sport:8080 tries:1"},
           {"seq": 3, "kind": "down", "code": "rehandshake", "detail": "raw"}]
P._events_once()

fails = []
rolls = [fa for _l, _k, fa, _d in captured if "چرخشِ پورتِ مبدأ" in fa]
print("the lines the ingest loop wrote:")
for _l, _k, fa, _d in captured:
    print("   " + fa)

if len(rolls) != 2:
    fails.append("expected 2 port-roll lines, got %d" % len(rolls))
for want, line in (("443", rolls[0] if rolls else ""), ("8080", rolls[1] if len(rolls) > 1 else "")):
    if want not in line:
        fails.append("a port-roll line does not name the port %s: %r" % (want, line))
for want, line in (("3", rolls[0] if rolls else ""), ("1", rolls[1] if len(rolls) > 1 else "")):
    if "تلاش" not in line or want not in line:
        fails.append("a port-roll line does not name the attempt count %s: %r" % (want, line))
# the neighbours must be untouched
if not any("دست‌دادنِ دوباره" in fa for _l, _k, fa, _d in captured):
    fails.append("the re-handshake line stopped rendering")

print()
if fails:
    for f in fails:
        print(" FAIL " + f)
    sys.exit(1)
print("the port-roll line names both the attempts and the port it came back on.")
