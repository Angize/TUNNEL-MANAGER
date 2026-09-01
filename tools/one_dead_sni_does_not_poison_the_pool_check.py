#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One pool SNI losing its ECH record must be degraded and reported, not left with a stale key.

The refresh loop only ever degraded ALL-or-NOTHING: `removed` required every host in the pool to
have gone empty for three cycles running. A pool of three SNIs where exactly one CDN hostname
stops publishing its HTTPS record therefore hit none of the branches -- `_ech_write` skips empty
updates, so that host kept the key it had before, forever, silently.

That is not cosmetic. When an edge stops offering ECH the server does not hand back a retry
config, so core's in-band ECH self-heal has nothing to retry with and the handshake fails outright.
The pool keeps rotating onto that SNI, every rotation onto it dies, and the operator is told
nothing at all -- while plain wss to that same hostname would have worked fine.

The dead host's key is now cleared on its own, the tunnel is rebuilt once, one warn event names
the host, and the rest of the pool is left alone.

    python3 tools/one_dead_sni_does_not_poison_the_pool_check.py
"""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

spec = importlib.util.spec_from_file_location("tnlc", PANEL)
m = importlib.util.module_from_spec(spec)
sys.modules["tnlc"] = m
spec.loader.exec_module(m)

fails = []


def chk(ok, label, got=""):
    if ok:
        print("  ok   %s" % label)
    else:
        print(" FAIL  %-58s %r" % (label, got))
        fails.append(label)


POOL = [{"host": "a.example.com", "ech": "QUFB"},
        {"host": "b.example.com", "ech": "QkJC"},
        {"host": "c.example.com", "ech": "Q0ND"}]


def run(answers, cycles):
    link = {"id": "L1", "type": "core", "enabled": True, "name": "T1", "ech": True, "ws_pool": True,
            "ws_edge_snis": json.loads(json.dumps(POOL))}
    store = {"links": [link]}
    events, rebuilds = [], []
    m._ech_empty.clear()
    m._ech_down_rebuilt.clear()
    m.load_links = lambda: json.loads(json.dumps(store["links"]))
    m.save_json = lambda p, v: store.__setitem__("links", json.loads(json.dumps(v)))
    m.log_event = lambda lvl, cat, t, d="": events.append((lvl, t, d))
    m.api_rebuild_link = lambda a: rebuilds.append(a)
    m.api_edge_status = lambda a: {"ok": True, "ready": True, "health": [], "events": [], "now": 0}
    m.get_settings = lambda: {"ech_refresh_mins": 15}
    m._ech_live_push = lambda lid, chmap: (False, "")
    m._fetch_ech_map = lambda hosts, px: dict(answers)
    for _ in range(cycles):
        m._ech_refresh_once()
    keys = {s["host"]: s["ech"] for s in store["links"][0]["ws_edge_snis"]}
    return keys, events, rebuilds


ALIVE = {"a.example.com": "QUFB", "b.example.com": "QkJC", "c.example.com": "Q0ND"}
B_GONE = {"a.example.com": "QUFB", "b.example.com": "", "c.example.com": "Q0ND"}
ALL_GONE = {"a.example.com": "", "b.example.com": "", "c.example.com": ""}

print("b.example.com stops publishing its record, a and c keep theirs:\n")
keys, events, rebuilds = run(B_GONE, 5)
chk(keys["b.example.com"] == "", "the dead host's stale key is cleared", keys["b.example.com"])
chk(keys["a.example.com"] == "QUFB" and keys["c.example.com"] == "Q0ND",
    "the two live hosts keep their keys", keys)
chk(len(rebuilds) == 1, "the tunnel is rebuilt exactly once, not every cycle", len(rebuilds))
warns = [(t, d) for lvl, t, d in events if lvl == "warn"]
chk(len(warns) == 1, "exactly one event is logged", events)
chk(len(warns) == 1 and "b.example.com" in (warns[0][0] + warns[0][1]),
    "and it names the host that went dark", warns)
chk(len(warns) == 1 and "a.example.com" not in (warns[0][0] + warns[0][1])
    and "c.example.com" not in (warns[0][0] + warns[0][1]),
    "without accusing the two healthy hosts", warns)

print("\nnothing happens before the third empty cycle:\n")
keys, events, rebuilds = run(B_GONE, 2)
chk(keys["b.example.com"] == "QkJC", "two empty cycles are not enough to degrade", keys["b.example.com"])
chk(not events and not rebuilds, "and nothing is reported yet", (events, rebuilds))

print("\na healthy pool is left completely alone:\n")
keys, events, rebuilds = run(ALIVE, 5)
chk(keys == {"a.example.com": "QUFB", "b.example.com": "QkJC", "c.example.com": "Q0ND"},
    "every key survives", keys)
chk(not rebuilds, "nothing is rebuilt", len(rebuilds))

print("\nthe whole pool going dark still takes the all-hosts path:\n")
keys, events, rebuilds = run(ALL_GONE, 5)
chk(all(v == "" for v in keys.values()), "every key is cleared", keys)
chk(len(rebuilds) == 1, "and the tunnel is rebuilt once", len(rebuilds))
whole = [t for lvl, t, _ in events]
chk(len(whole) == 1 and "بخشی" not in whole[0],
    "the message is the whole-pool one, not the partial one", whole)

print()
if fails:
    print("FAILURES (%d):" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("one dead SNI is degraded on its own and the rest of the pool is untouched.")
