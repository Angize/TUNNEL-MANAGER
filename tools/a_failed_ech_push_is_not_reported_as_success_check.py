#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A live ECH push that never reached the node must not be logged green, and must be recovered.

`_ech_live_push` returned a single string: the node's label on success, and "" for everything
else. The caller could not tell "there was no node to push to" from "the node was unreachable",
so it treated both the same and wrote an `ok` event saying the key had been refreshed on the
timer. Meanwhile the new key was already on disk and the running core still had the old one --
a split the panel would not close until something else happened to trigger a rebuild.

The push now reports whether it was attempted. A push that was attempted and failed falls back
to the rebuild that was always the working recovery path, and says so at warn.

    python3 tools/a_failed_ech_push_is_not_reported_as_success_check.py
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
        print(" FAIL  %-56s %r" % (label, got))
        fails.append(label)


LINK = {"id": "L1", "type": "core", "enabled": True, "name": "T1", "ech": True, "ws_pool": True,
        "ws_edge_snis": [{"host": "a.example.com", "ech": "T0xE"}]}
NODE = {"id": "n1", "name": "N1", "host": "1.2.3.4"}


def run(node, reply):
    store = {"links": [json.loads(json.dumps(LINK))]}
    events, rebuilds, calls = [], [], []
    m._ech_empty.clear()
    m._ech_down_rebuilt.clear()
    m.load_links = lambda: json.loads(json.dumps(store["links"]))
    m.save_json = lambda p, v: store.__setitem__("links", json.loads(json.dumps(v)))
    m.log_event = lambda lvl, cat, t, d="": events.append((lvl, t))
    m.api_rebuild_link = lambda a: rebuilds.append(a)
    m.api_edge_status = lambda a: {"ok": True, "ready": True, "health": [], "events": [], "now": 0}
    m.get_settings = lambda: {"ech_refresh_mins": 15}
    m._client_node = lambda L: node

    def call(n, path, method, body, timeout=8):
        calls.append(path)
        if reply == "raise":
            raise OSError("node unreachable")
        return reply

    m.node_call = call
    m._fetch_ech_map = lambda hosts, px: {"a.example.com": "TkVX"}
    m._ech_refresh_once()
    return store["links"][0]["ws_edge_snis"][0]["ech"], events, rebuilds, calls


print("the node is unreachable -- the key is on disk but the core never heard it:\n")
key, events, rebuilds, calls = run(NODE, "raise")
chk(key == "TkVX", "the fresh key is stored", key)
chk(calls == ["ech-update"], "the push was attempted", calls)
chk(not any(lvl == "ok" for lvl, _ in events), "no green event claims success", events)
chk(any(lvl == "warn" for lvl, _ in events), "a warn event is raised instead", events)
chk(len(rebuilds) == 1, "and the tunnel is rebuilt so the core gets the key", len(rebuilds))

print("\nthe node answers but refuses -- treated the same as unreachable:\n")
key, events, rebuilds, calls = run(NODE, {"ok": False})
chk(not any(lvl == "ok" for lvl, _ in events), "no green event claims success", events)
chk(len(rebuilds) == 1, "the tunnel is rebuilt", len(rebuilds))

print("\nthe node accepts the push -- nothing else needs to happen:\n")
key, events, rebuilds, calls = run(NODE, {"ok": True})
chk([lvl for lvl, _ in events] == ["ok"], "one green event", events)
chk(not rebuilds, "and no rebuild, because the live push was enough", len(rebuilds))

print("\nthere is no client node to push to -- not a failure, so no rebuild:\n")
key, events, rebuilds, calls = run(None, {"ok": True})
chk(not calls, "nothing is pushed", calls)
chk([lvl for lvl, _ in events] == ["ok"], "one green event", events)
chk(not rebuilds, "and no rebuild", len(rebuilds))

print("\nthe rebuild itself failing is reported at bad, not warn:\n")
store = {"links": [json.loads(json.dumps(LINK))]}
events = []
m._ech_empty.clear()
m._ech_down_rebuilt.clear()
m.load_links = lambda: json.loads(json.dumps(store["links"]))
m.save_json = lambda p, v: store.__setitem__("links", json.loads(json.dumps(v)))
m.log_event = lambda lvl, cat, t, d="": events.append((lvl, t))
m.api_edge_status = lambda a: {"ok": True, "ready": True, "health": [], "events": [], "now": 0}
m.get_settings = lambda: {"ech_refresh_mins": 15}
m._client_node = lambda L: NODE


def boom(*a, **k):
    raise OSError("down")


m.node_call = boom
m.api_rebuild_link = boom
m._fetch_ech_map = lambda hosts, px: {"a.example.com": "TkVX"}
m._ech_refresh_once()
chk(any(lvl == "bad" for lvl, _ in events), "a bad event is raised", events)
chk(not any(lvl == "ok" for lvl, _ in events), "and nothing green", events)

print()
if fails:
    print("FAILURES (%d):" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("a failed ECH push is reported honestly and recovered by a rebuild.")
