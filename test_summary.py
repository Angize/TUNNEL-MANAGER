#!/usr/bin/env python3
# Behavioral tests for the api_summary counter/alert fixes (no server, no root).
# Run: python3 test_summary.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlcentral", os.path.join(HERE, "tnl-central.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


# ---- controlled fleet -------------------------------------------------------
# Two nodes: A never probed (no cache), B probed and offline (has cache).
tnl.load_nodes = lambda: [{"id": "A", "name": "na"}, {"id": "B", "name": "nb"}]
tnl._cached_ping = lambda nid: {"ok": False}
tnl._cache_get = lambda nid: None if nid == "A" else {"ping": {"ok": False}}

# Three links: two core (both healthy), one gre (down).
tnl.load_links = lambda: [
    {"id": "e1", "type": "core", "name": "cor1", "a_node": "A", "b_node": "B", "subnet": "", "a_ip": "", "b_ip": ""},
    {"id": "e2", "type": "core", "name": "cor2", "a_node": "A", "b_node": "B", "subnet": "", "a_ip": "", "b_ip": ""},
    {"id": "g1", "type": "gre", "name": "gre1", "a_node": "A", "b_node": "B", "subnet": "", "a_ip": "", "b_ip": ""},
]
tnl._link_side_health = lambda L, side: (
    ({"up": True, "peer_ping": True}, None) if L["type"] == "core" else ({"up": False}, None)
)
tnl.link_drift = lambda i: False

res = tnl.api_summary({})

# #8: healthy count must never exceed the reported (non-core) link total.
check("links total excludes core (==1)", res["links"] == 1)
check("core counted separately (==2)", res["core"] == 2)
check("link_up counts only non-core links (==0)", res["link_up"] == 0)
check("link_down == 1 (the gre)", res["link_down"] == 1)
check("healthy <= total (no '2/1')", res["link_up"] <= res["links"])

# #10: an offline alert fires only for a node we actually probed (B), not for a
# node that simply hasn't been probed yet (A).
node_alerts = [a for a in res["alerts"] if a.get("kind") == "node"]
ids = {a.get("id") for a in node_alerts}
check("offline alert for probed node B", "B" in ids)
check("no offline alert for un-probed node A", "A" not in ids)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all summary tests passed")
