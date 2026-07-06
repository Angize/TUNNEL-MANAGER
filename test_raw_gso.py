#!/usr/bin/env python3
# Behavioral tests for the core "raw" transport (raw_profile) and the GSO
# throughput toggle in create/edit: validated, stored on the link record, and
# forwarded in the node "tunnel" payload. Run: python3 test_raw_gso.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlcentral", os.path.join(HERE, "tnl-central.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []
CALLS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


NODES = {"na": {"id": "na", "name": "NodeA"}, "nb": {"id": "nb", "name": "NodeB"}}
IPS = {"na": ["1.1.1.1"], "nb": ["2.2.2.2"]}
LINKS = []


def install():
    CALLS.clear()
    LINKS[:] = []

    def node_call(node, endpoint, method="POST", body=None, timeout=8):
        CALLS.append((endpoint, node["id"], body))
        if endpoint == "ping":
            return {"ok": True, "ips": {"eth0": IPS[node["id"]]}}
        if endpoint == "list":
            return {"configs": []}
        if endpoint == "portcheck":
            return {"ok": True, "busy": False, "who": ""}
        if endpoint == "tunnel":
            return {"ok": True, "tunnel_ip": "10.0.0.1/24"}
        return {"ok": True}

    tnl.node_call = node_call
    tnl.get_node = lambda nid: NODES.get(nid)
    tnl.load_links = lambda: list(LINKS)
    tnl.save_json = lambda path, data: LINKS.__setitem__(slice(None), data) if path == tnl.LINKS_FILE else None
    tnl._refresh_cache = lambda nids: None


def tunnel_bodies():
    return [b for (ep, nid, b) in CALLS if ep == "tunnel"]


BASE = {"a_node": "na", "b_node": "nb", "type": "core", "server_side": "a", "cipher": "auto"}

# ---- create: raw transport stores the profile and forwards it to both nodes ----
install()
r = tnl._create_tunnel_impl({**BASE, "transport": "raw", "raw_profile": "gre"})
check("core create with raw+profile succeeds", r.get("ok") is True)
rec = LINKS[0]
check("record stores transport=raw", rec.get("transport") == "raw")
check("record stores raw_profile", rec.get("raw_profile") == "gre")
tbs = tunnel_bodies()
check("both node payloads carry raw_profile", len(tbs) == 2 and all(b.get("raw_profile") == "gre" for b in tbs))

# ---- create: raw defaults the profile to bip -------------------------------
install()
tnl._create_tunnel_impl({**BASE, "transport": "raw"})
check("raw defaults profile to bip", LINKS[0].get("raw_profile") == "bip")

# ---- create: bad raw_profile is rejected -----------------------------------
install()
try:
    tnl._create_tunnel_impl({**BASE, "transport": "raw", "raw_profile": "wireguard"})
    check("bad raw_profile rejected", False)
except ValueError:
    check("bad raw_profile rejected", True)

# ---- create: raw with cipher=none is rejected (needs the AEAD) --------------
install()
try:
    tnl._create_tunnel_impl({**BASE, "transport": "raw", "raw_profile": "bip", "cipher": "none"})
    check("raw without crypto rejected", False)
except ValueError:
    check("raw without crypto rejected", True)

# ---- create: raw_profile ignored on udp/tcp (not stored) -------------------
install()
tnl._create_tunnel_impl({**BASE, "transport": "udp", "raw_profile": "gre"})
check("raw_profile ignored on udp", "raw_profile" not in LINKS[0])

# ---- create: gso stored + forwarded on any transport -----------------------
install()
tnl._create_tunnel_impl({**BASE, "transport": "tcp", "gso": True})
check("record stores gso", LINKS[0].get("gso") is True)
check("both node payloads carry gso", all(b.get("gso") is True for b in tunnel_bodies()))

install()
tnl._create_tunnel_impl({**BASE, "transport": "udp"})
check("gso off -> not stored", "gso" not in LINKS[0])

LINK = {"id": "L1", "name": "core50", "type": "core", "subnet": "192.168.50.0/24",
        "tunnel_id": 50, "a_node": "na", "a_name": "NodeA", "a_ip": "1.1.1.1",
        "b_node": "nb", "b_name": "NodeB", "b_ip": "2.2.2.2",
        "port": 443, "transport": "udp", "cipher": "auto", "server_side": "a", "psk": "x" * 64}

# ---- edit: switch to raw + choose a profile --------------------------------
install()
LINKS[:] = [dict(LINK)]
r = tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "raw",
                         "raw_profile": "icmp", "cipher": "auto"})
check("edit to raw succeeds", r.get("ok") is True)
check("edit persisted transport=raw", LINKS[0].get("transport") == "raw")
check("edit persisted raw_profile", LINKS[0].get("raw_profile") == "icmp")

# ---- edit: switching away from raw drops raw_profile -----------------------
install()
LINKS[:] = [dict(LINK, transport="raw", raw_profile="icmp")]
tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "udp", "cipher": "auto"})
check("edit off raw drops raw_profile", "raw_profile" not in LINKS[0])

# ---- edit: toggling gso on then off ----------------------------------------
install()
LINKS[:] = [dict(LINK)]
tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "udp", "cipher": "auto", "gso": True})
check("edit turned gso on", LINKS[0].get("gso") is True)
install()
LINKS[:] = [dict(LINK, gso=True)]
tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "udp", "cipher": "auto"})
check("edit turned gso off", "gso" not in LINKS[0])

# ---- edit: changing profile forces a rebuild (not a no-op) -----------------
install()
LINKS[:] = [dict(LINK, transport="raw", raw_profile="bip")]
r = tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "raw",
                         "raw_profile": "gre", "cipher": "auto"})
check("changing raw_profile rebuilds (not unchanged)", not r.get("unchanged"))

# ---- rebuild replays raw_profile + gso via _tunnel_extra -------------------
e = tnl._tunnel_extra({"transport": "raw", "raw_profile": "gre", "gso": True})
check("_tunnel_extra replays raw_profile", e.get("raw_profile") == "gre")
check("_tunnel_extra replays gso", e.get("gso") is True)
e2 = tnl._tunnel_extra({"transport": "udp"})
check("_tunnel_extra omits raw_profile/gso when absent", "raw_profile" not in e2 and "gso" not in e2)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all raw/gso tests passed")
