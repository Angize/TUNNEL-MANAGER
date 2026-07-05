#!/usr/bin/env python3
# Behavioral tests for the port-conflict guard in create/edit (no server/root).
# Run: python3 test_portguard.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlcentral", os.path.join(HERE, "tnl-central.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []
CALLS = []  # (endpoint, node_id, body)


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


NODES = {"na": {"id": "na", "name": "NodeA"}, "nb": {"id": "nb", "name": "NodeB"}}
IPS = {"na": ["1.1.1.1"], "nb": ["2.2.2.2"]}
LINKS = []


def install(busy=frozenset(), who="", old_agent=False):
    CALLS.clear()
    LINKS[:] = []  # each scenario starts from an empty registry unless it sets LINKS afterwards

    def node_call(node, endpoint, method="POST", body=None, timeout=8):
        CALLS.append((endpoint, node["id"], body))
        if endpoint == "ping":
            return {"ok": True, "ips": {"eth0": IPS[node["id"]]}}
        if endpoint == "list":
            return {"configs": []}
        if endpoint == "portcheck":
            if old_agent:
                return {"error": "unknown endpoint"}
            key = (node["id"], int(body["port"]), body["proto"])
            return {"ok": True, "busy": key in busy, "who": who}
        if endpoint == "tunnel":
            return {"ok": True, "tunnel_ip": "10.0.0.1/24"}
        return {"ok": True}

    tnl.node_call = node_call
    tnl.get_node = lambda nid: NODES.get(nid)
    tnl.load_links = lambda: list(LINKS)
    tnl.save_json = lambda path, data: LINKS.__setitem__(slice(None), data) if path == tnl.LINKS_FILE else None
    tnl._refresh_cache = lambda nids: None


def portchecks():
    return [(nid, b["port"], b["proto"]) for (ep, nid, b) in CALLS if ep == "portcheck"]


# ---- _port_bindings scope ----------------------------------------------------
A, B = NODES["na"], NODES["nb"]
b = tnl._port_bindings("engine", 443, "tcp", "a", 50, A, B)
check("engine checks only the server node (a), proto=tcp", b == [(A, 443, "tcp")])
b = tnl._port_bindings("engine", 443, "tcp", "b", 50, A, B)
check("engine server_side=b -> node B", b == [(B, 443, "tcp")])
b = tnl._port_bindings("engine", None, None, "a", 50, A, B)
check("engine default port = 20000+id, proto defaults udp", b == [(A, 20050, "udp")])
b = tnl._port_bindings("vxlan", 4789, None, None, 50, A, B)
check("vxlan checks BOTH nodes on udp", b == [(A, 4789, "udp"), (B, 4789, "udp")])
b = tnl._port_bindings("gre", None, None, None, 50, A, B)
check("gre has no port binding to check", b == [])

# ---- create: busy on the server node blocks ----------------------------------
install(busy={("na", 443, "tcp")}, who="xray")
try:
    tnl._create_tunnel_impl({"a_node": "na", "b_node": "nb", "type": "engine",
                             "server_side": "a", "transport": "tcp", "port": 443, "cipher": "auto"})
    check("engine create with busy server port -> blocked", False)
except ValueError as e:
    msg = str(e)
    check("engine create with busy server port -> blocked", "443/TCP" in msg and "NodeA" in msg and "xray" in msg)

# ---- create: client-side busy is IGNORED (client never binds) ----------------
install(busy={("nb", 443, "tcp")})  # B is the client here (server_side=a)
r = tnl._create_tunnel_impl({"a_node": "na", "b_node": "nb", "type": "engine",
                             "server_side": "a", "transport": "tcp", "port": 443, "cipher": "auto"})
check("engine create ignores busy client port", r.get("ok") is True)
check("only the server node was port-checked", portchecks() == [("na", 443, "tcp")])

# ---- create: vxlan busy on either node blocks --------------------------------
install(busy={("nb", 4789, "udp")})
try:
    tnl._create_tunnel_impl({"a_node": "na", "b_node": "nb", "type": "vxlan", "port": 4789})
    check("vxlan create blocked when port busy on node B", False)
except ValueError as e:
    check("vxlan create blocked when port busy on node B", "4789/UDP" in str(e) and "NodeB" in str(e))

# ---- create: default auto port is free -> succeeds ---------------------------
install(busy=set())
r = tnl._create_tunnel_impl({"a_node": "na", "b_node": "nb", "type": "engine",
                             "server_side": "a", "transport": "udp", "cipher": "auto"})
check("engine create on free default port succeeds", r.get("ok") is True)

# ---- create: old agent (no portcheck) is not hard-blocked --------------------
install(busy={("na", 443, "tcp")}, old_agent=True)
r = tnl._create_tunnel_impl({"a_node": "na", "b_node": "nb", "type": "engine",
                             "server_side": "a", "transport": "tcp", "port": 443, "cipher": "auto"})
check("old agent without portcheck is not blocked", r.get("ok") is True)

# ---- edit: unchanged port is not re-checked (no self-conflict) ---------------
LINK = {"id": "L1", "name": "engine50", "type": "engine", "subnet": "192.168.50.0/24",
        "tunnel_id": 50, "a_node": "na", "a_name": "NodeA", "a_ip": "1.1.1.1",
        "b_node": "nb", "b_name": "NodeB", "b_ip": "2.2.2.2",
        "port": 443, "transport": "tcp", "cipher": "auto", "server_side": "a", "psk": "x" * 64}
install(busy={("na", 443, "tcp")})  # its OWN port shows busy (it is listening) -> must be excluded
LINKS[:] = [LINK]
r = tnl._edit_link_impl({"id": "L1", "type": "engine", "server_side": "a",
                         "transport": "tcp", "port": 443, "cipher": "aes-256-gcm"})  # only cipher changes
check("edit with unchanged port is not blocked by its own listener", r.get("ok") is True)
check("unchanged port/proto/server was NOT port-checked", portchecks() == [])

# ---- edit: changing the port to a busy one is blocked ------------------------
install(busy={("na", 8443, "tcp")})
LINKS[:] = [LINK]
try:
    tnl._edit_link_impl({"id": "L1", "type": "engine", "server_side": "a",
                         "transport": "tcp", "port": 8443, "cipher": "auto"})
    check("edit to a busy port is blocked", False)
except ValueError as e:
    check("edit to a busy port is blocked", "8443/TCP" in str(e))

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all port-guard tests passed")
