#!/usr/bin/env python3
# Behavioral tests for the core "TLS cover" (HTTPS camouflage) option in
# create/edit: cover(bool) + cover_sni(str) validated, stored on the link
# record next to obfs/cipher, and forwarded in the node "tunnel" payload.
# TCP-only; ignored on UDP. Run: python3 test_tlscover.py
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

# ---- create: cover + tcp stored on the record and forwarded to both nodes ----
install()
r = tnl._create_tunnel_impl({**BASE, "transport": "tcp", "cover": True, "cover_sni": "www.microsoft.com"})
check("core create with cover+tcp succeeds", r.get("ok") is True)
rec = LINKS[0]
check("record stores cover=True", rec.get("cover") is True)
check("record stores cover_sni", rec.get("cover_sni") == "www.microsoft.com")
tbs = tunnel_bodies()
check("both node payloads carry cover", len(tbs) == 2 and all(b.get("cover") is True for b in tbs))
check("both node payloads carry cover_sni", all(b.get("cover_sni") == "www.microsoft.com" for b in tbs))

# ---- create: cover_sni is trimmed -------------------------------------------
install()
tnl._create_tunnel_impl({**BASE, "transport": "tcp", "cover": True, "cover_sni": "  example.org  "})
check("cover_sni is trimmed", LINKS[0].get("cover_sni") == "example.org")

# ---- create: cover on UDP is ignored (TCP-only), not stored ------------------
install()
tnl._create_tunnel_impl({**BASE, "transport": "udp", "cover": True, "cover_sni": "www.microsoft.com"})
check("cover ignored on udp (not stored)", "cover" not in LINKS[0])
check("cover_sni ignored on udp (not stored)", "cover_sni" not in LINKS[0])

# ---- create: cover off -> nothing stored -------------------------------------
install()
tnl._create_tunnel_impl({**BASE, "transport": "tcp", "cover": False})
check("cover off -> no cover key", "cover" not in LINKS[0] and "cover_sni" not in LINKS[0])

# ---- create: cover on but no SNI -> REJECTED (SNI is required, no default) ----
install()
try:
    tnl._create_tunnel_impl({**BASE, "transport": "tcp", "cover": True})
    check("cover on without sni is rejected", False)
except ValueError:
    check("cover on without sni is rejected", True)
check("cover-without-sni stored nothing", not LINKS or "cover" not in LINKS[0])

# ---- create: bad SNI is rejected ---------------------------------------------
for bad in ["bad sni!", "under_score.com", "a" * 254, "http://x.com"]:
    install()
    try:
        tnl._create_tunnel_impl({**BASE, "transport": "tcp", "cover": True, "cover_sni": bad})
        check("bad SNI rejected: %r" % bad, False)
    except ValueError:
        check("bad SNI rejected: %r" % bad, True)

# ---- edit: turn cover ON on an existing tcp core link ----------------------
LINK = {"id": "L1", "name": "core50", "type": "core", "subnet": "192.168.50.0/24",
        "tunnel_id": 50, "a_node": "na", "a_name": "NodeA", "a_ip": "1.1.1.1",
        "b_node": "nb", "b_name": "NodeB", "b_ip": "2.2.2.2",
        "port": 443, "transport": "tcp", "cipher": "auto", "server_side": "a", "psk": "x" * 64}

install()
LINKS[:] = [dict(LINK)]
r = tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "tcp",
                         "port": 443, "cipher": "auto", "cover": True, "cover_sni": "www.apple.com"})
check("edit turning cover on succeeds", r.get("ok") is True)
check("edit persisted cover=True", LINKS[0].get("cover") is True)
check("edit persisted cover_sni", LINKS[0].get("cover_sni") == "www.apple.com")
check("edit forwarded cover to nodes", all(b.get("cover") is True for b in tunnel_bodies()))

# ---- edit: turn cover OFF drops both keys from the record --------------------
install()
LINKS[:] = [dict(LINK, cover=True, cover_sni="www.apple.com")]
r = tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "tcp",
                         "port": 443, "cipher": "auto", "cover": False})
check("edit turning cover off succeeds", r.get("ok") is True)
check("edit dropped cover key", "cover" not in LINKS[0])
check("edit dropped cover_sni key", "cover_sni" not in LINKS[0])

# ---- edit: switching transport to udp ignores cover --------------------------
install()
LINKS[:] = [dict(LINK, cover=True, cover_sni="www.apple.com")]
tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "udp",
                     "port": 443, "cipher": "auto", "cover": True, "cover_sni": "www.apple.com"})
check("edit to udp drops cover", "cover" not in LINKS[0] and "cover_sni" not in LINKS[0])

# ---- edit: no-op when cover/sni unchanged (rebuild not forced) ---------------
install()
LINKS[:] = [dict(LINK, cover=True, cover_sni="www.apple.com")]
r = tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "tcp",
                         "port": 443, "cipher": "auto", "cover": True, "cover_sni": "www.apple.com"})
check("unchanged cover+sni -> no rebuild", r.get("unchanged") is True)

# ---- edit: bad SNI rejected --------------------------------------------------
install()
LINKS[:] = [dict(LINK)]
try:
    tnl._edit_link_impl({"id": "L1", "type": "core", "server_side": "a", "transport": "tcp",
                         "port": 443, "cipher": "auto", "cover": True, "cover_sni": "bad sni!"})
    check("edit bad SNI rejected", False)
except ValueError:
    check("edit bad SNI rejected", True)

# ---- rebuild replays cover/cover_sni via _tunnel_extra -----------------------
e = tnl._tunnel_extra({"cover": True, "cover_sni": "www.microsoft.com"})
check("_tunnel_extra replays cover", e.get("cover") is True and e.get("cover_sni") == "www.microsoft.com")
e2 = tnl._tunnel_extra({"transport": "tcp"})
check("_tunnel_extra omits cover when absent", "cover" not in e2 and "cover_sni" not in e2)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all TLS-cover tests passed")
