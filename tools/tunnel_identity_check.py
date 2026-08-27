# -*- coding: utf-8 -*-
"""Guard: a tunnel's identity comes from its id, and every build path says the same thing.

Three facts have to hold together, and the panel is the only place that can hold them:

  * the id is unique across the WHOLE fleet, 1..255. It was scoped to the two nodes of the pair, so
    every pair restarted at the same number -- three unrelated links were all called core42, and since
    the id is also the overlay subnet, all three sat on 192.168.42.0/24.
  * the name is `core<id>` or `native<id>`, from the id alone.
  * the overlay host is the ROLE: server .1, client .2. The nodes used to derive it themselves by
    comparing their public IPs, so which end was .1 depended on which provider handed out the bigger
    address.

The panel has FOUR paths that build a node body -- create, edit, rebuild and the restore/rollback -- and
this drives all four for real, capturing what each would send. Checking `overlay_host` on its own would
prove nothing about the path that forgets to call it, which is the failure this exists to prevent.

Exit 1 on any disagreement.
"""
import importlib.util
import ipaddress
import json
import os
import sys
import tempfile

sys.dont_write_bytecode = True
PANEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tnl-central.py")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import act_wait as A     # noqa: E402  (an action answers with a key, so A.run waits for its verdict)

A_ID, B_ID = 1, 2
A_IP, B_IP = "203.0.113.5", "198.51.100.7"
NODES = [{"id": A_ID, "name": "IR01", "host": A_IP}, {"id": B_ID, "name": "DE01", "host": B_IP}]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_central_identity", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def wire(P, links, node_ids=()):
    """Stub every side effect and record the bodies. `links` is the panel's link registry; `node_ids`
    are tunnel ids a NODE already carries that the panel does not know about."""
    sent = []
    P.load_links = lambda: [dict(x) for x in links]
    P.get_node = lambda nid: next((n for n in NODES if n["id"] == nid), None)
    # The node reports {iface: [ip]}, not a flat list -- this stub said "list" for a long time and the
    # real _flat_ips was stubbed out beside it, so nothing noticed. Keep the REAL shape and let the real
    # _flat_ips run on it, or a guard here proves nothing about the panel's own reading of a ping.
    P._ping_both = lambda A, B: ({"ips": {"eth0": [A_IP]}}, {"ips": {"eth0": [B_IP]}})
    # This guard is not about the readiness gate; give it a panel that already holds both artifacts
    # so _gate_ready runs for real and passes, instead of stubbing the gate itself away.
    P._readiness = lambda: {"agent": True, "core": True, "core_missing": [],
                            "core_version": "v0.0.0", "ok": True}
    P._refresh_cache = lambda nids: None
    P._push_staged = lambda n: {"ok": True}

    def node_call(node, op, method="GET", body=None, timeout=None, **kw):
        if op == "list":
            return {"configs": [{"id": i} for i in node_ids]}
        if op == "tunnel":   # the restore path posts here directly rather than through _node_tunnel
            sent.append((node["id"], dict(body or {})))
        return {"ok": True}
    P.node_call = node_call

    def node_tunnel(node, body):
        sent.append((node["id"], dict(body)))
        return {"ok": True, "tunnel_ip": "10.0.0.1/24"}
    P._node_tunnel = node_tunnel

    def save_json(path, obj):
        if path == P.LINKS_FILE:
            links[:] = [dict(x) for x in obj]
    P.save_json = save_json
    return sent


def core_link(tid, server_side="b", ttype="core"):
    return {"id": tid, "tunnel_id": tid, "name": P0.tunnel_name(ttype, tid), "type": ttype,
            "a_node": A_ID, "b_node": B_ID, "a_ip": A_IP, "b_ip": B_IP,
            "subnet": P0.subnet_default(ttype, tid), "port": 20000 + tid, "server_side": server_side,
            "cipher": "auto", "transport": "udp", "psk": "x" * 44, "enabled": True}


P0 = load()


def main():
    print("== 1) the id space is the fleet's, not the pair's ==")
    P = load()
    # Two links between OTHER nodes already hold 1 and 2. A third link on a fresh pair must not reuse them.
    links = [dict(core_link(1), a_node=3, b_node=4), dict(core_link(2), a_node=5, b_node=6)]
    sent = wire(P, links)
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "core", "transport": "udp",
                           "cipher": "auto", "server_side": "b"})
    got = sent[0][1]["id"]
    check(got == 3, "a new link on an untouched pair got id %s -- the two links on other pairs hold 1 and 2, "
                    "and reusing one would put two tunnels on one subnet and one name" % got)

    print("\n== 2) the id starts at 1 and the ceiling is the ADDRESS SPACE, not an octet ==")
    P = load()
    links = []
    sent = wire(P, links)
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre"})
    check(sent[0][1]["id"] == 1, "an empty fleet allocates id 1, got %s" % sent[0][1]["id"])
    # Each tunnel owns a /30, so the default base holds 2^(30-prefix) of them. Deriving the bound from
    # the base rather than writing a number down is what keeps the two from drifting apart.
    check(P.TID_MIN == 1, "ids start at 1")
    check(P.subnet_cap(P.SUBNET_BASE_DEFAULT) == 255,
          "the default range (%s) holds 255 tunnels, got %s"
          % (P.SUBNET_BASE_DEFAULT, P.subnet_cap(P.SUBNET_BASE_DEFAULT)))
    check(P.subnet_cap("172.16") == 4095 and P.subnet_cap("10") == 65535,
          "a wider range holds more: 172.16 -> %s, 10 -> %s" % (P.subnet_cap("172.16"), P.subnet_cap("10")))
    check(P.TID_MAX == 65535, "the widest base (10/8) addresses 65535 tunnels, got %s" % P.TID_MAX)

    P = load(); links = []; sent = wire(P, links)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre",
                               "id": P.subnet_cap(P.SUBNET_BASE_DEFAULT) + 1})
        check(False, "an explicit id past the ceiling was ACCEPTED -- it would wrap onto another tunnel")
    except ValueError:
        check(True, "an explicit id past the ceiling is refused")

    # Exhaustion, driven for real: shrink the space instead of building four million links.
    P = load(); P.subnet_cap = lambda base=None: 3
    links = [core_link(i) for i in (1, 2, 3)]
    sent = wire(P, links)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre"})
        check(False, "a full fleet must refuse rather than allocate id 0")
    except ValueError:
        check(True, "a full fleet refuses with a reason instead of allocating out of range")

    # The allocator fills HOLES, so a deleted tunnel's id comes back rather than the space marching up.
    P = load()
    links = [core_link(i) for i in (1, 2, 4, 5)]
    sent = wire(P, links)
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre"})
    check(sent[0][1]["id"] == 3, "the lowest free id is reused (want 3, got %s)" % sent[0][1]["id"])

    # A range that is FULL must refuse, even though a wider range still has room: the id IS the /24
    # inside the chosen base, so handing out 256 here would be an address 192.168 cannot express.
    P = load()
    links = [core_link(i) for i in range(1, 256)]
    sent = wire(P, links)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre", "subnet_base": "192.168"})
        check(False, "192.168 was full (1..255 taken) and still allocated id %s"
              % (sent[0][1]["id"] if sent else "?"))
    except ValueError:
        check(True, "a full 192.168 refuses instead of allocating an id it cannot address")
    # ...and the SAME fleet on a wider range keeps going.
    P = load(); links2 = [core_link(i) for i in range(1, 256)]; sent = wire(P, links2)
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre", "subnet_base": "10"})
    check(sent[0][1]["id"] == 256, "10.x carries on past 255 (got id %s)" % sent[0][1]["id"])

    print("\n== 2b) each id owns a /24, the ends are always .1/.2, and no two ids overlap ==")
    P = load()
    seen = {}
    for tid in (1, 2, 3, 255, 256, 1000, P.TID_MAX):   # across the widest base
        net = ipaddress.ip_network(P.subnet_default("core", tid, "10"), strict=False)
        check(net.prefixlen == 24, "id=%s -> %s is a /24" % (tid, net))
        check(str(net.network_address + 1).endswith(".1") and str(net.network_address + 2).endswith(".2"),
              "id=%s -> the server is %s and the client %s -- the last octet must ALWAYS be 1 and 2"
              % (tid, net.network_address + 1, net.network_address + 2))
        for h in (1, 2):
            a = str(net.network_address + h)
            check(a not in seen, "address %s belongs to id %s alone (id %s wanted it too)"
                  % (a, seen.get(a, tid), tid))
            seen[a] = tid
    try:
        P.subnet_default("core", 256, "192.168")
        check(False, "192.168 accepted id 256, which does not fit its 255 /24 blocks")
    except ValueError:
        check(True, "a base too small for the id is refused by name")

    print("\n== 2b2) a re-derive picks a base that FITS, instead of dead-ending on the default ==")
    # A tunnel whose stored subnet is the wrong IP version for its new type gets re-derived with NO base
    # asked for. Falling back to the default range dead-ended every id above its 255: the type could not
    # be changed at all, and the message named a range the operator never picked.
    P = load()
    for tid in (1, 42, 255):        # everything that fits the default must be UNCHANGED
        want = "192.168.%d.0/24" % tid
        got = P.subnet_default("core", tid)
        check(got == want, "id=%s still derives %s (got %s)" % (tid, want, got))
    for tid in (256, 4095, 4096, 65535):
        try:
            net = ipaddress.ip_network(P.subnet_default("core", tid), strict=False)
            check(True, "id=%s derives %s instead of refusing" % (tid, net))
        except ValueError as e:
            check(False, "id=%s DEAD-ENDS on a re-derive: %s" % (tid, e))
    # ...but a base the operator DID pick and that cannot hold the id still refuses, loudly.
    try:
        P.subnet_default("core", 256, "192.168")
        check(False, "an explicit 192.168 accepted id 256")
    except ValueError:
        check(True, "an EXPLICIT base too small still refuses")
    # the real path: a sit tunnel at a high id, edited to core
    got = P.norm_subnet("core", 5000, P.subnet_default("sit", 5000))
    check(got.endswith("/24") and ":" not in got,
          "a sit tunnel at id 5000 can be changed to core (got %s)" % got)

    print("\n== 2c) the PORT is allocated, not derived from the id ==")
    # 20000+id put a second ceiling on the id at 45535 and coupled two things that never needed it: a
    # port only has to be unique on the IP that BINDS it. An id past that point must still get a usable
    # port rather than one out of range.
    P = load()
    links = []
    sent = wire(P, links)
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "core", "transport": "udp",
                           "cipher": "auto", "server_side": "a", "id": 60000, "subnet_base": "10"})
    port = sent[0][1].get("port")
    check(isinstance(port, int) and 1 <= port <= 65535,
          "id=60000 got port %s -- 20000+id would be 80000, which is not a port" % port)
    check(port != 80000, "the port is not 20000+id")
    stored = [dict(x) for x in links]
    P = load(); links2 = list(stored); sent = wire(P, links2)
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "core", "transport": "udp",
                           "cipher": "auto", "server_side": "a", "subnet_base": "10"})
    p2 = sent[0][1].get("port")
    check(p2 != port, "a second link on the same pair got a different default port (%s vs %s)" % (p2, port))

    print("\n== 3) an id a NODE already carries is not handed out either ==")
    P = load()
    links = []
    sent = wire(P, links, node_ids=[1, 2, 3])
    P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre"})
    check(sent[0][1]["id"] == 4, "skipped 1-3 already on the node, got %s" % sent[0][1]["id"])

    print("\n== 4) the name is the id, and every kernel type shares one spelling ==")
    P = load()
    for tt in P.TYPES:
        links = []
        sent = wire(P, links)
        req = {"a_node": A_ID, "b_node": B_ID, "type": tt}
        if tt == "core":
            req.update(transport="udp", cipher="auto", server_side="b")
        P._create_tunnel_impl(req)
        want = "core1" if tt == "core" else "native1"
        check(sent[0][1]["name"] == want, "%-7s -> %s" % (tt, sent[0][1]["name"]))
        check(sent[0][1]["name"] == sent[1][1]["name"], "%-7s both ends agree on the name" % tt)

    print("\n== 5) ALL FOUR build paths stamp the same host, and the SERVER is always .1 ==")
    for ss in ("a", "b"):
        bodies = {}
        # -- create
        P = load(); links = []; sent = wire(P, links)
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "core", "transport": "udp",
                               "cipher": "auto", "server_side": ss})
        bodies["create"] = {nid: b for nid, b in sent}
        stored = [dict(x) for x in links] or [core_link(1, ss)]
        L = stored[0]
        # -- edit (a partial edit that changes nothing but must still rebuild both ends)
        P = load(); links2 = [dict(L)]; sent = wire(P, links2)
        A.run(P, lambda: P.api_edit_link({"id": L["id"], "type": "core", "transport": "udp",
                                          "cipher": "auto", "server_side": ss,
                                          "a_node": A_ID, "b_node": B_ID}))
        bodies["edit"] = {nid: b for nid, b in sent}
        # -- rebuild
        P = load(); links3 = [dict(L)]; sent = wire(P, links3)
        P._rebuild_link_impl({"id": L["id"]})
        bodies["rebuild"] = {nid: b for nid, b in sent}
        # -- restore / rollback
        P = load(); links4 = [dict(L)]; sent = wire(P, links4)
        P._restore_link(P.get_node(A_ID), P.get_node(B_ID), dict(L))
        bodies["restore"] = {nid: b for nid, b in sent}

        for path, byn in bodies.items():
            ha, hb = byn.get(A_ID, {}).get("host"), byn.get(B_ID, {}).get("host")
            check({ha, hb} == {1, 2}, "server_side=%s %-8s: A->.%s B->.%s (one .1 and one .2)" % (ss, path, ha, hb))
            srv = ha if ss == "a" else hb
            check(srv == 1, "server_side=%s %-8s: the SERVER end is .%s -- it must be .1" % (ss, path, srv))
        hosts = {p: (b.get(A_ID, {}).get("host"), b.get(B_ID, {}).get("host")) for p, b in bodies.items()}
        check(len(set(hosts.values())) == 1,
              "server_side=%s: create/edit/rebuild/restore all agree: %s" % (ss, hosts))

    print("\n== 6) two tunnels that meet on one node may not share an overlay subnet ==")
    # unique ids make the DEFAULTS unique; the custom subnet the operator can type is the open door.
    C_ID = 3
    P = load()
    links = [dict(core_link(9), a_node=A_ID, b_node=C_ID, subnet="192.168.9.0/24")]
    NODES.append({"id": C_ID, "name": "DE02", "host": "192.0.2.9"})
    sent = wire(P, links)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre", "subnet": "192.168.9.0/24"})
        check(False, "a custom subnet overlapping a tunnel on the SAME node was accepted -- both ends "
                     "then ip-addr-add out of one range and the kernel routes down whichever device it picked")
    except ValueError:
        check(True, "an overlapping custom subnet on a shared node is refused")
    # a narrower range inside the other one is the same collision
    P = load(); links = [dict(core_link(9), a_node=A_ID, b_node=C_ID, subnet="192.168.9.0/24")]
    sent = wire(P, links)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre", "subnet": "192.168.9.128/25"})
        check(False, "a subnet CONTAINED in another tunnel's was accepted")
    except ValueError:
        check(True, "a contained subnet is refused too, not just an exact match")
    # ...but two tunnels that share NO node may reuse a range: the addresses are on different machines
    P = load()
    links = [dict(core_link(9), a_node=5, b_node=6, subnet="192.168.9.0/24")]
    sent = wire(P, links)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre", "subnet": "192.168.9.0/24"})
        check(True, "the same range on a pair sharing no node is allowed")
    except ValueError as e:
        check(False, "refused a legal reuse on an unrelated pair: %s" % e)
    NODES.pop()

    print("\n== 7) a kernel tunnel has no server, so side A takes .1 on every path ==")
    L = core_link(1, "a", "gre")
    for path, run in (
        ("create", lambda P, links: P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "gre"})),
        # a non-core edit that changes NOTHING short-circuits as "unchanged" and builds no body at all,
        # so this one moves the subnet -- otherwise the case proves nothing about the edit path.
        ("edit", lambda P, links: A.run(P, lambda: P.api_edit_link({"id": 1, "type": "gre", "a_node": A_ID,
                                                                    "b_node": B_ID, "subnet": "10.9.0.0/24"}))),
        ("rebuild", lambda P, links: P._rebuild_link_impl({"id": 1})),
        ("restore", lambda P, links: P._restore_link(P.get_node(A_ID), P.get_node(B_ID), dict(L))),
    ):
        P = load()
        links = [] if path == "create" else [dict(L)]
        sent = wire(P, links)
        run(P, links)
        byn = {nid: b for nid, b in sent}
        check(byn.get(A_ID, {}).get("host") == 1 and byn.get(B_ID, {}).get("host") == 2,
              "gre %-8s: A->.%s B->.%s" % (path, byn.get(A_ID, {}).get("host"), byn.get(B_ID, {}).get("host")))

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the id is unique fleet-wide, the name follows it, and all four paths agree on server=.1 / client=.2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
