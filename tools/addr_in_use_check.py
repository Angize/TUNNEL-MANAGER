# -*- coding: utf-8 -*-
"""Guard: a subnet a node already holds on ANOTHER card is refused, on all three build paths.

Linux does not complain when two interfaces carry the same prefix -- `ip addr add` succeeds, the netdev
exists, and the node reports the build as successful. What you get instead is a SECOND route for that
prefix, and the kernel then sends the peer's address down whichever device it picked. The tunnel comes
up, the dashboard paints it green (the probe is bound to the tun device with SO_BINDTODEVICE, so IT
still gets through) and real traffic leaves by the other card. Nothing anywhere reports it.

The panel's other two nets miss it by construction: the id union only sees addresses that belong to a
TUNNEL, and _guard_subnet_overlap only compares against tunnels the panel itself knows about. An address
put on eth0 by hand is invisible to both.

So this drives create / edit / rebuild for real and asserts each one refuses -- and, just as important,
that the tunnel's OWN device does not trip it, or a rebuild could never succeed at all.

Exit 1 on any gap.
"""
import importlib.util
import os
import sys

sys.dont_write_bytecode = True
PANEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tnl-central.py")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import act_wait as A     # noqa: E402  (an action answers with a key, so A.raising waits for its verdict)

A_ID, B_ID = 1, 2
A_IP, B_IP = "203.0.113.5", "198.51.100.7"
NODES = [{"id": A_ID, "name": "IR01", "host": A_IP}, {"id": B_ID, "name": "DE01", "host": B_IP}]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_central_addr", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def wire(P, links, a_ifaces, b_ifaces):
    """`a_ifaces`/`b_ifaces` are the {iface: [ip]} maps the NODES report from their live interfaces."""
    sent = []
    P.load_links = lambda: [dict(x) for x in links]
    P.get_node = lambda nid: next((n for n in NODES if n["id"] == nid), None)
    P._ping_both = lambda A, B: ({"ips": a_ifaces}, {"ips": b_ifaces})
    # This guard is not about the readiness gate; give it a panel that already holds both artifacts
    # so _gate_ready runs for real and passes, instead of stubbing the gate itself away.
    P._readiness = lambda: {"agent": True, "core": True, "core_missing": [],
                            "core_version": "v0.0.0", "ok": True}
    P._refresh_cache = lambda nids: None
    P._push_staged = lambda n: {"ok": True}

    def node_call(node, op, method="GET", body=None, timeout=None, **kw):
        if op == "list":
            return {"configs": []}
        if op == "tunnel":
            sent.append((node["id"], dict(body or {})))
        return {"ok": True}
    P.node_call = node_call
    P._node_tunnel = lambda node, body: (sent.append((node["id"], dict(body))), {"ok": True, "tunnel_ip": "x"})[1]
    P.save_json = lambda path, obj: links.__setitem__(slice(None), [dict(x) for x in obj]) \
        if path == P.LINKS_FILE else None
    return sent


def link_rec(P, tid=1, name=None, subnet=None):
    name = name or P.tunnel_name("core", tid)
    return {"id": 7, "tunnel_id": tid, "name": name, "type": "core", "a_node": A_ID, "b_node": B_ID,
            "a_ip": A_IP, "b_ip": B_IP, "subnet": subnet or P.subnet_default("core", tid),
            "port": 20001, "server_side": "a", "cipher": "auto", "transport": "udp",
            "psk": "x" * 44, "enabled": True}


def main():
    P0 = load()
    TID = 42
    SUB = P0.subnet_default("core", TID)               # e.g. 192.168.42.0/24
    CLASH = SUB.split("/")[0].rsplit(".", 1)[0] + ".77"  # an address inside it, sitting on eth0

    print("== the operator has %s on eth0 by hand; the tunnel wants %s ==" % (CLASH, SUB))
    plain = {"eth0": [B_IP]}          # node B: nothing of ours on it
    dirty = {"eth0": [A_IP, CLASH]}

    for path in ("create", "edit", "rebuild"):
        P = load()
        links = [] if path == "create" else [link_rec(P, TID)]
        wire(P, links, dirty, plain)
        try:
            if path == "create":
                P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "core", "transport": "udp",
                                       "cipher": "auto", "server_side": "a", "id": TID})
            elif path == "edit":
                A.raising(P, lambda: P.api_edit_link({"id": 7, "type": "core", "transport": "udp",
                                                      "cipher": "auto", "server_side": "a",
                                                      "a_node": A_ID, "b_node": B_ID}))
            else:
                P._rebuild_link_impl({"id": 7})
            check(False, "%-7s ACCEPTED it -- the tunnel would come up green and carry nothing" % path)
        except ValueError as e:
            named = ("eth0" in str(e)) and (CLASH in str(e))
            check(named, "%-7s refused, and the message names the card and the address: %s"
                  % (path, str(e)[:60] + "..."))

    print("\n== ...and the tunnel's OWN device must NOT trip it, or nothing could ever be rebuilt ==")
    name = P0.tunnel_name("core", TID)
    own = {"eth0": [A_IP], name: [SUB.split("/")[0].rsplit(".", 1)[0] + ".1"]}
    for path in ("edit", "rebuild"):
        P = load()
        links = [link_rec(P, TID)]
        wire(P, links, own, plain)
        try:
            if path == "edit":
                A.raising(P, lambda: P.api_edit_link({"id": 7, "type": "core", "transport": "udp",
                                                      "cipher": "auto", "server_side": "a",
                                                      "a_node": A_ID, "b_node": B_ID}))
            else:
                P._rebuild_link_impl({"id": 7})
            check(True, "%-7s went through with the address on its own device" % path)
        except ValueError as e:
            check(False, "%-7s refused its OWN address on its OWN device: %s" % (path, e))

    print("\n== an unrelated address on eth0 is none of our business ==")
    P = load()
    wire(P, [], {"eth0": [A_IP, "10.9.9.9"]}, plain)
    try:
        P._create_tunnel_impl({"a_node": A_ID, "b_node": B_ID, "type": "core", "transport": "udp",
                               "cipher": "auto", "server_side": "a", "id": TID})
        check(True, "an address outside the subnet does not block the build")
    except ValueError as e:
        check(False, "refused over an unrelated address: %s" % e)

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("an address already on another card is refused on all three paths, and only then")
    return 0


if __name__ == "__main__":
    sys.exit(main())
