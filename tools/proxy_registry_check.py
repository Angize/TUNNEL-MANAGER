#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The proxy registry endpoints, driven for real against temp files.

The registry stores FIELDS ({scheme, host, port, user, pass}) and `proxy_url()` is the one place they
become a dial string. That split is what this pins, along with the three rules that are easy to break
silently:

  * the PASSWORD never appears in anything the browser is handed -- only `has_pass`. A row that carried
    it would put the credential in plain HTTP on every page refresh.
  * a BLANK password on edit keeps the stored one (the browser was never given it, so submitting the
    form it was shown must not wipe it) -- but clearing the USER clears it, because no user means no auth.
  * a node with a stored proxy_id but the toggle OFF is NOT a user of that proxy: counting it would
    refuse a delete that is safe and name a node that is really going out direct.

    python3 tools/proxy_registry_check.py
"""
import argparse
import importlib.util
import io
import json
import os
import sys
import tempfile
from pathlib import Path

NODES = [
    {"id": "n1", "name": "IR01", "host": "1.1.1.1", "port": 8099, "token": "t"},
    {"id": "n2", "name": "DE01", "host": "2.2.2.2", "port": 8099, "token": "t",
     "proxy_on": True, "proxy_id": "PX_A"},
    {"id": "n3", "name": "INTERCOLO", "host": "3.3.3.3", "port": 8099, "token": "t",
     "proxy_on": True, "proxy_id": "PX_A"},
    {"id": "n4", "name": "OFFNODE", "host": "4.4.4.4", "port": 8099, "token": "t",
     "proxy_on": False, "proxy_id": "PX_B"},
]
A = {"name": "hetzner", "scheme": "socks5", "host": "10.9.9.9", "port": "1080",
     "user": "pu", "pass": "SECRETpw"}
B = {"name": "cf", "scheme": "http", "host": "10.9.9.8", "port": 3128}


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    spec = importlib.util.spec_from_file_location("tnl_central", str(a.panel))
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    d = tempfile.mkdtemp(prefix="tnl_px_")
    P.PROXIES_FILE = os.path.join(d, "proxies.json")
    P.NODES_FILE = os.path.join(d, "nodes.json")
    P.log_event = lambda *args, **kw: None
    nodes = [dict(n) for n in NODES]
    json.dump(nodes, io.open(P.NODES_FILE, "w"))

    failures = []

    def chk(label, got, want):
        if got != want:
            failures.append("%s: got %r, expected %r" % (label, got, want))
        else:
            print("  ok   %-52s %r" % (label, got))

    pa = P.api_proxy_add(dict(A))["proxy"]
    pb = P.api_proxy_add(dict(B))["proxy"]

    chk("the row names the address without credentials", pa["addr"], "socks5://10.9.9.9:1080")
    chk("the row says a password is set, never which", pa.get("has_pass"), True)
    chk("a proxy with no user has no password", pb.get("has_pass"), False)
    chk("the password is in NO field of the row",
        [k for k, v in pa.items() if isinstance(v, str) and "SECRET" in v], [])
    chk("proxy_url composes the auth", P.proxy_url(P.get_proxy(pa["id"])),
        "socks5://pu:SECRETpw@10.9.9.9:1080")
    chk("proxy_url omits auth when there is no user", P.proxy_url(P.get_proxy(pb["id"])),
        "http://10.9.9.8:3128")
    chk("a fresh proxy has no users", pa["nodes"], [])

    for label, bad in (("a duplicate name, any case", dict(A, name="HETZNER")),
                       ("an unknown scheme", dict(A, name="x1", scheme="ftp")),
                       ("a port out of range", dict(A, name="x2", port="70000")),
                       ("a non-numeric port", dict(A, name="x3", port="abc")),
                       ("an empty host", dict(A, name="x4", host="")),
                       ("a user containing @", dict(A, name="x5", user="a@b")),
                       ("a password containing a colon", dict(A, name="x6", **{"pass": "a:b"})),
                       ("a password containing a space", dict(A, name="x7", **{"pass": "a b"}))):
        try:
            P.api_proxy_add(bad)
            failures.append("%s was accepted — it would compose into a URL that dials somewhere else"
                            % label)
        except ValueError:
            print("  ok   %-52s refused" % label)

    for n in nodes:
        if n.get("proxy_id") == "PX_A":
            n["proxy_id"] = pa["id"]
        elif n.get("proxy_id") == "PX_B":
            n["proxy_id"] = pb["id"]
    json.dump(nodes, io.open(P.NODES_FILE, "w"))

    rows = {r["name"]: r for r in P.api_proxies({})["proxies"]}
    chk("the in-use proxy names its nodes", sorted(rows["hetzner"]["nodes"]), ["DE01", "INTERCOLO"])
    chk("a stored id with the toggle OFF is not a user", rows["cf"]["nodes"], [])
    chk("no listed row carries the password",
        [r["name"] for r in P.api_proxies({})["proxies"]
         if "SECRET" in json.dumps(r, ensure_ascii=False)], [])

    try:
        P.api_proxy_del({"id": pa["id"]})
        failures.append("an in-use proxy was deleted — those nodes would drop to a DIRECT connection "
                        "with nothing said")
    except ValueError as e:
        chk("deleting an in-use proxy is refused, and names the nodes",
            "DE01" in str(e) and "INTERCOLO" in str(e), True)

    # edit: blank password keeps the stored one; the rest of the fields still move
    P.api_proxy_edit({"id": pa["id"], "name": "hetzner-2", "scheme": "http", "host": "10.9.9.7",
                      "port": "8080", "user": "pu", "pass": ""})
    kept = P.get_proxy(pa["id"])
    chk("a blank password on edit keeps the stored one", kept["pass"], "SECRETpw")
    chk("the other fields did move", "%s://%s:%d" % (kept["scheme"], kept["host"], kept["port"]),
        "http://10.9.9.7:8080")
    chk("the edit renamed it", kept["name"], "hetzner-2")

    P.api_proxy_edit({"id": pa["id"], "name": "hetzner-2", "scheme": "http", "host": "10.9.9.7",
                      "port": "8080", "user": "", "pass": ""})
    chk("clearing the user clears the password too", P.get_proxy(pa["id"])["pass"], "")

    chk("node_proxy resolves through the registry",
        P.node_proxy({"proxy_on": True, "proxy_id": pb["id"]}), "http://10.9.9.8:3128")
    chk("node_proxy on a dangling id is direct", P.node_proxy({"proxy_on": True, "proxy_id": "nope"}), "")
    chk("node_proxy with the toggle off is direct",
        P.node_proxy({"proxy_on": False, "proxy_id": pb["id"]}), "")

    # the test endpoint: end-to-end through a node when one takes it, reachability only when none does
    calls = []
    P.node_call = lambda n, ep, m="POST", body=None, timeout=8: (
        calls.append((n["name"], ep)) or {"ok": True})
    r = P.api_proxy_test({"id": pa["id"]})
    chk("testing a proxy a node uses pings THAT node", calls, [("DE01", "ping")])
    chk("and reports it as end to end", (r["ok"], r["end_to_end"], r["via"]), (True, True, "DE01"))
    chk("it reports a latency", isinstance(r.get("ms"), int), True)

    calls.clear()
    P.socket.create_connection = lambda addr, timeout=None: (
        calls.append(("dial", addr)) or type("S", (), {"close": lambda self: None})())
    r = P.api_proxy_test({"id": pb["id"]})
    chk("an unused proxy is only reached, not traversed", calls, [("dial", ("10.9.9.8", 3128))])
    chk("and says so", (r["ok"], r["end_to_end"]), (True, False))

    # ---- the dot: the poller's verdict, and the button must not disagree with it
    chk("the manual test publishes the verdict the dot reads",
        (P._px_get(pb["id"]).get("ok"), P._px_get(pb["id"]).get("end_to_end")), (True, False))

    P._px.clear()
    row = {r["name"]: r for r in P.api_proxies({})["proxies"]}["hetzner-2"]
    chk("never probed -> pending, so a fresh proxy is grey and not red",
        (row["pending"], row["online"]), (True, False))

    # a proxy nodes take is judged BY those nodes' cached ping -- no dial of its own
    calls.clear()
    P._cached_ping = lambda nid: {"ok": True, "rtt_ms": 31} if nid == "n2" else {}
    st = P._proxy_probe(P.get_proxy(pa["id"]), P._proxy_nodes().get(pa["id"], []))
    chk("a used proxy is judged by its node's cached ping, with no dial of its own",
        (st["ok"], st["ms"], st["via"], st["end_to_end"], calls), (True, 31, "DE01", True, []))
    P._px_publish(pa["id"], st)
    row = {r["name"]: r for r in P.api_proxies({})["proxies"]}["hetzner-2"]
    chk("and the row turns the verdict into a green dot", (row["online"], row["pending"]), (True, False))

    P._cached_ping = lambda nid: {"ok": False, "error": "unreachable"} if nid == "n2" else {}
    st = P._proxy_probe(P.get_proxy(pa["id"]), P._proxy_nodes().get(pa["id"], []))
    chk("a node that cannot be reached through it makes it red, with the reason",
        (st["ok"], st["ms"], st["error"]), (False, None, "unreachable"))

    # an UNPOLLED node must not be read as a verdict -- fall through to the proxy's own dial
    calls.clear()
    P._cached_ping = lambda nid: {}
    st = P._proxy_probe(P.get_proxy(pa["id"]), P._proxy_nodes().get(pa["id"], []))
    chk("nodes with no poll yet fall through to the proxy's own dial",
        (st["ok"], st["end_to_end"], calls), (True, False, [("dial", ("10.9.9.7", 8080))]))

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe registry keeps its password, answers who-uses-what once, and tests the real path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
