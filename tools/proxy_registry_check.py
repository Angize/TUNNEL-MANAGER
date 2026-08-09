#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The proxy registry endpoints, driven for real against temp files.

Three separate places used to answer "which nodes take this proxy": the row builder, the delete
refusal, and nothing else -- until one of them drifted. They now share `_proxy_users()`, and the two
cases that a re-written predicate gets wrong are pinned here:

  * a node with a stored proxy_id but the toggle OFF is NOT a user -- counting it would refuse a
    delete that is perfectly safe, and name a node that is really going out direct.
  * an EMPTY url on edit keeps the stored one. The browser only ever held a redacted copy, so
    submitting what it was shown must not strip the credentials.

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
SECRET = "socks5://u:p@10.9.9.9:1080"
REDACTED = "socks5://10.9.9.9:1080"


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
            print("  ok   %-50s %r" % (label, got))

    pa = P.api_proxy_add({"name": "hetzner", "url": SECRET})["proxy"]
    pb = P.api_proxy_add({"name": "cf", "url": "http://10.9.9.8:3128"})["proxy"]
    chk("add redacts the credentials", pa["url"], REDACTED)
    chk("a fresh proxy has no users", pa["nodes"], [])

    try:
        P.api_proxy_add({"name": "HETZNER", "url": "socks5://1.2.3.4:1"})
        failures.append("a duplicate name differing only in case was accepted")
    except ValueError:
        print("  ok   %-50s %r" % ("a duplicate name is refused, any case", True))

    for n in nodes:            # aim the fixtures at the ids the registry actually minted
        if n.get("proxy_id") == "PX_A":
            n["proxy_id"] = pa["id"]
        elif n.get("proxy_id") == "PX_B":
            n["proxy_id"] = pb["id"]
    json.dump(nodes, io.open(P.NODES_FILE, "w"))

    rows = {r["name"]: r for r in P.api_proxies({})["proxies"]}
    chk("the in-use proxy names its nodes", sorted(rows["hetzner"]["nodes"]), ["DE01", "INTERCOLO"])
    chk("a stored id with the toggle OFF is not a user", rows["cf"]["nodes"], [])
    chk("the listed url stays redacted", rows["hetzner"]["url"], REDACTED)

    try:
        P.api_proxy_del({"id": pa["id"]})
        failures.append("an in-use proxy was deleted — those nodes would drop to a DIRECT connection "
                        "with nothing said")
    except ValueError as e:
        chk("deleting an in-use proxy is refused, and names the nodes",
            "DE01" in str(e) and "INTERCOLO" in str(e), True)

    P.api_proxy_del({"id": pb["id"]})
    chk("an unused proxy deletes", [r["name"] for r in P.api_proxies({})["proxies"]], ["hetzner"])

    P.api_proxy_edit({"id": pa["id"], "name": "hetzner-2", "url": ""})
    chk("a blank url on edit keeps the stored credentials",
        json.load(io.open(P.PROXIES_FILE))[0]["url"], SECRET)
    chk("the edit renamed it", P.api_proxies({})["proxies"][0]["name"], "hetzner-2")

    chk("node_proxy resolves through the registry",
        P.node_proxy({"proxy_on": True, "proxy_id": pa["id"]}), SECRET)
    chk("node_proxy on a dangling id is direct", P.node_proxy({"proxy_on": True, "proxy_id": "nope"}), "")
    chk("node_proxy with the toggle off is direct",
        P.node_proxy({"proxy_on": False, "proxy_id": pa["id"]}), "")

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe registry answers who-uses-what from one place, and never leaks a credential")
    return 0


if __name__ == "__main__":
    sys.exit(main())
