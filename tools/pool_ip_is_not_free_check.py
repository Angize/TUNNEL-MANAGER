#!/usr/bin/env python3
"""An IP a rotation pool cycles through is IN USE, and must never read «آزاد».

`_node_ip_tags` built its used-map from `a_ip`/`b_ip` only — the ONE endpoint each side is currently
on. A pooled tunnel spends its whole life cycling through the other addresses in its pool, and every
one of them showed as free. That is not a cosmetic slip: the tag exists so the operator can pick a
spare address for another tunnel, so it invites handing out an address that is carrying traffic.

MEASURED on the live panel: core5 has `a_ip_pool = ['91.107.131.240', '91.98.107.197']` while
`a_ip = '91.107.131.240'`, and the second address read «آزاد» on the node sheet.

Driven through the real `_node_ip_tags`.

    python3 tools/pool_ip_is_not_free_check.py
"""
import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(state):
    spec = importlib.util.spec_from_file_location("pif_panel", os.path.join(REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["pif_panel"] = m
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    m.log_event = lambda *a, **k: None
    return m


def tags(P, nid):
    return {t["ip"]: t for t in P._node_ip_tags(nid)}


def main():
    P = load(tempfile.mkdtemp(prefix="pif-"))
    GE_IPS = ["91.107.131.240", "91.98.107.197", "10.0.0.9"]
    P.save_json(P.NODES_FILE, [
        {"id": "ge2", "name": "MMD-GE2", "host": "91.107.131.240", "port": 8099, "token": "t"},
        {"id": "ir2", "name": "MMD-IR2", "host": "94.182.131.37", "port": 8099, "token": "t"}])
    P._cached_list = lambda nid: {"configs": []}
    IR_IPS = ["94.182.131.37", "94.182.131.99"]
    P._cached_ping = lambda nid: ({"ok": True, "ips": {"eth0": GE_IPS}} if nid == "ge2"
                                  else {"ok": True, "ips": {"eth0": IR_IPS}})

    # core5's real shape, read off the live panel.
    link = {"id": "L5", "name": "core5", "type": "core", "a_node": "ge2", "b_node": "ir2",
            "a_name": "MMD-GE2", "b_name": "MMD-IR2", "a_ip": "91.107.131.240",
            "b_ip": "94.182.131.37", "ip_rotate": True,
            "a_ip_pool": ["91.107.131.240", "91.98.107.197"],
            "b_ip_pool": ["94.182.131.37", "94.182.131.99"]}
    P.save_json(P.LINKS_FILE, [link])

    print("== a pool address is in use, not free ==")
    t = tags(P, "ge2")
    check("the endpoint the tunnel is on reads as used", not t["91.107.131.240"]["free"])
    check("...and so does the OTHER address in its pool", not t["91.98.107.197"]["free"],
          "«آزاد» on an address core5 rotates onto")
    check("...naming the tunnel that holds it",
          [p["name"] for p in t["91.98.107.197"]["peers"]] == ["core5"],
          repr(t["91.98.107.197"]["peers"]))
    # ...and the tag must not spread to every address the node happens to have.
    check("an address in NO pool is still free", t["10.0.0.9"]["free"], repr(t["10.0.0.9"]))

    print("== rotation OFF: the pool is stored but not in use ==")
    # The pool list survives being switched off, so reading it unconditionally would mark addresses as
    # used for a tunnel that is pinned to one endpoint.
    P.save_json(P.LINKS_FILE, [dict(link, ip_rotate=False)])
    t = tags(P, "ge2")
    check("the endpoint is still used", not t["91.107.131.240"]["free"])
    check("...but a pool address of a NON-rotating tunnel is free again", t["91.98.107.197"]["free"],
          repr(t["91.98.107.197"]))

    print("== one tunnel is named once, however many of its lists an address is in ==")
    # a_ip is also the first entry of a_ip_pool, so the endpoint would otherwise be tagged twice and the
    # sheet would show «core5 core5».
    P.save_json(P.LINKS_FILE, [link])
    t = tags(P, "ge2")
    check("the endpoint carries exactly one tag", len(t["91.107.131.240"]["peers"]) == 1,
          repr(t["91.107.131.240"]["peers"]))

    print("== each side is tagged from ITS OWN pool ==")
    # Asserting that B is not tagged with A's addresses proves nothing: they are not among B's live
    # IPs, so they could never appear whatever the code read. What DOES separate the two is that each
    # side's own spare is tagged -- swap the sides and both of these go red.
    t2 = tags(P, "ir2")
    check("node B's endpoint is used", not t2["94.182.131.37"]["free"])
    check("...and node B's own spare is used too", not t2["94.182.131.99"]["free"],
          repr(t2["94.182.131.99"]))

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("a pooled address is never offered as spare.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
