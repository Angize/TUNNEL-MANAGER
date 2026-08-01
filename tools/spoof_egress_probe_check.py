#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The spoof egress test must probe the IPs the TUNNEL will use, on both ends.

The button's own text promises an answer "on THIS pair, in the direction the tunnel will use", and
that promise is the whole reason to trust it: uRPF and decoy routing are per-IP on these providers,
so a probe aimed somewhere else answers a different question. A multi-IP node can come back green on
its management address while the tunnel's chosen address is filtered — or the reverse.

It used to aim at the node registry's `host` (the MANAGEMENT address) and to send no `real_src` at
all, so the node fell back to the route-local source toward that same wrong destination. Both ends of
the baseline were therefore the wrong pair. And because `host` may legitimately be a HOSTNAME
(api_node_add accepts one), the button was an unconditional dead end for such a node — "receiver has
no usable IP", without contacting either side — while the tunnel itself builds perfectly, since
a_ip/b_ip come from the node's live IP list and never from `host`.

This drives the REAL handler with the node calls stubbed, and also checks the browser half: the
picked IPs have to be in the request body, or the server can only ever guess.

    python3 tools/spoof_egress_probe_check.py
"""
import argparse
import importlib.util
import sys
from pathlib import Path

NODES = {
    "na": {"id": "na", "name": "DE", "host": "91.107.190.159"},
    "nb": {"id": "nb", "name": "IR", "host": "94.183.210.135"},
    "nh": {"id": "nh", "name": "BY-HOSTNAME", "host": "de.example.net"},
}
PINGS = {
    "na": {"ok": True, "ips": {"eth0": ["91.107.190.159", "91.107.190.200"]}},
    "nb": {"ok": True, "ips": {"eth0": ["94.183.210.135", "94.183.210.99"]}},
    "nh": {"ok": True, "ips": {"eth0": ["203.0.113.77", "203.0.113.78"]}},
}


def load_panel(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def wire(P, calls):
    P.get_node = lambda i: NODES.get(i)
    P._cached_ping = lambda nid: PINGS.get(nid, {})

    def node_call(n, path, method, body=None, timeout=None):
        calls.append((n["name"], path, dict(body or {})))
        return {
            "spoof-egress-listen": {"ok": True, "token": "tok"},
            "spoof-egress-send": {"ok": True},
            "spoof-egress-result": {"done": True, "saw": {"baseline": True, "src": False, "dst": False},
                                    "observed": {}},
            "ping": PINGS.get(n["id"], {}),
        }.get(path, {})

    P.node_call = node_call
    P.time.sleep = lambda *_: None


def probe(P, calls, req):
    calls.clear()
    res = P.api_spoof_egress_probe(req)
    send = [c for c in calls if c[1] == "spoof-egress-send"]
    return res, (send[0][2] if send else {})


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    P = load_panel(a.panel)
    calls = []
    wire(P, calls)
    failures = []

    # (label, request, expected peer, expected real_src). server_side names the RECEIVER, so flipping
    # it must flip which end is probed and which end sources the baseline.
    cases = [
        ("operator picked the second IP on each node, srv=a",
         {"a_node": "na", "b_node": "nb", "server_side": "a", "proto": 58,
          "a_ip": "91.107.190.200", "b_ip": "94.183.210.99"},
         "91.107.190.200", "94.183.210.99"),
        ("same picks, srv=b — the direction flips",
         {"a_node": "na", "b_node": "nb", "server_side": "b", "proto": 58,
          "a_ip": "91.107.190.200", "b_ip": "94.183.210.99"},
         "94.183.210.99", "91.107.190.200"),
        ("no explicit pick — the node's first live IP",
         {"a_node": "na", "b_node": "nb", "server_side": "a", "proto": 58},
         "91.107.190.159", "94.183.210.135"),
        ("a pick that is not on the node — ignored, not trusted",
         {"a_node": "na", "b_node": "nb", "server_side": "a", "proto": 58, "a_ip": "8.8.8.8"},
         "91.107.190.159", "94.183.210.135"),
        ("receiver registered by HOSTNAME — must still run",
         {"a_node": "nh", "b_node": "nb", "server_side": "a", "proto": 58},
         "203.0.113.77", "94.183.210.135"),
    ]
    for label, req, want_peer, want_src in cases:
        res, body = probe(P, calls, req)
        if not res.get("ok"):
            failures.append("[%s] the probe refused to run: %r" % (label, res.get("error")))
            continue
        if body.get("peer") != want_peer:
            failures.append("[%s] probed peer=%r, want %r — per-IP filtering means a different address "
                            "is a different question" % (label, body.get("peer"), want_peer))
        if body.get("real_src") != want_src:
            failures.append("[%s] real_src=%r, want %r — the baseline has to LEAVE from the tunnel's own "
                            "IP too, not just arrive at it" % (label, body.get("real_src"), want_src))
        print("  ok  %-52s peer=%s src=%s" % (label, want_peer, want_src))

    # The browser half: the server can only aim correctly if the form sends what it picked, and the
    # picks must come from the same helper the create/edit submits use. Read the DECODED INDEX_HTML.
    js = getattr(P, "INDEX_HTML", "")
    if "<script" not in js:
        failures.append("INDEX_HTML did not decode to anything with a <script> in it — this check "
                        "cannot read its subject, so it must not report success")
    else:
        for want, what in (
            ("function pickedIP(px,side,stored)", "one definition of which IP a form picked"),
            ("aip:pickedIP('e_','a','')", "the create form's probe context carries its pick"),
            ("aip:pickedIP('ee_','a',l.a_ip||'')", "the edit form's probe context carries its pick"),
            ("a_ip:ctx.aip||'',b_ip:ctx.bip||''", "the probe request body carries them"),
            ("var aip=pickedIP('e_','a','');if(aip)body.a_ip=aip;", "the create submit shares the helper"),
            ("var aip=pickedIP('ee_','a',l.a_ip||'');if(aip)body.a_ip=aip;", "the edit submit shares it"),
        ):
            if want not in js:
                failures.append("browser JS: %s is missing (or the code moved and this check went "
                                "blind): %r not found" % (what, want))
        print("  ok  the browser sends the IPs it picked, from the shared helper")

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe spoof egress test probes the pair the tunnel will really use")
    return 0


if __name__ == "__main__":
    sys.exit(main())
