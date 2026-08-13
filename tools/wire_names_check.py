#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The name on the wire must stay opaque, and the two repos must agree on it.

The panel→node control channel is plain HTTP, so the request line crosses the border in the clear.
MEASURED on the Iran→Germany path: a URI containing the string "tunnel" is dropped — 5 of 5 attempts lost
at a 10s timeout, while `tunne1` (one character different) and `xunnel` arrived 5 of 5, and every other
endpoint arrived. That is why only BUILDING a tunnel on a foreign node ever failed: it was the one call
whose URL said what the product does. It cost a night of looking at the wrong layer.

So three things must hold, and none of them survives a careless rename:

  * every endpoint the panel calls has a wire name, and the node answers exactly that set;
  * no wire name leaks what this is — not "tunnel", not the name of any tool a censor greps for;
  * the URL is built ONLY from the map, so a fourth code path cannot appear that sends the real name.

    python3 tools/wire_names_check.py
"""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

# What a keyword filter plausibly greps for. Substring match, case-insensitive, on the wire name.
BAIT = ("tunnel", "vpn", "proxy", "socks", "shadow", "wireguard", "openvpn", "v2ray", "xray", "trojan",
         "vless", "vmess", "reality", "obfs", "relay", "bridge", "core", "spoof", "kernel", "wipe",
         "install", "update", "gost", "hysteria", "naive", "cloak")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    ap.add_argument("--node", default=here.parent.parent.parent / "TUNNEL-MANAGER-NODE" / "tnl-node.py")
    a = ap.parse_args()

    P = load(a.panel, "tnl_central")
    bad = []

    def chk(label, got, want):
        if got != want:
            bad.append("%s: got %r, expected %r" % (label, got, want))
            print("  FAIL %-58s %r != %r" % (label, got, want))
        else:
            print("  ok   %-58s %r" % (label, got))

    # ---- the wire name says nothing
    leaks = sorted((ep, w) for ep, w in P.NODE_WIRE.items()
                   for b in BAIT if b in str(w).lower())
    chk("no wire name contains a word a filter would grep for", leaks, [])
    chk("wire names are short enough to say nothing on their own",
        sorted(w for w in P.NODE_WIRE.values() if len(str(w)) > 4), [])
    chk("no two endpoints share a wire name",
        len(set(P.NODE_WIRE.values())), len(P.NODE_WIRE))
    chk("wire names are URL-safe", sorted(w for w in P.NODE_WIRE.values()
                                          if not re.fullmatch(r"[a-z0-9]{1,4}", str(w))), [])

    # ---- an unknown endpoint is a programming error, never a path invented on the fly
    try:
        P.wire("definitely-not-an-endpoint")
        chk("an unknown endpoint is refused", "returned", "ValueError")
    except ValueError:
        print("  ok   %-58s %r" % ("an unknown endpoint is refused", "ValueError"))

    # ---- the URL is built from the map and nowhere else
    src = Path(a.panel).read_text(encoding="utf-8")
    raw = re.findall(r"/api/\{endpoint\}|/api/%s\" % endpoint|/api/\" \+ endpoint", src)
    chk("no code path puts the raw endpoint name in a URL", raw, [])
    # three exits reach a node: node_call direct, _node_call_proxied, node_push. Each must translate.
    paths = [ln.strip() for ln in src.splitlines() if "/api/" in ln and "endpoint" in ln]
    chk("every line that builds a node path translates it", [p for p in paths if "wire(endpoint)" not in p], [])
    chk("and there are exactly the three known exits", len(paths), 3)

    # ---- the OTHER direction is plaintext too. /api/dl is a node fetching a staged artifact from the
    # panel, so its URL crosses the same filtered path as a control call and must say just as little.
    # Built for real rather than grepped: the query keys are what a filter greps, and they only exist
    # once _panel_dl_url has assembled them.
    P._CENTRAL_PORT = 8080
    P._route_src = lambda host: "203.0.113.7"
    P.node_proxy = lambda n: ""
    dl = [P._panel_dl_url({"host": "10.0.0.1", "token": "tok"}, k, arch)
          for k, arch in (("ag", ""), ("co", "amd64"), ("co", "arm64"), ("cb", ""))]
    chk("the panel's own download URL says nothing either",
        sorted({b for u in dl for b in BAIT if b in u.lower()}), [])
    # Every path the panel answers before a session exists — which is every path a NODE can reach.
    routed = sorted(set(re.findall(r'path == "(/api/[a-z-]+)"', src)))
    chk("...and that list was found at all", bool(routed), True)   # a regex that matches nothing passes everything
    chk("no URL the panel answers without a session says what this is",
        sorted({(p, b) for p in routed for b in BAIT if b in p.lower()}), [])

    # ---- and the node answers exactly this set
    N = load(a.node, "tnl_node")
    chk("the node's wire map matches the panel's",
        sorted(N.WIRE.items()), sorted((w, ep) for ep, w in P.NODE_WIRE.items()))
    chk("every op the node has is reachable", sorted(set(N.OPS) - set(N.WIRE.values())), [])
    chk("and no wire name points at an op that does not exist",
        sorted(set(N.WIRE.values()) - set(N.OPS)), [])
    chk("the node resolves the path through the map, not directly",
        bool(re.search(r"cmd = WIRE\.get\(path\[5:\], \"\"\)", Path(a.node).read_text(encoding="utf-8"))),
        True)

    if bad:
        print("\nFAILURES (%d):" % len(bad))
        for b in bad:
            print("  - %s" % b)
        return 1
    print("\nthe wire says nothing, and both repos agree on it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
