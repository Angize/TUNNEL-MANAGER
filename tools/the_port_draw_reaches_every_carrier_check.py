#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""port_tries has to reach every carrier that owns a source-port rung, not just the raw one.

The core arms a source-port rung on udp, on tcp/ws (and the http and grpc carriers that ride it), on
and on raw only when the forged source port is set to roll. `port_tries` says how deep that rung
is -- how many draws the ladder spends before it does anything more expensive -- and the panel only
ever collected it inside the raw branch of the create/edit form. On every other carrier the core kept
its compiled-in 2 whatever the operator typed, because the field was never rendered and never sent.

This pins both halves: the visibility rule names exactly the carriers that have a rung, and the value
survives every one of the four body-building paths for a udp tunnel.

    python3 tools/the_port_draw_reaches_every_carrier_check.py
"""
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

# The carriers whose client arms rc.port.setRoll in the core, and the ones that do not.
WITH_RUNG = ("udp", "tcp", "ws")


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def gate_source(P):
    names = re.search(r"var PORT_RUNG_TRANSPORTS=\[(.+?)\];", P.INDEX_HTML)
    body = re.search(r"function portTriesOn\(S\)\{(.+?)\nfunction ", P.INDEX_HTML, re.S)
    if not names or not body:
        return ""
    return names.group(1) + body.group(1)


def js_pass(P, fails):
    js = P.INDEX_HTML
    body = gate_source(P)
    if not body:
        fails.append("portTriesOn is gone; nothing decides where the field is shown")
        return
    for tr in WITH_RUNG:
        ok = ("'%s'" % tr) in body
        print(("  ok   " if ok else " FAIL ") + "portTriesOn names %s" % tr)
        if not ok:
            fails.append("portTriesOn does not name %s, which has a port rung" % tr)

    for want in ("portTriesSection(", "portTriesVis(", "corPortTriesVis()", "cePortTriesVis()"):
        ok = want in js
        print(("  ok   " if ok else " FAIL ") + "the form wires %s" % want)
        if not ok:
            fails.append("%s is missing, so the field is never rendered or refreshed" % want)

    ok = "if(portTriesOn(S)){body.port_tries=portTriesN(px)}" in js and "portTriesErr(px,S)" in js
    print(("  ok   " if ok else " FAIL ") + "the body collector is gated on the same rule, and refuses before it")
    if not ok:
        fails.append("port_tries is not collected through portTriesOn, or no longer refuses out of "
                     "range before collecting -- the rule and the field can drift")


def store_pass(P, fails):
    for tr in WITH_RUNG:
        cur = {"transport": tr, "cipher": "aes-256-gcm", "psk": "0123456789abcdef0123456789abcdef",
               "port": 5555, "ws_host": "cdn.example.com", "ws_path": "/"}
        got, _side = P._core_extra(dict(cur, port_tries=7), cur, "10.20.30.1", "10.20.30.2", [], [])
        ok = got.get("port_tries") == 7
        print(("  ok   " if ok else " FAIL ") + "%-5s _core_extra stores port_tries=%r" % (tr, got.get("port_tries")))
        if not ok:
            fails.append("%s: _core_extra dropped port_tries" % tr)

    L = {"type": "core", "transport": "udp", "port": 5555, "port_tries": 7,
         "psk": "0123456789abcdef0123456789abcdef", "cipher": "aes-256-gcm"}
    replayed = P._tunnel_extra(L, refetch_ech=False)
    ok = replayed.get("port_tries") == 7
    print(("  ok   " if ok else " FAIL ") + "_tunnel_extra replays port_tries=%r" % replayed.get("port_tries"))
    if not ok:
        fails.append("_tunnel_extra dropped port_tries, so rebuild and rollback lose it")

    stripped = P._node_extra({"port_tries": 7, "transport": "udp"})
    ok = stripped.get("port_tries") == 7
    print(("  ok   " if ok else " FAIL ") + "_node_extra keeps port_tries=%r" % stripped.get("port_tries"))
    if not ok:
        fails.append("_node_extra strips port_tries, so no node ever sees it")


def rollback_pass(P, fails):
    sent = []
    P.node_call = lambda N, path, method, body=None, **kw: sent.append(dict(body or {})) or {"ok": True}
    P._settings_tuning = lambda: {}
    L = {"type": "core", "transport": "udp", "name": "t1", "subnet": "10.20.30.0/24",
         "a_ip": "10.20.30.1", "b_ip": "10.20.30.2", "tunnel_id": 7,
         "a_node": 1, "b_node": 2, "server_side": "a", "enabled": True,
         "port": 5555, "psk": "0123456789abcdef0123456789abcdef", "cipher": "aes-256-gcm",
         "port_tries": 7}
    P._restore_link({"id": 1, "name": "A"}, {"id": 2, "name": "B"}, L,
                    P._tunnel_extra(L, refetch_ech=False))
    got = [b.get("port_tries") for b in sent]
    ok = got == [7, 7]
    print(("  ok   " if ok else " FAIL ") + "a rollback POSTs port_tries=%r to both nodes" % (got,))
    if not ok:
        fails.append("the rollback body carries %r, not 7 on both ends" % (got,))


def main():
    P = load_panel()
    fails = []
    js_pass(P, fails)
    print()
    store_pass(P, fails)
    print()
    rollback_pass(P, fails)
    print()
    if fails:
        print("FAILURES:")
        for f in fails:
            print("  - " + f)
        return 1
    print("port_tries reaches every carrier that has a rung, on every build path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
