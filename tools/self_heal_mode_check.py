#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""One switch governs the WHOLE self-heal chain, and manual mode still tells the operator what to do.

When a node's IP changes, three things have to happen: the node phones home, the panel adopts the new
address, and the drifted tunnel is rebuilt. The rebuild already obeyed `reconcile_mode` -- adopting the
address did not, so on "alert" the panel silently rewrote nodes.json anyway. Half-automatic is the worst
of both: the operator was told to do it by hand, and the panel had already done part of it.

So on "alert" nothing is written, and the address the node moved TO is surfaced instead -- on the card, in
the dashboard alerts and once in the log. Without that the operator cannot even learn the new IP: the node
is unreachable at the address the panel has.

    python3 tools/self_heal_mode_check.py
"""
import argparse
import importlib.util
import io
import json
import os
import sys
import tempfile
from pathlib import Path

NODES = [{"id": "n1", "name": "IR02", "host": "94.183.210.131", "port": 8099, "token": "tok1"},
         {"id": "n2", "name": "DE01", "host": "5.75.197.201", "port": 8099, "token": "tok2"}]
NEW = "94.183.210.9"


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    spec = importlib.util.spec_from_file_location("tnl_central", str(a.panel))
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    bad = []

    def chk(label, got, want):
        if got != want:
            bad.append("%s: got %r, expected %r" % (label, got, want))
            print("  FAIL %-60s %r != %r" % (label, got, want))
        else:
            print("  ok   %-60s %r" % (label, got))

    d = tempfile.mkdtemp(prefix="tnl_heal_")
    P.NODES_FILE = os.path.join(d, "nodes.json")
    json.dump([dict(n) for n in NODES], io.open(P.NODES_FILE, "w"))
    P.PROXIES_FILE = os.path.join(d, "proxies.json")
    logged = []
    P.log_event = lambda lvl, kind, fa, dfa="": logged.append((lvl, kind, fa, dfa))
    P._refresh_cache = lambda ids: None

    def mode(m):
        P.get_settings = lambda: {"reconcile_mode": m, "uptime_window": 1}

    # the stored host is dead, the address it is calling from answers
    def reach(alive):
        P.node_call = lambda n, *a, **k: {"ok": n["host"] in alive}

    def host_of(nid):
        return next(x["host"] for x in json.load(io.open(P.NODES_FILE)) if x["id"] == nid)

    # ---- manual: report, change nothing
    mode("alert")
    reach({NEW})
    r = P.api_checkin_impl(NEW, {"token": "tok1"})
    chk("manual mode does not adopt the new address", (r["updated"], host_of("n1")),
        (False, "94.183.210.131"))
    chk("but it tells the node WHERE we saw it", r.get("moved_to"), NEW)
    # what the BROWSER is handed, not the helper: the card cannot show an address api_nodes never sends
    row = {r["name"]: r for r in P.api_nodes({})["nodes"]}["IR02"]
    chk("the card is given the same address", row.get("moved_to"), NEW)
    chk("and a node that did not move gets nothing",
        {r["name"]: r for r in P.api_nodes({})["nodes"]}["DE01"].get("moved_to"), "")
    chk("and it is logged once, with the address in it",
        (len(logged), NEW in logged[0][3]), (1, True))
    for _ in range(5):
        P.api_checkin_impl(NEW, {"token": "tok1"})
    chk("a node calling every 20s does not fill the log", len(logged), 1)

    P._cached_ping = lambda nid: {"ok": False, "error": "unreachable"}
    P._cache_get = lambda nid: {"ping": {"ok": False}}
    P.load_links = lambda: []
    alerts = {x.get("msg", ""): x for x in P.api_summary({})["alerts"]}
    chk("the dashboard says which node moved and where",
        [m for m in alerts if NEW in m and "IR02" in m] != [], True)
    chk("as a warning, not an outage", [alerts[m]["level"] for m in alerts if NEW in m], ["warn"])

    # ---- the one-click adopt. It writes the host, so it must re-prove the address FIRST: the check-in
    # that reported it can be minutes old, and a host nobody can reach is worse than the warning it replaces.
    reach(set())                      # nothing answers now
    try:
        P.api_node_adopt_ip({"id": "n1"})
        chk("adopt refuses an address that stopped answering", "wrote it", "ValueError")
    except ValueError as e:
        chk("adopt refuses an address that stopped answering", NEW in str(e), True)
    chk("and the host is untouched", host_of("n1"), "94.183.210.131")
    chk("and the warning is still there to try again", P.moved_to("n1"), NEW)

    reach({NEW})
    r = P.api_node_adopt_ip({"id": "n1"})
    chk("adopt takes the reported address", (r["ok"], r["host"], host_of("n1")), (True, NEW, NEW))
    chk("and clears the warning", P.moved_to("n1"), "")
    chk("and says so in the log", any(NEW in (e[3] or "") and "تنظیمِ آی‌پی" in e[2] for e in logged), True)
    try:
        P.api_node_adopt_ip({"id": "n1"})
        chk("adopt with nothing reported is refused", "accepted", "ValueError")
    except ValueError as e:
        # the REASON matters: refusing because a fabricated address happened not to answer would pass a
        # check that only asks "did it raise", while the code had invented an address to write.
        chk("adopt with nothing reported says THAT, not 'it did not answer'", "ثبت نشده" in str(e), True)
    try:
        P.api_node_adopt_ip({"id": "nope"})
        chk("adopt on an unknown node is refused", "accepted", "ValueError")
    except ValueError:
        print("  ok   %-60s %r" % ("adopt on an unknown node is refused", "ValueError"))

    # the browser must be able to reach it: the endpoint is registered and CSRF-gated like every mutation
    chk("the endpoint is wired", P.API.get("node-adopt-ip") is P.api_node_adopt_ip, True)
    chk("and gated as a mutation", "node-adopt-ip" in P.MUTATIONS, True)
    js = P.INDEX_HTML
    chk("the card shows a control, not a paragraph, when a node moved",
        "n.moved_to?'<button class=\"mvwarn\"" in js, True)
    head = next((ln for ln in js.splitlines() if 'class="chead"' in ln and "mvwarn" in ln), "")
    chk("the chip is in the card HEAD, not the body", bool(head), True)
    chk("and it sits between the toggle and the spacer",
        head.index("tsw") < head.index("mvwarn") < head.index('class="grow"'), True)
    chk("tapping it cannot fold the card instead", "function openMovedIp(el,e){if(e)e.stopPropagation();" in js, True)
    chk("the popup's button posts the adopt", "post('node-adopt-ip',{id:btn.getAttribute('data-nid')})" in js, True)

    # restore the fixture for the checks below
    json.dump([dict(n) for n in NODES], io.open(P.NODES_FILE, "w"))
    P._moved_note("n1", "IR02", "94.183.210.131", NEW)

    # a node that is reachable again at its stored host must stop being reported
    reach({"94.183.210.131", NEW})
    P.api_checkin_impl(NEW, {"token": "tok1"})
    chk("a node found at its own host again is no longer 'moved'", P.moved_to("n1"), "")

    # ---- auto: do it
    mode("auto")
    reach({NEW})
    r = P.api_checkin_impl(NEW, {"token": "tok1"})
    chk("auto mode adopts it", (r["updated"], host_of("n1")), (True, NEW))
    chk("and nothing is left pending for the operator", P.moved_to("n1"), "")

    # ---- neither mode may believe an address that does not answer
    json.dump([dict(n) for n in NODES], io.open(P.NODES_FILE, "w"))
    for m in ("auto", "alert"):
        mode(m)
        reach(set())     # the old host is dead AND the new one does not answer either
        r = P.api_checkin_impl("1.2.3.4", {"token": "tok1"})
        chk("%s mode rejects an address that does not reach the node" % m,
            (r["updated"], host_of("n1"), r.get("moved_to")), (False, "94.183.210.131", None))

    # an unknown token can never move a node, in either mode
    for m in ("auto", "alert"):
        mode(m)
        reach({NEW})
        r = P.api_checkin_impl(NEW, {"token": "not-a-node"})
        chk("%s mode refuses an unknown token" % m, (r["ok"], host_of("n1")),
            (False, "94.183.210.131"))

    if bad:
        print("\nFAILURES (%d):" % len(bad))
        for b in bad:
            print("  - %s" % b)
        return 1
    print("\none switch governs the whole chain, and manual mode says what to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
