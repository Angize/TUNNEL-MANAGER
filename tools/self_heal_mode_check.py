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
import time
import os
import sys
import tempfile
from pathlib import Path

NODES = [{"id": "n1", "name": "IR02", "host": "94.183.210.131", "port": 8099, "token": "tok1"},
         {"id": "n2", "name": "DE01", "host": "5.75.197.201", "port": 8099, "token": "tok2"}]
NEW = "94.183.210.9"



# The check-in is signed now: it carries a FINGERPRINT of the token and an HMAC over the rest, never
# the token itself. Built here exactly as the node builds it -- a guard that called the verifier
# directly would say nothing about the shape the node actually sends.
_CKCTR = [int(time.time() * 1000)]


def claim(token, **fields):
    import base64, hashlib, hmac
    _CKCTR[0] += 1
    c = dict(fields)
    c["fp"] = hashlib.sha256(token.encode()).hexdigest()
    c["ctr"] = _CKCTR[0]
    msg = json.dumps(c, sort_keys=True, separators=(",", ":")).encode()
    c["sig"] = base64.b64encode(hmac.new(token.encode(), msg, hashlib.sha256).digest()).decode()
    return c


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
    r = P.api_checkin_impl(NEW, claim("tok1"))
    chk("manual mode does not adopt the new address", (r["updated"], host_of("n1")),
        (False, "94.183.210.131"))
    chk("but it tells the node WHERE we saw it", r.get("moved_to"), NEW)
    # what the BROWSER is handed, not the helper: the card cannot show an address api_nodes never sends
    row = {r["name"]: r for r in P.api_nodes({})["nodes"]}["IR02"]
    chk("the card is given the same address", row.get("moved_to"), NEW + ":8099")
    chk("and a node that did not move gets nothing",
        {r["name"]: r for r in P.api_nodes({})["nodes"]}["DE01"].get("moved_to"), "")
    chk("and it is logged once, with the address in it",
        (len(logged), NEW in logged[0][3]), (1, True))
    for _ in range(5):
        P.api_checkin_impl(NEW, claim("tok1"))
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
    chk("and says so in the log", any(NEW in (e[3] or "") and "تنظیمِ نشانی" in e[2] for e in logged), True)

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

    # ---- a node deleted while it was reported as moved must leave nothing behind. _moved was the one
    # per-node store the poller's prune did not cover, so it leaked for the life of the process.
    for st in P.NODE_STATE:
        getattr(P, st)["ghost"] = {"seeded": True}
        getattr(P, st)["n1"] = {"seeded": True}     # a LIVE node, seeded in the same stores
    P._pending_gc = lambda valid: None
    P._prune_node_state({n["id"] for n in NODES})
    chk("a vanished node is dropped from EVERY per-node store",
        sorted(st for st in P.NODE_STATE if "ghost" in getattr(P, st)), [])
    # and the other half of the same property: an over-eager prune would wipe every LIVE node's traffic
    # counters, uptime history and moved state on every sweep, which no assertion above would notice.
    chk("and a registered node keeps its state in all of them",
        sorted(st for st in P.NODE_STATE if "n1" in getattr(P, st)), sorted(P.NODE_STATE))
    chk("and _moved is one of those stores", "_moved" in P.NODE_STATE, True)
    src = Path(a.panel).read_text(encoding="utf-8")
    chk("the poller uses that one function, not its own copy of it",
        len([ln for ln in src.splitlines()
             if "_prune_node_state(valid)" in ln and not ln.lstrip().startswith("def ")]), 1)

    # ---- the refusal must name the real obstacle: a node whose proxy is down is unreachable at EVERY
    # address, so blaming the address sends the operator hunting the wrong thing.
    json.dump([{**NODES[0], "proxy_on": True, "proxy_id": "px9"}, dict(NODES[1])],
              io.open(P.NODES_FILE, "w"))
    json.dump([{"id": "px9", "name": "IR-DE", "scheme": "socks5", "host": "9.9.9.9", "port": 1080}],
              io.open(P.PROXIES_FILE, "w"))
    P._moved_note("n1", "IR02", "94.183.210.131", NEW, 8099)
    reach(set())
    P._px_publish("px9", {"ok": False, "ms": None, "error": "timed out"})
    try:
        P.api_node_adopt_ip({"id": "n1"})
        chk("adopt refuses while the proxy is down", "wrote it", "ValueError")
    except ValueError as e:
        chk("a down proxy is blamed on the PROXY", "پروکسیِ این نود قطع است" in str(e), True)
        chk("and the address is not accused", NEW in str(e), False)
    P._px_publish("px9", {"ok": True, "ms": 12, "error": ""})
    try:
        P.api_node_adopt_ip({"id": "n1"})
        chk("adopt still refuses a dead address", "wrote it", "ValueError")
    except ValueError as e:
        chk("a healthy proxy leaves the address to blame", NEW in str(e), True)

    # the log line must describe the control that exists now, not the edit form it replaced
    P._moved_clear("n1")          # _moved_note logs only on CHANGE; a primed value would silence this
    logged.clear()
    reach({NEW})
    P.api_checkin_impl(NEW, claim("tok1"))
    line = logged[0][3] if logged else ""
    chk("the log points at the chip, not the edit form",
        "نشانِ هشدار" in line and "ویرایشِ نود" not in line, True)

    # restore the fixture for the checks below
    json.dump([dict(n) for n in NODES], io.open(P.NODES_FILE, "w"))
    P._moved_note("n1", "IR02", "94.183.210.131", NEW, 8099)

    # a node that is reachable again at its stored host must stop being reported
    reach({"94.183.210.131", NEW})
    P.api_checkin_impl(NEW, claim("tok1"))
    chk("a node found at its own host again is no longer 'moved'", P.moved_to("n1"), "")

    # ---- auto: do it
    mode("auto")
    reach({NEW})
    r = P.api_checkin_impl(NEW, claim("tok1"))
    chk("auto mode adopts it", (r["updated"], host_of("n1")), (True, NEW))
    chk("and nothing is left pending for the operator", P.moved_to("n1"), "")

    # ---- neither mode may believe an address that does not answer
    json.dump([dict(n) for n in NODES], io.open(P.NODES_FILE, "w"))
    for m in ("auto", "alert"):
        mode(m)
        reach(set())     # the old host is dead AND the new one does not answer either
        r = P.api_checkin_impl("1.2.3.4", claim("tok1"))
        chk("%s mode rejects an address that does not reach the node" % m,
            (r["updated"], host_of("n1"), r.get("moved_to")), (False, "94.183.210.131", None))

    # an unknown token can never move a node, in either mode
    for m in ("auto", "alert"):
        mode(m)
        reach({NEW})
        r = P.api_checkin_impl(NEW, claim("not-a-node"))
        chk("%s mode refuses an unknown token" % m, (r["ok"], host_of("n1")),
            (False, "94.183.210.131"))

    # ---- the check-in must carry NO secret, and must not be replayable
    mode("auto")
    reach({NEW})
    # The bare token was what this used to carry. Whoever saw it could not command the node -- that
    # needs a signature -- but they could claim the node had MOVED to their address, answer the panel's
    # signed probe with the key they had just been handed, and own its control traffic from then on.
    r = P.api_checkin_impl(NEW, {"token": "tok1", "ips": {"eth0": [NEW]}})
    chk("a check-in carrying the raw TOKEN is refused", r.get("ok"), False)
    # ...and the fingerprint alone, which a listener CAN copy, proves nothing without the signature
    import hashlib as _h
    r = P.api_checkin_impl(NEW, {"fp": _h.sha256(b"tok1").hexdigest(), "ctr": 9 * 10 ** 12})
    chk("...and the fingerprint alone, with no signature, is refused too", r.get("ok"), False)
    c = claim("tok1")
    chk("a signed one is accepted", P.api_checkin_impl(NEW, c).get("ok"), True)
    chk("...and the SAME one replayed is refused", P.api_checkin_impl(NEW, c).get("ok"), False)
    c2 = claim("tok1")
    c2["hostname"] = "attacker"          # any edit invalidates the signature over the whole claim
    chk("...and one edited after signing is refused", P.api_checkin_impl(NEW, c2).get("ok"), False)

    # ---- the PORT moves with the address, in AUTO mode where adopting is the point. Without it the
    # self-heal covers only half of "where this node is": an agent that moved port is unreachable and
    # cannot say so, so the record has to be edited by hand.
    mode("auto")
    P._moved_clear("n1")
    cur_host = next(x["host"] for x in json.load(io.open(P.NODES_FILE)) if x["id"] == "n1")
    P.node_call = lambda nd, *a, **k: {"ok": (nd["host"], int(nd["port"])) == (cur_host, 9099)}
    r = P.api_checkin_impl(cur_host, claim("tok1", port=9099))
    chk("a node that changed only its PORT is followed", (r["updated"], r["port"]), (True, 9099))
    chk("and the record really carries it",
        next(int(x["port"]) for x in json.load(io.open(P.NODES_FILE)) if x["id"] == "n1"), 9099)
    P.node_call = lambda nd, *a, **k: {"ok": False}
    r = P.api_checkin_impl(cur_host, claim("tok1", port=7777))
    chk("a port that does not answer is NOT adopted", (r["updated"], r["port"]), (False, 9099))

    if bad:
        print("\nFAILURES (%d):" % len(bad))
        for b in bad:
            print("  - %s" % b)
        return 1
    print("\none switch governs the whole chain, and manual mode says what to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
