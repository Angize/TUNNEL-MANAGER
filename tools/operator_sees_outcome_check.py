#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The panel must not hide the outcome of a long operation from the operator.

Two failures of that kind were reported from the live fleet on the same night:

  * «بازسازی ناموفق» with no reason. Every server-side refusal DOES carry a Persian reason, so a bare
    line means the answer never arrived -- a rebuild allows each node 200s, so the request can easily
    outlive the phone connection that asked for it. Two things must hold: the panel remembers its own
    verdict (and serves it with the link), and the browser says "no answer" instead of claiming failure.
  * the upload's cancel button was in the two page-top cards, while the operator was scrolled down at
    the node whose bar was moving. A control the operator cannot see is a control that does not exist,
    and one that outlives its job is worse: it silently does nothing.

Server side is DRIVEN (api_rebuild_link -> api_fleet). The browser half is asserted against the DECODED
INDEX_HTML, because that is the text the browser really runs.

    python3 tools/operator_sees_outcome_check.py
"""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

LINK = {"id": "L1", "name": "core4", "type": "core", "a_node": "n1", "b_node": "n2",
        "a_name": "TEST2", "b_name": "IR02", "a_ip": "10.0.0.1", "b_ip": "10.0.0.2",
        "subnet": "192.168.4.0/24", "tunnel_id": 4, "enabled": True, "psk": "must-not-leak"}
NODES = [{"id": "n1", "name": "TEST2", "host": "10.0.0.1", "port": 8099, "token": "t"},
         {"id": "n2", "name": "IR02", "host": "10.0.0.2", "port": 8099, "token": "t"}]
REASON = "نودِ «TEST2» آفلاین است"


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
            print("  FAIL %-62s %r != %r" % (label, got, want))
        else:
            print("  ok   %-62s %r" % (label, got))

    P.load_links = lambda: [dict(LINK)]
    P.load_nodes = lambda: [dict(n) for n in NODES]
    P.get_node = lambda nid: next((dict(n) for n in NODES if n["id"] == nid), None)
    P._cached_list = lambda nid: {"ok": True, "configs": [], "health": {}}
    P._cached_ping = lambda nid: {"ok": True, "ips": {"eth0": ["10.0.0.1" if nid == "n1" else "10.0.0.2"]}}

    def fleet_rb():
        return next(x for x in P.api_fleet({})["links"] if x["id"] == "L1").get("rb")

    # ---- the panel keeps its own verdict, so a lost answer cannot erase the reason
    P._rebuild_link_impl = lambda d: (_ for _ in ()).throw(ValueError(REASON))
    raised = ""
    try:
        P.api_rebuild_link({"id": "L1"})
    except ValueError as e:
        raised = str(e)
    chk("a refusal still reaches the caller", raised, REASON)
    chk("the panel remembers WHY it refused", (P.rb_last("L1") or {}).get("error"), REASON)
    chk("and the link carries it to the browser", (fleet_rb() or {}).get("error"), REASON)
    chk("carrying it never leaks the psk", "psk" in next(x for x in P.api_fleet({})["links"]), False)

    P._rebuild_link_impl = lambda d: {"ok": True, "name": "core4"}
    P.api_rebuild_link({"id": "L1"})
    chk("a later success replaces the failure", (fleet_rb() or {}).get("ok"), True)

    with P._rb_lock:                       # an old verdict must not haunt the card for ever
        P._rb_last["L1"]["ts"] -= P.RB_KEEP + 5
    chk("a stale verdict is dropped", fleet_rb(), None)

    # ---- nobody waits three minutes for a dead path. A config write is milliseconds of work on the node,
    # so only the calls that carry megabytes may take a long timeout, and each one must say so by name.
    src = Path(a.panel).read_text(encoding="utf-8")
    chk("a node op gets a short timeout", P.NODE_OP_TIMEOUT <= 30, True)
    chk("long enough for the node's own build lock", P.NODE_OP_TIMEOUT >= 20, True)
    numeric = sorted(set(re.findall(r"timeout=(\d+)", src)))
    chk("no call hard-codes a timeout longer than that",
        [t for t in numeric if int(t) > P.NODE_OP_TIMEOUT], [])
    uploads = [ln.strip()[:60] for ln in src.splitlines() if "NODE_UPLOAD_TIMEOUT" in ln]
    chk("only the byte-carrying calls take the long one", len(uploads), 3)

    # ---- the browser half, read from the decoded page the browser runs
    js = P.INDEX_HTML

    def has(pat, flags=0):
        return bool(re.search(pat, js, flags))

    # a request that never got an answer is not a failure: post() must mark it and perr() must speak it
    chk("post() marks a request that got no answer", has(r"\.catch\(function\(e\)\{return\{ok:false,d:\{\},net:"), True)
    chk("an abort is told apart from a drop", has(r"e\.name=='AbortError'\)\?'timeout':'drop'"), True)
    chk("perr() speaks for the no-answer case first", has(r"function perr\(r,fbk\)\{return r&&r\.net\?"), True)
    for key in ("net_timeout", "net_drop", "rb_last_fail"):
        chk("the page has a string for %s" % key, has(r"\b%s:\"" % key), True)
    # the rebuild's two entry points must both go through perr, or one of them invents its own wording
    inline = re.findall(r"r\.d\.error\|\|r\.d\.msg\)\)\|\|T\('rebuild_failed'\)", js)
    chk("neither rebuild path re-implements the message", inline, [])
    chk("the card shows the panel's own last verdict", has(r"if\(l\.rb&&!l\.rb\.ok\)"), True)

    # the cancel lives with the bar, not in a card that is scrolled away, and dies with its job
    chk("the old page-top cancel row is gone", has(r"pushCancelRow|pushCancelShow|ag_cancel"), False)
    chk("pushBar decides the cancel from the job's liveness", has(r"function pushBar\(st,live\)"), True)
    chk("and only while that node is really uploading",
        has(r"live=live&&\(st\.state=='send'\|\|st\.state=='apply'\)"), True)
    chk("the button itself is gated on that liveness, not on a constant",
        has(r"var xb=live\?'<button class=\"pxc\""), True)
    bar = re.search(r"function pushBar\(st,live\)\{(.*?)\n(?:async )?function ", js, re.S)
    ret = re.search(r"return '<div class=\"pushbar.*", bar.group(1), re.S).group(0) if bar else ""
    chk("the cancel is emitted inside the bar's own label row",
        'class="plbl"' in ret and ret.index("plbl") < ret.index("+xb"), True)
    chk("a finished job paints no cancel", has(r"pushBar\(st,!d\.done\)"), True)
    body = re.search(r"function agentBody\(\)\{(.*?)\n(?:async )?function ", js, re.S)
    chk("the top cards carry no cancel of their own",
        bool(body) and "pushCancel" in body.group(1), False)

    if bad:
        print("\nFAILURES (%d):" % len(bad))
        for f in bad:
            print("  - %s" % f)
        return 1
    print("\nthe reason survives a lost answer, and the cancel is where the bar is")
    return 0


if __name__ == "__main__":
    sys.exit(main())
