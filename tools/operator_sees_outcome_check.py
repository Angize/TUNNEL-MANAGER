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

sys.path.insert(0, str(Path(__file__).resolve().parent))
import act_wait as A     # noqa: E402  (a rebuild answers with a key, so A.raising waits for its verdict)

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
    P._rebuild_link_impl = lambda d, h=None: (_ for _ in ()).throw(ValueError(REASON))
    raised = ""
    try:
        A.raising(P, lambda: P.api_rebuild_link({"id": "L1"}))
    except ValueError as e:
        raised = str(e)
    chk("a refusal still reaches the operator", raised, REASON)
    chk("the panel remembers WHY it refused", (P.rb_last("L1") or {}).get("error"), REASON)
    chk("and the link carries it to the browser", (fleet_rb() or {}).get("error"), REASON)
    chk("carrying it never leaks the psk", "psk" in next(x for x in P.api_fleet({})["links"]), False)

    P._rebuild_link_impl = lambda d, h=None: {"ok": True, "name": "core4"}
    A.run(P, lambda: P.api_rebuild_link({"id": "L1"}))
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
    # The long timeout belongs to calls that take a long time: the two that carry the core binary, and
    # the install that swaps it and relaunches every core tunnel on the node. Naming them beats counting
    # them -- a count says nothing about WHICH call grew the three-minute wait.
    # A call can wrap over several lines, so flatten the source first and match the endpoint that OPENS
    # the call each mention sits in -- matching per line silently misses a wrapped one and reads as fewer.
    flat = re.sub(r"\s+", " ", src)
    named = sorted(re.findall(r'node_call\(node, "([a-z-]+)".{0,200}?NODE_UPLOAD_TIMEOUT', flat))
    chk("...and only the core install's two steps ask for it by name", named, ["core-apply", "core-put"])
    chk("nothing else takes it but its own definition and node_push's default",
        len(re.findall("NODE_UPLOAD_TIMEOUT", src)) - len(named), 2)

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

    # the job's controls live in the floating pill, never in a card or a row that gets rewritten
    chk("the old page-top cancel row is gone", has(r"pushCancelRow|pushCancelShow|ag_cancel"), False)
    chk("the per-node bar no longer carries its own cancel", has(r"class=\"pxc\""), False)
    chk("the bar draws state and percent only", has(r"function pushBar\(st\)\{"), True)
    fab = re.search(r"function pushFab\(d\)\{(.*?)\n(?:async )?function ", js, re.S)
    fab = fab.group(1) if fab else ""
    chk("the pill carries all three controls",
        all(s in fab for s in ("pushPause(true)", "pushPause(false)", "pushCancel()")), True)
    chk("and it disappears with its job", "if(!live){setHTML(box,'');return}" in fab, True)
    chk("the pill reads paused from the SERVER's job, not a page flag", "d.paused" in fab, True)
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
