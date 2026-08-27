#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: an action reports where it runs, and can be stopped there.

Four things the operator hit, all of them from one central queue standing between a request and its
answer, and none of them caught by the guard that watched that queue:

  * «نصبِ نود» handed the browser a QUEUE id and the install's own step list was polled with it, so the
    four steps never filled in;
  * «لغو» on a running job only ever changed a label -- the flag was read once before the work started
    and never again, so the work ran to completion;
  * the progress bar showed 12% or 35%, numbers no action ever wrote;
  * «الان تست کن» on an edge pool returned a ticket, and the box was re-read before the probe was sent.

So the claim is the other way round now. An action that has to talk to a node answers with a KEY and
reports its own steps against it; a request that HAS an answer keeps answering with it. Both halves are
driven here -- the real APIs over a stub fleet, and the real page under node.

Exit 1 on any failure.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import raw_rows_gate_check as G     # noqa: E402  (reuse its DOM prelude)

FAILS = []


def check(ok, msg, detail=""):
    print(("  ok   " if ok else " FAIL ") + msg + (("   " + str(detail)) if not ok and detail else ""))
    if not ok:
        FAILS.append(msg)


def load(state):
    spec = importlib.util.spec_from_file_location("tnl_act_guard", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    root = P.CENTRAL_DIR
    for k in dir(P):                     # sweep, so no constant is left pointing at the real state dir
        v = getattr(P, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(P, k, os.path.join(state, os.path.relpath(v, root)))
    P.CENTRAL_DIR = state
    P.log_event = lambda *a, **k: None
    return P


BODY = {"a_node": "n1", "b_node": "n2", "type": "vxlan", "subnet_base": "192.168"}
NODES = [{"id": "n1", "name": "A", "host": "10.0.0.1", "port": 8099, "token": "t1"},
         {"id": "n2", "name": "B", "host": "10.0.0.2", "port": 8099, "token": "t2"}]
LINK = {"id": "L1", "name": "tun9", "type": "vxlan", "tunnel_id": 9, "subnet": "192.168.9.0/30",
        "a_node": "n1", "a_name": "A", "a_ip": "203.0.113.5",
        "b_node": "n2", "b_name": "B", "b_ip": "198.51.100.7"}


def fleet(P, gate):
    """A two-node fleet whose builds block on `gate`, so a request can be timed against work in flight."""
    P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
    P.save_json(P.LINKS_FILE, [])
    calls = []
    P._ping_both = lambda A, B: ({"ips": {"eth0": ["203.0.113.5"]}}, {"ips": {"eth0": ["198.51.100.7"]}})
    P._refresh_cache = lambda *a, **k: None
    P._cached_ping = lambda nid: {"ok": True}

    def node_call(node, ep, method="POST", body=None, timeout=8, _retry=True):
        calls.append((node["name"], ep))
        return {"ok": True, "configs": []} if ep == "list" else {"ok": True}
    P.node_call = node_call

    def node_tunnel(node, body):
        calls.append((node["name"], "tunnel"))
        gate.wait(20)
        return {"ok": True, "tunnel_ip": "10.9.9.1"}
    P._node_tunnel = node_tunnel
    return calls


def until(fn, secs=15):
    end = time.time() + secs
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.01)
    return None


def settled(P, key):
    return until(lambda: (lambda h: h if h and h["state"] != "run" else None)(P.api_acts({})["acts"].get(key)))


def part_runs(P, calls, gate):
    print("== 1) the request answers before the node does, and the steps are the action's own ==")
    t0 = time.time()
    r = P.api_create_tunnel(dict(BODY))
    dt = time.time() - t0
    key = r.get("act") or ""
    check(bool(key), "a build answers with an action key", r)
    check(dt < 1.0, "...in %.2fs, while the node is still holding its call open" % dt)

    h = until(lambda: (lambda x: x if (x or {}).get("step") == "ساخت روی نودِ «A»" else None)(
        P.api_acts({})["acts"].get(key))) or {}
    check(bool(h), "the action reports the step it is on, by name", h.get("step"))
    check(h.get("si") == 1 and h.get("sn") == 4 and h.get("pct") == 25,
          "...as a step OUT OF a count, so the bar is measured rather than invented",
          "si=%r sn=%r pct=%r" % (h.get("si"), h.get("sn"), h.get("pct")))
    check(h.get("can") is True, "...and says it can still be stopped here")

    print("== 2) cancel lands where the work is, and takes back what it already did ==")
    P.api_act_cancel({"act": key})
    gate.set()                            # node A answers; the panel must stop before it touches B
    h = settled(P, key) or {}
    check(h.get("state") == "cancel", "the action ends cancelled", h.get("state"))
    check(("B", "tunnel") not in calls, "...node B was never built", calls)
    check(("A", "delete") in calls, "...and node A was taken back down", calls)
    check(P.load_links() == [], "...so nothing was left behind on the panel either")

    print("== 3) one place, one action ==")
    gate.clear()
    k2 = P.api_create_tunnel(dict(BODY))["act"]
    until(lambda: (P.api_acts({})["acts"].get(k2) or {}).get("si") == 1)
    try:
        P.act_start(k2, lambda _h: None)
        check(False, "a second action on the same key is refused")
    except ValueError as e:
        check("در جریان است" in str(e), "a second action on the same key is refused", e)
    P.api_act_cancel({"act": k2})
    gate.set()
    settled(P, k2)

    print("== 4) a request the panel refuses never touches a node, and says why ==")
    calls.clear()
    k3 = P.api_create_tunnel({"a_node": "n1", "b_node": "n1", "type": "vxlan"})["act"]
    h = settled(P, k3) or {}
    check(h.get("state") == "fail", "it fails", h.get("state"))
    check(h.get("si") == 0 and not calls, "...before any node was contacted", calls)
    check(bool(h.get("err")), "...and carries the reason", h.get("err"))


# cmd -> (body, "act" | "answer"). An ACTION talks to two nodes and nobody holds still for it, so it
# answers with a key. Everything else is a question with an answer, and handing back a ticket instead
# means the caller reads a verdict that is not there yet.
ROSTER = [
    ("create-tunnel", {"a_node": "n1", "b_node": "n2", "type": "vxlan"}, "act"),
    ("edit-link", {"id": "L1", "type": "vxlan"}, "act"),
    ("rebuild-link", {"id": "L1"}, "act"),
    ("restart-link", {"id": "L1"}, "act"),
    ("delete-link", {"id": "L1"}, "act"),
    # each of these draws its answer onto the thing the operator is looking at, right now
    ("node-install", {"name": "x", "ssh_host": "10.0.0.9", "ssh_pass": "p"}, "answer"),
    ("pool-retest-now", {"id": "L1", "kind": "ip", "key": "k"}, "answer"),
    ("peer-retest-now", {"id": "L1", "kind": "src", "key": "k"}, "answer"),
    ("check-link", {"id": "L1"}, "answer"),
    ("node-test", {"id": "n1"}, "answer"),
    ("proxy-test", {"id": "p1"}, "answer"),
    ("update-agent", {"ids": ["n1"]}, "answer"),
    ("update-core", {"ids": ["n1"]}, "answer"),
    ("flux-rotate", {"id": "L1"}, "answer"),
    ("traffic-reset", {"id": "L1"}, "answer"),
    ("link-toggle", {"id": "L1", "enabled": False}, "answer"),
    ("portfw", {"node": "n1"}, "answer"),
    ("node-adopt-ip", {"id": "n1"}, "answer"),
    ("core-stage", {"version": "latest"}, "answer"),
    ("fleet", {}, "answer"),
    ("summary", {}, "answer"),
]


def part_keep(state):
    """How long a finished action stays where it ran.

    A card is the only place an action is ever shown, so what the panel forgets, the operator can never
    read. A failure has to outlive the moment it happened -- they were not necessarily looking -- while
    a success has said all it has to say. And a RUNNING action is never forgotten, whatever the clock."""
    print("== 4b) a failure waits to be read; a success does not ==")
    P = load(state)
    now = int(time.time())

    def put(st, age, ended=None):
        P._acts.clear()
        P._acts["k"] = {"key": "k", "target": "", "page": "", "ttype": "", "state": st,
                        "step": "", "si": 1, "sn": 4, "pct": 25, "err": "boom", "note": "",
                        "cancel": False, "can": False, "started": now - age - 5,
                        "ended": now - age if ended is None else ended}
        return "k" in P.api_acts({})["acts"]

    check(P.ACT_KEEP_FAIL >= 300, "a failure is kept for minutes, not seconds (%ss)" % P.ACT_KEEP_FAIL)
    for st in ("done", "cancel"):
        check(put(st, 0), "%-6s just finished -> still readable" % st)
        check(not put(st, P.ACT_KEEP + 1), "%-6s a little later    -> forgotten" % st)
    check(put("fail", P.ACT_KEEP + 1), "fail   past a success's window -> STILL readable")
    check(not put("fail", P.ACT_KEEP_FAIL + 1), "fail   long past its own       -> forgotten")
    check(put("run", 0, ended=0), "a running action is never forgotten, whatever the clock says")


def part_roster(state):
    print("== 5) every endpoint the browser posts answers in its own shape ==")
    P = load(state)
    P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
    P.save_json(P.LINKS_FILE, [dict(LINK)])
    # The REAL API map, over a fleet that answers everything: nothing stands between a command and its
    # own function any more, so what a name answers with is the function's own doing and has to be read
    # from it. A refusal counts as an answer -- what must never come back is a key to something else.
    P._ping_both = lambda A, B: ({"ips": {"eth0": ["203.0.113.5"]}}, {"ips": {"eth0": ["198.51.100.7"]}})
    P._refresh_cache = lambda *a, **k: None
    P._cached_ping = lambda nid: {"ok": True}
    P.node_call = lambda *a, **k: {"ok": True, "configs": []}
    P._node_tunnel = lambda node, body: {"ok": True, "tunnel_ip": "10.9.9.1"}
    P._push_start = lambda kind, nodes, plan: "PUSHJID"
    P._stage_core = lambda v: {"ok": True, "version": v}
    for cmd, body, want in ROSTER:
        if cmd not in P.API:
            check(False, "%-18s is still an endpoint" % cmd)
            continue
        try:
            got = P._dispatch(cmd, dict(body))
        except ValueError as e:
            got = {"refused": str(e)[:60]}
        except Exception as e:
            check(False, "%-18s -> %s" % (cmd, want), "%s: %s" % (type(e).__name__, e))
            continue
        is_act = bool(isinstance(got, dict) and got.get("act"))
        check(is_act == (want == "act"), "%-18s -> %s" % (cmd, want),
              json.dumps(got, ensure_ascii=False)[:90])
        if is_act:
            settled(P, got["act"])   # four of these share one key: let each finish before the next asks


# Every action, and a step it MUST have reported by the time it is done. One sample proves one path;
# these are five independent functions, and the queue that came before reported nothing on any of them.
STEPS = [
    ("ساختِ تونل", lambda P: P.api_create_tunnel({"a_node": "n1", "b_node": "n2", "type": "vxlan"}),
     ["خواندنِ وضعیتِ دو نود", "ساخت روی نودِ «A»", "ساخت روی نودِ «B»", "ثبتِ تونل"]),
    ("ویرایشِ تونل", lambda P: P.api_edit_link({"id": "L1", "type": "vxlan", "subnet": "192.168.40.0/30"}),
     ["خواندنِ وضعیتِ دو نود", "اعمال روی نودِ «A»", "اعمال روی نودِ «B»", "ثبتِ تغییر"]),
    ("بازسازیِ تونل", lambda P: P.api_rebuild_link({"id": "L1"}),
     ["خواندنِ وضعیتِ دو نود", "برچیدنِ هر دو سر", "ساخت روی نودِ «A»", "ساخت روی نودِ «B»"]),
    ("ری‌استارتِ هسته", lambda P: P.api_restart_link({"id": "L1"}),
     ["ری‌استارتِ هسته روی نودِ «A»", "ری‌استارتِ هسته روی نودِ «B»"]),
    ("حذفِ تونل", lambda P: P.api_delete_link({"id": "L1"}),
     ["بررسیِ دو سر", "برچیدنِ تونل روی دو نود", "برداشتنِ رکورد"]),
]


def part_steps(state):
    print("== 5b) each of the five reports its OWN steps, not one sample's ==")
    for title, start, want in STEPS:
        P = load(state)
        P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
        P.save_json(P.LINKS_FILE, [dict(LINK, type="core", server_side="a", transport="udp",
                                        psk="x" * 44, cipher="auto", port=20001)])
        P._ping_both = lambda A, B: ({"ips": {"eth0": ["203.0.113.5"]}}, {"ips": {"eth0": ["198.51.100.7"]}})
        P._refresh_cache = lambda *a, **k: None
        P._cached_ping = lambda nid: {"ok": True}
        P._readiness = lambda: {"agent": True, "core": True, "core_missing": [], "ok": True}
        seen = []
        # The steps are watched from INSIDE, because a poll can miss one that passes between two reads.
        real = P.act_step
        # *a/**kw on purpose: a spy that spells the signature out goes stale the moment act_step grows
        # an argument, and then every action "fails" for a reason that has nothing to do with the panel.
        def watch(h, step, i=0, n=0, *a, **kw):
            seen.append((step, i, n))
            return real(h, step, i, n, *a, **kw)
        P.act_step = watch
        P.node_call = lambda *a, **k: {"ok": True, "configs": []}
        P._node_tunnel = lambda node, body: {"ok": True, "tunnel_ip": "10.9.9.1"}
        h = settled(P, start(P)["act"]) or {}
        got = [s for s, _i, _n in seen]
        miss = [w for w in want if w not in got]
        check(not miss, "%-16s reports %d steps" % (title, len(want)), "missing=%s got=%s" % (miss, got))
        numbered = [(s, i, n) for s, i, n in seen if n]
        check(len(numbered) == len(seen), "%-16s ...every one of them counted" % title,
              [s for s, _i, n in seen if not n])
        check(h.get("state") == "done", "%-16s ...and it finished" % title,
              "%s %s" % (h.get("state"), h.get("err", "")[:60]))


def part_promise(state):
    """The button's promise, at EVERY step of EVERY action.

    `can` is what the page draws «لغو» from, and a press lands at the action's NEXT checkpoint -- not
    the one it is standing on. So a step that is itself a safe place to stop can still be the LAST one,
    and saying «you can stop this» while the final node write is in flight draws a button that does
    nothing. This holds each action still at each of its steps, presses cancel, and checks the promise
    against what actually happened."""
    print("== 5c) whenever the page may draw «لغو», pressing it lands ==")
    for title, start, _steps in STEPS:
        P = load(state)
        P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
        idx = 0
        while True:                    # once per step of this action
            P = load(state)
            P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
            P.save_json(P.LINKS_FILE, [dict(LINK, type="core", server_side="a", transport="udp",
                                            psk="x" * 44, cipher="auto", port=20001)])
            P._ping_both = lambda A, B: ({"ips": {"eth0": ["203.0.113.5"]}},
                                         {"ips": {"eth0": ["198.51.100.7"]}})
            P._refresh_cache = lambda *a, **k: None
            P._cached_ping = lambda nid: {"ok": True}
            P._readiness = lambda: {"agent": True, "core": True, "core_missing": [], "ok": True}
            P.node_call = lambda *a, **k: {"ok": True, "configs": []}
            P._node_tunnel = lambda node, body: {"ok": True, "tunnel_ip": "10.9.9.1"}
            here = {"n": 0, "at": idx, "can": None, "step": "", "hit": threading.Event()}
            realstep = P.act_step

            def step(h, s, i=0, n=0, *a, _h=here, _r=realstep, **kw):
                _r(h, s, i, n, *a, **kw)
                if _h["n"] == _h["at"]:
                    _h["can"] = bool(h["can"])
                    _h["step"] = s
                    _h["hit"].set()
                    time.sleep(0.15)   # the cancel lands while this step is the one in flight
                _h["n"] += 1
            P.act_step = step
            r = start(P)
            if not here["hit"].wait(5):
                break                  # this action has no step number `idx`; every one was covered
            try:                       # pressed once, whatever the promise was, and both halves checked
                P.api_act_cancel({"act": r["act"]})
                refused = False
            except ValueError:
                refused = True
            h = settled(P, r["act"]) or {}
            where = "%-16s step %d «%s»" % (title, idx, here["step"])
            if here["can"]:
                check(not refused and h.get("state") == "cancel",
                      "%s promised a stop -- and it landed" % where,
                      "state=%s refused=%s" % (h.get("state"), refused))
            else:
                check(refused and h.get("state") != "cancel",
                      "%s promised nothing -- and the press was refused" % where,
                      "state=%s refused=%s" % (h.get("state"), refused))
            idx += 1
            if idx > 8:
                break


def part_own_answer(state):
    print("== 6) an endpoint that has its OWN progress is not wrapped in something else's ==")
    P = load(state)
    P.save_json(P.NODES_FILE, [dict(NODES[0])])
    P.save_json(P.LINKS_FILE, [])
    P._readiness = lambda: {"agent": True, "core": True, "core_missing": [], "ok": True}
    P._install_worker = lambda *a, **k: None
    r = P._dispatch("node-install", {"name": "new", "ssh_host": "10.0.0.9", "ssh_pass": "p"})
    jid = (r or {}).get("job") or ""
    check(bool(jid), "«نصبِ نود» answers with an id", r)
    try:
        st = P.api_node_install_status({"job": jid})
        check(bool(st.get("steps")), "...and it is an id the install's own step list knows", st.get("steps"))
    except ValueError as e:
        check(False, "...and it is an id the install's own step list knows", e)

    # The edge pool's «الان تست کن»: the operator presses it and watches the box beside it for the
    # answer, so it must reach the node inside the request. Queued, the box was re-read seconds before
    # anything was sent. What is asserted is the SIGHUP going out under the caller, and no key coming
    # back -- both, because either one alone can be true of a button that does nothing.
    P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
    P.save_json(P.LINKS_FILE, [dict(LINK, type="core", transport="ws", server_side="a")])
    sent = []
    P.node_call = lambda node, ep, *a, **k: (sent.append(ep), {"ok": True})[1]
    P._ws_pool_client = lambda d: (dict(LINK), dict(NODES[1]))
    pr = P._dispatch("pool-retest-now", {"id": "L1", "kind": "ip", "key": "k"})
    check(isinstance(pr, dict) and not pr.get("act"),
          "«الان تست کن» answers with its own verdict, not a ticket", pr)
    check("retest-now" in sent, "...and the node was told inside the request", sent)


# a handle, and what the row it draws must and must not offer
ROW_CASES = [
    ({"key": "link:L1", "state": "run", "can": True, "step": "ساخت روی نودِ «A»", "si": 1, "sn": 4,
      "pct": 25, "err": "", "note": "", "started": 100, "ended": 0},
     ["actCancel", "width:25%", "ساخت روی نودِ"], ["actDismiss", "abar spin"]),
    ({"key": "link:L1", "state": "run", "can": False, "step": "ثبتِ تونل", "si": 3, "sn": 4,
      "pct": 75, "err": "", "note": "", "started": 100, "ended": 0},
     ["width:75%"], ["actCancel", "actDismiss"]),
    ({"key": "link:L1", "state": "run", "can": True, "step": "", "si": 0, "sn": 0,
      "pct": 0, "err": "", "note": "", "started": 100, "ended": 0},
     ["abar spin", "actCancel"], ["actDismiss", "width:"]),
    ({"key": "link:L1", "state": "fail", "can": False, "step": "", "si": 1, "sn": 4, "pct": 25,
      "err": "RTNETLINK answers: File exists", "note": "", "started": 100, "ended": 160},
     ["actDismiss"], ["actCancel", "RTNETLINK"]),
    ({"key": "link:L1", "state": "cancel", "can": False, "step": "", "si": 1, "sn": 4, "pct": 25,
      "err": "", "note": "", "started": 100, "ended": 160},
     ["actDismiss"], ["actCancel"]),
    ({"key": "link:L1", "state": "done", "can": False, "step": "", "si": 4, "sn": 4, "pct": 100,
      "err": "", "note": "", "started": 100, "ended": 160},
     ["actDismiss"], ["actCancel"]),
]

# Matched on a word boundary: apendCard contains "pendCard", and a bare substring would read the new
# name as the old one still being there.
DEAD = ["JOBQ", "jobRow", "jobRowOf", "pendCard", "refreshJobs", "queueSkel", "paintQueue",
        "qJobCard", "jobGoto", "jobCancel", "jobRetry", "jobForget", "jobsClear", "jobPct",
        'data-t="queue"', "'job-cancel'", "'job-retry'", "'job-clear'", "j('jobs')"]


# A press on a card has to SHOW something. Re-reading the actions is not drawing them: the row lives on
# a card, cards come from the fleet list, and only a BUILD changes that list's shape -- so the four that
# act on an existing tunnel are the ones that sat silent until the next poll came round.
# What a form does while the panel makes up its mind. si is the signal: step 0 is what the panel reads
# and checks, and everything past it is already written to a node -- so a refusal (an overlapping
# subnet, a port already taken) has to reach the operator while the form they can fix is still open. A
# form that closed first would take everything they typed with it.
ACCEPT = r"""
var FEED=[],SEEN=0;
// the DOM stub's setTimeout never fires, and actAccepted sleeps between polls -- so give it one
// that lands on the microtask queue: same order, no wall clock
globalThis.setTimeout=function(f){Promise.resolve().then(f);return 0};
globalThis.fetch=function(){var a=FEED[Math.min(SEEN++,FEED.length-1)];
 return Promise.resolve({ok:true,json:function(){
  return Promise.resolve({ok:true,acts:a?{'k':a}:{},now:1})}})};
function A(st,si,err){return {key:'k',state:st,si:si,sn:4,pct:si*25,can:true,step:'',err:err||'',
                              note:'',started:0,ended:0}}
var box={isConnected:true};
async function verdict(feed,live){FEED=feed;SEEN=0;box.isConnected=live!==false;
 return await actAccepted('k',box)}
var out={};
(async function(){
 // it waits while the panel is still reading, then lets go the moment a node is being written to
 out.readingThenAccepted=await verdict([A('run',0),A('run',0),A('run',1)]);
 // a refusal at step 0 comes back as something to show IN the form
 out.refusedBeforeAnyNode=await verdict([A('run',0),A('fail',0,'سابنت با تونلِ دیگری تداخل دارد')]);
 // an edit that changed nothing never leaves step 0 -- and must not hold the form open either
 out.finishedAtStepZero=await verdict([A('done',0)]);
 out.stoppedByHand=await verdict([A('run',0),A('cancel',0)]);
 out.alreadyForgotten=await verdict([null]);
 // and it lets go at once when the operator closed the form themselves
 out.formClosed=await verdict([A('run',0)],false);
 console.log(JSON.stringify(out));
})();
"""

PRESS = r"""
var pendStates=pendActs('tunnels').map(function(a){return a.state});   // read before the press clears it
cur='tunnels'; FLEET=[]; ACTS={}; ADISM={};
confirmBox=function(){return Promise.resolve(true)};
post=function(){return Promise.resolve({ok:true,d:{ok:true,act:'link:L1'}})};
refreshActs=function(){return Promise.resolve()};
toast=function(){}; setChk=function(){};
var drew={};
(async function(){
 var cases=[['rebuild',function(){return rebuildLink('L1')}],
            ['restart',function(){return restartLink('L1')}],
            ['delete', function(){return delLink('L1')}],
            ['cancel', function(){return actCancel('link:L1')}]];
 for(var i=0;i<cases.length;i++){
  var name=cases[i][0]; drew[name]=false;
  refreshFleet=(function(n){return function(){drew[n]=true;return Promise.resolve()}})(name);
  await cases[i][1]();
  for(var k=0;k<8;k++)await Promise.resolve();     // let the handler's own tail settle
 }
 console.log(JSON.stringify({rows:out,pend:pendStates,cardShowsAtOnce:drew}));
})();
"""


def part_wire(state):
    """Everything an action puts on the wire is something the page reads.

    A field nobody reads is a field nobody maintains, and it is read as a promise by whoever comes next.
    The handle is taken from a REAL action rather than a list here, so a field added to it and forgotten
    is caught the same day it is added."""
    print("== 6b) the wire carries what the page reads, and nothing else ==")
    P = load(state)
    P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
    P.save_json(P.LINKS_FILE, [])
    P._ping_both = lambda a, b: ({"ips": {"eth0": ["203.0.113.5"]}}, {"ips": {"eth0": ["198.51.100.7"]}})
    P._refresh_cache = lambda *a, **k: None
    P.node_call = lambda *a, **k: {"ok": True, "configs": []}
    P._node_tunnel = lambda n, b: {"ok": True, "tunnel_ip": "x"}
    r = P.api_create_tunnel({"a_node": "n1", "b_node": "n2", "type": "vxlan"})
    settled(P, r["act"])
    check(sorted(r) == ["act", "ok"], "starting one answers with the key and nothing else", sorted(r))
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    h = P.api_acts({})["acts"][r["act"]]
    # Grepping for `a.field` would pass on a coincidence -- any function with a local named `a` and a
    # matching property satisfies it. So the PAGE reads the handle instead, through a proxy that records
    # which keys it touched, and a field nothing reached is a field nothing reads.
    reached = _touched(js, h)
    unread = [f for f in sorted(h) if f not in reached]
    check(not unread, "every field on a handle is one the page reads", unread)


def _touched(js, handle):
    """Which of a handle's fields the page reads -- by letting it read one, in every state it can be in.

    A field is justified if SOME reachable state reads it: the row draws different things while it runs,
    when it fails and when it is done, and the placeholder reads what a card never does. Grepping for
    `a.field` instead would pass on any coincidence in a page this size."""
    states = [dict(handle, key="link:L1", state="run", can=True, si=1, sn=4, pct=25),
              dict(handle, key="link:L1", state="run", can=False, si=3, sn=4, pct=75),
              dict(handle, key="link:L1", state="run", can=True, si=0, sn=0, pct=0),
              dict(handle, key="link:L1", state="fail", err="boom", ended=9),
              dict(handle, key="link:L1", state="cancel", ended=9),
              dict(handle, key="link:L1", state="done", note="n", ended=9),
              dict(handle, key="new:ab", state="run", page="tunnels", can=True, si=1, sn=4)]
    harness = ("""
var HIT={};
function prox(a){return new Proxy(a,{get:function(t,k){HIT[k]=true;return t[k]}})}
var STATES=%s;
try{ACTNOW=9e9}catch(e){}
STATES.forEach(function(H){
 try{ADISM={};_ASTEP={};actRow(prox(H))}catch(e){}
 try{apendCard(prox(H))}catch(e){}
 try{ACTS={};ACTS[H.key]=prox(H);pendActs('tunnels');withPending('tunnels',[])}catch(e){}
 try{ACTS={};ACTS['link:L1']=prox(H);actOf({id:'L1'});cardActCls({id:'L1'})}catch(e){}
});
globalThis.setTimeout=function(f){Promise.resolve().then(f);return 0};
globalThis.fetch=function(){return Promise.resolve({ok:true,json:function(){
  return Promise.resolve({ok:true,acts:{'k':prox(STATES[0])},now:1})}})};
actAccepted('k').then(function(){console.log(JSON.stringify(Object.keys(HIT)))},
                      function(){console.log(JSON.stringify(Object.keys(HIT)))});
""" % json.dumps(states, ensure_ascii=False))
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "w.js"
        f.write_text(G.PRELUDE + chr(10) + js + chr(10) + harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode or not r.stdout.strip():
        raise AssertionError("the page would not read a handle: " + (r.stderr or "")[:300])
    return set(json.loads(r.stdout.strip().splitlines()[-1]))


def part_browser(state):
    print("== 7) the page draws the action, and nothing of the queue is left in it ==")
    P = load(state)
    page = P.INDEX_HTML
    left = [d for d in DEAD if re.search(r"\b" + re.escape(d), page)]
    check(not left, "no queue symbol is left in the page", left)

    js = max(re.findall(r"<script[^>]*>(.*?)</script>", page, re.S), key=len)
    # ...and the placeholder for a build: it must go the moment a real card exists to replace it, and
    # stay when there is none, or the list shows two tunnels where the operator asked for one.
    pend = [dict(s, key="new:" + s["state"], page="tunnels", ttype="vxlan", target="A ↔ B",
                 can=True, step="", si=0, sn=4, pct=0, err="", note="", started=100, ended=150)
            for s in ({"state": "run"}, {"state": "done"}, {"state": "fail"}, {"state": "cancel"})]
    harness = ("ACTNOW=200;\nconst out=%s.map(function(a){ACTS={};ACTS[a.key]=a;_ASTEP={};"
               "return actRow(a)});\nACTS={};ADISM={};%s.forEach(function(a){ACTS[a.key]=a});\n"
               % (json.dumps([c[0] for c in ROW_CASES]), json.dumps(pend))) + PRESS
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "t.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" + harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode:
        check(False, "the page's own script runs", (r.stderr or "")[:400])
        return
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "a.js"
        f.write_text(G.PRELUDE + chr(10) + js + chr(10) + ACCEPT, encoding="utf-8")
        ra = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if ra.returncode or not ra.stdout.strip():
        check(False, "the form's own wait runs", (ra.stderr or "")[:400])
    else:
        v = json.loads(ra.stdout.strip().splitlines()[-1])
        check(v["readingThenAccepted"] == {"ok": True},
              "the form waits while the panel reads, then lets go at the first node write",
              v["readingThenAccepted"])
        check("تداخل" in (v["refusedBeforeAnyNode"].get("err") or ""),
              "a refusal before any node comes back for the form to show", v["refusedBeforeAnyNode"])
        check(v["finishedAtStepZero"] == {"ok": True},
              "an action that finished at step 0 does not hold the form open", v["finishedAtStepZero"])
        check(bool(v["stoppedByHand"].get("err")), "a stop comes back as something to say",
              v["stoppedByHand"])
        check(v["alreadyForgotten"] == {"ok": True},
              "an action already forgotten is not an error", v["alreadyForgotten"])
        check(v["formClosed"] == {"gone": True},
              "and it lets go at once when the operator closed the form", v["formClosed"])

    got = json.loads(r.stdout.strip().splitlines()[-1])
    check(got["cardShowsAtOnce"] == {"rebuild": True, "restart": True, "delete": True, "cancel": True},
          "a press on a card draws its row without waiting for the next poll", got["cardShowsAtOnce"])
    check(sorted(got["pend"]) == ["cancel", "fail", "run"],
          "a build stops being a placeholder the moment its real card exists", got["pend"])
    for (a, must, mustnot), html in zip(ROW_CASES, got["rows"]):
        lbl = a["state"] if a["state"] != "run" else ("run/can" if a["can"] else "run/final")
        miss = [m for m in must if m not in html]
        extra = [m for m in mustnot if m in html]
        check(not miss and not extra, "%-9s row offers %s and not %s" % (lbl, must, mustnot),
              "missing=%s unexpected=%s  %s" % (miss, extra, html[:150]))


def main():
    gate = threading.Event()
    P = load(tempfile.mkdtemp())
    part_runs(P, fleet(P, gate), gate)
    part_roster(tempfile.mkdtemp())
    part_keep(tempfile.mkdtemp())
    part_steps(tempfile.mkdtemp())
    part_promise(tempfile.mkdtemp())
    part_own_answer(tempfile.mkdtemp())
    part_wire(tempfile.mkdtemp())
    part_browser(tempfile.mkdtemp())
    print()
    if FAILS:
        print("%d failure(s)." % len(FAILS))
        return 1
    print("an action answers with a key, reports its own steps, and stops where it runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
