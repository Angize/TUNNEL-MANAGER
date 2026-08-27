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
        P.act_start(k2, "t", lambda _h: None)
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
        P.act_step = lambda h, step, i=0, n=0, stop=True: (seen.append((step, i, n)),
                                                           real(h, step, i, n, stop))[1]
        P.node_call = lambda *a, **k: {"ok": True, "configs": []}
        P._node_tunnel = lambda node, body: {"ok": True, "tunnel_ip": "10.9.9.1"}
        h = settled(P, start(P)["act"]) or {}
        got = [s for s, _i, _n in seen]
        miss = [w for w in want if w not in got]
        check(not miss, "%-16s reports %d steps" % (title, len(want)), "missing=%s got=%s" % (miss, got))
        numbered = [(s, i, n) for s, i, n in seen if n]
        check(len(numbered) == len(seen), "%-16s ...every one of them counted" % title,
              [s for s, _i, n in seen if not n])
        check(h.get("state") in ("done", "fail"), "%-16s ...and it reached a verdict" % title,
              "%s %s" % (h.get("state"), h.get("err", "")[:60]))


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
               "console.log(JSON.stringify({rows:out,"
               "pend:pendActs('tunnels').map(function(a){return a.state})}));"
               % (json.dumps([c[0] for c in ROW_CASES]), json.dumps(pend)))
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "t.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" + harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode:
        check(False, "the page's own script runs", (r.stderr or "")[:400])
        return
    got = json.loads(r.stdout.strip().splitlines()[-1])
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
    part_steps(tempfile.mkdtemp())
    part_own_answer(tempfile.mkdtemp())
    part_browser(tempfile.mkdtemp())
    print()
    if FAILS:
        print("%d failure(s)." % len(FAILS))
        return 1
    print("an action answers with a key, reports its own steps, and stops where it runs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
