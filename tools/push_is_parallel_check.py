#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The agent/core upload runs several nodes at once -- but a BOUNDED number -- and no node can end the sweep.

Properties, all operator-stated, all easy to lose in a refactor:

  * PARALLEL, WITH A CEILING -- one worker per node, capped at PUSH_CAP. #480 removed the old shared
    semaphore after measuring it: two jobs blocked each other and a fleet of 37 went out four at a time
    (peak 4 before, peak 12 after, 3.3s to under 1s). So the fleet-sized run must put EVERY node in
    flight, and the cap must still hold a queue back when the fleet is bigger than it. The cap tests
    below lower PUSH_CAP on the module so a queue exists to observe at a 10-node fixture size.
  * a node that FAILS or TIMES OUT is recorded and the pool KEEPS GOING. One dead node must not take the
    whole sweep's result with it.
  * the progress a node reports is the bytes actually sent, not a phase guess, and it only moves forward.
  * PAUSE is the gentle stop: the nodes still waiting are held, the in-flight ones finish, RESUME drains
    the rest. CANCEL is the immediate one: the queue is skipped the instant it returns AND the in-flight
    sockets are dropped mid-body. Safe, because the node parses and checksums before it touches disk.

Driven against the real _push_worker with node_push faked, so what is tested is what the panel performs.

    python3 tools/push_is_parallel_check.py
"""
import argparse
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path

# The bounded-queue sections lower the module's PUSH_CAP to this, so a 10-node fixture still leaves a
# queue behind the ceiling. The real cap is 256: at fixture size every node would be in flight and the
# "what is still waiting" assertions would be vacuously true.
CAP = 4

# what _push_worker takes now: an ordered list of steps, each (code, endpoint, build, timeout, gate).
# build is called as build(node, ctx) -- the ctx carries the job/node ids and the bar's position.
PLAN = [("deliver", "update", lambda n, ctx: {"code": "x"}, 60, None)]

NODES = [{"id": "n%d" % i, "name": "N%d" % i, "host": "10.0.0.%d" % i, "port": 8099, "token": "t"}
         for i in (1, 2, 3, 4)]


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    spec = importlib.util.spec_from_file_location("tnl_central", str(a.panel))
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    REAL_PUSH = P.node_push      # the sections below replace it; this one section needs the real thing
    failures = []

    def chk(label, got, want):
        if got != want:
            failures.append("%s: got %r, expected %r" % (label, got, want))
        else:
            print("  ok   %-56s %r" % (label, got))

    P.get_node = lambda nid: next((n for n in NODES if n["id"] == nid), None)
    P._ensure_update_key = lambda n: None

    # ---- bounded parallelism, on a fleet larger than the pool
    BIG = [{"id": "b%02d" % i, "name": "B%d" % i} for i in range(10)]
    P.get_node = lambda nid: next((n for n in NODES + BIG if n["id"] == nid), None)
    starts, peak = [], {"cur": 0, "max": 0}
    lock = threading.Lock()

    def wide_push(node, endpoint, body, on_progress=None, timeout=200, should_abort=None):
        with lock:
            starts.append(node["id"])
            peak["cur"] += 1
            peak["max"] = max(peak["max"], peak["cur"])
        on_progress and on_progress(500, 1000)
        time.sleep(0.05)
        with lock:
            peak["cur"] -= 1
        return {"ok": True}

    P.node_push = wide_push
    jb = P._push_job_new("core", BIG)
    P._push_worker(jb, "core", BIG, PLAN)
    chk("more than one node uploads at a time", peak["max"] >= 2, True)
    chk("but never more than PUSH_CAP", peak["max"] <= P.PUSH_CAP, True)
    chk("a fleet smaller than the cap puts EVERY node in flight at once (this is what #480 bought)",
        peak["max"], len(BIG))
    chk("every node in the fleet was pushed to", sorted(starts), sorted(n["id"] for n in BIG))
    chk("a node is claimed and labelled in one write, never «running» with no step",
        all(v.get("step") for v in P.api_push_status({"job": jb})["nodes"].values()), True)
    chk("every node was claimed exactly once", sorted(starts), sorted(n["id"] for n in BIG))
    sb = P.api_push_status({"job": jb})
    chk("and every one of them reports done", sorted({v["state"] for v in sb["nodes"].values()}), ["ok"])

    # ---- a failure is charged to its own node only
    timeline = []

    def fake_push(node, endpoint, body, on_progress=None, timeout=200, should_abort=None):
        nid = node["id"]
        timeline.append(("start", nid))
        for sent in (0, 250, 500, 1000):     # a real push reports bytes as they go
            on_progress(sent, 1000)
            time.sleep(0.002)
        timeline.append(("end", nid))
        if nid == "n2":
            return {"ok": False, "offline": True, "error": "timed out"}   # the dead node
        if nid == "n3":
            raise OSError("connection reset")                             # a surprise, mid-sweep
        return {"ok": True, "restarting": True}

    P.node_push = fake_push
    jid = P._push_job_new("agent", NODES)
    P._push_worker(jid, "agent", NODES, PLAN)
    st = P.api_push_status({"job": jid})
    chk("the job finishes", st["done"], True)
    chk("every node is reported", sorted(st["nodes"]), ["n1", "n2", "n3", "n4"])
    chk("a node that answers ok reaches 100", (st["nodes"]["n1"]["state"], st["nodes"]["n1"]["pct"]),
        ("ok", 100))
    # the CODE picks the operator's word; the node's own sentence rides along as the detail, because
    # «شکست خورد» on its own tells nobody which of a dozen reasons it was
    chk("the node that TIMED OUT is marked, with its reason",
        (st["nodes"]["n2"]["state"], st["nodes"]["n2"]["err"], st["nodes"]["n2"]["detail"]),
        ("err", "offline", "timed out"))
    chk("a node that RAISED mid-sweep is marked too", st["nodes"]["n3"]["state"], "err")
    chk("the failures did not stop the others",
        (st["nodes"]["n4"]["state"], st["nodes"]["n4"]["pct"]), ("ok", 100))
    chk("no node was started twice", len([1 for k, _ in timeline if k == "start"]), 4)

    # progress must be real and monotonic: replay ONE node and watch the published pct
    seen = []
    P.node_push = lambda node, ep, body, on_progress=None, timeout=200, should_abort=None: (
        [on_progress(s, 1000) or seen.append(P.api_push_status({"job": j2})["nodes"]["n1"]["pct"])
         for s in (0, 100, 500, 900, 1000)] and {"ok": True})
    j2 = P._push_job_new("agent", [NODES[0]])
    P._push_worker(j2, "agent", [NODES[0]], PLAN)
    # the last sample is 96, not 95: the final byte flips the node to «apply», because past that point
    # the node holds the whole body and installs it whatever the panel does
    chk("the bar tracks bytes, not phases", seen, [0, 9, 47, 85, 96])
    chk("and the last byte leaves it working, before the reply arrives",
        P.api_push_status({"job": j2})["nodes"]["n1"]["state"] in ("run", "ok", "same"), True)
    chk("it never goes backwards", seen == sorted(seen), True)
    chk("the last 5% belong to the node's own verify+swap",
        P.api_push_status({"job": j2})["nodes"]["n1"]["pct"], 100)

    # ---- the bar covers the WHOLE plan, and never rewinds. Per step it reset to zero at every boundary,
    # so a core install (three steps) rewound twice, which reads as the upload having started over.
    seen3 = []

    def three_push(node, endpoint, body, on_progress=None, timeout=200, should_abort=None):
        total = 1000 if endpoint == "big" else 4
        for s in (0, total // 4, total // 2, total):
            on_progress(s, total)
            seen3.append(P.api_push_status({"job": j3})["nodes"]["n1"]["pct"])
        return {"ok": True}

    P.node_push = three_push
    PLAN3 = [("check", "ping", lambda _n, _c: {}, 15, lambda r: False),
             ("deliver", "big", lambda _n, _c: {"d": "x"}, 60, None),
             ("install", "apply", lambda _n, _c: {"a": 1}, 60, None)]
    j3 = P._push_job_new("core", [NODES[0]])
    P._push_worker(j3, "core", [NODES[0]], PLAN3)
    fin = P.api_push_status({"job": j3})["nodes"]["n1"]
    chk("the three-step plan actually ran (an empty trace would pass every check below)",
        len(seen3), 12)
    chk("three steps, and the bar never goes backwards", seen3 == sorted(seen3), True)
    chk("...it starts at zero and ends at a hundred", (seen3[0], fin["pct"]), (0, 100))
    chk("...and each step lands on its own share of the bar rather than restarting",
        (max(s for s in seen3 if s < 34) >= 30, max(s for s in seen3 if s < 67) >= 63), (True, True))
    chk("the row says which step of how many", (fin["si"], fin["sn"]), (3, 3))
    jq = P._push_job_new("agent", [NODES[0]])
    P._push_next(jq, (PLAN3[0][0], len(PLAN3)))
    stq = P.api_push_status({"job": jq})["nodes"]["n1"]
    chk("a node still queued carries the count the first step will publish", (stq["si"], stq["sn"]), (1, 3))
    with P._push_lock:                      # this job exists only to be inspected; leaving it live would
        P._push_jobs[jq]["done"] = True     # hold n1 busy for every later section

    # ---- cancel means NOW: the queue is skipped AND the in-flight sockets are dropped mid-body. The fake
    # honours should_abort the way the real node_push does, so what is tested is _push_one's wiring of it.
    gate = threading.Event()
    reached, aborted = [], []

    def cancel_push(node, endpoint, body, on_progress=None, timeout=200, should_abort=None):
        reached.append(node["id"])
        gate.wait(2)                          # hold the first PUSH_WORKERS nodes in flight
        if should_abort and should_abort():    # a real push checks this between chunks AND while waiting
            aborted.append(node["id"])
            return {"ok": False, "cancelled": True, "delivered": False}
        on_progress and on_progress(1, 1)
        return {"ok": True}

    P.node_push = cancel_push
    P.PUSH_CAP = CAP                          # hold a queue back so there is something to skip
    jc = P._push_job_new("agent", BIG)
    tc = threading.Thread(target=P._push_worker,
                          args=(jc, "agent", BIG, PLAN), daemon=True)
    tc.start()
    while len(reached) < CAP:
        time.sleep(0.01)
    P.api_push_cancel({"job": jc})
    sc_mid = P.api_push_status({"job": jc})
    chk("the queue is skipped the INSTANT cancel returns, not when a worker next asks",
        sorted({v["state"] for nid, v in sc_mid["nodes"].items() if nid not in reached}), ["skip"])
    gate.set()
    tc.join(timeout=8)
    sc = P.api_push_status({"job": jc})
    chk("_push_one really passes should_abort down", sorted(aborted), sorted(reached))
    chk("the nodes that were mid-upload are cut off and read skip",
        sorted({sc["nodes"][nid]["state"] for nid in reached}), ["skip"])
    chk("no node past the cap was ever started", len(reached), CAP)
    chk("so after a cancel nothing reads ok", sorted({v["state"] for v in sc["nodes"].values()}), ["skip"])
    chk("and the job still reports itself finished", sc["done"], True)
    # What this protects is that pushAdopt does not reattach to a job that is over. It used to be
    # spelled "_push_merged() is None", because the merged view vanished with the last live job -- and
    # that is exactly what left the final poll with nothing to paint. The merged view now survives the
    # end of a batch, so the claim is made where the browser makes it: on `done`.
    chk("a cancelled job reports itself done, which is what pushAdopt refuses to reattach to",
        (P._push_merged() or {}).get("done"), True)

    # a cut-off node must never be charged an error: it was the operator's choice, not a failure
    chk("a cut-off node carries no error text",
        sorted({sc["nodes"][nid].get("err") or "" for nid in reached}), [""])

    # ---- cancel while the ANSWER is awaited, not only while bytes move. This is the half that used to
    # be missing: the body of an install step is tiny, so the operator spends the whole step waiting for
    # a node that is swapping a binary and relaunching tunnels -- with a 300s timeout behind it. A cancel
    # that only reached the send loop did nothing at all there, and the row still ended «انجام شد».
    import socket as _s, threading as _t
    srv = _s.socket(); srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(4)
    port = srv.getsockname()[1]
    held = []

    def deaf():
        """Read the whole request and then never answer -- a node that is busy installing."""
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            held.append(c)                       # kept open: closing it would be an EOF, not a wait
            try:
                c.recv(65536)
            except Exception:
                pass

    _t.Thread(target=deaf, daemon=True).start()
    node = {"id": "slow", "name": "SLOW", "host": "127.0.0.1", "port": port, "token": "t"}
    P.node_proxy = lambda n: None
    P._auth_headers = lambda n, m, p, b: {"X-Auth": "x"}
    flag = {"go": False}
    t0 = time.time()
    out = {}
    th = _t.Thread(target=lambda: out.update(
        REAL_PUSH(node, "core-apply", {"sha256": "a" * 64}, timeout=300,
                  should_abort=lambda: flag["go"]) or {}), daemon=True)
    th.start()
    time.sleep(0.6)                       # the body is long gone; we are in the wait
    chk("...and the step really is waiting, not still sending", th.is_alive(), True)
    flag["go"] = True
    th.join(timeout=5)
    took = time.time() - t0
    chk("a cancel while the node's answer is awaited comes back", out.get("cancelled"), True)
    chk("...in well under the step's own timeout", took < 3, True)
    chk("...and says the node already had the whole request, so the row cannot claim it was untouched",
        out.get("delivered"), True)
    for c in held:
        try:
            c.close()
        except Exception:
            pass
    srv.close()

    # ---- pause holds the waiting nodes; resume drains them
    gate2 = threading.Event()
    seen2 = []

    def slow_push(node, endpoint, body, on_progress=None, timeout=200, should_abort=None):
        seen2.append(node["id"])
        gate2.wait(2)
        on_progress and on_progress(1, 1)
        return {"ok": True}

    P.node_push = slow_push
    P.PUSH_CAP = CAP
    jp = P._push_job_new("core", BIG)
    tp = threading.Thread(target=P._push_worker,
                          args=(jp, "core", BIG, PLAN), daemon=True)
    tp.start()
    while len(seen2) < CAP:
        time.sleep(0.01)
    P.api_push_pause({"job": jp, "paused": True})
    gate2.set()                               # let the in-flight ones finish
    time.sleep(0.4)                           # ...and give a broken pause time to hand out more
    chk("pause reports itself", P.api_push_status({"job": jp})["paused"], True)
    chk("the in-flight nodes still finished",
        len([1 for v in P.api_push_status({"job": jp})["nodes"].values() if v["state"] == "ok"]),
        CAP)
    chk("no node past the cap was handed out while paused", len(seen2), CAP)
    chk("a paused job is NOT done", P.api_push_status({"job": jp})["done"], False)
    P.api_push_pause({"job": jp, "paused": False})
    tp.join(timeout=8)
    sp = P.api_push_status({"job": jp})
    chk("resume drains the rest", sorted({v["state"] for v in sp["nodes"].values()}), ["ok"])
    chk("and only then is the job done", sp["done"], True)
    chk("pausing a finished job changes nothing", P.api_push_pause({"job": jp, "paused": True}),
        {"ok": True, "done": True})

    # ---- reattach: a page that lost its job id must find the running uploads again -- ALL of them.
    # The page has one pill and one cancel, so what it gets back is the union of every live job rather
    # than whichever happened to start last. A per-node update fired beside a fleet push has to appear.
    jr = P._push_job_new("core", NODES)
    jr2 = P._push_job_new("agent", BIG[:2])
    merged = P.api_push_status({})
    chk("push-status with NO job returns the merged view", merged["job"], "*")
    chk("...covering every live job, not just the newest",
        sorted(merged["nodes"]), sorted([n["id"] for n in NODES] + [n["id"] for n in BIG[:2]]))
    chk("and reports it as unfinished, so the page reattaches", merged["done"], False)
    chk("...and says the kinds differ rather than picking one", merged["kind"], "mixed")
    # A node another live job of the SAME kind still owes work to may not be taken by a second one --
    # in ANY of the states that mean work is outstanding. Checking only «queued» would let a second push
    # start on a node that is mid-upload, which is the exact race this rule exists to prevent.
    # A job of the OTHER kind is a different file, different node op, different lock: those run together,
    # which is what the operator asked for.
    for state in P.PUSH_BUSY_STATES:
        with P._push_lock:
            P._push_jobs[jr]["nodes"][NODES[0]["id"]]["state"] = state
        try:
            P._push_job_new("core", [NODES[0]])
            chk("a node in «%s» is refused a second push of its kind" % state, "accepted", "ValueError")
        except ValueError as e:
            chk("a node in «%s» is refused a second push of its kind" % state,
                "در جریان است" in str(e), True)
        j_other_kind = P._push_job_new("agent", [NODES[0]])
        chk("...but the OTHER kind starts on it right away (state «%s»)" % state,
            sorted(P.api_push_status({"job": j_other_kind})["nodes"]), [NODES[0]["id"]])
        with P._push_lock:
            P._push_jobs[j_other_kind]["done"] = True
    # ...and one the job has FINISHED with is free again
    with P._push_lock:
        P._push_jobs[jr]["nodes"][NODES[0]["id"]]["state"] = "ok"
    j_again = P._push_job_new("core", [NODES[0]])
    chk("...but a node the job has finished with can be pushed again",
        sorted(P.api_push_status({"job": j_again})["nodes"]), [NODES[0]["id"]])
    with P._push_lock:
        P._push_jobs[j_again]["done"] = True
    # ...but a DIFFERENT node is not
    j_other = P._push_job_new("agent", [BIG[5]])
    chk("...while another node starts straight away", sorted(P.api_push_status({"job": j_other})["nodes"]),
        [BIG[5]["id"]])
    with P._push_lock:
        for k in (jr, jr2, j_other):
            P._push_jobs[k]["done"] = True
    chk("once finished, nothing is offered to reattach to", P.api_push_status({}).get("idle"), True)

    # a node deleted while the queue was working must be reported, not pushed to
    P.get_node = lambda nid: None if nid == "n3" else next((n for n in NODES if n["id"] == nid), None)
    reached3 = []
    P.node_push = lambda node, ep, body, on_progress=None, timeout=200, should_abort=None: (
        reached3.append(node["id"]) or (on_progress(1, 1) if on_progress else None) or {"ok": True})
    j3 = P._push_job_new("agent", NODES)
    P._push_worker(j3, "agent", NODES, PLAN)
    s3 = P.api_push_status({"job": j3})
    chk("a node deleted mid-job is not pushed to", sorted(reached3), ["n1", "n2", "n4"])
    chk("and it is reported rather than skipped silently",
        (s3["nodes"]["n3"]["state"], s3["nodes"]["n3"]["err"]), ("err", "node_gone"))
    P.get_node = lambda nid: next((n for n in NODES if n["id"] == nid), None)

    # The push asks for a body PER NODE, and the core bytes only vary by architecture. Without a memo a
    # 12-node fleet base64-encoded and json-dumped the same 16MB binary twelve times and spawned openssl
    # twelve times to sign one hash.
    # Two architectures are two different binaries with two different checksums -- modelling them as one
    # would let a cache keyed on the artifact look correct while sharing one body between them.
    seenp = {"bytes": 0, "sign": 0}
    ARCHBYTES = {a: b"\x7fELF" + bytes([i]) * 200000 for i, a in enumerate(("amd64", "arm64"))}
    ARCHSHA = {a: chr(ord("a") + i) * 64 for i, a in enumerate(("amd64", "arm64"))}
    P._staged_bytes = lambda arch: (seenp.__setitem__("bytes", seenp["bytes"] + 1)
                                    or (ARCHBYTES[arch], ARCHSHA[arch], "v1"))
    P._sign_sha = lambda sha: seenp.__setitem__("sign", seenp["sign"] + 1) or "SIG"
    P._node_arch = lambda n: n["arch"]
    # the staged meta carries the per-arch sha the check gate compares against; it is written once by
    # _stage_core, which is why the gate no longer re-reads the megabytes to hash them per node
    P._staged_info = lambda: {"version": "v1", "sha": dict(ARCHSHA), "arches": list(ARCHSHA)}
    P._delivery_mode = lambda kind: "push"
    P._core_delivery_check = lambda *a: None
    mixed = [{"id": "m%d" % i, "name": "M%d" % i, "arch": "amd64" if i % 4 else "arm64"}
             for i in range(12)]
    P.get_node = lambda nid: next((n for n in mixed if n["id"] == nid), None)
    plans = {}
    P._push_start = lambda kind, nodes, plan: plans.setdefault("p", plan) and ""
    P.api_update_core({"ids": [n["id"] for n in mixed]})
    plan = plans["p"]
    chk("the core update is check -> deliver -> install", [x[0] for x in plan],
        ["check", "deliver", "install"])
    put = plan[1][2]
    outs = [put(n) for n in mixed]
    chk("12 nodes, 2 architectures -> the binary is encoded twice, not twelve times",
        (seenp["bytes"], seenp["sign"]), (2, 2))
    chk("nodes of the same arch share the encoded body", outs[1] is outs[2], True)
    chk("the two architectures get DIFFERENT bodies", outs[0] is not outs[1], True)
    # ...and different is not enough: each node must get ITS OWN arch. A crossed pair chmod-755s the wrong
    # ELF into place and every core tunnel on that node dies with "Exec format error", forever.
    got = {n["arch"]: json.loads(o.decode())["sha256"] for n, o in zip(mixed, outs)}
    chk("each architecture is sent its own binary", got, dict(ARCHSHA))

    # ---- the check step: what it saves is the megabytes, so it must not re-read them per node
    seenp["bytes"] = 0
    gate = plan[0][4]
    chk("a node already on this core is settled without sending anything",
        [gate({"arch": "amd64", "core_sha": ARCHSHA["amd64"][:12]}) for _ in range(6)], [True] * 6)
    chk("...and the gate never re-reads the staged binary at all -- it compares against the sha the "
        "staging step already wrote into the meta", seenp["bytes"], 0)
    chk("a node on a different core is not skipped",
        gate({"arch": "amd64", "core_sha": "f" * 12}), False)
    chk("a node that never answered has no arch, and is not skipped",
        gate({"core_sha": ARCHSHA["amd64"][:12]}), False)
    chk("...nor is one reporting an arch the panel cannot build for",
        gate({"arch": "mips", "core_sha": ARCHSHA["amd64"][:12]}), False)
    chk("the check step carries no payload", plan[0][2](mixed[0]), {})
    # an unknown arch must refuse at DELIVER rather than push the wrong ELF
    P._node_arch = lambda n: ""
    plans.clear()
    P.api_update_core({"ids": [mixed[0]["id"]]})
    try:
        plans["p"][1][2](mixed[0])
        chk("an unknown arch refuses instead of guessing", "built", "ValueError")
    except ValueError:
        chk("an unknown arch refuses instead of guessing", True, True)

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nbounded parallel, real byte progress, pause/resume/cancel, and no node ends the sweep")
    return 0


if __name__ == "__main__":
    sys.exit(main())
