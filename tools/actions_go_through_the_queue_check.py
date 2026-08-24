#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: an action is queued, a read is not, and every queued kind can actually run.

The queue is the only way an action reaches a node now, and it is wired by NAME: JOB_KINDS maps an API
name to a title and to the nodes it must hold, and _dispatch queues anything in that table. Three ways
that rots, none of which shows up on screen until an operator is waiting on it:

  * a kind is spelled wrong, or its API is renamed. The action is queued and the worker then cannot find
    a function to run -- the job sits there and the operator watches nothing happen.
  * a READ joins the table. `fleet` or `summary` queued means the page asks for its own data and is
    handed a job id, so it draws nothing at all and never recovers.
  * a new action is added beside the queued ones and never joins the table. It goes back to blocking the
    request for as long as the far node takes, which is the whole thing the queue exists to stop -- and
    it is invisible, because a fast node makes it look fine.

So this drives the REAL dispatcher over every endpoint the panel has.

Exit 1 on any failure.
"""
import importlib.util
import sys
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent

# Endpoints that must NEVER be queued: the page's own data. Written from the product rule, not read off
# the code, so this stays a real assertion if the roster is rewritten.
READS = ["fleet", "summary", "nodes", "node-names", "events", "settings", "traffic", "portfw-list",
         "proxies", "readiness", "agent-info", "edge-status", "peer-status", "install-status",
         "push-status", "node-stats", "node-ips", "link-rebuild-info", "jobs",
         # Interactive probes. Each is a button the operator presses and then watches for the answer,
         # which is painted onto the thing they are looking at. Queued, the press returns a job id and
         # the caller reads a verdict that is not there -- «?» drawn over live data.
         "check-link", "node-test", "spoof-egress-probe", "proxy-test"]

# Actions that must ALWAYS be queued: each one waits on a node or on the internet, which is exactly the
# wait that used to time the operator out.
ACTIONS = ["create-tunnel", "edit-link", "rebuild-link", "restart-link", "delete-link", "link-toggle",
           "flux-rotate", "node-install", "core-stage",
           "agent-fetch-git", "update-agent", "update-core", "portfw", "portfw-edit", "portfw-del"]

# One endpoint is both: kernel-tune applies, reverts AND reads its own status under one name. Only
# some bodies are the action, and getting that wrong is what put «?» in the tuning dialog.
HYBRID = [("node-kernel-tune", {"id": "n1"}, False),
          ("node-kernel-tune", {"id": "n1", "action": "status"}, False),
          ("node-kernel-tune", {"id": "n1", "action": "apply"}, True),
          ("node-kernel-tune", {"id": "n1", "action": "revert"}, True)]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_queue_guard", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    print("== 1) every queued kind names an API that exists ==")
    missing = sorted(k for k in P.JOB_KINDS if k not in P.API)
    check(not missing, "JOB_KINDS -> API: %s" % (missing or "every kind resolves"))
    check(set(P.QUEUED) == set(P.JOB_KINDS),
          "QUEUED is exactly JOB_KINDS (%d kinds)" % len(P.JOB_KINDS))

    print("== 2) every queued kind can be shown: a title and a node rule ==")
    for k, (title, nodes_of) in sorted(P.JOB_KINDS.items()):
        check(bool(title) and not title.isascii(),
              "%-20s -> titled %r" % (k, title))
        try:
            got = nodes_of({})
            ok = isinstance(got, list)
        except Exception as e:
            ok, got = False, repr(e)
        check(ok, "%-20s -> its node rule survives an empty body (%r)" % (k, got))

    print("== 3) an action is queued and a read is answered ==")
    # _dispatch is the one place that decides. Drive it, do not read the roster back to itself.
    calls = []
    P.API = dict(P.API)
    for name in READS + ACTIONS:
        P.API[name] = (lambda _n: (lambda d: (calls.append(_n), {"ok": True, "ran": _n})[1]))(name)
    P.jq_enqueue = lambda kind, d, auto=False: {"ok": True, "queued": True, "job": "x", "kind": kind}

    for name in ACTIONS:
        if name not in P.QUEUED:
            check(False, "%-20s is an ACTION but is not queued -- it still blocks the request" % name)
            continue
        r = P._dispatch(name, {})
        check(bool(r.get("queued")), "%-20s -> queued (%r)" % (name, r))

    for name in READS:
        if name not in P.API:
            continue
        r = P._dispatch(name, {})
        check(not r.get("queued") and r.get("ran") == name,
              "%-20s -> answered straight away (%r)" % (name, r))

    print("== 3b) the endpoint that is BOTH: the read answers, the action queues ==")
    # Its API is stubbed above, so what is under test here is the DECISION, not the node call.
    for name, body, want_q in HYBRID:
        P.API[name] = lambda d: {"ok": True, "ran": "hybrid"}
        r = P._dispatch(name, dict(body))
        check(bool(r.get("queued")) == want_q,
              "%-20s %-34s -> %s" % (name, str(body), "queued" if want_q else "answered"))

    print("== 4) the queue's own call-back runs the action instead of queueing it again ==")
    n0 = len(calls)
    r = P._dispatch("create-tunnel", {"_job": "j1"})
    check(not r.get("queued") and len(calls) == n0 + 1,
          "a body carrying _job RUNS the action (%r)" % r)

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("every action goes through the queue, every read goes around it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
