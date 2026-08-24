#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: retry is the same job again, and the node's English is answered in Persian.

Two things the operator hit on the live panel:

  * «تلاش دوباره» enqueued a COPY. The failed job stayed on the page and a second card appeared beside
    it, so three presses on one tunnel that would not build left three identical cards and three rows,
    each one a job of its own. A job is one card for its whole life.
  * a build that failed because a kernel module is missing said «RTNETLINK answers: No such file or
    directory» — to an operator who wants to know whether to try again. Every error a node's own tools
    produce arrives in English and this panel is Persian-only.

Exit 1 on any failure.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import raw_rows_gate_check as G     # noqa: E402  (reuse its DOM prelude)

# The message the operator actually saw, and the ones beside it. Every entry must come back with no
# English SENTENCE left in it: an identifier (a device name, a command in brackets, TLS) is not one.
MESSAGES = [
    "نودِ «DE01»: RTNETLINK answers: No such file or directory",
    "RTNETLINK answers: File exists",
    "RTNETLINK answers: Operation not supported",
    'RTNETLINK answers: Cannot find device "core9"',
    "Error talking to the kernel",
    "dial tcp 1.2.3.4:8080: connect: connection refused",
    "read tcp 10.0.0.1:22->10.0.0.2:22: connection reset by peer",
    "context deadline exceeded: i/o timeout",
    "ssh: Permission denied (publickey)",
    "bash: line 1: iptables: command not found",
    "x509: certificate signed by unknown authority",
    "No route to host",
    "Name or service not known",
]
# English words that are allowed to survive: they name a thing, they are not the error.
ALLOWED = re.compile(r"^(ip|l2tp|tcp|udp|tls|ssh|x|publickey|iptables|core\d*|add|tunnel|id|peer|encap|"
                     r"local|remote|sport|dport|connect|dev|link|set|name|type|mode)$", re.I)

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_onejob", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    print("== 1) «تلاش دوباره» is THIS job again, not a copy of it ==")
    d = tempfile.mkdtemp()
    P.CENTRAL_DIR, P.JOBS_FILE = d, os.path.join(d, "jobs.json")
    P.log_event = lambda *a, **k: None
    P.JOB_RETRY_BACKOFF = (0.02,) * 8
    P.API["t-guard-fail"] = lambda dd: (_ for _ in ()).throw(RuntimeError("boom"))
    P.JOB_KINDS["t-guard-fail"] = ("t", lambda _x: [])
    P.QUEUED = frozenset(P.JOB_KINDS)

    jid = P.jq_enqueue("t-guard-fail", {})["job"]
    for _ in range(200):
        if P._jobs[jid]["state"] == "fail":
            break
        time.sleep(0.05)
    check(P._jobs[jid]["state"] == "fail", "it failed first, so there is something to retry")
    before = len(P._jobs)
    r = P.api_job_retry({"job": jid})
    check(r.get("job") == jid, "retry answers with the SAME job id (%r)" % r.get("job"))
    check(len(P._jobs) == before, "no second job was created (%d -> %d)" % (before, len(P._jobs)))
    check(P._jobs[jid]["state"] == "wait" and P._jobs[jid]["tries"] == 0 and not P._jobs[jid]["err"],
          "the job went back to «در صف» with its counters cleared")
    for _ in range(200):
        if P._jobs[jid]["state"] == "fail":
            break
        time.sleep(0.05)
    check(len(P._jobs) == before, "and after running again it is still ONE job (%d)" % len(P._jobs))
    check(P.api_job_clear({"job": jid})["ok"] and jid not in P._jobs,
          "one finished job can be put away on its own")

    print("== 2) every English error sentence comes back in Persian ==")
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    if "function terr(" not in js:
        print("FAIL: terr is not in the rendered page")
        return 1
    harness = ("const out = %s.map(function(m){return terr(m)});console.log(JSON.stringify(out));"
               % json.dumps(MESSAGES))
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "t.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" + harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:600])
        return 1
    out = json.loads(r.stdout.strip().splitlines()[-1])
    for src, got in zip(MESSAGES, out):
        left = [w for w in re.findall(r"[A-Za-z][A-Za-z/]{2,}", got) if not ALLOWED.match(w)]
        check(not left, "%-46s -> %s" % (src[:46], got[:60] if not left else "LEFT IN ENGLISH: %s" % left))
        check(re.search(r"[؀-ۿ]", got) is not None,
              "%-46s -> answered in Persian" % src[:46])

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("one job is one card, and the node's English is answered in Persian.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
