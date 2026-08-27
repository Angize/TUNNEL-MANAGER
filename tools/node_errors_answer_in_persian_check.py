#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: every error a node's own tools produce comes back to the operator in Persian.

A build that failed because a kernel module is missing said «RTNETLINK answers: No such file or
directory» -- to an operator who wants to know whether to try again. Every error a node's own tools
produce arrives in English, and this panel is Persian-only, so `terr` is where it is answered.

The messages below are what the operator actually saw, and the ones beside them. Each must come back
with no English SENTENCE left in it: an identifier (a device name, a command, TLS) is not one.

Exit 1 on any failure.
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
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
    spec = importlib.util.spec_from_file_location("tnl_terr", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

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
    print("every English error a node produces is answered in Persian.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
