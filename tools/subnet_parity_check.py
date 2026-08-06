# -*- coding: utf-8 -*-
"""Guard: the browser and the panel derive the SAME subnet, and never one outside a private range.

subnetForBase is a second implementation of subnet_default. A drifting copy shows the operator an
address the tunnel never gets -- and the first cut of the widening rule fell off the end of 10/8 and
produced 11.0.0.0/24 for an id no range can hold, which is somebody else's address space.

Exit 1 on any mismatch, or on any subnet outside 10/8, 172.16/12, 192.168/16.
"""
import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import raw_rows_gate_check as G     # noqa: E402  (reuse its DOM prelude)

PRIVATE = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
IDS = [0, 1, 2, 3, 255, 256, 4095, 4096, 65535, 65536, 999999]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_central_subnets", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)

    harness = ("const out={};for(const b of ['192.168','172.16','10'])for(const t of %s)"
               "out[b+':'+t]=subnetForBase('core',t,b);"
               "for(const t of [1,42,70000])out['sit:'+t]=subnetForBase('sit',t,'10');"
               "console.log(JSON.stringify(out));") % json.dumps(IDS)
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "s.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" + harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode:
        check(False, "the page would not run: %s" % (r.stderr or "")[:250])
        print()
        print("%d failure(s)" % len(fails))
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])

    bad = 0
    for base in ("192.168", "172.16", "10"):
        for tid in IDS:
            # The browser WIDENS when the picked range cannot hold the id, exactly as an unbased derive
            # does server-side; below 1, and above every range, both say nothing.
            try:
                want = P.subnet_default("core", tid, base) if 1 <= tid <= P.subnet_cap(base)                     else P.subnet_default("core", tid)
            except ValueError:
                want = ""
            if tid < 1:
                want = ""
            if got["%s:%d" % (base, tid)] != want:
                bad += 1
                print(" FAIL base=%-8s id=%-7s python=%r js=%r"
                      % (base, tid, want, got["%s:%d" % (base, tid)]))
    check(bad == 0, "python and the page agree on all %d id x range cases" % (len(IDS) * 3))

    esc = [v for k, v in got.items() if v and not k.startswith("sit:")
           and not any(ipaddress.ip_network(v, strict=False).subnet_of(p) for p in PRIVATE)]
    check(not esc, "every subnet the browser produces is inside a private range (escaped: %s)" % esc)

    for tid in (1, 42, 70000):
        check(got["sit:%d" % tid] == P.subnet_default("sit", tid),
              "sit id=%s agrees (%s)" % (tid, got["sit:%d" % tid]))

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the two implementations of the subnet rule cannot drift apart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
