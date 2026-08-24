#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the queue page offers the control each state actually has, and says something new.

Two defects the operator hit on the live panel, both of them the kind that only shows up once there are
real jobs on the page:

  * every FINISHED job carried «تلاش دوباره». Pressing it did nothing but produce a refusal from the
    panel -- a dead control, on the one page an operator opens when something is stuck. Retry belongs to
    the two states that did not finish.
  * the line under the title fell back to the title itself, so a job read «بررسیِ اتصال / بررسیِ اتصال»
    and the page said everything twice while telling the operator nothing.

So this renders the REAL qJobCard out of the decoded INDEX_HTML under node, once per state, and reads
the buttons and the line back out of it.

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

TITLE = "بررسیِ اتصال"
RETRY, CANCEL, GOTO = "تلاش دوباره", "لغو", "برو به کارت"

# state -> (may retry, may cancel). Written from the product rule, not read off the code.
WANT = {
    "done":   (False, False),
    "cancel": (True, False),
    "fail":   (True, False),
    "run":    (False, True),
    "wait":   (False, True),
}

HARNESS = r"""
JOBNOW = 200; JOBLINK = {};
function textOf(h){ return h.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() }
const out = FIXTURES.map(function(jb){
  const h = qJobCard(jb);
  const btns = (h.match(/<button[^>]*>[\s\S]*?<\/button>/g) || []).map(textOf);
  const m = /<div class="qmeta">([\s\S]*?)<\/div>/.exec(h);
  return {state: jb.state, btns: btns, meta: m ? textOf(m[1]) : null};
});
console.log(JSON.stringify(out));
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_queue_page", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    for fn in ("function qJobCard(", "function jobWords(", "function qMeta("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1

    fixtures = [{"id": st, "kind": "check-link", "title": TITLE, "target": "core44", "link": "L1",
                 "state": st, "step": "", "pct": 100 if st == "done" else 20,
                 "tries": 6 if st == "fail" else 0,
                 "err": "MMD-IR12 جواب نداد" if st == "fail" else "",
                 "created": 100, "started": 110, "ended": 122} for st in WANT]

    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "q.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" +
                     HARNESS.replace("FIXTURES", json.dumps(fixtures)), encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True,
                           encoding="utf-8", timeout=60)
    if r.returncode:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:900])
        return 1
    got = {x["state"]: x for x in json.loads(r.stdout.strip().splitlines()[-1])}

    print("== 1) retry is offered on the states that did not finish, and nowhere else ==")
    for st, (may_retry, may_cancel) in WANT.items():
        b = got[st]["btns"]
        check((RETRY in b) == may_retry,
              "%-6s -> retry %s (%s)" % (st, "offered" if may_retry else "withheld", b))
        check((CANCEL in b) == may_cancel,
              "%-6s -> cancel %s (%s)" % (st, "offered" if may_cancel else "withheld", b))

    print("== 2) every job still has a way back to its card ==")
    for st in WANT:
        check(GOTO in got[st]["btns"], "%-6s -> «%s» (%s)" % (st, GOTO, got[st]["btns"]))

    print("== 3) the line under the title never just repeats the title ==")
    for st in WANT:
        m = got[st]["meta"]
        check(m != TITLE, "%-6s -> %r" % (st, m))
        check(m is None or m.strip() != "", "%-6s -> no empty line left behind (%r)" % (st, m))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("the queue page offers what each state has, and says something the title did not.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
