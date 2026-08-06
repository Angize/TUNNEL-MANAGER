# -*- coding: utf-8 -*-
"""Guard: a form error is never written where only a scroll would reveal it.

Every refusal used to be written into the `.msg` strip at the BOTTOM of the sheet. On a phone that is
below the fold, so the operator taps save, nothing appears to happen, and the reason is sitting off
screen. formErr writes the strip AND pops a toast, so the two can never drift apart.

Two halves, and both are needed:
  * STATIC -- no error site writes the strip by hand any more, or that one would be silent again;
  * DRIVEN -- formErr really does both things, checked by running it.

Exit 1 if either half slips.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PANEL = HERE.parent / "tnl-central.py"

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_central_errpop", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    page = mod.INDEX_HTML
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", page, re.S), key=len)

    print("== 1) nobody writes the strip by hand any more ==")
    inline = re.findall(r"className='msg err'", js)
    check(len(inline) == 1,
          "exactly one `className='msg err'` remains and it is inside formErr (found %d)" % len(inline))
    body = re.search(r"function formErr\(.*?\n", js)
    check(bool(body) and "className='msg err'" in body.group(0),
          "the one that remains IS formErr's own")
    calls = len(re.findall(r"\bformErr\(", js)) - 1     # minus the definition
    check(calls >= 40, "the error sites all go through it (%d call sites)" % calls)

    print("\n== 2) formErr really does BOTH things ==")
    harness = r"""
globalThis.__toasts = [];
globalThis.__el = {className:'', textContent:''};
function toast(msg,kind){ globalThis.__toasts.push([msg,kind]) }
__FORMERR__
formErr(globalThis.__el, 'boom');
formErr(null, 'no element, still must pop');
console.log(JSON.stringify({el: globalThis.__el, toasts: globalThis.__toasts}));
"""
    fn = re.search(r"function formErr\(m,txt\)\{.*?\n", js)
    if not fn:
        check(False, "formErr is not in the page in the shape this guard knows -- THIS GUARD is stale")
        print()
        print("%d failure(s)" % len(fails))
        return 1
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "e.js"
        p.write_text(harness.replace("__FORMERR__", fn.group(0)), encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode:
        check(False, "formErr would not run: %s" % (r.stderr or "")[:200])
    else:
        got = json.loads(r.stdout.strip().splitlines()[-1])
        check(got["el"]["textContent"] == "boom" and "err" in got["el"]["className"],
              "it still writes the strip (class=%r text=%r)"
              % (got["el"]["className"], got["el"]["textContent"]))
        check(len(got["toasts"]) == 2 and got["toasts"][0] == ["boom", "err"],
              "and it pops, every time, even with no strip to write to (%s)" % got["toasts"])

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("every form error reaches the operator without a scroll")
    return 0


if __name__ == "__main__":
    sys.exit(main())
