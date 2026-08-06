# -*- coding: utf-8 -*-
"""Guard: a form error takes the middle of the screen and stays until it is dismissed.

It used to be written into the `.msg` strip at the BOTTOM of the sheet. On a phone that is below the
fold: you tap save, nothing appears to happen, and the reason is off screen. A toast fixed the visibility
but not the staying -- it fades on its own, so a message read half-way is gone.

So formErr opens a CENTERED box with a close button and leaves it there. The strip is not written at all
any more; it is CLEARED, or a stale error from a previous attempt would sit under the new one.

Exit 1 if either the static or the driven half slips.
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_central_errpop", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", mod.INDEX_HTML, re.S), key=len)

    print("== 1) nobody writes the error strip any more ==")
    check(len(re.findall(r"className='msg err'", js)) == 0,
          "no `className='msg err'` anywhere -- the bottom strip is not an error channel now")
    calls = len(re.findall(r"\bformErr\(", js)) - 1
    check(calls >= 40, "the error sites all go through formErr (%d call sites)" % calls)
    fn = re.search(r"function formErr\(m,txt\)\{.*?\n(?=function )", js, re.S)
    check(bool(fn), "formErr is in the page in the shape this guard knows")
    if not fn:
        print()
        print("%d failure(s)" % len(fails))
        return 1
    check("openModal(" in fn.group(0), "it opens a modal rather than a self-dismissing toast")
    check("toast(" not in fn.group(0), "and it does NOT fall back to a toast that fades on its own")

    print("\n== 2) driven: it clears the strip and opens the box ==")
    harness = (
        "globalThis.__modals = [];\n"
        "globalThis.__el = {className:'msg err', textContent:'a previous error'};\n"
        "function openModal(html,opts){ globalThis.__modals.push({html:html}); return {} }\n"
        "function esc(x){ return String(x) }\n"
        "function ic(x){ return '' }\n"
        "function T(k){ return k }\n"
        + fn.group(0) +
        "formErr(globalThis.__el, 'boom');\n"
        "formErr(null, 'no strip, still must open');\n"
        "console.log(JSON.stringify({el: globalThis.__el, modals: globalThis.__modals}));\n")
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "e.js"
        f.write_text(harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode:
        check(False, "formErr would not run: %s" % (r.stderr or "")[:200])
        print()
        print("%d failure(s)" % len(fails))
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])
    check(got["el"]["textContent"] == "" and "err" not in got["el"]["className"],
          "the stale strip is CLEARED, not left under the box (class=%r text=%r)"
          % (got["el"]["className"], got["el"]["textContent"]))
    check(len(got["modals"]) == 2, "it opens one box per call, even with no strip (%d)" % len(got["modals"]))
    first = got["modals"][0]["html"] if got["modals"] else ""
    check("boom" in first, "the box carries the message")
    check("errx" in first and first.count("errClose") >= 2,
          "BOTH the corner X and the footer button can dismiss it -- it must not vanish on its own "
          "(errClose handlers found: %d)" % first.count("errClose"))

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("errors land in the middle of the screen and stay until dismissed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
