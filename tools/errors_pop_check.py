# -*- coding: utf-8 -*-
"""Guard: a form error takes the middle of the screen and stays until it is dismissed.

It used to be written into the `.msg` strip at the BOTTOM of the sheet. On a phone that is below the
fold: you tap save, nothing appears to happen, and the reason is off screen. A toast fixed the visibility
but not the staying -- it fades on its own, so a message read half-way is gone.

formErr now builds the SAME box confirmBox builds -- one `.mtext`, one `.mbtns` -- so a refusal and a
confirmation never look like two different products. The strip is not written any more; it is CLEARED,
or a stale error from a previous attempt would sit under the new one.

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
    fn = re.search(r"function formErr\(m,txt\)\{.*?\nfunction ", js, re.S)
    check(bool(fn), "formErr is in the page in the shape this guard knows")
    if not fn:
        print()
        print("%d failure(s)" % len(fails))
        return 1
    src = fn.group(0)
    check("toast(" not in src, "it does NOT fall back to a toast that fades on its own")
    check("mbtns" in src and "mtext" in src, "it builds confirmBox's own shape (.mtext + .mbtns)")

    # The picker's secondary line belongs to the OPEN list only. Putting it on the closed button pulled
    # every picker's `sub` onto it -- the node pickers show the node's IP there, and the button then
    # overflowed the sheet. Found by the operator, so it is pinned here.
    btn = re.search(r"function ssHTML\(.*?\n(?=function )", js, re.S)
    check(bool(btn) and "cur.sub" not in btn.group(0),
          "the CLOSED picker button shows the label only -- `sub` is for the open list")

    print("\n== 2) driven: it clears the strip and puts ONE box on screen ==")
    harness = (
        "globalThis.__added = [];\n"
        "function T(k){ return k }\n"
        "const doc = {addEventListener(){}, removeEventListener(){},"
        " querySelectorAll(){ return globalThis.__added },"
        " createElement(){ const kids={};"
        "   return {set className(v){this._c=v}, get className(){return this._c},"
        "     set innerHTML(h){ this._h=h }, get innerHTML(){ return this._h },"
        "     querySelector(sel){ return kids[sel] || (kids[sel] = {textContent:'', focus(){}, set onclick(f){}}) },"
        "     remove(){ const i=globalThis.__added.indexOf(this); if(i>=0) globalThis.__added.splice(i,1) },"
        "     set onclick(f){} } },"
        " body:{ appendChild(n){ globalThis.__added.push(n) } } };\n"
        "globalThis.document = doc;\n"
        "globalThis.__el = {className:'msg err', textContent:'a previous error'};\n"
        + src.rsplit("function ", 1)[0] +
        "formErr(globalThis.__el, 'boom');\n"
        "formErr(null, 'no strip, still must open');\n"
        "console.log(JSON.stringify({el: globalThis.__el,"
        " boxes: globalThis.__added.map(function(n){return {html:n.innerHTML, cls:n.className,"
        "   text:n.querySelector('.mtext').textContent, btn:n.querySelector('.mok').textContent}})}));\n")
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "e.js"
        f.write_text(harness, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode:
        check(False, "formErr would not run: %s" % (r.stderr or "")[:220])
        print()
        print("%d failure(s)" % len(fails))
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])
    check(got["el"]["textContent"] == "" and "err" not in got["el"]["className"],
          "the stale strip is CLEARED, not left under the box (class=%r text=%r)"
          % (got["el"]["className"], got["el"]["textContent"]))
    boxes = got["boxes"]
    check(len(boxes) == 2, "one box per call, even with no strip (%d)" % len(boxes))
    if boxes:
        b = boxes[0]
        check(b["text"] == "boom", "the box carries the message (%r)" % b["text"])
        check(b["btn"] == "got_it", "and exactly one acknowledge button (%r)" % b["btn"])
        check(b["html"].count("<button") == 1, "ONE button -- no second action, no corner X")
        check("errx" not in b["html"] and "errhead" not in b["html"], "no header row and no X")

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("a refusal is confirmBox's own box: centred, one button, stays put")
    return 0


if __name__ == "__main__":
    sys.exit(main())
