#!/usr/bin/env python3
"""Guard: a list refresh that lands mid-drag must not replace the cards under the finger.

Every list refresh reads its busy guard, then `await`s a fetch, then calls `setHTML` — which replaces
EVERY card in the list. The guard was read only BEFORE the await, so a drag started during that fetch was
invisible to it, and the response then tore the dragged card out of the document:

    async function refreshCore(){ if(...busy...) return;
      var f = await j('fleet?...');          // a whole round-trip
      setHTML(box, FLEET.map(coreCard)...)   // ...and now the card under the finger is gone

Reported as: for a second or two after dropping a card, the next drag lets go by itself. That window is
exactly the length of the fetch, and it is most visible right after a drop because reordPersist fires an
extra refresh there. Measured in a browser before the fix: `RORD.card.isConnected` went true -> false the
moment the response landed, the list snapped back to the server's order, and no further drag moved
anything.

This drives the REAL refreshCore out of the decoded INDEX_HTML against a fetch that resolves on a later
tick, starts a drag while it is in flight, and asserts setHTML is not called. The control asserts that
with no drag in progress it IS called, so the invariant cannot be met by breaking the refresh.

Exit 1 on any failure.
"""
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

PRELUDE = r"""
const noop = () => {};
const mkClassList = () => { const s = new Set(); return {
  add: c => s.add(c), remove: c => s.delete(c), toggle: (c, on) => (on ? s.add(c) : s.delete(c)),
  contains: c => s.has(c) }; };
function mkStub(){ return {style: {}, classList: mkClassList(), dataset: {}, children: [],
  set innerHTML(v){}, get innerHTML(){ return '' }, set textContent(v){}, get textContent(){ return '' },
  appendChild: noop, addEventListener: noop, setAttribute: noop, removeAttribute: noop, remove: noop,
  insertAdjacentHTML: noop, focus: noop, click: noop, querySelector: () => null, querySelectorAll: () => [],
  closest: () => null, getBoundingClientRect: () => ({top:0,left:0,width:0,height:0}), getAttribute: () => null,
  insertBefore: noop, value: '', disabled: false}; }
globalThis.window = globalThis;
globalThis.document = {
  documentElement: {scrollHeight: 2000, clientHeight: 800, classList: mkClassList(), style: {}},
  body: {classList: mkClassList(), style: {}, appendChild: noop},
  head: {appendChild: noop},
  getElementById: () => mkStub(), querySelector: () => null, querySelectorAll: () => [],
  createElement: () => mkStub(), addEventListener: noop,
  cookie: '', readyState: 'complete', title: '',
};
globalThis.innerHeight = 800; globalThis.pageYOffset = 0; globalThis.scrollBy = noop;
globalThis.location = {href: 'http://x/', pathname: '/', search: '', hash: '', reload: noop};
globalThis.localStorage = {getItem: () => null, setItem: noop, removeItem: noop};
globalThis.matchMedia = () => ({matches: false, addEventListener: noop, addListener: noop});
globalThis.navigator = {userAgent: 'node', language: 'fa'};
globalThis.setInterval = () => 0;
globalThis.setTimeout = ((real) => (fn, ms) => real(fn, ms))(globalThis.setTimeout);
globalThis.requestAnimationFrame = () => 0; globalThis.cancelAnimationFrame = noop;
globalThis.alert = noop; globalThis.confirm = () => false;
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
globalThis.fetch = () => new Promise(() => {});
"""

HARNESS = r"""
const out = {};
const naptime = ms => new Promise(r => setTimeout(r, ms));   // the page already owns `tick`

// Spy on the one call that destroys the cards. Everything else is the page's own code.
let SETHTML_WHILE_DRAGGING = 0, SETHTML_TOTAL = 0;
const realSetHTML = setHTML, realSetList = setList;
setHTML = function (box, html) { SETHTML_TOTAL++; if (RORD) SETHTML_WHILE_DRAGGING++; return realSetHTML(box, html) };
setList = function (box, rows) { SETHTML_TOTAL++; if (RORD) SETHTML_WHILE_DRAGGING++; return realSetList(box, rows) };
coreCard = () => '<div></div>';

// A fleet fetch that takes a round-trip, like a phone link.
const FETCH_MS = 120;
j = () => new Promise(r => setTimeout(() => r({links: [], total: 0}), FETCH_MS));

(async () => {
  // ---- the reported case: a drag begins while the post-drop refresh is still in flight
  RORD = null; RSAVE = false;
  SETHTML_WHILE_DRAGGING = 0; SETHTML_TOTAL = 0;
  const p = refreshCore();                       // guard passes: no drag yet
  await naptime(FETCH_MS / 3);
  RORD = {card: {}, box: {}, id: '49', kind: 'core', pid: 1, grabY: 0, lastY: 0, swaps: [], maxY: 0};
  await p;
  out.dragStartedMidFetch = {setHTMLTotal: SETHTML_TOTAL, setHTMLWhileDragging: SETHTML_WHILE_DRAGGING};

  // ---- the control: with no drag, the refresh MUST still repaint the list
  RORD = null;
  SETHTML_WHILE_DRAGGING = 0; SETHTML_TOTAL = 0;
  await refreshCore();
  out.noDrag = {setHTMLTotal: SETHTML_TOTAL};

  // ---- and the drag must not block refreshes forever: once it ends, the list repaints again
  RORD = null;
  SETHTML_TOTAL = 0;
  await refreshCore();
  out.afterTheDragEnds = {setHTMLTotal: SETHTML_TOTAL};

  console.log(JSON.stringify(out));
  process.exit(0);
})().catch(e => { console.log(JSON.stringify({__error__: String(e && e.stack || e)})); process.exit(0) });
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_refresh", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", mod.INDEX_HTML, re.S), key=len)
    for fn in ("async function refreshCore(", "function setHTML("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "refresh.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + HARNESS, encoding="utf-8")
        try:
            r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8", timeout=60)
        except subprocess.TimeoutExpired:
            print(" FAIL the harness never finished")
            print("\n1 failure(s).")
            return 1
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:900])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])
    if "__error__" in got:
        print("FAIL: the harness threw:\n" + got["__error__"][:900])
        return 1

    print("== 1) a refresh in flight must not repaint over a drag that started meanwhile ==")
    a = got["dragStartedMidFetch"]
    check(a["setHTMLWhileDragging"] == 0,
          "setHTML ran %d time(s) while a drag was live -- each one tears the card out from under the finger"
          % a["setHTMLWhileDragging"])

    print("== 2) ...and the refresh is not simply broken ==")
    check(got["noDrag"]["setHTMLTotal"] == 1,
          "with no drag in progress the list still repaints (setHTML calls = %d, want 1)" % got["noDrag"]["setHTMLTotal"])
    check(got["afterTheDragEnds"]["setHTMLTotal"] == 1,
          "once the drag is over the list repaints again (setHTML calls = %d, want 1)" % got["afterTheDragEnds"]["setHTMLTotal"])

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("a fetch that lands mid-drag leaves the cards alone, and repaints resume the moment it ends.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
