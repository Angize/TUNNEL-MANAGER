#!/usr/bin/env python3
"""Guard: a request that never answers must not wedge the panel.

`fetch` has no timeout. `RSAVE` is held across an `await` on it while a reorder persists, and it gates
the live refresh of EVERY list. So one stalled request used to hold the flag forever:

  * `refreshNodes` / `refreshTunnels` / `refreshCore` / `refreshPortfw` all early-return on `RSAVE`, so
    the whole dashboard silently stopped updating;
  * `reordDown` early-returns on `RSAVE`, so no card could be dragged again;
  * only a page reload recovered.

That was reproduced in a browser against the real handlers before it was fixed. This guard runs the REAL
`post`, `j` and `reordPersist` out of the DECODED INDEX_HTML under node against a `fetch` that never
settles, and asserts the flag comes back by itself. It also pins the two shape changes that came with it:
one request carrying the whole chain, and a drag that only its OWN pointer can end.

Note what does NOT fix it: releasing the flag in a `finally`. The old code already released it after a
`catch` that swallowed everything, so both ran or neither did -- and with an unbounded request neither
did. The bound on the request is the fix; the `finally` alone never was.

What it does NOT cover: real PointerEvents through the document listeners. `reordDown`/`reordMove` need
layout, so the drag itself was measured in a browser once and is not re-driven here.

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
const _node = {style:{}, classList:{add(){},remove(){},toggle(){},contains(){return false}},
  appendChild(){}, addEventListener(){}, setAttribute(){}, removeAttribute(){}, remove(){},
  querySelector(){return null}, querySelectorAll(){return []}, insertAdjacentHTML(){},
  getBoundingClientRect(){return {width:0,height:0,top:0,left:0}}, focus(){}, click(){}, closest(){return null},
  get innerHTML(){return ''}, set innerHTML(v){}, get textContent(){return ''}, set textContent(v){},
  value:'', dataset:{}, children:[], parentNode:null};
const _mk = () => Object.create(_node);
globalThis.document = {documentElement:_node, body:_node, head:_node,
  getElementById(){return _mk()}, querySelector(){return _mk()}, querySelectorAll(){return []},
  createElement(){return _mk()}, addEventListener(){}, cookie:'', readyState:'complete', title:''};
globalThis.window = globalThis;
globalThis.location = {href:'http://x/', pathname:'/', search:'', hash:'', reload(){}};
globalThis.localStorage = {getItem(){return null}, setItem(){}, removeItem(){}};
globalThis.matchMedia = () => ({matches:false, addEventListener(){}, addListener(){}});
globalThis.navigator = {userAgent:'node', language:'fa'};
globalThis.setInterval = () => 0;
globalThis.requestAnimationFrame = () => 0;
globalThis.cancelAnimationFrame = () => {};
globalThis.alert = () => {}; globalThis.confirm = () => false;
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
globalThis.fetch = () => new Promise(() => {});      // the page's own top-level code must not fire a real one
// A stalled connection, faithfully: the promise hangs, but an abort still rejects it the way a real
// fetch does. A stub that ignored the signal would hang this guard instead of testing the timeout.
globalThis.stalledFetch = (u, o) => new Promise((res, rej) => {
  const s = o && o.signal;
  if (s) s.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), {name:'AbortError'})));
});
"""

HARNESS = r"""
const out = {};
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Nothing here may reach the network or the DOM; only the subject under test is real.
globalThis.toast = (m, k) => { (out.toasts = out.toasts || []).push(String(k) + ':' + String(m)) };
refreshNodes = refreshTunnels = refreshCore = refreshPortfw = () => {};

(async () => {
  // ---- 1) the REAL post against a fetch that never settles.
  // TWO bounds ship: a POST is work the operator waits on (the panel budgets 200s for one node's build
  // alone), a GET and a latency-sensitive POST get the tight one. Both shortened so the guard is quick,
  // and kept an order of magnitude apart so section 2 can tell WHICH one reorder used.
  NET_TIMEOUT = 300;
  NET_POST_TIMEOUT = 3000;
  globalThis.fetch = globalThis.stalledFetch;         // hangs, exactly like a stalled connection
  const t0 = Date.now();
  const r = await post('some-mutation', {});
  out.postSettled = {ms: Date.now() - t0, value: r};

  // ---- 2) the REAL j against the same fetch: bounded REJECTION, so refreshX aborts before setHTML
  let jRejected = false;
  const t1 = Date.now();
  try { await j('fleet?kind=core'); } catch (_) { jRejected = true; }
  out.jRejected = {rejected: jRejected, ms: Date.now() - t1};

  // ---- 3) the REAL reordPersist: RSAVE must come back on its own
  RSAVE = false;
  const t2 = Date.now();
  const p = reordPersist('core', '1', ['2','3','4']);
  out.rsaveWhileInFlight = RSAVE;
  await p;
  out.rsaveAfter = RSAVE;
  out.reordMs = Date.now() - t2;

  // ---- 4) ONE request for the whole chain, carrying every crossed neighbour
  const sent = [];
  globalThis.fetch = (u, o) => { sent.push({u, body: JSON.parse(o.body)});
    return Promise.resolve({ok:true, json: () => Promise.resolve({ok:true})}) };
  RSAVE = false;
  await reordPersist('core', '1', ['2','3','4']);
  out.oneRequest = {count: sent.length, body: sent.length ? sent[0].body : null};

  // ---- 5) only the drag's OWN pointer ends it
  RORD = {card:_mk(), box:_mk(), id:'1', kind:'core', pid:1, grabY:0, lastY:0, swaps:[], maxY:0};
  reordEnd({pointerId: 99});                          // a second finger lifting
  out.survivesAnotherPointer = !!RORD;
  reordEnd({pointerId: 1});                           // the dragging finger lifting
  out.endsOnItsOwnPointer = !RORD;

  console.log(JSON.stringify(out));
  process.exit(0);                                    // a pending abort timer must not hold the guard open
})().catch(e => { console.log(JSON.stringify({__error__: String(e && e.stack || e)})); process.exit(0) });
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def index_html():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_reorder", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    page = mod.INDEX_HTML
    if "__TUNDEF_JSON__" in page:
        raise SystemExit("FAIL: the page still carries an unsubstituted placeholder")
    return page


def main():
    page = index_html()
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    for fn in ("function post(", "function j(", "async function reordPersist(", "function reordEnd("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "reorder.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + HARNESS, encoding="utf-8")
        try:
            r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8", timeout=30)
        except subprocess.TimeoutExpired:
            # The guard hanging IS the bug it exists for: an unbounded request never settles, so the
            # awaits never return. Say so as a FAILURE -- a hang otherwise reads as "stuck", not "red".
            print(" FAIL the harness never finished: a request never settled, which is precisely the wedge")
            print("")
            print("1 failure(s).")
            return 1
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:800])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])
    if "__error__" in got:
        print("FAIL: the harness threw:\n" + got["__error__"][:800])
        return 1

    print("== 1) a stalled request settles instead of hanging forever ==")
    ps = got["postSettled"]
    check(ps["value"] is not None and ps["value"].get("ok") is False,
          "post resolves {ok:false} on a dead request (got %s)" % json.dumps(ps["value"]))
    check(ps["ms"] < 30000, "it settles in %dms, not never" % ps["ms"])
    jr = got["jRejected"]
    check(jr["rejected"], "j REJECTS rather than resolving empty -- a blip must not blank a list")
    check(jr["ms"] < 5000, "and it rejects in %dms, not never" % jr["ms"])

    print("== 2) the reorder guard flag comes back by itself ==")
    check(got["rsaveWhileInFlight"] is True, "RSAVE is held while the save is in flight")
    check(got["rsaveAfter"] is False,
          "RSAVE is released after a request that never answered -- this is the wedge: while it is held, "
          "all four list refreshes AND every further drag are dead")
    # RSAVE gates every list refresh and the next drag, so reorder must take the TIGHT bound, not the
    # long one a mutation gets by default. The two are 10x apart in this harness, so the elapsed time
    # says which one it used -- a bare post() here would sit on the long bound and read as a wedge.
    check(got["reordMs"] < 1500,
          "reorder used the tight bound: it gave RSAVE back after %dms (the long POST bound is 3000ms "
          "here -- inheriting it would freeze every list and the next drag for minutes in production)"
          % got["reordMs"])

    print("== 3) one request carries the whole chain ==")
    one = got["oneRequest"]
    check(one["count"] == 1, "a three-neighbour drag sends %s request(s), want 1" % one["count"])
    check(isinstance(one["body"], dict) and one["body"].get("targets") == ["2", "3", "4"],
          "it carries every crossed neighbour in order: %s" % json.dumps(one["body"]))
    check(isinstance(one["body"], dict) and "target" not in one["body"],
          "and no single-target field is left behind for the server to guess at")

    print("== 4) only the drag's own pointer ends it ==")
    check(got["survivesAnotherPointer"], "a second finger lifting does not end a drag the first is holding")
    check(got["endsOnItsOwnPointer"], "...and the dragging pointer still ends it")

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("a dead request cannot wedge the panel, and a drag ends only on its own pointer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
