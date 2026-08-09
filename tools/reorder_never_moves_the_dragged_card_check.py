#!/usr/bin/env python3
"""Guard: a reorder swap must never move the card the finger is holding.

The dragged card holds the pointer capture (`card.setPointerCapture` in `reordDown`). Moving a node in
the DOM is a remove followed by an insert, so moving THAT card makes the browser release the capture and
the gesture ends. `reordShift` used to move the dragged card when shifting UP and the neighbour when
shifting DOWN:

    if(up)RORD.box.insertBefore(c,nb);else RORD.box.insertBefore(nb,c);

which is exactly what the operator reported: dragging a card DOWN scrolls smoothly, dragging it UP «ردیف
به ردیف ول میشه» — it lets go once per row, at every swap. Moving the NEIGHBOUR to the card's other side
produces the identical order and leaves the capture alone.

This drives the REAL `reordDown` / `reordMove` / `reordApply` / `reordShift` out of the decoded
INDEX_HTML, through the document listeners the page itself registers, and spies on `insertBefore` to see
which node each swap actually moves. It also pins the resulting ORDER in both directions, so "never move
the dragged card" cannot be satisfied by breaking the reorder.

The layout is SYNTHETIC: cards are given a uniform pitch and their rects are derived from their index
plus their own translateY. That is enough for the midpoint comparisons `reordApply` makes, and it is the
only part a browser would supply. Nothing here proves what a real browser does with pointer capture —
that came from the operator's recording.

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
// ---- a DOM small enough to read, real enough for midpoint maths ----
const PITCH = 64, CARD_H = 53, LIST_TOP = 300;
const LISTENERS = {};
const noop = () => {};
const mkClassList = () => { const s = new Set(); return {
  add: c => s.add(c), remove: c => s.delete(c), toggle: (c, on) => (on ? s.add(c) : s.delete(c)),
  contains: c => s.has(c) }; };

function ty(el){ const m = /translateY\(([-0-9.]+)px\)/.exec(el.style.transform || ''); return m ? parseFloat(m[1]) : 0 }

const box = {id: 'corList', children: [], classList: mkClassList(), style: {}};
// Record the NODE, not a verdict: `var RORD` lives in the page script's module scope, so this prelude
// cannot see it -- reading globalThis.RORD here always gave undefined and every swap scored "neighbour",
// which made this whole guard pass against the very line it exists to catch.
box.insertBefore = function (node, ref) {
  globalThis.MOVED.push(node);
  const cur = box.children.indexOf(node);
  if (cur >= 0) box.children.splice(cur, 1);
  const at = ref ? box.children.indexOf(ref) : box.children.length;
  box.children.splice(at < 0 ? box.children.length : at, 0, node);
  return node;
};

function mkCard(rid) {
  const card = {
    style: {transform: ''}, classList: mkClassList(), parentNode: box, offsetHeight: CARD_H,
    _attrs: {'data-rid': String(rid), 'data-rk': 'core'},
    getAttribute(k){ return this._attrs[k] === undefined ? null : this._attrs[k] },
    setAttribute(k, v){ this._attrs[k] = v },
    setPointerCapture: noop, releasePointerCapture: noop,
    // reordApply walks these to find the neighbour it is crossing, and the fix inserts before nextSibling.
    get previousElementSibling(){ const i = box.children.indexOf(this); return i > 0 ? box.children[i - 1] : null },
    get nextElementSibling(){ const i = box.children.indexOf(this); return i < box.children.length - 1 ? box.children[i + 1] : null },
    get nextSibling(){ return this.nextElementSibling },
    querySelectorAll(){ return [] }, querySelector(){ return null }, appendChild: noop,
    closest(sel){ return sel === '.card[data-rid]' || sel === '.card' ? this : null },
    getBoundingClientRect(){
      const i = box.children.indexOf(this);
      const top = LIST_TOP + i * PITCH + ty(this);
      return {top, height: CARD_H, bottom: top + CARD_H, left: 0, right: 360, width: 360};
    },
  };
  card.grip = {
    closest(sel){ return sel === '.rgrip' ? this : card.closest(sel) },
    getBoundingClientRect(){ const r = card.getBoundingClientRect(); return {top: r.top + 13, height: 27, left: 300, width: 27} },
  };
  return card;
}

// Everything the page's own top-level render() touches, so it can boot without reaching the subject.
function mkStub(){ return {style: {}, classList: mkClassList(), dataset: {}, children: [],
  set innerHTML(v){}, get innerHTML(){ return '' }, set textContent(v){}, get textContent(){ return '' },
  appendChild: noop, addEventListener: noop, setAttribute: noop, removeAttribute: noop, remove: noop,
  insertAdjacentHTML: noop, focus: noop, click: noop, querySelector: () => null, querySelectorAll: () => [],
  closest: () => null, getBoundingClientRect: () => ({top:0,left:0,width:0,height:0}), getAttribute: () => null,
  value: '', disabled: false}; }

globalThis.MOVED = [];
globalThis.window = globalThis;
globalThis.document = {
  documentElement: {scrollHeight: 2000, clientHeight: 800, classList: mkClassList(), style: {}},
  body: {classList: mkClassList(), style: {}, appendChild: noop},
  head: {appendChild: noop},
  getElementById(id){ return id === 'corList' ? box : mkStub() },
  querySelector(){ return null }, querySelectorAll(){ return [] },
  createElement(){ return mkStub() },
  _unusedCreate(){ return {style: {}, classList: mkClassList(), appendChild: noop} },
  addEventListener(type, fn){ (LISTENERS[type] = LISTENERS[type] || []).push(fn) },
  cookie: '', readyState: 'complete', title: '',
};
globalThis.innerHeight = 800;
globalThis.pageYOffset = 0;
globalThis.scrollBy = noop;
globalThis.location = {href: 'http://x/', pathname: '/', search: '', hash: '', reload: noop};
globalThis.localStorage = {getItem: () => null, setItem: noop, removeItem: noop};
globalThis.matchMedia = () => ({matches: false, addEventListener: noop, addListener: noop});
globalThis.navigator = {userAgent: 'node', language: 'fa'};
// The page starts three self-rescheduling loops (tick / edgesLoop / peerLoop). Leave them unarmed, or
// node never exits and this guard hangs instead of reporting.
globalThis.setInterval = () => 0;
globalThis.setTimeout = () => 0;
globalThis.requestAnimationFrame = () => 0;
globalThis.cancelAnimationFrame = noop;
globalThis.alert = noop; globalThis.confirm = () => false;
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
globalThis.fetch = () => new Promise(() => {});
"""

HARNESS = r"""
globalThis.toast = () => {};
refreshNodes = refreshTunnels = refreshCore = refreshPortfw = () => {};
// Nothing may reach the network. Leaving the real post() here would hand the drop to a fetch that never
// settles, RSAVE would stay held, and every drag after the first would refuse to start -- which is a
// different bug (tools/reorder_survives_a_dead_request_check.py owns it), not this one.
globalThis.post = () => Promise.resolve({ok: true, d: {ok: true}});

const fire = (type, ev) => (LISTENERS[type] || []).forEach(fn => fn(ev));
const order = () => box.children.map(c => c.getAttribute('data-rid')).join(',');

function build(n) {
  RORD = null; RSAVE = false;
  box.children.length = 0;
  for (let i = 1; i <= n; i++) box.children.push(mkCard(i));
}

// One drag, through the page's own document listeners.
function drag(rid, dir, px) {
  const card = box.children.find(c => c.getAttribute('data-rid') === String(rid));
  const g = card.grip, r = g.getBoundingClientRect(), y0 = r.top + r.height / 2;
  globalThis.MOVED = [];
  fire('pointerdown', {target: g, pointerId: 1, isPrimary: true, pointerType: 'touch',
                       clientX: 310, clientY: y0, cancelable: true, preventDefault(){}});
  const started = !!RORD;
  const dragged = RORD && RORD.card;   // taken HERE: reordEnd clears RORD before we can compare
  for (let d = 5; d <= px; d += 5)
    fire('pointermove', {pointerId: 1, isPrimary: true, pointerType: 'touch',
                         clientX: 310, clientY: y0 + dir * d, cancelable: true, preventDefault(){}});
  const res = {started, order: order(),
               moved: globalThis.MOVED.map(n => (n === dragged ? 'DRAGGED-CARD' : 'neighbour'))};
  fire('pointerup', {pointerId: 1, isPrimary: true, pointerType: 'touch', clientX: 310, clientY: y0,
                     cancelable: true, preventDefault(){}});
  return res;
}

REORDMODE = true;
const out = {};
build(5); out.up_1   = drag(5, -1, 90);
build(5); out.up_2   = drag(5, -1, 150);
build(5); out.up_4   = drag(5, -1, 290);
build(5); out.down_1 = drag(1,  1, 90);
build(5); out.down_2 = drag(1,  1, 150);
build(5); out.down_4 = drag(1,  1, 290);
console.log(JSON.stringify(out));
process.exit(0);
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_reord", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    page = mod.INDEX_HTML
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", page, re.S), key=len)
    for fn in ("function reordShift(", "function reordApply(", "function reordDown("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "reord.js"
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

    print("== 1) the drag starts at all ==")
    for k, v in got.items():
        check(v["started"], "%s: reordDown armed the drag" % k)

    print("== 2) a swap NEVER moves the card the finger is holding ==")
    for k, v in got.items():
        check(v["moved"] and all(m == "neighbour" for m in v["moved"]),
              "%s: moved %s" % (k, v["moved"] or "NOTHING (no swap happened -- the drag is broken, not fixed)"))

    print("== 3) ...and the order is still what the drag asked for ==")
    want = {"up_1": "1,2,3,5,4", "up_2": "1,2,5,3,4", "up_4": "5,1,2,3,4",
            "down_1": "2,1,3,4,5", "down_2": "2,3,1,4,5", "down_4": "2,3,4,5,1"}
    for k, w in want.items():
        check(got[k]["order"] == w, "%s: order = %s, want %s" % (k, got[k]["order"], w))

    print("== 4) up and down cost the same number of swaps ==")
    for a, b in (("up_1", "down_1"), ("up_2", "down_2"), ("up_4", "down_4")):
        check(len(got[a]["moved"]) == len(got[b]["moved"]),
              "%s=%d swaps, %s=%d" % (a, len(got[a]["moved"]), b, len(got[b]["moved"])))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("the dragged card is never the node that moves, and both directions still reorder correctly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
