#!/usr/bin/env python3
"""Guard: the colour menu must not act on the gesture that opened it.

The menu opens 450ms into a long press, WHILE the finger is still down, as a fixed overlay covering
the screen. When the finger lifts, the browser sends the synthesized click to whatever is under that
point -- which is now the overlay. Two things happened, both reported by the operator as "it vanishes
the moment I let go, I have to press several times":

  * released over the backdrop -> `e.target === ov` -> the menu closed itself instantly;
  * released over a colour dot -> the dot was "clicked" and a colour the operator never chose was
    saved. That one is worse than the flicker, because it is silent.

The fix is one rule: the overlay ignores clicks until the gesture that opened it has ended and a short
arming delay has passed. This drives the real openTagPicker out of the rendered page under node
against a DOM stub, once per case, because the defect is in WHEN the handler is allowed to run and no
amount of reading the markup shows that.

    python3 tools/the_tag_menu_outlives_the_hold_check.py
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
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
GRAB = ("openTagPicker", "tagNoSelect", "esc", "num")

SHIM = r"""
var LOG = [];
var LIVE = null;
var _handlers = {};
function mkEl(cls){
  return {className: cls || '', _on: {}, innerHTML: '', _gone: false,
    addEventListener: function(t, f){ (this._on[t] = this._on[t] || []).push(f) },
    removeEventListener: function(){},
    remove: function(){ this._gone = true },
    fire: function(t, ev){ (this._on[t] || []).forEach(function(f){ f(ev) }) }};
}
var document = {
  body: { appendChild: function(el){ LIVE = el } },
  createElement: function(){ return mkEl('') },
  addEventListener: function(t, f){ (_handlers[t] = _handlers[t] || []).push(f) },
  removeEventListener: function(t, f){
    var a = _handlers[t] || []; var i = a.indexOf(f); if (i >= 0) a.splice(i, 1) }
};
function release(){ (_handlers['touchend'] || []).slice().forEach(function(f){ f({}) }) }
function clickBackdrop(){ LIVE.fire('click', {target: {closest: function(){ return null }}, }) }
function clickBackdropIsOv(){
  LIVE.fire('click', {target: Object.assign(LIVE, {closest: function(){ return null }})}) }
function clickDot(n){
  LIVE.fire('click', {target: {closest: function(){ return {getAttribute: function(){ return String(n) }} }}}) }
var FLEET = [{id: 7, tag: 0}];
var TAGPEND = {};
function T(k){ return k }
function setCardTag(id, tag){ LOG.push([id, tag]) }
var CARD_TAGS = [{a:'#1',b:'#2'},{a:'#3',b:'#4'},{a:'#5',b:'#6'}];
var TAG_HOLD_MS = 450;
var card = {getAttribute: function(k){ return k === 'data-rid' ? '7' : '' }};
"""

DRIVER = r"""
function out(o){ console.log('@@' + JSON.stringify(o)) }
function fresh(){ LOG = []; LIVE = null; _handlers = {}; openTagPicker(card); }

// 1) the finger that opened the menu lifts over the BACKDROP
fresh();
var opened = !!LIVE;
release();
clickBackdropIsOv();
var afterLiftBackdrop = {open: !LIVE._gone, saved: LOG.length};

// 2) the finger lifts over a COLOUR DOT
fresh();
release();
clickDot(3);
var afterLiftDot = {open: !LIVE._gone, saved: LOG.slice()};

// 3) once armed, a real tap on a dot must work
fresh();
release();
setTimeout(function(){
  clickDot(2);
  var pick = {closed: LIVE._gone, saved: LOG.slice()};

  // 4) once armed, a real tap on the backdrop must dismiss without saving
  fresh();
  release();
  setTimeout(function(){
    clickBackdropIsOv();
    var dismiss = {closed: LIVE._gone, saved: LOG.length};

    // 5) a long hold: the arming must key off the RELEASE, not off open time
    fresh();
    setTimeout(function(){
      release();
      clickBackdropIsOv();
      var longHold = {open: !LIVE._gone, saved: LOG.length};
      out({opened: opened, afterLiftBackdrop: afterLiftBackdrop, afterLiftDot: afterLiftDot,
           pick: pick, dismiss: dismiss, longHold: longHold});
    }, 2000);
  }, 600);
}, 600);
"""

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def grab(js, name):
    m = re.search(r"\nfunction %s\(" % re.escape(name), js)
    if not m:
        print("FAIL: %s is not in the page any more — this guard is out of date" % name)
        sys.exit(1)
    i = m.start() + 1
    k = js.index("{", i)
    depth = 0
    while True:
        if js[k] == "{":
            depth += 1
        elif js[k] == "}":
            depth -= 1
            if depth == 0:
                return js[i:k + 1]
        k += 1


def main():
    spec = importlib.util.spec_from_file_location("tnl_tagmenu", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", mod.INDEX_HTML, re.S), key=len)

    arm = re.search(r"var TAG_HOLD_MS=[^\n]*TAG_ARM_MS=(\d+),TAG_STUCK_MS=(\d+)", js)
    check(bool(arm), "the page declares an arming delay and a stuck-menu fallback")
    if arm:
        check(int(arm.group(2)) >= 5000,
              "the fallback is far longer than any real hold (%sms)" % arm.group(2), arm.group(2))
    src = SHIM + ("var TAG_ARM_MS=%s;var TAG_STUCK_MS=%s;\n"
                  % ((arm.group(1), arm.group(2)) if arm else (300, 10000)))
    src += "\n".join(grab(js, n) for n in GRAB) + "\n" + DRIVER

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "tag.js"
        p.write_text(src, encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True,
                           encoding="utf-8", timeout=90)
    if r.returncode != 0:
        print("FAIL: the page's own openTagPicker would not run:\n" + (r.stderr or "")[:900])
        sys.exit(1)
    line = [x for x in (r.stdout or "").splitlines() if x.startswith("@@")]
    if not line:
        print("FAIL: the driver produced nothing:\n" + (r.stdout or r.stderr)[:600])
        sys.exit(1)
    o = json.loads(line[-1][2:])

    print("== the gesture that opens the menu must not also act on it ==")
    check(o["opened"], "a long press opens the menu at all")
    check(o["afterLiftBackdrop"]["open"],
          "lifting the finger over the backdrop leaves the menu OPEN", o["afterLiftBackdrop"])
    check(o["afterLiftBackdrop"]["saved"] == 0,
          "  and saves nothing", o["afterLiftBackdrop"])
    check(o["afterLiftDot"]["open"],
          "lifting the finger over a colour dot leaves the menu OPEN", o["afterLiftDot"])
    check(o["afterLiftDot"]["saved"] == [],
          "  and does NOT save a colour the operator never chose", o["afterLiftDot"])

    print("\n== and the menu is still fully usable a moment later ==")
    check(o["pick"]["closed"] and o["pick"]["saved"] == [["7", 2]],
          "a real tap on a colour saves it and closes the menu", o["pick"])
    check(o["dismiss"]["closed"] and o["dismiss"]["saved"] == 0,
          "a real tap on the backdrop dismisses it and saves nothing", o["dismiss"])

    print("\n== the arming keys off the RELEASE, not off the moment it opened ==")
    check(o["longHold"]["open"] and o["longHold"]["saved"] == 0,
          "a two-second hold still survives its own finger-lift", o["longHold"])

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("the colour menu outlives the press that opens it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
