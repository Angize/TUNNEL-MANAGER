#!/usr/bin/env python3
"""Guard: the connection check must not report success on a probe it just watched fail.

`check-link` asks each node for a real ICMP probe THROUGH the tunnel. The node answers with `alive`,
which it decides from the core heartbeat BEFORE the probe is consulted, plus `loss_pct` from the probe
itself. A tunnel whose upstream is blackholed still has a fresh heartbeat -- the peer's replies arrive
and refresh it -- so `alive` is true while not one packet crosses. The panel used to render the measured
100% loss on screen and then stamp the whole thing «اتصال برقرار» in green.

This drives the REAL path: it loads the DECODED browser JS (escapes resolved, placeholders injected --
reading the .py bytes would test something the browser never gets), stubs only the DOM and the network,
and calls `checkLink()` itself. Asserting on `oneWay()` alone would say nothing about the verdict line,
which is where the bug was.

Exit 1 on any failed expectation, on no `node`, or on a harness that could not run -- a check that
cannot reach its subject must not report success.
"""
import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# The guard flips the panel source between runs, and a .pyc that survives one of those flips is
# imported in place of the file under test — a revert then still "passes". Never write bytecode.
sys.dont_write_bytecode = True

SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S)

STUBS = r"""
// Enough DOM for the panel's load-time code to run headless. Everything the verdict path itself
// touches (esc, T, sideTxt, sideState, chkLines, CK/XK) is the panel's own, not stubbed.
var __els = {};
function __mkEl(){return {innerHTML:'',className:'',textContent:'',style:{},dataset:{},value:'',disabled:false,
  classList:{add:function(){},remove:function(){},toggle:function(){},contains:function(){return false}},
  appendChild:function(){},removeChild:function(){},setAttribute:function(){},getAttribute:function(){return null},
  addEventListener:function(){},closest:function(){return null},
  querySelectorAll:function(){return []},querySelector:function(){return null},
  remove:function(){},focus:function(){},blur:function(){},click:function(){}}}
var document={documentElement:__mkEl(),body:__mkEl(),
  getElementById:function(id){if(!__els[id])__els[id]=__mkEl();return __els[id]},
  createElement:function(){return __mkEl()},
  querySelectorAll:function(){return []},querySelector:function(){return null},
  addEventListener:function(){},removeEventListener:function(){}};
var localStorage={getItem:function(){return null},setItem:function(){},removeItem:function(){}};
var window=globalThis; var navigator={userAgent:'node',clipboard:{writeText:function(){}}};
var location={href:'',pathname:'/',search:'',reload:function(){}};
globalThis.setInterval=function(){return 0}; globalThis.setTimeout=function(){return 0};
globalThis.fetch=function(){return Promise.resolve({ok:true,json:function(){return Promise.resolve({})}})};
globalThis.requestAnimationFrame=function(){return 0};
globalThis.alert=function(){}; globalThis.confirm=function(){return true};
"""

DRIVER = r"""
// ---- drive the real checkLink() ----
var __fails = [];
function want(cond, msg){ if(!cond) __fails.push(msg); }

var __captured = null;
var __boxes = {};
setChk = function(id, cls, html){ __captured = {cls: cls, html: html}; };
toast  = function(){};
// Hand out a real object for the box ids so whatever checkLink paints is observable. Anything else
// stays null, as before.
el = function(id){
  if (id && id.indexOf('bx') === 0) { if (!__boxes[id]) __boxes[id] = {className:'', title:''}; return __boxes[id]; }
  return null;
};

function run(aHealth, bHealth){
  __captured = null; __boxes = {};
  FLEET = [{id:'t1', a_name:'IR01', b_name:'DE01'}];
  post = function(){ return Promise.resolve({ok:true, d:{ok:true,
    a_online:true, b_online:true, a_health:aHealth, b_health:bHealth}}); };
  return checkLink('t1').then(function(){ return __captured; });
}

// One verdict now decides everything: the node sends a TCP handshake out of the tunnel device and
// reports whether ANYTHING came back. There is no ladder left to get the ordering wrong in, so what
// these assertions defend is that no OTHER field creeps back into the decision.
var ALIVE = {up:true, alive:true,  dead:false, rtt_ms:31.2, loss_pct:0};
var DEAD  = {up:true, alive:false, dead:true,  rtt_ms:null, loss_pct:100};
var PEND  = {up:true, alive:null,  dead:false, rtt_ms:null, loss_pct:null};
// The node decides the two states itself, from a majority of its samples, so these are the only
// shapes it can publish: a side that answered most of the probe, or one that did not.
var LOSSY = {up:true, alive:false, dead:true,  rtt_ms:81.6, loss_pct:60.0};   // most of it did not cross
var NICK  = {up:true, alive:true,  dead:false, rtt_ms:78.2, loss_pct:30.0};   // a minority lost: still connected

Promise.resolve().then(function(){
  return run(ALIVE, ALIVE);
}).then(function(r){
  want(r && r.cls === 'ok', 'both handshakes answered must read ok, got ' + JSON.stringify(r && r.cls));
  want(r && r.html.indexOf(T('conn_ok')) >= 0, 'the ok header must read ' + T('conn_ok'));
  want(__boxes['bxa_t1'] && __boxes['bxa_t1'].className === 'tnnode st-ok',
    'and the check must repaint the frame itself, not leave it to the next poll — got ' +
    JSON.stringify(__boxes['bxa_t1'] && __boxes['bxa_t1'].className));

  return run(ALIVE, DEAD);
}).then(function(r){
  want(r && r.cls === 'err',
    'ONE end whose handshake never came back fails the whole tunnel: half a tunnel is not a tunnel. ' +
    'got ' + JSON.stringify(r && r.cls));
  want(__boxes['bxb_t1'] && __boxes['bxb_t1'].className === 'tnnode st-bad',
    'and that end repaints RED at once, got ' + JSON.stringify(__boxes['bxb_t1'] && __boxes['bxb_t1'].className));

  return run(PEND, ALIVE);
}).then(function(r){
  want(r && r.cls === 'err',
    'no verdict yet is not a pass — the check may only say ok about what was measured');

  // The whole point of the redesign: throughput counters are DISPLAY, never evidence. A side with bytes
  // pouring through it and an unanswered handshake is red; a totally silent side whose handshake came
  // back is green. If either of these flips, some counter has crept back into the verdict.
  want(sideState(true, {up:true, alive:false, dead:true, rx_still:0, tx_still:0}).k === 'bad',
    'bytes moving in both directions must NOT rescue a side whose handshake went unanswered');
  want(sideState(true, {up:true, alive:true, dead:false, rx_still:9999, tx_still:9999}).k === 'ok',
    'and a long-idle side whose handshake DID come back stays green');

  // The contradiction this guard exists for: the button said متصل while the card beside it drew a red
  // frame, because the button sampled three times and the sweep twice. They read one measurement now,
  // so the header may be ok ONLY when every side is drawn green. Asserted over the whole matrix, not
  // over one example -- a single pair passing says nothing about the pair that actually diverged.
  // Sequentially: run() writes shared capture state, so a Promise.all here would race and report a
  // disagreement that only the test created.
  return [[ALIVE,ALIVE],[ALIVE,LOSSY],[LOSSY,LOSSY],[ALIVE,DEAD],[LOSSY,DEAD],
          [NICK,ALIVE],[NICK,NICK],[PEND,ALIVE],[DEAD,DEAD]].reduce(function(chain, pair){
    return chain.then(function(){ return run(pair[0], pair[1]); }).then(function(r){
      var green = sideState(true, pair[0]).k === 'ok' && sideState(true, pair[1]).k === 'ok';
      want((r && r.cls === 'ok') === green,
        'the check header and the frames must never disagree: header=' + (r && r.cls) +
        ' but both-green=' + green + ' for ' + JSON.stringify(pair.map(function(h){return h.loss_pct})));
    });
  }, Promise.resolve()).then(function(){

  // TWO states. The panel adds no threshold of its own: a second one here could only ever disagree
  // with the node that did the measuring, which is the exact bug the single threshold was built for.
  [ALIVE, DEAD, PEND, LOSSY, NICK,
   {up:true, alive:true, dead:false, rtt_ms:80, loss_pct:49.9},
   {up:true, alive:true, dead:false, rtt_ms:80, loss_pct:50.0},
   {up:true, alive:false, dead:true, rtt_ms:80, loss_pct:50.1}].forEach(function(h){
    want(sideState(true, h).k !== 'warn',
      'there is no degraded state any more, but loss_pct=' + h.loss_pct + ' painted one');
  });
  want(sideState(true, LOSSY).k === 'bad',
    'a side the node called disconnected must be red whatever its loss reads');
  want(sideState(true, NICK).k === 'ok',
    'and a side it called connected must be green -- the panel must not re-judge it on the percentage');
  want(sideTxt(true, LOSSY).indexOf('60') >= 0,
    'a red side still STATES the loss it measured, got ' + sideTxt(true, LOSSY));
  want(sideTxt(true, NICK).indexOf('78') >= 0,
    'and a green side states its ping, which is a round trip and never a retry timer');

  want(sideState(true, ALIVE).k === 'ok', 'answered -> green');
  want(sideState(true, DEAD).k === 'bad', 'unanswered -> red');
  want(sideState(true, PEND).k === 'na', 'not yet measured -> neutral, never green');
  want(sideState(true, {up:false, alive:null}).k === 'bad', 'iface down -> red');
  want(sideState(false, ALIVE).k === 'bad', 'node offline -> red');
  want(sideState(true, null).k === 'bad', 'node has no such tunnel -> red');

  want(boxCls(true, ALIVE, ALIVE) === 'st-ok', 'a healthy box is framed green');
  want(boxCls(true, DEAD, ALIVE) === 'st-bad', 'an unanswered box is framed red');
  want(boxCls(false, ALIVE, ALIVE) === 'st-bad', 'an offline node is framed red');
  want(sideDot(true, DEAD, ALIVE).indexOf(T('st_disc')) >= 0,
    'the WORD stays: a red frame alone does not say what went wrong');
  want(sideTxt(true, ALIVE).indexOf('31') >= 0, 'the answered side shows the round trip it measured');

  console.log(JSON.stringify({fails: __fails}));
  });
}).catch(function(e){
  console.log(JSON.stringify({fails: ['harness threw: ' + (e && e.stack || e)]}));
});
"""


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=str(here.parent.parent / "tnl-central.py"))
    a = ap.parse_args()

    node_bin = shutil.which("node")
    if not node_bin:
        print("FAIL: `node` is not on PATH -- cannot run the browser JS")
        return 1

    spec = importlib.util.spec_from_file_location("tnl_central_under_check", a.panel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    js = "\n".join(SCRIPT_RE.findall(mod.INDEX_HTML))
    if "function checkLink" not in js:
        print("FAIL: checkLink() is not in the decoded panel JS -- THIS SCRIPT is out of date")
        return 1

    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "verdict.js"
        f.write_text(STUBS + js + DRIVER, encoding="utf-8")
        # encoding is explicit: the assertions carry Persian, and text=True alone decodes with the
        # console codepage, so on Windows a FAILING run dies in cp1252 instead of printing why.
        r = subprocess.run([node_bin, str(f)], capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
    out = (r.stdout or "").strip().splitlines()
    payload = next((ln for ln in reversed(out) if ln.startswith("{")), None)
    if payload is None:
        print("FAIL: the harness produced no verdict")
        print((r.stderr or r.stdout or "")[-2000:])
        return 1
    fails = json.loads(payload).get("fails") or []

    # A class the browser JS cannot catch: the frame colours are CSS, and a state whose variable does not
    # exist renders border:0 — invisible, while every structural assertion above still passes. Checking
    # the four rules resolve to a variable the sheet actually declares is the cheap half of that.
    css = re.search(r"<style>(.*?)</style>", mod.INDEX_HTML, re.S)
    if css is None:
        fails.append("no <style> block in the panel — THIS SCRIPT is out of date")
    else:
        sheet = css.group(1)
        declared = set(re.findall(r"(--[a-z0-9-]+)\s*:", sheet))
        for state in ("st-ok", "st-warn", "st-bad", "st-na"):
            rule = re.search(r"\.tnnode\.%s\{([^}]*)\}" % state, sheet)
            if rule is None:
                fails.append("no .tnnode.%s rule — the node box has no frame for that state" % state)
                continue
            for var in re.findall(r"var\((--[a-z0-9-]+)\)", rule.group(1)):
                if var not in declared:
                    fails.append("`.tnnode.%s` uses %s, which the sheet never declares — the frame "
                                 "renders as border:0 and the state is INVISIBLE" % (state, var))
    for msg in fails:
        print(" FAIL " + msg)
    if not fails:
        print("  ok  the check-link verdict, the side text and the dot all account for a failed probe")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
