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
setChk = function(id, cls, html){ __captured = {cls: cls, html: html}; };
toast  = function(){};
el     = function(){ return null; };

function run(aHealth, bHealth){
  __captured = null;
  FLEET = [{id:'t1', a_name:'IR01', b_name:'DE01'}];
  post = function(){ return Promise.resolve({ok:true, d:{ok:true,
    a_online:true, b_online:true, a_health:aHealth, b_health:bHealth}}); };
  return checkLink('t1').then(function(){ return __captured; });
}

var ALIVE_OK  = {up:true, alive:true,  dead:false, rtt_ms:31.2, loss_pct:0};
var ONE_WAY   = {up:true, alive:true,  dead:false, rtt_ms:null, loss_pct:100};
var HALF_LOSS = {up:true, alive:true,  dead:false, rtt_ms:80.0, loss_pct:50};

run(ALIVE_OK, ALIVE_OK).then(function(r){
  want(r && r.cls === 'ok', 'a clean probe on both sides must still report ok, got ' + JSON.stringify(r && r.cls));
  want(r && r.html.indexOf(T('conn_ok')) >= 0, 'the ok header must read ' + T('conn_ok'));

  return run(ONE_WAY, ONE_WAY);
}).then(function(r){
  want(r && r.cls === 'err',
    'BOTH sides measured 100% loss and the verdict was ' + JSON.stringify(r && r.cls) +
    ' -- a check that watched every probe packet vanish must not report success');
  want(r && r.html.indexOf(T('conn_bad')) >= 0, 'the failing header must read ' + T('conn_bad'));
  want(r && r.html.indexOf(T('t_side_oneway')) >= 0,
    'each side line must name the state (' + T('t_side_oneway') + '), not just print the number');

  return run(ALIVE_OK, ONE_WAY);
}).then(function(r){
  want(r && r.cls === 'err', 'ONE side at 100% loss must still fail the verdict, got ' + JSON.stringify(r && r.cls));

  return run(HALF_LOSS, HALF_LOSS);
}).then(function(r){
  want(r && r.cls === 'ok',
    'partial loss is a lossy tunnel, not a dead one -- it must stay ok, got ' + JSON.stringify(r && r.cls));

  // the dot the dashboard paints, from the same health objects
  want(sideState(true, ONE_WAY).k === 'warn',
    'the dot for a one-way side must be amber, got ' + sideState(true, ONE_WAY).k);
  want(sideState(true, ONE_WAY).w === '',
    'the node boxes are tight — the one-way dot carries no word, got ' +
    JSON.stringify(sideState(true, ONE_WAY).w));
  want(sideState(true, ONE_WAY).t === T('tst_oneway_ping'),
    'with no word the tooltip is the ONLY explanation — a probe-driven amber must cite the probe');
  want(sideState(true, ALIVE_OK).k === 'ok',
    'a healthy side must still be green, got ' + sideState(true, ALIVE_OK).k);
  want(sideState(true, {up:true, alive:true, dead:true, loss_pct:100}).k === 'bad',
    'a confirmed-dead side must stay red, not be downgraded to amber');
  want(sideTxt(true, ONE_WAY).indexOf(T('t_side_conn')) < 0,
    'the one-way side text must not still say ' + T('t_side_conn'));

  // ---- pairing the two ends: the only thing that can settle "does what I send arrive" ----
  // A is pushing packets in and B's tunnel delivers none of them. This is the real measured case:
  // 122 out of the Iranian node in 20s, 0 arrived — with A's heartbeat fresh the whole time.
  var A_SENDING = {up:true, alive:true, dead:false, rtt_ms:null, loss_pct:null, tx_live:true, rx_live:true};
  var B_DEAF    = {up:true, alive:true, dead:false, rtt_ms:null, loss_pct:null, tx_live:true, rx_live:false};

  want(linkDir(A_SENDING, B_DEAF) === false,
    'A is sending and B receives nothing — the direction must read broken with no probe involved');
  want(linkDir(B_DEAF, A_SENDING) === true,
    'the OTHER direction is carrying and must not be condemned with it');
  want(sideState(true, A_SENDING, B_DEAF).k === 'warn',
    'the side whose traffic lands nowhere must be amber');
  want(sideState(true, A_SENDING, B_DEAF).t === T('tst_oneway_peer'),
    'the PAIRED verdict runs with no probe at all, so its tooltip must not cite lost pings — got ' +
    JSON.stringify(sideState(true, A_SENDING, B_DEAF).t));
  want(sideState(true, B_DEAF, A_SENDING).k === 'ok',
    'the side whose traffic DOES land must stay green — the half that works is information');

  // Idle is not failure, and one unknown half must never manufacture a verdict.
  var IDLE = {up:true, alive:true, dead:false, tx_live:false, rx_live:false};
  want(linkDir(IDLE, IDLE) === null, 'an idle tunnel must stay undetermined, not fail');
  want(linkDir(A_SENDING, {up:true, alive:true}) === null,
    'a peer that reports no direction at all must not produce a verdict');
  want(linkDir(A_SENDING, null) === null, 'an unreachable peer must not produce a verdict');
  want(sideState(true, IDLE, IDLE).k === 'ok', 'an idle-but-alive side stays green');

  // ---- the answered keepalive: this end settles its own direction, no far end needed ----
  var IDLE_RT = {up:true, alive:true, dead:false, tx_live:false, rx_live:false,
                 round_trip:true, carrier_rtt_ms:37};
  want(linkDir(IDLE_RT, IDLE) === true,
    'an answered keepalive proves our ping got there AND came back — it must settle the direction on an ' +
    'IDLE tunnel, where no byte counter moves and the pairing has nothing to compare');
  want(linkDir(IDLE_RT, null) === true,
    'and it must hold with the far end unreachable, since it needs nothing from it');
  want(sideState(true, IDLE_RT, IDLE).k === 'ok', 'a proven round trip reads green');
  want(sideTxt(true, IDLE_RT, IDLE).indexOf('37') >= 0,
    'the carrier RTT is measured through obfs and crypto — the path the data really takes — so it is ' +
    'the one to show');
  // Positive only. A stale round trip must not condemn anything: the TCP family skips the ping when
  // data just arrived, so "no recent pong" is no news at all.
  want(linkDir({up:true, alive:true, tx_live:false, rx_live:false, round_trip:null}, IDLE) === null,
    'no recent round trip must stay undetermined, never a failure');

  return run(A_SENDING, B_DEAF);
}).then(function(r){
  want(r && r.cls === 'err',
    'one direction proven not to land must fail the whole check, even with both ends alive and no ' +
    'probe loss to point at; got ' + JSON.stringify(r && r.cls));
  want(r && r.html.indexOf(T('t_side_oneway')) >= 0, 'and it must name which state it is');

  console.log(JSON.stringify({fails: __fails}));
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
    for msg in fails:
        print(" FAIL " + msg)
    if not fails:
        print("  ok  the check-link verdict, the side text and the dot all account for a failed probe")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
