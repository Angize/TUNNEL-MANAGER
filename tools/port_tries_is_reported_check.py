#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: «چند بار پورتِ مبدأ عوض شود» is refused when it is out of range, never silently dropped.

The input takes two digits and the form clamped with `body.port_tries=(_pt>=1&&_pt<=50)?_pt:0`. So an
operator who typed 70 -- which the box accepts -- got a zero, the backend's `if _ptries:` skipped the
key, and the tunnel was built on the default rung depth of 2. No error, no warning, no trace: the
number just went away. Typing 70 and typing nothing produced the same tunnel.

This drives the REAL form code out of the rendered INDEX_HTML in node -- _collectCoreBody, portTriesErr,
portTriesN, portTriesOn -- because the defect was in the submit path, and a test that called a helper
would have said nothing about it. Two things are checked at once:

  * an out-of-range number REACHES formErr and stops the submit (blocked), and
  * an in-range number reaches body.port_tries UNCHANGED, so "refuse instead of drop" did not become
    "refuse everything".

The ceiling itself is not written here -- it is read out of the page's own PORT_TRIES_MAX, which
tools/tuning_consistency.py pins to the core's maxPortTries. This guard is about the behaviour.

    python3 tools/port_tries_is_reported_check.py
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

GRAB = ("_collectCoreBody", "sprotOn", "sprotLive", "sprotN", "dportsN", "sprotErr", "sprotWarnUpd",
        "sprotVis", "portTriesOn", "portTriesVis", "portTriesN", "portTriesErr", "portTriesWarnUpd",
        "fecDatagram", "wkCarrier", "wkClamp", "desyncOk", "desyncInjects", "portErr", "sportErr",
        "rawProtoErr", "sportPaint", "sportPresetPaint", "cdnShapeOn", "esc")

SHIM = r"""
var _F = {};
function _mk(id){ return {id:id, value:'', style:{display:''}, innerHTML:'',
  querySelectorAll:function(){ return [] },
  classList:{_s:{}, add:function(c){this._s[c]=1}, remove:function(c){delete this._s[c]},
             contains:function(c){return !!this._s[c]},
             toggle:function(c,on){ if(on===undefined) on=!this._s[c]; if(on)this._s[c]=1; else delete this._s[c]; return !!on}}}; }
function el(id){ if(!_F[id]) _F[id]=_mk(id); return _F[id]; }
function v(id){ var e=el(id); return e?String(e.value).trim():''; }
function T(k){ return k; }
function ic(n,c){ return ''; }
function ssVal(k){ return _SEL[k]||''; }
function num(x){ x=+x; return isFinite(x)?x:0; }
var _WKN = 4, RAW_SPORT_FIX = 51820;
var _SEL = {};
var _ERR = null;
function formErr(m, t){ _ERR = t; }
function poolGet(p){ return {pool:false}; }
function poolCollect(p,b){ return true; }
function cdnShapeBody(p,b,c){}
function rawProtoOwner(n){ return null; }
var _eeS = null;
function cePortTriesVis(){}
"""

DRIVER = r"""
var OUT = [];
function fresh(typed){
  _F = {}; _ERR = null;
  _SEL = {'e_cipher':'auto', 'e_a':'na', 'e_b':'nb'};
  el('e_porttries').value = typed;
  return {Tr:'udp', RawProfile:'bare', Obfs:true, Cover:false, Fec:false, FecData:10, FecParity:3,
          SportRandom:false, Sprot:false, Gso:false, Desync:false, DesyncTtl:4, DesyncCount:2,
          DesyncMode:'ttl', Cdn:'ws', WorkersA:1, WorkersB:1, Srv:'a', SniSplit:false, SplitPos:0,
          SniMode:'split', SplitTtl:0, WsTls:false, Ech:false, EchProxy:false};
}
function run(label, typed){
  var S = fresh(typed), body = {};
  var blocked = _collectCoreBody(S, 'e_', el('e_msg'), body);
  OUT.push([label, {blocked: !!blocked, err: _ERR,
                    pt: ('port_tries' in body) ? body.port_tries : null,
                    has: ('port_tries' in body)}]);
}
run('empty', '');
run('1', '1');
run('2', '2');
run('MAX', String(PORT_TRIES_MAX));
run('MAX+1', String(PORT_TRIES_MAX + 1));
run('70', '70');
run('99', '99');
run('0', '0');
console.log(JSON.stringify(OUT));
"""


def load_panel():
    spec = importlib.util.spec_from_file_location("panel_pt", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def grab(js, name):
    i = js.index("function %s(" % name)
    depth, j, started = 0, i, False
    while j < len(js):
        if js[j] == "{":
            depth += 1
            started = True
        elif js[j] == "}":
            depth -= 1
            if started and depth == 0:
                return js[i:j + 1]
        j += 1
    raise SystemExit("could not read %s out of the page" % name)


def main():
    js = load_panel().INDEX_HTML
    m = re.search(r"PORT_TRIES_MAX=(\d+)\s*[,;]", js)
    if not m:
        print(" FAIL  the page carries no PORT_TRIES_MAX -- the form has no ceiling to report against,"
              " so an out-of-range number can only be dropped in silence")
        return 1
    cap = int(m.group(1))
    src = SHIM + "\n"
    src += re.search(r"var PORT_RUNG_TRANSPORTS=\[.+?\];", js).group(0) + "\n"
    src += re.search(r"var SPROT_DEF=\d+;", js).group(0) + "\n"
    src += "var RAW_DPORTS_MAX=" + re.search(r"RAW_DPORTS_MAX=(\d+)\s*[,;]", js).group(1) + ";\n"
    src += "var RAW_SPROT_MAX=" + re.search(r"RAW_SPROT_MAX=(\d+)\s*[,;]", js).group(1) + ";\n"
    src += "var PORT_TRIES_MAX=%d;\n" % cap
    src += "\n".join(grab(js, n) for n in GRAB) + "\n"
    src += DRIVER

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(src)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print("FAIL: node could not run the form code:\n" + (out.stderr or "")[:2000])
        return 1
    rows = dict(json.loads(out.stdout.strip().splitlines()[-1]))

    print("== the ceiling the page carries: %d ==" % cap)
    fails = []

    def check(ok, msg, got=None):
        print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "  -- %r" % (got,)))
        if not ok:
            fails.append(msg)

    for label in ("1", "2", "MAX"):
        r = rows[label]
        want = cap if label == "MAX" else int(label)
        check(not r["blocked"] and r["pt"] == want,
              "%-6s is accepted and reaches the body unchanged (%s)" % (label, want), r)

    for label in ("MAX+1", "70", "99"):
        r = rows[label]
        check(r["blocked"], "%-6s is REFUSED, not silently zeroed" % label, r)
        check(bool(r["err"]), "%-6s puts a message on the form" % label, r)
        check(r["pt"] is None, "%-6s never reaches the body" % label, r)

    for label in ("empty", "0"):
        r = rows[label]
        check(not r["blocked"], "%-6s is allowed (it means: leave it at the core default)" % label, r)
        check(not r["pt"], "%-6s carries no number" % label, r)

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
