#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The rotation toggle must reach the request body on every gesture, including the ones that turn it OFF.

The bug this closes lived in the BROWSER, not in _core_extra: _collectCoreBody only set
body.raw_sport_rotate when the typed number parsed to 1..64. Typing the documented off value, or
switching the profile away from udp, omitted the key entirely -- and _core_extra then inherited the
stored value from `cur`. So rotation could be switched on and never off, and moving a rotating tunnel
to esp/ah/tcp was refused with an error naming a form row that is hidden for those profiles.

A backend test cannot see that: hand _core_extra a body containing raw_sport_rotate:0 and it has always
done the right thing. The defect is only visible in what the form EMITS, so this drives the real
_collectCoreBody out of the rendered page under node, against a DOM stub, once per operator gesture.

It also pins the source block being genuinely inert while the toggle is on -- not merely greyed out.
pointer-events hides a control from a mouse; it does not stop the code, and a presentational-only guard
is exactly what produced the original bug.

    python3 tools/sport_rotate_toggle_check.py
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

GRAB = ("_collectCoreBody", "sprotOn", "sprotLive", "sprotN", "dportsN", "sprotErr", "sprotWarnUpd",
        "sprotToggle", "sprotVis", "portTriesOn", "portTriesVis", "portTriesN", "portTriesErr",
        "portTriesWarnUpd", "fecDatagram", "wkCarrier",
        "wkClamp", "desyncOk", "desyncInjects", "portErr", "sportErr", "rawProtoErr",
        "sportPaint", "sportPresetPaint", "cdnShapeOn", "esc", "ceSetSport", "ceSetSportPort")

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
var _WKN = 4, RAW_SPORT_FIX = 51820, SPROT_DEF_FALLBACK = 4;
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


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", PANEL)
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
    raise SystemExit("unbalanced %s" % name)


# Each case: a name, the gestures to run, and what the emitted body must look like afterwards.
DRIVER = r"""
var OUT = [];
function fresh(profile, storedN){
  _F = {}; _ERR = null;
  _SEL['ee_cipher'] = 'chacha20-poly1305';
  var S = {Tr:'raw', RawProfile:profile, SportRandom:false, Sprot:!!storedN, Fec:false,
           FecData:10, FecParity:3, WorkersA:1, WorkersB:1, Desync:false, Cdn:'ws'};
  el('ee_rawport').value = '20401';
  el('ee_rawsport').value = '';
  el('ee_rawsprot').value = storedN ? String(storedN) : '';
  el('ee_rawproto').value = '253';
  sprotVis('ee_', S);
  _eeS = S;
  return S;
}
function body(S){ var b={}; _ERR=null; var blocked=_collectCoreBody(S,'ee_',null,b);
  return {blocked:!!blocked, err:_ERR, rot:('raw_sport_rotate' in b)?b.raw_sport_rotate:'<ABSENT>',
          dp:('raw_dports' in b)?b.raw_dports:'<ABSENT>',
          rnd:b.raw_sport_random, sport:b.raw_sport, fec:b.fec, locked:el('ee_srcblk').classList.contains('portlock')}; }

// 1. an existing rotating tunnel, operator turns the toggle OFF
var S = fresh('udp', 5);
sprotToggle('ee_', S);
OUT.push(['toggle turned off', body(S)]);

// 2. the same tunnel, operator only changes the number
S = fresh('udp', 5); el('ee_rawsprot').value='3';
OUT.push(['number changed to 3', body(S)]);

// 3. an existing rotating tunnel, operator switches the profile away from udp
['esp','ah','l2tpv3','icmp','bare','tcp','gre','ipip','etherip','ipcomp'].forEach(function(p){
  var s = fresh('udp', 5); s.RawProfile = p; sprotVis('ee_', s);
  OUT.push(['profile -> '+p, body(s)]);
});

// 4. a fresh tunnel, operator turns the toggle ON
S = fresh('udp', 0);
sprotToggle('ee_', S);
OUT.push(['toggle turned on', body(S)]);

// 5. while it is on, the fixed/random source controls must be inert IN CODE, not only greyed
S = fresh('udp', 0); sprotToggle('ee_', S);
S.SportRandom = false;
ceSetSport(1);                  // the real handler behind the "reactive random" button
ceSetSportPort(4500);           // and the real handler behind the fixed-port presets
OUT.push(['locked setter ran', body(S)]);

// 6. an out-of-range number blocks only while the toggle is on
S = fresh('udp', 0); sprotToggle('ee_', S); el('ee_rawsprot').value='99';
OUT.push(['N=99 while on', body(S)]);
S = fresh('udp', 0); el('ee_rawsprot').value='99';
OUT.push(['N=99 while off', body(S)]);

// 7. the destination count rides the same toggle: it reaches the body while on, and is cleared off
S = fresh('udp', 0); sprotToggle('ee_', S); el('ee_rawdports').value='4';
OUT.push(['dports 4 while rotating', body(S)]);
S = fresh('udp', 5); el('ee_rawdports').value='4'; sprotToggle('ee_', S);
OUT.push(['dports 4 then toggled off', body(S)]);
S = fresh('udp', 0); sprotToggle('ee_', S); el('ee_rawdports').value='9';
OUT.push(['dports 9 while rotating', body(S)]);
S = fresh('udp', 5); el('ee_rawdports').value='9'; sprotToggle('ee_', S);
OUT.push(['dports 9 then toggled off', body(S)]);

// 8. FEC and rotation must never leave the form together
S = fresh('udp', 0); sprotToggle('ee_', S); S.Fec = true;
OUT.push(['fec ticked while rotating', body(S)]);

console.log(JSON.stringify(OUT));
"""

GUARDED_SETTER = ""

EXPECT = {
    "toggle turned off": dict(rot=0, blocked=False),
    "number changed to 3": dict(rot=3, blocked=False),
    "toggle turned on": dict(rot=4, blocked=False, rnd=False, sport=0, locked=True),
    "locked setter ran": dict(rot=4, rnd=False, sport=0, locked=True),
    "N=99 while on": dict(blocked=True),
    "N=99 while off": dict(rot=0, blocked=False),
    "fec ticked while rotating": dict(rot=4, fec=False),
    "dports 4 while rotating": dict(rot=4, dp=4, blocked=False),
    "dports 4 then toggled off": dict(rot=0, dp=0, blocked=False),
    "dports 9 while rotating": dict(blocked=True),
    "dports 9 then toggled off": dict(rot=0, dp=0, blocked=False),
}
for _p in ("esp", "ah", "l2tpv3", "icmp", "bare", "tcp", "gre", "ipip", "etherip", "ipcomp"):
    EXPECT["profile -> " + _p] = dict(rot=0, blocked=False, locked=False)


def main():
    P = load_panel()
    js = P.INDEX_HTML
    src = SHIM + "\n"
    src += re.search(r"var PORT_RUNG_TRANSPORTS=\[.+?\];", js).group(0) + "\n"
    src += re.search(r"var SPROT_DEF=\d+;", js).group(0) + "\n"
    src += "var RAW_DPORTS_MAX=" + re.search(r"RAW_DPORTS_MAX=(\d+)\s*[,;]", js).group(1) + ";\n"
    src += "var RAW_SPROT_MAX=" + re.search(r"RAW_SPROT_MAX=(\d+)\s*[,;]", js).group(1) + ";\n"
    src += "var PORT_TRIES_MAX=" + re.search(r"PORT_TRIES_MAX=(\d+)\s*[,;]", js).group(1) + ";\n"
    src += "\n".join(grab(js, n) for n in GRAB) + "\n"
    src += GUARDED_SETTER + DRIVER

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(src)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print("FAIL: node could not run the form code:\n" + (out.stderr or "")[:2000])
        return 1
    rows = json.loads(out.stdout.strip().splitlines()[-1])

    fails = []
    for name, got in rows:
        want = EXPECT.get(name)
        if want is None:
            fails.append("no expectation for %r" % name)
            continue
        bad = [k for k, wv in want.items() if got.get(k) != wv]
        mark = "  ok   " if not bad else " FAIL  "
        print("%s%-24s rot=%-9s blocked=%-5s rnd=%-5s locked=%s"
              % (mark, name, got.get("rot"), got.get("blocked"), got.get("rnd"), got.get("locked")))
        for k in bad:
            fails.append("%s: %s was %r, want %r" % (name, k, got.get(k), want[k]))

    print()
    if fails:
        print("FAILURES:")
        for f in fails:
            print("  - " + f)
        return 1
    print("the toggle reaches the body on every gesture, and the source block is inert while it is on")
    return 0


if __name__ == "__main__":
    sys.exit(main())
