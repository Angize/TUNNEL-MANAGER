#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The download-proxy card must paint every time the page is built, not only the first time.

dlpxPaint cached its work in a module global and used that global as the reason to do nothing:

    async function dlpxPaint(){var box=el('dlpx_fields');if(!box||DLPX)return;

DLPX is set the first time the card paints. But agentSkel rewrites the whole view -- `el('view')
.innerHTML = vhead(...) + agentBody()` -- every time the operator opens that page, and agentBody ships
`<div id="dlpx_fields"></div>` empty. So on the second visit the div is empty again while DLPX is still
set, dlpxPaint returns at the guard, and the card shows its title and its Save button with no toggle
and no proxy list between them. The poll calls it again every few seconds and it returns at the same
guard. Only a full page reload clears DLPX, which is exactly what the operator found by hand.

The check drives the real dlpxPaint out of the rendered page under node, twice, the way the two visits
do.

    python3 tools/the_download_proxy_card_survives_a_revisit_check.py
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def grab(js, name, kind="function"):
    i = js.index("%s %s(" % (kind, name))
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


HARNESS = """
var DOM = {};
function el(id){ return DOM[id] || null }
function esc(s){ return String(s==null?'':s) }
function T(k){ return k }
function ssHTML(id,opts,sel){ return '<select id="'+id+'">'+opts.map(function(o){
  return '<option value="'+o.v+'">'+o.label+'</option>' }).join('')+'</select>' }
var PX=[];
var settingsCalls=0, proxyCalls=0;
async function pxLoad(){ proxyCalls++; PX=[{id:'p1',name:'one',url:'http://a'},{id:'p2',name:'two',url:'http://b'}] }
async function j(what){ if(what==='settings'){ settingsCalls++; return {dl_proxy_on:true, dl_proxy_id:'p2'} } return {} }

// what agentBody() ships: an empty div, rebuilt on every visit to the page
function buildView(){ DOM['dlpx_fields'] = {innerHTML:'', get firstChild(){ return this.innerHTML ? {} : null }} }

async function visit(){ buildView(); await dlpxPaint(); return DOM['dlpx_fields'].innerHTML }

(async function(){
  var first = await visit();
  var second = await visit();
  var third = await visit();
  // the poll calls dlpxPaint every few seconds without rebuilding the view; a card the operator has
  // already touched must survive that untouched.
  DOM['dlpx_fields'].innerHTML = 'OPERATOR-EDITED';
  await dlpxPaint();
  var afterPoll = DOM['dlpx_fields'].innerHTML;
  console.log(JSON.stringify({first:first, second:second, third:third, afterPoll:afterPoll,
                              settingsCalls:settingsCalls, proxyCalls:proxyCalls}));
})();
"""


def main():
    P = load_panel()
    js = P.INDEX_HTML
    src = "\n".join([grab(js, "dlpxPaint", "async function"), grab(js, "pxFields")])
    src = "var DLPX=null;\n" + src + "\n" + HARNESS

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(src)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print("FAIL: node could not run dlpxPaint:\n" + out.stderr)
        return 1
    got = json.loads(out.stdout.strip().splitlines()[-1])

    fails = []

    def check(name, ok, detail=""):
        print(("  ok   " if ok else " FAIL ") + name + (("\n       " + detail) if not ok and detail else ""))
        if not ok:
            fails.append(name)

    check("the first visit paints the card", "proxy_tgl" in got["first"], repr(got["first"])[:120])
    check("the second visit paints it too", "proxy_tgl" in got["second"],
          "the card came up empty on a revisit; only a full page reload fixes it")
    check("and so does the third", "proxy_tgl" in got["third"], repr(got["third"])[:120])
    check("the picked proxy is kept", "p2" in got["second"] or not got["second"], repr(got["second"])[:120])
    check("a painted card is left alone by the poll", got["afterPoll"] == "OPERATOR-EDITED",
          "the poll repainted over what was on screen: %r" % got["afterPoll"][:80])
    check("settings is read once, not on every paint", got["settingsCalls"] == 1,
          "read %d times" % got["settingsCalls"])

    print()
    if fails:
        print("FAILURES: " + ", ".join(fails))
        return 1
    print("the download-proxy card paints on every visit, and asks the server once")
    return 0


if __name__ == "__main__":
    sys.exit(main())
