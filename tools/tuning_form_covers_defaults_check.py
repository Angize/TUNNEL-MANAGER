#!/usr/bin/env python3
"""Guard: the Settings tuning FORM and _TUNING_DEFAULTS describe the same knob set.

Adding or removing a tuning knob touches three places that no compiler ties together: the
`_TUNING_DEFAULTS` dict, the row in `settingsCard`, and the read in `_collectTuning`. Drop only one of
them and nothing raises:

  * row removed, collector kept   -> `parseInt(v('set_t_gone'))` is NaN, JSON.stringify writes **null**,
    and the panel POSTs a null over a knob the operator never touched;
  * collector entry removed, default kept -> the knob silently stops being savable, and the form keeps
    showing a value that goes nowhere;
  * row added, default missing    -> `_tv` falls through to undefined and the field renders empty.

So this renders the REAL card and runs the REAL collector out of the DECODED INDEX_HTML under node (the
.py source still has its escapes doubled and its placeholders unresolved, so a harness reading it tests
text no browser gets) and asserts:

  1. _collectTuning() returns exactly the _TUNDEF key set -- no extra, none missing;
  2. no collected value is null/NaN -- that is the shape a half-removed knob takes;
  3. every set_t_* input the card renders is actually READ by _collectTuning;
  4. a stored non-default round-trips back out of the form unchanged.

Exit 1 on any of them.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

# A stored value for every knob, deliberately off its default, so the round-trip cannot pass by both
# ends agreeing on the default. Units are what settings.json stores (SECONDS / MiB / percent), not what
# the form shows -- converting between the two is exactly what is under test.
STORED = {
    "suspect_backoff": [300, 900, 2700],
    "dead_retest_secs": 7200,
    "min_liveness_secs": 30,
    "probe_min_pct": 25,
    "sock_buf_mb": 8,
}

PRELUDE = r"""
globalThis._vals = {};
// value:'' is load-bearing. In a browser el() returns null for an id the card never rendered and v()
// answers '', so parseInt gives NaN and the knob is POSTed as null -- the very failure this guard
// exists for. A stub node without .value would crash instead, turning a clean FAIL into a harness error.
const _node = {value:'', style:{}, classList:{add(){},remove(){},toggle(){},contains(){return false}},
  appendChild(){}, addEventListener(){}, setAttribute(){}, removeAttribute(){}, remove(){},
  querySelector(){return null}, querySelectorAll(){return []}, insertAdjacentHTML(){},
  getBoundingClientRect(){return {width:0,height:0,top:0,left:0}}, focus(){}, click(){}, closest(){return null},
  get innerHTML(){return ''}, set innerHTML(v){}, get textContent(){return ''}, set textContent(v){},
  get scrollLeft(){return 0}, set scrollLeft(v){}, dataset:{}, children:[], parentNode:null};
const _mk = () => Object.create(_node);
globalThis.document = {documentElement:_node, body:_node, head:_node,
  getElementById(id){ if(id in globalThis._vals){ const n=_mk(); n.value=globalThis._vals[id]; return n } return _mk() },
  querySelector(){return _mk()}, querySelectorAll(){return []},
  createElement(){return _mk()}, addEventListener(){}, cookie:'', readyState:'complete', title:''};
globalThis.window = globalThis;
globalThis.location = {href:'http://x/', pathname:'/', search:'', hash:'', reload(){}};
globalThis.localStorage = {getItem(){return null}, setItem(){}, removeItem(){}};
globalThis.matchMedia = () => ({matches:false, addEventListener(){}, addListener(){}});
globalThis.navigator = {userAgent:'node', language:'fa'};
globalThis.fetch = () => new Promise(() => {});
globalThis.setInterval = () => 0;
globalThis.setTimeout = (fn) => 0;
globalThis.requestAnimationFrame = () => 0;
globalThis.alert = () => {}; globalThis.confirm = () => false;
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
"""

HARNESS = r"""
// Pull every <input id=... value=...> out of the card the page just built. tNum and the suspect input
// both write id before value, so one pass reads the whole form.
function formOf(settings){
  const html = settingsCard(settings), vals = {};
  const re = /<input[^>]*\bid="([^"]+)"[^>]*\bvalue="([^"]*)"/g;
  let m; while ((m = re.exec(html))) vals[m[1]] = m[2].replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, '&');
  return {html, vals};
}
// JSON.stringify is what the browser really sends, so NaN reaches the panel as null -- collect through
// it rather than around it, or the guard would see a NaN the wire never carries.
function collect(){ return JSON.parse(JSON.stringify(_collectTuning())) }

const out = {tundef: _TUNDEF, forms: {}};
for (const [name, settings] of [["defaults", {}], ["stored", {tuning: %s}]]) {
  const f = formOf(settings);
  globalThis._vals = f.vals;                 // the page's own el()/v() now read this form
  out.forms[name] = {ids: Object.keys(f.vals), back: collect()};
}
out.collectSrc = _collectTuning.toString();
console.log(JSON.stringify(out));
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def index_html():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_tuningform", PANEL)
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
    for fn in ("function settingsCard(", "function _collectTuning("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "tuningform.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % json.dumps(STORED)), encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:800])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])
    defaults, forms = got["tundef"], got["forms"]

    print("== 1) the form collects exactly the knobs _TUNING_DEFAULTS declares ==")
    for name in ("defaults", "stored"):
        back = forms[name]["back"]
        extra = sorted(set(back) - set(defaults))
        missing = sorted(set(defaults) - set(back))
        check(not extra, "%s: _collectTuning returns nothing _TUNDEF does not declare (extra=%s)" % (name, extra))
        check(not missing, "%s: every _TUNDEF knob is collected (missing=%s)" % (name, missing))

    print("== 2) no knob collects as null -- the shape a half-removed form row takes ==")
    for name in ("defaults", "stored"):
        nulls = sorted(k for k, v in forms[name]["back"].items() if v is None or (isinstance(v, list) and not v))
        check(not nulls, "%s: no null/empty collected value (%s)" % (name, nulls or "none"))

    print("== 3) every field the card RENDERS is read back by _collectTuning ==")
    src = got["collectSrc"]
    ids = [i for i in forms["stored"]["ids"] if i.startswith("set_t_")]
    # A floor first: with no ids the orphan scan below is vacuous, and the likeliest cause is this
    # guard's own <input> regex having stopped matching -- which must read as broken, not as clean.
    check(len(ids) >= len(defaults),
          "the card rendered %d set_t_* inputs for %d declared knobs" % (len(ids), len(defaults)))
    orphans = [i for i in ids if ("'%s'" % i) not in src and ('"%s"' % i) not in src]
    check(not orphans, "no input is rendered and then ignored (orphans=%s)" % (orphans or "none"))

    print("== 4) a stored non-default survives the form round-trip ==")
    # STORED is hand-written, so it rots the moment a knob is added: section 5 would still cover the
    # new knob, but only against its DEFAULT -- and a knob that round-trips its default while mangling
    # every other value is exactly the bug this section exists for. Make the rot loud.
    check(set(STORED) == set(defaults),
          "STORED covers every declared knob (only-in-STORED=%s only-in-_TUNDEF=%s)"
          % (sorted(set(STORED) - set(defaults)), sorted(set(defaults) - set(STORED))))
    back = forms["stored"]["back"]
    for k, want in sorted(STORED.items()):
        check(back.get(k) == want, "%s: stored %s -> form -> %s" % (k, want, back.get(k)))

    print("== 5) ...and the compiled-in defaults do too ==")
    back = forms["defaults"]["back"]
    for k, want in sorted(defaults.items()):
        check(back.get(k) == want, "%s: default %s -> form -> %s" % (k, want, back.get(k)))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("the tuning form and _TUNING_DEFAULTS describe the same knobs, both ways.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
