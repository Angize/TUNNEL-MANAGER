#!/usr/bin/env python3
"""Guard: the pool-retest knobs are MINUTES in the form and SECONDS everywhere else.

`suspect_backoff` and `dead_retest_secs` are stored in settings.json, sent to the node and stamped into
the core config in SECONDS, but the operator types them in MINUTES — so `settingsCard` divides on the way
out and `_collectTuning` multiplies on the way back. Drop either half and the panel silently writes a
value 60x off; nothing downstream can tell, because 600 is a legal number of seconds.

This runs BOTH real functions out of the DECODED INDEX_HTML under node (the .py source still has its
escapes doubled and its placeholders unresolved, so a harness reading it tests text no browser gets) and
asserts three things:

  1. seconds -> form -> seconds is the identity, for the defaults and for a stored non-default;
  2. the two labels say «دقیقه» while the seconds knob beside them still says «ثانیه»;
  3. the pool card's retest-bar denominators stay in SECONDS (they are compared against epoch stamps).

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

# The two knobs under test, and the neighbour that must NOT have moved to minutes. The witness has to be
# a knob in SECONDS sitting beside them -- min_liveness took over when the pin TTL was removed, which is
# the point of naming it once here rather than spelling it into every assertion.
MIN_KNOBS = {"set_t_suspect": "suspect_backoff", "set_t_deadretest": "dead_retest_secs"}
SEC_KNOB = "set_t_minlive"
SEC_KEY = "min_liveness_secs"


def index_html():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_minutes", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    page = mod.INDEX_HTML
    if "__TUNDEF_JSON__" in page:
        raise SystemExit("FAIL: the page still carries an unsubstituted placeholder")
    return page


# Enough DOM for the page's top-level code to run. getElementById is the one piece with real behaviour:
# it hands back whatever `_vals` says, so the page's own el()/v() read the form the same way they do in
# the browser and `_collectTuning` is exercised unmodified.
PRELUDE = r"""
globalThis._vals = {};
const _node = {style:{}, classList:{add(){},remove(){},toggle(){},contains(){return false}},
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
const out = {cases: []};
for (const c of %s) {
  const f = formOf(c.settings);
  globalThis._vals = f.vals;                 // the page's own el()/v() now read this form
  const back = _collectTuning();
  out.cases.push({name: c.name, shown: {suspect: f.vals['set_t_suspect'], dead: f.vals['set_t_deadretest'],
                                        pin: f.vals['set_t_minlive']},
                  back: {suspect_backoff: back.suspect_backoff, dead_retest_secs: back.dead_retest_secs,
                         min_liveness_secs: back.min_liveness_secs}});
}
out.labels = {suspect: T('set_t_suspect'), dead: T('set_t_deadretest'), pin: T('set_t_minlive')};
out.poolDenoms = {backoff: _poolBackoff, dead: _poolDeadStep};
out.cd = %s.map(r => [r, poolCdTxt(r)]);
out.defaults = {suspect_backoff: _TUNDEF.suspect_backoff, dead_retest_secs: _TUNDEF.dead_retest_secs};
console.log(JSON.stringify(out));
"""

# The retest countdown, now that a dead entry waits hours: seconds -> what the .pcd span shows.
CD = {0: "0:00", 59: "0:59", 60: "1:00", 1450: "24:10", 1800: "30:00", 3599: "59:59",
      3600: "1:00:00", 3661: "1:01:01", 19800: "5:30:00", 21600: "6:00:00"}

CASES = [
    {"name": "the compiled-in defaults", "settings": {}},
    {"name": "a stored non-default", "settings": {"tuning": {"suspect_backoff": [300, 900, 2700],
                                                             "dead_retest_secs": 7200}}},
    {"name": "a one-minute floor", "settings": {"tuning": {"suspect_backoff": [60], "dead_retest_secs": 60}}},
]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    page = index_html()
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    for fn in ("function settingsCard(", "function _collectTuning("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1
    payload = json.dumps(CASES, ensure_ascii=False)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "minutes.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % (payload, json.dumps(sorted(CD)))), encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:800])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])

    print("== 1) seconds -> form -> seconds is the identity ==")
    for case, res in zip(CASES, got["cases"]):
        tun = case["settings"].get("tuning") or {}
        want_sb = tun.get("suspect_backoff", got["defaults"]["suspect_backoff"])
        want_dr = tun.get("dead_retest_secs", got["defaults"]["dead_retest_secs"])
        check(res["back"]["suspect_backoff"] == want_sb,
              "%s: suspect_backoff %s -> «%s» دقیقه -> %s" % (case["name"], want_sb, res["shown"]["suspect"],
                                                             res["back"]["suspect_backoff"]))
        check(res["back"]["dead_retest_secs"] == want_dr,
              "%s: dead_retest_secs %s -> «%s» دقیقه -> %s" % (case["name"], want_dr, res["shown"]["dead"],
                                                              res["back"]["dead_retest_secs"]))
        # The form really is showing minutes, not seconds relabelled.
        shown = [int(x) for x in re.findall(r"\d+", res["shown"]["suspect"])]
        check(shown == [round(v / 60) for v in want_sb],
              "%s: the suspect field shows %s, the minutes of %s" % (case["name"], shown, want_sb))
        check(res["shown"]["dead"] == str(round(want_dr / 60)),
              "%s: the dead-retest field shows %s, the minutes of %s" % (case["name"], res["shown"]["dead"], want_dr))
        # The seconds knob beside them must be untouched by any of this.
        check(res["back"][SEC_KEY] == int(res["shown"]["pin"]),
              "%s: %s stays 1:1 (%s)" % (case["name"], SEC_KEY, res["shown"]["pin"]))

    print("== 2) the labels name the unit the field takes ==")
    check("دقیقه" in got["labels"]["suspect"], "suspect label says دقیقه: %s" % got["labels"]["suspect"])
    check("دقیقه" in got["labels"]["dead"], "dead-retest label says دقیقه: %s" % got["labels"]["dead"])
    check("ثانیه" in got["labels"]["pin"], "the seconds neighbour still says ثانیه: %s" % got["labels"]["pin"])

    print("== 3) the pool card's retest bar keeps its SECONDS denominators ==")
    check(got["poolDenoms"]["backoff"] == got["defaults"]["suspect_backoff"],
          "_poolBackoff=%s (the seconds defaults)" % got["poolDenoms"]["backoff"])
    check(got["poolDenoms"]["dead"] == got["defaults"]["dead_retest_secs"],
          "_poolDeadStep=%s (the seconds default)" % got["poolDenoms"]["dead"])

    print("== 4) the retest countdown grows an hours field instead of counting to 360:00 ==")
    for secs, txt in got["cd"]:
        check(txt == CD[secs], "%ds shows %s (want %s)" % (secs, txt, CD[secs]))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("the form takes minutes, everything downstream keeps seconds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
