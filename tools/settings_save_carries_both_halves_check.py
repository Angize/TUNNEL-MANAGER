#!/usr/bin/env python3
"""Guard: the one Save button on the settings card posts BOTH halves of that card.

The card holds two kinds of value that used to live in two cards behind two buttons: the panel timings,
which the panel applies to itself immediately, and the tuning knobs, which are stamped into a tunnel's
core config on its next build. They are now one form with one `saveSettings()`, and nothing ties the two
halves together any more:

  * drop `tuning:` from the payload and every knob in three of the four groups silently stops saving --
    the form still shows the operator's number, the POST just does not carry it;
  * drop a panel key and that row becomes decorative in the same silent way;
  * `resetSettings` restores from `_SETDEF`/`_TUNDEF`, so a key missing from either is a row the reset
    button quietly skips.

tools/tuning_form_covers_defaults_check.py cannot see any of this: it calls `_collectTuning` directly,
and a collector that works perfectly says nothing about a save that never calls it.

So this drives the REAL `refreshSettings` -> render -> `saveSettings` chain out of the decoded
INDEX_HTML under node, against a `post` that captures the body, and asserts the body carries every panel
key and every tuning knob at the value the form was showing. Then it does the same for `resetSettings`
and asserts the body IS the compiled-in defaults, both halves.

Exit 1 on any failure.
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

# A stored value for every row of the card, deliberately off its default, so a round-trip cannot pass by
# both ends agreeing on the default. Panel keys in the units settings.json stores; tuning likewise
# (SECONDS / MiB / percent) -- the minutes conversion on two of them is what makes this worth running.
STORED = {
    "reconcile_mode": "auto",
    "reconcile_interval": 42,
    "poll_interval": 0.7,
    "ui_interval": 1.5,
    "ech_refresh_mins": 33,
    "uptime_window": 12,
    "tuning": {
        "suspect_backoff": [300, 900, 2700],
        "dead_retest_secs": 7200,
        "keepalive": 20,
        "dead_mult": 5,
        "ping_loss_threshold": 4,
        "min_liveness_secs": 30,
        "probe_timeout_secs": 9,
        "probe_min_pct": 25,
        "sock_buf_mb": 8,
    },
}
# ech_refresh_mins=0 means "off" and is a legal stored value. It is also the one number that a `|| default`
# fallback turns back into 15 on render -- so the operator switches ECH refresh off, reloads, and it is on
# again. Kept as its own case because it is invisible in the case above.
ZERO_CASE = {"ech_refresh_mins": 0}

PRELUDE = r"""
globalThis._vals = {};
const noop = () => {};
const mkClassList = () => { const s = new Set(); return {add:c=>s.add(c),remove:c=>s.delete(c),
  toggle:(c,on)=>(on?s.add(c):s.delete(c)),contains:c=>s.has(c)}; };
const _node = {value:'', style:{}, classList:mkClassList(), dataset:{}, children:[],
  appendChild:noop, addEventListener:noop, setAttribute:noop, removeAttribute:noop, remove:noop,
  querySelector:()=>null, querySelectorAll:()=>[], insertAdjacentHTML:noop, insertBefore:noop,
  getBoundingClientRect:()=>({width:0,height:0,top:0,left:0}), focus:noop, click:noop, closest:()=>null,
  getAttribute:()=>null, get innerHTML(){return ''}, set innerHTML(v){},
  get textContent(){return ''}, set textContent(v){}, parentNode:null};
const _mk = () => Object.create(_node);
globalThis.__box = null;
globalThis.document = {documentElement:{classList:mkClassList(),style:{},scrollHeight:0,clientHeight:0},
  body:{classList:mkClassList(),style:{},appendChild:noop}, head:{appendChild:noop},
  getElementById(id){ if(id === 'setBox') return globalThis.__box;
                      if(id in globalThis._vals){ const n=_mk(); n.value=globalThis._vals[id]; return n }
                      return _mk() },
  querySelector:()=>null, querySelectorAll:()=>[], createElement:()=>_mk(), addEventListener:noop,
  cookie:'', readyState:'complete', title:''};
globalThis.window = globalThis;
globalThis.location = {href:'http://x/', pathname:'/', search:'', hash:'', reload:noop};
globalThis.localStorage = {getItem:()=>null, setItem:noop, removeItem:noop};
globalThis.matchMedia = () => ({matches:false, addEventListener:noop, addListener:noop});
globalThis.navigator = {userAgent:'node', language:'fa'};
globalThis.fetch = () => new Promise(() => {});
globalThis.setInterval = () => 0;
globalThis.setTimeout = ((real) => (fn, ms) => real(fn, ms))(globalThis.setTimeout);
globalThis.requestAnimationFrame = () => 0; globalThis.cancelAnimationFrame = noop;
globalThis.alert = noop; globalThis.confirm = () => true;
globalThis.getComputedStyle = () => ({getPropertyValue:()=>''});
"""

HARNESS = r"""
const out = {tundef: _TUNDEF, setdef: _SETDEF, cases: []};

let POSTED = null;
post = (u, b) => { POSTED = {url: u, body: JSON.parse(JSON.stringify(b))}; return Promise.resolve({ok: true, d: {ok: true}}) };
toast = () => {}; formErr = () => {}; perr = () => ''; confirmBox = () => Promise.resolve(true);
refreshAgent = () => {}; agentBody = () => ''; tunPmBind = () => {};

// The page writes the card into #setBox. Capture that HTML and make the page's own el()/v() read it back,
// exactly as a browser would -- the form is the only thing standing between the render and the save.
function boxOf(){ let html = ''; return {get innerHTML(){return html}, set innerHTML(v){ html = v },
  style:{}, classList:{add(){},remove(){},toggle(){},contains(){return false}} } }
function readForm(html){ const vals = {};
  const re = /<input[^>]*\bid="([^"]+)"[^>]*\bvalue="([^"]*)"/g;
  let m; while ((m = re.exec(html))) vals[m[1]] = m[2].replace(/&#39;/g,"'").replace(/&quot;/g,'"').replace(/&amp;/g,'&');
  return vals }

async function run(name, settings){
  globalThis.__box = boxOf();
  j = () => Promise.resolve(settings);          // the page's own fetch of /api/settings
  await refreshSettings();                       // render the card for real
  const html = globalThis.__box.innerHTML;
  globalThis._vals = readForm(html);             // ...and let the page read its own form back
  POSTED = null;
  await saveSettings();
  const saved = POSTED;
  POSTED = null;
  await resetSettings();
  out.cases.push({name, saved, reset: POSTED, mode: _setMode,
                  groups: (html.match(/class="grphd ([a-z-]+)"/g) || []),
                  saveButtons: (html.match(/onclick="save[A-Za-z]*\(\)"/g) || []),
                  ids: Object.keys(globalThis._vals)});
}

(async () => {
  for (const c of %s) await run(c.name, c.settings);
  console.log(JSON.stringify(out));
  process.exit(0);
})().catch(e => { console.log(JSON.stringify({__error__: String(e && e.stack || e)})); process.exit(0) });
"""

CASES = [
    {"name": "a stored non-default", "settings": STORED},
    {"name": "the compiled-in defaults", "settings": {}},
    {"name": "ECH refresh switched off", "settings": ZERO_CASE},
]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


# Two knobs live on the agent and core cards instead of the settings card: they are switches that
# save themselves the moment they are tapped, so Save must NOT carry them -- a card rendered before
# the switch was flipped would otherwise post the old value back over it.
SELF_SAVING = {"agent_delivery", "core_delivery", "control_auth"}


def main():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_savecard", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    page = mod.INDEX_HTML
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    for fn in ("async function refreshSettings(", "async function saveSettings(",
               "async function resetSettings(", "function settingsCard("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "savecard.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % json.dumps(CASES)), encoding="utf-8")
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
    if "__error__" in got:
        print("FAIL: the harness threw:\n" + got["__error__"][:900])
        return 1

    tundef, setdef = got["tundef"], got["setdef"]
    by_name = {c["name"]: c for c in got["cases"]}

    print("== 0) the card really is ONE card with four subject groups and ONE save ==")
    first = got["cases"][0]
    check(len(first["groups"]) == 4,
          "four group headers rendered: %s" % (first["groups"] or "none"))
    check(len(set(first["groups"])) == 4,
          "each group carries its own scope class (duplicates make two groups look like one subject)")
    check(first["saveButtons"] == ['onclick="saveSettings()"'],
          "exactly one save button, and it is saveSettings: %s" % (first["saveButtons"] or "none"))

    print("== 1) Save carries the PANEL half at the value the form showed ==")
    for name, settings in [(c["name"], c["settings"]) for c in CASES]:
        body = (by_name[name]["saved"] or {}).get("body")
        if not body:
            check(False, "%s: nothing was POSTed at all" % name)
            continue
        check((by_name[name]["saved"] or {}).get("url") == "settings-set",
              "%s: posts to settings-set" % name)
        for k in [x for x in setdef if x not in SELF_SAVING]:
            want = settings.get(k, setdef[k])
            got_v = body.get(k)
            # v() hands back strings; the server coerces. Compare as text so "42" == 42 but 15 != 33.
            check(got_v is not None and str(got_v) == str(want),
                  "%s: %-18s form -> POST %s (want %s)" % (name, k, json.dumps(got_v, ensure_ascii=False), want))

    print("== 1b) the two delivery switches own themselves; Save must not speak for them ==")
    for name in [c["name"] for c in CASES]:
        body = (by_name[name]["saved"] or {}).get("body") or {}
        for k in sorted(SELF_SAVING):
            check(k not in body, "%s: Save does not post %s — a stale card would clobber the switch" % (name, k))
    for fn, paint, why in [("async function setDelivery(", "paintDelivery()", "delivery"),
                           # control_auth is the one the operator reaches for when the fleet has gone
                           # quiet, so it especially must not need the card's Save button to take effect.
                           ("async function setCtlAuth(", "paintCtlAuth()", "control-auth")]:
        i = js.find(fn)
        check(i >= 0, "the %s switch exists" % why)
        if i < 0:
            continue
        check("post('settings-set'" in js[i:i + 400],
              "...the %s switch posts settings-set itself" % why)
        check(paint in js[i:i + 400],
              "...and repaints, so a rejected save does not leave the wrong option lit (%s)" % why)

    print("== 2) ...and the TUNING half, in the same one request ==")
    for name, settings in [(c["name"], c["settings"]) for c in CASES]:
        body = (by_name[name]["saved"] or {}).get("body") or {}
        tun = body.get("tuning")
        check(isinstance(tun, dict), "%s: the POST carries a tuning object" % name)
        if not isinstance(tun, dict):
            continue
        missing = sorted(set(tundef) - set(tun))
        check(not missing, "%s: every declared knob is in the POST (missing=%s)" % (name, missing))
        stored_tun = settings.get("tuning") or {}
        for k in sorted(tundef):
            want = stored_tun.get(k, tundef[k])
            check(tun.get(k) == want, "%s: %-19s form -> POST %s (want %s)" % (name, k, tun.get(k), want))

    print("== 3) the reconcile MODE survives the render, not just the number rows ==")
    check(by_name["a stored non-default"]["mode"] == "auto",
          "a stored mode of auto renders as auto (got %s)" % by_name["a stored non-default"]["mode"])
    check((by_name["a stored non-default"]["saved"] or {}).get("body", {}).get("reconcile_mode") == "auto",
          "...and is what Save posts")

    print("== 4) Reset restores BOTH halves to the compiled-in defaults ==")
    body = (by_name["a stored non-default"]["reset"] or {}).get("body")
    check(body is not None, "reset POSTs something")
    if body:
        for k, want in sorted(setdef.items()):
            check(body.get(k) == want, "%-18s reset -> %s (want %s)" % (k, json.dumps(body.get(k), ensure_ascii=False), want))
        check(body.get("tuning") == tundef, "tuning resets to the whole _TUNDEF dict")
        extra = sorted(set(body) - set(setdef) - {"tuning"})
        check(not extra, "reset posts nothing the defaults do not declare (extra=%s)" % extra)

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("one card, one button: every row of it reaches the panel in a single request, and reset undoes all of it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
