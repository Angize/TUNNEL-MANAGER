"""Guard: the FEC switch says the truth about FEC, on every transport, in both forms.

FEC only exists on a datagram carrier, and the panel had that set written out FOUR times: once in
corFecDatagram, once in ceFecDatagram, once inline in the edit form's fecSection call, and once inline
in _collectCoreBody. The inline one in the edit form left `spoof` out, so opening a spoof tunnel that
had FEC on rendered the switch UNLIT while the state stayed true — and the gate that runs right after
only ever turns things OFF, so it never re-lit it. One click on what looked like «off» ran the toggle,
which agreed FEC was allowed, and turned it OFF. The operator asked for FEC and got it removed, with
nothing on screen changing.

So the property is not "the inline copy matches": it is that ONE predicate decides, and that the
painted switch and the collected body always agree with the state behind it.

Driven out of the decoded INDEX_HTML through the REAL open path (openCoreEdit / openCoreModal) and the
REAL setters, for every transport the panel offers. The accepted set is PINNED here, not read back out
of the page — a guard that derives its expectation from the code under test agrees with the bug.

One thing the stub DOM cannot do is apply markup: openModal is captured, not parsed, so a node's class
starts empty however the HTML string painted it. The edit case therefore seeds the three fec nodes from
the captured markup and re-runs ceApplyGates, which is exactly the order the browser does it in
(insert, then gate) and is idempotent.

Exit 1 on any mismatch.
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

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

# The transports a datagram carrier's FEC applies to. PINNED, deliberately.
ALLOWED = {"udp", "raw", "spoof"}


def load_panel():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_fec", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PRELUDE = r"""
globalThis.__nodes = {};
const proto = {classList:{_s:new Set(),add(c){this._s.add(c)},remove(c){this._s.delete(c)},
    toggle(c,v){v===undefined?(this._s.has(c)?this._s.delete(c):this._s.add(c)):(v?this._s.add(c):this._s.delete(c))},
    contains(c){return this._s.has(c)}},
  appendChild(){}, addEventListener(){}, setAttribute(){}, removeAttribute(){}, remove(){},
  querySelector(){return null}, querySelectorAll(){return []}, insertAdjacentHTML(){}, closest(){return null},
  getBoundingClientRect(){return {width:0,height:0,top:0,left:0}}, focus(){}, click(){},
  get innerHTML(){return ''}, set innerHTML(v){}, get textContent(){return ''}, set textContent(v){},
  dataset:{}, children:[], parentNode:null, value:''};
function mk(id){ const n = Object.create(proto); n.style = {display:''}; n.id = id;
  n.classList = {_s:new Set(), add(c){this._s.add(c)}, remove(c){this._s.delete(c)},
                 toggle(c,v){v?this._s.add(c):this._s.delete(c)}, contains(c){return this._s.has(c)}};
  return n }
globalThis.document = {documentElement:mk('html'), body:mk('body'), head:mk('head'),
  getElementById(id){ return (globalThis.__nodes[id] ||= mk(id)) },
  querySelector(){return mk('q')}, querySelectorAll(){return []},
  createElement(){return mk('new')}, addEventListener(){}, cookie:'', readyState:'complete', title:''};
globalThis.window = globalThis;
globalThis.location = {href:'http://x/', pathname:'/', search:'', hash:'', reload(){}};
globalThis.localStorage = {getItem(){return null}, setItem(){}, removeItem(){}};
globalThis.matchMedia = () => ({matches:false, addEventListener(){}, addListener(){}});
globalThis.navigator = {userAgent:'node', language:'fa'};
globalThis.fetch = () => new Promise(() => {});
globalThis.setInterval = () => 0;
globalThis.setTimeout = () => 0;
globalThis.requestAnimationFrame = () => 0;
globalThis.alert = () => {}; globalThis.confirm = () => false;
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
"""

HARNESS = r"""
let __html = '';
openModal = function(h){ __html = h };
toast = function(){};
j = async function(){ return {nodes:[{id:1,name:'IR01',host:'1.1.1.1',online:true},
                                     {id:2,name:'DE01',host:'2.2.2.2',online:true}]} };

function fecMarkup(html){
  const row = html.match(/<div id="ee_fecrow"[^>]*>/);
  const sw  = html.match(/<div class="([^"]*)" id="ee_fecsw"/);
  const rat = html.match(/<div id="ee_fecrates" style="([^"]*)"/);
  return {rowShown: row ? row[0].indexOf('display:none') < 0 : null,
          swLit:    sw  ? sw[1].split(/\s+/).indexOf('on') >= 0 : null,
          ratesShown: rat ? rat[1].indexOf('display:none') < 0 : null};
}
function node(id){ return document.getElementById(id) }
// _collectCoreBody refuses a form it cannot build a tunnel from, and four of those refusals sit BEFORE
// the fec line. Fill in what each transport needs so the collect really reaches it -- an abort would
// report fec ABSENT for a reason that has nothing to do with fec.
function bodyFec(S, px){
  const b = {};
  for (const [id, val] of [['cipher','auto'], ['rawport','443'], ['rawproto','253'],
                           ['dnszone','t.example.com'], ['dnsresolvers','1.1.1.1'],
                           ['decoyip','198.51.100.5'], ['wshost','a.example.com'], ['wspath','/x']]) {
    node(px+id).value = val;
  }
  S.Decoy = true;                       // spoof needs a forged source or destination; give it one
  _collectCoreBody(S, px, node(px+'msg'), b);
  return ('fec' in b) ? (b.fec ? 'true' : 'false') : 'ABSENT';
}

const TRANSPORTS = _ENUMS.tr_all.slice();
const out = {edit:{}, create:{}, transports: TRANSPORTS};

// ---- EDIT: the real open path, on a stored tunnel that HAS fec on ----
for (const tr of TRANSPORTS) {
  __html = '';
  globalThis.__nodes = {};                       // a fresh DOM per open, like a fresh modal
  FLEET = [{id:'t1', name:'core42', transport:tr, fec:true, fec_data:10, fec_parity:3,
            a_name:'IR01', b_name:'DE01', server_side:'a', cipher:'auto', port:20050,
            subnet:'10.20.0.0/30', a_ips:['1.1.1.1'], b_ips:['2.2.2.2']}];
  openCoreEdit('t1');
  const m = fecMarkup(__html);
  // Apply the markup the way the browser would, then let the page gate it -- the real order.
  node('ee_fecsw').classList.toggle('on', !!m.swLit);
  node('ee_fecrow').style.display = m.rowShown ? '' : 'none';
  node('ee_fecrates').style.display = m.ratesShown ? '' : 'none';
  ceApplyGates();

  const seen = {markup:m,
    rowShown: node('ee_fecrow').style.display !== 'none',
    swLit:    node('ee_fecsw').classList.contains('on'),
    ratesShown: node('ee_fecrates').style.display !== 'none',
    state: !!_eeS.Fec, predicate: !!ceFecDatagram(), body: bodyFec(_eeS, 'ee_')};
  ceToggleFec();                                  // exactly one operator click
  seen.afterClick = {state: !!_eeS.Fec, swLit: node('ee_fecsw').classList.contains('on'),
                     body: bodyFec(_eeS, 'ee_')};
  out.edit[tr] = seen;
}

// ---- CREATE: the real open path, then the real transport setter ----
(async function(){
  for (const tr of TRANSPORTS) {
    globalThis.__nodes = {};
    __html = '';
    await openCoreModal();
    const m0 = fecMarkup(__html.replace(/ee_/g, 'ee_'));   // create ids are e_*, read them directly below
    const row0 = __html.match(/<div id="e_fecrow"[^>]*>/);
    const sw0  = __html.match(/<div class="([^"]*)" id="e_fecsw"/);
    node('e_fecsw').classList.toggle('on', sw0 ? sw0[1].split(/\s+/).indexOf('on') >= 0 : false);
    node('e_fecrow').style.display = (row0 && row0[0].indexOf('display:none') < 0) ? '' : 'none';
    corSetTr(tr);                                  // the real segment the operator taps
    const seen = {openRowShown: row0 ? row0[0].indexOf('display:none') < 0 : null,
      openSwLit: sw0 ? sw0[1].split(/\s+/).indexOf('on') >= 0 : null,
      rowShown: node('e_fecrow').style.display !== 'none',
      swLit: node('e_fecsw').classList.contains('on'),
      state: !!_corS.Fec, predicate: !!corFecDatagram(), body: bodyFec(_corS, 'e_')};
    corToggleFec();                                // one click on a fresh (off) switch
    seen.afterClick = {state: !!_corS.Fec, swLit: node('e_fecsw').classList.contains('on'),
                       body: bodyFec(_corS, 'e_')};
    out.create[tr] = seen;
    void m0;
  }
  console.log(JSON.stringify(out));
})();
"""


def main():
    mod = load_panel()
    page = mod.INDEX_HTML
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    for fn in ("function fecDatagram(", "function openCoreEdit(", "function corSetTr("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page — the guard cannot read its subject" % fn)
            return 1

    # ONE predicate: nobody else may spell the set out. Four copies is how spoof got dropped from one.
    spelled = re.findall(r"Tr\s*==\s*'udp'\s*\|\|[^;){]*'spoof'", js)
    if len(spelled) != 1:
        print("FAIL: the datagram-transport set is written out %d times in the page JS; "
              "there must be exactly one (fecDatagram). Copies found:" % len(spelled))
        for s in spelled:
            print("   " + s[:120])
        return 1

    # STATIC, and only this one: the create form renders at Tr='udp' every time (openCoreModal sets it),
    # so a hardcoded dg there is right at render and the setter fixes every later transport — nothing
    # observable to assert. It is still the shape that shipped the bug, so pin the call itself: whatever
    # fecSection is told, it must be told by the predicate.
    calls = re.findall(r"(fecSection\('e{1,2}_'[^\n]*?)\)\+", js)
    for c in calls:
        if not re.search(r"(cor|ce)FecDatagram\(\)\s*$", c.strip()):
            print("FAIL: a fecSection call decides its own dg instead of asking the predicate:\n"
                  "   fecSection(%s)" % c[:160])
            return 1
    if len(calls) != 2:
        print("FAIL: found %d fecSection call sites, expected the create and edit forms" % len(calls))
        return 1
    print("  ok   both fecSection call sites take their dg from the predicate (static check)")

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fec.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + HARNESS, encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:1200])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])

    fails = []
    print("  ok   the datagram-transport set is spelled out exactly once (fecDatagram)")

    for tr in got["transports"]:
        allow = tr in ALLOWED
        e = got["edit"][tr]

        checks = [
            ("edit  ", tr, "the render's own gate", e["markup"]["rowShown"], allow,
             "the row is rendered {got}, want {want} — fecSection's dg argument disagrees with the predicate"),
            ("edit  ", tr, "the switch is painted from the same predicate", e["markup"]["swLit"], allow,
             "a stored fec=true paints the switch {got}, want {want}"),
            ("edit  ", tr, "the row after the gates", e["rowShown"], allow, "row shown={got}, want {want}"),
            ("edit  ", tr, "predicate", e["predicate"], allow, "ceFecDatagram()={got}, want {want}"),
            ("edit  ", tr, "state", e["state"], allow, "_eeS.Fec={got}, want {want}"),
            ("edit  ", tr, "the switch agrees with the state", e["swLit"], e["state"],
             "the switch reads {got} while the state is {want} — the operator cannot see what is set"),
        ]
        for form, t, what, gotv, wantv, msg in checks:
            ok = gotv == wantv
            print(("  ok   " if ok else " FAIL ") + f"{form} {t:6} {what}"
                  + ("" if ok else "  <-- " + msg.format(got=gotv, want=wantv)))
            if not ok:
                fails.append(f"edit/{t}/{what}")

        want_body = "true" if allow else "ABSENT"
        ok = e["body"] == want_body
        print(("  ok   " if ok else " FAIL ") + f"edit   {tr:6} the body carries fec={e['body']}"
              + ("" if ok else f"  <-- want {want_body}"))
        if not ok:
            fails.append(f"edit/{tr}/body")

        # One click. On a datagram transport it must turn a lit switch OFF and say so in the body; on
        # anything else it must do nothing at all.
        ac = e["afterClick"]
        want_state = False if allow else False
        ok = ac["state"] == want_state and ac["swLit"] == ac["state"]
        print(("  ok   " if ok else " FAIL ") +
              f"edit   {tr:6} one click -> state={ac['state']} switch={ac['swLit']} body fec={ac['body']}"
              + ("" if ok else "  <-- the click and the paint disagree"))
        if not ok:
            fails.append(f"edit/{tr}/click")

        c = got["create"][tr]
        for what, gotv, wantv in (("the row after the setter", c["rowShown"], allow),
                                  ("predicate", c["predicate"], allow),
                                  ("the switch agrees with the state", c["swLit"], c["state"])):
            ok = gotv == wantv
            print(("  ok   " if ok else " FAIL ") + f"create {tr:6} {what}"
                  + ("" if ok else f"  <-- got {gotv}, want {wantv}"))
            if not ok:
                fails.append(f"create/{tr}/{what}")
        # A fresh create form starts with FEC off, so one click must turn it ON where it is allowed.
        ok = c["afterClick"]["state"] == allow and c["afterClick"]["swLit"] == c["afterClick"]["state"]
        print(("  ok   " if ok else " FAIL ") +
              f"create {tr:6} one click -> state={c['afterClick']['state']} switch={c['afterClick']['swLit']}"
              + ("" if ok else f"  <-- want state={allow} and the switch to match"))
        if not ok:
            fails.append(f"create/{tr}/click")

    print()
    if fails:
        print(f"{len(fails)} FEC gate mismatch(es): {', '.join(sorted(set(fails)))}")
        return 1
    print("one predicate decides FEC in both forms, and the switch, the state and the body agree "
          "on every transport")
    return 0


if __name__ == "__main__":
    sys.exit(main())
