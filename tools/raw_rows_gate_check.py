"""Guard: the raw form's conditional rows, and the IP row's column order, in BOTH forms.

Two rows in the raw block appear only for some profiles:

  * the outer IP protocol number — only for the headerless profile, which is the only one whose number
    is chosen rather than fixed by its header;
  * the forged carrier port — only for the two profiles that forge L4 ports (udp/tcp).

Each form has its own tile handler, and adding a row means remembering to call its gate from BOTH.
Missing it in one leaves the row visible over a profile it does not belong to — which is not cosmetic:
the operator sets a port on ESP, the panel refuses the save with a message about a profile they did not
think they were on, and if the refusal were ever relaxed the core would exit at startup instead.
That shipped: ceSetProfile updated the proto row and not the port row, and the operator found it.

This drives the REAL setters (corSetProfile / ceSetProfile) out of the decoded INDEX_HTML for every
registered profile and asserts what each row does, so a new conditional row is covered the moment its
gate is wired -- and NOT covered silently if it is only wired into one of the two forms.

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


def load_panel():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_gates", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Enough DOM for the page's top-level code, plus an id->node map so style.display persists across calls
# (a fresh stub per el() would make every gate look like it worked).
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
// The IP row: DESTINATION column first (order 0), which in RTL is the right-hand side. The edit form
// has no node pickers to hang the old ordering off, so it went unordered for a whole release and the
// two forms disagreed about which side the destination was on. Both are driven here.
const ipOrder = {};
for (const [form, st, px] of [['create', _corS, 'e_'], ['edit', _eeS, 'ee_']]) {
  ipOrder[form] = {};
  for (const srv of ['a', 'b']) {
    st.Srv = srv;
    _rotS[px] = {on:false, secs:600, aIps:['1.1.1.1'], bIps:['2.2.2.2'], aSel:{}, bSel:{}};
    renderRotIps(px);
    ipOrder[form][srv] = {a: document.getElementById(px+'aip').style.order,
                          b: document.getElementById(px+'bip').style.order};
  }
}
// A stored value must reach the EDIT form's input. raw_proto had a prefill line and raw_port did not,
// so the operator could not see which port a tunnel was on. Checked by driving the same two statements
// the open-edit path runs, then the gate that could overwrite them.
const prefill = {};
for (const [field, id, stored] of [['raw_proto','ee_rawproto',58], ['raw_port','ee_rawport',51820]]) {
  document.getElementById(id).value = '';                    // fresh form
  const l = {}; l[field] = stored;
  cePrefillFields(l);                                        // the REAL prefill the open path runs
  _eeS.Tr = 'raw'; _eeS.RawProfile = (field === 'raw_port') ? 'udp' : 'bare';
  ceProtoVis(); cePortVis();                                 // the gates run AFTER the prefill
  prefill[field] = document.getElementById(id).value;
}
// And with nothing stored, the field must still say what is EFFECTIVE rather than sit blank.
const dflt = {};
for (const [id, profile, gate] of [['ee_rawproto','bare',ceProtoVis], ['ee_rawport','udp',cePortVis]]) {
  document.getElementById(id).value = '';
  _eeS.Tr = 'raw'; _eeS.RawProfile = profile; gate();
  dflt[id] = document.getElementById(id).value;
}
// The source-port MODE segment lives inside the port row, so it is gated by the same profile rule --
// but it has its own per-form setter and its own per-form state field, which is exactly where the
// "create wired, edit not" defects have always come from. Driven here for both.
const sport = {};
for (const [form, st, setter, px] of [['create', _corS, corSetSport, 'e_'],
                                      ['edit',   _eeS,  ceSetSport,  'ee_']]) {
  sport[form] = {};
  for (const on of [1, 0, 1]) {                       // ...and back, so a stuck segment is caught
    setter(on);
    sport[form][on ? 'random' : 'fixed'] = {
      state: !!st.SportRandom,
      fixOn: document.getElementById(px+'sp_fix').classList.contains('on'),
      rndOn: document.getElementById(px+'sp_rnd').classList.contains('on'),
    };
  }
  // What the SHARED body builder actually sends for each mode -- the only thing the node ever sees.
  sport[form].body = {};
  for (const on of [0, 1]) {
    setter(on);
    st.Tr = 'raw'; st.RawProfile = 'tcp';
    document.getElementById(px+'cipher').value = 'auto';
    document.getElementById(px+'rawport').value = '443';
    const b = {};
    _collectCoreBody(st, px, document.getElementById(px+'msg'), b);
    // The KEY's presence matters as much as its value: an absent key falls back to what the tunnel was
    // saved with, so a form that simply omits it when the operator picks «ثابت» cannot turn the mode
    // OFF at all -- the stored true is resurrected on every save.
    sport[form].body[on ? 'random' : 'fixed'] =
      ('raw_sport_random' in b) ? (b.raw_sport_random ? 'true' : 'false') : 'ABSENT';
  }
  setter(0);
}
// An UNSET state must collect as fixed. This is what "the default is fixed" has to mean at the only
// place it matters -- the body -- rather than only at the segment the operator sees.
{
  const st = {Tr:'raw', RawProfile:'tcp', Srv:'a'};      // no SportRandom field at all
  document.getElementById('e_cipher').value = 'auto';
  document.getElementById('e_rawport').value = '443';
  const b = {};
  _collectCoreBody(st, 'e_', document.getElementById('e_msg'), b);
  sport.unsetCollectsFixed = (b.raw_sport_random === false);
}
const PROFILES = %s;
const out = {};
for (const [form, st, setter, px] of [['create', _corS, corSetProfile, 'e_'],
                                      ['edit',   _eeS,  ceSetProfile,  'ee_']]) {
  st.Tr = 'raw';
  out[form] = {};
  for (const p of PROFILES) {
    setter(p);
    const row = id => { const n = document.getElementById(px + id); return n.style.display !== 'none' };
    out[form][p] = {proto: row('protorow'), port: row('portrow')};
  }
}
console.log(JSON.stringify({rows: out, ipOrder, prefill, dflt, sport}));
"""


def main():
    mod = load_panel()
    page = mod.INDEX_HTML
    profiles = sorted(mod.CORE_RAW_PROFILE_PROTOS)
    has_ports = {"udp", "tcp"}          # the profiles that forge an L4 header WITH ports
    headerless = {"bare"}               # the profile whose outer number is chosen, not fixed

    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    for fn in ("function corSetProfile(", "function ceSetProfile("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "gates.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % json.dumps(profiles)), encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:900])
        return 1
    payload = json.loads(r.stdout.strip().splitlines()[-1])
    got, order = payload["rows"], payload["ipOrder"]

    fails = []
    # The harness CALLS cePrefillFields, so it can only prove the function is right — not that the form
    # still calls it. That half is static on purpose: one definition plus at least one call site.
    calls = js.count("cePrefillFields(")
    ok = calls >= 2
    print(("  ok   " if ok else " FAIL ") +
          f"cePrefillFields is defined AND called ({calls} mentions; <2 means the open path dropped it)")
    if not ok:
        fails.append("prefill/not-called")

    # A stored value must survive into the edit form's input, and an unset one must show the effective
    # default rather than a blank box.
    for field, want in (("raw_proto", "58"), ("raw_port", "51820")):
        ok = str(payload["prefill"][field]) == want
        print(("  ok   " if ok else " FAIL ") +
              f"edit   {field}: a stored {want} reaches the input (got {payload['prefill'][field]!r})")
        if not ok:
            fails.append(f"prefill/{field}")
    for el_id, want in (("ee_rawproto", "253"), ("ee_rawport", "443")):
        ok = str(payload["dflt"][el_id]) == want
        print(("  ok   " if ok else " FAIL ") +
              f"edit   {el_id}: unset shows the effective {want} (got {payload['dflt'][el_id]!r})")
        if not ok:
            fails.append(f"default/{el_id}")

    # The destination column is the SERVER's side, and it must come first in both forms.
    for form in ("create", "edit"):
        for srv in ("a", "b"):
            dst_side, src_side = (srv, "b" if srv == "a" else "a")
            got_dst = order[form][srv][dst_side]
            got_src = order[form][srv][src_side]
            ok = got_dst == "0" and got_src == "1"
            print(("  ok   " if ok else " FAIL ") +
                  f"{form:6} server={srv}: destination column order={got_dst!r}, source order={got_src!r}"
                  f"{'' if ok else '  <-- destination must be first (order 0 = right in RTL)'}")
            if not ok:
                fails.append(f"{form}/srv={srv}/order")

    # The source-port mode: state, painted segment, and what the shared body builder emits. All three,
    # in BOTH forms -- a mode that paints but never reaches the body is the failure that ships.
    sport = payload["sport"]
    for form in ("create", "edit"):
        for mode, want_state in (("fixed", False), ("random", True)):
            g = sport[form][mode]
            ok = g["state"] == want_state and g["rndOn"] == want_state and g["fixOn"] != want_state
            print(("  ok   " if ok else " FAIL ") +
                  f"{form:6} sport {mode:6}: state={g['state']} fixed-lit={g['fixOn']} random-lit={g['rndOn']}")
            if not ok:
                fails.append(f"{form}/sport/{mode}")
        for mode, want in (("fixed", "false"), ("random", "true")):
            sent = sport[form]["body"][mode]
            ok = sent == want
            print(("  ok   " if ok else " FAIL ") +
                  f"{form:6} sport {mode:6}: body carries raw_sport_random={sent}"
                  f"{'' if ok else '  <-- want ' + str(want) + '; the mode never reaches the node'}")
            if not ok:
                fails.append(f"{form}/sport-body/{mode}")

    # STATIC, and only this one: the edit form's state is initialised inline in openCoreEdit, which the
    # harness cannot call. Without it the segment would still paint and still collect -- off a state that
    # never learned what the tunnel was saved with, so every edit would silently reset the mode to fixed.
    ok = re.search(r"_eeS\.SportRandom\s*=\s*!!\s*l\.raw_sport_random", js) is not None
    print(("  ok   " if ok else " FAIL ") +
          "edit   openCoreEdit reads raw_sport_random off the stored link (static check)")
    if not ok:
        fails.append("edit/sport-prefill")
    # The operator chose FIXED as the default: a new tunnel must not start rolling unless asked.
    ok = re.search(r"_corS\.SportRandom\s*=\s*false", js) is not None
    print(("  ok   " if ok else " FAIL ") +
          "create openCoreModal defaults the source port to FIXED (static check)")
    if not ok:
        fails.append("create/sport-default")
    ok = bool(sport.get("unsetCollectsFixed"))
    print(("  ok   " if ok else " FAIL ") +
          "both   an unset mode collects as fixed, so the default holds at the BODY too")
    if not ok:
        fails.append("default/collect")

    for form in ("create", "edit"):
        for prof in profiles:
            for row, want in (("proto", prof in headerless), ("port", prof in has_ports)):
                is_on = got[form][prof][row]
                ok = is_on == want
                print(("  ok   " if ok else " FAIL ") +
                      f"{form:6} raw/{prof:8} {row:5} row {'shown' if is_on else 'hidden'}"
                      f"{'' if ok else '  <-- want ' + ('shown' if want else 'hidden')}")
                if not ok:
                    fails.append(f"{form}/{prof}/{row}")

    print()
    if fails:
        print(f"{len(fails)} row(s) gated wrong: {', '.join(fails)}")
        return 1
    print("both forms gate both conditional rows, and put the destination column first")
    return 0


if __name__ == "__main__":
    sys.exit(main())
