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
console.log(JSON.stringify({rows: out, ipOrder, prefill, dflt}));
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
