"""Guard: the raw-form conditional rows must re-gate on EVERY profile change, in BOTH forms.

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
console.log(JSON.stringify(out));
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
    got = json.loads(r.stdout.strip().splitlines()[-1])

    fails = []
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
    print("both forms gate both conditional rows on every registered profile")
    return 0


if __name__ == "__main__":
    sys.exit(main())
