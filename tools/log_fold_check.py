#!/usr/bin/env python3
"""Guard: the system log's fold covers endpoint rows and never swallows a plain sentence.

A log card shows the reason line and nothing else at a glance; the endpoint boxes — «از» / «به» /
«لبه» — live behind a «جزئیات» toggle. But a card whose whole detail is one sentence («اتصال قطع شد»)
must NOT get a toggle: that sentence IS the reason said once more, so a control over it costs a tap and
reveals nothing.

The split is decided in one place, `evDetail`, by the SAME test that already sorted labelled rows from
notes. This pins that: labelled rows fold, notes stay inline, and a rebuilt list keeps whatever the
operator opened — refreshLogs throws the whole list away every few seconds, so fold state read back off
the DOM would be wiped on the next poll.

It runs the real function out of the DECODED INDEX_HTML under node, never against the .py source: the
escapes are still doubled there, so a harness reading the file directly either fails to parse or, worse,
quietly passes on text that was never what the browser sees.

Exit 1 = the fold would hide a sentence, expose the endpoints, or lose its state on a poll.
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


def index_html():
    """The page as the SERVER hands it out. Imported, never parsed out of the source: the literal in the
    file is a template with placeholders still in it (__ENUMS_JSON__ and friends are substituted at
    import), and a guard reading that would be testing something no browser ever receives."""
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_fold", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    page = mod.INDEX_HTML
    if "__ENUMS_JSON__" in page:
        raise SystemExit("FAIL: the page still carries an unsubstituted placeholder")
    return page


# The page's script runs top-level code that touches the document (setting lang/dir) and installs timers.
# Stub only what it reaches for, so the FUNCTIONS under test are still the page's own text, byte for byte
# — the alternative, snipping evDetail out of the source, is how a harness ends up testing something the
# browser never runs.
PRELUDE = r"""
const _node = {style:{}, classList:{add(){},remove(){},toggle(){},contains(){return false}},
  appendChild(){}, addEventListener(){}, setAttribute(){}, removeAttribute(){}, remove(){},
  querySelector(){return null}, querySelectorAll(){return []}, insertAdjacentHTML(){},
  getBoundingClientRect(){return {width:0,height:0,top:0,left:0}}, focus(){}, click(){},
  get innerHTML(){return ''}, set innerHTML(v){}, get textContent(){return ''}, set textContent(v){},
  get scrollLeft(){return 0}, set scrollLeft(v){}, dataset:{}, children:[], parentNode:null};
const _mk = () => Object.create(_node);
globalThis.document = {documentElement:_node, body:_node, head:_node,
  getElementById(){return _mk()}, querySelector(){return _mk()}, querySelectorAll(){return []},
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
const cases = %s;
const out = [];
for (const c of cases) {
  const html = evDetail(c.lines, 'kX');
  out.push({
    name: c.name,
    folded: html.indexOf('class="lfold') >= 0,
    hasRows: html.indexOf('class="lfromto"') >= 0,
    hasNote: html.indexOf('class="lnote"') >= 0,
    empty: html === '',
  });
}
// State must live outside the DOM, or the poll's rebuild wipes it.
LOGOPEN['kX'] = true;
const reopened = evDetail(['از: 1.1.1.1 → 2.2.2.2', 'به: 3.3.3.3 → 2.2.2.2'], 'kX').indexOf(' open') >= 0;
// The key must be stable for the same event and differ for a different one.
const a1 = evKey({ts: 10, fa: 'x', dfa: 'y'}), a2 = evKey({ts: 10, fa: 'x', dfa: 'y'});
const b1 = evKey({ts: 10, fa: 'x', dfa: 'z'});
console.log(JSON.stringify({out, reopened, keyStable: a1 === a2, keyDistinct: a1 !== b1,
                            keySafe: /^k[0-9]+$/.test(a1)}));
"""

CASES = [
    {"name": "a source rotation's endpoint pair", "lines": ["از: 1.1.1.1 → 2.2.2.2", "به: 3.3.3.3 → 2.2.2.2"],
     "want": {"folded": True, "hasRows": True}},
    {"name": "a ws edge switch", "lines": ["از: 1.2.3.4:443 · a.example", "به: 5.6.7.8:443 · a.example"],
     "want": {"folded": True, "hasRows": True}},
    {"name": "a burn naming one endpoint", "lines": ["لبه: 5.6.7.8"],
     "want": {"folded": True, "hasRows": True}},
    {"name": "a bare disconnect sentence", "lines": ["اتصال قطع شد"],
     "want": {"folded": False, "hasNote": True}},
    {"name": "a self-heal sentence", "lines": ["پس از افتِ سشن، خودکار وصل شد (self-heal)"],
     "want": {"folded": False, "hasNote": True}},
    {"name": "no detail at all", "lines": [],
     "want": {"folded": False, "empty": True}},
]


def main():
    page = index_html()
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    if "function evDetail(" not in js or "function evKey(" not in js:
        print("FAIL: evDetail/evKey are not in the rendered page — the guard cannot read its subject")
        return 1
    payload = json.dumps([{"name": c["name"], "lines": c["lines"]} for c in CASES], ensure_ascii=False)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "fold.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % payload), encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:800])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])

    bad = []
    for case, res in zip(CASES, got["out"]):
        for k, v in case["want"].items():
            ok = res.get(k) == v
            print(("  ok   " if ok else " FAIL ") + f"{case['name']}: {k}={res.get(k)} (want {v})")
            if not ok:
                bad.append(case["name"])
    for k, msg in (("reopened", "an opened card must stay open when the poll rebuilds the list"),
                   ("keyStable", "the same event must key to the same card"),
                   ("keyDistinct", "two different events must not share a fold"),
                   ("keySafe", "the key goes into a DOM id and an onclick literal — digits only")):
        ok = bool(got.get(k))
        print(("  ok   " if ok else " FAIL ") + msg)
        if not ok:
            bad.append(msg)

    if bad:
        print(f"\n{len(bad)} failure(s)")
        return 1
    print("\nthe fold hides endpoints, never a sentence, and survives the poll")
    return 0


if __name__ == "__main__":
    sys.exit(main())
