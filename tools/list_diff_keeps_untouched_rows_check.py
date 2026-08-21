#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: a list refresh must replace only the rows that changed.

Every live page rebuilds its list on a timer. It used to assign the whole thing at once, which drops
every row in the document — including the ones whose markup came back identical. What goes with them
is not only pixels: a selection the operator is half way through making, a live upload bar, an edge
box another loop filled on its own cadence. That is why a value on a card cannot be copied on a panel
that is polling every couple of seconds.

`setList` fixes it by matching rows on a key. This drives the REAL `setList` out of the decoded
INDEX_HTML against a small DOM and asserts what the operator actually needs:

  * a row whose markup did not change keeps the very node it had — same object, not an equal one
  * a row whose markup did change is replaced
  * a reorder moves the nodes the list already has
  * rows that left are gone, and the list is exactly what was asked for
  * a tick that changes nothing touches the document at all

And the assumption the whole scheme rests on: every builder that feeds a list returns exactly ONE
root element. `rowNode` keeps the first and would drop the rest in silence.

Exit 1 on any failure.
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

# A DOM with the few things setList touches, and no more: children that are really there, insertion
# that really moves a node, and an innerHTML that really parses. Rows are one element each — which is
# the claim the last check in here defends — so the parser only has to split top-level elements.
PRELUDE = r"""
const noop = () => {};
let NODE_SERIAL = 0;
class El {
  constructor(tag){ this.tag = tag; this.serial = ++NODE_SERIAL; this.attrs = {}; this.kids = []; this.parent = null; this.text = ''; }
  get children(){ return this.kids; }
  get firstChild(){ return this.kids[0] || null; }
  get firstElementChild(){ return this.kids[0] || null; }
  get nextSibling(){ if(!this.parent) return null; const i = this.parent.kids.indexOf(this); return this.parent.kids[i+1] || null; }
  setAttribute(k, v){ this.attrs[k] = String(v); }
  getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }
  insertBefore(node, ref){
    if (node.parent) node.parent.kids.splice(node.parent.kids.indexOf(node), 1);
    node.parent = this;
    const at = ref ? this.kids.indexOf(ref) : this.kids.length;
    this.kids.splice(at < 0 ? this.kids.length : at, 0, node);
    return node;
  }
  appendChild(node){ return this.insertBefore(node, null); }
  removeChild(node){ const i = this.kids.indexOf(node); if (i >= 0) { this.kids.splice(i, 1); node.parent = null; } return node; }
  remove(){ if (this.parent) this.parent.removeChild(this); }
  set textContent(v){ for (const k of this.kids) k.parent = null; this.kids = []; this.text = String(v); }
  get textContent(){ return this.kids.length ? this.kids.map(k => k.textContent).join('') : this.text; }
  set innerHTML(h){
    for (const k of this.kids) k.parent = null;
    this.kids = [];
    for (const piece of splitTop(String(h))) this.appendChild(parseOne(piece));
  }
  get innerHTML(){ return this.kids.map(k => k.outer).join(''); }
  get outer(){ return this._outer || ''; }
  get content(){ return this; }
}
// Split a string of sibling elements at depth 0. Good enough for markup the panel itself produced.
function splitTop(h){
  const out = []; let depth = 0, start = -1;
  const tag = /<(\/?)([a-zA-Z][\w-]*)([^>]*)>/g;
  let m;
  while ((m = tag.exec(h))) {
    const closing = m[1] === '/', selfClose = /\/\s*$/.test(m[3]);
    const isVoid = /^(br|hr|img|input|meta|link|source|path|circle|rect|line|polyline|polygon|use|stop)$/i.test(m[2]);
    if (!closing && !selfClose && !isVoid) { if (depth === 0) start = m.index; depth++; }
    else if (closing) { depth--; if (depth === 0 && start >= 0) { out.push(h.slice(start, tag.lastIndex)); start = -1; } }
    else if (depth === 0) out.push(m[0]);
  }
  return out;
}
function parseOne(piece){
  const m = /^<([a-zA-Z][\w-]*)/.exec(piece);
  const el = new El(m ? m[1] : 'div');
  el._outer = piece;
  const inner = piece.replace(/^<[^>]*>/, '').replace(/<\/[^>]*>$/, '');
  el.text = inner.replace(/<[^>]*>/g, '');
  return el;
}
globalThis.window = globalThis;
globalThis.document = { createElement: t => new El(t), getElementById: () => null,
  querySelector: () => null, querySelectorAll: () => [], addEventListener: noop,
  body: {appendChild: noop, classList: {add: noop, remove: noop, toggle: noop, contains: () => false}},
  documentElement: {classList: {add: noop, remove: noop, toggle: noop, contains: () => false}, style: {}} };
globalThis.setInterval = () => 0;
globalThis.setTimeout = () => 0;
globalThis.requestAnimationFrame = () => 0;
globalThis.localStorage = {getItem: () => null, setItem: noop, removeItem: noop};
globalThis.matchMedia = () => ({matches: false, addEventListener: noop, addListener: noop});
Object.defineProperty(globalThis, 'navigator', {value: {userAgent: 'node', language: 'fa'}, configurable: true});
globalThis.location = {href: 'http://x/', pathname: '/', search: '', hash: '', reload: noop};
globalThis.fetch = () => new Promise(() => {});
globalThis.getComputedStyle = () => ({getPropertyValue: () => ''});
globalThis.alert = noop; globalThis.confirm = () => false;
"""

HARNESS = r"""
const out = {};
const box = document.createElement('div');
const rows = a => a.map(x => ({k: x[0], h: '<div class="card" id="c_' + x[0] + '">' + x[1] + '</div>'}));
const serials = () => box.children.map(c => c.serial);
const keys = () => box.children.map(c => c.getAttribute('data-k')).join(',');

// the skeleton a page paints before its first fetch lands
box.innerHTML = '<div class="sk">loading</div>';
setList(box, rows([['a', 'A1'], ['b', 'B1'], ['c', 'C1']]));
out.first = {keys: keys(), tagged: box.children.every(c => c.getAttribute('data-k') && c._h)};
const s0 = serials();

// one row's markup moved on; the other two came back identical
setList(box, rows([['a', 'A2'], ['b', 'B1'], ['c', 'C1']]));
const s1 = serials();
out.oneChanged = {replaced: s1[0] !== s0[0], keptB: s1[1] === s0[1], keptC: s1[2] === s0[2]};

// a tick that brings nothing back at all
setList(box, rows([['a', 'A2'], ['b', 'B1'], ['c', 'C1']]));
out.nothingChanged = {allKept: JSON.stringify(serials()) === JSON.stringify(s1)};

// the operator reordered the cards: the same nodes must move
setList(box, rows([['c', 'C1'], ['a', 'A2'], ['b', 'B1']]));
out.reordered = {keys: keys(), moved: JSON.stringify(serials()) === JSON.stringify([s1[2], s1[0], s1[1]])};

// one left
setList(box, rows([['c', 'C1'], ['b', 'B1']]));
out.removed = {keys: keys(), count: box.children.length};

// the empty state is a row like any other, and the list can come back from it
setList(box, [{k: '__empty', h: '<div class="card muted">nothing here</div>'}]);
out.empty = {keys: keys(), text: box.textContent};
setList(box, rows([['z', 'Z1']]));
out.backFromEmpty = {keys: keys()};

// every builder that feeds a list has to return exactly one root element
TOPEN = {}; PUSHSTATE = null; STAGED = null; AGMETA = null; QRY = {}; PG = {}; TOT = {};
const oneRoot = h => splitTop(h).length === 1;
const L = {id: 'x1', name: 't', type: 'core', a_node: 'n1', b_node: 'n2', a_name: 'A', b_name: 'B',
  status: 'up', enabled: true, transport: 'udp', subnet: '10.0.0.0/30', port: 1,
  rx_bps: 1, tx_bps: 1, rx_total: 1, tx_total: 1, ping_ms: 1, loss: 0};
const N = {id: 'n1', name: 'node1', host: '1.2.3.4', online: true, info: {version: 1, arch: 'amd64'}};
const PXX = {id: 'p1', name: 'px', node_id: 'n1', node: 'node1', kind: 'socks5', port: 1080};
const PFF = {node_id: 'n1', node: 'node1', name: 'pf1', listen_port: 80, dst_ips: ['1.2.3.4'],
  health: {rule: true, reachable: true}};
out.roots = {};
for (const [name, fn] of [['coreCard', () => coreCard(L)], ['linkCard', () => linkCard(L)],
                          ['nodeCard', () => nodeCard(N)], ['pxCard', () => pxCard(PXX, 0)],
                          ['pfCard', () => pfCard(PFF, 0)], ['agRow', () => agRow(N)]]) {
  try { out.roots[name] = oneRoot(fn()); } catch (e) { out.roots[name] = 'ERR ' + e.message; }
}
LOGEVS = [{ts: 1755600000, level: 'ok', kind: 'link', fa: 'a logged event', dfa: ''}];
LOGFILTER = 'all'; LOGOPEN = {};
try { const lr = logRows(); out.roots.logRow = lr.length === 1 && oneRoot(lr[0].h) && !!lr[0].k; }
catch (e) { out.roots.logRow = 'ERR ' + e.message; }

console.log('@@' + JSON.stringify(out));
"""


def decoded_index_html():
    """The page as the browser gets it. Import rather than read the file: the source still holds
    `__NAME_JSON__` placeholders that only the import-time .replace wiring fills in."""
    spec = importlib.util.spec_from_file_location("tnl_central_listdiff", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.INDEX_HTML


def page_script(html):
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)
    if not blocks:
        sys.exit("list-diff: no <script> block in the decoded page")
    return max(blocks, key=len)


def main():
    src = PANEL.read_text(encoding="utf-8")
    script = page_script(decoded_index_html())
    if "function setList(" not in script:
        sys.exit("list-diff: the page has no setList — the lists went back to whole-list assignment")

    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False, encoding="utf-8") as f:
        f.write(PRELUDE + "\n" + script + "\n" + HARNESS)
        path = f.name
    r = subprocess.run([("node"), path], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print(r.stdout[-3000:])
        print(r.stderr[-3000:])
        sys.exit("list-diff: the page did not run")
    line = [l for l in r.stdout.splitlines() if l.startswith("@@")]
    if not line:
        print(r.stdout[-3000:])
        sys.exit("list-diff: the harness printed nothing")
    got = json.loads(line[-1][2:])

    print("== list refresh replaces only what changed ==")
    fails = []

    def ok(cond, good, bad):
        print(("  ok   " if cond else " FAIL  ") + (good if cond else bad))
        if not cond:
            fails.append(bad)

    ok(got["first"]["keys"] == "a,b,c" and got["first"]["tagged"],
       "the first fill lays the rows out and keys every one of them",
       "the first fill did not key its rows: %r" % (got["first"],))
    ok(got["oneChanged"]["replaced"] and got["oneChanged"]["keptB"] and got["oneChanged"]["keptC"],
       "a changed row is replaced and the untouched ones keep the very nodes they had",
       "a refresh replaced rows that did not change: %r — a selection in one of them dies with it"
       % (got["oneChanged"],))
    ok(got["nothingChanged"]["allKept"],
       "a tick that brings nothing back touches nothing",
       "a tick with no new data still rebuilt rows: %r" % (got["nothingChanged"],))
    ok(got["reordered"]["keys"] == "c,a,b" and got["reordered"]["moved"],
       "a reorder moves the nodes the list already has",
       "a reorder rebuilt the rows instead of moving them: %r" % (got["reordered"],))
    ok(got["removed"]["keys"] == "c,b" and got["removed"]["count"] == 2,
       "a row that left is gone, and only it",
       "removal left the list wrong: %r" % (got["removed"],))
    ok(got["empty"]["keys"] == "__empty" and "nothing here" in got["empty"]["text"]
       and got["backFromEmpty"]["keys"] == "z",
       "the empty state is a row like any other, and the list comes back from it",
       "the empty state broke the list: %r / %r" % (got["empty"], got["backFromEmpty"]))
    for name, v in sorted(got["roots"].items()):
        ok(v is True, "%s returns exactly one root element" % name,
           "%s does not return exactly one root element (%r) — rowNode keeps the first and drops the "
           "rest without a word" % (name, v))

    if fails:
        print()
        print("%d failure(s)." % len(fails))
        return 1
    print()
    print("every list keeps the rows that did not change")
    return 0


if __name__ == "__main__":
    sys.exit(main())
