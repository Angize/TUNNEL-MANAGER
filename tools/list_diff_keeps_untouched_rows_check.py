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
  * a row whose markup DID change keeps its nodes too, and is brought up to date inside them
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
class Txt {
  constructor(v){ this.serial = ++NODE_SERIAL; this.nodeType = 3; this.nodeName = '#text'; this.nodeValue = v; this.parent = null; }
  get nextSibling(){ if(!this.parent) return null; const i = this.parent.nodes.indexOf(this); return this.parent.nodes[i+1] || null; }
  get textContent(){ return this.nodeValue; }
  get outer(){ return this.nodeValue; }
}
class El {
  constructor(tag){ this.serial = ++NODE_SERIAL; this.nodeType = 1; this.tag = tag;
    this.nodeName = tag.toUpperCase(); this.attrs = new Map(); this.nodes = []; this.parent = null; }
  get children(){ return this.nodes.filter(n => n.nodeType === 1); }
  get childNodes(){ return this.nodes; }
  get firstChild(){ return this.nodes[0] || null; }
  get firstElementChild(){ return this.children[0] || null; }
  get nextSibling(){ if(!this.parent) return null; const i = this.parent.nodes.indexOf(this); return this.parent.nodes[i+1] || null; }
  // A real element always has one, and setList marks a freshly inserted row through it. Without this
  // the stub is not an element and the guard fails on its own scaffolding rather than on the diff.
  get classList(){ const el = this;
    const set = () => new Set((el.getAttribute('class') || '').split(/\s+/).filter(Boolean));
    const put = s => el.setAttribute('class', [...s].join(' '));
    return { add(c){ const s = set(); s.add(c); put(s); },
             remove(c){ const s = set(); s.delete(c); put(s); },
             toggle(c, on){ const s = set(); (on === undefined ? (s.has(c) ? s.delete(c) : s.add(c)) : (on ? s.add(c) : s.delete(c))); put(s); },
             contains(c){ return set().has(c); } }; }
  get attributes(){ return [...this.attrs].map(([name, value]) => ({name, value})); }
  setAttribute(k, v){ this.attrs.set(k, String(v)); }
  getAttribute(k){ return this.attrs.has(k) ? this.attrs.get(k) : null; }
  hasAttribute(k){ return this.attrs.has(k); }
  removeAttribute(k){ this.attrs.delete(k); }
  insertBefore(node, ref){
    if (node.parent) node.parent.nodes.splice(node.parent.nodes.indexOf(node), 1);
    node.parent = this;
    const at = ref ? this.nodes.indexOf(ref) : this.nodes.length;
    this.nodes.splice(at < 0 ? this.nodes.length : at, 0, node);
    return node;
  }
  appendChild(node){ return this.insertBefore(node, null); }
  replaceChild(fresh, old){ const i = this.nodes.indexOf(old);
    if (fresh.parent) fresh.parent.nodes.splice(fresh.parent.nodes.indexOf(fresh), 1);
    fresh.parent = this; old.parent = null; this.nodes[i] = fresh; return old; }
  removeChild(node){ const i = this.nodes.indexOf(node); if (i >= 0) { this.nodes.splice(i, 1); node.parent = null; } return node; }
  remove(){ if (this.parent) this.parent.removeChild(this); }
  set textContent(v){ for (const n of this.nodes) n.parent = null; this.nodes = []; if (v !== '') this.appendChild(new Txt(String(v))); }
  get textContent(){ return this.nodes.map(n => n.textContent).join(''); }
  set innerHTML(h){ for (const n of this.nodes) n.parent = null; this.nodes = []; for (const n of parseNodes(String(h))) this.appendChild(n); }
  get innerHTML(){ return this.nodes.map(n => n.outer).join(''); }
  get outer(){ const at = [...this.attrs].map(([k, v]) => ` ${k}="${v}"`).join('');
    return `<${this.tag}${at}>${this.innerHTML}</${this.tag}>`; }
}
const VOID = /^(br|hr|img|input|meta|link|source)$/i;
// A parser, not a splitter: morphNode walks text nodes and nested elements, so the guard has to have
// them. Markup the panel itself produced, so no error recovery.
function parseNodes(h){
  const out = []; let i = 0;
  while (i < h.length) {
    const lt = h.indexOf('<', i);
    if (lt < 0) { if (h.slice(i)) out.push(new Txt(h.slice(i))); break; }
    if (lt > i) out.push(new Txt(h.slice(i, lt)));
    const gt = h.indexOf('>', lt);
    const raw = h.slice(lt + 1, gt);
    const tagm = /^([a-zA-Z][\w-]*)/.exec(raw);
    if (!tagm) throw new Error('unbalanced markup at ' + JSON.stringify(h.slice(lt, lt + 60)));
    const tag = tagm[1];
    const el = new El(tag);
    const attr = /([:\w-]+)\s*=\s*"([^"]*)"/g;
    let m; while ((m = attr.exec(raw))) el.attrs.set(m[1], m[2]);
    if (VOID.test(tag) || /\/\s*$/.test(raw)) { out.push(el); i = gt + 1; continue; }
    // find this tag's own closing tag, counting nested ones of the same name
    let depth = 1, at = gt + 1, close = -1;
    // The lookahead is built from a STRING, so the backslash has to survive into the RegExp: written
    // as '[\s/>]' the escape is eaten by the string literal and the class becomes [s/>], which stops
    // counting every nested `<div class=…>` and silently mis-nests any real card.
    const same = new RegExp('<(/?)' + tag + '(?=[\\s/>])', 'gi'); same.lastIndex = at;
    let mm; while ((mm = same.exec(h))) { depth += mm[1] ? -1 : 1; if (!depth) { close = mm.index; break; } }
    const inner = close < 0 ? h.slice(at) : h.slice(at, close);
    for (const n of parseNodes(inner)) el.appendChild(n);
    i = close < 0 ? h.length : h.indexOf('>', close) + 1;
    out.push(el);
  }
  return out;
}
// Counting a real card's root elements needs nothing but tag depth, and the little parser above is
// only ever fed the guard's own rows.
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

// one row's markup moved on; the other two came back identical. The changed one has to end up
// showing the new markup WITHOUT being taken out of the document, and the text node it shows it in
// has to be the same one — that is the node a selection lives in.
const textNode = box.children[0].firstChild;
setList(box, rows([['a', 'A2'], ['b', 'B1'], ['c', 'C1']]));
const s1 = serials();
out.oneChanged = {keptA: s1[0] === s0[0], keptB: s1[1] === s0[1], keptC: s1[2] === s0[2],
  sameTextNode: box.children[0].firstChild === textNode,
  showsTheNewText: box.children[0].textContent === 'A2',
  markupRemembered: box.children[0]._h.indexOf('A2') > 0};

// a tick that brings nothing back at all
setList(box, rows([['a', 'A2'], ['b', 'B1'], ['c', 'C1']]));
out.nothingChanged = {allKept: JSON.stringify(serials()) === JSON.stringify(s1)};

// a row that loses a child, and one that gains one: what is left over has to go, and what is new has
// to arrive, or the row shows a mixture of the two polls
const raw = h => [{k: 'r', h}];
const rbox = document.createElement('div');
setList(rbox, raw('<div id="r"><b>x</b><i>y</i><u>z</u></div>'));
const rnode = rbox.children[0];
setList(rbox, raw('<div id="r"><b>x</b></div>'));
out.shrank = {kept: rbox.children[0] === rnode, html: rbox.children[0].outer};
setList(rbox, raw('<div id="r"><b>x</b><i>y2</i></div>'));
out.grew = {kept: rbox.children[0] === rnode, html: rbox.children[0].outer};

// attributes: a card's inline handler carries the row's own index, so a row left holding the last
// poll's attributes acts on whatever used to be in its place.
setList(rbox, raw('<div id="r" class="card" onclick="act(1)">x</div>'));
const anode = rbox.children[0];
setList(rbox, raw('<div id="r" class="card off" onclick="act(2)" title="t">x</div>'));
out.attrs = {kept: rbox.children[0] === anode, cls: rbox.children[0].getAttribute('class'),
  click: rbox.children[0].getAttribute('onclick'), title: rbox.children[0].getAttribute('title')};
setList(rbox, raw('<div id="r" class="card">x</div>'));
out.attrsDropped = {title: rbox.children[0].getAttribute('title'),
  click: rbox.children[0].getAttribute('onclick'), kept: rbox.children[0] === anode};

// a child that changed KIND has to be swapped for the new one, not have the new one's attributes
// painted onto it: a span wearing a div's markup is the wrong element in the wrong place.
setList(rbox, raw('<div id="r"><b>keep</b><span class="v">1</span></div>'));
const knode = rbox.children[0], kkid = rbox.children[0].children[0];
setList(rbox, raw('<div id="r"><b>keep</b><i class="v">2</i></div>'));
out.childKind = {rowKept: rbox.children[0] === knode, siblingKept: rbox.children[0].children[0] === kkid,
  html: rbox.children[0].outer};

// a row whose own kind changed cannot be updated in place; it has to be swapped
setList(rbox, raw('<div id="r">x</div>'));
const before = rbox.children[0];
setList(rbox, raw('<section id="r">x</section>'));
out.rowKind = {swapped: rbox.children[0] !== before, html: rbox.children[0].outer};

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
TOPEN = {}; PUSHSTATE = null; STAGED = null; AGMETA = null; QRY = {};
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
    oc = got["oneChanged"]
    ok(oc["keptA"] and oc["keptB"] and oc["keptC"],
       "no row is taken out of the document, changed or not",
       "a refresh took rows out of the document: %r — a selection in one of them dies with it" % (oc,))
    ok(oc["sameTextNode"] and oc["showsTheNewText"] and oc["markupRemembered"],
       "the row that changed is brought up to date in the nodes it already had",
       "the changed row did not update in place: %r" % (oc,))
    ok(got["shrank"]["kept"] and got["shrank"]["html"] == '<div id="r" data-k="r"><b>x</b></div>',
       "a row that lost children keeps its node and loses exactly them",
       "a row that lost children came out wrong: %r" % (got["shrank"],))
    ok(got["grew"]["kept"] and got["grew"]["html"] == '<div id="r" data-k="r"><b>x</b><i>y2</i></div>',
       "a row that gained a child keeps its node and gains exactly it",
       "a row that gained a child came out wrong: %r" % (got["grew"],))
    ok(got["attrs"]["kept"] and got["attrs"]["cls"] == "card off"
       and got["attrs"]["click"] == "act(2)" and got["attrs"]["title"] == "t",
       "a row's attributes follow the new markup without the row leaving the document",
       "attributes did not follow the new markup: %r — the row is left acting on the last poll" % (got["attrs"],))
    ok(got["attrsDropped"]["title"] is None and got["attrsDropped"]["click"] is None
       and got["attrsDropped"]["kept"],
       "an attribute the new markup dropped is gone from the row",
       "an attribute outlived the markup that put it there: %r" % (got["attrsDropped"],))
    ok(got["childKind"]["rowKept"] and got["childKind"]["siblingKept"]
       and got["childKind"]["html"] == '<div id="r" data-k="r"><b>keep</b><i class="v">2</i></div>',
       "a child that changed kind is swapped, and its siblings are not",
       "a child that changed kind came out wrong: %r" % (got["childKind"],))
    ok(got["rowKind"]["swapped"]
       and got["rowKind"]["html"] == '<section id="r" data-k="r">x</section>',
       "a row whose own kind changed is swapped rather than painted over",
       "a row that changed kind came out wrong: %r" % (got["rowKind"],))
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
