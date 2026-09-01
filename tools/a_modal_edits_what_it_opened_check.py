#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: an edit form saves the record it was opened on, not whatever sits at that index now.

The port-forward and proxy forms used to be addressed by POSITION. `pfCard(p,i)` baked `i` into its
buttons, `openPfEdit(i)` read `PF[i]`, and `savePfEdit(i)` read `PF[i]` again -- minutes later, when
the operator pressed save. That was survivable only because an open form froze every list refresh:
`PF` could not move while the form was up. Now the lists stay live behind the form, and the same
index can point at a different port-forward by the time it is read again -- the operator would edit
one rule and overwrite another, with nothing on screen saying so.

Reading the array on the CLICK is fine and stays: the card was rendered from that same array a moment
earlier, so its index is current. What may not happen is reading it again after the form has been
sitting open. The identity is captured when the form opens and rides on the form itself.

This drives the REAL forms out of the DECODED INDEX_HTML under node: it opens the form on the second
row, then swaps the list the way a poll would, then presses save and reads the request that goes out.

  * portfw: the request names the port-forward the form was opened on
  * proxy:  the request carries that proxy's id, and goes to proxy-edit
  * and the control, so the guard cannot pass by making save inert: with the list untouched the same
    press still saves the same record, and the ADD form still posts proxy-add with no id at all

Exit 1 on any failure, on no `node`, or on a harness that could not reach its subject.

    python3 tools/a_modal_edits_what_it_opened_check.py
"""
import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from list_diff_keeps_untouched_rows_check import PRELUDE  # noqa: E402

PANEL = HERE.parent / "tnl-central.py"
SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S)
NL = chr(10)

# The shared mini-DOM stops where the diff guard stopped. A form needs the rest of what openModal and
# a save handler really touch: a body that holds the overlay, ids that resolve inside it, `closest`
# for the button that carries the record, and an input whose .value reflects the markup.
EXTRA = r"""
Object.defineProperty(El.prototype, 'className', {
  get(){ return this.getAttribute('class') || ''; },
  set(v){ this.setAttribute('class', String(v)); } });
Object.defineProperty(El.prototype, 'value', {
  get(){ return this._val !== undefined ? this._val : (this.getAttribute('value') || ''); },
  set(v){ this._val = String(v); } });
El.prototype.addEventListener = function(){};
El.prototype.removeEventListener = function(){};
Object.defineProperty(El.prototype, 'style', {
  get(){ if(!this._style) this._style = {}; return this._style; } });
Object.defineProperty(El.prototype, 'dataset', {
  get(){ const d = {};
    for (const [k, v] of this.attrs)
      if (k.indexOf('data-') === 0) d[k.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
    return d; } });

// Only the selector shapes the panel really uses: tag / #id / .class, in any combination, and one or
// more descendant steps. Anything else throws rather than quietly answering wrongly.
const SIMPLE = /^([a-zA-Z]+)?(#[\w-]+)?((?:\.[\w-]+)*)$/;
function matchOne(el, sel){
  const m = SIMPLE.exec(sel);
  if (!m || sel === '') throw new Error('the harness does not implement the selector ' + JSON.stringify(sel));
  if (m[1] && el.tag.toLowerCase() !== m[1].toLowerCase()) return false;
  if (m[2] && el.getAttribute('id') !== m[2].slice(1)) return false;
  const cls = el.className.split(/\s+/);
  for (const c of (m[3].match(/\.[\w-]+/g) || [])) if (cls.indexOf(c.slice(1)) < 0) return false;
  return true;
}
function matches(el, sel){
  const parts = sel.trim().split(/\s+/);
  if (!matchOne(el, parts[parts.length - 1])) return false;
  let n = el.parent;
  for (let i = parts.length - 2; i >= 0; i--) {
    while (n && !matchOne(n, parts[i])) n = n.parent;
    if (!n) return false;
    n = n.parent;
  }
  return true;
}
function descend(root, sel, all){
  const parts = sel.split(',').map(s => s.trim()).filter(Boolean), hits = [];
  const walk = n => {
    if (n.nodeType !== 1) return;
    if (parts.some(p => matches(n, p))) { hits.push(n); if (!all) return; }
    for (const k of n.nodes) { walk(k); if (!all && hits.length) return; }
  };
  for (const k of root.nodes) { walk(k); if (!all && hits.length) break; }
  return all ? hits : (hits[0] || null);
}
El.prototype.querySelector    = function(sel){ return descend(this, sel, false); };
El.prototype.querySelectorAll = function(sel){ return descend(this, sel, true); };
El.prototype.closest = function(sel){
  let n = this;
  while (n) { if (n.nodeType === 1 && matches(n, sel)) return n; n = n.parent; }
  return null;
};

const __body = new El('body');
document.body = __body;
document.addEventListener = function(){};
document.removeEventListener = function(){};
document.getElementById = function(id){
  const walk = n => {
    if (n.nodeType === 1 && n.getAttribute('id') === id) return n;
    for (const k of n.nodes || []) { const hit = walk(k); if (hit) return hit; }
    return null;
  };
  return walk(__body);
};
document.querySelector    = sel => descend(__body, sel, false);
document.querySelectorAll = sel => descend(__body, sel, true);
"""

HARNESS = r"""
const out = {cases: [], errors: []};
let sent = null;
toast = function(){}; refresh = function(){ return Promise.resolve(); };
refreshPortfw = function(){}; refreshProxies = function(){};
formErr = function(m, txt){ out.errors.push('the form refused to save: ' + txt); return true; };
j = () => Promise.resolve({nodes: []});
post = (ep, body) => { sent = {ep: ep, body: body}; return Promise.resolve({ok: true, d: {ok: true}}); };

// The button the operator actually presses, found the way the operator finds it: the primary one in
// the form that is on screen.
function saveBtn(){
  const ovs = document.querySelectorAll('.modalov');
  const ov = ovs[ovs.length - 1];
  if (!ov) throw new Error('no form is open');
  const b = ov.querySelector('.primary');
  if (!b) throw new Error('the open form has no primary button');
  return b;
}
function closeAll(){ document.querySelectorAll('.modalov').forEach(o => closeModal(o)); }

const A = {node_id:'n1', node:'IR01', name:'pf-a', iface:'tun0', listen_port:'8001', dst_port:'9001',
           dst_ips:['10.0.0.1'], switch_interval:0, health:{}};
const B = {node_id:'n2', node:'DE01', name:'pf-b', iface:'tun1', listen_port:'8002', dst_port:'9002',
           dst_ips:['10.0.0.2'], switch_interval:0, health:{}};
const PA = {id:'pa', name:'px-a', scheme:'socks5', host:'1.1.1.1', port:1080, user:'', has_pass:false};
const PB = {id:'pb', name:'px-b', scheme:'http',   host:'2.2.2.2', port:8080, user:'', has_pass:false};

async function pfCase(name, swap){
  const c = {name: name};
  out.cases.push(c);
  try {
    NODES = []; PF = [A, B];
    await openPfEdit(1);                       // the operator opens the SECOND row
    c.opened = v('pe_lp');                     // ...and the form really is that row's
    if (swap) PF = [B, A];                     // the poll that now keeps running reorders the list
    sent = null;
    await savePfEdit(saveBtn());
    c.sent = sent;
  } catch (e) { c.threw = String((e && e.message) || e); }
  closeAll();
}

async function pxCase(name, open, swap){
  const c = {name: name};
  out.cases.push(c);
  try {
    PX = [PA, PB];
    openPxModal(open);
    c.opened = v('px_name');
    if (swap) PX = [PB, PA];
    sent = null;
    await savePx(saveBtn());
    c.sent = sent;
  } catch (e) { c.threw = String((e && e.message) || e); }
  closeAll();
}

Promise.resolve().then(async function(){
  await pfCase('portfw form, list reordered while it was open', true);
  await pfCase('portfw form, list untouched (control)', false);
  await pxCase('proxy form, list reordered while it was open', 1, true);
  await pxCase('proxy form, list untouched (control)', 1, false);
  await pxCase('proxy ADD form (control)', null, true);
}).then(function(){
  console.log('@@' + JSON.stringify(out));
}, function(e){
  out.errors.push('harness threw: ' + ((e && e.stack) || e));
  console.log('@@' + JSON.stringify(out));
});
"""

# What each case must have sent. The port-forward is named by node+name, the proxy by its id.
WANT = {
    "portfw form, list reordered while it was open":
        ("8002", "portfw-edit", {"node": "n2", "name": "pf-b"}),
    "portfw form, list untouched (control)":
        ("8002", "portfw-edit", {"node": "n2", "name": "pf-b"}),
    "proxy form, list reordered while it was open":
        ("px-b", "proxy-edit", {"id": "pb"}),
    "proxy form, list untouched (control)":
        ("px-b", "proxy-edit", {"id": "pb"}),
    "proxy ADD form (control)":
        ("", "proxy-add", {"id": None}),
}


def decoded_index_html(panel):
    spec = importlib.util.spec_from_file_location("tnl_central_modalid", panel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.INDEX_HTML


def panel_js(html):
    blocks = SCRIPT_RE.findall(html)
    if not blocks:
        raise SystemExit("FAIL  INDEX_HTML decoded to something with no <script> in it")
    return max(blocks, key=len)


def run_node(js):
    node = shutil.which("node")
    if not node:
        raise SystemExit("FAIL  no `node` on PATH — a check that cannot run must not report success")
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "drive.mjs"
        f.write_text(PRELUDE + EXTRA + NL + js + NL + HARNESS, encoding="utf-8")
        r = subprocess.run([node, str(f)], capture_output=True, text=True, timeout=180,
                           encoding="utf-8", errors="replace")
    line = next((l for l in (r.stdout or "").splitlines() if l.startswith("@@")), None)
    if not line:
        raise SystemExit("FAIL  the harness produced no result" + NL + (r.stdout or "") + (r.stderr or ""))
    return json.loads(line[2:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=str(PANEL))
    a = ap.parse_args()

    res = run_node(panel_js(decoded_index_html(Path(a.panel))))
    ok, bad = [], list(res.get("errors", []))
    seen = {c["name"] for c in res.get("cases", [])}
    missing = set(WANT) - seen
    if missing:
        bad.append("the harness never drove %s — it has gone blind" % ", ".join(sorted(missing)))

    for c in res.get("cases", []):
        n = c["name"]
        want_open, want_ep, want_body = WANT[n]
        if c.get("threw"):
            bad.append("%s: %s" % (n, c["threw"]))
            continue
        if c.get("opened") != want_open:
            bad.append("%s: the form did not open on the row it was asked for (a field reads %r, "
                       "want %r) — the case proved nothing" % (n, c.get("opened"), want_open))
            continue
        s = c.get("sent")
        if not s:
            bad.append("%s: pressing save sent nothing at all" % n)
            continue
        if s["ep"] != want_ep:
            bad.append("%s: save went to %r, want %r" % (n, s["ep"], want_ep))
            continue
        wrong = {k: (s["body"].get(k), w) for k, w in want_body.items() if s["body"].get(k) != w}
        if wrong:
            bad.append("%s: the request named %s — the form saved over a DIFFERENT record than the "
                       "one it was opened on"
                       % (n, ", ".join("%s=%r (want %r)" % (k, g, w) for k, (g, w) in sorted(wrong.items()))))
            continue
        ok.append("%-48s -> %s %s" % (n, s["ep"], json.dumps(
            {k: s["body"].get(k) for k in want_body}, ensure_ascii=False)))

    for line in ok:
        print("  ok   " + line)
    if bad:
        print(NL + "FAILURES (%d):" % len(bad))
        for f in bad:
            print("  - %s" % f)
        return 1
    print(NL + "an edit form saves the record it was opened on, whatever the list does behind it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
