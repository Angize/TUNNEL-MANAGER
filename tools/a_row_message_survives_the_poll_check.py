#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: an answer painted into a list card must survive the poll that repaints the card.

Every list rebuilds itself on a timer. An action that writes its answer straight into a per-row strip
-- «در حال تست…», then the verdict -- is writing something the row renderer cannot produce again, so
the next repaint takes it away. Nothing throws: the operator taps test and the card goes blank.

The panel used to answer that by freezing the world. `listBusy()` consulted a `CHECKING` counter that
every test raised, and all five list refreshes bailed while it was up -- so for the whole length of a
connectivity check, and for the whole length of «تستِ همه» over the entire fleet, no node going down
and no tunnel dropping reached the screen. The strip was safe because nothing else moved.

The fix this guard defends is the opposite one: the strip is RENDER STATE. `rmsgSet` writes it to
`RMSG` first and the DOM second, and every row renderer emits it back through `rmsgHTML`, so a repaint
reproduces it instead of destroying it. Nothing has to be frozen, and the freeze is gone.

Which strips are at risk is derived from OUTPUT, not from what a function is called: the harness
renders each row and reads back every `.msg` element the markup really contains. A renderer named
something this guard never heard of still gets covered, and a strip that moves out of the card stops
being demanded -- neither can quietly fall out of scope.

What is enforced:

  runtime, on the REAL path -- real `setList`, real `nodeCard`/`linkCard`/`coreCard`/`pxCard`, real
  `testNode`/`checkLink`/`testPx`, out of the DECODED INDEX_HTML (the .py bytes still hold unresolved
  escapes and `__NAME_JSON__` placeholders, so they are not what the browser runs)
    1. the answer is on screen while the request is in flight, and a poll landing right then does not
       take it away -- the original bug, reproduced by resolving the fetch only after the poll ran.
    2. it is still there after a poll that brings back IDENTICAL rows, and after one that really
       changes the row, so the card is morphed rather than merely left alone.
    3. a cleared strip stays cleared, so a stale verdict cannot come back on the next tick.
    4. a failed test empties its strip instead of leaving «در حال تست…» on the card for good.

  static
    5. `listBusy()` may consult ONLY the reorder flags. A refresh may be held while the operator's
       finger owns the DOM order and the server does not know yet -- never to protect a paint.
    6. no async function captures one of those at-risk elements before its first `await` and paints
       into it afterwards. By then it can be detached and the answer lands in an orphan.
    7. every at-risk strip comes back out of `rmsgHTML`, or is re-applied after the rebuild by a
       painter that owns its state (`if(S)paint(S)` -- what the upload bars do).

Exit 1 on any failure, on no `node`, or on a harness that could not reach its subject.

    python3 tools/a_row_message_survives_the_poll_check.py
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
ASYNC_FN = re.compile(r"\basync\s+function\s+([A-Za-z_$][\w$]*)\s*\(")
PLAIN_FN = re.compile(r"(?<!async )\bfunction\s+([A-Za-z_$][\w$]*)\s*\(")
NL = chr(10)

# The reorder flags are the only legitimate reason to hold a list refresh: while a card is under the
# finger, or its new order is still in flight, the DOM is ahead of the server and a repaint would undo
# the operator. Anything else in here is a paint being protected by a freeze again.
REORDER_FLAGS = {"RORD", "RSAVE"}


def bodies_of(js, want_async=True):
    """(name, body, line) for every function declaration, brace-matched."""
    out = []
    for m in (ASYNC_FN if want_async else PLAIN_FN).finditer(js):
        i = js.index("{", m.end() - 1)
        depth, j = 0, i
        while j < len(js):
            if js[j] == "{":
                depth += 1
            elif js[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((m.group(1), js[i:j + 1], js[:m.start()].count(NL) + 1))
    return out


def all_bodies(js):
    return bodies_of(js, want_async=False) + bodies_of(js, want_async=True)


# What the shared mini-DOM does not carry, because the diff guard never needed it: an id lookup that
# really walks the tree, and the accessor an action writes a strip through.
EXTRA = r"""
Object.defineProperty(El.prototype, 'className', {
  get(){ return this.getAttribute('class') || ''; },
  set(v){ this.setAttribute('class', String(v)); } });
const __roots = [];
document.getElementById = function(id){
  const walk = n => {
    if (n.nodeType === 1 && n.getAttribute('id') === id) return n;
    for (const k of n.nodes || []) { const hit = walk(k); if (hit) return hit; }
    return null;
  };
  for (const r of __roots) { const hit = walk(r); if (hit) return hit; }
  return null;
};
"""

HARNESS = r"""
const out = {cases: [], strips: [], errors: []};

// The popup is not what is under test; the strip the action empties before raising it is. Record the
// call and let the real rmsgClear beside it do its work.
let popped = 0;
formErr = function(m, txt){ popped++; return true; };
toast = function(){};

TOPEN = {}; PUSHSTATE = null; STAGED = null; AGMETA = null;
QRY = {nodes:'', tunnels:'', core:'', proxies:'', portfw:''};
PG = {nodes:0, tunnels:0, core:0, proxies:0, portfw:0};
TOT = {nodes:1, tunnels:1, core:1, proxies:1, portfw:1};
LIM = 20; UPWIN = 1;

const N = {id:'n1', name:'IR01', host:'1.2.3.4', port:9, online:true,
           info:{version:7, arch:'amd64', tunnels:1, portfw:0, core_ver:'v1', core_sha:'aa'}};
const L = {id:'t1', name:'tun1', type:'core', a_node:'n1', b_node:'n2', a_name:'IR01', b_name:'DE01',
           a_ip:'10.0.0.1', b_ip:'10.0.0.2', a_online:true, b_online:true, enabled:true,
           transport:'udp', subnet:'10.0.0.0/30', port:1, rx_bps:1, tx_bps:1, rx_total:1, tx_total:1};
const P = {id:'p1', name:'px1', addr:'1.2.3.4:1080', online:true, nodes:[]};
const F = {node_id:'n1', node:'IR01', name:'pf1', iface:'tun0', listen_port:80, dst_port:81,
           dst_ips:['1.2.3.4'], health:{rule:true, reachable:true},
           rx_bps:0, tx_bps:0, rx_total:0, tx_total:0};

const ALIVE = {up:true, alive:true, dead:false, rtt_ms:31.2, loss_pct:0};

// ---- which strips a rebuild really destroys, read out of the markup the renderers produce ----
function collect(card, key, html){
  const walk = n => {
    if (n.nodeType !== 1) return;
    const cls = n.getAttribute('class') || '', id = n.getAttribute('id') || '';
    if (id && /(^|\s)msg(\s|$)/.test(cls)) out.strips.push({card: card, key: key, id: id});
    for (const k of n.nodes) walk(k);
  };
  for (const n of parseNodes(html)) walk(n);
}
FLEET = [L]; PX = [P];
ACTS = {}; ACTNOW = 0; ADISM = {}; _ASTEP = {};
const ACT = {key:'link:t1', state:'run', step:'build', si:0.5, can:true, target:'IR01 ↔ DE01',
             ttype:'core', started:0, seen:'link:t1:0'};
LOGEVS = [{ts:1755600000, level:'ok', kind:'link', cat:'tunnel', fa:'an event', dfa:''}];
LOGFILTER = 'all'; LOGOPEN = {}; LOGSHOW = 50;
collect('nodeCard',  N.id,               nodeCard(N));
collect('linkCard',  L.id,               linkCard(L));
collect('coreCard',  L.id,               coreCard(L));
collect('pxCard',    P.id,               pxCard(P, 0));
collect('pfCard',    F.node_id + F.name, pfCard(F, 0));
collect('agRow',     N.id,               agRow(N));
collect('apendCard', ACT.key,            apendCard(ACT));
logRows().forEach(r => collect('logRow', r.k, r.h));

// ---- the real page loop: setList over the real renderer, and the real action on top of it ----
function mount(render){
  const box = document.createElement('div');
  __roots.length = 0; __roots.push(box);
  const paint = () => setList(box, render());
  paint();
  return {box, paint};
}
const strip = id => { const e = document.getElementById(id); return e ? e.innerHTML : null; };

// A promise the harness decides when to settle, so a poll can be made to land mid-flight.
function held(value){
  let release;
  const p = new Promise(r => { release = () => r(value); });
  return {p, release};
}

// setList SKIPS a repaint whose rows came back byte-identical, so a poll that changes nothing proves
// nothing: every poll below is made to really rebuild the row first, which is what the live page does
// anyway -- the traffic figures on a card move on every tick.
async function case_(name, opts){
  const c = {name: name, id: opts.id};
  out.cases.push(c);                          // recorded before the work, so a throw still reports
  try {
    const m = mount(opts.render);
    const h = held(opts.answer);
    post = () => h.p;
    const running = opts.act();
    c.pending = strip(opts.id);               // «در حال…» is up before anything came back
    opts.mutate(1);
    m.paint();                                // ...and a poll rebuilds the card right on top of it
    c.rebuiltDuringFlight = m.box.children[0].outer.indexOf(opts.marks[0]) >= 0;
    c.pendingAfterPoll = strip(opts.id);
    h.release();
    await running;                            // the answer lands on a card that was replaced meanwhile
    c.answered = strip(opts.id);
    m.paint();                                // a poll that changes nothing must not disturb it
    c.afterSamePoll = strip(opts.id);
    opts.mutate(2);
    m.paint();                                // and neither must one that rebuilds the row again
    c.rebuiltAfter = m.box.children[0].outer.indexOf(opts.marks[1]) >= 0;
    c.afterChangedPoll = strip(opts.id);
    rmsgClear(opts.id);
    c.cleared = strip(opts.id);
    opts.mutate(3);
    m.paint();
    c.stillCleared = strip(opts.id);
  } catch (e) { c.threw = String((e && e.message) || e); }
}

Promise.resolve().then(async function(){
  await case_('testNode', {
    id: 'ntm_n1',
    render: () => [{k: N.id, h: nodeCard(N)}],
    act: () => testNode('n1'),
    answer: {ok:true, d:{ok:true, info:{hostname:'ir01', rtt_ms:12}}},
    mutate: i => { N.name = 'IR01-v' + i; },
    marks: ['IR01-v1', 'IR01-v2']});

  await case_('checkLink', {
    id: 'lchk_t1',
    render: () => { FLEET = [L]; return [{k: L.id, h: linkCard(L)}]; },
    act: () => checkLink('t1'),
    answer: {ok:true, d:{ok:true, a_online:true, b_online:true, a_health:ALIVE, b_health:ALIVE}},
    mutate: i => { L.name = 'tun1-v' + i; },
    marks: ['tun1-v1', 'tun1-v2']});

  await case_('checkLink on a core card', {
    id: 'lchk_t1',
    render: () => { FLEET = [L]; return [{k: L.id, h: coreCard(L)}]; },
    act: () => checkLink('t1'),
    answer: {ok:true, d:{ok:true, a_online:true, b_online:true, a_health:ALIVE, b_health:ALIVE}},
    mutate: i => { L.name = 'core1-v' + i; },
    marks: ['core1-v1', 'core1-v2']});

  await case_('testPx', {
    id: 'pxm_p1',
    render: () => { PX = [P]; return [{k: P.id, h: pxCard(P, 0)}]; },
    act: () => testPx(0),
    answer: {ok:true, d:{ok:true, ms:9}},
    mutate: i => { P.name = 'px1-v' + i; },
    marks: ['px1-v1', 'px1-v2']});

  // The failure branch: the strip is emptied and the popup carries the reason. A repaint must not
  // bring back the «در حال تست…» that was there a moment ago.
  const m = mount(() => [{k: N.id, h: nodeCard(N)}]);
  popped = 0;
  post = () => Promise.resolve({ok:true, d:{ok:false, info:{error:'x'}}});
  await testNode('n1');
  m.paint();
  out.failBranch = {strip: strip('ntm_n1'), popped: popped};

  // A verdict is an answer to a press, not a fact about the fleet. It has no timestamp on it, so one
  // that outlives the visit reads as current when it is an hour old. Leaving the page forgets it --
  // driven through the real render(), which is the only way to leave a page.
  const view = document.createElement('div');
  view.setAttribute('id', 'view');
  __roots.length = 0; __roots.push(view);
  j = () => Promise.resolve({nodes: [N], total: 1, uptime_window: 1});
  cur = 'nodes'; render();
  for (let i = 0; i < 8; i++) await Promise.resolve();
  const listed = !!document.getElementById('ntm_n1');
  rmsgSet('ntm_n1', 'ok', 'a verdict from the last visit');
  const set = strip('ntm_n1');
  cur = 'nodes'; render();
  for (let i = 0; i < 8; i++) await Promise.resolve();
  out.pageSwitch = {listed: listed, set: set, after: strip('ntm_n1'),
                    store: Object.keys(RMSG).length};
}).then(function(){
  console.log('@@' + JSON.stringify(out));
}, function(e){
  out.errors.push('harness threw: ' + ((e && e.stack) || e));
  console.log('@@' + JSON.stringify(out));
});
"""


def decoded_index_html(panel):
    """The page as the browser gets it."""
    spec = importlib.util.spec_from_file_location("tnl_central_rowmsg", panel)
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


def at_risk(strips):
    """{prefix: [cards…]} for every .msg strip a row renderer really put inside a card. A per-row id
    keeps only the part before the row's own key; a constant id inside a card is at risk too, and
    keeps its whole name."""
    out = {}
    for s in strips:
        sid, key = s["id"], s["key"]
        pfx = sid[:-len(key)] if key and sid.endswith(key) else sid
        out.setdefault(pfx, set()).add(s["card"])
    return {k: sorted(v) for k, v in out.items()}


def runtime_checks(res):
    """(ok, bad, proven) -- proven holds the strip ids a case drove END TO END and PASSED. A case that
    failed proves nothing, so it must not switch off the shape rule that would have caught it too."""
    ok, bad, proven = list(), list(res.get("errors", [])), set()
    if not res.get("cases"):
        bad.append("the harness drove no action at all — it has gone blind")
        return ok, bad, proven
    for c in res["cases"]:
        n = c["name"]
        before = len(bad)
        if c.get("threw"):
            bad.append("%s: the harness could not finish the case (%s)" % (n, c["threw"]))
        if not c.get("rebuiltDuringFlight") or not c.get("rebuiltAfter"):
            bad.append("%s: a poll did not actually rebuild the card, so the case proved nothing" % n)
        if not c.get("pending"):
            bad.append("%s: nothing was on the strip while the request was in flight — the operator "
                       "taps and gets no sign the panel heard it" % n)
        if c.get("pending") != c.get("pendingAfterPoll"):
            bad.append("%s: a poll landing mid-flight wiped the pending line off the card (%r -> %r)"
                       % (n, c.get("pending"), c.get("pendingAfterPoll")))
        if not c.get("answered"):
            bad.append("%s: the answer never reached the strip — it was painted into the card the "
                       "poll had already replaced" % n)
        if c.get("answered") != c.get("afterSamePoll"):
            bad.append("%s: an unchanged poll took the answer away (%r -> %r)"
                       % (n, c.get("answered"), c.get("afterSamePoll")))
        if c.get("answered") != c.get("afterChangedPoll"):
            bad.append("%s: a poll that rebuilt the card took the answer away (%r -> %r)"
                       % (n, c.get("answered"), c.get("afterChangedPoll")))
        if c.get("cleared") or c.get("stillCleared"):
            bad.append("%s: a cleared strip came back on the next poll (%r) — a stale verdict is "
                       "worse than none" % (n, c.get("stillCleared")))
        if len(bad) == before:
            proven.add(c.get("id", ""))
            ok.append("%-26s answer survives the poll that rebuilds the card mid-flight, and every "
                      "poll after it" % (n + "()"))
    fb = res.get("failBranch")
    if not fb:
        bad.append("the failure branch was never driven")
    elif fb["strip"]:
        bad.append("a failed test left %r on the card while the popup carried the reason — the row "
                   "goes on claiming it is still running" % fb["strip"])
    elif not fb["popped"]:
        bad.append("a failed test reported nothing to the operator at all")
    else:
        ok.append("%-26s clears its strip and reports the failure" % "testNode() failing")

    ps = res.get("pageSwitch")
    if not ps:
        bad.append("leaving the page was never driven")
    elif not ps["listed"]:
        bad.append("render() did not repaint the node list at all, so this case proved nothing")
    elif not ps["set"]:
        bad.append("the verdict was never on screen before leaving the page")
    elif ps["after"] or ps["store"]:
        bad.append("a verdict survived leaving and re-entering the page (%r, %d left in the store) — "
                   "it carries no time with it, so an hour-old one reads as current"
                   % (ps["after"], ps["store"]))
    else:
        ok.append("%-26s a verdict does not outlive the visit it was asked for" % "leaving the page")
    return ok, bad, proven


def static_checks(js, risk, proven):
    ok, bad = [], []
    funcs = all_bodies(js)

    lb = next((b for n, b, _ in funcs if n == "listBusy"), None)
    if lb is None:
        bad.append("listBusy() is gone — this check can no longer tell a legitimate hold from a freeze")
    else:
        extra = set(re.findall(r"[A-Za-z_$][\w$]*", lb)) - {"return"} - REORDER_FLAGS
        if extra:
            bad.append("listBusy() consults %s as well as the reorder flags — a paint is being "
                       "protected by freezing every list again. While that is up, a node going down "
                       "never reaches the screen, which is the behaviour this guard exists to keep out"
                       % ", ".join(sorted(extra)))
        else:
            ok.append("listBusy() holds a refresh only for an in-flight reorder (%s)"
                      % ", ".join(sorted(REORDER_FLAGS)))

    if not risk:
        bad.append("no .msg strip was found inside any rendered card — the shapes moved and this "
                   "check has gone blind")
        return ok, bad
    ok.append("strips a rebuild destroys, read out of the rendered cards: %s"
              % " ".join("%s(%s)" % (p, "/".join(c)) for p, c in sorted(risk.items())))

    per_row = re.compile(r"el\('(%s)'" % "|".join(re.escape(p) for p in sorted(risk)))
    caught = 0
    for name, body, line in bodies_of(js, want_async=True):
        first = body.find("await ")
        if first < 0:
            continue
        m = per_row.search(body[:first])
        if not m or ("className='msg" not in body and ".innerHTML=" not in body):
            continue
        caught += 1
        bad.append("%s() (line %d) captures %s…, an element inside a card, before its await and "
                   "paints into it afterwards — a poll landing mid-flight rebuilds the card, so the "
                   "answer goes into a detached node and the operator sees nothing. Write it through "
                   "rmsgSet(), which stores it and looks the element up after the wait."
                   % (name, line, m.group(1)))
    if not caught:
        ok.append("no action captures a card element across its await")

    from_store = set()
    for _n, body, _l in funcs:
        from_store |= set(re.findall(r"rmsgHTML\('([A-Za-z_][\w]*_?)'", body))
    painters = {}
    for name, body, _l in funcs:
        for m in per_row.finditer(body):
            if ".innerHTML=" in body or "className=" in body:
                painters.setdefault(m.group(1), set()).add(name)
    reapplied = set()
    for name, body, _l in funcs:
        if not name.startswith("refresh"):
            continue
        for pfx, who in painters.items():
            for w in sorted(who):
                if re.search(r"if\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*%s\s*\(\s*\1\s*\)" % re.escape(w), body):
                    reapplied.add(pfx)
    # Where a runtime case already drove the strip end to end, that proof stands on its own: demanding
    # a particular SHAPE on top of it would only be a second, weaker opinion about the same strip. The
    # shape rule is for the strips no case drives.
    for pfx in sorted(risk):
        if pfx in proven:
            continue
        if pfx in from_store:
            ok.append("%-9s comes back out of RMSG" % pfx)
        elif pfx in reapplied:
            ok.append("%-9s is re-applied after the rebuild by %s"
                      % (pfx, "/".join(sorted(painters.get(pfx, ())))))
        else:
            bad.append("the %s… strip is emitted empty by a row renderer and nothing puts it back — "
                       "whatever an action writes there dies on the next poll" % pfx)
    return ok, bad


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=str(PANEL))
    a = ap.parse_args()

    js = panel_js(decoded_index_html(Path(a.panel)))
    res = run_node(js)
    ok, bad, driven = runtime_checks(res)
    risk = at_risk(res.get("strips", []))
    proven = {p for p in risk for i in driven if i.startswith(p)}
    sok, sbad = static_checks(js, risk, proven)
    ok += sok
    bad += sbad

    for line in ok:
        print("  ok   " + line)
    if bad:
        print(NL + "FAILURES (%d):" % len(bad))
        for f in bad:
            print("  - %s" % f)
        return 1
    print(NL + "the strip is render state: the lists stay live while an action runs, and the answer "
          "survives every repaint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
