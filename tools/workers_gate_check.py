#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the `workers` knob — the number of TUN queues one tunnel's receive path gets.

Four things have to hold, and each of them has been the shape of a real defect in a neighbouring knob:

  1. The ceiling is ONE number across three repos. The core clamps silently, so a panel that offered a
     fifth queue would promise something the wire never delivers and nothing would ever say so.
  2. The carriers the core spends the queues on are read out of `queueingCarrier` itself, never listed
     here, and FEC is out on all of them (its decoder rebuilds a block out of consecutive frames). Any
     other carrier must not carry the key, or the panel reads as set while the core takes one queue.
  3. Every panel path agrees. The count is per END, like a_ip_pool/b_ip_pool beside it: create,
     edit, a PARTIAL edit and rebuild must all produce it, and it must survive into the node's
     persisted config and out into the core's config file. Both node stages are driven here, not read.
  4. THE TWO ENDS ARE INDEPENDENT. The queues are a send-side lever and the two ends do not send into
     the same hardware, so one number for both can only ever be right for one of them. Every path is
     driven with the ends set DIFFERENTLY, because a chain that carries one value correctly says
     nothing about whether it carries two.
  5. Both FORMS are wired, on both sides. The create form and the edit form each have their own setter
     and their own state field, which is where every "create wired, edit not" defect here has come
     from — and now each of those is doubled.

    python3 tools/workers_gate_check.py
"""
import argparse
import ast
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

fails = []
_ran = set()


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def section(fn):
    """Mark a check_* function as a section and record that it actually RAN.

    A section that stops being called from main() proves nothing while still reading like coverage —
    which is how this file already lost check_storage_invariant once, silently, between two edits. The
    tail of main() compares what ran against every section defined here, so a new one that is never
    wired in fails on its first run instead of passing quietly."""
    def wrap(*a, **k):
        _ran.add(fn.__name__)
        return fn(*a, **k)
    wrap.__name__ = fn.__name__
    wrap.__doc__ = fn.__doc__
    return wrap


def load(path, name):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, str(path))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def py_const(src, name):
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    raise KeyError(name)


# ------------------------------------------------------------------ 1) one ceiling, three repos
@section
def check_ceiling(core_dir, panel_src, node_src):
    cfg = (core_dir / "config.go").read_text(encoding="utf-8")
    m = re.search(r"^const maxWorkers = (\d+)$", cfg, re.M)
    if not m:
        check(False, "core config.go declares `const maxWorkers = N`")
        return
    core_max = int(m.group(1))
    check(py_const(panel_src, "CORE_MAX_WORKERS") == core_max,
          "panel CORE_MAX_WORKERS == core maxWorkers (%d)" % core_max)
    check(py_const(node_src, "MAX_WORKERS") == core_max,
          "node MAX_WORKERS == core maxWorkers (%d)" % core_max)
    # ...and the core really does clamp to it, so the panel's refusal is the only place an out-of-range
    # value is visible rather than silently halved.
    check(bool(re.search(r"if c\.Workers > maxWorkers \{\s*\n\s*c\.Workers = maxWorkers", cfg)),
          "core clamps Workers to maxWorkers in applyDefaults")
    return core_max


# ------------------------------------------------------------------ 2) the pair the core spends them on
@section
def check_core_gate(core_dir):
    """Which carriers the core spends queues on, read out of its own source.

    Returned rather than hardcoded, so the day the core admits another carrier every panel and node
    expectation below moves with it instead of quietly asserting yesterday's list."""
    cfg = (core_dir / "config.go").read_text(encoding="utf-8")
    m = re.search(r"func queueingCarrier\(t string\) bool \{ return ([^\n}]+)\}", cfg)
    check(bool(m), "core config.go names the queueing carriers in queueingCarrier")
    carriers = sorted(set(re.findall(r't == "([a-z]+)"', m.group(1)))) if m else []
    check(bool(carriers), "queueingCarrier names at least one carrier (got %r)" % (carriers,))
    main = (core_dir / "main.go").read_text(encoding="utf-8")
    check(bool(re.search(r"nq := 1\s*\n\s*if !cfg\.Fec && queueingCarrier\(cfg\.Transport\) \{"
                         r"\s*\n\s*nq = cfg\.Workers", main)),
          "core main.go gates the queue count on queueingCarrier and !Fec")
    return carriers or None


# ------------------------------------------------------------------ 3) the panel/node/core value chain
A_IP, B_IP = "203.0.113.5", "198.51.100.7"
A_IPS, B_IPS = [A_IP], [B_IP]

RAW = {"cipher": "auto", "transport": "raw", "raw_profile": "tcp", "raw_port": 443}


def side_bodies(P, ce):
    """What _core_workers_bodies puts on each end's node body. This, not _node_extra, is where the
    count reaches a node now: _node_extra cannot do it because it never learns which end it is building
    for."""
    a, b = {}, {}
    P._core_workers_bodies(ce, a, b)
    return a.get("workers"), b.get("workers")


def stored_for(P, req):
    ce, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
    s = dict(ce)
    s["type"] = "core"
    return s


@section
def check_panel_matrix(P, core_max):
    # (label, request, stored-link, expected `workers` in the panel's node body or an exception)
    raw4 = stored_for(P, dict(RAW, a_workers=4, b_workers=4))
    cases = [
        ("raw, both ends on 1      -> not stored (the single-queue default)",
         dict(RAW, a_workers=1, b_workers=1), {}, (None, None)),
        ("raw, both ends on 4      -> stored",
         dict(RAW, a_workers=4, b_workers=4), {}, (4, 4)),
        ("raw, A on 4 and B on 1   -> ONLY A gets queues",
         dict(RAW, a_workers=4, b_workers=1), {}, (4, None)),
        ("raw, A on 1 and B on 3   -> ONLY B gets queues",
         dict(RAW, a_workers=1, b_workers=3), {}, (None, 3)),
        ("raw+FEC, asked for       -> refused (the core would take one queue anyway)",
         dict(RAW, a_workers=4, fec=True, fec_data=10, fec_parity=3), {}, ValueError),
        ("ws, asked for            -> refused",
         {"cipher": "auto", "transport": "ws", "ws_host": "e.example.com", "ws_path": "/",
          "a_workers": 4}, {}, ValueError),
        ("above the ceiling        -> refused",
         dict(RAW, a_workers=core_max + 1), {}, ValueError),
        # The INHERIT half. Switching carrier IS the request to leave the old carrier's knobs behind, so
        # a stored value must be DROPPED rather than refused — refusing it would make the switch
        # impossible on every tunnel that had ever been raw.
        ("stored 4, edit switches to ws -> dropped, not refused",
         {"transport": "ws", "ws_host": "e.example.com", "ws_path": "/"}, raw4, (None, None)),
        ("stored 4, edit turns FEC on   -> dropped, not refused",
         {"transport": "raw", "fec": True, "fec_data": 10, "fec_parity": 3}, raw4, (None, None)),
        ("stored 4, partial edit        -> kept on BOTH ends",
         {"transport": "raw"}, raw4, (4, 4)),
        ("stored 4/4, edit lowers B only -> A keeps its own",
         {"transport": "raw", "b_workers": 1}, raw4, (4, None)),
    ]
    for label, req, cur, want in cases:
        try:
            ce, _ = P._core_extra(dict(req), dict(cur), A_IP, B_IP, A_IPS, B_IPS)
            got = side_bodies(P, ce)
        except ValueError as e:
            got = ValueError
            label += "  [%s]" % str(e)[:48]
        except Exception as e:  # anything else is a bug in the guard's own inputs
            got = type(e)
            label += "  [%s: %s]" % (type(e).__name__, str(e)[:40])
        check(got == want, "%-62s -> %s" % (label.split("  [")[0], label.split("  [")[1][:-1]
                                            if "  [" in label else repr(got)))


def _wk_keys(d):
    """The per-end queue keys present in a stored record."""
    return {k: d[k] for k in ("a_workers", "b_workers") if k in d}


@section
def check_storage_invariant(P, core_max, carriers):
    """`workers` may only ever be STORED on a carrier the core spends it on, with FEC off.

    This is what lets _link_workers simply read the key instead of re-deriving the core's gate: if the
    invariant holds, a stored value is by construction one the core will spend. Proven by driving every
    carrier a form can create and then EDITING each result into every carrier and both FEC states —
    the transitions are where a knob leaks, because that is where a value arrives by inheritance rather
    than by being asked for."""
    base = {"udp": {}, "tcp": {}, "raw": {"raw_profile": "tcp"},
            "ws": {"ws_host": "e.example.com", "ws_path": "/"},
            "dns": {"dns_zone": "t.example.com", "dns_resolvers": ["10.0.0.1"]}}

    def build(req, cur):
        try:
            ce, _ = P._core_extra(dict(req), dict(cur), A_IP, B_IP, A_IPS, B_IPS)
            return ce
        except ValueError:
            return None

    stored = {}
    for t, extra in base.items():
        for fec in (False, True):
            for wk in (1, core_max):
                req = {"cipher": "auto", "transport": t, **extra}
                if fec and t in P.DATAGRAM_TRANSPORTS:
                    req.update(fec=True, fec_data=10, fec_parity=3)
                if wk > 1:
                    req["a_workers"] = wk
                    req["b_workers"] = wk
                r = build(req, {})
                if r is not None:
                    stored[(t, fec, wk)] = dict(r, type="core")
    leaks, moves = [], 0
    for k, cur in stored.items():
        if _wk_keys(cur) and (cur.get("transport") not in carriers or cur.get("fec")):
            leaks.append(("create", k, _wk_keys(cur)))
        for t2, extra2 in base.items():
            for fec2 in (False, True):
                req = {"transport": t2, **extra2}
                if t2 in P.DATAGRAM_TRANSPORTS:
                    req["fec"] = fec2
                    if fec2:
                        req.update(fec_data=10, fec_parity=3)
                r = build(req, cur)
                if r is None:
                    continue
                moves += 1
                if _wk_keys(r) and (r.get("transport") not in carriers or r.get("fec")):
                    leaks.append(("edit", k, t2, fec2, _wk_keys(r)))
    check(not leaks, "the queue count is stored ONLY on %s without FEC — %d create shapes, %d edit "
                     "transitions, leaks: %r" % ("/".join(carriers), len(stored), moves, leaks[:4]))
    kept = sorted(k for k, v in stored.items() if _wk_keys(v))
    check(kept == sorted((c, False, core_max) for c in carriers),
          "...and the create shapes that keep it are exactly the queueing carriers: %r" % (kept,))


@section
def check_chain(P, N, core_max):
    """create / edit / partial edit / rebuild, each carried all the way into the core's config file."""
    # The two ends are given DIFFERENT counts on purpose: a chain that carries one number correctly
    # says nothing about whether it carries two.
    req = dict(RAW, a_workers=core_max, b_workers=2)
    # ONE create, and the stored record derived from it. Calling _core_extra twice mints two different
    # psks, and every later comparison then reports a divergence the panel does not have.
    ce_c, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
    stored = dict(ce_c, type="core")
    ce_e, _ = P._core_extra(dict(req), dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    ce_p, _ = P._core_extra({"transport": "raw"}, dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    def pair(ce, base):
        """One end's full node body, the way every create/edit/rebuild path builds it: the funnelled
        extras plus the per-side count."""
        a, b = dict(base), dict(base)
        P._core_workers_bodies(ce, a, b)
        return a, b

    bodies = {
        "create": pair(ce_c, P._node_extra(ce_c)),
        "edit": pair(ce_e, P._node_extra(ce_e)),
        "edit(partial)": pair(ce_p, P._node_extra(ce_p)),
        "rebuild": pair(stored, P._node_extra(P._tunnel_extra(dict(stored), refetch_ech=False))),
    }

    # The three builders must produce the SAME node body, whole -- not merely agree on the key under
    # study. A key that only one path spreads is the shape this guard exists for, and checking one key
    # at a time is how such a key stays invisible: the per-end pair itself leaked into create's and
    # edit's bodies while rebuild's stayed clean, and only a whole-body diff showed it.
    whole = {}
    for nm, ce in (("create", ce_c), ("edit", ce_e), ("rebuild", P._tunnel_extra(dict(stored), refetch_ech=False))):
        a_b, b_b = dict(P._node_extra(ce)), dict(P._node_extra(ce))
        P._core_workers_bodies(stored if nm == "rebuild" else ce, a_b, b_b)
        whole[nm] = (a_b, b_b)
    same = whole["create"] == whole["edit"] == whole["rebuild"]
    diff = {} if same else {k: v for k, v in whole["create"][0].items()
                            if whole["rebuild"][0].get(k) != v}
    check(same, "create, edit and rebuild build the SAME node body, whole%s"
          % ("" if same else " — create carries %r that rebuild does not" % diff))

    class Captured(Exception):
        def __init__(self, obj):
            self.obj = obj

    N.local_ips_flat = lambda: [A_IP]
    N.iface_for_ip = lambda ip: "eth0"
    N.read_config = lambda name: None
    N.base_mtu = lambda iface: 1500
    N.write_config = lambda name, obj: (_ for _ in ()).throw(Captured(dict(obj)))

    for path, (a_body, b_body) in bodies.items():
        seen = {}
        for side, body, want in (("A", a_body, core_max), ("B", b_body, 2)):
            d = dict(body, type="core", self_ip=A_IP, peer_ip=B_IP, subnet="10.9.0.0/24", id=9,
                     name="core9", host=1, role="server", psk="ab" * 32)
            try:
                N.op_tunnel(d)
                check(False, "%s/%s: the node reached no write_config" % (path, side))
                continue
            except Captured as c:
                obj = c.obj
            cfg = N._core_config(dict(obj, iface="eth0"))
            seen[side] = (body.get("workers"), obj.get("workers"), cfg.get("workers"), want)
        ok = all(b == o == c == w for b, o, c, w in seen.values()) and len(seen) == 2
        check(ok, "%-14s A: body/node/core=%r want %r · B: %r want %r"
              % (path, seen.get("A", ("?",) * 4)[:3], core_max, seen.get("B", ("?",) * 4)[:3], 2))

    # ...and the node's own two gates, driven rather than read: an out-of-range value is refused, and
    # a persisted value never reaches the core beside FEC.
    d = dict(bodies["create"][0], type="core", self_ip=A_IP, peer_ip=B_IP, subnet="10.9.0.0/24", id=9,
             name="core9", host=1, role="server", psk="ab" * 32)
    d["workers"] = core_max + 1
    try:
        N.op_tunnel(d)
        check(False, "node refuses workers above the ceiling")
    except Captured:
        check(False, "node refuses workers above the ceiling")
    except ValueError:
        check(True, "node refuses workers above the ceiling")
    fec = N._core_config({"name": "core9", "tunnel_ip": "10.9.0.1", "role": "server", "psk": "ab" * 32,
                          "cipher": "auto", "transport": "raw", "raw_profile": "tcp", "iface": "eth0",
                          "workers": core_max, "fec": True})
    check("workers" not in fec, "node hands the core no queues beside FEC (workers=%r)"
          % fec.get("workers", "<absent>"))


# ------------------------------------------------------------------ 4) both forms, driven in a browser
PRELUDE = r"""
globalThis.__nodes = {};
const proto = {classList:{_s:new Set(),add(c){this._s.add(c)},remove(c){this._s.delete(c)},
    toggle(c,v){v===undefined?(this._s.has(c)?this._s.delete(c):this._s.add(c)):(v?this._s.add(c):this._s.delete(c))},
    contains(c){return this._s.has(c)}},
  appendChild(){}, addEventListener(){}, setAttribute(){}, removeAttribute(){}, remove(){},
  querySelector(){return null}, querySelectorAll(){return []}, insertAdjacentHTML(){}, closest(){return null},
  getBoundingClientRect(){return {width:0,height:0,top:0,left:0}}, focus(){}, click(){},
  get innerHTML(){return ''}, set innerHTML(v){},
  dataset:{}, children:[], parentNode:null, value:''};
// textContent is KEPT per element, not swallowed: a stub that returns '' whatever was written makes
// every assertion about rendered text vacuously true, which is worse than having no assertion.
function mk(id){ const n = Object.create(proto); n.style = {display:''}; n.id = id; n._text = '';
  Object.defineProperty(n, 'textContent', {get(){return this._text}, set(v){this._text = String(v)}});
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
const MAX = %d;
const out = {vis:{}, seg:{}, body:{}, drop:{}};
// The row appears on raw-without-FEC and nowhere else, in BOTH forms, driven through the REAL gate the
// form calls -- not through a re-implementation of its condition.
for (const [form, S, gate, px] of [['create', _corS, corWorkersVis, 'e_'],
                                   ['edit',   _eeS,  ceWorkersVis,  'ee_']]) {
  out.vis[form] = {};
  S.NodesArr = ['', ''];                       // no node pair -> the budget line never fetches
  for (const tr of ['udp','tcp','raw','ws','dns']) {
    for (const fec of [false, true]) {
      S.Tr = tr; S.Fec = fec; S.WorkersA = MAX; S.WorkersB = MAX;
      gate();
      out.vis[form][tr + (fec ? '+fec' : '')] =
        document.getElementById(px+'wrkrow').style.display !== 'none';
    }
  }
  // A value picked on raw must not survive a switch to a carrier that cannot spend it: the state itself
  // is reset, so the body builder cannot carry it into a save the panel would then refuse.
  S.Tr = 'raw'; S.Fec = false; S.WorkersA = MAX; S.WorkersB = MAX; gate();
  S.Tr = 'ws'; gate();
  out.drop[form] = [S.WorkersA, S.WorkersB];
}
// The segment: each button paints, and the STATE moves with it. Per-form setter, per-form state field.
for (const [form, S, setter, px] of [['create', _corS, corSetWorkers, 'e_'],
                                     ['edit',   _eeS,  ceSetWorkers,  'ee_']]) {
  out.seg[form] = {};
  const lit = sd => { const on = [];
    for (let k = 1; k <= MAX; k++)
      if (document.getElementById(px+'wk_'+sd+'_'+k).classList.contains('on')) on.push(k);
    return on };
  for (const sd of ['a','b']) {
    for (let n = 1; n <= MAX; n++) {
      setter(sd, n);
      out.seg[form][sd+n] = {state: (sd=='a' ? S.WorkersA : S.WorkersB), on: lit(sd)};
    }
  }
  // The property the whole feature exists for: moving one end must leave the other alone. A single
  // shared state field would satisfy every check above and fail only this one.
  setter('a', MAX); setter('b', 1);
  out.seg[form].split = {a: S.WorkersA, b: S.WorkersB, aLit: lit('a'), bLit: lit('b')};
}
// ...and what the SHARED body builder actually sends, which is the only thing the node ever sees. The
// key's PRESENCE matters as much as its value: an absent key falls back to the stored one, so a form
// that only sent a raised value could never lower one again.
for (const [form, S, setter, px] of [['create', _corS, corSetWorkers, 'e_'],
                                     ['edit',   _eeS,  ceSetWorkers,  'ee_']]) {
  out.body[form] = {};
  document.getElementById(px+'cipher').value = 'auto';
  document.getElementById(px+'rawport').value = '443';
  for (const [label, tr, fec, na, nb] of [['raw/1','raw',false,1,1], ['raw/max','raw',false,MAX,MAX],
                                          ['raw/split','raw',false,MAX,1],
                                          ['raw+fec','raw',true,MAX,MAX], ['ws','ws',false,MAX,MAX],
                                          ['udp/max','udp',false,MAX,MAX], ['udp+fec','udp',true,MAX,MAX]]) {
    S.Tr = tr; S.Fec = fec; S.RawProfile = 'tcp'; setter('a', na); setter('b', nb);
    const b = {};
    _collectCoreBody(S, px, document.getElementById(px+'msg'), b);
    out.body[form][label] = ('a_workers' in b || 'b_workers' in b)
      ? [b.a_workers, b.b_workers] : 'ABSENT';
  }
}
out.exclude = {};
FLEET = [{id:'L-9', name:'core9', a_node:'n1', b_node:'n2', a_name:'IR01', b_name:'DE01',
          a_ip:'10.0.0.1', b_ip:'10.0.0.2', a_ips:['10.0.0.1'], b_ips:['10.0.0.2'],
          server_side:'a', type:'core', transport:'raw', raw_profile:'tcp', cipher:'auto',
          subnet:'10.9.0.0/24', a_workers:3, b_workers:2}];
openCoreEdit('L-9');
out.exclude.prefilled = [_eeS.WorkersA, _eeS.WorkersB];
out.exclude.lit = ['a','b'].map(sd =>
  [1,2,3,4].filter(n => document.getElementById('ee_wk_'+sd+'_'+n).classList.contains('on')));
// The node each segment names, so the operator can tell which end they are raising. A segment pair with
// no names is a coin toss on the one setting whose whole point is that the ends differ.
out.exclude.labels = ['a','b'].map(sd => document.getElementById('ee_wklbl_'+sd).textContent);
// The label must name the NODE, and the SERVER end must sit on top. Both are read off the link the
// form was opened with: nodeName() resolves against a NODES list the tunnels page never loads, so it
// fell through to the raw node id and the operator saw «روی fe70a7ad34».
out.exclude.order = ['a','b'].map(sd => String(document.getElementById('ee_wkone_'+sd).style.order));

out.box = {};
(async () => {
  // (5) the segment can never be left with nothing lit, whatever it is handed.
  out.box.paint = {};
  for (const n of [0, 1, MAX, MAX + 5, undefined, 'x'])
    { workersPaint('e_', 'a', n); out.box.paint[String(n)] = _WKMAX.filter(k =>
        document.getElementById('e_wk_a_'+k).classList.contains('on')); }

  // (6) the state reset must not depend on the row existing -- corFecGate's rule, and the reason a
  //     stale 4 could otherwise ride a carrier switch into the body.
  const S = {Tr:'ws', Fec:false, WorkersA:MAX, WorkersB:MAX}, saved = globalThis.document.getElementById;
  globalThis.document.getElementById = () => null;
  try { workersVis('zz_', S, 'A', 'B') } catch (e) { out.box.visThrew = String(e).slice(0,60) }
  globalThis.document.getElementById = saved;
  out.box.stateWithNoRow = [S.WorkersA, S.WorkersB];

  console.log(JSON.stringify(out));
})();
"""


@section
def check_forms(P, core_max, carriers):
    page = P.INDEX_HTML
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", page, re.S)
    js = max(blocks, key=len) if blocks else ""
    for fn in ("function corWorkersVis(", "function ceWorkersVis(",
               "function corSetWorkers(", "function ceSetWorkers("):
        if fn not in js:
            check(False, "%s is in the rendered page" % fn.replace("function ", "").rstrip("("))
            return
    # The harness CALLS the gates, so it can only prove they are right — not that the forms still run
    # them. That half is static: one definition plus at least one call site each, in the gate chain the
    # transport switch and the FEC toggle go through.
    for fn, chain in (("corWorkersVis", "corSetTr"), ("ceWorkersVis", "ceApplyGates")):
        n = js.count(fn + "()")
        check(n >= 3, "%s is defined AND called %d× (<3 means %s or a toggle dropped it)"
              % (fn, n, chain))

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "workers.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % core_max), encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        check(False, "the page's own script runs:\n" + (r.stderr or "")[:900])
        return
    # An empty stdout means the harness died between its last statement and its one console.log — node
    # can still exit 0 there. Report it as a failed check rather than an IndexError traceback, which
    # reads as a broken tool instead of broken code.
    lines = (r.stdout or "").strip().splitlines()
    if not lines:
        check(False, "the page harness printed nothing — it stopped before its output line:\n"
                     + (r.stderr or "")[:600])
        return
    try:
        got = json.loads(lines[-1])
    except ValueError:
        check(False, "the page harness printed no parseable result: %r" % (lines[-1][:200],))
        return

    for form in ("create", "edit"):
        vis = got["vis"][form]
        shown = sorted(k for k, v in vis.items() if v)
        check(shown == list(carriers),
              "%-6s form: the row shows on %s (expected %s)" % (form, shown, list(carriers)))
        check(got["drop"][form] == [1, 1],
              "%-6s form: leaving raw resets BOTH ends to one queue (got %r)"
              % (form, got["drop"][form]))
        for sd in ("a", "b"):
            for n in range(1, core_max + 1):
                st = got["seg"][form][sd + str(n)]
                check(st["state"] == n and st["on"] == [n],
                      "%-6s form: end %s picking %d sets the state to %r and lights %r"
                      % (form, sd.upper(), n, st["state"], st["on"]))
        sp = got["seg"][form]["split"]
        check(sp["a"] == core_max and sp["b"] == 1 and sp["aLit"] == [core_max] and sp["bLit"] == [1],
              "%-6s form: the two ends move INDEPENDENTLY — A=%r%r B=%r%r (one shared field passes "
              "every other check and fails only this)" % (form, sp["a"], sp["aLit"], sp["b"], sp["bLit"]))
        body = got["body"][form]
        check(body["raw/1"] == [1, 1],
              "%-6s form: raw with both ends at one queue SENDS 1/1 (got %r) — an absent key would "
              "resurrect a stored 4" % (form, body["raw/1"]))
        check(body["raw/max"] == [core_max, core_max],
              "%-6s form: raw at %d sends %r" % (form, core_max, body["raw/max"]))
        check(body["raw/split"] == [core_max, 1],
              "%-6s form: A on %d and B on 1 reaches the body as %r, not one value for both"
              % (form, core_max, body["raw/split"]))
        check(body["raw+fec"] == "ABSENT",
              "%-6s form: raw+FEC sends no queue key (got %r)" % (form, body["raw+fec"]))
        check(body["ws"] == "ABSENT",
              "%-6s form: ws sends no queue key (got %r)" % (form, body["ws"]))
        check(body["udp/max"] == [core_max, core_max],
              "%-6s form: udp at %d sends %r" % (form, core_max, body["udp/max"]))
        check(body["udp+fec"] == "ABSENT",
              "%-6s form: udp+FEC sends no queue key (got %r)" % (form, body["udp+fec"]))

    ex = got["exclude"]
    check(ex.get("prefilled") == [3, 2] and ex.get("lit") == [[3], [2]],
          "open-edit loads EACH END's stored queue count into its own segment (state=%r, lit=%r)"
          % (ex.get("prefilled"), ex.get("lit")))
    lbl = ex.get("labels") or []
    check(len(lbl) == 2 and all(lbl) and lbl[0] != lbl[1],
          "each segment names the node it raises, and the two differ (%r) — without that the operator "
          "is guessing which end they are setting" % (lbl,))
    check(all(any(nm in x for nm in ("IR01", "DE01")) for x in lbl)
          and not any(nid in x for x in lbl for nid in ("n1", "n2")),
          "each label names the NODE, never its id — nodeName() resolves against a list the tunnels "
          "page never loads, so it fell through to the id and the operator read «روی fe70a7ad34» (%r)" % (lbl,))
    order = ex.get("order") or []
    check(order == ["0", "1"],
          "the SERVER end is on top and the client under it (server_side='a', order=%r) — the two "
          "segments are the one setting whose whole point is that the ends differ" % (order,))

    b = got.get("box") or {}
    lit = b.get("paint") or {}
    bad = {k: v for k, v in lit.items() if len(v) != 1}
    check(not bad, "the segment always has exactly one button lit, whatever it is handed (%r)" % bad)
    check(b.get("stateWithNoRow") == [1, 1],
          "the queue state resets on a carrier that cannot spend it even with no row in the DOM "
          "(got %r)" % b.get("stateWithNoRow"))


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    ap.add_argument("--node", default=here.parent.parent.parent / "TUNNEL-MANAGER-NODE" / "tnl-node.py")
    ap.add_argument("--core", default=here.parent.parent.parent / "TUNNEL-MANAGER-CORE")
    a = ap.parse_args()
    panel, node, core = Path(a.panel), Path(a.node), Path(a.core)

    print("== 1) one ceiling across the three repos ==")
    core_max = check_ceiling(core, panel.read_text(encoding="utf-8"), node.read_text(encoding="utf-8"))
    if core_max is None:
        print("\n%d failure(s)" % len(fails))
        return 1
    print("\n== 2) the carriers the core spends queues on ==")
    carriers = check_core_gate(core)
    if carriers is None:
        print("\n%d failure(s)" % len(fails))
        return 1
    P = load(panel, "tnl_central_workers")
    N = load(node, "tnl_node_workers")
    print("\n== 3) panel: which carrier stores it, and inherit-vs-ask ==")
    check_panel_matrix(P, core_max)
    print("\n== 4) the value chain: every panel path -> node -> core config ==")
    check_chain(P, N, core_max)
    print("\n== 5) what may be STORED, over every carrier and every edit transition ==")
    check_storage_invariant(P, core_max, carriers)
    print("\n== 6) both forms, driven through their own gates ==")
    check_forms(P, core_max, carriers)

    print("")
    missed = sorted(n for n in globals()
                    if n.startswith("check_") and callable(globals()[n]) and n not in _ran)
    if missed:
        print("these sections are defined but never run: %s" % ", ".join(missed))
        return 1
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("workers is one number in three repos, stored only where the core spends it, and both forms "
          "are wired to it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
