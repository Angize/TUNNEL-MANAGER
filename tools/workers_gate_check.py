#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the `workers` knob — the number of TUN queues one tunnel's receive path gets.

Four things have to hold, and each of them has been the shape of a real defect in a neighbouring knob:

  1. The ceiling is ONE number across three repos. The core clamps silently, so a panel that offered a
     fifth queue would promise something the wire never delivers and nothing would ever say so.
  2. The core spends the queues on exactly ONE pair — a raw carrier with FEC off (main.go gates its
     queue count on it; FEC's decoder rebuilds a block out of consecutive frames). Any other carrier
     must not carry the key, or the panel reads as set while the core takes its single queue.
  3. Every panel path agrees. `workers` is per-tunnel state like raw_port beside it: create, edit, a
     PARTIAL edit and rebuild must all produce it, and it must survive into the node's persisted config
     and out into the core's config file. Both node stages are driven here, not read.
  4. Both FORMS are wired. The create form and the edit form each have their own setter and their own
     state field, which is where every "create wired, edit not" defect in this panel has come from.

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


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


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
def check_core_gate(core_dir):
    main = (core_dir / "main.go").read_text(encoding="utf-8")
    m = re.search(r'nq := 1\s*\n\s*if cfg\.Transport == "raw" && !cfg\.Fec \{\s*\n\s*nq = cfg\.Workers',
                  main)
    check(bool(m), 'core main.go spends the queues on raw-without-FEC only (`transport=="raw" && !Fec`)')


# ------------------------------------------------------------------ 3) the panel/node/core value chain
A_IP, B_IP = "203.0.113.5", "198.51.100.7"
A_IPS, B_IPS = [A_IP], [B_IP]

RAW = {"cipher": "auto", "transport": "raw", "raw_profile": "tcp", "raw_port": 443}


def stored_for(P, req):
    ce, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
    s = dict(ce)
    s["type"] = "core"
    return s


def check_panel_matrix(P, core_max):
    # (label, request, stored-link, expected `workers` in the panel's node body or an exception)
    raw4 = stored_for(P, dict(RAW, workers=4))
    cases = [
        ("raw, segment on 1        -> not stored (the single-queue default)",
         dict(RAW, workers=1), {}, None),
        ("raw, segment on 4        -> stored",
         dict(RAW, workers=4), {}, 4),
        ("raw+FEC, asked for       -> refused (the core would take one queue anyway)",
         dict(RAW, workers=4, fec=True, fec_data=10, fec_parity=3), {}, ValueError),
        ("ws, asked for            -> refused",
         {"cipher": "auto", "transport": "ws", "ws_host": "e.example.com", "ws_path": "/",
          "workers": 4}, {}, ValueError),
        ("above the ceiling        -> refused",
         dict(RAW, workers=core_max + 1), {}, ValueError),
        # The INHERIT half. Switching carrier IS the request to leave the old carrier's knobs behind, so
        # a stored value must be DROPPED rather than refused — refusing it would make the switch
        # impossible on every tunnel that had ever been raw.
        ("stored 4, edit switches to ws -> dropped, not refused",
         {"transport": "ws", "ws_host": "e.example.com", "ws_path": "/"}, raw4, None),
        ("stored 4, edit turns FEC on   -> dropped, not refused",
         {"transport": "raw", "fec": True, "fec_data": 10, "fec_parity": 3}, raw4, None),
        ("stored 4, partial edit        -> kept",
         {"transport": "raw"}, raw4, 4),
    ]
    for label, req, cur, want in cases:
        try:
            ce, _ = P._core_extra(dict(req), dict(cur), A_IP, B_IP, A_IPS, B_IPS)
            got = P._node_extra(ce).get("workers")
        except ValueError as e:
            got = ValueError
            label += "  [%s]" % str(e)[:48]
        except Exception as e:  # anything else is a bug in the guard's own inputs
            got = type(e)
            label += "  [%s: %s]" % (type(e).__name__, str(e)[:40])
        check(got == want, "%-62s -> %s" % (label.split("  [")[0], label.split("  [")[1][:-1]
                                            if "  [" in label else repr(got)))


def check_budget(P):
    """The endpoint the form warns from: which links count against a node, and which do not."""
    LINKS = [
        # id      type      nodes       transport  fec    workers  enabled
        ("this",  "core",   ("n1", "n2"), "raw",   False, 4,       True),
        ("plain", "core",   ("n1", "n3"), "ws",    False, None,    True),   # 1 queue, like every core tunnel
        ("fec",   "core",   ("n1", "n3"), "raw",   True,  4,       True),   # FEC gets one queue, not four
        ("big",   "core",   ("n1", "n3"), "raw",   False, 3,       True),
        ("dflt",  "core",   ("n1", "n3"), "raw",   False, None,    True),   # raw at the default: still 1
        ("off",   "core",   ("n1", "n3"), "raw",   False, 4,       False),  # stopped: it holds nothing
        ("kern",  "vxlan",  ("n1", "n3"), None,    False, None,    True),   # no core process at all
        ("other", "core",   ("n3", "n4"), "raw",   False, 4,       True),   # not this node
    ]
    rows = []
    for lid, ttype, (a, b), tr, fec, wk, en in LINKS:
        L = {"id": lid, "type": ttype, "a_node": a, "b_node": b, "enabled": en}
        if tr:
            L["transport"] = tr
        if fec:
            L["fec"] = True
        if wk:
            L["workers"] = wk
        rows.append(L)
    P.load_links = lambda: rows
    P.get_node = lambda nid: {"id": nid, "name": nid.upper()} if nid in ("n1", "n2") else None
    P._cached_ping = lambda nid: {"stats": {"cpus": 2}} if nid == "n1" else {}
    got = P.api_workers_budget({"a": "n1", "b": "n2", "exclude": "this"})["nodes"]
    # n1 keeps: plain(1) + fec(1) + big(3) + dflt(1) = 6.  Dropped: this(excluded), off(disabled),
    # kern(not core), other(different nodes).
    check(got.get("a", {}).get("used") == 6,
          "budget counts one queue per core tunnel and the raised count only where it is spent "
          "(n1 used=%r, want 6)" % got.get("a", {}).get("used"))
    check(got.get("a", {}).get("cpus") == 2 and got.get("b", {}).get("cpus") == 0,
          "an offline node reports 0 cpus rather than a number the form would judge against "
          "(%r)" % {k: v.get("cpus") for k, v in got.items()})
    check(got.get("b", {}).get("used") == 0,
          "the excluded link is the only one on n2, so it counts nothing (n2 used=%r)"
          % got.get("b", {}).get("used"))


def check_chain(P, N, core_max):
    """create / edit / partial edit / rebuild, each carried all the way into the core's config file."""
    req = dict(RAW, workers=core_max)
    stored = stored_for(P, req)
    ce_e, _ = P._core_extra(dict(req), dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    ce_p, _ = P._core_extra({"transport": "raw"}, dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    bodies = {
        "create": P._node_extra(stored_for(P, req)),
        "edit": P._node_extra(ce_e),
        "edit(partial)": P._node_extra(ce_p),
        "rebuild": P._node_extra(P._tunnel_extra(dict(stored), refetch_ech=False)),
    }

    class Captured(Exception):
        def __init__(self, obj):
            self.obj = obj

    N.local_ips_flat = lambda: [A_IP]
    N.iface_for_ip = lambda ip: "eth0"
    N.read_config = lambda name: None
    N.base_mtu = lambda iface: 1500
    N.write_config = lambda name, obj: (_ for _ in ()).throw(Captured(dict(obj)))

    for path, body in bodies.items():
        d = dict(body, type="core", self_ip=A_IP, peer_ip=B_IP, subnet="10.9.0.0/24", id=9,
                 name="core9", host=1, role="server", psk="ab" * 32)
        try:
            N.op_tunnel(d)
            check(False, "%s: the node reached no write_config" % path)
            continue
        except Captured as c:
            obj = c.obj
        cfg = N._core_config(dict(obj, iface="eth0"))
        check(body.get("workers") == core_max and obj.get("workers") == core_max
              and cfg.get("workers") == core_max,
              "%-14s panel body=%r -> node persisted=%r -> core config=%r"
              % (path, body.get("workers"), obj.get("workers"), cfg.get("workers")))

    # ...and the node's own two gates, driven rather than read: an out-of-range value is refused, and
    # a persisted value never reaches the core beside FEC.
    d = dict(bodies["create"], type="core", self_ip=A_IP, peer_ip=B_IP, subnet="10.9.0.0/24", id=9,
             name="core9", host=1, role="server", psk="ab" * 32, workers=core_max + 1)
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
const MAX = %d;
const out = {vis:{}, seg:{}, body:{}, drop:{}};
// The row appears on raw-without-FEC and nowhere else, in BOTH forms, driven through the REAL gate the
// form calls -- not through a re-implementation of its condition.
for (const [form, S, gate, px] of [['create', _corS, corWorkersVis, 'e_'],
                                   ['edit',   _eeS,  ceWorkersVis,  'ee_']]) {
  out.vis[form] = {};
  S.NodesArr = ['', ''];                       // no node pair -> the budget line never fetches
  for (const tr of ['udp','tcp','raw','flux','spoof','ws','dns']) {
    for (const fec of [false, true]) {
      S.Tr = tr; S.Fec = fec; S.Workers = MAX;
      gate();
      out.vis[form][tr + (fec ? '+fec' : '')] =
        document.getElementById(px+'wrkrow').style.display !== 'none';
    }
  }
  // A value picked on raw must not survive a switch to a carrier that cannot spend it: the state itself
  // is reset, so the body builder cannot carry it into a save the panel would then refuse.
  S.Tr = 'raw'; S.Fec = false; S.Workers = MAX; gate();
  S.Tr = 'ws'; gate();
  out.drop[form] = S.Workers;
}
// The segment: each button paints, and the STATE moves with it. Per-form setter, per-form state field.
for (const [form, S, setter, px] of [['create', _corS, corSetWorkers, 'e_'],
                                     ['edit',   _eeS,  ceSetWorkers,  'ee_']]) {
  out.seg[form] = {};
  for (let n = 1; n <= MAX; n++) {
    setter(n);
    const on = [];
    for (let k = 1; k <= MAX; k++) if (document.getElementById(px+'wk_'+k).classList.contains('on')) on.push(k);
    out.seg[form][n] = {state: S.Workers, on: on};
  }
}
// ...and what the SHARED body builder actually sends, which is the only thing the node ever sees. The
// key's PRESENCE matters as much as its value: an absent key falls back to the stored one, so a form
// that only sent a raised value could never lower one again.
for (const [form, S, setter, px] of [['create', _corS, corSetWorkers, 'e_'],
                                     ['edit',   _eeS,  ceSetWorkers,  'ee_']]) {
  out.body[form] = {};
  document.getElementById(px+'cipher').value = 'auto';
  document.getElementById(px+'rawport').value = '443';
  for (const [label, tr, fec, n] of [['raw/1','raw',false,1], ['raw/max','raw',false,MAX],
                                     ['raw+fec','raw',true,MAX], ['ws','ws',false,MAX]]) {
    S.Tr = tr; S.Fec = fec; S.RawProfile = 'tcp'; setter(n);
    const b = {};
    _collectCoreBody(S, px, document.getElementById(px+'msg'), b);
    out.body[form][label] = ('workers' in b) ? b.workers : 'ABSENT';
  }
}
// The budget must EXCLUDE the link being edited, or that tunnel's own queues are counted twice and the
// form reports a node as full when it is not. Driven through the REAL open-edit path, because the id it
// needs is set there: `editingId` looks like the obvious source and is NOT — openModal overwrites it
// with its own sentinel before this ever runs.
out.exclude = {};
// Capture at the FETCH, not at j(): j is a script-scope binding, so assigning globalThis.j would leave
// the real one in place and the guard would pass on a page that never asks for the budget at all.
globalThis.fetch = (u) => { out.exclude.url = u; return new Promise(() => {}) };
FLEET = [{id:'L-9', name:'core9', a_node:'n1', b_node:'n2', a_name:'IR01', b_name:'DE01',
          a_ip:'10.0.0.1', b_ip:'10.0.0.2', a_ips:['10.0.0.1'], b_ips:['10.0.0.2'],
          server_side:'a', type:'core', transport:'raw', raw_profile:'tcp', cipher:'auto',
          subnet:'10.9.0.0/24', workers:3}];
openCoreEdit('L-9');
out.exclude.prefilled = _eeS.Workers;
out.exclude.lit = [1,2,3,4].filter(n => document.getElementById('ee_wk_'+n).classList.contains('on'));
console.log(JSON.stringify(out));
"""


def check_forms(P, core_max):
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
    got = json.loads(r.stdout.strip().splitlines()[-1])

    for form in ("create", "edit"):
        vis = got["vis"][form]
        shown = sorted(k for k, v in vis.items() if v)
        check(shown == ["raw"], "%-6s form: the row shows on %s (expected ['raw'])" % (form, shown))
        check(got["drop"][form] == 1,
              "%-6s form: leaving raw resets the state to one queue (got %r)"
              % (form, got["drop"][form]))
        for n in range(1, core_max + 1):
            s = got["seg"][form][str(n)]
            check(s["state"] == n and s["on"] == [n],
                  "%-6s form: picking %d sets the state to %r and lights %r"
                  % (form, n, s["state"], s["on"]))
        body = got["body"][form]
        check(body["raw/1"] == 1,
              "%-6s form: raw at one queue SENDS workers=1 (got %r) — an absent key would resurrect a "
              "stored 4" % (form, body["raw/1"]))
        check(body["raw/max"] == core_max,
              "%-6s form: raw at %d sends workers=%r" % (form, core_max, body["raw/max"]))
        check(body["raw+fec"] == "ABSENT",
              "%-6s form: raw+FEC sends no workers key (got %r)" % (form, body["raw+fec"]))
        check(body["ws"] == "ABSENT",
              "%-6s form: ws sends no workers key (got %r)" % (form, body["ws"]))

    ex = got["exclude"]
    check(ex.get("prefilled") == 3 and ex.get("lit") == [3],
          "open-edit loads the STORED queue count into the form (state=%r, lit=%r)"
          % (ex.get("prefilled"), ex.get("lit")))
    check("exclude=L-9" in (ex.get("url") or ""),
          "open-edit's budget EXCLUDES the edited link, or its own queues are counted twice (url=%r)"
          % (ex.get("url") or "<never fetched>",))


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
    print("\n== 2) the carrier pair the core spends queues on ==")
    check_core_gate(core)
    P = load(panel, "tnl_central_workers")
    N = load(node, "tnl_node_workers")
    print("\n== 3) panel: which carrier stores it, and inherit-vs-ask ==")
    check_panel_matrix(P, core_max)
    print("\n== 4) the value chain: every panel path -> node -> core config ==")
    check_chain(P, N, core_max)
    print("\n== 5) the per-node queue budget the form warns from ==")
    check_budget(P)
    print("\n== 6) both forms, driven through their own gates ==")
    check_forms(P, core_max)

    print("")
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("workers is one number in three repos, stored only where the core spends it, and both forms "
          "are wired to it.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
