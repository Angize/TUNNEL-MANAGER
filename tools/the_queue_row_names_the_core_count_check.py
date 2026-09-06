#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the parallel-queue row says how many cores the node it names actually has.

The row asks the operator to pick between 1 and 8 send queues «روی MMD-GE15», and until now that was
the whole label. Nothing on the page said MMD-GE15 has two cores. Picking 8 queues on a 2-core box
does not make it faster -- it makes eight goroutines fight over two cores -- and the operator had no
way to know without ssh'ing to the node. Measured on the live pair the day this shipped: MMD-IR15 is
a 4-core Xeon E5-2696 v2, MMD-GE15 a 2-core EPYC-Rome. The form offered both the same eight tiles.

The count already existed. `read_stats()` on the node has always reported `cpus`, and the node DETAIL
drawer already printed it -- it just never reached the two places that decide a queue count. So this
follows the value, not the helper:

  * api_node_names carries `cpus`, because the CREATE modal has no fleet record to read;
  * api_fleet carries `a_cpus`/`b_cpus`, because openCoreEdit never refetches node-names and would
    otherwise show the count only when the operator had visited the nodes page first;
  * and both label paths -- corWorkersVis (create, off SEL) and ceWorkersVis (edit, off the record) --
    are RUN here against a recording DOM, not called through their helper, because a helper that
    formats correctly proves nothing about a caller that never passes it the number.

An unknown count prints no fragment at all. «روی MMD-GE15 · دارای  هسته» would be worse than the
label we started with.

    python3 tools/the_queue_row_names_the_core_count_check.py
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel():
    spec = importlib.util.spec_from_file_location("panel_cores", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# The shared PRELUDE hands out a fresh throwaway stub per getElementById and drops every textContent
# write, so a label written through it is unobservable. This keeps one node per id and remembers what
# was written to it -- enough to run the real paint and read the answer back.
DOM = r"""
const DOMREG = {};
function mkNode(id){
  let _t = '', _h = '';
  const s = {id: id, style: {display: '', order: ''}, dataset: {}, children: [],
    classList: {add:()=>{},remove:()=>{},toggle:()=>{},contains:()=>false},
    get textContent(){return _t}, set textContent(v){_t = String(v)},
    get innerHTML(){return _h}, set innerHTML(v){_h = String(v)},
    appendChild:()=>{}, addEventListener:()=>{}, setAttribute:()=>{}, removeAttribute:()=>{},
    remove:()=>{}, insertAdjacentHTML:()=>{}, focus:()=>{}, click:()=>{},
    querySelector:()=>null, querySelectorAll:()=>[], closest:()=>null, getAttribute:()=>null,
    insertBefore:()=>{}, getBoundingClientRect:()=>({top:0,left:0,width:0,height:0}),
    value: '', disabled: false};
  return s;
}
document.getElementById = function(id){ return DOMREG[id] || (DOMREG[id] = mkNode(id)) };
"""

HARNESS = r"""
function lbls(idp){ return {a: document.getElementById(idp+'wklbl_a').textContent,
                            b: document.getElementById(idp+'wklbl_b').textContent,
                            order_a: document.getElementById(idp+'wkone_a').style.order,
                            order_b: document.getElementById(idp+'wkone_b').style.order,
                            row: document.getElementById(idp+'wrkrow').style.display} }
const OUT = {};
for (const c of CASES) {
  const l = c.link;
  if (c.path === 'edit') {
    _eeS.Srv = (l.server_side=='b')?'b':'a'; _eeS.Tr = l.transport;
    _eeS.RawProfile = l.raw_profile||'bare';
    _eeS.NodesArr = [l.a_node, l.b_node];
    _eeS.NamesArr = [l.a_name||'', l.b_name||''];
    _eeS.CpusArr = [num(l.a_cpus), num(l.b_cpus)];
    _eeS.WorkersA = wkClamp(l.a_workers); _eeS.WorkersB = wkClamp(l.b_workers);
    NODES = c.nodes || [];
    ceWorkersVis();
    OUT[c.name] = lbls('ee_');
  } else {
    _corS.Srv = (l.server_side=='b')?'b':'a'; _corS.Tr = l.transport;
    _corS.RawProfile = l.raw_profile||'bare';
    _corS.WorkersA = wkClamp(l.a_workers); _corS.WorkersB = wkClamp(l.b_workers);
    NODES = c.nodes || [];
    SEL['e_a'] = l.a_node; SEL['e_b'] = l.b_node;
    corWorkersVis();
    OUT[c.name] = lbls('e_');
  }
}
console.log('@@' + JSON.stringify(OUT));
"""

N15 = [{"id": 1, "name": "MMD-IR15", "cpus": 4, "online": True},
       {"id": 2, "name": "MMD-GE15", "cpus": 2, "online": True}]
N_NOCPU = [{"id": 1, "name": "MMD-IR15", "online": True},
           {"id": 2, "name": "MMD-GE15", "online": True}]
RAW = {"server_side": "b", "transport": "raw", "raw_profile": "tcp",
       "a_node": 1, "b_node": 2, "a_name": "MMD-IR15", "b_name": "MMD-GE15",
       "a_workers": 4, "b_workers": 2}


def link(**kw):
    d = dict(RAW)
    d.update(kw)
    return d


# name -> (path, link, the NODES the browser holds, what each label must read)
CASES = [
    ("edit, the record carries both", "edit", link(a_cpus=4, b_cpus=2), N_NOCPU,
     "روی MMD-IR15 · دارای 4 هسته", "روی MMD-GE15 · دارای 2 هسته"),
    ("edit, only NODES knows", "edit", link(), N15,
     "روی MMD-IR15 · دارای 4 هسته", "روی MMD-GE15 · دارای 2 هسته"),
    ("edit, nobody knows", "edit", link(a_node=9, b_node=8, a_name="GONE-A", b_name="GONE-B"), N15,
     "روی GONE-A", "روی GONE-B"),
    ("edit, one side is offline", "edit", link(a_cpus=4, b_node=9, b_name="GONE"), N_NOCPU,
     "روی MMD-IR15 · دارای 4 هسته", "روی GONE"),
    ("edit, one core and sixty-four", "edit",
     link(a_name="X", b_name="Y", a_cpus=1, b_cpus=64), N_NOCPU,
     "روی X · دارای 1 هسته", "روی Y · دارای 64 هسته"),
    ("create, off the node list", "create", link(), N15,
     "روی MMD-IR15 · دارای 4 هسته", "روی MMD-GE15 · دارای 2 هسته"),
    ("create, the list has no count", "create", link(), N_NOCPU,
     "روی MMD-IR15", "روی MMD-GE15"),
]


def render(P):
    sys.path.insert(0, str(ROOT / "tools"))
    import card_names_its_carrier_check as C
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    cases = [{"name": n, "path": p, "link": l, "nodes": nd} for n, p, l, nd, _, _ in CASES]
    src = (C.PRELUDE + "\n" + DOM + "\n" + js + "\nconst CASES=" +
           json.dumps(cases, ensure_ascii=False) + ";" + HARNESS)
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "c.js"
        f.write_text(src, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True,
                           encoding="utf-8", timeout=120)
    if r.returncode != 0:
        print("FAIL: the page would not run:\n" + (r.stderr or "")[:900])
        sys.exit(1)
    for line in r.stdout.splitlines():
        if line.startswith("@@"):
            return json.loads(line[2:])
    print("FAIL: the harness printed nothing")
    sys.exit(1)


def fleet(P, nodes, ping, link_):
    P.load_nodes = lambda: nodes
    P.load_links = lambda: [dict(link_)]
    P._ensure_cached = lambda ns: None
    P._cached_ping = lambda nid: ping.get(nid, {})
    P._cached_list = lambda nid: {"ok": True, "configs": [], "health": {}, "sports": {}, "rots": {}}
    P.link_drift = lambda lid: None
    P.rb_last = lambda lid: None
    return P.api_fleet({"kind": "core"})["links"][0]


def main():
    P = load_panel()

    print("\n-- the two APIs that carry the number --")
    NODES = [{"id": 1, "name": "MMD-IR15", "host": "94.182.131.39", "port": 9000},
             {"id": 2, "name": "MMD-GE15", "host": "91.107.152.57", "port": 9000}]
    IPS = {"v4": ["94.182.131.39"]}
    PING = {1: {"ok": True, "stats": {"cpus": 4}, "ips": IPS},
            2: {"ok": True, "stats": {"cpus": 2}, "ips": {}}}
    L = {"id": "re20", "type": "core", "name": "core20", "a_node": 1, "b_node": 2,
         "server_side": "b", "transport": "raw", "raw_profile": "tcp", "psk": "x", "tunnel_id": 20}

    rec = fleet(P, NODES, PING, L)
    check(rec.get("a_cpus") == 4 and rec.get("b_cpus") == 2,
          "api_fleet carries a_cpus and b_cpus", (rec.get("a_cpus"), rec.get("b_cpus")))
    # a_ips and the cpu count now read the same cached ping. If that share went wrong the ips would
    # go quietly empty and only the map on the card would notice.
    check(rec.get("a_ips") == P._flat_ips(PING[1]),
          "  and the ips it shares that ping with still arrive", rec.get("a_ips"))

    names = {n["name"]: n.get("cpus") for n in P.api_node_names({})["nodes"]}
    check(names == {"MMD-IR15": 4, "MMD-GE15": 2}, "api_node_names carries cpus", names)

    PING[2] = {"ok": False, "error": "unreachable"}
    rec = fleet(P, NODES, PING, L)
    check(rec.get("a_cpus") == 4 and rec.get("b_cpus") is None,
          "an unreachable node reports no count rather than a wrong one",
          (rec.get("a_cpus"), rec.get("b_cpus")))
    check(P.api_node_names({})["nodes"][1].get("cpus") is None,
          "  and node-names says the same", P.api_node_names({})["nodes"][1].get("cpus"))

    print("\n-- both label paths, run --")
    out = render(P)
    for name, path, l, nd, wa, wb in CASES:
        got = out.get(name) or {}
        check(got.get("a") == wa, "%s: side a reads «%s»" % (name, wa), got.get("a"))
        check(got.get("b") == wb, "%s: side b reads «%s»" % (name, wb), got.get("b"))
        check("هسته" not in (got.get("a", "") + got.get("b", "")) or
              not re.search(r"دارای\s+هسته", got.get("a", "") + got.get("b", "")),
              "%s:   and never prints an empty count" % name, got)
        srv = "b" if l["server_side"] == "b" else "a"
        check(str(got.get("order_" + srv)) == "0",
              "%s:   the server side still comes first" % name,
              (got.get("order_a"), got.get("order_b")))

    print("\n-- the label is one string, and its keys exist --")
    i18n = P.INDEX_HTML
    check('workers_lbl_cores:"' in i18n, "workers_lbl_cores is a real key")
    m = re.search(r'workers_lbl_cores:"([^"]*)"', i18n)
    check(m is not None and "{c}" in m.group(1), "  and it has a slot for the number",
          m.group(1) if m else None)

    print()
    if fails:
        print("FAILED (%d)" % len(fails))
        for f in fails:
            print("  - " + f)
        return 1
    print("the queue row names the node AND the cores it has")
    return 0


if __name__ == "__main__":
    sys.exit(main())
