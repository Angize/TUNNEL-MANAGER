#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: a tunnel card's header must name what the tunnel actually rides on.

The core page is all core tunnels, so a chip reading "Core" told the operator nothing — what differs
between those cards is the CARRIER, and it used to be visible only after expanding the card. System
cards have always named their kernel type in that slot; core cards now name their carrier.

Two ways this rots, and neither shows up in a screenshot:

  * a new transport lands and `carrierLabel` falls through to the `UDP` default, so a DNS or a spoof
    tunnel sits on the dashboard labelled UDP;
  * the header and the expanded body derive the label separately and drift, so the card contradicts
    itself — the header saying WS while the body says GRPC.

So this renders the REAL coreCard / linkCard for every transport out of the decoded INDEX_HTML under
node, reads the chip back out of the header, and asserts it names the carrier AND that the body's own
row agrees with it. The `full` form carries detail the header drops (the raw profile, the flux shape,
the dns zone) — that is checked as a prefix relationship, not equality.

Exit 1 on any failure.
"""
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

# transport -> what the header chip must read. Written from the PRODUCT rule, not from the code, so this
# stays a real assertion if carrierLabel is rewritten.
CORE_CASES = [
    ({"transport": "udp"}, "UDP"),
    ({"transport": "tcp"}, "TCP"),
    ({"transport": "raw", "raw_profile": "icmp"}, "RAW"),
    ({"transport": "raw", "raw_profile": "bare", "raw_proto": 253}, "RAW"),
    ({"transport": "flux", "flux_carrier": "stun"}, "FLUX"),
    ({"transport": "ws", "ws_host": "cdn.example.com"}, "WS"),
    ({"transport": "ws", "cdn_carrier": "http", "ws_host": "cdn.example.com"}, "HTTP"),
    ({"transport": "ws", "cdn_carrier": "grpc", "ws_host": "cdn.example.com"}, "GRPC"),
    ({"transport": "dns", "dns_zone": "t.example.com"}, "DNS"),
    ({"transport": "spoof", "spoof_src": True, "spoof_dst": True}, "SPOOF"),
]
SYS_TYPES = ["gre", "vxlan", "ipip", "sit", "gretap", "wg"]

PRELUDE = r"""
const noop = () => {};
const mkClassList = () => { const s = new Set(); return {add:c=>s.add(c),remove:c=>s.delete(c),
  toggle:(c,on)=>(on?s.add(c):s.delete(c)),contains:c=>s.has(c)}; };
function mkStub(){ return {style:{},classList:mkClassList(),dataset:{},children:[],
  set innerHTML(v){}, get innerHTML(){return ''}, set textContent(v){}, get textContent(){return ''},
  appendChild:noop,addEventListener:noop,setAttribute:noop,removeAttribute:noop,remove:noop,
  insertAdjacentHTML:noop,focus:noop,click:noop,querySelector:()=>null,querySelectorAll:()=>[],
  closest:()=>null,getBoundingClientRect:()=>({top:0,left:0,width:0,height:0}),getAttribute:()=>null,
  insertBefore:noop,value:'',disabled:false}; }
globalThis.window = globalThis;
globalThis.document = {documentElement:{classList:mkClassList(),style:{},scrollHeight:0,clientHeight:0},
  body:{classList:mkClassList(),style:{},appendChild:noop}, head:{appendChild:noop},
  getElementById:()=>mkStub(), querySelector:()=>null, querySelectorAll:()=>[],
  createElement:()=>mkStub(), addEventListener:noop, cookie:'', readyState:'complete', title:''};
globalThis.innerHeight = 800; globalThis.pageYOffset = 0; globalThis.scrollBy = noop;
globalThis.location = {href:'http://x/',pathname:'/',search:'',hash:'',reload:noop};
globalThis.localStorage = {getItem:()=>null,setItem:noop,removeItem:noop};
globalThis.matchMedia = () => ({matches:false,addEventListener:noop,addListener:noop});
globalThis.navigator = {userAgent:'node',language:'fa'};
globalThis.setInterval = () => 0; globalThis.setTimeout = () => 0;
globalThis.requestAnimationFrame = () => 0; globalThis.cancelAnimationFrame = noop;
globalThis.alert = noop; globalThis.confirm = () => false;
globalThis.getComputedStyle = () => ({getPropertyValue:()=>''});
globalThis.fetch = () => new Promise(() => {});
"""

HARNESS = r"""
// The chip is the FIRST .ctag in the header; the body is everything after the header opens.
function chipOf(html){ const m = /<span class="ctag ([^"]*)">([^<]*)<\/span>/.exec(html);
  return m ? {cls: m[1], text: m[2]} : null }
function textOf(html){ return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ') }

const out = {core: [], sys: []};
for (const l of %s) { const html = coreCard(l);
  out.core.push({transport: l.transport, cdn: l.cdn_carrier || '', chip: chipOf(html),
                 full: carrierLabel(l, true), body: textOf(html)}); }
for (const l of %s) { const html = linkCard(l);
  out.sys.push({type: l.type, chip: chipOf(html)}); }
console.log(JSON.stringify(out));
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    import importlib.util
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_chip", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", mod.INDEX_HTML, re.S), key=len)
    for fn in ("function accHead(", "function carrierLabel(", "function coreCard(", "function linkCard("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1

    base = dict(id=1, name="t1", type="core", a_node=1, b_node=2, a_name="IR01", b_name="DE01",
                a_ip="203.0.113.5", b_ip="198.51.100.7", enabled=True, server_side="a",
                cipher="auto", subnet="10.20.1.0/24", port=20001,
                health={"a": {"up": True, "alive": True}, "b": {"up": True, "alive": True}})
    cores = [dict(base, **extra) for extra, _ in CORE_CASES]
    sysu = [dict(base, type=t, name="n%d" % i) for i, t in enumerate(SYS_TYPES)]

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "chip.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % (json.dumps(cores), json.dumps(sysu))),
                     encoding="utf-8")
        try:
            r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8", timeout=60)
        except subprocess.TimeoutExpired:
            print(" FAIL the harness never finished")
            print("\n1 failure(s).")
            return 1
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:900])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])

    print("== 1) a core card's header names its CARRIER ==")
    seen = set()
    for (extra, want), row in zip(CORE_CASES, got["core"]):
        chip = row["chip"]
        label = "%s%s" % (extra["transport"], ("/" + extra["cdn_carrier"]) if extra.get("cdn_carrier") else "")
        check(chip is not None and chip["text"] == want,
              "%-11s -> chip %s, want %s" % (label, (chip and repr(chip["text"])) or "MISSING", want))
        if chip:
            seen.add(chip["text"])
            check(chip["cls"].startswith("c-"),
                  "%-11s -> chip carries its own colour class (%s)" % (label, chip["cls"]))

    print("== 2) ...and no two carriers share one label ==")
    check(len(seen) == len({w for _, w in CORE_CASES}),
          "every carrier is distinguishable on the card: %s" % sorted(seen))

    print("== 3) the header and the expanded body do not contradict each other ==")
    # These four carry a second half the header deliberately drops. If the body stops carrying it the
    # detail is gone from the UI entirely -- the header never had it -- and a "same family" check alone
    # would still pass, which is how this section was vacuous on its first pass.
    DETAILED = {"raw", "flux", "spoof", "dns"}
    for (extra, want), row in zip(CORE_CASES, got["core"]):
        full, t = row["full"], extra["transport"]
        check(full.split("·")[0] == want,
              "%-11s -> body says %-16s header says %-6s (same family)" % (t, full, want))
        check(full in row["body"],
              "%-11s -> the body row really carries %s" % (t, full))
        if t in DETAILED:
            check("·" in full and full.split("·", 1)[1].strip() != "",
                  "%-11s -> the body still carries the detail the header drops (%s)" % (t, full))

    print("== 4) system cards still name their kernel type ==")
    for t, row in zip(SYS_TYPES, got["sys"]):
        chip = row["chip"]
        check(chip is not None and chip["text"] == t.upper(),
              "%-7s -> chip %s" % (t, (chip and repr(chip["text"])) or "MISSING"))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("every card names the carrier it rides on, and the header and body agree.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
