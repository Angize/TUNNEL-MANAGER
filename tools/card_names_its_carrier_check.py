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
«نوع» row carries the IDENTICAL chip. The sub-choice the header drops (the raw profile, the spoof
carrier, the spoof mode, the dns zone) has its own row: the families that have one must print it, and
the families that do not must print no row at all rather than an empty one.

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

# transport -> (what the header chip must read, what the body profile row must read). Both written
# from the PRODUCT rule, not from the code, so this stays a real assertion if the helpers are rewritten.
# An empty profile means the family IS the whole answer and the row must not be printed at all.
CORE_CASES = [
    ({"transport": "udp"}, "UDP", ""),
    ({"transport": "tcp"}, "TCP", ""),
    ({"transport": "raw", "raw_profile": "icmp"}, "RAW", "ICMP"),
    ({"transport": "raw", "raw_profile": "tcp", "raw_port": 8801}, "RAW", "TCP"),
    ({"transport": "raw", "raw_profile": "udp", "raw_sport_random": True}, "RAW", "UDP"),
    ({"transport": "raw", "raw_profile": "bare", "raw_proto": 253}, "RAW", "BARE(253)"),
    ({"transport": "ws", "ws_host": "cdn.example.com"}, "WS", ""),
    ({"transport": "ws", "cdn_carrier": "http", "ws_host": "cdn.example.com"}, "HTTP", ""),
    ({"transport": "ws", "cdn_carrier": "grpc", "ws_host": "cdn.example.com"}, "GRPC", ""),
    ({"transport": "dns", "dns_zone": "t.example.com"}, "DNS", "T.EXAMPLE.COM"),
    ({"transport": "spoof", "spoof_src": True, "spoof_dst": True}, "SPOOF", "SRC+DST"),
]
SYS_TYPES = ["gre", "vxlan", "ipip", "sit", "gretap", "wg"]

# The source-port row names the MODE and then, in brackets, the port actually in force. The live number
# out of the client's core wins over the stored one, because a ROLLED port exists nowhere else at all:
# the stored config only says that it rolls. With no live number and no fixed one there is nothing
# truthful to put in brackets, so there must be no brackets.
SPORT_CASES = [
    ("default",            {}, "ثابت (51820)"),
    ("fixed 4500",         {"raw_sport": 4500}, "ثابت (4500)"),
    ("fixed, live agrees", {"raw_sport": 4500, "sport_live": 4500}, "ثابت (4500)"),
    ("rolled, no live",    {"raw_sport_random": True}, "رندوم"),
    ("rolled, live 39421", {"raw_sport_random": True, "sport_live": 39421}, "رندوم (39421)"),
    # A live port the core reports must win: the operator is reading what the wire carries, not what
    # the form once said. This is the case that makes the row worth printing at all.
    ("fixed 4500, live 500", {"raw_sport": 4500, "sport_live": 500}, "ثابت (500)"),
]

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
// The chip is the FIRST .ctag in the header; the body prints its own inside the .tagrow row, and the
// sub-choice sits one row below it, as the profile label followed by a .mono value.
function chipOf(html){ const m = /<span class="ctag ([^"]*)">([^<]*)<\/span>/.exec(html);
  return m ? {cls: m[1], text: m[2]} : null }
function rowChipOf(html){
  const m = /<div class="tagrow">[^<]*<span class="ctag ([^"]*)">([^<]*)<\/span>/.exec(html);
  return m ? {cls: m[1], text: m[2]} : null }
function textOf(html){ return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ') }
const PL = T('profile');
const PROW = new RegExp('>' + PL + ': <b class=\"mono\">([^<]*)</b>');
// Every port row the card printed, keyed by its label, so the guard can say WHICH port is missing.
const PORTLBL = {dst: T('port_dst'), src: T('port_src'), one: T('port')};
function portsOf(html){ const out = {};
  for (const k of Object.keys(PORTLBL)) {
    const m = new RegExp('>' + PORTLBL[k] + ': <b class=\"mono\">([^<]*)</b>').exec(html);
    if (m) out[k] = m[1]; }
  return out }

const out = {core: [], sys: [], profLabel: PL};
for (const l of %s) { const html = coreCard(l);
  const pm = PROW.exec(html);
  out.core.push({transport: l.transport, cdn: l.cdn_carrier || '', chip: chipOf(html),
                 rowChip: rowChipOf(html), prof: carrierProfile(l),
                 profRow: pm ? pm[1] : null, ports: portsOf(html), body: textOf(html)}); }
for (const l of %s) { const html = linkCard(l);
  out.sys.push({type: l.type, chip: chipOf(html)}); }
out.sport = [];
for (const l of %s) { out.sport.push(portsOf(coreCard(l)).src || null); }
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
    for fn in ("function accHead(", "function carrierLabel(", "function carrierProfile(",
               "function coreCard(", "function linkCard("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1

    base = dict(id=1, name="t1", type="core", a_node=1, b_node=2, a_name="IR01", b_name="DE01",
                a_ip="203.0.113.5", b_ip="198.51.100.7", enabled=True, server_side="a",
                cipher="auto", subnet="10.20.1.0/24", port=20001,
                health={"a": {"up": True, "alive": True}, "b": {"up": True, "alive": True}})
    cores = [dict(base, **extra) for extra, _w, _p in CORE_CASES]
    sysu = [dict(base, type=t, name="n%d" % i) for i, t in enumerate(SYS_TYPES)]
    sports = [dict(base, transport="raw", raw_profile="tcp", raw_port=8801, **extra)
              for _n, extra, _w in SPORT_CASES]

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "chip.js"
        p.write_text(PRELUDE + "\n" + js + "\n" + (HARNESS % (json.dumps(cores), json.dumps(sysu),
                                                                  json.dumps(sports))),
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
    for (extra, want, _p), row in zip(CORE_CASES, got["core"]):
        chip = row["chip"]
        label = "%s%s" % (extra["transport"], ("/" + extra["cdn_carrier"]) if extra.get("cdn_carrier") else "")
        check(chip is not None and chip["text"] == want,
              "%-11s -> chip %s, want %s" % (label, (chip and repr(chip["text"])) or "MISSING", want))
        if chip:
            seen.add(chip["text"])
            check(chip["cls"].startswith("c-"),
                  "%-11s -> chip carries its own colour class (%s)" % (label, chip["cls"]))

    print("== 2) ...and no two carriers share one label ==")
    check(len(seen) == len({w for _, w, _p in CORE_CASES}),
          "every carrier is distinguishable on the card: %s" % sorted(seen))

    print("== 3) the header chip and the body type row are the SAME chip ==")
    for (extra, want, _p), row in zip(CORE_CASES, got["core"]):
        t, rc, hc = extra["transport"], row["rowChip"], row["chip"]
        check(rc is not None and hc is not None and rc == hc,
              "%-11s -> body row chip %s, header chip %s" % (t, rc, hc))

    print("== 4) ...and the sub-choice the chip drops has its own row ==")
    # The chip deliberately says only the family, so raw/spoof/dns would lose their second half
    # entirely if this row went missing -- and a chip-equality check alone would still pass, which is
    # exactly how the previous version of this section went vacuous. The reverse is checked too: a
    # family with nothing to choose must print NO row, not an empty one.
    for (extra, want, prof), row in zip(CORE_CASES, got["core"]):
        t = extra["transport"] + (("/" + extra["cdn_carrier"]) if extra.get("cdn_carrier") else "")
        check(row["prof"] == prof,
              "%-11s -> carrierProfile %r, want %r" % (t, row["prof"], prof))
        if prof:
            check(row["profRow"] == prof,
                  "%-11s -> the card prints the row %s: %s (got %r)" % (t, got["profLabel"], prof, row["profRow"]))
        else:
            check(row["profRow"] is None,
                  "%-11s -> no profile row at all (got %r)" % (t, row["profRow"]))

    print("== 5) a raw udp/tcp card prints BOTH forged ports ==")
    # raw's udp and tcp profiles are the only carriers that forge a whole L4 header, so they are the
    # only ones with a source port to show -- and the card used to print no port at all for raw, which
    # read as "this tunnel has no port" on the one carrier that has two. The numbers themselves are
    # tied to the core by tools/tuning_consistency.py; this is about which ROWS exist.
    for (extra, want, _p), row in zip(CORE_CASES, got["core"]):
        t = extra["transport"]
        prof, ports = extra.get("raw_profile"), row["ports"]
        if t == "raw" and prof in ("udp", "tcp"):
            check(set(ports) == {"dst", "src"},
                  "raw/%-5s -> prints both forged ports (%s)" % (prof, ports))
        elif t in ("raw", "spoof", "dns"):
            check(ports == {},
                  "%-11s -> forges no port, so prints none (%s)" % (t, ports))
        else:
            check(set(ports) == {"one"},
                  "%-11s -> prints the one dialled port (%s)" % (t, ports))

    print("== 6) the source-port row names the mode AND the port in force ==")
    for (name, extra, want), val in zip(SPORT_CASES, got["sport"]):
        check(val == want, "%-22s -> %r, want %r" % (name, val, want))

    print("== 7) system cards still name their kernel type ==")
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
