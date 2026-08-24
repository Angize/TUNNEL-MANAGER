#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the addresses on a tunnel card can be lifted out with one tap, on the panel as deployed.

An operator reads an overlay subnet or a node IP off a card and then has to type it somewhere else, on a
phone, from memory. So every card prints those three values — both node IPs and the subnet — as a
copy-on-tap element.

Two ways this dies quietly, and neither shows up in a screenshot:

  * a card is rewritten and a value goes back to a plain <b>, so tapping it does nothing and the only
    signal is an operator retyping an address;
  * somebody "modernises" the copy path to navigator.clipboard alone. The panel is reached over plain
    http on an IP, which is NOT a secure context: navigator.clipboard is undefined there, so the copy
    silently stops working on the one deployment that exists while still working on localhost.

So this renders the REAL coreCard / linkCard out of the decoded INDEX_HTML under node, asserts each of
the three values is a wired copy element, and then RUNS copyTxt on both sides of the secure-context
branch to prove the insecure one still copies.

Exit 1 on any failure.
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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import raw_rows_gate_check as G     # noqa: E402  (reuse its DOM prelude)

A_IP, B_IP, SUBNET = "203.0.113.5", "198.51.100.7", "10.20.1.0/24"

HARNESS = r"""
// Overrides on top of the shared prelude: a createElement that hands back a REAL value slot, and an
// execCommand that records, so the fallback path can be run rather than grepped for.
let lastTa = null;
const EXEC = [];
document.createElement = function(tag){ const o = mk('new'); o.tag = tag;
  o.select = function(){}; o.setSelectionRange = function(){};
  if (tag === 'textarea') lastTa = o;
  return o };
document.execCommand = function(cmd){ EXEC.push(cmd); return true };

function copyables(html){ const out = []; const re = /<(?:b|div)\s[^>]*\bcpv\b[^>]*>([^<]*)</g;
  let m; while ((m = re.exec(html))) out.push(m[1]); return out }
function unwired(html){ const out = []; const re = /<(?:b|div)\s[^>]*\bcpv\b[^>]*>/g;
  let m; while ((m = re.exec(html))) if (m[0].indexOf('copyTxt(') < 0) out.push(m[0]); return out }

const res = {cards: []};
for (const l of %s) { const html = (l.type === 'core') ? coreCard(l) : linkCard(l);
  res.cards.push({kind: l.type, values: copyables(html), unwired: unwired(html)}); }

// node defines `navigator` as a read-only accessor, so a plain assignment is swallowed and the whole
// secure branch would read as absent -- which is the answer this guard has to earn, not assume.
function setNav(v){ Object.defineProperty(globalThis, 'navigator',
  {value: v, configurable: true, writable: true}) }

// the deployed panel: plain http, so no secure context and no navigator.clipboard at all
let wrote = null;
globalThis.isSecureContext = false;
setNav({userAgent: 'node', language: 'fa'});
copyTxt('203.0.113.5');
res.insecure = {exec: EXEC.slice(), value: lastTa && lastTa.value, wrote: wrote};

// and a TLS-fronted one, where the async API is there and must be preferred
EXEC.length = 0; lastTa = null;
globalThis.isSecureContext = true;
setNav({userAgent: 'node', language: 'fa',
  clipboard: {writeText: function(s){ wrote = s; return Promise.resolve() }}});
copyTxt('10.20.1.0/24');
res.secure = {exec: EXEC.slice(), value: lastTa && lastTa.value, wrote: wrote};

console.log(JSON.stringify(res));
"""

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def main():
    spec = importlib.util.spec_from_file_location("tnl_central_copy", HERE.parent / "tnl-central.py")
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    for fn in ("function copyTxt(", "function copyFallback(", "function cpv("):
        if fn not in js:
            print("FAIL: %s is not in the rendered page -- the guard cannot read its subject" % fn)
            return 1

    base = dict(id=1, name="t1", a_node=1, b_node=2, a_name="IR01", b_name="DE01",
                a_ip=A_IP, b_ip=B_IP, enabled=True, server_side="a", cipher="auto",
                subnet=SUBNET, port=20001, tunnel_id=1)
    cards = [dict(base, type="core", transport="udp"), dict(base, type="vxlan")]

    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "copy.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" + (HARNESS % json.dumps(cards)), encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:900])
        return 1
    got = json.loads(r.stdout.strip().splitlines()[-1])

    print("== 1) every card offers its two node IPs and its subnet as copy targets ==")
    want = {A_IP, B_IP, SUBNET}
    for row in got["cards"]:
        check(set(row["values"]) == want,
              "%-6s card -> copyable %s, want %s" % (row["kind"], sorted(row["values"]), sorted(want)))
        check(not row["unwired"],
              "%-6s card -> every copy element calls copyTxt (unwired: %s)" % (row["kind"], row["unwired"]))

    print("== 2) the copy still runs where the panel actually lives: plain http, no clipboard API ==")
    ins = got["insecure"]
    check(ins["exec"] == ["copy"], "insecure context -> execCommand('copy') ran (%s)" % ins["exec"])
    check(ins["value"] == A_IP, "insecure context -> the value reached the textarea (%r)" % ins["value"])
    check(ins["wrote"] is None, "insecure context -> nothing was handed to a clipboard API that is not there")

    print("== 3) ...and a TLS-fronted panel takes the async API instead ==")
    sec = got["secure"]
    check(sec["wrote"] == SUBNET, "secure context -> writeText got the value (%r)" % sec["wrote"])
    check(sec["exec"] == [], "secure context -> no execCommand fallback was needed (%s)" % sec["exec"])

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("every card address is one tap from the clipboard, on http and on https alike.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
