#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: when the source port moves, the card shows BOTH ends' ports and names the right clock.

A raw udp/tcp tunnel has three source-port modes, and two of them move:

  * «ثابت»           - one port, chosen to look like something (51820 = WireGuard, 500 = IKE).
  * «چرخشِ پورتِ مبدأ» - both ends walk a PSK-keyed permutation, one step every N packets.
  * «رندومِ واکنشی»   - the same walk, one step per FAILOVER.

The reactive mode used to move only the client: the server answered from the configured port for the
life of the tunnel, so of the two source ports on the wire one was a constant. It steps now, driven by
the client's port changing, which is the same event seen from the other side.

The card has to keep up, and there are three ways it silently does not:

  * it renders ONE «پورتِ مبدأ» row for a mode that has two moving ports, so half of what is on the
    wire is invisible and the operator watching for a stuck port cannot see the stuck one;
  * it renders «هر 0 پکت» -- the reactive mode reports no packet budget, and a template that just
    substitutes it produces a sentence that is not merely wrong but nonsense;
  * the DESTINATION starts moving. It must not. A host firewall filters inbound on the destination
    (`ufw allow 443/udp`), and CORE #455 had to be reverted because moving it killed every ufw client.
    In the reactive mode the client's destination is the configured raw_port, full stop.

So this renders the REAL coreCard out of the decoded INDEX_HTML under node and reads the port rows
back. It also checks the two ends of the chain that feed it, because a perfect card with nothing to
render is the same blank screen: the core must publish its ports in BOTH moving modes (it used to
publish only for the packet rotation), and the node must forward that report whenever a source port is
in it (it used to forward only when a packet budget was in it, which the reactive mode does not set).

    python3 tools/both_ends_show_their_source_port_check.py

Exit 1 on any failure.
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PANEL = ROOT / "tnl-central.py"
CORE = Path(os.environ.get("CORE_DIR") or (ROOT.parent / "TUNNEL-MANAGER-CORE"))
NODE = Path(os.environ.get("NODE_DIR") or (ROOT.parent / "TUNNEL-MANAGER-NODE"))

sys.path.insert(0, str(HERE))
import card_names_its_carrier_check as C  # noqa: E402

REPORT = {"cli": 31337, "srv": 52011, "dport": 443, "dports": 0, "every": 0,
          "lo": 10000, "hi": 59999, "drawn": 3}
ROT_REPORT = dict(REPORT, every=4, cli=21000, srv=44444, drawn=9)

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


HARNESS = r"""
const LBL = %s, KEYS = %s;
const out = {labels: {}, keys: {}, rows: []};
for (const [k, key] of Object.entries(LBL)) out.labels[k] = T(key);
for (const k of KEYS) out.keys[k] = T(k);
function rowsOf(html){ const o = {};
  for (const [k, lbl] of Object.entries(out.labels)) {
    const m = new RegExp('>' + lbl + ': <b class="mono">([^<]*)</b>').exec(html);
    if (m) o[k] = m[1]; }
  const b = /<div class="wrap muted">([^<]*)<\/div>/g;
  let last = null, m2;
  while ((m2 = b.exec(html)) !== null) last = m2[1];
  o.band = last;
  return o; }
for (const l of %s) { out.rows.push(rowsOf(coreCard(l))); }
console.log(JSON.stringify(out));
"""

LABELS = {"dst": "port_dst", "one": "port_src", "up": "port_src_rot_up",
          "down": "port_src_rot_down"}
WORDS = ["port_src", "port_src_rand", "port_src_fixed", "port_src_rot", "port_src_rot_up",
         "port_src_rot_down", "port_src_rot_every", "port_src_rot_drawn", "port_src_rot_fail"]


def render(cases):
    spec = importlib.util.spec_from_file_location("tnl_bothends", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", mod.INDEX_HTML, re.S), key=len)
    src = C.PRELUDE + "\n" + js + "\n" + (
        HARNESS % (json.dumps(LABELS), json.dumps(WORDS), json.dumps(cases)))
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "card.js"
        p.write_text(src, encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True,
                           encoding="utf-8", timeout=90)
    if r.returncode != 0:
        print("FAIL: the page's own script would not run:\n" + (r.stderr or "")[:900])
        sys.exit(1)
    return json.loads(r.stdout.strip().splitlines()[-1])


def main():
    base = dict(id=1, name="t1", type="core", a_node=1, b_node=2, a_name="IR01", b_name="DE01",
                a_ip="203.0.113.5", b_ip="198.51.100.7", enabled=True, server_side="a",
                cipher="auto", subnet="10.20.1.0/24", port=20001, transport="raw",
                raw_profile="udp", raw_port=443,
                health={"a": {"up": True, "alive": True}, "b": {"up": True, "alive": True}})
    cases = [
        ("reactive, both ends reporting", dict(base, raw_sport_random=True, rot_live=REPORT)),
        ("rotation, both ends reporting", dict(base, raw_sport_rotate=4, rot_live=ROT_REPORT)),
        ("reactive, only the client's node answered",
         dict(base, raw_sport_random=True, rot_live=dict(REPORT, srv=0))),
        ("reactive, only the server's node answered",
         dict(base, raw_sport_random=True, rot_live=dict(REPORT, cli=0, dport=0))),
        ("reactive, nothing reported yet", dict(base, raw_sport_random=True)),
        ("fixed 51820", dict(base, raw_sport=51820, sport_live=51820)),
    ]
    res = render([c[1] for c in cases])
    T = res["keys"]
    rows = dict(zip([c[0] for c in cases], res["rows"]))

    print("== 1) a moving source port is shown for BOTH ends ==")
    for name in ("reactive, both ends reporting", "rotation, both ends reporting"):
        r = rows[name]
        rep = cases[[c[0] for c in cases].index(name)][1]["rot_live"]
        check(r.get("up") == str(rep["cli"]), "%s: the client's port is on the card" % name, r)
        check(r.get("down") == str(rep["srv"]),
              "%s: and so is the SERVER's -- half the wire was invisible" % name, r)
        check("one" not in r,
              "%s: and there is no single «%s» row pretending one number covers two"
              % (name, T["port_src"]), r)

    print("\n== 2) the two modes name their own clock, and neither says «هر 0 پکت» ==")
    react = rows["reactive, both ends reporting"]["band"] or ""
    rot = rows["rotation, both ends reporting"]["band"] or ""
    check(T["port_src_rot_fail"] in react,
          "the reactive mode says «%s»" % T["port_src_rot_fail"], react)
    check(T["port_src_rot_every"].replace("{n}", "0") not in react,
          "and never «%s»" % T["port_src_rot_every"].replace("{n}", "0"), react)
    check(T["port_src_rot_every"].replace("{n}", "4") in rot,
          "the packet rotation still says «%s»" % T["port_src_rot_every"].replace("{n}", "4"), rot)
    check(T["port_src_rot_fail"] not in rot, "and does not claim to move on failures", rot)
    for name, band in (("reactive", react), ("rotation", rot)):
        check("{n}" in "".join(T[k] for k in ("port_src_rot_every", "port_src_rot_drawn"))
              and "{n}" not in band, "%s: no template placeholder reaches the screen" % name, band)
        check(str(REPORT["lo"]) in band and str(REPORT["hi"]) in band,
              "%s: the band the core measured is on the card" % name, band)

    print("\n== 3) the destination does NOT move (a host firewall filters on it) ==")
    for name in ("reactive, both ends reporting", "reactive, only the client's node answered",
                 "reactive, only the server's node answered", "reactive, nothing reported yet"):
        check(rows[name].get("dst") == "443",
              "%s: the destination is the configured 443" % name, rows[name])

    print("\n== 4) half a report still says what it knows ==")
    half = rows["reactive, only the client's node answered"]
    check(half.get("up") == "31337", "the client's port is shown when the server's node is silent", half)
    check("down" not in half, "and no zero is printed for the end that said nothing", half)
    other = rows["reactive, only the server's node answered"]
    check(other.get("down") == "52011", "and the mirror: the server alone still shows its port", other)
    check("up" not in other, "with no zero for the client", other)
    silent = rows["reactive, nothing reported yet"]
    check(silent.get("one") == T["port_src_rand"],
          "with nothing reported the row names the mode", silent)

    print("\n== 5) the fixed mode still shows exactly one port, and does not move ==")
    fix = rows["fixed 51820"]
    check("51820" in (fix.get("one") or ""), "«%s» shows its number" % T["port_src_fixed"], fix)
    check("up" not in fix and "down" not in fix,
          "and prints no moving rows -- the operator chose that number to be recognisable", fix)

    print("\n== 6) the core publishes its ports in BOTH moving modes ==")
    raw = CORE / "internal" / "packet" / "raw_linux.go"
    if not raw.exists():
        print("  SKIP cross-repo check: no core checkout at %s" % CORE)
    else:
        src = raw.read_text(encoding="utf-8")
        snap = re.search(r"func \(r \*Raw\) rotSnapshot\(\) rotStatus \{(.*?)\n\}", src, re.S)
        check(bool(snap), "rotSnapshot is still the function that fills the report")
        if snap:
            check("!r.portsMove()" in snap.group(1),
                  "it publishes whenever the ports MOVE, not only for the packet rotation",
                  snap.group(1).strip().splitlines()[0:2])
            check("rotActive()" not in snap.group(1),
                  "and does not gate on the packet rotation anywhere inside")
        check(re.search(r"func \(r \*Raw\) portsMove\(\) bool \{ return r\.rotActive\(\) \|\| r\.sportRandom \}",
                        src) is not None,
              "and «the ports move» means either mode")
        step = re.search(r"func \(r \*Raw\) portStepAt\(sent uint64\) uint64 \{(.*?)\n\}", src, re.S)
        check(bool(step) and "r.portEpoch.Load()" in step.group(1)
              and "sent/uint64(r.sportEvery)" in step.group(1),
              "the ONE place the two clocks differ is portStepAt: packets, or failovers",
              step and step.group(1).strip())

    print("\n== 7) the node forwards that report whenever a source port is in it ==")
    nodef = NODE / "tnl-node.py"
    if not nodef.exists():
        print("  SKIP cross-repo check: no node checkout at %s" % NODE)
    else:
        nsrc = nodef.read_text(encoding="utf-8")
        gate = re.search(r'if st\["rot"\]\["(\w+)"\]:\s*\n\s*rots\[nm\] = st\["rot"\]', nsrc)
        check(bool(gate), "op_list still builds the rots map the panel reads")
        if gate:
            check(gate.group(1) == "sport",
                  "it forwards on the SOURCE PORT, not on a packet budget the reactive mode never sets",
                  "gated on %r" % gate.group(1))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("both ends' source ports reach the card, and only the destination stands still.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
