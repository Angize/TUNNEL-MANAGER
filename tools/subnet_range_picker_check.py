#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the system-tunnel edit form picks a range the same way the core one does, and the
"free" number beside each range is the whole registry's, not the open page's.

Two defects, one screen.

  * The system-tunnel edit modal built its picker from a bare list and seeded it with the literal
    '192.168'. The core editor passes subnetBaseOf(l) -- the tunnel's OWN base. So opening a 10.x or a
    172.16.x overlay and changing only the TYPE renumbered it onto 192.168, because recalcEditSubnet
    then derived the address from whatever the picker was showing.
  * The "(free)" count under each range came from subnetFree(), which counted window.FLEET -- the list
    of the page you are looking at. /fleet is fetched with kind=tunnels or kind=core, so each page saw
    only half the tunnel ids, and it is fetched with the SEARCH BOX as `q`, so typing in the filter
    changed how many addresses the panel claimed were free. It is now one number per range out of
    api_summary, computed over every link.

The picker half runs the REAL browser functions out of the rendered INDEX_HTML under node. The count
half drives the real api_summary. Neither reads a helper in isolation: the first defect lived in the
argument passed at the call site, and the second in where the data came from.

    python3 tools/subnet_range_picker_check.py
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

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "  -- %r" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel(state=None, tag="a"):
    spec = importlib.util.spec_from_file_location("tnl_snr_" + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    if state:
        root = m.CENTRAL_DIR
        for k in dir(m):
            v = getattr(m, k)
            if isinstance(v, str) and v.startswith(root):
                setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
        m.CENTRAL_DIR = state
    return m


def grab(js, name):
    i = js.index("function %s(" % name)
    depth, j, started = 0, i, False
    while j < len(js):
        if js[j] == "{":
            depth += 1
            started = True
        elif js[j] == "}":
            depth -= 1
            if started and depth == 0:
                return js[i:j + 1]
        j += 1
    raise SystemExit("could not read %s out of the page" % name)


DRIVER = r"""
var OUT = {};
OUT.opens_on = [];
[['192.168', 1], ['172.16', 300], ['10', 5000]].forEach(function(p){
  var base = p[0], tid = p[1];
  var l = {id:'L', type:'gre', tunnel_id:tid, subnet:subnetForBase('gre', tid, base)};
  OUT.opens_on.push([base, tid, l.subnet, subnetBaseOf(l)]);
});
// changing the TYPE must keep the tunnel on the base it already had
OUT.type_change = [];
[['172.16', 300], ['10', 5000]].forEach(function(p){
  var base = p[0], tid = p[1];
  var was = subnetForBase('gre', tid, base);
  OUT.type_change.push([base, was, subnetForBase('vxlan', tid, subnetBaseOf({type:'gre', tunnel_id:tid, subnet:was}))]);
});
// a hand-typed subnet reports itself as custom, and deriving from 'custom' must not be attempted
OUT.custom = subnetBaseOf({type:'gre', tunnel_id:7, subnet:'192.168.77.0/24'});
console.log(JSON.stringify(OUT));
"""


def main():
    m = load_panel()
    js = m.INDEX_HTML

    print("== the picker in the system-tunnel edit modal ==")
    src = re.search(r"ssHTML\('lsr_'\+id,([^,]+),([^,]+),", js)
    check(bool(src), "the modal still builds a range picker")
    if src:
        items, seed = src.group(1).strip(), src.group(2).strip()
        check(items == "SUBNETRANGES()",
              "it uses the same item list as the core editor, so it carries the free counts", items)
        check(seed == "subnetBaseOf(l)",
              "it opens on the tunnel's OWN base, not a literal", seed)
    check("SUBNETRANGES2" not in js,
          "the countless second list is gone, so there is only one range picker to keep right")

    print("== recalcEditSubnet leaves a hand-typed subnet alone ==")
    fn = grab(js, "recalcEditSubnet")
    check("!='custom'" in fn or "!= 'custom'" in fn,
          "it refuses to derive an address when the picker says custom",
          "subnetForBase('custom') falls back to 192.168 and would silently renumber the tunnel")

    print("== the browser functions themselves ==")
    prelude = "function num(x){x=+x;return isFinite(x)?x:0}\n"
    body = prelude + re.search(r"var SUBNET_BASE_NETS=.+?;", js, re.S).group(0) + "\n"
    for n in ("subnetCap", "subnetForBase", "subnetBaseOf"):
        body += grab(js, n) + "\n"
    body += DRIVER
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(body)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print("FAIL: node could not run the page's own functions:\n" + (out.stderr or "")[:1500])
        return 1
    got = json.loads(out.stdout.strip().splitlines()[-1])

    for base, tid, subnet, back in got["opens_on"]:
        check(back == base, "a %-7s tunnel (id %d, %s) opens on its own base" % (base, tid, subnet), back)
    for base, was, now in got["type_change"]:
        check(now == was, "changing the type keeps a %-7s tunnel where it was" % base, (was, now))
    check(got["custom"] == "custom", "a hand-typed subnet is reported as custom", got["custom"])

    print("== the free count is the registry's, not the open page's ==")
    check("window.FLEET" not in grab(js, "subnetFree"),
          "subnetFree no longer counts the list the page happens to hold")
    with tempfile.TemporaryDirectory() as state:
        p = load_panel(state, "b")
        caps = {b: p.subnet_cap(b) for b in p.SUBNET_BASES}
        links = [{"tunnel_id": t} for t in (1, 2, 3, 300, 70000)]
        free = p.subnet_free_counts(links)
        for b, cap in caps.items():
            want = cap - sum(1 for t in (1, 2, 3, 300, 70000) if 1 <= t <= cap)
            check(free.get(b) == want, "%-7s: %d free of %d" % (b, want, cap), free.get(b))
        check(p.subnet_free_counts([]) == caps, "an empty registry leaves every range whole", p.subnet_free_counts([]))
        core_and_sys = [{"tunnel_id": 1, "type": "core"}, {"tunnel_id": 2, "type": "gre"}]
        both = p.subnet_free_counts(core_and_sys)
        check(all(both[b] == caps[b] - 2 for b in caps),
              "a core tunnel and a system tunnel are BOTH counted -- the page split is what made this wrong",
              both)
    check('"subnet_free": subnet_free_counts(links)' in PANEL.read_text(encoding="utf-8"),
          "api_summary carries the counts to the browser")

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
