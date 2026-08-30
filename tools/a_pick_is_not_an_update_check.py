#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the amber "آپدیت دارد" mark on a node means that node is BEHIND, and nothing else.

The version box above the fleet is global, so choosing a version there -- to install it on one node --
used to relabel every other node as having an update waiting. The operator picks v2.89.0 for a single
box and the whole grid turns amber and offers to "update" thirty nodes that are already on v2.90.0.
The same wrong label appeared a second way: once the older pick was staged, every node differed from
what the panel held, so a downgrade advertised itself as an update.

This drives the REAL agRow out of the decoded INDEX_HTML across the matrix that separates the two
meanings -- behind vs merely different -- and asserts three things about each cell: the badge class,
whether the button is painted as an update, and whether it can be pressed at all. A node that differs
from the pick must stay pressable; that is the point of picking.

Exit 1 on any failure.
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from list_diff_keeps_untouched_rows_check import PRELUDE

PANEL = HERE.parent / "tnl-central.py"

HARNESS = r"""
const CASES = [
  ['nothing picked, node matches what is staged', '',        'v2.90.0', 'aaaaaaaaaaaa', 'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['an OLDER version picked for another node',    'v2.89.0', 'v2.90.0', 'aaaaaaaaaaaa', 'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['the same version picked',                     'v2.90.0', 'v2.90.0', 'aaaaaaaaaaaa', 'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['a NEWER version picked',                      'v2.91.0', 'v2.90.0', 'aaaaaaaaaaaa', 'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['the node really is behind',                   '',        'v2.88.0', 'dddddddddddd', 'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['really behind, and picked too',               'v2.90.0', 'v2.88.0', 'dddddddddddd', 'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['the staged version was rolled back',          '',        'v2.90.0', 'aaaaaaaaaaaa', 'v2.89.0', 'bbbbbbbbbbbbbbbb', true],
  ['staged is an uploaded binary',                'custom',  'v2.90.0', 'aaaaaaaaaaaa', 'custom',  'cccccccccccccccc', true],
  ['no core on the node at all',                  'v2.89.0', '',        '',             'v2.90.0', 'aaaaaaaaaaaaaaaa', true],
  ['offline, with a version picked',              'v2.89.0', 'v2.90.0', 'aaaaaaaaaaaa', 'v2.90.0', 'aaaaaaaaaaaaaaaa', false]
];

function read(html){
  const vps = [...html.matchAll(/<span class="vp ([a-z]+)" title="([^"]*)">/g)];
  const btns = [...html.matchAll(/<button class="ib([^"]*)"( disabled)?/g)];
  if (vps.length !== 2 || btns.length !== 2) throw new Error('agRow shape changed: ' + vps.length + '/' + btns.length);
  return {badge: vps[1][1], tip: vps[1][2],
          amber: btns[1][1].indexOf('up') >= 0, pressable: !btns[1][2]};
}

AGMETA = {none: true};
const out = [];
for (const [name, pick, cver, csha, sver, ssha, online] of CASES) {
  SEL.corver = pick;
  STAGED = {version: sver, arches: ['amd64'], sha: {amd64: ssha}};
  const r = read(agRow({id: 'x', name: 'IR01', host: '1.2.3.4', online: online,
    info: {version: 1, arch: 'amd64', core_ver: cver, core_sha: csha}}));
  out.push({name, ...r});
}
console.log('@@' + JSON.stringify(out));
"""


def decoded():
    spec = importlib.util.spec_from_file_location("tnl_central_pick", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.INDEX_HTML


def main():
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", decoded(), re.S)
    if not blocks:
        sys.exit("pick-guard: no <script> block in the decoded page")
    script = max(blocks, key=len)
    for need in ("function agRow(", "function ssVal("):
        if need not in script:
            sys.exit("pick-guard: the page has no %s" % need)

    with tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False, encoding="utf-8") as f:
        f.write(PRELUDE + "\n" + script + "\n" + HARNESS)
        path = f.name
    r = subprocess.run(["node", path], capture_output=True, text=True, timeout=120,
                       encoding="utf-8", errors="replace")
    line = [l for l in r.stdout.splitlines() if l.startswith("@@")]
    if r.returncode != 0 or not line:
        print(r.stdout[-2000:])
        print(r.stderr[-2000:])
        sys.exit("pick-guard: the page did not run")
    got = {c["name"]: c for c in json.loads(line[-1][2:])}

    fails = []

    def ok(cond, good, bad):
        print(("  ok   " if cond else " FAIL  ") + (good if cond else bad))
        if not cond:
            fails.append(bad)

    def cell(name, amber, pressable, badge):
        c = got[name]
        got_s = "badge=%s amber=%s pressable=%s" % (c["badge"], c["amber"], c["pressable"])
        want_s = "badge=%s amber=%s pressable=%s" % (badge, amber, pressable)
        ok(c["amber"] == amber and c["pressable"] == pressable and c["badge"] == badge,
           "%s -> %s" % (name, got_s), "%s -> %s, wanted %s" % (name, got_s, want_s))

    print("== amber means behind; a pick only means pressable ==")
    cell('nothing picked, node matches what is staged', False, False, 'ok')
    cell('an OLDER version picked for another node', False, True, 'ok')
    cell('the same version picked', False, False, 'ok')
    cell('a NEWER version picked', False, True, 'ok')
    cell('the node really is behind', True, True, 'up')
    cell('really behind, and picked too', True, True, 'up')
    cell('the staged version was rolled back', False, True, 'ok')
    cell('staged is an uploaded binary', True, True, 'up')
    cell('no core on the node at all', True, True, 'na')
    cell('offline, with a version picked', False, False, 'offl')

    ok('v2.89.0' in got['an OLDER version picked for another node']['tip'],
       "and the tooltip names the version it would install, not 'آپدیت دارد'",
       "the tooltip does not name the picked version: %r"
       % got['an OLDER version picked for another node']['tip'])
    ok('آپدیت' in got['the node really is behind']['tip'],
       "a node that is genuinely behind still says so",
       "a behind node lost its update wording: %r" % got['the node really is behind']['tip'])
    lit = [c["name"] for c in got.values() if c["amber"]]
    ok(len(lit) == 4,
       "exactly the four cells that are really behind or bare light up",
       "%d cells lit up: %r" % (len(lit), lit))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("picking a version offers it; only being behind advertises it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
