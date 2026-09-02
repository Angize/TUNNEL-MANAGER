#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The card must show the source port on every carrier that redraws it, not only on raw.

The node already publishes the live source port for every tunnel -- op_list reads path.sport out of the
core's status file and sends it as sport_live, whatever the carrier is. portRows threw it away for
everything but raw, so on udp, tcp, and the CDN carriers the operator could not see which port the
tunnel was actually on. That did not matter while raw was the only carrier that could redraw its source
port. It does now that udp has a port rung of its own: the ladder moves the port under the
operator's feet and the card said nothing about it.

This drives the real portRows out of the rendered page under node, so it is the function the browser
runs, not a copy of it.

    python3 tools/the_card_shows_the_live_source_port_check.py
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

CASES = [
    ({"transport": "udp", "port": 20050, "sport_live": 41027}, ["20050", "41027"], []),
    ({"transport": "udp", "port": 20050}, ["20050"], ["port_src"]),
    ({"transport": "tcp", "port": 20050, "sport_live": 33111}, ["20050", "33111"], []),
    ({"transport": "ws", "port": 443, "sport_live": 35550}, ["443", "35550"], []),
    ({"transport": "dns", "port": 20050, "sport_live": 41027}, [], ["41027", "20050"]),
    ({"transport": "spoof", "sport_live": 41027}, [], ["41027"]),
    ({"transport": "raw", "raw_profile": "tcp", "raw_port": 443, "raw_sport_random": True,
      "sport_live": 8443}, ["443", "8443"], []),
    ({"transport": "raw", "raw_profile": "bare", "sport_live": 8443}, [], ["8443"]),
]


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
    raise SystemExit("unbalanced %s" % name)


def main():
    P = load_panel()
    js = P.INDEX_HTML
    consts = re.search(r"var PORT_RUNG_TRANSPORTS=\[.+?\];", js).group(0)
    src = "\n".join([consts] + [grab(js, n) for n in ("portRows", "portTriesOn", "num", "esc")])
    src += "\nvar RAW_SPORT_FIX=51820, RAW_DPORT_DEF=443;\nfunction T(k){return k}\n"
    src += "var CASES=%s;\n" % json.dumps([c[0] for c in CASES])
    src += "console.log(JSON.stringify(CASES.map(function(l){return portRows(l)})));\n"

    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(src)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print("FAIL: node could not run portRows:\n" + out.stderr)
        return 1
    rendered = json.loads(out.stdout.strip().splitlines()[-1])

    fails = []
    for (link, want, unwanted), html in zip(CASES, rendered):
        tag = link["transport"] + ("/" + link["raw_profile"] if link.get("raw_profile") else "")
        ok = all(w in html for w in want) and not any(u in html for u in unwanted)
        print(("  ok   " if ok else " FAIL ") + "%-9s -> %s" % (tag, html or "(nothing)"))
        if not ok:
            fails.append("%s rendered %r; wanted %s and not %s" % (tag, html, want, unwanted))

    print()
    if fails:
        print("FAILURES:")
        for f in fails:
            print("  - " + f)
        return 1
    print("the card names the live source port on every carrier that can redraw it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
