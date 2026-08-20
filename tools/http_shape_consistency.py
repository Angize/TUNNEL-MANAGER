#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The http-carrier shape has one range, written in four places.

  * panel  tnl-central.py   HTTP_SHAPE          -- what the API validates and stores
  * panel  tnl-central.py   CDN_SHAPE (browser) -- the min/max/value the form offers
  * node   tnl-node.py      _up_max             -- what the node lets through
  * core   config.go                            -- what the core accepts; it REJECTS, never clamps

A form that offers more than the API accepts is an error the operator meets only on submit; a panel
that stores more than the node forwards is a setting that vanishes in silence; and either of those
past the core's ceiling is a tunnel that will not start on either end.

    python3 tools/http_shape_consistency.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MMD = os.path.dirname(os.path.dirname(HERE))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")
NODE = os.path.join(MMD, "TUNNEL-MANAGER-NODE", "tnl-node.py")
CORE = os.path.join(MMD, "TUNNEL-MANAGER-CORE", "config.go")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def panel_shape(src):
    m = re.search(r"HTTP_SHAPE = \{(.*?)\}\n", src, re.S)
    if not m:
        sys.exit("HTTP_SHAPE not found in the panel")
    out = {}
    for k, lo, hi, d in re.findall(r'"([a-z_]+)": \((\d+), (\d+), (\d+)\)', m.group(1)):
        out[k] = (int(lo), int(hi), int(d))
    return out


def browser_shape(src):
    m = re.search(r"var CDN_SHAPE=\{(.*?)\};", src)
    if not m:
        sys.exit("CDN_SHAPE not found in the panel's browser code")
    out = {}
    for k, lo, hi, d in re.findall(r"k:'([a-z_]+)',lo:(\d+),hi:(\d+),d:(\d+)", m.group(1)):
        out[k] = (int(lo), int(hi), int(d))
    return out


def node_max(src):
    m = re.search(r"_up_max = \{(.*?)\}", src, re.S)
    if not m:
        sys.exit("_up_max not found in the node")
    return {k: int(v) for k, v in re.findall(r'"([a-z_]+)": (\d+)', m.group(1))}


def core_max(src):
    """The ceiling the core states in its own rejection message."""
    out = {}
    for k in ("http_up_workers", "http_streams"):
        m = re.search(k + r" must be between 1 and (\d+)", src)
        if m:
            out[k] = int(m.group(1))
    m = re.search(r"http_up_batch_kb must be between 0 and (\d+)", src)
    if m:
        out["http_up_batch_kb"] = int(m.group(1))
    return out


def main():
    panel = open(PANEL, encoding="utf-8").read()
    p, b = panel_shape(panel), browser_shape(panel)
    n = node_max(open(NODE, encoding="utf-8").read())
    c = core_max(open(CORE, encoding="utf-8").read()) if os.path.exists(CORE) else {}

    print("== http carrier shape ==")
    fails = []
    if not p:
        fails.append("HTTP_SHAPE parsed empty")
    if set(p) != set(b):
        fails.append("the API knows %s, the form offers %s" % (sorted(p), sorted(b)))
    for k in sorted(p):
        if k in b and p[k] != b[k]:
            fails.append("%s: the API takes %s, the form offers %s" % (k, p[k], b[k]))
        if k not in n:
            fails.append("%s: the node does not forward it, so it is dropped in silence" % k)
        elif p[k][1] > n[k]:
            fails.append("%s: the panel allows %d, the node caps at %d" % (k, p[k][1], n[k]))
        elif c and k in c and p[k][1] > c[k]:
            fails.append("%s: the panel allows %d, the core refuses above %d" % (k, p[k][1], c[k]))
        else:
            print("  ok  %-18s %d..%d (default %d), node %d, core %s"
                  % (k, p[k][0], p[k][1], p[k][2], n[k], c.get(k, "?")))
    if not c:
        print("  --  core config.go not readable from here; its ceiling was not checked")
    if fails:
        print()
        for f in fails:
            print(" FAIL " + f)
        return 1
    print()
    print("the shape has the same range in the form, the API and the node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
