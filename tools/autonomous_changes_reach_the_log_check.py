#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every change the operator did NOT make must reach the log, exactly once, and only when it is true.

The core writes one ring; the panel turns it into the operator's log. Three rules that had drifted:

  * an edge-pool rotation was never reported at all. The panel could only infer it from `active`
    changing between polls -- fifteen seconds apart, silent when the rotation did not land, and muted
    for a while after an operator pin. The core reports it now, so the inference must stand down or the
    same rotation is logged twice.
  * a source-port redraw was written at the DRAW. The ladder redraws every few seconds for as long as
    an outage lasts, so a tunnel that never came back wrote a line per draw. It is written on the
    RECOVERY now, naming the port that worked -- so the panel's text may no longer say «before
    condemning any address», which described the moment it was written at, not what it means.
  * every rotation code the core can emit must be one the panel knows, or it renders as a red
    «disconnected» -- an autonomous, harmless step reported as a fault.

    python3 tools/autonomous_changes_reach_the_log_check.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PANEL = os.path.join(ROOT, "tnl-central.py")
CORE = os.path.join(os.path.dirname(ROOT), "TUNNEL-MANAGER-CORE", "internal", "packet")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def core_src():
    out = {}
    if not os.path.isdir(CORE):
        return out
    for f in sorted(os.listdir(CORE)):
        if f.endswith(".go") and not f.endswith("_test.go"):
            with open(os.path.join(CORE, f), encoding="utf-8") as fh:
                out[f] = fh.read()
    return out


def main():
    P = load()
    src = core_src()
    if not src:
        fails.append("the core tree is not beside this one, so the pairing cannot be checked at all")
        return report()
    blob = "\n".join(src.values())

    print("== 1) every rotation the core reports is a code the panel knows ==")
    # st.rotated(axis, ...) emits "<axis>-rotate". Collect the axes the core actually passes.
    axes = set(re.findall(r'\.rotated\(\s*"([a-z]+)"', blob))
    check(axes, "the core routes its rotations through one place (axes found: %s)" % sorted(axes))
    for a in sorted(axes):
        code = a + "-rotate"
        check(code in P._EV_ROT_CODE,
              "%s is rendered as an informational step, not a red «disconnected»" % code)

    print("\n== 2) the edge pool reports its own rotation ==")
    check("edge" in axes,
          "the edge pool calls the same reporter the direct carriers do — inferring it from `active` "
          "changing between polls is 15 s late, silent when the rotation does not land, and muted "
          "after an operator pin")

    print("\n== 3) and the panel's inference stands down when the ring already said it ==")
    js = getattr(P, "INDEX_HTML", "")
    py = open(PANEL, encoding="utf-8").read()
    check(re.search(r"rotated\s*=\s*set\(\)", py) and re.search(r"if lid in rotated", py),
          "the poll-diff defers to the event, or one rotation is logged twice")

    print("\n== 4) the port line is written on the recovery, not on the draw ==")
    check(not re.search(r'event\("down",\s*"port-roll"', blob.replace("core_status.go", "")) or
          'port-roll' not in "".join(v for k, v in src.items() if k != "core_status.go"),
          "no carrier writes a port line of its own; only the one place that knows whether it worked")
    cs = src.get("core_status.go", "")
    check("rollTries" in cs and re.search(r'func \(s \*coreStatus\) portRedrawn\(\)', cs),
          "the draw is COUNTED rather than written")
    check('"port-roll",' in cs and '"sport:"' in cs and '" tries:"' in cs,
          "and the line names the port it recovered on AND how many draws it cost")
    lvl, fa = P._EV_ROT_CODE.get("port-roll", ("", ""))
    check(lvl == "ok" and "برگشت" in fa,
          "the panel's text says the redraw WORKED (%r/%r) — it used to describe the moment it was "
          "written at, which is no longer when it is written" % (lvl, fa))

    return report()


def report():
    if fails:
        print("\nFAILURES (%d):" % len(fails))
        for f in fails:
            print("  - %s" % f)
        return 1
    print("\nevery autonomous change reaches the log once, and only when it is true.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
