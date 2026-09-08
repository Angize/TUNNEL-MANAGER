#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every change the operator did NOT make must reach the log, exactly once, and only when it is true.

The core writes one ring; the panel turns it into the operator's log. Three rules that had drifted:

  * an edge-pool rotation was never reported at all. The panel could only infer it from `active`
    changing between polls -- fifteen seconds apart and silent when the rotation did not land. The
    core reports it now, so the inference must stand down or the same rotation is logged twice.
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


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
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
    # One *TCP now serves tcp, ws, http and grpc off the same two PeerPools, so it does not pass a
    # literal: axes() returns the tag and the detail prefix for each axis, and the four names live in
    # that one table. Read them, resolving the axis constants -- otherwise the edge and sni axes vanish
    # from this set and the checks below go green because they found nothing to check.
    consts = dict(re.findall(r'\n\taxis(\w+)\s*=\s*"(\w+)"', blob))
    table = re.search(r'func \(b \*TCP\) axes\(\) \(low, high axisNames\) \{(.*?)\n\}', blob, re.S)
    check(bool(table), "the carrier still names its axes in one place")
    if table:
        for lit, const in re.findall(r'axisNames\{(?:"([a-z]+)"|axis(\w+)),', table.group(1)):
            if lit:
                axes.add(lit)
            elif const in consts:
                axes.add(consts[const])
    check(axes, "the core routes its rotations through one place (axes found: %s)" % sorted(axes))
    for a in sorted(axes):
        code = a + "-rotate"
        sched, forced = P._ev_rot("rot", code), P._ev_rot("down", code)
        check(bool(sched) and bool(forced),
              "%s is rendered as an informational step, not a red «disconnected»" % code,
              (sched, forced))
        if not (sched and forced):
            continue
        # Rendering both is not enough: they have to be DIFFERENT. A scheduled rotation is the clock
        # coming due on a healthy tunnel; a forced one is the ladder walking off an endpoint that
        # stopped carrying. One colour and one sentence for both is what the operator had before, and
        # that is indistinguishable from having no signal at all.
        check(sched[0] == "ok" and forced[0] == "warn",
              "%s: the scheduled rotation is informational and the forced one is a warning" % code,
              (sched[0], forced[0]))
        check(sched[1] != forced[1],
              "%s: and the two say different things, not just different colours" % code, sched[1])

    # The other half of the pair, read out of the core: the panel can only tell them apart if the core
    # publishes them apart. It used to send the identical event for both and keep the difference to
    # itself in wasDown, which is why this reads the core source rather than a constant.
    cs = src.get("core_status.go", "")
    check(re.search(r'func \(s \*coreStatus\) rotated\([^)]*\)\s*\{\s*if proactive \{\s*s\.event\("rot",', cs),
          "the core publishes a scheduled rotation under its own kind rather than as the tunnel "
          "going down")
    check(re.search(r'if proactive \{.*?\n\t\}\n\ts\.down\(axis\+"-rotate"', cs, re.S),
          "and a forced one still goes through down(), which is what arms the recovery line")

    print("\n== 2) the edge pool reports its own rotation ==")
    # BOTH of its axes. They are two PeerPools now and each is walked by a different arm, so an edge
    # step and a domain step are two different lines in the operator's log. A tag helper that quietly
    # collapses the domain onto the source axis would leave every SNI rotation invisible.
    check({"edge", "sni"} <= axes,
          "both edge axes report themselves: found %s" % sorted(axes))
    check("edge" in axes,
          "the edge pool calls the same reporter the direct carriers do — inferring it from `active` "
          "changing between polls is 15 s late and silent when the rotation does not land")

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
    # The detail used to be one expression and this read it whole, leading space and all:
    # '" tries:"'. CORE #481 builds it in two steps -- `detail := "tries:"…` then `detail = "sport:"…
    # + " " + detail` -- so the runtime string is byte-identical and the old literal is gone. Ask for
    # the two things the line has to NAME, not for the shape of the expression that concatenates them.
    check('"port-roll",' in cs and '"sport:"' in cs and '"tries:"' in cs,
          "and the line names the port it recovered on AND how many draws it cost",
          [k for k in ('"port-roll",', '"sport:"', '"tries:"') if k not in cs])
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
