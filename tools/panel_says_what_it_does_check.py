#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A toast must not claim something the code does not do, and a per-row button must act on ITS row.

Neither «الان تست کن» sends a probe. The core only pulls that entry's nextRetest forward; nothing dials
until the next rotation, and the tun probe is the only thing that judges an endpoint. And the button is
rendered beside ONE burned entry, so it must name that entry -- a call carrying only the link id zeroed
every wait in the pool while looking like it touched one row.

    python3 tools/panel_says_what_it_does_check.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

# Failure messages quote Persian, and this is run on a cp1252 console — without this the guard raises
# UnicodeEncodeError while PRINTING the failure it correctly found.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

fails = []


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    P = load_panel()
    js = getattr(P, "INDEX_HTML", "")
    if "<script" not in js:
        fails.append("INDEX_HTML did not decode to anything with a <script> in it — this check cannot "
                     "read its subject, so it must not report success")
        return report()

    for name, fn, endpoint in (("direct", "peerProbeNow", "peer-retest-now"),
                               ("ws edge", "poolProbeNow", "pool-retest-now")):
        m = re.search(r"async function " + fn + r"\((?P<args>[^)]*)\)\{.*?\n(?=[/a-zA-Z])", js, re.S)
        if not m:
            fails.append("the %s pool's probe button was not found in the decoded JS (it moved, and this "
                         "check went blind)" % name)
            continue
        body = m.group(0)

        claim = re.search(r"toast\(T\('([a-z_]+)'\),'ok'\)", body)
        if not claim:
            fails.append("the %s pool's probe button no longer toasts anything on success — the operator "
                         "presses it and is told nothing" % name)
        elif claim.group(1) != "peer_probe_pulled":
            fails.append("the %s pool's probe button toasts %r. Nothing dials: the core only pulls that "
                         "entry's nextRetest forward, and no pool has a prober behind it. The one true "
                         "thing to say is peer_probe_pulled — the wait was zeroed, and the tun probe "
                         "judges it on the next rotation." % (name, claim.group(1)))
        else:
            print("  ok  the %s pool's probe button claims only that the wait was zeroed" % name)

        # The button sits beside ONE burned row, so it must send that row's axis and key. Without them
        # it can only ask for the whole pool while looking like it touched one entry.
        args = [a.strip() for a in m.group("args").split(",") if a.strip()]
        if "key" not in args:
            fails.append("the %s pool's probe button takes %r — with no key it can only ask for the "
                         "whole pool, while sitting next to one row" % (name, args))
        elif not re.search(r"post\('" + endpoint + r"',\{[^}]*kind:[^}]*key:", body):
            fails.append("the %s pool's probe button does not forward kind+key to %s" % (name, endpoint))
        else:
            print("  ok  the %s pool's probe button asks for its own row only" % name)

        for call in re.findall(r'onclick="' + fn + r'\(([^"]*)\)"', js):
            if "kind" not in call and "side" not in call:
                fails.append("a %s row renders %s(%s) — it does not pass the row's own axis"
                             % (name, fn, call))

    if "pool_probe_sent" in js:
        fails.append("the string pool_probe_sent («پروبِ فوری فرستاده شد») is still in the panel. No pool "
                     "sends a probe of its own any more, and a dead string is how the claim comes back")
    else:
        print("  ok  the retired «پروبِ فوری فرستاده شد» string is gone from the panel")

    return report()


def report():
    if fails:
        print("\nFAILURES (%d):" % len(fails))
        for f in fails:
            print("  - %s" % f)
        return 1
    print("\nthe panel's toasts agree with what the code does, and each button acts on its own row")
    return 0


if __name__ == "__main__":
    sys.exit(main())
