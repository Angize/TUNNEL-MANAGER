#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A toast must not claim something the code does not do.

The DIRECT (udp/tcp/raw/flux) pool's «الان تست کن» sends no probe: core's probeAllNow only pulls
nextRetest forward, and there is no retestLoop behind those pools, so nothing dials until the next
rotation or failover. Its ws-EDGE twin DOES dial, so the same claim is true there — which is why this
checks both, and cannot be satisfied by deleting the string from one of them.

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

    m = re.search(r"async function peerProbeNow\(\)\{.*?\n(?=[/a-zA-Z])", js, re.S)
    if not m:
        fails.append("peerProbeNow was not found in the decoded JS (or it moved and this check went blind)")
    else:
        body = m.group(0)
        if "pool_probe_sent" in body:
            fails.append("the DIRECT pool's probe button toasts pool_probe_sent («پروبِ فوری فرستاده "
                         "شد»), but nothing dials: core's probeAllNow only pulls nextRetest forward and "
                         "there is no retestLoop behind these pools. peer_live_note right above it "
                         "already tells the operator «خودش تستی نمی‌فرستد».")
        else:
            print("  ok  the direct pool's probe button does not claim to have sent a probe")

    # ...and the ws EDGE twin must KEEP it, so this cannot be satisfied by deleting the string.
    if "async function poolProbeNow(" in js:
        pm = re.search(r"async function poolProbeNow\(lid\)\{.*?\n(?=[/a-zA-Z])", js, re.S)
        if pm and "pool_probe_sent" not in pm.group(0):
            fails.append("the ws EDGE pool's probe button no longer claims a probe was sent — there it "
                         "IS true (retestLoop dials the due entries), and saying less than the truth is "
                         "its own kind of wrong")
        else:
            print("  ok  the ws edge pool's button still says what is true for it")
    else:
        fails.append("poolProbeNow was not found — the positive half of this check went blind")

    return report()


def report():
    if fails:
        print("\nFAILURES (%d):" % len(fails))
        for f in fails:
            print("  - %s" % f)
        return 1
    print("\nthe panel's toasts agree with what the code does")
    return 0


if __name__ == "__main__":
    sys.exit(main())
