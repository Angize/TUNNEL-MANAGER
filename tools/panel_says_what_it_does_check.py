#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The panel must not state, in prose or in a toast, something the code contradicts.

Two claims from the 2026-07-31 review, both of the same shape: a sentence that was true when it was
written, kept next to code that stopped making it true, with nothing in the toolchain able to notice.

  1. the CDN_PROFILES header said «"cf" carries the core's own defaults, so it emits NOTHING and a
     Cloudflare tunnel is byte-identical to before this existed» — written when "cf" really was an
     empty entry. panel #295 then measured 8x256 and filled it in, one screen below the sentence.
     Both halves went false at once: the core's default is 8x128, and every http-carrier client body
     now leaves the panel with two extra knobs on it.

  2. the DIRECT pool's «الان تست کن» toasted «پروبِ فوری فرستاده شد». It does not send one. core's
     probeAllNow just sets nextRetest = now, and there is no retestLoop behind the direct pools —
     tcp.go starts one only for the ws EDGE pool — so nothing dials until the next rotation or
     failover. The help text two lines above the button (peer_live_note, fixed in #299) already said
     «خودش تستی نمی‌فرستد», so the panel was contradicting itself inside one box.

Neither is catchable by the other guards: config_contract checks what reaches the node, the label
guard checks the tiles, and no test reads Persian prose. This one does.

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

# Phrases that assert a profile changes nothing. If any profile carries knobs, they are false.
EMITS_NOTHING = ("emits NOTHING", "byte-identical to before this existed")

fails = []


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    P = load_panel()
    src = open(PANEL, encoding="utf-8").read()

    # --- 1) the prose above CDN_PROFILES vs the dict itself -------------------------------------
    profiles = getattr(P, "CDN_PROFILES", None)
    if not profiles:
        fails.append("CDN_PROFILES is missing or empty — this check cannot read its subject")
    else:
        head = src[: src.index("CDN_PROFILES = {")]
        head = head[head.rfind("\n\n") :]  # the comment block immediately above the dict
        carrying = sorted(n for n, prof in profiles.items() if prof)
        for phrase in EMITS_NOTHING:
            if phrase in head and carrying:
                fails.append(
                    "the comment above CDN_PROFILES still says %r, but %s carr%s real knobs now — a "
                    "tunnel built on %s is NOT byte-identical to one built before the profiles existed"
                    % (phrase, ", ".join(carrying), "ies" if len(carrying) == 1 else "y",
                       "it" if len(carrying) == 1 else "them"))
        if not fails:
            print("  ok  the CDN_PROFILES prose does not claim a profile that carries knobs is inert")

    # --- 2) the DIRECT pool's probe button must not claim a probe was sent -----------------------
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
    print("\nthe panel's prose and its toasts agree with what the code does")
    return 0


if __name__ == "__main__":
    sys.exit(main())
