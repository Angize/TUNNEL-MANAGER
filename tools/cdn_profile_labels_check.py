#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The CDN-profile tiles must advertise the numbers the profile actually sends.

Each profile in the picker shows a one-line summary — «۸ کارگر × ۲۵۶KB» — and that line is the ONLY
place an operator learns what the choice does. It is hand-written Persian in I18N, sitting ~5,700
lines away from CDN_PROFILES, which is the dict that decides the bytes.

They drifted inside one batch: panel #293 wrote «۸ کارگر × ۱۲۸KB (پیش‌فرض)» when "cf" really was the
core's default, and panel #295 then changed CDN_PROFILES["cf"] to 8×256 KB without touching the
string. The tile went on advertising the exact setting #295's own measurement table calls "the old
default … worst upstream by a wide margin" — so the picker recommended, by its numbers, the thing the
change was made to get away from. Nothing could catch that: no test reads Persian UI strings, and the
config-contract guard checks what reaches the node, not what the operator was told.

This reads the two numbers back out of each tile and compares them with the profile dict. Run it with
no arguments; it is wired into CI beside the other guards.

    python3 tools/cdn_profile_labels_check.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

# Persian-Indic digits, which is what the UI is written in (CLAUDE.md §2: the panel is Persian-only).
FA_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹", "0123456789")

# The core's own defaults, for a profile that deliberately carries no override. Kept here rather than
# read from tuning.go because these two are top-level config.go defaults, not tuning knobs, and
# tuning_consistency.py already owns the knob roster.
CORE_DEFAULT_WORKERS, CORE_DEFAULT_BATCH_KB = 8, 128


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tile_numbers(src, key):
    """Pull (workers, batch_kb) out of a tile's summary string, e.g. «۸ کارگر × ۲۵۶KB (پیش‌فرض)»."""
    m = re.search(r'%s:"([^"]*)"' % re.escape(key), src)
    if not m:
        return None, "no such I18N key"
    text = m.group(1).translate(FA_DIGITS)
    n = re.search(r"(\d+)\s*کارگر", text)
    kb = re.search(r"(\d+)\s*KB", text, re.IGNORECASE)
    if not n or not kb:
        return None, "the summary does not state «N کارگر» and «N KB»: %r" % m.group(1)
    return (int(n.group(1)), int(kb.group(1))), m.group(1)


def main():
    P = load_panel()
    src = open(PANEL, encoding="utf-8").read()
    failures = []
    profiles = getattr(P, "CDN_PROFILES", None)
    if not profiles:
        print("CDN_PROFILES is missing or empty — nothing to check")
        return 1

    for name, prof in sorted(profiles.items()):
        key = "cdnp_%s_m" % name
        got, shown = tile_numbers(src, key)
        if got is None:
            failures.append("[%s] %s: %s" % (name, key, shown))
            continue
        want = (int(prof.get("http_up_workers") or CORE_DEFAULT_WORKERS),
                int(prof.get("http_up_batch_kb") or CORE_DEFAULT_BATCH_KB))
        if got != want:
            failures.append(
                "[%s] the tile says %d workers x %d KB, the profile sends %d x %d\n"
                "      tile:    %s\n"
                "      profile: %r" % (name, got[0], got[1], want[0], want[1], shown, prof))
            continue
        print("  ok  %-8s tile says %d x %d KB, and that is what it sends" % (name, got[0], got[1]))

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nall %d CDN profile tiles advertise what they send" % len(profiles))
    return 0


if __name__ == "__main__":
    sys.exit(main())
