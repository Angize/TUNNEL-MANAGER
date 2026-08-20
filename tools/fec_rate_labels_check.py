#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The FEC rate tiles must advertise the overhead they really produce.

Each tile shows a one-line Persian summary and that line is the ONLY place an operator learns what
the choice does, while FEC_RATES decides the shards. No other guard can catch a drift between them:
none of them reads a Persian UI string.

«N٪ سربار» must be p/d, which is the overhead of a SATURATED block. A partial block always carries at
least one parity shard, so its instantaneous overhead is higher — the arithmetic floor of keeping a
block protected — and fec_note has to say so.

    python3 tools/fec_rate_labels_check.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

# Every failure message here quotes a Persian UI string, and the maintainer runs these on a Windows
# console whose default encoding is cp1252 — which cannot encode Persian digits at all. So the guard
# would raise UnicodeEncodeError while PRINTING the failure it had correctly detected: it fires, and
# then tells you nothing. Found by actually running a deliberately-broken tree, not by reading.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Persian-Indic digits, which is what the UI is written in (CLAUDE.md §2: the panel is Persian-only).
FA_DIGITS = str.maketrans("0123456789", "0123456789")

def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tile_numbers(src, key):
    """Pull (workers, batch_kb) out of a tile's summary string, e.g. «8 کارگر × 256KB (پیش‌فرض)»."""
    m = re.search(r'%s:"([^"]*)"' % re.escape(key), src)
    if not m:
        return None, "no such I18N key"
    text = m.group(1).translate(FA_DIGITS)
    n = re.search(r"(\d+)\s*کارگر", text)
    kb = re.search(r"(\d+)\s*KB", text, re.IGNORECASE)
    if not n or not kb:
        return None, "the summary does not state «N کارگر» and «N KB»: %r" % m.group(1)
    return (int(n.group(1)), int(kb.group(1))), m.group(1)


def pct_of(src, key):
    """Pull the percentage out of an overhead label, e.g. «30٪ سربار» -> 30."""
    m = re.search(r'%s:"([^"]*)"' % re.escape(key), src)
    if not m:
        return None, "no such I18N key"
    text = m.group(1).translate(FA_DIGITS)
    n = re.search(r"(\d+)\s*٪", text)
    if not n:
        return None, "the label does not state «N٪»: %r" % m.group(1)
    return int(n.group(1)), m.group(1)


def main():
    P = load_panel()
    src = open(PANEL, encoding="utf-8").read()
    failures = []
    # --- FEC rate tiles: the «N٪ سربار» label must be p/d, and fec_note must carry the caveat.
    rates = re.search(r"function FEC_RATES\(\)\{return \[(.*?)\]\}", src, re.S)
    if not rates:
        failures.append("FEC_RATES was not found — this check cannot read its subject, so it must not "
                        "report success")
    else:
        tiles = re.findall(r"\{d:(\d+),p:(\d+),n:T\('[^']+'\),ov:T\('([^']+)'\)\}", rates.group(1))
        if not tiles:
            failures.append("FEC_RATES matched but no {d,p,ov} tiles parsed out of it")
        for d, p, ov_key in tiles:
            d, p = int(d), int(p)
            got, shown = pct_of(src, ov_key)
            want = round(p * 100.0 / d)
            if got is None:
                failures.append("[fec %d+%d] %s: %s" % (d, p, ov_key, shown))
            elif got != want:
                failures.append("[fec %d+%d] the tile says %d%% overhead, but p/d is %d%%\n"
                                "      tile: %s" % (d, p, got, want, shown))
            else:
                print("  ok  fec %d+%d tile says %d%%, and p/d is %d%%" % (d, p, got, want))
        note = re.search(r'fec_note:"([^"]*)"', src)
        if not note:
            failures.append("fec_note was not found")
        elif "100٪" not in note.group(1):
            failures.append("fec_note does not say the tile percentage is the SATURATED-block figure "
                            "(a single-packet block costs 100٪) — on its own the tile reads as a "
                            "promise the encoder only keeps on a busy tunnel")
        else:
            print("  ok  fec_note says the tile percentage is the saturated-block figure")

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("every FEC rate tile advertises what it produces")
    return 0


if __name__ == "__main__":
    sys.exit(main())
