"""Guard: the core form's IP-row containers must carry the ids renderRotIps BUILDS.

renderRotIps looks its container up as `el(px+side+'ip')` — the id never appears in one piece at the
lookup site, so nothing in the source ties it to the `<div id="e_bip">` in the markup. Rename that div
and `el('e_bip')` returns null, renderRotIps returns before rendering, and **the whole destination IP
row silently disappears from the form**. No error, no console message, no failing test — it shipped.

That is exactly what a repo-wide rename did on 2026-08-05: `e_bip` reads like the old `bip` profile and
is actually `b`+`ip`. Word-boundary matching cannot see a concatenated identifier, which is why §4's
"identifiers first" pass is not enough on its own and this guard exists.

It renders the two forms from the DECODED INDEX_HTML and asserts every id the function can ask for is
really in the markup, for both prefixes and both sides.

Exit 1 if any is missing.
"""
import importlib.util
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"


def index_html():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_iprows", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.INDEX_HTML


def main():
    page = index_html()
    fails = []

    def check(ok, msg):
        print(("  ok   " if ok else " FAIL ") + msg)
        if not ok:
            fails.append(msg)

    # The lookup must still be the concatenation this guard is built around; if it is rewritten, this
    # check is describing something that no longer happens and must be updated rather than left green.
    lookup = re.search(r"el\((px)\+side\+'ip'\)", page)
    check(bool(lookup), "renderRotIps still builds its container id as px+side+'ip'"
                        " -- if not, THIS GUARD is out of date")

    # Which prefixes renderRotIps is called with, read off the source rather than assumed.
    prefixes = sorted(set(re.findall(r"renderRotIps\('(\w+_)'\)", page)))
    check(len(prefixes) >= 2, f"renderRotIps is called for the prefixes {prefixes}")

    for px in prefixes:
        for side in ("a", "b"):
            wanted = f'id="{px}{side}ip"'
            check(wanted in page,
                  f"{wanted} is in the markup -- renderRotIps('{px}') asks for it by concatenation, and a "
                  f"missing container drops that whole IP row from the form with no error")

    print()
    if fails:
        print(f"{len(fails)} failure(s)")
        return 1
    print("every IP-row container renderRotIps can ask for exists in the markup")
    return 0


if __name__ == "__main__":
    sys.exit(main())
