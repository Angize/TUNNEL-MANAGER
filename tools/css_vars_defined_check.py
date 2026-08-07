"""Guard: every CSS custom property the panel USES is actually DEFINED.

`--warn` was referenced five times and defined nowhere. Two of those uses carried a literal fallback and
looked fine; the other three -- the suspect pool row's stripe, its state icon, and the FEC overhead
figure -- resolved to nothing, so `color: var(--warn)` was simply an invalid declaration and the element
kept whatever colour it inherited. The middle health state of every rotation pool had no colour at all,
and the panel still rendered, still passed every structural test, and looked merely a bit flat.

That is the whole class: a typo'd or renamed token fails SILENTLY in CSS. There is no error, no console
warning, nothing to notice unless someone measures the computed colour of the exact element.

The check is textual on the decoded INDEX_HTML, not on the .py source (CLAUDE.md 4). A fallback does
not excuse a missing definition: `var(--x,#abc)` means "there should be an --x" and the fallback is a
belt, so it is reported too -- just separately, since it is not currently broken on screen.

Exit 1 on any use with no definition anywhere.
"""
import importlib.util
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"


def main():
    spec = importlib.util.spec_from_file_location("tnl_central_cssvars", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)          # placeholders are substituted at import
    html = m.INDEX_HTML

    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", html, re.S))
    # inline style="..." attributes reference tokens too, and that is where one of the three lived
    inline = "\n".join(re.findall(r"style=[\"'][^\"']*[\"']", html))
    used_bare, used_fb = set(), set()
    for text in (css, inline, html):
        for name, fb in re.findall(r"var\(\s*(--[A-Za-z0-9_-]+)\s*(,[^)]*)?\)", text):
            (used_fb if fb else used_bare).add(name)

    # A definition is `--name:` in ANY declaration — the stylesheet, an inline style attribute, or a
    # string the JS writes into one. Scanning only <style> reports the per-element override pattern
    # (`--hue` set inline, read as `var(--hue,var(--acc))`) as missing, which it is not.
    defined = set(re.findall(r"(--[A-Za-z0-9_-]+)\s*:", html))

    missing_bare = sorted(used_bare - defined)
    missing_fb = sorted(used_fb - defined - used_bare)

    for n in sorted(used_bare | used_fb):
        if n in defined:
            continue
        tag = "FAIL " if n in used_bare else " warn"
        print(f"{tag} {n} is used but never defined")

    if missing_fb:
        print("\nreferenced with a literal fallback and never defined "
              "(renders, but the token is a lie): " + ", ".join(missing_fb))

    if missing_bare:
        print(f"\n{len(missing_bare)} custom propert{'y' if len(missing_bare) == 1 else 'ies'} used with "
              f"NO definition and NO fallback: {', '.join(missing_bare)}")
        print("Those declarations are invalid at computed-value time, so the element silently keeps its "
              "inherited value. Point them at a token that exists, or define them.")
        return 1

    print(f"  ok  all {len(used_bare | used_fb)} referenced custom properties are defined "
          f"({len(defined)} defined in total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
