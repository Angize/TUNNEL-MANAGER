#!/usr/bin/env python3
"""The log page is one surface in both themes, and every event reads as a sentence.

The log used to be a stack of default cards on the default page chrome: a green button, a grey search
box and blue chips above a list of white cards, each with a short noun-phrase title and its reason
filed away in a fold the operator had to open. Two things were wrong with it and both are checked here.

  * The page was not one thing. The header, the clear button, the search box and the chips came from
    the shared components and kept the panel's default colours, while the list below them had its own.
    A page whose chrome and content disagree reads as two pages.
  * The reason lived somewhere else than the event. «تونلِ «core18»: قطع شد» told the operator nothing
    they did not already know from the red stripe; the sentence that mattered — why — sat folded.

The sodium treatment answers both: one container, one token set, and a sentence that carries its own
reason. Values keep their monospace amber so they can still be scanned without reading the prose.

What must hold, and what breaks if it stops holding:

  * the whole page sits inside .sodlog, so its chrome takes the same tokens as its rows. Move any
    piece outside and it silently reverts to the panel default, which is the state this replaced.
  * every sodium token is defined for BOTH themes. A token defined only under body.dark renders one
    theme's text on the other theme's ground.
  * the severity bar glows only in dark. On the light ground a glow is invisible and the bar must
    carry the colour by itself.
  * the timestamp is NOT forced to LTR. It is a mixed string — «17 شهریور، 03:36» — and forcing it
    left-to-right reorders the month around the digits into «17 03:36 ،شهریور».
  * a custom property must never be declared with a var() that is undefined where it is declared.
    --sod-glow was first written on .sodlog as `0 0 10px -1px var(--sev)`, and since --sev only exists
    on the row, the whole property computed to the empty string and no bar ever glowed.

Reads the DECODED INDEX_HTML, never the .py bytes.

    python3 tools/the_log_page_is_one_surface_check.py
"""
import importlib.util
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load():
    spec = importlib.util.spec_from_file_location("panel_logui_guard",
                                                  os.path.join(PANEL_REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["panel_logui_guard"] = m
    spec.loader.exec_module(m)
    return m


def css_of(html, selector):
    """The declaration block for one exact selector, or None."""
    mo = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", html)
    return mo.group(1) if mo else None


def main():
    m = load()
    html = m.INDEX_HTML
    js = re.findall(r"<script>(.*?)</script>", html, re.S)[0]

    print("== the page is one surface ==")
    skel = js.split("function logsSkel()")[1].split("function ")[0]
    check("the log page opens a .sodlog container", 'class="sodlog"' in skel, skel[:90])
    check("...exactly one container, not one per section",
          skel.count('class="sodlog"') == 1, skel.count('class="sodlog"'))
    opened = skel.find('class="sodlog"')
    closed = skel.rfind("</div>")
    for piece, what in (("vhead(", "the title and description"),
                        ("chkall", "the clear-log button"),
                        ("toolbar(", "the search box"),
                        ("logChips", "the filter chips"),
                        ("logList", "the list itself")):
        at = skel.find(piece)
        check("%s is inside it" % what, opened < at < closed,
              "at %d, container spans %d..%d" % (at, opened, closed))
    opens, closes = len(re.findall(r"<div[ >]", skel)), skel.count("</div>")
    check("...and every div the page opens is closed", opens == closes, "%d open / %d close" % (opens, closes))

    print("== every sodium token is defined for both themes ==")
    light = css_of(html, ".sodlog")
    dark = css_of(html, "body.dark .sodlog")
    check("the light block exists", bool(light))
    check("the dark block exists", bool(dark))
    if light and dark:
        lt = set(re.findall(r"(--sod-[a-z0-9-]+)\s*:", light))
        dt = set(re.findall(r"(--sod-[a-z0-9-]+)\s*:", dark))
        check("no token is defined only for dark", not (dt - lt), sorted(dt - lt))
        check("no token is defined only for light", not (lt - dt), sorted(lt - dt))
        check("both blocks paint their own ground", "background:" in light and "background:" in dark)
        used = set(re.findall(r"var\((--sod-[a-z0-9-]+)", html))
        check("every token that is used is declared", not (used - lt), sorted(used - lt))

    print("== a custom property never leans on a variable it cannot see ==")
    bad = []
    for block, where in ((light, ".sodlog"), (dark, "body.dark .sodlog")):
        if not block:
            continue
        for name, val in re.findall(r"(--sod-[a-z0-9-]+)\s*:([^;]*)", block):
            for ref in re.findall(r"var\((--[a-z0-9-]+)", val):
                if not re.search(re.escape(ref) + r"\s*:", block):
                    bad.append("%s in %s references %s, which is not declared there" % (name, where, ref))
    check("no token computes to the empty string", not bad, bad[:3])

    print("== severity reads in both themes ==")
    bar = css_of(html, ".sodev .sbar")
    darkbar = css_of(html, "body.dark .sodev .sbar")
    check("the bar carries its colour with no glow by default",
          bool(bar) and "background:var(--sev)" in bar.replace(" ", "") and "box-shadow" not in bar, bar)
    check("...and only the dark theme adds a glow",
          bool(darkbar) and "box-shadow" in darkbar, darkbar)
    for lvl in ("bad", "warn", "ok"):
        check("the %s row sets its own --sev" % lvl,
              re.search(r"\.sodev\.%s\{--sev:var\(--sod-%s\)\}" % (lvl, lvl), html.replace(" ", "")) is not None)

    print("== the timestamp keeps its own direction ==")
    st = css_of(html, ".sodev .stime")
    check("the time is not forced left-to-right",
          bool(st) and "direction:ltr" not in st.replace(" ", ""), st)
    check("...it is rendered as plaintext so the month stays put",
          bool(st) and "unicode-bidi:plaintext" in st.replace(" ", ""), st)
    check("...and the row does not re-apply the mono class to it",
          'class="mono stime"' not in js, "the mono helper forces LTR")

    print("== an event reads as a sentence, and its values stay scannable ==")
    check("the renderer builds a sentence from the title and its prose", "function sodSentence" in js)
    check("...joining them rather than folding the reason away",
          "sodSentence(p.title,sp.notes)" in js.replace(" ", ""), "notes must reach the sentence")
    check("values are laid out on their own row, not spliced into the prose",
          re.search(r"if\(lead\.length\)\s*sen\+='<div class=\"svals\">'", js) is not None,
          "the values row must be built from lead, not merely mentioned")
    check("...in monospace, so they can be scanned without reading",
          "monospace" in (css_of(html, ".sodev .sval") or ""))
    check("only the first few values ride along; the rest fold",
          re.search(r"SOD_LEAD\s*=\s*\d+", js) is not None and "sp.rows.slice(SOD_LEAD)" in js.replace(" ", ""))
    check("the three severity labels are real strings, not raw keys",
          all(re.search(r"sod_%s:\"[^\"]+\"" % k, js) for k in ("bad", "warn", "ok")))

    print("== and the page it replaced is gone ==")
    rows = js.split("function logRows()")[1].split("function ")[0]
    check("no event still renders through the old card", "lstripe" not in rows, rows[:80])

    if FAILED:
        print("\n%d failure(s):" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("\nthe log page is one surface, in both themes, and every event says why.")


if __name__ == "__main__":
    main()
