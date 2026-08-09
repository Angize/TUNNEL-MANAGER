#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every function the browser calls, and every CSS class its markup uses, must actually exist.

Neither existing guard catches this. `undefined_names_check.py` reads the PYTHON half only, and
`js_syntax_check.py` only asks whether the script parses -- a call to a function nobody wrote parses
perfectly and throws `ReferenceError` when that path runs, and a class nobody styled renders as an
unstyled control. Both shipped in the proxies branch:

  * `openPxModal` called `modalShell(...)`, which was never written, so «افزودنِ پروکسی» did nothing.
  * the toggle was `<label class="sw">` and `.sw` has no rule anywhere, so it rendered as a bare native
    checkbox instead of the panel's pill switch.

Panel JS is mostly HTML inside string literals, so the two halves need opposite treatment: real code is
scanned for bare `name(` calls with strings and comments REMOVED (otherwise Persian prose like «(CDN)»
reads as a call), and the strings are scanned for `onclick="name(...)"` handlers and `class="..."` names.

Known limit, stated rather than hidden: a handler built by concatenation (`'+fnp+'ToggleEch()'`) has no
literal name to check, so those are skipped -- as are calls made through a variable.

    python3 tools/js_names_exist_check.py
"""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

BUILTINS = {
    "if", "for", "while", "switch", "catch", "return", "function", "typeof", "new", "delete", "throw",
    "do", "else", "in", "of", "void", "await", "case", "with", "yield", "instanceof",
    "Array", "Object", "String", "Number", "Boolean", "Math", "JSON", "Date", "RegExp", "Error",
    "Promise", "Set", "Map", "Symbol", "BigInt", "Proxy", "Reflect", "WeakMap", "WeakSet",
    "parseInt", "parseFloat", "isNaN", "isFinite", "encodeURIComponent", "decodeURIComponent",
    "encodeURI", "decodeURI", "eval", "alert", "confirm", "prompt",
    "setTimeout", "clearTimeout", "setInterval", "clearInterval", "requestAnimationFrame",
    "cancelAnimationFrame", "fetch", "atob", "btoa", "structuredClone", "queueMicrotask",
    "AbortController", "URL", "URLSearchParams", "TextEncoder", "TextDecoder", "Intl", "Blob",
    "FormData", "Headers", "Request", "Response", "Event", "CustomEvent", "FileReader", "File",
    "MutationObserver", "IntersectionObserver", "ResizeObserver", "WebSocket", "XMLHttpRequest",
    "Image", "Audio", "DOMParser", "getComputedStyle", "matchMedia", "localStorage",
}

# Classes driven by script or by a state machine rather than by a rule of their own.
CLASS_STATE_ONLY = {
    "on", "off", "open", "dark", "run", "wait", "done", "sel", "busy", "active", "show", "hidden",
}

# Selector hooks: they exist so querySelector can find the element, and are never meant to style it.
SCRIPT_HOOKS = {"kt_msg", "myes", "mno", "mok", "rbsec"}

# Unstyled leftovers that predate this check. Shrink it; never add to it -- a NEW unstyled class is the
# bug this file is here to catch.
KNOWN_UNSTYLED = {"gbtn", "sm"}


def load_pages(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return [("INDEX_HTML", getattr(mod, "INDEX_HTML", "")),
            ("LOGIN_HTML", getattr(mod, "LOGIN_HTML", ""))]


RE_START_AFTER = set("(,=:[!&|?{};+-*%~^") | {""}


def _regex_here(code_so_far):
    """Is this `/` a regex literal rather than division? Decided by the previous significant char.

    Not optional: `esc()` contains `.replace(/[&<>"']/g, …)`, and a lexer that misses it takes the `"`
    inside that character class as a string opener and desynchronises for the rest of the file --
    measured, that blanked every declaration after it and produced 23 phantom "undefined" calls.
    """
    prev = code_so_far.rstrip()
    if not prev:
        return True
    if prev[-1] in RE_START_AFTER:
        return True
    return bool(re.search(r"\b(?:return|typeof|case|in|of|new|delete|void|do|else)$", prev))


def lex(js):
    """Split JS into (code with strings/comments/regexes blanked, [(string body, line)]).

    One pass, quote- and regex-aware, so a `//` inside 'socks5://x' is not a comment and an apostrophe
    inside a comment or a regex character class does not open a string.
    """
    code, strings = [], []
    i, n = 0, len(js)
    line = 1
    while i < n:
        c = js[i]
        if c == "\n":
            line += 1
            code.append(c)
            i += 1
        elif c == "/" and i + 1 < n and js[i + 1] not in "/*" and _regex_here("".join(code)):
            j = i + 1                      # a regex literal: skip to its unescaped closing slash
            in_class = False
            while j < n and js[j] != "\n":
                if js[j] == "\\":
                    j += 2
                    continue
                if js[j] == "[":
                    in_class = True
                elif js[j] == "]":
                    in_class = False
                elif js[j] == "/" and not in_class:
                    break
                j += 1
            code.append(" ")
            i = j + 1
        elif c in "'\"`":
            q, j, buf = c, i + 1, []
            while j < n and js[j] != q:
                if js[j] == "\\":
                    buf.append(js[j:j + 2])
                    j += 2
                    continue
                buf.append(js[j])
                j += 1
            strings.append(("".join(buf), line))
            line += js[i:j].count("\n")
            code.append(" ")
            i = j + 1
        elif c == "/" and i + 1 < n and js[i + 1] == "/":
            j = js.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and i + 1 < n and js[i + 1] == "*":
            j = js.find("*/", i)
            seg = js[i:n if j < 0 else j + 2]
            line += seg.count("\n")
            i = n if j < 0 else j + 2
        else:
            code.append(c)
            i += 1
    return "".join(code), strings


def declared(code):
    names = set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", code))
    names |= set(re.findall(r"\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)", code))
    names |= set(re.findall(r"[,;{(]\s*([A-Za-z_$][\w$]*)\s*=", code))
    for m in re.finditer(r"\bfunction\s*[A-Za-z_$\w]*\s*\(([^)]*)\)", code):
        for p in m.group(1).split(","):
            p = p.strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", p):
                names.add(p)
    return names


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    failures = []
    for label, page in load_pages(Path(a.panel)):
        js = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", page, re.S))
        css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", page, re.S))
        if not js:
            failures.append("%s: no <script> found — this check cannot read its subject" % label)
            continue
        code, strings = lex(js)
        known = declared(code) | BUILTINS

        calls = {}
        for m in re.finditer(r"(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(", code):
            calls.setdefault(m.group(1), code[:m.start()].count("\n") + 1)
        bad = {n: ln for n, ln in calls.items() if n not in known}
        for n, ln in sorted(bad.items()):
            failures.append("%s line %d: code calls %s(), which nothing declares" % (label, ln, n))
        print("  ok  %-11s code: %d call name(s), %d undefined" % (label, len(calls), len(bad)))

        handlers = {}
        for body, ln in strings:
            for m in re.finditer(r"\bon[a-z]+\s*=\s*[\"']\s*([A-Za-z_$][\w$]*)\s*\(", body):
                handlers.setdefault(m.group(1), ln)
        badh = {n: ln for n, ln in handlers.items() if n not in known}
        for n, ln in sorted(badh.items()):
            failures.append("%s line %d: markup wires on…=\"%s(…)\", which nothing declares — the control "
                            "renders fine and throws ReferenceError only when it is used"
                            % (label, ln, n))
        print("  ok  %-11s markup: %d inline handler(s), %d undefined"
              % (label, len(handlers), len(badh)))

        styled = set(re.findall(r"\.([A-Za-z][\w-]*)", css))
        # A class list is often BUILT: class="base '+(on?' on':'')+'". Read the literal head of such an
        # attribute too, dropping its last token when the chunk ends mid-attribute -- that token may be
        # half a name. Requiring a closing quote instead would have missed the real `.sw` bug.
        used = {}
        for body, ln in strings:
            for m in re.finditer(r'class\s*=\s*"([^"<>{}]*?)("|$)', body):
                toks = m.group(1).split()
                if not m.group(2) and toks:
                    toks = toks[:-1] if not m.group(1).endswith((" ", "	")) else toks
                for cls in toks:
                    if re.match(r"^[a-z][a-z0-9_-]*$", cls):
                        used.setdefault(cls, ln)
        badc = {c: ln for c, ln in used.items() if c not in styled and c not in CLASS_STATE_ONLY
                and c not in SCRIPT_HOOKS and c not in KNOWN_UNSTYLED}
        for c, ln in sorted(badc.items()):
            failures.append("%s line %d: markup uses class=\"%s\", which no CSS rule mentions — that "
                            "control renders as a bare browser default" % (label, ln, c))
        print("  ok  %-11s markup: %d class(es), %d with no CSS rule" % (label, len(used), len(badc)))

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nevery name the browser calls is declared, and every class it writes is styled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
