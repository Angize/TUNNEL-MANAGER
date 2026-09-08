#!/usr/bin/env python3
"""Nobody reaches the panel without leaving a line in the log the operator reads.

A break-in you never recorded is one you cannot notice. Before this, /api/login wrote nothing at all:
a successful login was invisible, and ten thousand failures were invisible too. The first thing an
operator needs is not a stronger lock, it is the ability to see the door being tried.

Every path through the login is driven over a real socket and the resulting event is read back:

  * a success, a failure, the lock-out, a further attempt while locked, and a logout
  * the address, the browser and the device that did it, plus the raw user-agent kept whole for
    forensics — the parsed fields are a convenience, the raw string is the evidence
  * whether the username was the real one. The value is «درست»/«ناشناخته» and NEVER the string that
    was typed: an operator who fat-fingers their password into the username box must not have it
    written into a log that is served back to the browser.

Two failure modes this exists to stop:

  * silence. Removing any one of the log calls leaves the panel working perfectly and the operator
    blind, which is exactly the state this replaced.
  * a log that can be washed. Every attempt that reaches the password check is recorded, so a burst is
    visible; but attempts arriving while an address is ALREADY locked are recorded once per window,
    or an attacker could push a day of real events out of a 5000-entry store just by hammering.

The user-agent is attacker-controlled and ends up rendered in the panel, so it is also checked for
being stripped of control characters, truncated, and robbed of the arrow that would otherwise split it
across the two halves of an endpoint pill.

    python3 tools/every_login_is_recorded_check.py
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import threading
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []

CHROME = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/128.0.0.0 Safari/537.36")
IPHONE = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
          "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1")
FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
ANDROID = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/127.0.0.0 Mobile Safari/537.36")
HOSTILE = 'Mozilla/5.0 <img src=x onerror="alert(1)"> ' + chr(7) + ' "q" ' + "A" * 300
# A NUL would be cut by the HTTP layer before the panel ever sees it, taking the rest of the
# payload with it and leaving both assertions below proving nothing. BEL survives; so does length.

PILL_GATE = re.compile(r"[،؛؟.!?()«»—]")


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(state):
    spec = importlib.util.spec_from_file_location("panel_authlog_guard",
                                                  os.path.join(PANEL_REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["panel_authlog_guard"] = m
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit("these panel paths still point at the real state dir: %s" % left)
    return m


def main():
    state = tempfile.mkdtemp()
    m = load(state)
    conf = {"user": "admin", "secret": "ab" * 32}
    conf["salt"], conf["hash"] = m.hash_password("right-pw")
    m.save_json(m.WEB_CONF, conf)
    srv = m.BoundedThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
    srv.conf = conf
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]

    def call(path, body=None, cookie=None, ua=CHROME):
        req = urllib.request.Request(
            base + path, data=json.dumps(body or {}).encode() if body is not None else None,
            method="POST" if body is not None else "GET")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Requested-With", "tnl-central")
        req.add_header("User-Agent", ua)
        if cookie:
            req.add_header("Cookie", "tnl_session=" + cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.headers.get("Set-Cookie", "")
        except urllib.error.HTTPError as e:
            e.read()
            return e.code, ""

    def auth_events():
        return [e for e in m.load_events() if e.get("kind") == "auth"]

    def detail(e):
        return dict(l.split(": ", 1) for l in e["dfa"].split("\n") if ": " in l)

    def whole(e):
        """The sentence AND its fields. The try count moved into the sentence when the log page
        was redesigned; what the operator must see is the count, not which half it sits in."""
        return e["fa"] + chr(10) + e["dfa"]

    print("== a successful login leaves a line ==")
    st, setc = call("/api/login", {"user": "admin", "pass": "right-pw"}, ua=CHROME)
    sess = setc.split("tnl_session=", 1)[1].split(";", 1)[0] if "tnl_session=" in setc else ""
    evs = auth_events()
    check("the login succeeded", st == 200 and bool(sess), st)
    check("...and wrote exactly one event", len(evs) == 1, len(evs))
    e = evs[0]
    check("it is filed under the auth kind", e["kind"] == "auth")
    check("...which the log page has a chip for", m._ev_cat("auth") == "auth")
    check("it carries the time", isinstance(e["ts"], int) and e["ts"] > 1_700_000_000)
    d = detail(e)
    check("the address is recorded", d.get("از") == "127.0.0.1", d)
    check("the browser is named", d.get("مرورگر") == "Chrome 128", d)
    check("the device is named", d.get("دستگاه") == "Windows 10/11", d)
    check("the raw user-agent is kept whole", d.get("نشانه") == CHROME, d.get("نشانه"))

    print("== every failed attempt leaves one too, and says which username was tried ==")
    m._fails.clear()
    call("/api/login", {"user": "admin", "pass": "no"}, ua=FIREFOX)
    d = detail(auth_events()[0])
    check("a failure with the real username is marked «درست»", d.get("نام کاربری") == "درست", d)
    check("...and names the browser and device", (d.get("مرورگر"), d.get("دستگاه")) == ("Firefox 128", "Linux"), d)
    check("...and counts the try", "1 از 8" in whole(auth_events()[0]), whole(auth_events()[0]))
    m._fails.clear()
    call("/api/login", {"user": "someone-else", "pass": "no"}, ua=ANDROID)
    d = detail(auth_events()[0])
    check("an unknown username is marked «ناشناخته»", d.get("نام کاربری") == "ناشناخته", d)
    check("...and android is named", d.get("دستگاه") == "Android", d)
    check("the typed username is never written to the log",
          not any("someone-else" in e["dfa"] or "someone-else" in e["fa"] for e in auth_events()))

    print("== a burst is fully recorded up to the lock, then throttled ==")
    m._fails.clear()
    before = len(auth_events())
    for _ in range(40):
        call("/api/login", {"user": "admin", "pass": "no"}, ua=FIREFOX)
    added = auth_events()[:len(auth_events()) - before]
    warns = [x for x in added if x["level"] == "warn"]
    locked = [x for x in added if "قفل شد." in x["fa"]]
    still = [x for x in added if "همچنان" in x["fa"]]
    check("every attempt that reached the check was recorded", len(warns) == m.FAIL_LIMIT - 1,
          "%d warns for a limit of %d" % (len(warns), m.FAIL_LIMIT))
    check("the lock-out is recorded once, with its count",
          len(locked) == 1 and str(m.FAIL_LIMIT) in whole(locked[0]),
          [x["fa"] for x in added])
    check("...and every recorded failure numbers itself",
          all(re.search("تلاشِ \d+ از %d" % m.FAIL_LIMIT, x["fa"]) for x in warns),
          [x["fa"][:52] for x in warns[:2]])
    check("hammering a locked address cannot flood the log", len(still) <= 1, len(still))
    check("...so 40 attempts cost far fewer than 40 events", len(added) <= m.FAIL_LIMIT + 2, len(added))

    print("== logout is recorded, and a stranger cannot forge one ==")
    before = len(auth_events())
    call("/api/logout", {}, cookie=sess)
    check("logging out wrote an event", len(auth_events()) - before == 1)
    check("...naming the revocation", "باطل" in auth_events()[0]["fa"], auth_events()[0]["fa"])
    before = len(auth_events())
    call("/api/logout", {}, cookie="not-a-session")
    check("an unauthenticated logout writes nothing", len(auth_events()) - before == 0)

    print("== the user-agent is attacker-controlled, so it is cleaned before it is stored ==")
    m._fails.clear()
    call("/api/login", {"user": "admin", "pass": "right-pw"}, ua=HOSTILE)
    raw = detail(auth_events()[0]).get("نشانه", "")
    check("the payload really reached the panel intact", len(HOSTILE) > m.UA_MAX * 2, len(HOSTILE))
    check("control characters are stripped", not any(ord(c) < 32 for c in raw), repr(raw[:40]))
    check("...and the bell really was in what arrived", chr(7) in HOSTILE)
    check("it is truncated to UA_MAX", len(raw) == m.UA_MAX, "%d vs %d" % (len(raw), m.UA_MAX))
    check("the arrow that splits an endpoint pill is removed", "←" not in m.ua_clean("a ← b"))
    check("...and the payload is stored as text, not dropped", "<img" in raw, raw[:60])

    print("== and every detail line renders as a pill, never as prose ==")
    bad = []
    for e in auth_events():
        for line in e["dfa"].split("\n"):
            c = line.find(": ")
            k = line[:c] if c > 0 else ""
            if not k or len(k) > 16 or PILL_GATE.search(k):
                bad.append((e["fa"], line[:60]))
    check("no auth detail falls back to a grey sentence", not bad, bad[:3])

    srv.shutdown()
    if FAILED:
        print("\n%d failure(s):" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("\nevery way in and out of the panel is written down.")


if __name__ == "__main__":
    main()
