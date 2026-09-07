#!/usr/bin/env python3
"""«خروج» has to end the session, and the brute-force lock has to count the right client.

Two ways in, both closed here, both easy to reopen by accident:

  * A session token is a bearer credential. Logout used to clear the browser's cookie and nothing else,
    while check_token validated on signature and expiry alone — so a token lifted off the wire or out of
    a shared machine stayed good for its whole SESSION_TTL no matter what the operator pressed. The
    token now carries a session epoch that logout increments and persists, so pressing it kills every
    outstanding token at once. A future refactor that drops the epoch from either half restores the old
    behaviour silently: the panel still works, and only the attacker notices.

  * The 8-per-300s lock is keyed on the client address, and behind the reverse proxy that production
    needs for TLS that address comes from X-Forwarded-For. Standard proxies APPEND the real client to
    the right of whatever the client already sent, so the LEFTMOST entry is attacker-chosen. Reading it
    gave an attacker a fresh counter per attempt and no lock at all. The rightmost non-proxy hop is the
    only one a proxy vouches for.

    python3 tools/the_session_really_ends_check.py
"""
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(state):
    spec = importlib.util.spec_from_file_location("panel_session_guard",
                                                  os.path.join(PANEL_REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["panel_session_guard"] = m
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


class Req:
    """Just enough of the handler for _client_ip: a peer, a config and some headers."""

    def __init__(self, m, peer, conf, xff=None):
        self._client_ip = m.Handler._client_ip.__get__(self)
        self.client_address = (peer, 40000)
        self._conf = lambda: conf
        self.headers = {"X-Forwarded-For": xff} if xff is not None else {}


def main():
    state = tempfile.mkdtemp()
    m = load(state)
    conf = {"user": "admin", "secret": "ab" * 32}
    m.save_json(m.WEB_CONF, conf)

    print("== a token stops working the moment the operator logs out ==")
    tok = m.make_token(conf, "admin")
    check("a fresh token is accepted", m.check_token(conf, tok) == "admin")
    m.bump_sess_epoch(conf)
    check("after logout the SAME token is dead", m.check_token(conf, tok) is None)
    check("...and the epoch survives a panel restart", m.load_conf().get("sess_epoch") == 1)

    fresh = m.make_token(conf, "admin")
    check("a token issued after logout works", m.check_token(conf, fresh) == "admin")
    m.bump_sess_epoch(conf)
    check("...and the next logout kills that one too", m.check_token(conf, fresh) is None)

    def forge(user, exp, epoch):
        body = "%s|%s|%s" % (user, exp, epoch)
        sig = hmac.new(bytes.fromhex(conf["secret"]), body.encode(), hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(("%s|%s" % (body, sig)).encode()).decode()

    now, cur = int(time.time()), m.sess_epoch(conf)
    check("the epoch is signed, not merely carried",
          m.check_token(conf, forge("admin", now + 99, cur + 1)) is None)
    check("an expired token is still refused", m.check_token(conf, forge("admin", now - 1, cur)) is None)
    check("another user's token is refused", m.check_token(conf, forge("root", now + 99, cur)) is None)
    check("a token with a junk epoch does not crash the check",
          m.check_token(conf, forge("admin", now + 99, "x")) is None)
    print("== driven through the real handler, over a real socket ==")
    conf["salt"], conf["hash"] = m.hash_password("pw-for-the-guard")
    conf["sess_epoch"] = m.sess_epoch(conf)
    m.save_json(m.WEB_CONF, conf)
    srv = m.BoundedThreadingHTTPServer(("127.0.0.1", 0), m.Handler)
    srv.conf = conf
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]

    def call(path, body=None, cookie=None):
        req = urllib.request.Request(
            base + path,
            data=json.dumps(body or {}).encode() if body is not None else None,
            method="POST" if body is not None else "GET")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Requested-With", "tnl-central")
        if cookie:
            req.add_header("Cookie", "tnl_session=" + cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read(), r.headers.get("Set-Cookie", "")
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers.get("Set-Cookie", "")

    st, _, setc = call("/api/login", {"user": "admin", "pass": "pw-for-the-guard"})
    session = setc.split("tnl_session=", 1)[1].split(";", 1)[0] if "tnl_session=" in setc else ""
    check("a real login hands back a session", st == 200 and bool(session), (st, setc[:60]))

    st, page, _ = call("/", cookie=session)
    check("...that the panel accepts", st == 200 and b"<!doctype html" in page[:40].lower(), st)
    before = m.sess_epoch(srv.conf)

    st, _, _ = call("/api/logout", {}, cookie=session)
    check("pressing logout answers 200", st == 200, st)
    check("...and really raised the epoch", m.sess_epoch(srv.conf) == before + 1,
          "%s -> %s" % (before, m.sess_epoch(srv.conf)))

    st, body, _ = call("/api/nodes", cookie=session)
    check("the same cookie is refused afterwards, not merely dropped by the browser",
          st == 401, (st, body[:80]))
    srv.shutdown()


    print("== the lock counts the client the proxy vouches for, not the one it wrote ==")
    LOOP = {"tls": True}
    LIST = {"tls": True, "trusted_proxies": ["10.0.0.5", "10.0.0.6"]}
    check("a hop the client prepended is ignored",
          Req(m, "127.0.0.1", LOOP, "1.2.3.4, 203.0.113.9")._client_ip() == "203.0.113.9")
    check("...however many of them there are",
          Req(m, "127.0.0.1", LOOP, "9.9.9.9, 8.8.8.8, 203.0.113.9")._client_ip() == "203.0.113.9")
    check("every trusted hop is peeled off the right",
          Req(m, "10.0.0.5", LIST, "203.0.113.9, 10.0.0.6, 10.0.0.5")._client_ip() == "203.0.113.9")
    check("a forged hop behind the peel is still ignored",
          Req(m, "10.0.0.5", LIST, "1.1.1.1, 203.0.113.9, 10.0.0.6")._client_ip() == "203.0.113.9")
    check("an untrusted peer's header is not read at all",
          Req(m, "198.51.100.7", LOOP, "1.2.3.4")._client_ip() == "198.51.100.7")
    check("without tls the header is not read at all",
          Req(m, "198.51.100.7", {}, "1.2.3.4")._client_ip() == "198.51.100.7")
    check("a hop that is not an address is not used as a key",
          Req(m, "127.0.0.1", LOOP, "not-an-ip")._client_ip() == "127.0.0.1")
    check("a chain of nothing but proxies falls back to the peer",
          Req(m, "10.0.0.5", LIST, "10.0.0.6, 10.0.0.5")._client_ip() == "10.0.0.5")

    print("== the lock itself still locks, and its table cannot be grown without bound ==")
    m._fails.clear()
    for _ in range(m.FAIL_LIMIT):
        m.note_fail("brute")
    check("locked after FAIL_LIMIT failures", m.rate_limited("brute") is True)
    check("a different client is unaffected", m.rate_limited("other") is False)
    m._fails.clear()
    for i in range(m.FAIL_MAX_KEYS * 2):
        m.note_fail("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255))
    check("the table stays bounded under a flood of distinct keys",
          len(m._fails) <= m.FAIL_MAX_KEYS, len(m._fails))

    print("== and one attacker cannot occupy every login worker ==")
    got = [m._login_gate.acquire(blocking=False) for _ in range(m.LOGIN_GATE + 2)]
    check("the login gate admits LOGIN_GATE at once", got.count(True) == m.LOGIN_GATE)
    check("...and refuses the rest instead of queueing", got[m.LOGIN_GATE:] == [False, False])
    for _ in range(m.LOGIN_GATE):
        m._login_gate.release()
    check("the gate is released again afterwards", m._login_gate.acquire(blocking=False) is True)
    m._login_gate.release()

    if FAILED:
        print("\n%d failure(s):" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("\nlogout ends the session, and the lock counts the right client.")


if __name__ == "__main__":
    main()
