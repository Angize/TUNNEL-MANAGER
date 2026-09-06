#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: when «بررسی آپدیت» fails, the operator is told WHY.

`_fetch_core_versions` used to wrap its whole body in `except Exception: return None`, so every way
of failing arrived at the button as one sentence: "دریافت از گیت‌هاب ناموفق بود". A timeout, a dead
proxy, github's 60-per-hour cap answering 403, a TLS error and a malformed body were indistinguishable
-- and the operator's next move is different for each one. The button beside it, «دریافت از گیت‌هاب»
for the agent, has always reported the reason; only this one swallowed it.

That is not a cosmetic gap. With the download proxy on, the api quota belongs to the proxy's EXIT ip
and is shared with whatever else uses it, so 403 is a real state a panel reaches while its own ip
still has 59 of 60 left. "ناموفق" sends you looking at the network; "HTTP 403 rate limit exceeded"
tells you to turn the proxy off for a minute.

What this asserts, by driving the real api_core_check with the real _gh_get replaced at the socket
seam -- never by reading the source:

  * five different failures each reach the operator with their own text in the message;
  * a failure whose str() is EMPTY (a bare TimeoutError, a bare ConnectionResetError -- both of which
    the panel really can raise) still names its class instead of ending on a dangling colon;
  * a failed check does not clobber a version list that was already good;
  * the happy path still works, and still reports newer/same/first correctly;
  * the check's timeout is the same as the panel's other github fetches -- the 10s it used to carry
    was the tightest budget in the file and sat on the longest chain, panel -> proxy -> github;
  * _proxy_get carries github's reason phrase, not just the number;
  * and _resolve_core_version still falls back to "latest" rather than raising -- it has a working
    url that needs no api call, so making the fetch raise must not break staging.

    python3 tools/a_failed_update_check_says_why_check.py

Exit 1 on any failure.
"""
import importlib.util
import json
import os
import socket
import ssl
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, "..")))
PANEL = os.path.join(ROOT, "tnl-central.py")

FAILED = []
RELEASES = [{"tag_name": "v9.9.9", "name": "nine"}, {"tag_name": "v9.9.8", "name": "eight"}]
PX = {"id": "px1", "name": "DE-hop", "scheme": "socks5", "host": "5.75.197.201", "port": 1080,
      "user": "", "pass": ""}


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("\n         %s" % (detail,)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location("tnl_whycheck", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit("these panel paths still point at the real state dir: %s" % left)
    return m


class FakeResp:
    """A github response: status, reason phrase and body, read the way _proxy_get reads one."""

    def __init__(self, status, reason, body):
        self.status, self.reason, self._body, self._i = status, reason, body, 0

    def getheader(self, k):
        return str(len(self._body)) if k.lower() == "content-length" else None

    def read(self, n=None):
        out = self._body[self._i:] if n is None else self._body[self._i:self._i + n]
        self._i += len(out)
        return out


class FakeConn:
    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout, self.sock = host, port, timeout, None

    def request(self, method, path, headers=None, body=None):
        pass

    def getresponse(self):
        return SERVE()

    def close(self):
        pass


SERVE = None


def wire_proxy(m, seen_timeout):
    """Put the panel on the proxy path with the socket, TLS and HTTP layers stubbed."""
    def sock(proxy, dh, dp, timeout):
        seen_timeout.append(timeout)
        return "SOCKET"

    m._proxy_socket = sock
    m.ssl = type("S", (), {"create_default_context": staticmethod(
        lambda: type("C", (), {"wrap_socket": staticmethod(lambda s, server_hostname=None: s)})())})
    m.http = type("H", (), {"client": type("C", (), {"HTTPSConnection": FakeConn})})
    m.save_json(m.PROXIES_FILE, [PX])
    m.api_settings_set({**m.get_settings(), "dl_proxy_on": True, "dl_proxy_id": PX["id"]})


class Boom(Exception):
    pass


def main():
    global SERVE
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state)
        real_gh_get = m._gh_get
        seen_timeout = []
        wire_proxy(m, seen_timeout)

        print("\n-- every way of failing reaches the operator with its own words --")
        # str(e) carries the text for each of these; the point is that the text SURVIVES to the button.
        cases = [
            ("a github status", lambda: (_ for _ in ()).throw(OSError("HTTP 403 rate limit exceeded")),
             "403"),
            ("a socket timeout", lambda: (_ for _ in ()).throw(socket.timeout("timed out")), "timed out"),
            ("a dead proxy", lambda: (_ for _ in ()).throw(OSError("socks5 connect failed (code 5)")),
             "socks5"),
            ("a tls failure", lambda: (_ for _ in ()).throw(ssl.SSLError("certificate verify failed")),
             "certificate"),
            ("a body that is not json", lambda: b"<html>not json</html>", "expecting"),
        ]
        said = {}
        for name, act, want in cases:
            def gh(url, timeout, headers=None, on_progress=None, should_abort=None, _a=act):
                return _a()
            m._gh_get = gh
            out = m.api_core_check({})
            err = str(out.get("error") or "")
            said[name] = err
            check("%s reaches the button" % name, not out.get("ok") and want.lower() in err.lower(), err)
        # and the point of all five: they are TELLABLE APART. One shared sentence for five causes is
        # what this guard exists to stop, so assert the property rather than only its five instances.
        check("the five causes produce five different messages", len(set(said.values())) == len(said),
              said)

        print("\n-- and a failure with no message of its own still names itself --")
        for exc in (TimeoutError(), ConnectionResetError(), Boom()):
            def gh(url, timeout, headers=None, on_progress=None, should_abort=None, _e=exc):
                raise _e
            m._gh_get = gh
            err = str(m.api_core_check({}).get("error") or "")
            check("%s is named, not left as a dangling colon" % type(exc).__name__,
                  type(exc).__name__ in err and not err.rstrip().endswith(":"), err)

        print("\n-- a failed check does not throw away a list that was already good --")
        m._gh_get = lambda *a, **k: json.dumps(RELEASES).encode()
        first = m.api_core_check({})
        check("the good check lands", first.get("ok") and first.get("latest") == "v9.9.9", first)
        check("and it is the first one", first.get("first_check") is True, first)

        def gh_boom(*a, **k):
            raise OSError("HTTP 403 rate limit exceeded")
        m._gh_get = gh_boom
        m.api_core_check({})
        keep = m.api_core_versions({})
        ids = [v.get("id") for v in (keep.get("versions") or [])]
        check("the versions survive the failed check", ids[:2] == ["v9.9.9", "v9.9.8"], ids)
        check("and so does the timestamp", int(keep.get("checked_ts") or 0) > 0, keep.get("checked_ts"))

        print("\n-- the happy path still answers the three questions the button asks --")
        m._gh_get = lambda *a, **k: json.dumps(RELEASES).encode()
        again = m.api_core_check({})
        check("a repeat check is not 'newer'", again.get("ok") and not again.get("newer"), again)
        m._gh_get = lambda *a, **k: json.dumps(
            [{"tag_name": "v9.9.10", "name": "ten"}] + RELEASES).encode()
        moved = m.api_core_check({})
        check("a new release IS 'newer'", moved.get("ok") and moved.get("newer")
              and moved.get("latest") == "v9.9.10", moved)

        print("\n-- the check's budget is the panel's github budget, not a tighter one of its own --")
        m._gh_get = real_gh_get
        SERVE = lambda: FakeResp(200, "OK", json.dumps(RELEASES).encode())
        seen_timeout.clear()
        m.api_core_check({})
        got_check = list(seen_timeout)
        seen_timeout.clear()
        agent_src = '#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 77}\n'
        SERVE = lambda: FakeResp(200, "OK", agent_src.encode())
        m.api_agent_fetch_git({})
        got_agent = list(seen_timeout)
        check("the version check and the agent fetch dial with the same timeout",
              got_check and got_agent and got_check[0] == got_agent[0],
              "check=%s agent=%s" % (got_check, got_agent))

        print("\n-- _proxy_get says WHICH failure, not just that there was one --")
        SERVE = lambda: FakeResp(403, "rate limit exceeded", b"{}")
        out = m.api_core_check({})
        err = str(out.get("error") or "")
        check("the status number reaches the operator", "403" in err, err)
        check("and so does github's reason phrase", "rate limit exceeded" in err, err)

        print("\n-- and staging still has its fallback: the api is an optimisation there, not a need --")
        # With a cached list the resolver answers from it and never reaches github, so empty the cache:
        # the fallback under test is the one a panel takes on a cold start with github unreachable.
        with m._core_versions_lock:
            m._core_versions_cache["data"] = None
        SERVE = lambda: FakeResp(500, "Internal Server Error", b"{}")
        try:
            got = m._resolve_core_version("latest")
            raised = None
        except Exception as e:
            got, raised = None, e
        check("an unreachable api resolves to 'latest' instead of raising",
              raised is None and got == "latest", raised or got)
        check("a named version never needed the api anyway", m._resolve_core_version("v1.2.3") == "v1.2.3")

    print()
    if FAILED:
        print("FAILED (%d)" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("a failed update check names its cause, and a successful one still answers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
