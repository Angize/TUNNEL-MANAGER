#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: every request the PANEL makes to github can be routed through one of its own proxies.

The nodes already have this: a node marked proxy_on has its whole control channel routed. The panel
had nothing -- so on a panel that cannot reach github directly, staging a core, fetching the agent and
even listing the versions all fail, with no setting anywhere that helps.

One switch and one pick from the proxy list now covers all three, because all three go through _gh_get.
What this asserts:

  * with the switch off, nothing changes: the direct urlopen path is used;
  * with it on, the binary, the agent source and the release list ALL go through _proxy_socket, to the
    right host and port, and the bytes come back intact;
  * the redirect github answers a release download with is followed, through the proxy, to the end;
  * a proxy id that does not exist is refused when it is SAVED, not silently at the next download;
  * turning it off clears the id, so a later delete of that proxy cannot resurrect a stale route.

The socket boundary is stubbed with a tiny https server-in-a-string; _proxy_socket itself is replaced,
which is exactly the seam a real socks5 or CONNECT proxy sits behind.

Exit 1 on any failure.
"""
import importlib.util
import io
import json
import os
import ssl
import sys
import tempfile

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, "..")))
PANEL = os.path.join(ROOT, "tnl-central.py")

FAILED = []
BIN = b"\x7fELF" + b"Q" * 5000
AGENT = '#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 77}\n'
RELEASES = [{"tag_name": "v9.9.9", "name": "nine"}, {"tag_name": "v9.9.8", "name": "eight"}]
PX = {"id": "px1", "name": "DE-hop", "scheme": "socks5", "host": "5.75.197.201", "port": 1080,
      "user": "", "pass": ""}


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location("tnl_dlpx_check", PANEL)
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
    def __init__(self, status, body, location=""):
        self.status = status
        self._body = body
        self._loc = location

    def getheader(self, k):
        return self._loc if k.lower() == "location" else None

    def read(self):
        return self._body


class FakeConn:
    """Stands in for HTTPSConnection: the panel hands it a socket, then speaks HTTP over it."""

    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.sock = None
        self.path = None
        self.headers = {}

    def request(self, method, path, headers=None, body=None):
        self.path = path
        self.headers = dict(headers or {})

    def getresponse(self):
        return SERVE(self.host, self.path, self.headers)

    def close(self):
        pass


SERVE = None


def wire_proxy(m, dialed):
    def sock(proxy, dh, dp, timeout):
        dialed.append((proxy, dh, dp))
        return "SOCKET"

    m._proxy_socket = sock
    m.ssl = type("S", (), {"create_default_context": staticmethod(
        lambda: type("C", (), {"wrap_socket": staticmethod(lambda s, server_hostname=None: s)})())})
    m.http = type("H", (), {"client": type("C", (), {"HTTPSConnection": FakeConn})})


def direct_only(m, direct):
    class R:
        def __init__(self, b):
            self.b = b

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n=None):
            return self.b[:n] if n else self.b

    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        direct.append(url)
        if "api.github.com" in url:
            return R(json.dumps(RELEASES).encode())
        return R(AGENT.encode() if url.endswith(".py") else BIN)

    m.urllib.request.urlopen = urlopen


def main():
    global SERVE
    state = tempfile.mkdtemp()
    m = load_panel(state)
    m.log_event = lambda *a, **k: None
    m.save_json(m.PROXIES_FILE, [PX])

    dialed, direct = [], []
    wire_proxy(m, dialed)
    direct_only(m, direct)

    seen = []

    def serve(host, path, headers):
        seen.append({"host": host, "path": path, "headers": dict(headers)})
        if "api.github.com" in host:
            return FakeResp(200, json.dumps(RELEASES).encode())
        if path.endswith(".py"):
            return FakeResp(200, AGENT.encode())
        if "objects." in host:
            return FakeResp(200, BIN)
        return FakeResp(302, b"", "https://objects.example.com" + path)

    SERVE = serve

    m.api_settings_set({"dl_proxy_on": False})
    direct[:] = []
    dialed[:] = []
    got = m._dl("https://github.com/x/y/releases/download/v9.9.9/tnl-core-linux-amd64", 30)
    check("with the switch off the panel goes straight out, as it always did",
          got == BIN and len(direct) == 1 and not dialed, "%r %r" % (direct, dialed))

    m.api_settings_set({"dl_proxy_on": True, "dl_proxy_id": "px1"})
    direct[:] = []
    dialed[:] = []
    got = m._dl("https://github.com/x/y/releases/download/v9.9.9/tnl-core-linux-amd64", 30)
    check("with it on the binary comes back through the proxy, intact",
          got == BIN and not direct, "%d bytes, direct=%r" % (len(got or b""), direct))
    check("  and the proxy it dialled is the one that was picked",
          [d[0] for d in dialed] == [m.proxy_url(PX)] * len(dialed) and len(dialed) == 2,
          repr(dialed))
    check("  the release redirect was followed, to the object host, on 443",
          [(d[1], d[2]) for d in dialed] == [("github.com", 443), ("objects.example.com", 443)],
          repr(dialed))

    direct[:] = []
    dialed[:] = []
    seen[:] = []
    v = m._fetch_core_versions()
    check("the version list comes through the proxy too",
          [x["id"] for x in (v or [])] == ["v9.9.9", "v9.9.8"] and not direct and len(dialed) == 1,
          "%r direct=%r dialled=%r" % (v, direct, dialed))
    check("  carrying the json Accept header the api needs, and the panel's user agent",
          len(seen) == 1 and seen[0]["headers"].get("Accept") == "application/vnd.github+json"
          and seen[0]["headers"].get("User-Agent") == "tnl-central",
          json.dumps(seen, ensure_ascii=False)[:200])
    check("  and it asked for the releases path, not something else",
          len(seen) == 1 and seen[0]["path"].endswith("/releases"), repr([x["path"] for x in seen]))

    direct[:] = []
    dialed[:] = []
    m.api_agent_fetch_git({})
    check("the agent source comes through the proxy as well",
          not direct and len(dialed) == 1 and dialed[0][1] == "raw.githubusercontent.com",
          "direct=%r dialled=%r" % (direct, dialed))

    try:
        m.api_settings_set({"dl_proxy_on": True, "dl_proxy_id": "nope"})
        ok, why = False, "no error raised"
    except ValueError as e:
        ok, why = "پروکسی" in str(e), str(e)
    check("a proxy that does not exist is refused when it is saved", ok, why)
    check("  and the working setting was left alone",
          m.get_settings().get("dl_proxy_id") == "px1", json.dumps(m.get_settings().get("dl_proxy_id")))

    try:
        m.api_settings_set({"dl_proxy_on": True, "dl_proxy_id": ""})
        ok, why = False, "no error raised"
    except ValueError as e:
        ok, why = "انتخاب" in str(e), str(e)
    check("turning it on with nothing picked is refused too", ok, why)

    m.api_settings_set({"dl_proxy_on": False})
    st = m.get_settings()
    check("turning it off clears the id, so a deleted proxy cannot come back as a stale route",
          st.get("dl_proxy_on") is False and st.get("dl_proxy_id") == "",
          json.dumps({k: st.get(k) for k in ("dl_proxy_on", "dl_proxy_id")}))
    direct[:] = []
    dialed[:] = []
    m._dl("https://github.com/x/y/z", 30)
    check("  and the next download really is direct again", len(direct) == 1 and not dialed,
          "%r %r" % (direct, dialed))

    m.api_settings_set({"dl_proxy_on": True, "dl_proxy_id": "px1"})
    m.save_json(m.PROXIES_FILE, [])
    direct[:] = []
    dialed[:] = []
    m._dl("https://github.com/x/y/z", 30)
    check("a proxy deleted out from under the setting falls back to direct, it does not hang",
          len(direct) == 1 and not dialed, "%r %r" % (direct, dialed))

    print()
    if FAILED:
        print("%d failure(s)" % len(FAILED))
        return 1
    print("one switch routes every github request the panel makes, and only those")
    return 0


if __name__ == "__main__":
    sys.exit(main())
