#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""When the operator sets an ECH DoH proxy, the direct resolvers must not run at all.

The operator sets that proxy for exactly one reason: the panel's own view of DNS is not trusted.
`_fetch_ech` used to ADD the two proxied lookups to the four direct DoH endpoints and the local
`dig`, then take whichever answered first. On a censored path the direct lookups do not politely
return nothing -- they return a poisoned or regionally stale HTTPS record, they return it from the
same machine faster than a proxied TLS round trip can finish, and `as_completed` hands that answer
back as the truth. The panel then stores a key the CDN edge will reject, and the operator's proxy
setting bought them nothing.

The proxy is now a replacement, not a racer.

    python3 tools/the_ech_proxy_replaces_the_direct_path_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

spec = importlib.util.spec_from_file_location("tnlc", PANEL)
m = importlib.util.module_from_spec(spec)
sys.modules["tnlc"] = m
spec.loader.exec_module(m)

fails = []


def chk(ok, label, got=""):
    if ok:
        print("  ok   %s" % label)
    else:
        print(" FAIL  %-64s %r" % (label, got))
        fails.append(label)


class Trace:
    def __init__(self):
        self.dig = []
        self.direct = []
        self.proxied = []


def run(host, proxy, dig_answer="", doh_answer=""):
    t = Trace()

    class FakeRun:
        def __init__(self, out):
            self.stdout = out

    def fake_subprocess_run(cmd, **kw):
        if host in cmd:
            t.dig.append(cmd)
        return FakeRun(dig_answer.encode())

    class FakeResp:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        if host in req.full_url:
            t.direct.append(req.full_url)
        return FakeResp(doh_answer.encode())

    def fake_socks5(phost, pport, user, pw, dhost, dport, tmo):
        t.proxied.append(dhost)
        raise RuntimeError("no real socket in this check")

    m.subprocess.run = fake_subprocess_run
    m._socks5_socket = fake_socks5
    import urllib.request
    orig = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        m._fetch_ech(host, proxy)
    finally:
        urllib.request.urlopen = orig
    return t


ECH_TXT = 'edge.example.com. 300 IN HTTPS 1 . ech="QUJD"'

print("with no proxy configured -- the direct path is the only path:\n")
t = run("plain.example.com", "", dig_answer=ECH_TXT)
chk(len(t.dig) == 1, "the local dig runs", t.dig)
chk(len(t.proxied) == 0, "nothing is sent through a proxy", t.proxied)

print("\nwith a proxy configured -- the direct path must not run at all:\n")
t = run("viaproxy.example.com", "socks5://127.0.0.1:1080", dig_answer=ECH_TXT,
        doh_answer='{"Answer":[]}')
chk(len(t.dig) == 0, "the local dig does NOT run", t.dig)
chk(len(t.direct) == 0, "no direct DoH endpoint is contacted", t.direct)
chk(len(t.proxied) > 0, "the proxied lookups do run", t.proxied)
chk(set(t.proxied) == {"cloudflare-dns.com", "dns.google"},
    "and they are the two proxied resolvers", sorted(set(t.proxied)))

print("\nthe race cannot be won by a poisoned direct answer:\n")
t = run("poisoned.example.com", "socks5://127.0.0.1:1080",
        dig_answer='x. 300 IN HTTPS 1 . ech="UE9JU09O"')
chk(len(t.dig) == 0, "a direct answer is never even asked for, so it cannot win", t.dig)

print()
if fails:
    print("FAILURES (%d):" % len(fails))
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("the ECH proxy replaces the direct resolvers instead of racing them.")
