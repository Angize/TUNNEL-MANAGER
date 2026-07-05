#!/usr/bin/env python3
# Tests for the X-Forwarded-For trust fix in Handler._client_ip (no server/root).
# Run: python3 test_client_ip.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlcentral", os.path.join(HERE, "tnl-central.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


def client_ip(peer, conf, xff="9.9.9.9"):
    h = tnl.Handler.__new__(tnl.Handler)      # bypass BaseHTTPRequestHandler.__init__ (no socket)
    h.client_address = (peer, 4444)
    h._conf = lambda: conf
    h.headers = {"X-Forwarded-For": xff} if xff is not None else {}
    return h._client_ip()


# A remote client cannot spoof its source by sending X-Forwarded-For: the direct
# TCP peer is not a trusted proxy, so we key on the real peer address.
check("spoofed XFF from a remote peer is ignored",
      client_ip("203.0.113.7", {"tls": True}) == "203.0.113.7")

# The TLS terminator on loopback IS trusted, so its forwarded IP is honored.
check("XFF honored from a loopback proxy",
      client_ip("127.0.0.1", {"tls": True}) == "9.9.9.9")

# An explicitly configured off-host proxy is trusted; others still are not.
check("XFF honored from a configured trusted proxy",
      client_ip("10.0.0.5", {"tls": True, "trusted_proxies": ["10.0.0.5"]}) == "9.9.9.9")
check("XFF ignored from a peer not in trusted_proxies",
      client_ip("10.0.0.9", {"tls": True, "trusted_proxies": ["10.0.0.5"]}) == "10.0.0.9")

# With no TLS front, the peer is always used regardless of the header.
check("no-TLS: peer used, XFF ignored",
      client_ip("203.0.113.7", {}) == "203.0.113.7")

# Missing/empty header falls back to the peer even from a trusted proxy.
check("loopback proxy with no XFF falls back to peer",
      client_ip("127.0.0.1", {"tls": True}, xff=None) == "127.0.0.1")

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all client-ip tests passed")
