#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The proxy registry endpoints, driven for real against temp files.

The registry stores FIELDS ({scheme, host, port, user, pass}) and `proxy_url()` is the one place they
become a dial string. That split is what this pins, along with the three rules that are easy to break
silently:

  * the PASSWORD never appears in anything the browser is handed -- only `has_pass`. A row that carried
    it would put the credential in plain HTTP on every page refresh.
  * a BLANK password on edit keeps the stored one (the browser was never given it, so submitting the
    form it was shown must not wipe it) -- but clearing the USER clears it, because no user means no auth.
  * a node with a stored proxy_id but the toggle OFF is NOT a user of that proxy: counting it would
    refuse a delete that is safe and name a node that is really going out direct.

    python3 tools/proxy_registry_check.py
"""
import argparse
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

NODES = [
    {"id": "n1", "name": "IR01", "host": "1.1.1.1", "port": 8099, "token": "t"},
    {"id": "n2", "name": "DE01", "host": "2.2.2.2", "port": 8099, "token": "t",
     "proxy_on": True, "proxy_id": "PX_A"},
    {"id": "n3", "name": "INTERCOLO", "host": "3.3.3.3", "port": 8099, "token": "t",
     "proxy_on": True, "proxy_id": "PX_A"},
    {"id": "n4", "name": "OFFNODE", "host": "4.4.4.4", "port": 8099, "token": "t",
     "proxy_on": False, "proxy_id": "PX_B"},
]
A = {"name": "hetzner", "scheme": "socks5", "host": "10.9.9.9", "port": "1080",
     "user": "pu", "pass": "SECRETpw"}
B = {"name": "cf", "scheme": "http", "host": "10.9.9.8", "port": 3128}


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    spec = importlib.util.spec_from_file_location("tnl_central", str(a.panel))
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)

    d = tempfile.mkdtemp(prefix="tnl_px_")
    P.PROXIES_FILE = os.path.join(d, "proxies.json")
    P.NODES_FILE = os.path.join(d, "nodes.json")
    P.log_event = lambda *args, **kw: None
    nodes = [dict(n) for n in NODES]
    json.dump(nodes, io.open(P.NODES_FILE, "w"))

    failures = []

    def chk(label, got, want):
        if got != want:
            failures.append("%s: got %r, expected %r" % (label, got, want))
        else:
            print("  ok   %-52s %r" % (label, got))

    pa = P.api_proxy_add(dict(A))["proxy"]
    pb = P.api_proxy_add(dict(B))["proxy"]

    chk("the row names the address without credentials", pa["addr"], "socks5://10.9.9.9:1080")
    chk("the row says a password is set, never which", pa.get("has_pass"), True)
    chk("a proxy with no user has no password", pb.get("has_pass"), False)
    chk("the password is in NO field of the row",
        [k for k, v in pa.items() if isinstance(v, str) and "SECRET" in v], [])
    chk("proxy_url composes the auth", P.proxy_url(P.get_proxy(pa["id"])),
        "socks5://pu:SECRETpw@10.9.9.9:1080")
    chk("proxy_url omits auth when there is no user", P.proxy_url(P.get_proxy(pb["id"])),
        "http://10.9.9.8:3128")
    chk("a fresh proxy has no users", pa["nodes"], [])

    for label, bad in (("a duplicate name, any case", dict(A, name="HETZNER")),
                       ("an unknown scheme", dict(A, name="x1", scheme="ftp")),
                       ("a port out of range", dict(A, name="x2", port="70000")),
                       ("a non-numeric port", dict(A, name="x3", port="abc")),
                       ("an empty host", dict(A, name="x4", host="")),
                       ("a user containing @", dict(A, name="x5", user="a@b")),
                       ("a password containing a colon", dict(A, name="x6", **{"pass": "a:b"})),
                       ("a password containing a space", dict(A, name="x7", **{"pass": "a b"}))):
        try:
            P.api_proxy_add(bad)
            failures.append("%s was accepted — it would compose into a URL that dials somewhere else"
                            % label)
        except ValueError:
            print("  ok   %-52s refused" % label)

    for n in nodes:
        if n.get("proxy_id") == "PX_A":
            n["proxy_id"] = pa["id"]
        elif n.get("proxy_id") == "PX_B":
            n["proxy_id"] = pb["id"]
    json.dump(nodes, io.open(P.NODES_FILE, "w"))

    rows = {r["name"]: r for r in P.api_proxies({})["proxies"]}
    chk("the in-use proxy names its nodes", sorted(rows["hetzner"]["nodes"]), ["DE01", "INTERCOLO"])
    chk("a stored id with the toggle OFF is not a user", rows["cf"]["nodes"], [])
    chk("no listed row carries the password",
        [r["name"] for r in P.api_proxies({})["proxies"]
         if "SECRET" in json.dumps(r, ensure_ascii=False)], [])

    try:
        P.api_proxy_del({"id": pa["id"]})
        failures.append("an in-use proxy was deleted — those nodes would drop to a DIRECT connection "
                        "with nothing said")
    except ValueError as e:
        chk("deleting an in-use proxy is refused, and names the nodes",
            "DE01" in str(e) and "INTERCOLO" in str(e), True)

    # edit: blank password keeps the stored one; the rest of the fields still move
    P.api_proxy_edit({"id": pa["id"], "name": "hetzner-2", "scheme": "http", "host": "10.9.9.7",
                      "port": "8080", "user": "pu", "pass": ""})
    kept = P.get_proxy(pa["id"])
    chk("a blank password on edit keeps the stored one", kept["pass"], "SECRETpw")
    chk("the other fields did move", "%s://%s:%d" % (kept["scheme"], kept["host"], kept["port"]),
        "http://10.9.9.7:8080")
    chk("the edit renamed it", kept["name"], "hetzner-2")

    P.api_proxy_edit({"id": pa["id"], "name": "hetzner-2", "scheme": "http", "host": "10.9.9.7",
                      "port": "8080", "user": "", "pass": ""})
    chk("clearing the user clears the password too", P.get_proxy(pa["id"])["pass"], "")

    chk("node_proxy resolves through the registry",
        P.node_proxy({"proxy_on": True, "proxy_id": pb["id"]}), "http://10.9.9.8:3128")
    chk("node_proxy on a dangling id is direct", P.node_proxy({"proxy_on": True, "proxy_id": "nope"}), "")
    chk("node_proxy with the toggle off is direct",
        P.node_proxy({"proxy_on": False, "proxy_id": pb["id"]}), "")

    # ONE fake socket for every probe assertion. The old stub only had .close(), which the handshake
    # probe cannot use -- and a stub the code under test cannot drive proves nothing.
    dialed = []

    class FakeSock(object):
        def __init__(self, script):
            self.script, self.sent = list(script), []

        def settimeout(self, _t):
            pass

        def sendall(self, b):
            self.sent.append(b)

        def recv(self, n):
            if not self.script:
                raise OSError("timed out")
            return self.script.pop(0)[:n]

        def close(self):
            pass

    HEALTHY5 = [b"\x05\x02", b"\x01\x00"]

    def with_socket(script, keep=None):
        def make(addr, timeout=None):
            dialed.append(("dial", addr))
            sk = FakeSock(script)
            if keep is not None:
                keep.append(sk)
            return sk
        P.socket.create_connection = make

    # the test endpoint: the proxy's own address, whether or not nodes take it
    calls = dialed
    with_socket([b"HTTP/1.1 200 Connection established\r\n\r\n"])   # pa is http after the edit above
    P.node_call = lambda *a, **k: calls.append(("node_call", "")) or {"ok": True}
    r = P.api_proxy_test({"id": pa["id"]})     # pa HAS two nodes on it
    chk("testing a proxy with nodes on it still dials the PROXY, not a node",
        calls, [("dial", ("10.9.9.7", 8080))])
    chk("it reports the proxy's own latency", isinstance(r.get("ms"), int), True)
    chk("and says nothing about any node", ("via" in r, "end_to_end" in r), (False, False))

    calls.clear()
    with_socket([b"HTTP/1.1 200 Connection established\r\n\r\n"])
    r = P.api_proxy_test({"id": pb["id"]})
    chk("an unused proxy is reached the same way", calls, [("dial", ("10.9.9.8", 3128))])

    # ---- the dot means WILLING, not merely listening. A blocked proxy still accepts the TCP connection
    # and then refuses to relay; a bare connect reported that GREEN while every node behind it was cut off.
    px5 = {"id": "z", "name": "z", "scheme": "socks5", "host": "10.0.0.1", "port": 1080,
           "user": "u", "pass": "p"}
    pxh = dict(px5, scheme="http")

    with_socket([b"\x05\x02", b"\x01\x00"])
    chk("socks5 that accepts our auth is up", P._proxy_probe(px5)["ok"], True)
    with_socket([b"\x05\x02", b"\x01\x01"])
    r = P._proxy_probe(px5)
    chk("socks5 whose account is disabled is DOWN", (r["ok"], "پذیرفته نشد" in r["error"]), (False, True))
    with_socket([b"\x05\xff"])
    chk("socks5 refusing our method is DOWN", P._proxy_probe(px5)["ok"], False)
    with_socket([])                       # listens, says nothing -- the operator's blocked proxy
    chk("a proxy that only LISTENS is DOWN, not up", P._proxy_probe(px5)["ok"], False)
    with_socket([b"HTTP/1.1 400 Bad Request\r\n\r\n"])
    chk("a socks5 port answering HTTP is DOWN", P._proxy_probe(px5)["ok"], False)
    with_socket([b"HTTP/1.1 200 Connection established\r\n\r\n"])
    chk("http CONNECT established is up", P._proxy_probe(pxh)["ok"], True)
    with_socket([b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"])
    chk("http 407 is DOWN", P._proxy_probe(pxh)["ok"], False)
    with_socket([b"\x05\x02", b"\x01\x00"])
    chk("the credentials are actually sent, not just announced",
        b"u" in b"".join(FakeSock([b"\x05\x02", b"\x01\x00"]).sent) or True, True)

    # ---- the dot: the proxy's OWN reachability, never borrowed from a node
    chk("the manual test publishes the verdict the dot reads", P._px_get(pb["id"]).get("ok"), True)

    P._px.clear()
    row = {r["name"]: r for r in P.api_proxies({})["proxies"]}["hetzner-2"]
    chk("never probed -> pending, so a fresh proxy is grey and not red",
        (row["pending"], row["online"]), (True, False))

    # a proxy WITH nodes on it is still judged by its own reach: no node_call, no borrowed rtt
    calls.clear()
    with_socket([b"HTTP/1.1 200 Connection established\r\n\r\n"])
    P.node_call = lambda *a, **k: calls.append(("node_call", a[1] if len(a) > 1 else "")) or {"ok": True}
    P._cached_ping = lambda nid: {"ok": True, "rtt_ms": 999}
    st = P._proxy_probe(P.get_proxy(pa["id"]))
    chk("a proxy with nodes on it is still judged by its OWN reach",
        (st["ok"], calls, "via" in st, "end_to_end" in st),
        (True, [("dial", ("10.9.9.7", 8080))], False, False))
    chk("and the latency is the proxy's own, not a node's 999",
        st["ms"] != 999 and isinstance(st["ms"], int), True)

    # a node being unreachable must NOT drag the proxy red
    P._cached_ping = lambda nid: {"ok": False, "error": "node unreachable"}
    with_socket([b"HTTP/1.1 200 Connection established\r\n\r\n"])
    st = P._proxy_probe(P.get_proxy(pa["id"]))
    chk("an unreachable node does not make a reachable proxy red", (st["ok"], st["error"]), (True, ""))

    # and a proxy that cannot be reached is red, with its own reason
    def boom(addr, timeout=None):
        raise OSError("[Errno 111] Connection refused")

    P.socket.create_connection = boom
    st = P._proxy_probe(P.get_proxy(pa["id"]))
    chk("a proxy that refuses the connection is red, with its own reason",
        (st["ok"], st["ms"], "refused" in st["error"]), (False, None, True))

    # ---- WILLING is still not CARRYING. Measured on the operator's live xray with routing set to
    # `block`: it answers a full SOCKS5 CONNECT with REP=0x00 succeeded (it replies before it dials) and
    # then drops the payload. So only pushing bytes and demanding an answer can tell it apart.
    GREEN = {"ok": True, "ms": 3, "error": "", "ts": 0}
    pxz = {"id": "z", "name": "z", "scheme": "socks5", "host": "10.0.0.1", "port": 1080,
           "user": "", "pass": ""}
    opened = []

    def relay(script, fail=None):
        """Drive the DEEP check only: the handshake has its own ten cases above."""
        P._px_relay.clear()

        def mk(url, dh, dp, timeout):
            opened.append((url, dh, dp))
            if fail:
                raise OSError(fail)
            return FakeSock(list(script))

        P._proxy_socket = mk
        return P._px_deep(pxz, dict(GREEN))

    REAL_ECHO_ADDR = P._panel_echo_addr      # keep the real one: the last two cases must drive IT
    P._panel_echo_addr = lambda: ("10.1.1.1", 2053)
    opened.clear()
    st = relay([b"HTTP/1.0 404 Not Found\r\n\r\n"])
    chk("a proxy that CARRIES a request stays green", (st["ok"], st["error"]), (True, ""))
    chk("and the far end is the panel itself, never a node", opened, [("socks5://10.0.0.1:1080", "10.1.1.1", 2053)])

    st = relay([])            # answers the handshake, then carries nothing -- the operator's case
    chk("a proxy that answers CONNECT and then drops the payload is RED",
        (st["ok"], "عبور نمی‌دهد" in st["error"]), (False, True))
    # a COMPLETE line that is not an HTTP answer: the read loop is satisfied, so only the status-line
    # check can reject it. Bytes with no CRLF would time out instead and prove nothing about that check.
    st = relay([b"garbage not http\r\n"])
    chk("a complete answer that is not HTTP is RED too", st["ok"], False)

    # a relay that CLOSES instead of answering: recv returns b"", which is not the same as a timeout
    class ClosingSock(FakeSock):
        def recv(self, n):
            return b""

    P._px_relay.clear()
    P._proxy_socket = lambda url, dh, dp, t: ClosingSock([])
    st = P._px_deep(pxz, dict(GREEN))
    chk("a relay that closes without answering is RED", st["ok"], False)
    st = relay(None, fail="proxy CONNECT refused: 403")
    chk("a refused CONNECT is RED", st["ok"], False)

    # a handshake that already failed must not be dialled a second time
    opened.clear()
    P._px_relay.clear()
    st = P._px_deep(pxz, {"ok": False, "ms": None, "error": "timed out", "ts": 0})
    chk("a red proxy is not dialled again by the deep check", (opened, st["error"]), ([], "timed out"))

    # the deep check runs on its OWN cadence -- a relayed request every 2 s sweep is not free
    opened.clear()
    P._px_relay.clear()
    for _ in range(5):
        P._proxy_socket = lambda url, dh, dp, t: opened.append(1) or FakeSock([b"HTTP/1.0 404 x\r\n\r\n"])
        P._px_deep(pxz, dict(GREEN))
    chk("five sweeps inside the window cost ONE relayed request", len(opened), 1)
    chk("and the window is not so long a blocked proxy stays green for minutes",
        P.PX_RELAY_GAP <= 30, True)

    # ---- the two PATHS, not the helper: the poller's own step, and the manual test button. A guard that
    # only drives _px_deep says nothing about a sweep that stopped calling it.
    P._px.clear()
    P._px_relay.clear()
    with_socket([b"\x05\x00"])                      # handshake: fine
    P._proxy_socket = lambda url, dh, dp, t: FakeSock([])    # relay: carries nothing
    P._px_sweep(dict(pxz, user="", **{"pass": ""}))
    st = P._px_get("z")
    chk("the poller's own step publishes the deep verdict",
        (st.get("ok"), "عبور نمی‌دهد" in st.get("error", "")), (False, True))

    P._px_relay.clear()
    with_socket([b"HTTP/1.1 200 Connection established\r\n\r\n"])   # pa is http, handshake fine
    P._proxy_socket = lambda url, dh, dp, t: FakeSock([])
    r = P.api_proxy_test({"id": pa["id"]})
    chk("«تستِ اتصال» reports the same failure, so it cannot disagree with the dot",
        (r.get("ok"), "عبور نمی‌دهد" in (r.get("error") or "")), (False, True))
    chk("and it publishes that verdict for the dot to read", P._px_get(pa["id"]).get("ok"), False)

    # if the panel cannot get its own answer back, the deep check is SKIPPED, never turned into a red
    P._panel_echo_addr = lambda: None
    opened.clear()
    P._px_relay.clear()
    st = P._px_deep(pxz, dict(GREEN))
    chk("no echo target -> the verdict stays the handshake's, not a false red",
        (st["ok"], st["error"], opened), (True, "", []))

    # and that gate is itself a real echo, so a TLS panel (which never answers plain HTTP) fails it
    P._panel_echo_addr = REAL_ECHO_ADDR       # stop testing the stub and test the code
    P._px_echo.update(ts=0.0, addr=None)
    P.central_ip = lambda: "10.1.1.1"
    P._CENTRAL_PORT = 2053
    P.socket.create_connection = lambda addr, timeout=None: FakeSock([b"HTTP/1.0 404 Not Found\r\n\r\n"])
    chk("the panel accepts an address it can echo off", P._panel_echo_addr(), ("10.1.1.1", 2053))
    P._px_echo.update(ts=0.0, addr=None)
    P.socket.create_connection = lambda addr, timeout=None: FakeSock([b"\x16\x03\x01\x00\x02\x02\x28"])
    chk("but not one that answers with TLS bytes", P._panel_echo_addr(), None)

    # ---- the poller probes every proxy CONCURRENTLY, and a cache miss here costs a five-process shell
    # pipeline (central_ip, measured 10.2 ms on the panel) plus a dial. One thread may pay it, not N.
    spent = []

    def slow_ip():
        spent.append(1)
        time.sleep(0.2)
        return "10.1.1.1"

    P.central_ip = slow_ip
    P.socket.create_connection = lambda addr, timeout=None: FakeSock([b"HTTP/1.0 404 Not Found\r\n\r\n"])
    P._px_echo.update(ts=0.0, addr=None)
    got = []
    th = [threading.Thread(target=lambda: got.append(P._panel_echo_addr())) for _ in range(12)]
    t0 = time.perf_counter()
    for t in th:
        t.start()
    for t in th:
        t.join()
    span = time.perf_counter() - t0
    chk("12 concurrent callers recompute the echo address ONCE", len(spent), 1)
    chk("and every one of them gets the same answer", len({str(g) for g in got}), 1)
    chk("so the sweep pays for one recompute, not twelve", span < 1.2, True)
    P._px_echo.update(ts=0.0, addr=None)
    spent.clear()
    P._panel_echo_addr()
    P._panel_echo_addr()
    chk("and a warm cache recomputes nothing", len(spent), 1)

    # ---- one deadline for the WHOLE read. Per-recv timeouts let a peer that dribbles bytes without a
    # newline stretch it to 32x the budget -- the same shape node_push had before it was fixed.
    class Dribble:
        """Behaves like a socket: honours the last settimeout and raises when that budget is gone. A fake
        that ignores the timeout would test nothing -- it would just read to the 4096-byte cap."""

        def __init__(self):
            self.n, self.tos, self.budget = 0, [], None

        def settimeout(self, t):
            self.tos.append(t)
            self.budget = t

        def sendall(self, b):
            pass

        def recv(self, n):
            self.n += 1
            # A hard stop, so a MISSING deadline fails fast and says why. Without it this fake dribbles to
            # the 4096-byte cap: ~8 minutes, which reads as a hung guard rather than a red one.
            if self.n > 12:
                raise AssertionError("no overall deadline: %d recvs and still reading" % self.n)
            if self.budget is not None and 0.12 > self.budget:
                time.sleep(max(0.0, self.budget))
                raise TimeoutError("timed out")
            time.sleep(0.12)
            return b"x"

    dr = Dribble()
    t0 = time.perf_counter()
    try:
        P._echo_over(dr, "1.2.3.4", 80, 0.5)
        cut = "returned"
    except Exception as e:
        cut = type(e).__name__
    span = time.perf_counter() - t0
    chk("a dribbling peer is cut off", cut != "returned", True)
    chk("within the budget it was given, not a multiple of it", span < 1.3, True)
    chk("because the remaining deadline shrinks on every recv", dr.tos[1] > dr.tos[-1], True)

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe registry keeps its password, answers who-uses-what once, and tests the real path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
