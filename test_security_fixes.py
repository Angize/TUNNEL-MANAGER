#!/usr/bin/env python3
# Tests for the security hardening: stored-XSS data-* refactor, /api/checkin rate limiting,
# manual node-token strength floor, and the CSP response header. No server/root/network needed.
# Run: python3 test_security_fixes.py
import importlib.util
import io
import os
import re
import shutil
import subprocess
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


# --------------------------------------------------------------------------- 1) stored XSS
# Node strings must NOT be interpolated into inline-handler JS strings anymore; they ride
# in data-* attributes (attribute-escaped via esc) and the handlers read them from `this`.
html = tnl.INDEX_HTML

check("cor button uses onclick=corMenu(this)", 'onclick="corMenu(this)"' in html)
check("cor button carries data-nid/data-cur", 'data-nid="' in html and 'data-cur="' in html)
check("corMenu reads data-nid/data-cur from the button",
      "function corMenu(btn){var id=btn.getAttribute('data-nid');var cur=btn.getAttribute('data-cur')" in html)
check("corPick reads data-nid/data-v from the row",
      "function corPick(row){var id=row.getAttribute('data-nid');var ver=row.getAttribute('data-v')" in html)
check("cor menu row uses onclick=corPick(this)", 'onclick="corPick(this)"' in html)
check("del button uses onclick=delNode(this) with data-nm", 'onclick="delNode(this)"' in html and 'data-nm="' in html)
check("delNode reads data-nid/data-nm from the button",
      "function delNode(btn){var id=btn.getAttribute('data-nid');var nm=btn.getAttribute('data-nm')" in html)

# The vulnerable pattern (a node string interpolated into a quoted arg of an inline on*= handler)
# must be gone. In the runtime JS these looked like  onclick="corMenu(\'..'+esc(..)+'..\')".
check("no corMenu(\\' inline-JS interpolation remains", "corMenu(\\'" not in html)
check("no delNode(...,esc(name)) inline-JS interpolation remains", "esc(n.name)+'\\')" not in html)
# No on*= handler embeds an esc()-encoded value inside a single-quoted JS string literal.
bad = re.findall(r"on\w+=\"[^\"]*\\'[^\"]*esc\(", html)
check("no on*= handler embeds esc() into a JS-string literal", not bad)

# The extracted <script> still parses (structural guard; a real quote-breakout would break syntax).
scripts = re.findall(r"<script[^>]*>(.*?)</script>", html, re.DOTALL)
check("exactly one <script> block extracted", len(scripts) == 1)
node = shutil.which("node") or ("/opt/node22/bin/node" if os.path.exists("/opt/node22/bin/node") else None)
if node:
    p = os.path.join(HERE, "_xss_check.js")
    open(p, "w").write(scripts[0])
    rc = subprocess.run([node, "--check", p], capture_output=True, text=True)
    check("node --check passes on the embedded script", rc.returncode == 0)
    if rc.returncode != 0:
        print(rc.stderr)
    os.remove(p)
else:
    print("skip  node --check (node not found)")


# --------------------------------------------------------------------------- 2) checkin rate limit + token floor
def make_handler(peer="203.0.113.5", conf=None, body=None):
    h = tnl.Handler.__new__(tnl.Handler)      # bypass BaseHTTPRequestHandler.__init__ (no socket)
    h.client_address = (peer, 5555)
    h._conf = lambda: (conf or {})
    h.headers = {}
    h._body = lambda cap=1048576: (body or {})
    sent = {}

    def _send(code, b, ctype="application/json", extra=None):
        sent["code"], sent["body"] = code, b
    h._send = _send
    return h, sent


tnl.load_nodes = lambda: []          # no file IO: every checkin is an "unknown node" -> auth failure
tnl._fails.clear()

# 8 failing check-ins are allowed, each recorded; the 9th is throttled before touching the handler.
for i in range(8):
    h, sent = make_handler(body={"token": "z" * 40})
    h._checkin()
    if sent["code"] != 401:
        check("failing checkin returns 401 (attempt %d)" % (i + 1), False)
        break
else:
    check("8 failing check-ins each return 401", True)

check("failed check-ins are recorded in the shared limiter", tnl.rate_limited("203.0.113.5"))
h, sent = make_handler(body={"token": "z" * 40})
h._checkin()
check("9th check-in from same IP is rate-limited (429)", sent["code"] == 429)

# A different source IP is unaffected by another IP's failures.
h2, sent2 = make_handler(peer="198.51.100.9", body={"token": "z" * 40})
h2._checkin()
check("a fresh source IP is not throttled", sent2["code"] == 401)

# token strength floor in api_node_add: a manually supplied short token is rejected.
try:
    tnl.api_node_add({"name": "n1", "host": "10.0.0.1", "port": 8080, "token": "short"})
    check("manual token < 16 chars rejected", False)
except ValueError as e:
    check("manual token < 16 chars rejected", "short" in str(e) or "16" in str(e))

# an empty token is still rejected (unchanged behavior)
try:
    tnl.api_node_add({"name": "n1", "host": "10.0.0.1", "port": 8080, "token": "   "})
    check("empty token still rejected", False)
except ValueError:
    check("empty token still rejected", True)

# a 16+ char token passes the length gate (fails later only at the network/ping stage, not on length)
tnl.save_json = lambda *a, **k: None
tnl.node_call = lambda *a, **k: {"ok": False, "error": "unreachable"}
tnl._refresh_cache = lambda *a, **k: None
tnl._name_taken = lambda nodes, name: False
tnl._host_taken = lambda nodes, host: False
try:
    r = tnl.api_node_add({"name": "n1", "host": "10.0.0.1", "port": 8080, "token": "a" * 16})
    check("16-char manual token is accepted (passes length floor)", r.get("ok") is True)
except ValueError as e:
    check("16-char manual token is accepted (passes length floor)", False)
    print("  unexpected:", e)


# --------------------------------------------------------------------------- 3) CSP header
h = tnl.Handler.__new__(tnl.Handler)
hdrs = {}
h.send_response = lambda code: None
h.send_header = lambda k, v: hdrs.__setitem__(k, v)
h.end_headers = lambda: None
h.wfile = io.BytesIO()
h._send(200, "<html>hi</html>", "text/html; charset=utf-8")

csp = hdrs.get("Content-Security-Policy", "")
check("CSP header is present", bool(csp))
check("CSP allows inline scripts (UI needs it)", "script-src 'self' 'unsafe-inline'" in csp)
check("CSP allows Google-Fonts stylesheet import", "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com" in csp)
check("CSP allows gstatic fonts", "font-src https://fonts.gstatic.com" in csp)
check("CSP allows data: images", "img-src 'self' data:" in csp)
check("CSP locks down objects/base/framing", "object-src 'none'" in csp and "base-uri 'none'" in csp and "frame-ancestors 'none'" in csp)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all security-fix tests passed")
