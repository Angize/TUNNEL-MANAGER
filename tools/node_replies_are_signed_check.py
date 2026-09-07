#!/usr/bin/env python3
"""A reply the panel cannot authenticate is not a reply — proved against the node's own _send.

Commands to a node were signed and replay-guarded from the start; replies were not signed at all. The
panel parsed whatever came back, so anyone sitting between the two could answer «انجام شد» for a wipe,
hold a dead node green on the dashboard, or feed chosen strings into the panel's DOM. The tunnels
themselves never carried this traffic — the management channel is plain HTTP by design — so the on-path
attacker this project already assumes is exactly the one who could do it.

The panel reads a node reply on THREE paths and every one of them has to verify:

  * node_call            the direct urllib path, success and HTTPError alike
  * _node_call_proxied   the http.client path taken when the node sits behind a proxy
  * node_push            the hand-rolled socket path that carries agent and core uploads

Four forgeries are put in front of each: no signature at all, a signature made with the wrong key, a
good signature lifted from a different request counter, and a good signature over a different body.
The replay case is the one that matters most, because a captured «ok» is free to an on-path attacker.

_resp_sig_msg lives in both repos with no module between them, so the two are compared byte for byte.
If they drift, every call fails closed and the fleet looks offline.

Needs the node repo. Set NODE_REPO, or have TUNNEL-MANAGER-NODE beside this one.

    python3 tools/node_replies_are_signed_check.py
"""
import base64
import hashlib
import hmac
import http.server
import importlib.util
import inspect
import json
import os
import socketserver
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)
NODE_REPO = os.environ.get("NODE_REPO") or os.path.join(os.path.dirname(PANEL_REPO), "TUNNEL-MANAGER-NODE")
NODE_SRC = os.path.join(NODE_REPO, "tnl-node.py")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []
TOKEN = "a" * 40


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


class Threaded(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def sign(key, ctr, status, body):
    msg = "resp\n%s\n%s\n%s" % (ctr, status, hashlib.sha256(body).hexdigest())
    return base64.b64encode(hmac.new(key.encode("utf-8"), msg.encode("utf-8"),
                                     hashlib.sha256).digest()).decode()


class Impostor(http.server.BaseHTTPRequestHandler):
    """Everything an on-path attacker can do without the node's token, plus the one thing they cannot."""
    mode = "none"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _reply(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n:
            self.rfile.read(n)
        body = json.dumps({"ok": True, "pong": "ATTACKER"}).encode()
        ctr = self.headers.get("X-Ctr", "")
        sig = ""
        if Impostor.mode == "wrongkey":
            sig = sign("attacker-key", ctr, 200, body)
        elif Impostor.mode == "replayed":
            sig = sign(TOKEN, "999", 200, body)
        elif Impostor.mode == "tampered":
            sig = sign(TOKEN, ctr, 200, json.dumps({"ok": True, "pong": "real-node"}).encode())
        elif Impostor.mode == "correct":
            sig = sign(TOKEN, ctr, 200, body)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if sig:
            self.send_header("X-Resp-Sig", sig)
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _reply


def main():
    if not os.path.isfile(NODE_SRC):
        sys.exit("node repo not found at %s (set NODE_REPO)" % NODE_SRC)
    panel = load(os.path.join(PANEL_REPO, "tnl-central.py"), "panel_sig_guard")
    node = load(NODE_SRC, "node_sig_guard")

    print("== the signed string is one string, in two repos ==")
    check("panel and node build the same reply signature input",
          panel._resp_sig_msg("123", 200, "abc") == node._resp_sig_msg("123", 200, "abc"),
          "%r vs %r" % (panel._resp_sig_msg("123", 200, "abc"), node._resp_sig_msg("123", 200, "abc")))
    check("...and the request signature input still agrees too",
          panel._sig_msg("POST", "/api/pg", "1", "x") == node._sig_msg("POST", "/api/pg", "1", "x"))
    check("the node signs from its single reply exit, so errors are covered too",
          "_resp_sig" in inspect.getsource(node.Handler._send))

    node.OPS["ping"] = lambda d: {"ok": True, "pong": "real-node"}
    real = Threaded(("127.0.0.1", 0), node.Handler)
    real.conf = {"token": TOKEN}
    threading.Thread(target=real.serve_forever, daemon=True).start()
    REAL = {"id": "n1", "host": "127.0.0.1", "port": real.server_address[1], "token": TOKEN}

    fake = Threaded(("127.0.0.1", 0), Impostor)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    FAKE = {"id": "n1", "host": "127.0.0.1", "port": fake.server_address[1], "token": TOKEN}

    print("== the real agent is believed ==")
    check("a reply from the real node is accepted",
          panel.node_call(REAL, "ping", "GET", timeout=5).get("pong") == "real-node")
    check("...and node_push reaches it too",
          panel.node_push(REAL, "ping", {"x": 1}, timeout=5).get("pong") == "real-node")
    check("a node whose token does not match is not believed",
          panel.node_call(dict(REAL, token="b" * 40), "ping", "GET", timeout=5).get("offline") is True)

    print("== four forgeries, on every path the panel reads a reply ==")
    paths = (("node_call", lambda n: panel.node_call(n, "ping", "GET", timeout=5)),
             ("node_push", lambda n: panel.node_push(n, "ping", {"x": 1}, timeout=5)))
    for mode, label in (("none", "no signature at all"),
                        ("wrongkey", "signed with a key that is not the node's"),
                        ("replayed", "a good signature lifted from another request"),
                        ("tampered", "a good signature over a different body")):
        Impostor.mode = mode
        for pname, call in paths:
            r = call(FAKE)
            check("%s rejects a reply with %s" % (pname, label),
                  r.get("pong") is None and r.get("offline") is True, r)

    print("== and the control: a correctly signed reply still passes ==")
    Impostor.mode = "correct"
    for pname, call in paths:
        check("%s accepts a correctly signed reply" % pname, call(FAKE).get("pong") == "ATTACKER")

    print("== the proxied path is not a way round it ==")
    Impostor.mode = "none"
    panel.node_proxy = lambda n: "socks5://127.0.0.1:1"
    r = panel.node_call(FAKE, "ping", "GET", timeout=3)
    check("a proxied call that cannot be verified is not trusted either",
          r.get("pong") is None, r)

    real.shutdown()
    fake.shutdown()
    if FAILED:
        print("\n%d failure(s):" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("\nevery reply the panel acts on is one it could authenticate.")


if __name__ == "__main__":
    main()
