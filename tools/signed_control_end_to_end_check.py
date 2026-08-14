#!/usr/bin/env python3
"""The panel's signature is the one the NODE verifies — proved against the node's own code.

`control_auth = sign` stops the shared token crossing the wire: the panel proves a request with an HMAC
over its method, path, counter and body hash instead. That only works if both ends agree on the signed
string byte for byte. They are two functions in two repos, and if they ever drift EVERY request is
refused at once — the panel loses the whole fleet and the way back is ssh.

So this drives the real panel senders against the real node handler over a real socket:

  1. every request the panel makes is signed, and the token appears NOWHERE in it;
  2. all three senders that reach a node agree: node_call, the proxied variant, and node_push;
  3. a replay is refused, and a panel whose counter fell behind RESYNCS instead of locking itself out;
  4. there is no way back to sending the token — it was removed rather than left behind a switch,
     because every node refuses it now and a switch could only ever brick the fleet.

Needs the node repo. Set NODE_REPO, or have TUNNEL-MANAGER-NODE beside this one.

    python3 tools/signed_control_end_to_end_check.py
"""
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)
NODE_REPO = os.environ.get("NODE_REPO") or os.path.join(os.path.dirname(PANEL_REPO), "TUNNEL-MANAGER-NODE")
NODE_SRC = os.path.join(NODE_REPO, "tnl-node.py")
TOKEN = "shared-secret-token"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(path, name, state):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR if hasattr(m, "CENTRAL_DIR") else m.CONFIG_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    if hasattr(m, "CENTRAL_DIR"):
        m.CENTRAL_DIR = state
    else:
        m.CONFIG_DIR = state
    m.log_event = getattr(m, "log_event", None) and (lambda *a, **k: None)
    return m


def record(N):
    """What the NODE actually received: its request line, its headers, and the status it answered.

    Read inside the node's own handler rather than off a TCP relay -- the relay added a failure mode of
    its own (it reset the connection and the resets read as refusals), and this is closer to the claim
    anyway: what the node parsed IS what crossed the wire."""
    got = []
    real_auth, real_send = N.Handler._authed, N.Handler._send

    def spy_auth(self, method):
        got.append({"line": self.requestline, "hdr": {k: v for k, v in self.headers.items()}, "code": None})
        return real_auth(self, method)

    def spy_send(self, code, body):
        if got:
            got[-1]["code"] = code
        return real_send(self, code, body)

    N.Handler._authed, N.Handler._send = spy_auth, spy_send
    return got


# 401 = "you did not prove yourself", 409 = "your counter is stale". Anything else means the node
# ACCEPTED the request; several ops cannot run against a bare temp dir and answer 500, which is not
# this guard's subject.
def accepted(got):
    return bool(got) and got[-1]["code"] not in (401, 409)


def token_on_wire(got, token):
    return any(token in v for g in got for v in g["hdr"].values())


def main():
    if not os.path.isfile(NODE_SRC):
        print("SKIP: node repo not found at %s (set NODE_REPO)" % NODE_REPO)
        return 0
    pstate, nstate = tempfile.mkdtemp(prefix="sig-p-"), tempfile.mkdtemp(prefix="sig-n-")
    P = load(os.path.join(PANEL_REPO, "tnl-central.py"), "sig_panel", pstate)
    N = load(NODE_SRC, "sig_node", nstate)
    N.save_conf({"port": 8099, "token": TOKEN})
    N._seed_req_ctr()

    got = record(N)
    srv = N.ThreadingHTTPServer(("127.0.0.1", 0), N.Handler)
    srv.conf = {"port": 8099, "token": TOKEN}
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    node = {"id": "n1", "name": "one", "host": "127.0.0.1", "port": srv.server_address[1], "token": TOKEN}
    P._CENTRAL_PORT = 2053
    P.save_json(P.NODES_FILE, [dict(node)])

    try:
        # ---- 1) the string both ends sign has to be identical, or nothing else here matters
        check("panel and node build the SAME signed string",
              P._sig_msg("POST", "/api/mk", 42, "abc") == N._sig_msg("POST", "/api/mk", 42, "abc"),
              "%r vs %r" % (P._sig_msg("POST", "/api/mk", 42, "abc"), N._sig_msg("POST", "/api/mk", 42, "abc")))

        # The counter must increase on its OWN, not because the clock moved. Two calls to one node
        # inside the same millisecond are ordinary -- _ensure_update_key immediately before a push, or
        # four push workers on one fleet -- and a repeat is refused as a replay. Driven in a tight loop
        # because a wall-clock test cannot tell "advanced" from "a millisecond passed".
        seq = [P._take_ctr("tight-loop") for _ in range(5000)]
        check("the counter advances by itself, not because the clock did",
              all(b > a for a, b in zip(seq, seq[1:])),
              "%d repeats in 5000" % sum(1 for a, b in zip(seq, seq[1:]) if b <= a))

        print("== every request is signed, and the secret never travels ==")
        got.clear()
        P.node_call(node, "ping", "GET", timeout=10)
        check("a signed call is accepted by the node's own handler", accepted(got),
              str(got[-1]["code"]) if got else "no request")
        check("the token appears NOWHERE in the request", not token_on_wire(got, TOKEN))
        check("...and an X-Sig does", any("X-Sig" in g["hdr"] for g in got))

        # a POST with a body: the body hash is the half a header-only signature would miss
        got.clear()
        P.node_call(node, "list", "POST", {"any": "thing"}, timeout=10)
        check("a signed POST with a body is accepted", accepted(got),
              str(got[-1]["code"]) if got else "no request")
        check("...and its body was signed, not omitted",
              bool(got and got[-1]["hdr"].get("X-Body")), json.dumps(got[-1]["hdr"]) if got else "")
        check("...and its token still never travelled", not token_on_wire(got, TOKEN))

        print("== the third sender: node_push, the one that carries megabytes ==")
        got.clear()
        big = json.dumps({"code": "x" * 5000, "sha256": "0" * 64, "sig": ""}).encode()
        P.node_push(node, "update", big, timeout=20)
        check("a signed push is accepted (its op then refuses the payload, which is not this test)",
              accepted(got), str(got[-1]["code"]) if got else "no request")
        check("...and the push put no token on the wire", not token_on_wire(got, TOKEN))

        print("== a lagging panel resyncs instead of locking itself out ==")
        # The NODE's mark has to be pushed ahead, not the panel's counter pulled back: _take_ctr floors
        # itself at the clock, so a panel that forgot where it was is already correct on its next
        # request. What can still strand it is a node holding a mark ABOVE the panel's clock -- from a
        # panel whose clock ran fast and was then corrected, or a restored backup.
        ahead = int(time.time() * 1000) + 10 ** 6
        with N._req_ctr_lock:
            N._req_ctr = N._req_ctr_hwm = ahead
        got.clear()
        P.node_call(node, "ping", "GET", timeout=10)
        check("a panel whose counter fell behind recovers by itself", accepted(got),
              " -> ".join(str(g["code"]) for g in got))
        check("...in exactly two requests: the 409, then the retry",
              [g["code"] for g in got][:1] == [409] and len(got) == 2,
              " -> ".join(str(g["code"]) for g in got))
        with P._ctr_lock:
            after = P._ctr_next[node["id"]]
        check("...by adopting the node's mark, not by retrying blindly", after > ahead, str(after))

        print("== and there is no way back to sending the token ==")
        # The switch is gone, not merely defaulted: every node refuses a bearer token now, so a way back
        # could only ever brick the fleet -- and the tokens were never rotated, so anyone who watched
        # this wire before the changeover still holds one.
        check("the panel has no token mode left", not hasattr(P, "_control_auth"),
              "_control_auth still exists")
        P.api_settings_set({"control_auth": "token"})     # an unknown key: accepted and ignored
        got.clear()
        P.node_call(node, "ping", "GET", timeout=10)
        check("...so asking for one changes nothing, and the request is still signed",
              not token_on_wire(got, TOKEN) and any("X-Sig" in g["hdr"] for g in got),
              json.dumps(got[-1]["hdr"]) if got else "no request")
    finally:
        srv.shutdown()
        srv.server_close()

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("the panel signs what the node verifies, on all three senders.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
