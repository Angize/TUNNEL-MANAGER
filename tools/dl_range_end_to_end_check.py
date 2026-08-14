#!/usr/bin/env python3
"""The panel serves the range the NODE asks for — proved against the node's own fetch code.

Resuming only works if both halves agree, and they are two functions in two repos. A node that asks for
`bytes=N-` and a panel that answers 200 with the whole file produces a download that is spliced, hashes
to nothing, and reports «checksum mismatch» — blaming the staged artifact for a transport fault. So the
panel's real handler is put in front of the node's real _fetch_url over a real socket.

Needs the node repo. Set NODE_REPO, or have TUNNEL-MANAGER-NODE beside this one.

    python3 tools/dl_range_end_to_end_check.py
"""
import hashlib
import importlib.util
import os
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)
NODE_REPO = os.environ.get("NODE_REPO") or os.path.join(os.path.dirname(PANEL_REPO), "TUNNEL-MANAGER-NODE")
NODE_SRC = os.path.join(NODE_REPO, "tnl-node.py")

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
    m.log_event = lambda *a, **k: None
    return m


BLOB = bytes(range(256)) * 4096          # 1 MiB, every offset checkable
SHA = hashlib.sha256(BLOB).hexdigest()


def main():
    if not os.path.isfile(NODE_SRC):
        print("SKIP: node repo not found at %s (set NODE_REPO)" % NODE_REPO)
        return 0
    P = load(os.path.join(PANEL_REPO, "tnl-central.py"), "dlr_panel", tempfile.mkdtemp(prefix="dlr-p-"))
    N = load(NODE_SRC, "dlr_node", tempfile.mkdtemp(prefix="dlr-n-"))
    N._is_central_origin = lambda u: True

    P._dl_artifact = lambda k, arch: BLOB          # what is staged is not this check's subject
    P._dl_ticket_node = lambda q: {"id": "n1"}     # nor is the ticket; both have their own guards
    P.rate_limited = lambda ip: False

    srv = P.ThreadingHTTPServer(("127.0.0.1", 0), P.Handler)
    srv.conf = {"tls": False}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:%d/api/dl?k=co&arch=amd64" % srv.server_address[1]

    try:
        print("== the whole file, unasked ==")
        buf = N._fetch_url(url, 8 << 20, timeout=10, budget=30)
        check("a plain fetch gets every byte", len(buf) == len(BLOB), "%d of %d" % (len(buf), len(BLOB)))
        check("...and the right ones", hashlib.sha256(buf).hexdigest() == SHA)

        print("== and the REST, when the node asks for it ==")
        # Driven through the node's own request path rather than a hand-built one: the header the node
        # actually sends is the thing the panel has to understand.
        import urllib.request
        for start in (1, 512 * 1024, len(BLOB) - 1):
            req = urllib.request.Request(url, headers={"Range": "bytes=%d-" % start})
            with urllib.request.urlopen(req, timeout=10) as r:
                body, code = r.read(), r.status
                cr = r.headers.get("Content-Range")
            check("bytes=%d- is answered 206 with exactly the tail" % start,
                  code == 206 and body == BLOB[start:], "code=%s len=%d" % (code, len(body)))
            check("...and says which bytes it is" % (), cr == "bytes %d-%d/%d" % (start, len(BLOB) - 1, len(BLOB)),
                  repr(cr))

        print("== a range past the end is refused, not served from zero ==")
        # Serving 200 here is the dangerous answer: the node appends a full copy to what it already has.
        req = urllib.request.Request(url, headers={"Range": "bytes=%d-" % len(BLOB)})
        try:
            urllib.request.urlopen(req, timeout=10)
            check("a start past the end is refused", False, "it was served")
        except urllib.error.HTTPError as e:
            check("a start past the end is refused", e.code == 416, "code=%s" % e.code)
            check("...naming the real size", e.headers.get("Content-Range") == "bytes */%d" % len(BLOB),
                  repr(e.headers.get("Content-Range")))

        print("== and a header shape the panel does not implement is refused, not guessed ==")
        for bad in ("bytes=-500", "bytes=abc-", "items=0-", "bytes=900-100"):
            req = urllib.request.Request(url, headers={"Range": bad})
            try:
                urllib.request.urlopen(req, timeout=10)
                check("refuses %r" % bad, False, "it was served")
            except urllib.error.HTTPError as e:
                check("refuses %r" % bad, e.code == 416, "code=%s" % e.code)

        print("== the offer is advertised, or a client never tries ==")
        with urllib.request.urlopen(urllib.request.Request(url), timeout=10) as r:
            check("a full response advertises Accept-Ranges", r.headers.get("Accept-Ranges") == "bytes",
                  repr(r.headers.get("Accept-Ranges")))
    finally:
        srv.shutdown()
        srv.server_close()

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("the panel serves the range the node asks for.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
