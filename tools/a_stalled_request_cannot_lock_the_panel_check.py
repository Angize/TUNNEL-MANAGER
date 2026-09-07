#!/usr/bin/env python3
"""A few bytes a second must not take the control plane away from the operator.

Two separate mistakes, and either one alone is enough to lose the panel:

  * The worker permit was taken in process_request, which socketserver runs on the ACCEPT LOOP. Once
    every permit was held, acquire() blocked the accept loop itself, so the panel stopped answering
    anybody — not a slow panel, a silent one. The permit must be taken without blocking and the
    connection refused outright when there is none.

  * Handler.timeout is a per-read idle timeout, so a client that sends one byte before each window
    holds its worker forever while costing nothing. Reading the request line and headers needs a
    wall-clock budget on top, after which the connection goes.

Both are exercised over real sockets against the real Handler, because the failure is in the plumbing
and not in anything a shape test can see. The 503 body is deliberately NOT asserted: delivering it
reliably would mean lingering on a socket with unread data, which is the very thing being avoided. What
is asserted is that the answer is immediate and is not service.

    python3 tools/a_stalled_request_cannot_lock_the_panel_check.py
"""
import importlib.util
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []
WORKERS = 4
BUDGET = 2.0


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + str(detail)) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load():
    spec = importlib.util.spec_from_file_location("panel_dos_guard",
                                                  os.path.join(PANEL_REPO, "tnl-central.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["panel_dos_guard"] = m
    spec.loader.exec_module(m)
    return m


def main():
    m = load()

    class H(m.Handler):
        header_budget = BUDGET
        timeout = 30

    class S(m.BoundedThreadingHTTPServer):
        _MAX_WORKERS = WORKERS
        _sem = threading.BoundedSemaphore(WORKERS)

    srv = S(("127.0.0.1", 0), H)
    srv.conf = {}
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def request(timeout=8.0):
        t0 = time.time()
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.settimeout(timeout)
        data = b""
        try:
            s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            while True:
                b = s.recv(65536)
                if not b:
                    break
                data += b
        except socket.timeout:
            return "HUNG", time.time() - t0
        except (ConnectionAbortedError, ConnectionResetError):
            pass
        finally:
            s.close()
        if not data:
            return "REFUSED", time.time() - t0
        return data.split(b"\r\n")[0].decode(errors="replace"), time.time() - t0

    print("== an idle panel serves ==")
    line, _ = request()
    check("a normal request is answered", line == "HTTP/1.0 200 OK", line)

    print("== with every worker stalled, the accept loop is still alive ==")
    stalled = []
    for _ in range(WORKERS):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"GET / HTTP/1.1\r\n")
        stalled.append(s)
    time.sleep(0.5)
    line, el = request(timeout=6.0)
    check("a new client is answered rather than left hanging", line != "HUNG", "%r after %.2fs" % (line, el))
    check("...immediately, not after a timeout", el < 3.0, "%.2fs" % el)
    check("...and refused rather than served", "HTTP/1.0 200" not in line, line)

    print("== and a trickle does not get to keep its worker ==")
    t0 = time.time()
    dropped = None
    try:
        stalled[0].settimeout(BUDGET * 4)
        while True:
            if not stalled[0].recv(4096):
                dropped = time.time() - t0
                break
    except socket.timeout:
        dropped = None
    except OSError:
        dropped = time.time() - t0
    check("a stalled request is dropped by the server", dropped is not None)
    check("...inside the header budget", dropped is not None and dropped <= BUDGET * 3,
          "%.2fs vs budget %.1fs" % (dropped or -1, BUDGET))

    drip = socket.create_connection(("127.0.0.1", port), timeout=10)
    drip.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")
    t0, dead = time.time(), False
    try:
        while time.time() - t0 < BUDGET * 3:
            drip.sendall(b"X-Pad: 1\r\n")
            time.sleep(0.3)
    except OSError:
        dead = True
    check("dribbling a byte before each idle window does not extend the hold", dead)
    try:
        drip.close()
    except OSError:
        pass

    for s in stalled:
        try:
            s.close()
        except OSError:
            pass
    time.sleep(BUDGET + 1.0)
    line, _ = request()
    check("the panel serves again once the flood lets go", line == "HTTP/1.0 200 OK", line)

    print("== the shape that made it possible is gone ==")
    import inspect
    pr = inspect.getsource(m.BoundedThreadingHTTPServer.process_request)
    check("the accept loop never blocks on the permit", "blocking=False" in pr, pr)
    check("a request line and headers have a wall-clock budget", isinstance(m.Handler.header_budget, (int, float)))

    srv.shutdown()
    if FAILED:
        print("\n%d failure(s):" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        sys.exit(1)
    print("\nthe panel cannot be taken away with a trickle.")


if __name__ == "__main__":
    main()
