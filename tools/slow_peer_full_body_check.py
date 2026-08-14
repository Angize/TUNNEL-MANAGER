#!/usr/bin/env python3
"""A slow peer gets the WHOLE body; a stalled one still gets cut.

`Handler.timeout` is a socket timeout, and a socket timeout applies PER BLOCKING CALL. Writing a whole
response in one call therefore puts ONE deadline on the entire transfer, which is right for a few KB of
JSON and wrong for /api/dl, the one endpoint that returns megabytes.

MEASURED against the live panel before this was fixed: an 11,243,704-byte core to a node on a
~60-140 KB/s link arrived as 5,613,896 bytes -- behind a correct Content-Length, with no error on either
side -- and the node reported «checksum mismatch», blaming the staged file for a transfer that was cut.

Both halves are the property, and a guard that checked only the first would pass on the obvious wrong
fix (delete the timeout), which hands any stalled peer a worker thread forever:

  1. a peer that reads slowly but keeps reading must receive every byte;
  2. a peer that stops reading altogether must still be dropped.

Driven against the REAL Handler over a REAL socket, with the send buffer pinned small so the kernel
cannot absorb the body and make the test vacuous.

    python3 tools/slow_peer_full_body_check.py
"""
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []
SNDBUF = 16 * 1024          # pin it small: with a big kernel buffer the server never blocks and this
RCVBUF = 16 * 1024          # test would pass no matter how the body is written
TIMEOUT = 2                 # stand-in for the shipped 60s, so the test costs seconds not minutes
BODY = 2 * 1024 * 1024      # >> SNDBUF, so the write really does have to wait for the reader
TOKEN = 'tok-slow-peer'


def check(name, cond, detail=''):
    print(('  ok   ' if cond else ' FAIL  ') + name + (('  -- ' + detail) if detail else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location('tnl_slowpeer', PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    m.log_event = lambda *a, **k: None
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit('these panel paths still point at the real state dir: %s' % left)
    return m


def request(port, path, read_all, slice_bytes=16384, pause=0.025):
    """Speak HTTP by hand so the READ RATE is ours. Returns (declared, received, sha, elapsed)."""
    s = socket.create_connection(('127.0.0.1', port), timeout=30)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    s.sendall(('GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' % path).encode())
    buf, t0 = b'', time.time()
    while b'\r\n\r\n' not in buf:                      # headers first, at full speed
        c = s.recv(4096)
        if not c:
            break
        buf += c
    head, _, rest = buf.partition(b'\r\n\r\n')
    declared = 0
    for line in head.split(b'\r\n'):
        if line.lower().startswith(b'content-length:'):
            declared = int(line.split(b':', 1)[1].strip())
    h = hashlib.sha256(rest)
    got = len(rest)
    if read_all:
        s.settimeout(20)
        while got < declared:                          # ...then drain slowly, but never stop
            time.sleep(pause)
            try:
                c = s.recv(slice_bytes)
            except (socket.timeout, OSError):
                break
            if not c:
                break
            h.update(c)
            got += len(c)
    else:
        time.sleep(TIMEOUT + 1.5)                      # the stalled peer: read NOTHING at all
        # Then drain with a LONG deadline, on purpose. The discriminator is how much a server that was
        # never given a deadline of its own will still hand over: it stayed alive through the stall, so
        # it delivers the WHOLE body once we resume. A short client deadline hides that -- with 5s here
        # both a timing-out server and an immortal one stopped at the same 65536 buffered bytes, and the
        # assertion below silently measured this client instead of the server.
        s.settimeout(30)
        try:
            while got < declared:
                c = s.recv(slice_bytes)
                if not c:
                    break
                h.update(c)
                got += len(c)
        except (socket.timeout, OSError):
            pass
    s.close()
    return declared, got, h.hexdigest(), time.time() - t0


def main():
    state = tempfile.mkdtemp(prefix='tnl-slowpeer-')
    srv = None
    try:
        m = load_panel(state)
        raw = b'\x7fELF' + os.urandom(BODY - 4)
        m.save_bytes(os.path.join(m.CORE_STAGE_DIR, 'tnl-core-amd64'), raw)
        m.save_json(m.CORE_STAGE_META, {'version': 'v9.9.9', 'arches': ['amd64'],
                                        'sha': {'amd64': hashlib.sha256(raw).hexdigest()},
                                        'size': {'amd64': len(raw)}, 'ts': int(time.time())})
        m.save_json(m.NODES_FILE, [{'id': 'n1', 'name': 'slow', 'host': '127.0.0.1',
                                    'port': 8099, 'token': TOKEN}])
        shipped_timeout = m.Handler.timeout      # read BEFORE the test shortens it
        m.Handler.timeout = TIMEOUT
        srv = m.BoundedThreadingHTTPServer(('127.0.0.1', 0), m.Handler)
        srv.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SNDBUF)
        srv.conf = {'user': 'x', 'secret': '00' * 32}
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = srv.server_address[1]
        # Minted by the panel itself: /api/dl takes a signed ticket now, and a hand-built query string
        # would be refused before a single byte of the body was written -- which this guard would then
        # report as a truncation.
        m._CENTRAL_PORT = port
        m._route_src = lambda h: '127.0.0.1'
        path = m._panel_dl_url({'id': 'n1', 'host': '127.0.0.1', 'token': TOKEN},
                               'co', 'amd64').split(str(port), 1)[1]
        want = hashlib.sha256(raw).hexdigest()

        print('== 1) a peer that reads slowly but never stops gets every byte ==')
        declared, got, sha, el = request(port, path, read_all=True)
        check('the response declares the whole body', declared == len(raw), '%d vs %d' % (declared, len(raw)))
        # The point of the exercise: this transfer takes LONGER than the socket timeout. If it did not,
        # the test would pass on the broken code too.
        check('...and the transfer really did outlast the socket timeout (%ss)' % TIMEOUT,
              el > TIMEOUT, '%.2fs' % el)
        check('every byte arrived', got == len(raw), '%d of %d after %.1fs' % (got, len(raw), el))
        check('...and they hash to the staged core', sha == want, '%s vs %s' % (sha[:12], want[:12]))

        # 2) The other half of the property, and the reason it is asserted on the SOURCE rather than
        # driven: "a stalled peer is dropped" could not be reproduced as a discriminator. MEASURED on
        # Linux, a stalled reader ends at the same 65536 buffered bytes whether the handler has a
        # timeout or not, so the behavioural version of this check passed on `timeout = None` -- i.e. it
        # blessed the one wrong fix it existed to catch. A check that cannot fail is worse than no check
        # (CLAUDE.md §12), so what is asserted here is the thing that actually protects the worker
        # thread: that a finite deadline still exists.
        print('== 2) ...and the deadline that protects a stalled peer is still there ==')
        t = shipped_timeout
        check('Handler.timeout is a finite, positive number',
              isinstance(t, (int, float)) and not isinstance(t, bool) and t > 0,
              'timeout=%r — removing it is the wrong way to fix the truncation: it hands any peer that '
              'stops reading a worker thread for good' % (t,))
    finally:
        if srv is not None:
            srv.shutdown()
            srv.server_close()
        shutil.rmtree(state, ignore_errors=True)
    print()
    if FAILED:
        print('%d FAILED:' % len(FAILED))
        for f in FAILED:
            print('  - ' + f)
        return 1
    print('a slow peer is served in full; a stalled one is still cut.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
