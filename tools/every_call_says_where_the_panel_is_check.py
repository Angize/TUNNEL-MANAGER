#!/usr/bin/env python3
import http.server
import importlib.util
import json
import os
import socket
import sys
import tempfile
import threading

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []
SEEN = []


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location('tnl_central_host_check', PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit('these panel paths still point at the real state dir: %s' % left)
    return m


class Sink(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def _take(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n:
            self.rfile.read(n)
        SEEN.append({k.lower(): v for k, v in self.headers.items()})
        out = json.dumps({'ok': True}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = _take
    do_POST = _take


def last(key):
    return SEEN[-1].get(key.lower(), '') if SEEN else ''


def main():
    state = tempfile.mkdtemp()
    m = load_panel(state)
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    node = {'id': 'n1', 'name': 'N1', 'host': '127.0.0.1', 'port': port, 'token': 'tok'}

    m._CENTRAL_PORT = 2053
    m._CENTRAL_TLS = False
    m.central_ip = lambda: '185.252.86.72'

    def bust():
        h = getattr(m, '_CENTRAL_HOST', None)
        if h is not None:
            h['ip'], h['ts'] = '', 0.0

    bust()

    try:
        r = m.node_call(node, 'ping', 'GET', timeout=5)
        check('a DIRECT call reaches the node', r.get('ok') is True, repr(r))
        check('  and carries X-Central-Host', last('X-Central-Host') == '185.252.86.72',
              repr(last('X-Central-Host')))
        check('  beside the port and tls it already sent',
              last('X-Central-Port') == '2053' and last('X-Central-TLS') == '0',
              '%s %s' % (last('X-Central-Port'), last('X-Central-TLS')))

        m._proxy_socket = lambda proxy, dh, dp, timeout: socket.create_connection((dh, dp), timeout)
        r = m._node_call_proxied(node, 'socks5://198.51.100.7:1080', 'ping', 'GET', None, 5)
        check('a PROXIED call reaches the node', r.get('ok') is True, repr(r))
        check('  and carries X-Central-Host -- this is the path that was broken',
              last('X-Central-Host') == '185.252.86.72', repr(last('X-Central-Host')))

        r = m.node_push(node, 'ping', {'x': 1}, timeout=5)
        check('an UPLOAD reaches the node', r.get('ok') is True, repr(r))
        check('  and carries X-Central-Host too', last('X-Central-Host') == '185.252.86.72',
              repr(last('X-Central-Host')))

        m.central_ip = lambda: 'central-ip'
        bust()
        m.node_call(node, 'ping', 'GET', timeout=5)
        check('an unusable central_ip sends no host at all rather than a bad one',
              'x-central-host' not in SEEN[-1], repr(last('X-Central-Host')))
        check('  and the port header still goes, so the node keeps its old behaviour',
              last('X-Central-Port') == '2053', repr(last('X-Central-Port')))

        m.central_ip = lambda: '185.252.86.72'
        bust()
        m._CENTRAL_PORT = 0
        m.node_call(node, 'ping', 'GET', timeout=5)
        check('before the panel knows its own port it announces nothing',
              'x-central-host' not in SEEN[-1] and 'x-central-port' not in SEEN[-1], repr(SEEN[-1]))
        m._CENTRAL_PORT = 2053

        calls = []
        m.central_ip = lambda: (calls.append(1), '185.252.86.72')[1]
        bust()
        for _ in range(5):
            m.node_call(node, 'ping', 'GET', timeout=5)
        check('the address is looked up once, not on every call the panel makes',
              len(calls) == 1, '%d lookups for 5 calls' % len(calls))
    finally:
        srv.shutdown()

    print()
    if FAILED:
        print('%d failure(s)' % len(FAILED))
        return 1
    print('every path the panel talks to a node on says where the panel is')
    return 0


if __name__ == '__main__':
    sys.exit(main())
