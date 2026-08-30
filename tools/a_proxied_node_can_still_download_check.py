#!/usr/bin/env python3
import importlib.util
import os
import sys
import tempfile
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location('tnl_dl_origin_check', PANEL)
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


PX = {'id': 'px1', 'name': 'IR-DE', 'scheme': 'socks5', 'host': '5.75.197.201', 'port': 1080}
DIRECT = {'id': 'n1', 'name': 'D1', 'host': '203.0.113.10', 'port': 8099, 'token': 'tok-direct'}
PROXIED = {'id': 'n2', 'name': 'P1', 'host': '91.107.169.159', 'port': 8099, 'token': 'tok-proxied',
           'proxy_on': True, 'proxy_id': 'px1'}


def main():
    state = tempfile.mkdtemp()
    m = load_panel(state)
    m.save_json(m.PROXIES_FILE, [PX])
    m.save_json(m.NODES_FILE, [DIRECT, PROXIED])
    m._CENTRAL_PORT = 2053
    m._CENTRAL_TLS = False
    m.central_ip = lambda: '185.252.86.72'
    m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
    m._route_src = lambda host: '198.51.100.5'

    o = m._panel_origin_for(DIRECT)
    check('a DIRECT node is given the address that routes to it',
          o == 'http://198.51.100.5:2053', repr(o))

    o = m._panel_origin_for(PROXIED)
    check('a PROXIED node is given an address at all -- it used to be refused one',
          bool(o), repr(o))
    check('  and it is the panel naming itself, not the route it has no direct use for',
          o == 'http://185.252.86.72:2053', repr(o))
    check('  which is the same address it announces in X-Central-Host',
          o == 'http://%s:2053' % m.central_host(), repr(o))

    url = m._panel_dl_url(PROXIED, 'co', 'amd64')
    check('so a proxied node gets a real download url', bool(url), repr(url))
    q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
    check('  and the ticket on it validates back to that node',
          (m._dl_ticket_node(q) or {}).get('id') == 'n2', repr(q))

    for mode, key in (('panel', 'url'), ('github', 'url'), ('push', 'data')):
        st = m.get_settings()
        st['core_delivery'] = mode
        m.save_json(m.SETTINGS_FILE, st)
        m.save_bytes(os.path.join(m.CORE_STAGE_DIR, 'tnl-core-amd64'), b'\x7fELF' + b'z' * 1000)
        try:
            body = m._core_install_body(PROXIED, 'YmFzZTY0', 'a' * 64, 'v9.9.9', 'sig', arch='amd64')
            ok, why = key in body, ''
        except ValueError as e:
            ok, why = False, str(e)
        check('core delivery %-6s works for a proxied node' % mode, ok, why)

    st = m.get_settings()
    st['agent_delivery'] = 'panel'
    m.save_json(m.SETTINGS_FILE, st)
    try:
        b = m._agent_update_body(PROXIED, 'src', {'sha256': 'b' * 64, 'size': 10}, 'sig')
        ok, why = 'url' in b, ''
    except ValueError as e:
        ok, why = False, str(e)
    check('and so does agent delivery panel', ok, why)

    m.central_ip = lambda: 'central-ip'
    m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
    check('with no usable address of its own the panel still refuses rather than guessing',
          m._panel_origin_for(PROXIED) == '', repr(m._panel_origin_for(PROXIED)))

    m.central_ip = lambda: '185.252.86.72'
    m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
    m._CENTRAL_PORT = 0
    check('and before it knows its own port it refuses too',
          m._panel_origin_for(PROXIED) == '' and m._panel_origin_for(DIRECT) == '')

    print()
    if FAILED:
        print('%d failure(s)' % len(FAILED))
        return 1
    print('a proxied node is no longer refused a download address')
    return 0


if __name__ == '__main__':
    sys.exit(main())
