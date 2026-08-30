#!/usr/bin/env python3
import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []
TOK = 'tok-abcdef0123456789'
NID = 'n1'


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state, tag):
    spec = importlib.util.spec_from_file_location('tnl_moved_' + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    load = getattr(m, '_moved_load', None)
    m._moved.clear()
    if load:
        m._moved.update(load())
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit('these panel paths still point at the real state dir: %s' % left)
    return m


def seed(m, host='1.1.1.1', port=8099, proxy_on=False):
    m.save_json(m.NODES_FILE, [{'id': NID, 'name': 'N1', 'host': host, 'port': port,
                                'token': TOK, 'enabled': True, 'proxy_on': proxy_on}])


def claim(port=8099, ctr=None):
    c = {'fp': hashlib.sha256(TOK.encode()).hexdigest(), 'ips': ['2.2.2.2'],
         'port': port, 'hostname': 'n1', 'ctr': int(ctr if ctr is not None else time.time() * 1000)}
    c['sig'] = base64.b64encode(hmac.new(
        TOK.encode(), json.dumps(c, sort_keys=True, separators=(',', ':')).encode(),
        hashlib.sha256).digest()).decode()
    return c


def answers(m, *hosts):
    live = set(hosts)
    m.node_call = lambda node, ep, method='POST', body=None, timeout=8, _retry=True: (
        {'ok': True} if node.get('host') in live else {'ok': False, 'offline': True})


def main():
    state = tempfile.mkdtemp()
    m = load_panel(state, 'a')
    ctr = [1000]

    def go(src='2.2.2.2'):
        ctr[0] += 1
        return m.api_checkin_impl(src, claim(ctr=ctr[0]))

    seed(m)
    answers(m, '1.1.1.1')
    r = go()
    check('the old address still answering is not a move',
          r.get('ok') is True and not m.moved_to(NID), repr(r))

    seed(m)
    answers(m)
    r = go()
    check('an UNCONFIRMED new address must answer ok=False so the node repeats itself',
          r.get('ok') is False and r.get('unconfirmed') is True, repr(r))
    check('and nothing is recorded from it', not m.moved_to(NID), repr(m.moved_to(NID)))

    seed(m)
    answers(m, '2.2.2.2')
    r = go()
    check('a CONFIRMED new address is recorded and acknowledged',
          r.get('ok') is True and r.get('moved_to') == '2.2.2.2' and m.moved_to(NID) == '2.2.2.2', repr(r))
    check('the node host is left alone in alert mode',
          m.get_node(NID)['host'] == '1.1.1.1', m.get_node(NID)['host'])
    evs = m._ev_all()
    warn = [e for e in evs
            if e.get('level') == 'warn' and '2.2.2.2' in json.dumps(e, ensure_ascii=False)]
    check('and the operator gets a warning in the event log', bool(warn), repr(evs)[:200])

    m2 = load_panel(state, 'b')
    check('the move SURVIVES a panel restart',
          m2.moved_to(NID) == '2.2.2.2' and m2.moved_port(NID) == 8099, repr(m2.moved_to(NID)))

    seed(m2)
    answers(m2, '1.1.1.1')
    ctr[0] += 1
    m2.api_checkin_impl('1.1.1.1', claim(ctr=ctr[0]))
    check('a node that came home clears the flag', not m2.moved_to(NID), repr(m2.moved_to(NID)))
    m3 = load_panel(state, 'c')
    check('and the clear survives a restart too', not m3.moved_to(NID), repr(m3.moved_to(NID)))

    seed(m3)
    answers(m3, '2.2.2.2')
    st = m3.get_settings()
    st['reconcile_mode'] = 'auto'
    m3.save_json(m3.SETTINGS_FILE, st)
    ctr[0] += 1
    r = m3.api_checkin_impl('2.2.2.2', claim(ctr=ctr[0]))
    check('auto mode still adopts the address itself',
          r.get('ok') is True and r.get('updated') is True and m3.get_node(NID)['host'] == '2.2.2.2', repr(r))

    print()
    if FAILED:
        print('%d failure(s)' % len(FAILED))
        return 1
    print('a moved node is remembered across a restart, and an unconfirmed one is retried')
    return 0


if __name__ == '__main__':
    sys.exit(main())
