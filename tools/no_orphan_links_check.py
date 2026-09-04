#!/usr/bin/env python3
"""A node record and its links leave together, or neither leaves.

The panel used to offer «فقط از پنل جدا کن»: it dropped the node from NODES_FILE and left every link
that named it sitting in LINKS_FILE. Those links then had no node. api_fleet fell back to the stored
a_name so they kept rendering, api_summary counted each one `down += 1` with an alert, and the nodes
screen offered no way to remove them -- the «قطع» counter and the alert list could never clear again.

Forgetting the links instead would have been worse, not better: the tunnel id is drawn as the LOWEST
free number in LINKS_FILE, so the very next tunnel takes the freed id, gets the same interface name,
and the panel sends that name explicitly -- so the node's own "is this name taken" check never runs and
it overwrites the still-running config on the peer. And re-adding the node cannot repair anything
either: api_node_add mints a fresh random id, so the orphans would point at a node that no longer
exists under any id.

So there is one delete path, and this guard pins the invariant it exists to keep: after api_node_del
returns, no link in LINKS_FILE names a node that is not in NODES_FILE. Checked on both branches --
the node answers, and the forced one where it does not.
"""
import importlib.util
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')
FAILED = []


def check(name, cond, detail=''):
    print(('  ok   ' if cond else ' FAIL  ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state, tag):
    spec = importlib.util.spec_from_file_location('tnl_orphan_' + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    return m


def seed(m):
    m.save_json(m.NODES_FILE, [
        {'id': 'na', 'name': 'A', 'host': '1.1.1.1', 'port': 8099, 'token': 't' * 20},
        {'id': 'nb', 'name': 'B', 'host': '2.2.2.2', 'port': 8099, 'token': 't' * 20},
        {'id': 'nc', 'name': 'C', 'host': '3.3.3.3', 'port': 8099, 'token': 't' * 20},
    ])
    m.save_json(m.LINKS_FILE, [
        {'id': 'l1', 'name': 'core1', 'type': 'core', 'tunnel_id': 1, 'subnet': '192.168.1.0/24',
         'a_node': 'na', 'a_name': 'A', 'a_ip': '1.1.1.1', 'b_node': 'nb', 'b_name': 'B', 'b_ip': '2.2.2.2'},
        {'id': 'l2', 'name': 'core2', 'type': 'core', 'tunnel_id': 2, 'subnet': '192.168.2.0/24',
         'a_node': 'nc', 'a_name': 'C', 'a_ip': '3.3.3.3', 'b_node': 'na', 'b_name': 'A', 'b_ip': '1.1.1.1'},
        {'id': 'l3', 'name': 'core3', 'type': 'core', 'tunnel_id': 3, 'subnet': '192.168.3.0/24',
         'a_node': 'nb', 'a_name': 'B', 'a_ip': '2.2.2.2', 'b_node': 'nc', 'b_name': 'C', 'b_ip': '3.3.3.3'},
    ])


def orphans(m):
    have = {n['id'] for n in m.load_nodes()}
    return [L['name'] for L in m.load_links()
            if L.get('a_node') not in have or L.get('b_node') not in have]


def run(tag, force, node_answers):
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, tag)
        seed(m)
        calls = []

        def fake_call(n, op, method='GET', body=None, timeout=None, **kw):
            calls.append((n['id'], op))
            return {'ok': node_answers}

        m.node_call = fake_call
        m._cached_ping = lambda nid: {'ok': node_answers}
        d = {'id': 'na'}
        if force:
            d['wipe_force'] = True
        try:
            out = m.api_node_del(d)
            err = None
        except Exception as e:                                    # noqa: BLE001
            out, err = None, str(e)
        return sorted(L['id'] for L in m.load_links()), out, err, calls, orphans(m)


def main():
    print('== the node answers: it is wiped, and both of its links go with it ==')
    left, out, err, calls, orph = run('ok', force=False, node_answers=True)
    check('api_node_del succeeded', err is None, err or '')
    check('the node itself was wiped', ('na', 'wipe') in calls, repr(calls))
    check('both peer halves were closed',
          sorted(c for c in calls if c[1] == 'delete') == [('nb', 'delete'), ('nc', 'delete')], repr(calls))
    check('its two links are gone, and only they', left == ['l3'], repr(left))
    check('NO link names a node that is gone', orph == [], repr(orph))
    check('the reply says how many links went', (out or {}).get('links_removed') == 2, repr(out))

    print('== the node is dead and the operator forces it: same invariant ==')
    left, out, err, calls, orph = run('force', force=True, node_answers=False)
    check('api_node_del succeeded', err is None, err or '')
    check('the dead node was NOT called for a wipe', ('na', 'wipe') not in calls, repr(calls))
    check('its two links are gone anyway', left == ['l3'], repr(left))
    check('NO link names a node that is gone', orph == [], repr(orph))
    check('the reply reports the node was not wiped', (out or {}).get('node_wiped') is False, repr(out))

    print('== there is no second delete path that skips the cleanup ==')
    src = open(PANEL, encoding='utf-8').read()
    body = src[src.index('def api_node_del('):src.index('def api_node_test(')]
    check('api_node_del reads no "wipe" flag', '"wipe"' not in body.replace('"wipe", "POST"', ''),
          'a flag that makes the link cleanup optional is exactly what created the phantoms')
    check('LINKS_FILE is written unconditionally', body.count('save_json(LINKS_FILE') == 1)
    check('the form sends no wipe flag', 'wipe:wipe' not in src)
    check('the detach button is gone', 'del_detach_t' not in src)

    print()
    if FAILED:
        print('%d failure(s).' % len(FAILED))
        return 1
    print('all good.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
