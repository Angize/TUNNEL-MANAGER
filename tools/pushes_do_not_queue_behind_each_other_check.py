#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []
CORE = {'amd64': b'\x7fELF' + b'A' * 200000, 'arm64': b'\x7fELF' + b'B' * 200000}
AGENT = '#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 77}\n'
N = 12


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location('tnl_push_conc_check', PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    m._CENTRAL_PORT = 8080
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit('these panel paths still point at the real state dir: %s' % left)
    return m


def main():
    state = tempfile.mkdtemp()
    m = load_panel(state)
    nodes = [{'id': 'n%d' % i, 'name': 'n%d' % i, 'host': '10.0.0.%d' % i, 'port': 8099,
              'token': 't%d' % i} for i in range(N)]
    m.save_json(m.NODES_FILE, nodes)
    m.log_event = lambda *a, **k: None
    m._cached_ping = lambda nid: {'arch': 'amd64', 'sha256': '', 'core_sha': ''}
    m._resolve_core_version = lambda v: 'v9.9.9'
    m._dl = lambda url, timeout, **kw: (hashlib.sha256(CORE['amd64']).hexdigest().encode()
                                  if url.endswith('.sha256') else CORE['amd64'])
    m.api_agent_fetch_git = lambda d: m._store_agent_src(
        AGENT, {'too_big': 'x', 'bad_py': 'x', 'not_agent': 'x', 'no_ver': 'x'}, {'source': 'git'})
    m.api_settings_set({'core_delivery': 'github', 'agent_delivery': 'github'})

    live = {'n': 0, 'peak': 0, 'kinds': set(), 'both': 0}
    lock = threading.Lock()
    started = {}

    def push(node, endpoint, body, on_progress=None, timeout=None, chunk=65536, should_abort=None):
        if endpoint == 'ping':
            return {'ok': True, 'arch': 'amd64', 'sha256': '', 'core_sha': ''}
        kind = 'agent' if endpoint == 'update' else 'core'
        with lock:
            live['n'] += 1
            live['peak'] = max(live['peak'], live['n'])
            live['kinds'].add(kind)
            if len(live['kinds']) == 2:
                live['both'] += 1
            started.setdefault(node['id'] + ':' + kind, time.monotonic())
        time.sleep(0.35)
        with lock:
            live['n'] -= 1
            live['kinds'].discard(kind)
        return {'ok': True}

    m.node_push = push
    m.node_call = lambda node, ep, method='POST', body=None, timeout=8: {'ok': True, 'arch': 'amd64'}

    t0 = time.monotonic()
    ra = m.api_update_agent({'ids': [n['id'] for n in nodes]})
    rc = m.api_update_core({'ids': [n['id'] for n in nodes], 'version': 'v9.9.9'})
    check('both jobs were accepted at once', bool(ra.get('job') and rc.get('job')),
          json.dumps([ra, rc], ensure_ascii=False))

    for _ in range(900):
        with m._push_lock:
            done = all(m._push_jobs[j]['done'] for j in (ra['job'], rc['job']) if j in m._push_jobs)
        if done:
            break
        time.sleep(0.05)
    took = time.monotonic() - t0

    first = min(started.values()) - t0 if started else 99
    check('the second job starts at once, it does not queue behind the first', first < 1.0,
          'first delivery began %.2fs in' % first)
    check('more than four nodes run at the same time', live['peak'] > 4,
          'peak was %d' % live['peak'])
    check('  and it scales to the whole set', live['peak'] >= N, 'peak was %d of %d' % (live['peak'], N))
    check('agent and core were in flight together', live['both'] > 0,
          'never overlapped (%d)' % live['both'])

    with m._push_lock:
        oks = sum(1 for j in (ra['job'], rc['job'])
                  for v in m._push_jobs[j]['nodes'].values() if v['state'] in ('ok', 'same'))
    check('every node in both jobs finished', oks == 2 * N, '%d of %d' % (oks, 2 * N))
    check('%d nodes x 2 jobs took about one round, not %d' % (N, N // 2),
          took < 3.0, 'took %.1fs' % took)

    print()
    if FAILED:
        print('%d failure(s)' % len(FAILED))
        return 1
    print('nothing waits for a slot: both jobs run, and every node in them, at once')
    return 0


if __name__ == '__main__':
    sys.exit(main())
