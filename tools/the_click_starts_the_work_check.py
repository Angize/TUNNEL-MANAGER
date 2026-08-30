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
CORE = {'amd64': b'\x7fELF' + b'A' * 4096, 'arm64': b'\x7fELF' + b'B' * 4096}
SHA = {a: hashlib.sha256(r).hexdigest() for a, r in CORE.items()}
SLOW = 1.2
NODES = [{'id': 'n%d' % i, 'name': 'n%d' % i, 'host': '10.0.0.%d' % i, 'port': 8099,
          'token': 't%d' % i} for i in range(6)]


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location('tnl_click_check', PANEL)
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


def wire(m, calls, sent):
    m.save_json(m.NODES_FILE, [dict(n) for n in NODES])
    m.log_event = lambda *a, **k: None
    m._cached_ping = lambda nid: {'arch': 'amd64', 'sha256': '', 'core_sha': ''}
    m._ensure_update_key = lambda node: None
    m.node_call = lambda node, ep, method='POST', body=None, timeout=8: {'ok': True, 'arch': 'amd64'}
    m._resolve_core_version = lambda v: v

    def push(node, endpoint, body, on_progress=None, timeout=None, chunk=65536, should_abort=None):
        if endpoint == 'ping':
            return {'ok': True, 'arch': 'amd64', 'sha256': '', 'core_sha': ''}
        raw = bytes(body) if isinstance(body, (bytes, bytearray)) else json.dumps(body or {}).encode()
        sent.append({'node': node['id'], 'endpoint': endpoint, 'body': json.loads(raw.decode())})
        return {'ok': True}

    m.node_push = push

    def slow_sha(version, arch):
        calls.append((version, arch))
        time.sleep(SLOW)
        if version == 'v0.0.0':
            raise RuntimeError('no such release')
        return SHA[arch]

    m._release_sha = slow_sha
    m._dl = lambda url, timeout: sys.exit('the panel reached the network: ' + url)


def drain(m, jid, limit=40.0):
    t = time.monotonic()
    while time.monotonic() - t < limit:
        with m._push_lock:
            j = m._push_jobs.get(jid or '')
            if not j or j['done']:
                return {k: dict(v) for k, v in (j or {}).get('nodes', {}).items()}
        time.sleep(0.02)
    return {}


def main():
    m = load_panel(tempfile.mkdtemp())
    calls, sent = [], []
    wire(m, calls, sent)
    m.api_settings_set({'core_delivery': 'github'})

    ids = [n['id'] for n in NODES]
    t0 = time.monotonic()
    r = m.api_update_core({'ids': ids, 'version': 'v9.9.9'})
    took = time.monotonic() - t0
    check('the click is answered before the release is even looked up',
          took < SLOW / 2, 'api_update_core blocked for %.2fs (one lookup costs %.1fs)' % (took, SLOW))
    check('  and it answered with a job to poll, not an error', bool(r.get('job')),
          json.dumps(r, ensure_ascii=False))

    nodes = drain(m, r.get('job'))
    check('every node still finished', len(nodes) == len(NODES) and
          all(v['state'] in ('ok', 'same') for v in nodes.values()),
          json.dumps(nodes, ensure_ascii=False)[:300])
    check('  the version was staged after the answer, not before',
          sorted(set(a for _v, a in calls)) == ['amd64', 'arm64'], repr(calls))
    check('  and looked up once per arch however many nodes there are',
          len(calls) == 2, '%d lookups for %d nodes' % (len(calls), len(NODES)))
    put = [s['body'] for s in sent if s['endpoint'] == 'core-put']
    check('  every node got the sha of the version that was asked for',
          len(put) == len(NODES) and all(b['sha256'] == SHA['amd64'] and b['version'] == 'v9.9.9'
                                         for b in put),
          json.dumps(put[:1], ensure_ascii=False))
    check('  and the staged meta on disk agrees',
          (m._staged_info() or {}).get('version') == 'v9.9.9', json.dumps(m._staged_info()))

    calls[:] = []
    sent[:] = []
    t0 = time.monotonic()
    r = m.api_update_core({'ids': ids, 'version': 'v0.0.0'})
    took = time.monotonic() - t0
    check('a version that does not exist is answered just as fast', took < SLOW / 2,
          'blocked for %.2fs' % took)
    nodes = drain(m, r.get('job'))
    bad = [v for v in nodes.values() if v['state'] != 'err']
    check('  but every node is then marked failed, not quietly skipped', not bad,
          json.dumps(nodes, ensure_ascii=False)[:300])
    check('  with the reason in Persian, naming the version',
          all('v0.0.0' in str(v.get('detail') or '') for v in nodes.values()),
          json.dumps([v.get('detail') for v in nodes.values()][:2], ensure_ascii=False))
    check('  and nothing was pushed to any node', not sent, json.dumps(sent, ensure_ascii=False)[:200])
    check('  and the good staged meta was not overwritten',
          (m._staged_info() or {}).get('version') == 'v9.9.9', json.dumps(m._staged_info()))

    calls[:] = []
    t0 = time.monotonic()
    r = m.api_update_core({'ids': ids})
    took = time.monotonic() - t0
    drain(m, r.get('job'))
    check('an update with no version picked stages nothing at all', not calls, repr(calls))
    check('  and is instant', took < SLOW / 2, 'blocked for %.2fs' % took)

    m.save_json(m.CORE_STAGE_META, {})
    try:
        m.api_update_core({'ids': ids})
        ok, why = False, 'no error raised'
    except ValueError as e:
        ok, why = 'انتخاب' in str(e), str(e)
    check('with nothing staged and nothing picked it still refuses up front', ok, why)

    print()
    if FAILED:
        print('%d failure(s)' % len(FAILED))
        return 1
    print('the answer comes back at once and the release lookup happens behind it')
    return 0


if __name__ == '__main__':
    sys.exit(main())
