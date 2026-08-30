#!/usr/bin/env python3
import hashlib
import importlib.util
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []
CORE = {'amd64': b'\x7fELF' + b'A' * 200000, 'arm64': b'\x7fELF' + b'B' * 200000}
SHA = {a: hashlib.sha256(r).hexdigest() for a, r in CORE.items()}
AGENT = '#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 77}\n'
NODES = [{'id': 'n1', 'name': 'a', 'host': '10.0.0.1', 'port': 8099, 'token': 't1'},
         {'id': 'n2', 'name': 'b', 'host': '10.0.0.2', 'port': 8099, 'token': 't2'}]
ARCH = {'n1': 'amd64', 'n2': 'arm64'}


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location('tnl_gh_mode_check', PANEL)
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


def wire(m, sent, hits):
    m.save_json(m.NODES_FILE, [dict(n) for n in NODES])
    m.log_event = lambda *a, **k: None
    m._cached_ping = lambda nid: {'arch': ARCH.get(nid, ''), 'sha256': '', 'core_sha': ''}

    def push(node, endpoint, body, on_progress=None, timeout=None, chunk=65536, should_abort=None):
        if endpoint == 'ping':
            return {'ok': True, 'arch': ARCH[node['id']], 'sha256': '', 'core_sha': ''}
        raw = bytes(body) if isinstance(body, (bytes, bytearray)) else json.dumps(body or {}).encode()
        sent.append({'node': node['id'], 'endpoint': endpoint, 'body': json.loads(raw.decode())})
        return {'ok': True}

    m.node_push = push
    m.node_call = lambda node, ep, method='POST', body=None, timeout=8: (
        {'ok': True, 'arch': ARCH[node['id']]} if ep == 'ping' else {'ok': True})

    def dl(url, timeout, on_progress=None, should_abort=None):
        hits.append(url)
        if url.endswith('.sha256'):
            return (SHA['arm64'] if 'arm64' in url else SHA['amd64']).encode()
        return CORE['arm64'] if 'arm64' in url else CORE['amd64']

    m._dl = dl
    m._resolve_core_version = lambda v: 'v9.9.9'
    m.api_agent_fetch_git = lambda d: (hits.append('AGENT-RAW'), m._store_agent_src(
        AGENT, {'too_big': 'x', 'bad_py': 'x', 'not_agent': 'x', 'no_ver': 'x'}, {'source': 'git'}))[1]


def run_job(m, fn, arg):
    r = fn(arg)
    jid = r.get('job')
    for _ in range(600):
        with m._push_lock:
            j = m._push_jobs.get(jid or '')
            if not j or j['done']:
                return {'nodes': {k: dict(v) for k, v in (j or {}).get('nodes', {}).items()}}
        import time
        time.sleep(0.02)
    return {'nodes': {}}


def main():
    state = tempfile.mkdtemp()
    m = load_panel(state)
    sent, hits = [], []
    wire(m, sent, hits)

    m.api_settings_set({'core_delivery': 'github', 'agent_delivery': 'github'})

    hits[:] = []
    sent[:] = []
    run_job(m, m.api_update_core, {'ids': ['n1', 'n2'], 'version': 'v9.9.9'})
    binaries = [u for u in hits if not u.endswith('.sha256')]
    check('a github core push downloads NO binary to the panel', not binaries, repr(binaries))
    check('  it fetches nothing at all -- not even the checksums', not hits, repr(hits))
    check('  nothing was written to the stage dir',
          not [f for f in os.listdir(m.CORE_STAGE_DIR) if not f.endswith('.json')],
          repr(os.listdir(m.CORE_STAGE_DIR)))
    b = [s['body'] for s in sent if s['endpoint'] == 'core-put']
    check('  every node still got a signed url, and no bytes', len(b) == 2 and
          all(x.get('url') and x.get('sig') and 'data' not in x and 'sha256' not in x for x in b),
          json.dumps(b, ensure_ascii=False)[:200])
    check('  and each arch got ITS own asset',
          sorted(x['url'].rsplit('/', 1)[-1] for x in b) ==
          ['tnl-core-linux-amd64', 'tnl-core-linux-arm64'], repr([x['url'] for x in b]))
    check('the panel reports itself ready without any binary', m._readiness()['core'] is True,
          json.dumps(m._readiness(), ensure_ascii=False))

    hits[:] = []
    sent[:] = []
    run_job(m, m.api_update_agent, {'ids': ['n1']})
    check('a github agent push re-reads the raw file every time',
          hits.count('AGENT-RAW') == 1, repr(hits))
    ab = [s['body'] for s in sent if s['endpoint'] == 'update']
    check('  and sends a url, never the code',
          len(ab) == 1 and ab[0].get('url') and 'code' not in ab[0], json.dumps(ab, ensure_ascii=False)[:200])
    check('  signed over the sha of what it just read',
          ab and ab[0]['sha256'] == hashlib.sha256(AGENT.encode()).hexdigest(), repr(ab))

    m._store_agent_src('#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 5}\n',
                       {'too_big': 'x', 'bad_py': 'x', 'not_agent': 'x', 'no_ver': 'x'})
    hits[:] = []
    try:
        m.api_update_agent({'ids': ['n1']})
        ok, why = False, 'no error raised'
    except ValueError as e:
        ok, why = 'گیت‌هاب' in str(e), str(e)
    check('an UPLOADED agent is still refused, not silently replaced by github', ok, why)
    check('  and the upload was left alone', 'AGENT-RAW' not in hits, repr(hits))

    for f in os.listdir(m.CORE_STAGE_DIR):
        if not f.endswith('.json'):
            os.remove(os.path.join(m.CORE_STAGE_DIR, f))
    hits[:] = []
    m._ensure_update_key = lambda node: None
    m.node_call = lambda node, ep, method='POST', body=None, timeout=8: (
        {'ok': True, 'arch': 'amd64'} if ep == 'ping' else {'ok': True})
    r = m._push_staged(dict(NODES[0]))
    check('_push_staged serves a proxied or fresh node without a binary either',
          r.get('ok') is True, json.dumps(r, ensure_ascii=False))
    check('  and it downloaded nothing', not hits, repr(hits))
    check('  and wrote nothing to the stage dir',
          not [f for f in os.listdir(m.CORE_STAGE_DIR) if not f.endswith('.json')],
          repr(os.listdir(m.CORE_STAGE_DIR)))

    m.api_settings_set({'core_delivery': 'github'})
    hits[:] = []
    r = m.api_core_stage({'version': 'v9.9.9'})
    check('the fetch-from-github button stages a version without pulling anything',
          r.get('ok') and r.get('meta_only') is True, json.dumps(r, ensure_ascii=False))
    check('  it read nothing from the network', not hits, repr(hits))
    check('  and left the stage dir empty',
          not [f for f in os.listdir(m.CORE_STAGE_DIR) if not f.endswith('.json')],
          repr(os.listdir(m.CORE_STAGE_DIR)))
    check('  yet the panel now calls itself ready', m._readiness()['core'] is True,
          json.dumps(m._readiness(), ensure_ascii=False))

    tripped = []
    real_stage, real_fetch = m._stage_core, m._fetch_release
    m._stage_core = lambda v: tripped.append('_stage_core(%s)' % v)
    m._fetch_release = lambda v, a, **kw: tripped.append('_fetch_release(%s,%s)' % (v, a))
    m._push_staged_on_add(dict(NODES[0]))
    m.api_core_stage({'version': 'v9.9.9'})
    m.api_core_versions({})
    real_dl = m._dl
    m._dl = lambda url, timeout, **kw: tripped.append('_dl(%s)' % url)
    m._readiness()
    m._push_staged(dict(NODES[0]))
    run_job(m, m.api_update_core, {'ids': ['n1', 'n2'], 'version': 'v9.9.9'})
    run_job(m, m.api_update_core, {'ids': ['n1']})
    for arch in m.CORE_ARCHES:
        m._staged_sha(arch)
    check('NO operator path makes the panel reach the network in github mode',
          not tripped, repr(sorted(set(tripped))))
    m._stage_core, m._fetch_release, m._dl = real_stage, real_fetch, real_dl

    m.api_settings_set({'core_delivery': 'push'})
    hits[:] = []
    r = m.api_core_stage({'version': 'v9.9.9'})
    check('push mode still downloads the binary from that same button',
          r.get('meta_only') is False and any(not u.endswith('.sha256') for u in hits), repr(hits))
    hits[:] = []
    run_job(m, m.api_update_core, {'ids': ['n1'], 'version': 'v9.9.9'})
    check('and an update in push mode still carries the bytes',
          bool(m._staged_bytes('amd64')), repr(hits))

    print()
    if FAILED:
        print('%d failure(s)' % len(FAILED))
        return 1
    print('github mode ships a signed url and nothing else -- the panel never opens a connection')
    return 0


if __name__ == '__main__':
    sys.exit(main())
