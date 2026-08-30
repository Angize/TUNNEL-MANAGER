#!/usr/bin/env python3
"""The three delivery modes deliver the SAME artifact, over the real push paths.

`agent_delivery` / `core_delivery` pick who carries the bytes the last hop -- the panel uploading them,
the node downloading them from GitHub, or the node downloading them from the panel. The panel still
decides WHAT is installed in every mode, so the thing this has to prove is that switching the mode
never changes the artifact, only its route.

Every case here drives the shipped entry point (api_update_agent, api_update_core, _push_staged,
_install_worker, and a REAL GET against the panel's own Handler) and reads what came out the far end.
A test that called the body builder directly would say nothing about the call sites that do not go
through it.
"""
import base64
import hashlib
import http.client
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')

FAILED = []


def check(name, cond, detail=''):
    print(('  ok  ' if cond else '  FAIL ') + name + (('  -- ' + detail) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    """The panel with every path it writes re-pointed into `state`.

    Re-pointed by SWEEPING the module, not by listing the names: a hand-written list missed
    PROXIES_FILE, and on a machine where /opt/tnl-central happens to exist the guard wrote there and
    passed anyway. It only surfaced on a runner where that directory does not exist."""
    spec = importlib.util.spec_from_file_location('tnl_delivery_check', PANEL)
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


AGENT_SRC = '#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 42}\nprint(PING)\n'
CORE = {'amd64': b'\x7fELF' + b'A' * 200000, 'arm64': b'\x7fELF' + b'B' * 200000}
BLOB = b'\x7fELF' + b'C' * 200000


def stage_all(m, agent_source='git'):
    """Put a staged agent and a staged core (both arches) on the panel, the way the real ones land."""
    m._store_agent_src(AGENT_SRC, {'too_big': 'x', 'bad_py': 'x', 'not_agent': 'x', 'no_ver': 'x'},
                       {'source': agent_source} if agent_source else None)
    shas = {}
    for arch, raw in CORE.items():
        m.save_bytes(os.path.join(m.CORE_STAGE_DIR, 'tnl-core-' + arch), raw)
        shas[arch] = hashlib.sha256(raw).hexdigest()
    m.save_json(m.CORE_STAGE_META, {'version': 'v9.9.9', 'arches': sorted(CORE),
                                    'sha': shas, 'size': {a: len(r) for a, r in CORE.items()},
                                    'ts': int(time.time())})
    m.save_json(m.CORE_BLOB_META, {'sha256': hashlib.sha256(BLOB).hexdigest(), 'size': len(BLOB),
                                   'name': 'core.bin', 'uploaded_ts': int(time.time())})
    m.save_bytes(m.CORE_BLOB, BLOB)
    return shas


NODES = [
    {'id': 'n1', 'name': 'amd-one', 'host': '10.0.0.1', 'port': 8099, 'token': 'tok-one'},
    {'id': 'n2', 'name': 'arm-two', 'host': '10.0.0.2', 'port': 8099, 'token': 'tok-two'},
    {'id': 'n3', 'name': 'proxied', 'host': '10.0.0.3', 'port': 8099, 'token': 'tok-three',
     'proxy_on': True, 'proxy_id': 'px1'},
]
ARCH = {'n1': 'amd64', 'n2': 'arm64', 'n3': 'amd64'}


def wire_fakes(m, sent):
    """Replace exactly the three things that touch the network, and nothing else."""
    m.save_json(m.NODES_FILE, [dict(n) for n in NODES])
    m.save_json(m.PROXIES_FILE, [{'id': 'px1', 'name': 'px', 'scheme': 'socks5',
                                  'host': '127.0.0.1', 'port': 1080, 'user': '', 'pass': ''}])

    def fake_push(node, endpoint, body, on_progress=None, timeout=None, chunk=65536, should_abort=None):
        if endpoint == 'ping':                 # the check step: nothing is delivered by it
            return {'ok': True, 'arch': ARCH.get(node['id'], 'amd64'), 'sha256': '', 'core_sha': ''}
        data = bytes(body) if isinstance(body, (bytes, bytearray)) else json.dumps(body or {}).encode()
        sent.append({'node': node['id'], 'endpoint': endpoint, 'body': json.loads(data.decode())})
        if on_progress:
            on_progress(len(data), len(data))
        return {'ok': True}

    def fake_call(node, endpoint, method='POST', body=None, timeout=8):
        if endpoint == 'ping':
            return {'ok': True, 'arch': ARCH.get(node['id'], 'amd64')}
        if endpoint in ('core-put', 'core-apply'):
            sent.append({'node': node['id'], 'endpoint': endpoint, 'body': body})
        return {'ok': True, 'code': 'staged'}

    m.node_push = fake_push
    m.node_call = fake_call
    m._cached_ping = lambda nid: {'arch': ARCH.get(nid, ''), 'sha256': '', 'core_sha': ''}
    m._route_src = lambda host: '203.0.113.7'      # the panel's address as this node would see it
    m.log_event = lambda *a, **k: None


def run_job(m, fn, arg):
    """Run a push API and wait for its job to finish; returns the API's own answer."""
    r = fn(arg)
    jid = r.get('job')
    for _ in range(600):
        with m._push_lock:
            j = m._push_jobs.get(jid or '')
            if not jid or (j and j['done']):
                break
        time.sleep(0.01)
    if jid:
        with m._push_lock:
            r['nodes'] = {k: dict(v) for k, v in m._push_jobs[jid]['nodes'].items()}
    return r


def bodies(sent, nid, ep=None):
    return [s['body'] for s in sent if s['node'] == nid and (ep is None or s['endpoint'] == ep)]


# ---------------------------------------------------------------- 1) the artifact never changes
def case_agent(m, mode, shas):
    sent = []
    wire_fakes(m, sent)
    m.api_settings_set({'agent_delivery': mode})
    r = run_job(m, m.api_update_agent, {'ids': ['n1', 'n2']})
    agent_sha = hashlib.sha256(AGENT_SRC.encode()).hexdigest()
    for nid in ('n1', 'n2'):
        b = bodies(sent, nid)
        check('agent/%s: %s got exactly one update' % (mode, nid), len(b) == 1, str(len(b)))
        if len(b) != 1:
            continue
        b = b[0]
        check('agent/%s: %s carries the staged sha' % (mode, nid), b.get('sha256') == agent_sha)
        check('agent/%s: %s carries a signature' % (mode, nid), bool(b.get('sig')))
        if mode == 'push':
            check('agent/%s: %s got the bytes, no url' % (mode, nid),
                  b.get('code') == AGENT_SRC and 'url' not in b)
        else:
            # A body with BOTH would be silently delivered as bytes: op_update reads `code` first.
            check('agent/%s: %s got a url and NO bytes' % (mode, nid),
                  bool(b.get('url')) and 'code' not in b, json.dumps(sorted(b))[:120])
        if mode == 'github':
            check('agent/%s: %s points at the agent repo' % (mode, nid), b.get('url') == m.NODE_RAW_URL)
        if mode == 'panel':
            tok = [n['token'] for n in NODES if n['id'] == nid][0]
            u = b.get('url') or ''
            # The url used to carry the token itself. It was the last place the secret still travelled.
            check('agent/%s: %s url carries NO token' % (mode, nid), tok not in u, u)
            check('agent/%s: %s url is a signed ticket for ITS node' % (mode, nid),
                  hashlib.sha256(tok.encode()).hexdigest() in u and 'sig=' in u and 'exp=' in u, u)
    if mode == 'panel':
        us = [bodies(sent, n)[0]['url'] for n in ('n1', 'n2') if bodies(sent, n)]
        check('agent/panel: the two nodes get two different urls', len(set(us)) == 2)
    return r


def case_core(m, mode, shas, api, arg, label):
    sent = []
    wire_fakes(m, sent)
    m.api_settings_set({'core_delivery': mode})
    run_job(m, api, arg)
    for nid, arch in (('n1', 'amd64'), ('n2', 'arm64')):
        b = bodies(sent, nid, 'core-put')
        ap = bodies(sent, nid, 'core-apply')
        check('%s/%s: %s got exactly one core-put' % (label, mode, nid), len(b) == 1, str(len(b)))
        check('%s/%s: %s got exactly one core-apply after it' % (label, mode, nid), len(ap) == 1, str(len(ap)))
        if len(ap) == 1:
            check('%s/%s: %s install step names ITS arch sha, and carries no bytes' % (label, mode, nid),
                  ap[0].get('sha256') == shas[arch] and bool(ap[0].get('sig'))
                  and 'data' not in ap[0] and 'url' not in ap[0],
                  json.dumps(sorted(ap[0]))[:120])
        if len(b) != 1:
            continue
        b = b[0]
        check('%s/%s: %s carries ITS arch sha' % (label, mode, nid), b.get('sha256') == shas[arch],
              '%s vs %s' % (b.get('sha256'), shas[arch]))
        check('%s/%s: %s carries a signature' % (label, mode, nid), bool(b.get('sig')))
        if mode == 'push':
            check('%s/%s: %s got ITS arch bytes' % (label, mode, nid),
                  base64.b64decode(b['data']) == CORE[arch] and 'url' not in b)
        else:
            check('%s/%s: %s got a url and NO bytes' % (label, mode, nid),
                  bool(b.get('url')) and 'data' not in b, json.dumps(sorted(b))[:120])
        if mode == 'github':
            check('%s/%s: %s url names its own arch + the staged version' % (label, mode, nid),
                  b.get('url') == m._release_asset_url('v9.9.9', arch), b.get('url', ''))
        if mode == 'panel':
            check('%s/%s: %s url names its own arch' % (label, mode, nid),
                  'arch=' + arch in (b.get('url') or ''), b.get('url', ''))
    # THE trap _body_cache exists to avoid: one cached body handed to both architectures kills every
    # core tunnel on the arm64 node with "Exec format error", and never self-corrects.
    ba, bb = bodies(sent, 'n1', 'core-put'), bodies(sent, 'n2', 'core-put')
    if ba and bb:
        check('%s/%s: the two arches did NOT share a body' % (label, mode), ba[0] != bb[0])


# ---------------------------------------------------------------- 2) what the mode cannot deliver
def case_refusals(m):
    sent = []
    wire_fakes(m, sent)
    m._store_agent_src(AGENT_SRC, {'too_big': 'x', 'bad_py': 'x', 'not_agent': 'x', 'no_ver': 'x'})  # uploaded, not git
    m.api_settings_set({'agent_delivery': 'github'})
    try:
        m.api_update_agent({'ids': ['n1']})
        check('github + an uploaded agent is refused up front', False, 'no error raised')
    except ValueError as e:
        check('github + an uploaded agent is refused up front', 'گیت‌هاب' in str(e), str(e))
    check('...and nothing was sent to any node', not sent, str(len(sent)))

    m._store_agent_src(AGENT_SRC, {'too_big': 'x', 'bad_py': 'x', 'not_agent': 'x', 'no_ver': 'x'},
                       {'source': 'git'})
    m.api_settings_set({'core_delivery': 'github'})
    sent[:] = []
    try:
        m.api_update_core({'ids': ['n1'], 'version': 'custom'})
        check('github + an uploaded core binary is refused up front', False, 'no error raised')
    except ValueError as e:
        check('github + an uploaded core binary is refused up front', 'گیت‌هاب' in str(e), str(e))
    check('...and nothing was sent to any node either', not sent, str(len(sent)))

    real_ip = m.central_ip
    m.central_ip = lambda: '198.51.100.1'
    m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
    for kind, api, arg, ep in (('agent', m.api_update_agent, {'ids': ['n3']}, 'update'),
                               ('core', m.api_update_core, {'ids': ['n3']}, 'core-put')):
        sent[:] = []
        m.api_settings_set({kind + '_delivery': 'panel'})
        run_job(m, api, arg)
        b = bodies(sent, 'n3', ep)
        check('panel-fetch: the proxied node is handed a url like any other (%s)' % kind,
              bool(b) and bool(b[0].get('url')) and 'data' not in b[0] and 'code' not in b[0],
              json.dumps(sorted(b[0]) if b else [], ensure_ascii=False))
        check('panel-fetch: and the url is the panel naming itself (%s)' % kind,
              bool(b) and (b[0].get('url') or '').startswith('http://198.51.100.1:'),
              (b[0].get('url') if b else '') or '')

    m.central_ip = lambda: 'central-ip'
    m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
    for kind, api, arg in (('agent', m.api_update_agent, {'ids': ['n3']}),
                           ('core', m.api_update_core, {'ids': ['n3']})):
        sent[:] = []
        m.api_settings_set({kind + '_delivery': 'panel'})
        r = run_job(m, api, arg)
        st = (r.get('nodes') or {}).get('n3', {})
        check('panel-fetch: a panel with no usable address of its own refuses (%s)' % kind,
              st.get('state') == 'err' and 'آدرسِ خودش' in (st.get('detail') or ''),
              json.dumps(st, ensure_ascii=False))
        check('panel-fetch: and nothing was delivered then (%s)' % kind, not sent)
    m.central_ip = real_ip
    m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0

    # A TLS-fronted panel announces https to its nodes (X-Central-TLS), and the node then refuses any
    # http url -- including one at the panel's own address. So the url built here has to carry the same
    # scheme the headers do, or the panel hands out a url its own nodes are bound to refuse.
    m._CENTRAL_TLS = True
    try:
        u = m._panel_dl_url({'id': 'n1', 'host': '10.0.0.1', 'token': 'tok-one'}, 'ag')
        check('a TLS-fronted panel hands out an https url', u.startswith('https://'), u)
    finally:
        m._CENTRAL_TLS = False
    u = m._panel_dl_url({'id': 'n1', 'host': '10.0.0.1', 'token': 'tok-one'}, 'ag')
    check('...and a plain-http panel still hands out http', u.startswith('http://'), u)


# ---------------------------------------------------------------- 3) the url really serves those bytes
def case_endpoint(m, shas):
    m.api_settings_set({'agent_delivery': 'panel', 'core_delivery': 'panel'})
    sent = []
    wire_fakes(m, sent)
    run_job(m, m.api_update_agent, {'ids': ['n1']})
    run_job(m, m.api_update_core, {'ids': ['n1', 'n2']})
    run_job(m, m.api_update_core, {'ids': ['n1'], 'version': 'custom'})
    urls = {}
    for s in sent:
        if 'url' not in s['body']:             # the install step names the artifact, it does not carry it
            continue
        key = s['endpoint'] + ':' + s['node'] + ':' + (s['body'].get('version') or '')
        urls[key] = (s['body']['url'], s['body']['sha256'])

    httpd = m.BoundedThreadingHTTPServer(('127.0.0.1', 0), m.Handler)
    httpd.conf = {'user': 'x', 'secret': '00' * 32}
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]

    def get(path):
        c = http.client.HTTPConnection('127.0.0.1', port, timeout=10)
        c.request('GET', path)
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    try:
        for key, (url, sha) in sorted(urls.items()):
            path = url.split(str(m._CENTRAL_PORT), 1)[1]
            st, body = get(path)
            check('GET %s answers 200' % key, st == 200, str(st))
            # The whole point: the bytes behind the url hash to the sha the panel signed, so a node in
            # url mode installs exactly what a node in push mode would have been handed.
            check('...and its bytes hash to the sha the panel signed (%s)' % key,
                  hashlib.sha256(body).hexdigest() == sha,
                  '%s vs %s' % (hashlib.sha256(body).hexdigest()[:12], sha[:12]))
        # ---- the ticket is the whole authorisation, so every way of not having a good one is refused
        import urllib.parse as _up
        agent_url = m._panel_dl_url({'id': 'n1', 'host': '10.0.0.1', 'token': 'tok-one'}, 'ag')
        base, qs = agent_url.split(str(m._CENTRAL_PORT), 1)[1].split('?', 1)
        q = dict(_up.parse_qsl(qs))

        def ticket(**over):
            d = dict(q)
            d.update(over)
            return base + '?' + _up.urlencode(d)

        st, _ = get(ticket())
        check('a good ticket is served', st == 200, str(st))
        st, _ = get(ticket(sig='x' * 43))
        check('a forged signature gets 401', st == 401, str(st))
        st, _ = get(ticket(fp='0' * 64))
        check('an unknown fingerprint gets 401', st == 401, str(st))
        st, _ = get(ticket(k='co'))
        check('...and asking for a DIFFERENT artifact with this ticket gets 401',
              st == 401, 'the signature covers what was asked for: %s' % st)
        # Minted properly, with a past expiry -- NOT the same as editing `exp` on a good ticket, which
        # only breaks the signature and would pass this whether the expiry is checked or not.
        m.DL_TICKET_TTL = -5
        try:
            stale = m._panel_dl_url({'id': 'n1', 'host': '10.0.0.1', 'token': 'tok-one'}, 'ag')
        finally:
            m.DL_TICKET_TTL = 3600
        st, _ = get(stale.split(str(m._CENTRAL_PORT), 1)[1])
        check('a correctly signed but EXPIRED ticket gets 401', st == 401, str(st))
        st, _ = get(ticket(exp=str(int(time.time()) - 5)))
        check('...and one whose expiry was edited afterwards too', st == 401, str(st))
        st, _ = get(base + '?k=ag')
        check('no ticket at all gets 401', st == 401, str(st))
        # ...and a good ticket still cannot name something that is not there, or a path
        core_url = m._panel_dl_url({'id': 'n1', 'host': '10.0.0.1', 'token': 'tok-one'}, 'co', 'amd64')
        cb, cq = core_url.split(str(m._CENTRAL_PORT), 1)[1].split('?', 1)
        cd = dict(_up.parse_qsl(cq))
        st, _ = get(cb + '?' + _up.urlencode(cd))
        check('a good core ticket is served', st == 200, str(st))
        bad = m._panel_dl_url({'id': 'n1', 'host': '10.0.0.1', 'token': 'tok-one'}, 'co', '../etc')
        st, _ = get(bad.split(str(m._CENTRAL_PORT), 1)[1])
        check('a bogus arch gets 404, never a file path', st == 404, str(st))
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------- 4) the SSH install leg
def case_install(m):
    for mode, expect_github in (('push', False), ('github', True), ('panel', False)):
        m.api_settings_set({'agent_delivery': mode})
        runs = []

        def fake_ssh(cfg, cmd, timeout, stdin_text=None):
            runs.append((cmd, stdin_text))
            if 'TNL_SSH_OK' in cmd:
                return 0, 'TNL_SSH_OK\n', ''
            if 'auto-install' in cmd:
                return 0, 'TNL_INSTALL_OK\nTNL_NODE_TOKEN=abc123\n', ''
            return 0, 'TNL_DL_OK\nTNL_RECV_OK\n', ''

        m._ssh_run = fake_ssh
        jid = 'j' + mode
        m._install_jobs[jid] = {'steps': [{'key': k, 'label': l, 'state': 'wait', 'detail': '', 'log': ''}
                                          for k, l in m._INSTALL_STEPS],
                                'done': False, 'ok': False, 'banner': '', 'node_id': None,
                                'ts': int(time.time())}
        m._install_worker(jid, {'host': '10.0.0.9', 'port': 22, 'user': 'root', 'password': 'x'},
                          'fresh-' + mode, 8099, False, '')
        step = [r for r in runs if 'tnl-node.py' in r[0] and 'auto-install' not in r[0]]
        check('install/%s: the agent step ran once' % mode, len(step) == 1, str(len(step)))
        if len(step) != 1:
            continue
        cmd, stdin = step[0]
        sha = hashlib.sha256(AGENT_SRC.encode()).hexdigest()
        check('install/%s: the node verifies the sha the PANEL staged' % mode, sha in cmd, cmd[:160])
        if expect_github:
            check('install/github: the node curls the agent repo', m.NODE_RAW_URL in cmd)
            check('install/github: nothing is fed down the ssh session', stdin is None)
        else:
            check('install/%s: the agent source goes down the ssh session' % mode,
                  stdin == base64.b64encode(AGENT_SRC.encode()).decode())
            check('install/%s: it does not curl anything' % mode, 'curl' not in cmd and 'wget' not in cmd)
        st = [s for s in m._install_jobs[jid]['steps'] if s['key'] == 'agent'][0]
        check('install/%s: the step reports ok' % mode, st['state'] == 'ok', json.dumps(st, ensure_ascii=False))


def main():
    state = tempfile.mkdtemp(prefix='tnl-delivery-')
    try:
        m = load_panel(state)
        shas = stage_all(m)
        print('== 1) the same artifact, three routes ==')
        for mode in m.DELIVERY_MODES:
            case_agent(m, mode, shas)
        # ONE loop: the two that were here called the same api with two labels, so the second proved
        # nothing the first had not. Naming a version is a staging question, not a delivery one.
        for mode in m.DELIVERY_MODES:
            case_core(m, mode, shas, m.api_update_core, {'ids': ['n1', 'n2']}, 'core-staged')
        print('== 2) what a mode cannot deliver, it refuses ==')
        case_refusals(m)
        print('== 3) the url the node is handed serves those exact bytes ==')
        stage_all(m)
        case_endpoint(m, shas)
        print('== 4) the ssh install leg ==')
        case_install(m)
        print('== 5) _push_staged (node-add / core-build retry) honours the mode too ==')
        stage_all(m)
        for mode in m.DELIVERY_MODES:
            sent = []
            wire_fakes(m, sent)
            m.api_settings_set({'core_delivery': mode})
            m._push_staged(dict(NODES[0]))
            b = bodies(sent, 'n1', 'core-put')
            check('_push_staged/%s: one core-put' % mode, len(b) == 1, str(len(b)))
            check('_push_staged/%s: and the install step after it' % mode,
                  len(bodies(sent, 'n1', 'core-apply')) == 1, str(len(bodies(sent, 'n1', 'core-apply'))))
            if b:
                check('_push_staged/%s: %s' % (mode, 'bytes' if mode == 'push' else 'url'),
                      ('data' in b[0]) == (mode == 'push') and ('url' in b[0]) == (mode != 'push'))
                check('_push_staged/%s: signed with the staged sha' % mode,
                      b[0].get('sha256') == shas['amd64'] and bool(b[0].get('sig')))
            real_ip = m.central_ip
            m.central_ip = lambda: '198.51.100.1'
            m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
            r = m._push_staged({**NODES[2], 'id': 'n3'})
            check('_push_staged/%s: the proxied node is served like any other' % mode,
                  r.get('ok') is True, json.dumps(r, ensure_ascii=False))
            m.central_ip = lambda: 'central-ip'
            m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
            r = m._push_staged({**NODES[2], 'id': 'n3'})
            check('_push_staged/%s: and refused when the panel cannot name itself' % mode,
                  r.get('ok') is True if mode != 'panel' else
                  (not r.get('ok') and 'آدرسِ خودش' in r.get('error', '')),
                  json.dumps(r, ensure_ascii=False))
            m.central_ip = real_ip
            m._CENTRAL_HOST['ip'], m._CENTRAL_HOST['ts'] = '', 0.0
    finally:
        shutil.rmtree(state, ignore_errors=True)
    print()
    if FAILED:
        print('%d FAILED:' % len(FAILED))
        for f in FAILED:
            print('  - ' + f)
        sys.exit(1)
    print('every mode delivers the same artifact; only the route changes.')


if __name__ == '__main__':
    main()
