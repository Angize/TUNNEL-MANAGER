#!/usr/bin/env python3
# tnl-central — control plane for a fleet of tnl nodes.
#
# Runs ONLY on the central server. Human logs in (user/password); the panel keeps a registry of
# node agents (host:port + token) and drives them over HTTP to build node<->node tunnels, view the
# whole fleet, and see each node's live status & stats. The central is a controller only — tunnel
# traffic flows directly between the two nodes, never through here.
#
# Usage:
#   sudo python3 tnl-central.py --install    # set user/password/port, install+start systemd service
#   sudo python3 tnl-central.py --set-pass   # change login credentials
#   sudo python3 tnl-central.py              # run (used by systemd)
#
# Plain HTTP: the session cookie is sniffable — run on a trusted network / VPN, or front with TLS.

import base64
import getpass
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CENTRAL_DIR = "/opt/tnl-central"
WEB_CONF = os.path.join(CENTRAL_DIR, "web.conf")
NODES_FILE = os.path.join(CENTRAL_DIR, "nodes.json")
LINKS_FILE = os.path.join(CENTRAL_DIR, "links.json")
TRAFFIC_FILE = os.path.join(CENTRAL_DIR, "traffic.json")
SETTINGS_FILE = os.path.join(CENTRAL_DIR, "settings.json")  # operator-tunable panel settings (reconcile mode, intervals, …)
AGENT_FILE = os.path.join(CENTRAL_DIR, "agent.py")          # the node-agent source the operator uploaded, pushed to nodes
AGENT_META = os.path.join(CENTRAL_DIR, "agent.meta.json")   # {version, sha256, size, uploaded_ts}
SERVICE_FILE = "/etc/systemd/system/tnl-central.service"
SELF_PATH = os.path.realpath(__file__)
INSTALLED = os.path.join(CENTRAL_DIR, "tnl-central.py")  # stable path the systemd unit points at

SESSION_TTL = 8 * 3600
PBKDF2_ITERS = 150_000
TYPES = ("vxlan", "gre", "sit")
_reg_lock = threading.Lock()     # serialize every nodes.json / links.json read-modify-write
_agent_lock = threading.Lock()   # serialize agent.py + agent.meta.json writes so they never tear apart
_node_locks = {}                 # per-node build locks: ops sharing a node serialize (no id collision) while
_node_locks_guard = threading.Lock()   # ops on disjoint nodes run concurrently — one hung node can't stall the fleet
_settings = {}                   # in-memory copy of settings.json (read hot-path by the loops); seeded in serve()
_settings_lock = threading.Lock()
_drift = {}                      # link_id -> True when a node IP has drifted and a rebuild is pending/needed
_drift_lock = threading.Lock()
_CENTRAL_PORT = 0                # panel port, advertised to nodes (X-Central-Port) so they can call back /api/checkin


class _PairLock:
    """Acquire the per-node build locks for the given node ids in a stable (sorted) order — deadlock-free."""
    def __init__(self, *node_ids):
        ids = sorted({str(i) for i in node_ids if i})
        with _node_locks_guard:
            self._locks = [_node_locks.setdefault(i, threading.Lock()) for i in ids]

    def __enter__(self):
        for lk in self._locks:
            lk.acquire()
        return self

    def __exit__(self, *a):
        for lk in reversed(self._locks):
            lk.release()


def _sint(v):
    try:
        return int(v)
    except Exception:
        return 0


def _sflt(v):
    try:
        return float(v)
    except Exception:
        return 0.0

# ----------------------------------------------------------------------------- auth / conf

def load_conf():
    with open(WEB_CONF) as f:
        return json.load(f)


def save_json(path, obj):
    os.makedirs(CENTRAL_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def save_text(path, txt):
    os.makedirs(CENTRAL_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(txt)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)

# ----------------------------------------------------------------------------- settings
# Operator-tunable knobs, persisted to settings.json and cached in memory. Kept deliberately open so
# new keys can be added later: unknown stored keys are preserved and unset keys fall back to defaults.

def settings_defaults():
    return {
        "reconcile_mode": "alert",  # default. "alert" = only flag a drifted tunnel; the operator clicks
                                    # بازسازی on the affected one. "auto" = panel rebuilds it itself (single-IP).
        "reconcile_interval": 15,   # seconds between reconcile sweeps (5–3600)
        "poll_interval": 2,         # seconds the fleet poller rests between sweeps (1–60)
    }


def load_settings():
    d = settings_defaults()
    try:
        with open(SETTINGS_FILE) as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            d.update(stored)  # merge over defaults so a missing key falls back and extra keys survive
    except Exception:
        pass
    return d


def get_settings():
    with _settings_lock:
        return dict(_settings) if _settings else load_settings()


def _seed_settings():
    with _settings_lock:
        _settings.clear()
        _settings.update(load_settings())


def validate_settings(d):
    """Merge a partial update onto the current settings, coercing/clamping the known knobs."""
    out = get_settings()
    if "reconcile_mode" in d:
        m = str(d["reconcile_mode"]).strip().lower()
        if m not in ("auto", "alert"):
            raise ValueError("حالت باید auto یا alert باشد")
        out["reconcile_mode"] = m
    if "reconcile_interval" in d and d["reconcile_interval"] not in (None, ""):
        out["reconcile_interval"] = max(5, min(3600, int(d["reconcile_interval"])))
    if "poll_interval" in d and d["poll_interval"] not in (None, ""):
        out["poll_interval"] = max(1, min(60, int(d["poll_interval"])))
    return out


def _set_drift(lid, val):
    with _drift_lock:
        if val:
            _drift[lid] = True
        else:
            _drift.pop(lid, None)


def link_drift(lid):
    with _drift_lock:
        return lid in _drift


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERS)
    return salt, dk.hex()


def verify_password(conf, password):
    try:
        _, got = hash_password(password, conf.get("salt", ""))
    except Exception:
        return False
    return hmac.compare_digest(got, conf.get("hash", ""))


def make_token(conf, user):
    body = f"{user}|{int(time.time()) + SESSION_TTL}"
    sig = hmac.new(bytes.fromhex(conf["secret"]), body.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}|{sig}".encode()).decode()


def check_token(conf, token):
    try:
        user, exp, sig = base64.urlsafe_b64decode(token.encode()).decode().rsplit("|", 2)
    except Exception:
        return None
    body = f"{user}|{exp}"
    good = hmac.new(bytes.fromhex(conf["secret"]), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig) or int(exp) < int(time.time()) or user != conf.get("user"):
        return None
    return user


_fails = {}
_fails_lock = threading.Lock()


def rate_limited(ip):
    with _fails_lock:
        rec = _fails.get(ip)
        if not rec:
            return False
        if time.time() - rec[1] > 300:
            _fails.pop(ip, None)
            return False
        return rec[0] >= 8


def note_fail(ip):
    with _fails_lock:
        now = time.time()
        for k in [k for k, v in _fails.items() if now - v[1] > 300]:  # drop stale IPs so the map can't grow unbounded
            _fails.pop(k, None)
        rec = _fails.get(ip)
        if not rec or now - rec[1] > 300:
            _fails[ip] = [1, now]
        else:
            rec[0] += 1

# ----------------------------------------------------------------------------- registry + node client

def is_ipv4(s):
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except Exception:
        return False


def load_nodes():
    try:
        with open(NODES_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def load_links():
    try:
        with open(LINKS_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def get_node(nid):
    return next((n for n in load_nodes() if n["id"] == nid), None)


def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise OSError("proxy closed the connection")
        buf += c
    return buf


def _socks5_socket(ph, pp, pu, pw, dh, dp, timeout):
    """Open a socket to dh:dp through a SOCKS5 proxy (stdlib, no PySocks)."""
    s = socket.create_connection((ph, pp), timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x02\x00\x02" if pu else b"\x05\x01\x00")  # offer no-auth (+ user/pass if creds given)
    _, method = _recvn(s, 2)
    if method == 2:
        if not pu:
            raise OSError("socks5 proxy requires auth")
        u, w = pu.encode(), (pw or "").encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
        if _recvn(s, 2)[1] != 0:
            raise OSError("socks5 auth rejected")
    elif method != 0:
        raise OSError("socks5 no supported auth method")
    try:
        addr = b"\x01" + socket.inet_aton(dh)          # IPv4 literal
    except OSError:
        hb = dh.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb          # domain name
    s.sendall(b"\x05\x01\x00" + addr + int(dp).to_bytes(2, "big"))
    rep = _recvn(s, 4)
    if rep[1] != 0:
        raise OSError(f"socks5 connect failed (code {rep[1]})")
    atyp = rep[3]  # drain the bound address so the socket is left at the tunnel body
    _recvn(s, 4 if atyp == 1 else 16 if atyp == 4 else _recvn(s, 1)[0])
    _recvn(s, 2)
    return s


def _http_connect_socket(ph, pp, pu, pw, dh, dp, timeout):
    """Open a socket to dh:dp through an HTTP CONNECT proxy."""
    s = socket.create_connection((ph, pp), timeout)
    s.settimeout(timeout)
    req = f"CONNECT {dh}:{dp} HTTP/1.1\r\nHost: {dh}:{dp}\r\n"
    if pu:
        req += "Proxy-Authorization: Basic " + base64.b64encode(f"{pu}:{pw or ''}".encode()).decode() + "\r\n"
    s.sendall((req + "\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            raise OSError("proxy closed the connection")
        buf += c
        if len(buf) > 65536:
            raise OSError("proxy response too large")
    line = buf.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 200" not in line:
        raise OSError("proxy CONNECT refused: " + line[:80])
    return s


def _node_call_proxied(node, proxy, endpoint, method, body, timeout):
    dh, dp = node["host"], int(node["port"])
    pu = urllib.parse.urlparse(proxy if "://" in proxy else "socks5://" + proxy)
    scheme = (pu.scheme or "socks5").lower()
    if not pu.hostname or not pu.port:
        return {"ok": False, "offline": True, "error": "bad proxy address"}
    try:
        if scheme.startswith("socks"):
            sock = _socks5_socket(pu.hostname, pu.port, pu.username, pu.password, dh, dp, timeout)
        elif scheme in ("http", "https", "connect"):
            sock = _http_connect_socket(pu.hostname, pu.port, pu.username, pu.password, dh, dp, timeout)
        else:
            return {"ok": False, "offline": True, "error": f"bad proxy scheme '{scheme}'"}
        conn = http.client.HTTPConnection(dh, dp, timeout=timeout)
        conn.sock = sock  # reuse the proxy-tunneled socket (skips conn.connect())
        data = json.dumps(body or {}).encode() if method == "POST" else None
        headers = {"X-Node-Token": node.get("token", "")}
        if _CENTRAL_PORT:
            headers["X-Central-Port"] = str(_CENTRAL_PORT)  # teach the node our callback port for /api/checkin
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, f"/api/{endpoint}", body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        conn.close()
        try:
            return json.loads(raw.decode())
        except Exception:
            return {"ok": False, "error": f"HTTP {r.status}"}
    except Exception as e:
        return {"ok": False, "offline": True, "error": ("proxy: " + str(e).split("] ")[-1])[:90]}


def node_call(node, endpoint, method="POST", body=None, timeout=8):
    proxy = (node.get("proxy") or "").strip()
    if proxy:  # route this node's control traffic through its SOCKS5/HTTP proxy
        return _node_call_proxied(node, proxy, endpoint, method, body, timeout)
    url = f"http://{node['host']}:{int(node['port'])}/api/{endpoint}"
    data = json.dumps(body or {}).encode() if method == "POST" else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Node-Token", node.get("token", ""))
    if _CENTRAL_PORT:
        req.add_header("X-Central-Port", str(_CENTRAL_PORT))  # teach the node our callback port for /api/checkin
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"ok": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"ok": False, "offline": True, "error": str(e).split("] ")[-1][:80]}


def parallel_map(fn, items, workers=32):
    """Run fn over items concurrently (I/O-bound node calls), preserving order."""
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))

# ----------------------------------------------------------------------------- fleet cache + poller
# The panel scales to hundreds of nodes by NEVER probing the fleet on the request path. A background
# poller continuously refreshes every node's ping+list into an in-memory cache; API endpoints read
# from that cache (O(page), not O(fleet)), so page loads stay instant no matter how big the fleet is.

POLL_WORKERS = 64          # concurrent node probes per sweep
POLL_GAP = 2               # seconds to rest between full sweeps
SWEEP_DEADLINE = 30        # a single hung node must never wedge the whole sweep past this
_pc = {}                   # node_id -> {"ping":..., "list":..., "ping_ts":t, "list_ts":t}
_pc_lock = threading.Lock()
_tf = {}                   # node_id -> {prev_ts, prev_up, if:{key:{prx,ptx,rx_bps,tx_bps,crx,ctx}}, seed:{}}
_tf_lock = threading.Lock()
TF_MAX_GAP = 120.0         # a poll gap bigger than this: keep the byte delta but suppress the smeared rate
TF_BPS_CEIL = 100e9        # 100 Gbit/s sanity ceiling — a larger computed rate is a garbage read -> treat as reset
_uh = {}                   # node_id -> {"ring":[1/0,...], "bts":ts, "dn":bool} — rolling up/down history (RAM only)
_uh_lock = threading.Lock()
UPTIME_BUCKET = 120        # seconds per uptime sample (a bucket is DOWN if the node was unreachable any time in it)
UPTIME_KEEP = 90           # ring length -> ~3h of history for the uptime bar


def _cache_get(nid):
    with _pc_lock:
        e = _pc.get(nid)
        return dict(e) if e else None


def _poll_node(n):
    ping = node_call(n, "ping", "GET", timeout=6)
    lst = node_call(n, "list", "GET", timeout=12)
    now = time.time()
    with _pc_lock:  # publish ping+list together so readers never see a torn (fresh-ping / stale-list) pair
        _pc[n["id"]] = {"ping": ping, "list": lst, "ping_ts": now, "list_ts": now}
    if ping.get("ok"):  # fold traffic under its own lock (never nested inside _pc_lock)
        s = ping.get("stats") or {}
        _tf_ingest(n["id"], s.get("net"), s.get("uptime"), now)
    else:               # unreachable -> decay rates to 0 so a dead node isn't counted as still flowing
        _tf_zero_rates(n["id"])
    _uh_sample(n["id"], bool(ping.get("ok")), now)


def _refresh_cache(nids):
    """Synchronously refresh the cache for a few nodes (after a mutation) so the UI updates at once."""
    nodes = {n["id"]: n for n in load_nodes()}
    parallel_map(_poll_node, [nodes[i] for i in dict.fromkeys(nids) if i in nodes])


def _ensure_cached(nodes):
    """Warm the cache for a bounded set of nodes (a single page) that the poller hasn't reached yet."""
    miss = [n for n in nodes if not _cache_get(n["id"])]
    if miss:
        parallel_map(_poll_node, miss)


def poller_loop():
    ex = ThreadPoolExecutor(max_workers=POLL_WORKERS)  # persistent; stragglers can't block the next sweep
    while True:
        try:
            nodes = load_nodes()
            valid = {n["id"] for n in nodes}
            with _pc_lock:
                for nid in [k for k in _pc if k not in valid]:
                    _pc.pop(nid, None)
            with _tf_lock:
                for nid in [k for k in _tf if k not in valid]:
                    _tf.pop(nid, None)
            with _uh_lock:
                for nid in [k for k in _uh if k not in valid]:
                    _uh.pop(nid, None)
            with _node_locks_guard:  # drop per-node build locks for removed nodes (skip any currently held)
                for nid in [k for k in _node_locks if k not in valid]:
                    lk = _node_locks.get(nid)
                    if lk is not None and not lk.locked():
                        _node_locks.pop(nid, None)
            if nodes:
                # submit all, then move on after the deadline — one trickling node can't freeze the fleet
                futures_wait([ex.submit(_poll_node, n) for n in nodes], timeout=SWEEP_DEADLINE)
        except Exception:
            pass
        time.sleep(max(1, int(get_settings().get("poll_interval", POLL_GAP) or POLL_GAP)))


def _cached_ping(nid):
    return (_cache_get(nid) or {}).get("ping") or {}


def _cached_list(nid):
    return (_cache_get(nid) or {}).get("list") or {}


# ----------------------------------------------------------------------------- traffic accounting
# Rates + lifetime byte totals are computed CENTRAL-side from the node's raw /proc/net/dev counters,
# folded into the same 2s poll (the poll cadence IS the sample clock). Reset / reboot / counter-wrap
# all collapse to "delta:=0, re-baseline", so a counter reset never fabricates a throughput spike or
# corrupts the lifetime total. cum only ever adds validated (>=0) deltas — never the raw counter.

def _tf_ingest(nid, net, up, now):
    if not isinstance(net, dict):
        return
    with _tf_lock:
        e = _tf.get(nid)
        if e is None:
            e = _tf[nid] = {"prev_ts": 0.0, "prev_up": None, "if": {}, "seed": {}}
        dt = (now - e["prev_ts"]) if e["prev_ts"] else 0
        reboot = e["prev_up"] is not None and up is not None and up < e["prev_up"]
        emit = (0 < dt <= TF_MAX_GAP) and not reboot   # normal sample: emit rate + accumulate bytes
        gap = dt > TF_MAX_GAP and not reboot            # long stall: keep the bytes, suppress the smeared rate
        ifs = e["if"]
        for key, v in net.items():
            if not (isinstance(v, list) and len(v) == 2):
                continue
            try:
                rx, tx = int(v[0]), int(v[1])
            except (TypeError, ValueError):
                continue
            s = ifs.get(key)
            if s is None:                               # first sample -> baseline; restore lifetime cum from seed
                sd = e["seed"].get(key)
                ifs[key] = {"prx": rx, "ptx": tx, "rx_bps": 0.0, "tx_bps": 0.0,
                            "crx": sd[0] if sd else 0, "ctx": sd[1] if sd else 0}
                continue
            for raw, pk, ck, bk in ((rx, "prx", "crx", "rx_bps"), (tx, "ptx", "ctx", "tx_bps")):
                draw = raw - s[pk]
                if draw < 0 or reboot:                  # counter went backwards / node rebooted -> don't fabricate
                    s[bk] = 0.0
                elif emit:
                    bps = draw * 8.0 / dt
                    if bps > TF_BPS_CEIL:               # garbage read
                        s[bk] = 0.0
                    else:
                        s[bk] = bps
                        s[ck] += draw
                elif gap:
                    s[bk] = 0.0
                    if draw <= TF_BPS_CEIL / 8.0 * dt:   # bound the gap credit too: ignore an implausibly large delta
                        s[ck] += draw
                s[pk] = raw
        e["prev_ts"] = now
        e["prev_up"] = up


def _tf_read(nid):
    """A copied-out snapshot of one node's per-iface rates + totals."""
    with _tf_lock:
        e = _tf.get(nid)
        return {k: dict(v) for k, v in e["if"].items()} if e else {}


def _tf_zero_rates(nid):
    """Node is unreachable this sweep -> zero its instantaneous rates (totals/baselines untouched)
    so a dead node stops contributing phantom throughput to the fleet/card figures."""
    with _tf_lock:
        e = _tf.get(nid)
        if e:
            for s in e["if"].values():
                s["rx_bps"] = 0.0
                s["tx_bps"] = 0.0


def _uh_sample(nid, up, now):
    """Record up/down into the rolling uptime ring; a bucket is DOWN if the node was unreachable at any
    poll during it. One sample per UPTIME_BUCKET seconds."""
    with _uh_lock:
        e = _uh.get(nid)
        if e is None:
            _uh[nid] = {"ring": [], "bts": now, "dn": not up}
            return
        if not up:
            e["dn"] = True
        if now - e["bts"] >= UPTIME_BUCKET:
            val = 0 if e["dn"] else 1
            missed = min(int((now - e["bts"]) / UPTIME_BUCKET), UPTIME_KEEP)  # backfill a multi-bucket gap, don't compress it
            e["ring"].extend([val] * missed)
            if len(e["ring"]) > UPTIME_KEEP:
                e["ring"] = e["ring"][-UPTIME_KEEP:]
            e["bts"] = now
            e["dn"] = not up


def _uh_ring(nid):
    with _uh_lock:
        e = _uh.get(nid)
        return list(e["ring"]) if e else []


def _tf_snapshot():
    """{nid: {ifkey: [cum_rx, cum_tx]}} for persistence (seed values survive for un-polled nodes)."""
    out = {}
    with _tf_lock:
        for nid, e in _tf.items():
            d = {k: [int(x[0]), int(x[1])] for k, x in e.get("seed", {}).items()}
            for k, s in e.get("if", {}).items():
                d[k] = [s["crx"], s["ctx"]]
            if d:
                out[nid] = d
    return out


def _tf_load():
    try:
        with open(TRAFFIC_FILE) as f:
            data = json.load(f)
    except Exception:
        return
    with _tf_lock:
        for nid, ifs in (data or {}).items():
            e = _tf.setdefault(nid, {"prev_ts": 0.0, "prev_up": None, "if": {}, "seed": {}})
            for k, v in (ifs or {}).items():
                if isinstance(v, list) and len(v) == 2:
                    e["seed"][k] = [int(v[0]), int(v[1])]


def traffic_persist_loop():
    while True:
        time.sleep(60)
        try:
            snap = _tf_snapshot()
            valid = {n["id"] for n in load_nodes()}
            save_json(TRAFFIC_FILE, {k: v for k, v in snap.items() if k in valid})
        except Exception:
            pass


def query_dict(path):
    """Parse a GET path's query string into a flat {key: value} dict (last value wins)."""
    return {k: v[-1] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(path).query).items()}


def _paginate(d, default_limit=25, max_limit=100):
    try:
        off = max(0, int(d.get("offset") or 0))
    except Exception:
        off = 0
    try:
        lim = int(d.get("limit") or default_limit)
    except Exception:
        lim = default_limit
    lim = max(1, min(max_limit, lim))
    return off, lim, str(d.get("q") or "").strip().lower()


def subnet_default(ttype, tid, base=None):
    if ttype == "sit":
        return f"fd00:{tid}::/64"
    if base == "10":
        return f"10.{tid}.0.0/24"
    if base == "172.16":
        return f"172.16.{tid}.0/24"
    return f"192.168.{tid}.0/24"


def norm_subnet(ttype, tid, provided, base=None):
    """A subnet valid for the type: keep the provided one if its IP version fits (v6 for SIT,
    v4 otherwise), else fall back to the type's default (optionally in a chosen private range).
    Prevents a v4 subnet reaching a SIT tunnel."""
    sub = provided or subnet_default(ttype, tid, base)
    want6 = (ttype == "sit")
    try:
        ok = ipaddress.ip_network(sub, strict=False).version == (6 if want6 else 4)
    except Exception:
        ok = False
    return sub if ok else subnet_default(ttype, tid, base)

# ----------------------------------------------------------------------------- central API

def _require(d, keys):
    for k in keys:
        if k not in d or d[k] in (None, ""):
            raise ValueError(f"missing field: {k}")


def valid_proxy(p):
    """Accept '' or a scheme://[user:pass@]host:port proxy (socks5/http). Returns the normalized value."""
    p = str(p or "").strip()
    if not p:
        return ""
    u = urllib.parse.urlparse(p if "://" in p else "socks5://" + p)
    if u.scheme.lower() not in ("socks5", "socks5h", "http", "https", "connect") or not u.hostname or not u.port:
        raise ValueError("پروکسی نامعتبر — نمونه: socks5://host:1080 یا http://user:pass@host:8080")
    return p if "://" in p else "socks5://" + p


def _node_view(n):
    base = {"id": n["id"], "name": n["name"], "host": n["host"], "port": n["port"], "proxy": n.get("proxy", ""),
            "uptime": _uh_ring(n["id"])}
    c = _cache_get(n["id"])
    if not c or c.get("ping") is None:
        return {**base, "online": False, "pending": True, "info": {"error": "در حال بررسی…"}}
    p = c["ping"]
    return {**base, "online": bool(p.get("ok")),
            "info": p if p.get("ok") else {"error": p.get("error", "unreachable")}}


def api_nodes(d):
    off, lim, q = _paginate(d)
    nodes = load_nodes()
    if q:
        nodes = [n for n in nodes if q in n["name"].lower() or q in n["host"].lower()]
    total = len(nodes)
    page = nodes[off:off + lim]
    _ensure_cached(page)  # bounded to one page — warms cold-start without touching the whole fleet
    return {"nodes": [_node_view(n) for n in page], "total": total, "offset": off, "limit": lim}


def api_node_names(d):
    """Compact list (id/name/host/online) of ALL nodes — for the create-tunnel pickers."""
    q = str(d.get("q") or "").strip().lower()
    out = []
    for n in load_nodes():
        if q and q not in n["name"].lower() and q not in n["host"].lower():
            continue
        p = _cached_ping(n["id"])
        out.append({"id": n["id"], "name": n["name"], "host": n["host"],
                    "online": bool(p.get("ok")), "info": {"ips": p.get("ips") or {}}})
    return {"nodes": out, "total": len(out)}


def _link_side_health(L, node_key):
    lst = _cached_list(L[node_key])
    if lst.get("configs") is None:
        return None, False  # node unreachable / not yet cached
    return (lst.get("health") or {}).get(L["name"]), True


def api_summary(d):
    nodes = load_nodes()
    links = load_links()
    on = tun = pf = mu = mt = du = dt = 0
    cpu_sum = load_sum = 0.0
    for n in nodes:
        p = _cached_ping(n["id"])
        if p.get("ok"):
            on += 1
            tun += _sint(p.get("tunnels"))
            pf += _sint(p.get("portfw"))
            s = p.get("stats")
            if not isinstance(s, dict):
                s = {}
            mu += _sint(s.get("mem_used_mb"))
            mt += _sint(s.get("mem_total_mb"))
            du += _sint(s.get("disk_used_mb"))
            dt += _sint(s.get("disk_total_mb"))
            cpu_sum += _sflt(s.get("cpu_pct"))
            _load = s.get("load")
            load_sum += _sflt(_load[0]) if isinstance(_load, list) and _load else 0.0
    healthy = 0
    for L in links:
        ah, aok = _link_side_health(L, "a_node")
        bh, bok = _link_side_health(L, "b_node")
        if isinstance(ah, dict) and ah.get("up") and isinstance(bh, dict) and bh.get("up"):
            healthy += 1
    frx_bps = ftx_bps = frx = ftx = 0
    with _tf_lock:
        for e in _tf.values():
            nd = e.get("if", {}).get("_node")
            if nd:
                frx_bps += nd["rx_bps"]
                ftx_bps += nd["tx_bps"]
                frx += nd["crx"]
                ftx += nd["ctx"]
    return {"nodes_online": on, "nodes_total": len(nodes), "links": len(links),
            "links_healthy": healthy, "tunnels": tun, "portfw": pf,
            "ram_pct": round(mu / mt * 100) if mt else 0,
            "cpu_pct": round(cpu_sum / on) if on else 0,
            "disk_pct": round(du / dt * 100) if dt else 0,
            "mem_used_mb": mu, "mem_total_mb": mt,
            "disk_used_mb": du, "disk_total_mb": dt,
            "load_avg": round(load_sum / on, 2) if on else 0,
            "fleet_rx_bps": frx_bps, "fleet_tx_bps": ftx_bps,
            "fleet_rx_total": frx, "fleet_tx_total": ftx}


def api_node_add(d):
    _require(d, ["name", "host", "port", "token"])
    name = str(d["name"]).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise ValueError("bad node name")
    host = str(d["host"]).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("bad host")
    port = int(d["port"])
    if not 1 <= port <= 65535:
        raise ValueError("bad port")
    token = str(d["token"]).strip()
    if not token:
        raise ValueError("token required")
    proxy = valid_proxy(d.get("proxy"))
    node = {"id": secrets.token_hex(5), "name": name, "host": host, "port": port, "token": token, "proxy": proxy}
    with _reg_lock:
        nodes = load_nodes()
        nodes.append(node)
        save_json(NODES_FILE, nodes)
    p = node_call(node, "ping", "GET")
    _refresh_cache([node["id"]])
    return {"ok": True, "id": node["id"], "online": bool(p.get("ok")),
            "error": "" if p.get("ok") else p.get("error", "unreachable")}


def api_node_edit(d):
    _require(d, ["id", "name", "host", "port"])
    name = str(d["name"]).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise ValueError("bad node name")
    host = str(d["host"]).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("bad host")
    port = int(d["port"])
    if not 1 <= port <= 65535:
        raise ValueError("bad port")
    token = str(d.get("token") or "").strip()
    proxy = valid_proxy(d.get("proxy"))  # validated here so a bad value never reaches the registry
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if x["id"] == d["id"]), None)
        if not n:
            raise ValueError("node not found")
        n["name"], n["host"], n["port"], n["proxy"] = name, host, port, proxy
        if token:
            n["token"] = token  # blank = keep the existing token
        save_json(NODES_FILE, nodes)
        links = load_links()  # keep the denormalized link names in sync with the rename
        chg = False
        for L in links:
            if L.get("a_node") == d["id"] and L.get("a_name") != name:
                L["a_name"], chg = name, True
            if L.get("b_node") == d["id"] and L.get("b_name") != name:
                L["b_name"], chg = name, True
        if chg:
            save_json(LINKS_FILE, links)
    p = node_call(n, "ping", "GET")
    _refresh_cache([d["id"]])
    return {"ok": True, "online": bool(p.get("ok")), "error": "" if p.get("ok") else p.get("error", "unreachable")}


def api_node_del(d):
    _require(d, ["id"])
    with _reg_lock:
        save_json(NODES_FILE, [n for n in load_nodes() if n["id"] != d["id"]])
    with _pc_lock:
        _pc.pop(d["id"], None)
    with _tf_lock:
        _tf.pop(d["id"], None)
    with _uh_lock:
        _uh.pop(d["id"], None)
    return {"ok": True}


def api_node_test(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    p = node_call(n, "ping", "GET")
    return {"ok": bool(p.get("ok")), "info": p}


def api_node_meta(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    p = node_call(n, "ping", "GET")
    if not p.get("ok"):
        raise ValueError("node offline")
    ips = [ip for ips in p.get("ips", {}).values() for ip in ips]
    return {"ips": ips}


def api_node_stats(d):
    """Fresh live stats for the node-details popup (CPU/RAM/Disk gauges) — bypasses the cache."""
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    p = node_call(n, "ping", "GET", timeout=8)
    if not p.get("ok"):
        return {"online": False, "error": p.get("error", "unreachable")}
    return {"online": True, "stats": p.get("stats") or {},
            "tunnels": p.get("tunnels"), "portfw": p.get("portfw"), "hostname": p.get("hostname")}


def api_node_traffic(d):
    """Live traffic for the node-details popup: node throughput/totals + per-tunnel rows (from _tf)."""
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    online = bool(_cached_ping(n["id"]).get("ok"))
    ifs = _tf_read(n["id"])
    node = ifs.get("_node", {})
    tunnels = []
    for L in load_links():
        if n["id"] in (L.get("a_node"), L.get("b_node")):
            t = ifs.get(L.get("name"))
            if t:
                tunnels.append({"name": L.get("name"), "type": L.get("type"),
                                "rx_bps": t["rx_bps"], "tx_bps": t["tx_bps"],
                                "rx_total": t["crx"], "tx_total": t["ctx"]})
    return {"online": online,
            "node": {"rx_bps": node.get("rx_bps", 0.0), "tx_bps": node.get("tx_bps", 0.0),
                     "rx_total": node.get("crx", 0), "tx_total": node.get("ctx", 0)},
            "tunnels": tunnels}


def api_agent_upload(d):
    """Store a new node-agent source in the panel (validated) so it can be pushed to the fleet."""
    _require(d, ["code"])
    src = d["code"]
    if not isinstance(src, str) or not src.strip():
        raise ValueError("کد خالی است")
    if len(src.encode()) > 262144:
        raise ValueError("فایل بیش از حد بزرگ است")
    try:
        compile(src, "tnl-node.py", "exec")            # same compile gate the node uses — a broken paste never gets stored
    except SyntaxError as e:
        raise ValueError("کد پایتون نامعتبر: " + str(e))
    if '"agent": "tnl-node"' not in src:               # sentinel: only the node agent can be pushed (never tnl-central.py)
        raise ValueError("این فایل ایجنتِ نود نیست")
    m = re.search(r'"version":\s*(\d+)', src)
    if not m:
        raise ValueError("نسخهٔ ایجنت در کد پیدا نشد")
    ver, sha = int(m.group(1)), hashlib.sha256(src.encode()).hexdigest()
    with _agent_lock:
        save_text(AGENT_FILE, src)
        save_json(AGENT_META, {"version": ver, "sha256": sha, "size": len(src.encode()), "uploaded_ts": int(time.time())})
    return {"ok": True, "version": ver, "sha256": sha[:12]}


def api_agent_info(d):
    """The stored agent's metadata (for the banner + per-node outdated badges)."""
    try:
        with open(AGENT_META) as f:
            return json.load(f)
    except Exception:
        return {"none": True}


def api_agent_push(d):
    """Push the stored agent to the given node ids; each node validates + swaps + self-restarts."""
    _require(d, ["ids"])
    try:
        with _agent_lock:                                # read code+meta atomically vs the locked upload write-pair
            with open(AGENT_FILE) as f:
                src = f.read()
            with open(AGENT_META) as f:
                meta = json.load(f)
    except OSError:
        raise ValueError("ابتدا یک ایجنت بارگذاری کنید")
    ids = [i for i in dict.fromkeys(d["ids"]) if get_node(i)]

    def push_one(nid):
        n = get_node(nid)
        if not n:                                        # deleted between the filter and here -> report it, don't crash the whole push
            return {"id": nid, "ok": False, "offline": True, "restarting": False, "already": False, "error": "node removed"}
        r = node_call(n, "update", "POST", {"code": src, "sha256": meta["sha256"]}, timeout=30)
        return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")),
                "restarting": bool(r.get("restarting")), "already": bool(r.get("already")), "error": r.get("error") or r.get("msg") or ""}

    return {"results": parallel_map(push_one, ids)}  # poller re-reads each node's version within ~2s after it bounces


def api_fleet(d):
    off, lim, q = _paginate(d)
    nodes = {n["id"]: n for n in load_nodes()}
    # resolve node names LIVE from the registry so a renamed node shows its current name here too
    links = []
    for L in load_links():
        links.append({**L, "a_name": nodes.get(L.get("a_node"), {}).get("name", L.get("a_name", "")),
                      "b_name": nodes.get(L.get("b_node"), {}).get("name", L.get("b_name", ""))})
    if q:
        links = [L for L in links if q in L["a_name"].lower() or q in L["b_name"].lower()
                 or q in L.get("type", "").lower() or q in str(L.get("tunnel_id", "")).lower()]
    total = len(links)
    page = links[off:off + lim]
    need = {L[k] for L in page for k in ("a_node", "b_node")}
    _ensure_cached([nodes[i] for i in need if i in nodes])  # bounded to the page's nodes
    with _tf_lock:  # snapshot per-link traffic once under the lock (either side carries the same iface name)
        tfl = {}
        for L in page:
            for nid in (L["a_node"], L["b_node"]):
                s = (_tf.get(nid) or {}).get("if", {}).get(L["name"])
                if s:
                    tfl[L["id"]] = {"rx_bps": s["rx_bps"], "tx_bps": s["tx_bps"],
                                    "rx_total": s["crx"], "tx_total": s["ctx"]}
                    break
    out = []
    for L in page:
        la, lb = _cached_list(L["a_node"]), _cached_list(L["b_node"])
        ah = (la.get("health") or {}).get(L["name"]) if la.get("configs") is not None else None
        bh = (lb.get("health") or {}).get(L["name"]) if lb.get("configs") is not None else None
        out.append({**L, "a_online": bool(la.get("ok")) or la.get("configs") is not None,
                    "b_online": bool(lb.get("ok")) or lb.get("configs") is not None,
                    "a_health": ah, "b_health": bh, "drift": link_drift(L["id"]), **tfl.get(L["id"], {})})
    return {"links": out, "total": total, "offset": off, "limit": lim}


def _link_nodes(d):
    L = next((x for x in load_links() if x.get("id") == (d or {}).get("id")), None)
    return (L["a_node"], L["b_node"]) if L else (None, None)


def api_create_tunnel(d):
    d = d or {}
    with _PairLock(d.get("a_node"), d.get("b_node")):  # lock only the two nodes involved; unrelated pairs build concurrently
        return _create_tunnel_impl(d)


def _create_tunnel_impl(d):
    _require(d, ["a_node", "b_node", "type"])
    A, B = get_node(d["a_node"]), get_node(d["b_node"])
    if not A or not B:
        raise ValueError("node not found")
    if A["id"] == B["id"]:
        raise ValueError("pick two different nodes")
    ttype = d["type"]
    if ttype not in TYPES:
        raise ValueError("bad type")
    for L in load_links():  # one tunnel of each type per node-pair (any direction)
        if L.get("type") == ttype and {L.get("a_node"), L.get("b_node")} == {A["id"], B["id"]}:
            raise ValueError(f"یک تونلِ {ttype} بینِ این دو نود از قبل ساخته شده")
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"node '{A['name']}' offline")
    if not pb.get("ok"):
        raise ValueError(f"node '{B['name']}' offline")
    a_ips = [ip for ips in pa.get("ips", {}).values() for ip in ips]
    b_ips = [ip for ips in pb.get("ips", {}).values() for ip in ips]
    a_ip = d.get("a_ip") or (a_ips[0] if a_ips else None)
    b_ip = d.get("b_ip") or (b_ips[0] if b_ips else None)
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("could not determine node IPs")
    la = node_call(A, "list", "GET", timeout=30)
    lb = node_call(B, "list", "GET", timeout=30)
    if la.get("configs") is None or lb.get("configs") is None:
        raise ValueError("could not read existing tunnels from a node (busy/offline); aborted to avoid an id collision")
    used = set()
    for L in (la, lb):
        for c in L.get("configs", []):
            try:
                used.add(int(c.get("id")))
            except Exception:
                pass
    explicit = int(d.get("id") or 0)
    if explicit and not 1 <= explicit <= 254:
        raise ValueError("شناسهٔ تونل خارج از محدوده است (۱ تا ۲۵۴)")
    if explicit and explicit in used:
        raise ValueError(f"tunnel id {explicit} is already in use on one of the nodes")
    tid = explicit or next((i for i in range(42, 255) if i not in used), 0)
    if not tid:
        raise ValueError("no free tunnel id on the pair")
    subnet = norm_subnet(ttype, tid, d.get("subnet"), d.get("subnet_base"))
    name = f"{ttype}{tid}"
    ra = node_call(A, "tunnel", "POST", {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip,
                                         "subnet": subnet, "id": tid, "name": name}, timeout=200)
    if not ra.get("ok"):
        raise ValueError(f"node '{A['name']}': {ra.get('error') or ra.get('msg')}")
    rb = node_call(B, "tunnel", "POST", {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip,
                                         "subnet": subnet, "id": tid, "name": name}, timeout=200)
    if not rb.get("ok"):
        rr = node_call(A, "delete", "POST", {"name": name})  # roll back A side
        warn = "" if rr.get("ok") else f" — هشدار: '{name}' روی {A['name']} پاک نشد، دستی تمیزش کن"
        raise ValueError(f"node '{B['name']}': {rb.get('error') or rb.get('msg')} (rolled back {A['name']}){warn}")
    try:
        with _reg_lock:  # atomic append so a concurrent delete-link can't lose/resurrect a record
            links = load_links()
            links.append({"id": secrets.token_hex(6), "name": name, "type": ttype, "subnet": subnet,
                          "tunnel_id": tid, "a_node": A["id"], "a_name": A["name"], "a_ip": a_ip,
                          "b_node": B["id"], "b_name": B["name"], "b_ip": b_ip, "created": int(time.time())})
            save_json(LINKS_FILE, links)
    except Exception as e:  # tunnels are live on BOTH nodes but the record failed to persist — tear them back down
        da = node_call(A, "delete", "POST", {"name": name})
        db = node_call(B, "delete", "POST", {"name": name})
        stuck = "، ".join(N["name"] for N, r in ((A, da), (B, db)) if not r.get("ok"))
        warn = f" — هشدار: '{name}' روی {stuck} پاک نشد، دستی تمیزش کن" if stuck else ""
        raise ValueError(f"ذخیرهٔ رکوردِ لینک شکست خورد؛ تونل‌ها برچیده شدند{warn} ({str(e)[:80]})")
    _refresh_cache([A["id"], B["id"]])
    return {"ok": True, "name": name, "a_tunnel_ip": ra.get("tunnel_ip"), "b_tunnel_ip": rb.get("tunnel_ip")}


def api_delete_link(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")
    errs = []
    for nid, nm in ((L["a_node"], L["a_name"]), (L["b_node"], L["b_name"])):
        n = get_node(nid)
        if n:
            r = node_call(n, "delete", "POST", {"name": L["name"]})
            if not r.get("ok"):
                errs.append(f"{nm}: {r.get('error')}")
    if errs:  # a registered node failed/was offline — KEEP the record so a later delete can finish teardown (no orphans)
        _refresh_cache([L["a_node"], L["b_node"]])
        return {"ok": False, "msg": "; ".join(errs) + " — لینک نگه داشته شد؛ وقتی نود در دسترس شد دوباره حذف کن"}
    with _reg_lock:  # atomic RMW; re-read so a concurrent create isn't clobbered
        save_json(LINKS_FILE, [x for x in load_links() if x["id"] != d["id"]])
    _refresh_cache([L["a_node"], L["b_node"]])
    return {"ok": True}


def _restore_link(A, B, L):
    """Best-effort rebuild of the OLD tunnel on both sides (used to roll back a failed edit)."""
    tid = int(L["tunnel_id"])
    for N, self_ip, peer_ip in ((A, L["a_ip"], L["b_ip"]), (B, L["b_ip"], L["a_ip"])):
        if N:
            node_call(N, "tunnel", "POST", {"type": L["type"], "self_ip": self_ip, "peer_ip": peer_ip,
                                            "subnet": L["subnet"], "id": tid, "name": L["name"]}, timeout=200)


def api_edit_link(d):
    a, b = _link_nodes(d)
    with _PairLock(a, b):  # serialize only with ops touching the same node(s)
        return _edit_link_impl(d)


def _edit_link_impl(d):
    _require(d, ["id", "type"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")
    ttype = d["type"]
    if ttype not in TYPES:
        raise ValueError("bad type")
    for x in load_links():  # keep one-of-each-type-per-pair when changing type
        if (x.get("id") != L["id"] and x.get("type") == ttype
                and {x.get("a_node"), x.get("b_node")} == {L["a_node"], L["b_node"]}):
            raise ValueError(f"یک تونلِ {ttype} بینِ این دو نود از قبل هست")
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise ValueError("a node of this link is no longer registered")
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"node '{A['name']}' offline")
    if not pb.get("ok"):
        raise ValueError(f"node '{B['name']}' offline")
    tid = int(L["tunnel_id"])
    a_ips = [ip for ips in pa.get("ips", {}).values() for ip in ips]
    b_ips = [ip for ips in pb.get("ips", {}).values() for ip in ips]
    a_ip = L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)
    b_ip = L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("could not determine node IPs")
    subnet = norm_subnet(ttype, tid, d.get("subnet"))
    old_name = L["name"]
    name_changed = ttype != L["type"]  # the interface name encodes the type (vxlanNN vs greNN)
    new_name = f"{ttype}{tid}" if name_changed else old_name
    if ttype == L["type"] and subnet == L["subnet"] and a_ip == L["a_ip"] and b_ip == L["b_ip"]:
        return {"ok": True, "unchanged": True, "name": old_name}
    if name_changed:  # veth/OVS ids are shared per tunnel_id, so the old iface must go before the new one
        node_call(A, "delete", "POST", {"name": old_name})
        node_call(B, "delete", "POST", {"name": old_name})
    ra = node_call(A, "tunnel", "POST", {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip,
                                         "subnet": subnet, "id": tid, "name": new_name}, timeout=200)
    if not ra.get("ok"):
        _restore_link(A, B, L)
        raise ValueError(f"node '{A['name']}': {ra.get('error') or ra.get('msg')} (restored old tunnel)")
    rb = node_call(B, "tunnel", "POST", {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip,
                                         "subnet": subnet, "id": tid, "name": new_name}, timeout=200)
    if not rb.get("ok"):
        if name_changed:
            node_call(A, "delete", "POST", {"name": new_name})
            node_call(B, "delete", "POST", {"name": new_name})
        _restore_link(A, B, L)
        raise ValueError(f"node '{B['name']}': {rb.get('error') or rb.get('msg')} (restored old tunnel)")
    with _reg_lock:
        links = load_links()
        for x in links:
            if x["id"] == L["id"]:
                x.update({"name": new_name, "type": ttype, "subnet": subnet, "a_ip": a_ip, "b_ip": b_ip})
                break
        save_json(LINKS_FILE, links)
    _refresh_cache([L["a_node"], L["b_node"]])
    return {"ok": True, "name": new_name, "a_tunnel_ip": ra.get("tunnel_ip"), "b_tunnel_ip": rb.get("tunnel_ip")}


def api_check_link(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")

    def chk(nid):
        n = get_node(nid)
        if not n:
            return {"online": False, "health": None}
        r = node_call(n, "check", "POST", {"name": L["name"]}, timeout=30)
        if r.get("ok"):
            return {"online": True, "health": r.get("health")}
        if r.get("offline"):
            return {"online": False, "health": None}
        return {"online": True, "health": None}  # node up but tunnel unknown/error

    a, b = parallel_map(chk, [L["a_node"], L["b_node"]])  # ping both ends at once (halves the wait)
    return {"ok": True, "name": L["name"], "a_online": a["online"], "b_online": b["online"],
            "a_health": a["health"], "b_health": b["health"]}


def api_rebuild_link(d):
    a, b = _link_nodes(d)
    with _PairLock(a, b):
        return _rebuild_link_impl(d)


def _rebuild_link_impl(d):
    """Tear the tunnel down on both nodes and build it again with the SAME params (id/type/subnet)."""
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise ValueError("a node of this link is no longer registered")
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"node '{A['name']}' offline")
    if not pb.get("ok"):
        raise ValueError(f"node '{B['name']}' offline")
    tid, ttype, subnet, name = int(L["tunnel_id"]), L["type"], L["subnet"], L["name"]
    a_ips = [ip for ips in pa.get("ips", {}).values() for ip in ips]
    b_ips = [ip for ips in pb.get("ips", {}).values() for ip in ips]
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()  # operator's explicit pick
    a_ip = (want_a if want_a in a_ips else
            (L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)))
    b_ip = (want_b if want_b in b_ips else
            (L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)))
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("could not determine node IPs")
    node_call(A, "delete", "POST", {"name": name})  # tear down both ends first
    node_call(B, "delete", "POST", {"name": name})
    ra = node_call(A, "tunnel", "POST", {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip,
                                         "subnet": subnet, "id": tid, "name": name}, timeout=200)
    if not ra.get("ok"):
        _restore_link(A, B, L)   # both ends were pre-deleted; best-effort rebuild to the prior state
        raise ValueError(f"node '{A['name']}': {ra.get('error') or ra.get('msg')} (تلاش برای بازگردانی)")
    rb = node_call(B, "tunnel", "POST", {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip,
                                         "subnet": subnet, "id": tid, "name": name}, timeout=200)
    if not rb.get("ok"):
        _restore_link(A, B, L)
        raise ValueError(f"node '{B['name']}': {rb.get('error') or rb.get('msg')} (تلاش برای بازگردانی)")
    if a_ip != L["a_ip"] or b_ip != L["b_ip"]:
        with _reg_lock:
            links = load_links()
            for x in links:
                if x["id"] == L["id"]:
                    x.update({"a_ip": a_ip, "b_ip": b_ip})
                    break
            save_json(LINKS_FILE, links)
    _set_drift(L["id"], False)  # rebuilt with live IPs -> any pending drift warning is resolved
    _refresh_cache([L["a_node"], L["b_node"]])
    return {"ok": True, "name": name}


# --------------------------------------------------------------------------- link reconciler
# When a node's public IP changes, apply_all() on THAT node self-heals its own local_ip — but the
# PEER still points remote_ip at the old address, so the tunnel stays down until an operator rebuilds
# it. This loop closes the gap: it watches every link for a stored endpoint IP that has drifted off
# the node's live IP set, and rebuilds the link — which rewrites remote_ip on the peer AND the record.

RECONCILE_GAP = 15       # default seconds between reconcile sweeps (overridable via settings)
RECONCILE_RETRY = 60     # per-link cool-down so a failing rebuild can't hammer the pair
_reconcile_last = {}     # link_id -> last rebuild-attempt ts (touched only by the single reconcile thread)


def _reconcile_once():
    mode = get_settings().get("reconcile_mode", "auto")
    now = time.time()
    links = load_links()
    valid_ids = {L["id"] for L in links}
    for k in [k for k in _reconcile_last if k not in valid_ids]:  # prune records for deleted links
        _reconcile_last.pop(k, None)
    with _drift_lock:
        for k in [k for k in _drift if k not in valid_ids]:
            _drift.pop(k, None)
    for L in links:
        pa, pb = _cached_ping(L["a_node"]), _cached_ping(L["b_node"])
        if not pa.get("ok") or not pb.get("ok"):
            continue  # only reconcile when BOTH ends are up — a rebuild needs both reachable
        a_ips = [ip for ips in pa.get("ips", {}).values() for ip in ips]
        b_ips = [ip for ips in pb.get("ips", {}).values() for ip in ips]
        if not a_ips or not b_ips:
            continue
        a_ok, b_ok = L.get("a_ip") in a_ips, L.get("b_ip") in b_ips
        if a_ok and b_ok:
            _set_drift(L["id"], False)  # both endpoints valid (healed / IP came back) -> clear the flag
            continue
        _set_drift(L["id"], True)       # a node IP has drifted off the link
        if mode != "auto":
            continue                    # global "alert" mode: only flag it; the operator rebuilds from the UI
        # auto mode heals ONLY when every drifted side is unambiguous — the node has exactly one live IP,
        # so there is no doubt which IP replaced the old one. A multi-IP node is left flagged for the
        # operator to pick the right IP in the UI (guessing among several IPs isn't safe).
        ambiguous = (not a_ok and len(a_ips) != 1) or (not b_ok and len(b_ips) != 1)
        if ambiguous:
            continue
        if now - _reconcile_last.get(L["id"], 0) < RECONCILE_RETRY:
            continue
        _reconcile_last[L["id"]] = now
        try:
            r = api_rebuild_link({"id": L["id"]})  # single-IP side(s): rebuild binds to the only live IP
            if r.get("ok"):
                _set_drift(L["id"], False)
        except Exception:
            pass


def reconcile_loop():
    while True:
        time.sleep(max(5, int(get_settings().get("reconcile_interval", RECONCILE_GAP) or RECONCILE_GAP)))
        try:
            _reconcile_once()
        except Exception:
            pass


def api_portfw(d):
    _require(d, ["node", "listen_port", "dst_port", "dst_ips"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    body = {"listen_port": d["listen_port"], "dst_port": d["dst_port"],
            "dst_ips": d["dst_ips"], "interval_min": d.get("interval_min", 5)}
    if d.get("iface"):
        body["iface"] = d["iface"]
    r = node_call(n, "portfw", "POST", body, timeout=120)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    _refresh_cache([n["id"]])
    return {"ok": True, "name": r.get("name")}


def api_portfw_list(d):
    off, lim, q = _paginate(d)
    all_pf = []
    for n in load_nodes():  # aggregate from the cache (RAM) — no live probing on the request path
        r = _cached_list(n["id"])
        if r.get("configs") is None:
            continue
        h = r.get("health") or {}
        for c in r["configs"]:
            if c.get("type") != "portfw":
                continue
            if q and q not in n["name"].lower() and q not in str(c.get("name", "")).lower():
                continue
            all_pf.append({"node": n["name"], "node_id": n["id"], "name": c.get("name"),
                           "iface": c.get("iface"), "listen_port": c.get("listen_port"),
                           "dst_port": c.get("dst_port"), "dst_ips": c.get("dst_ips", []),
                           "switch_interval": c.get("switch_interval", 0), "health": h.get(c.get("name"))})
    return {"portfw": all_pf[off:off + lim], "total": len(all_pf), "offset": off, "limit": lim}


def api_portfw_edit(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    body = {"name": d["name"]}
    for k in ("listen_port", "dst_port", "dst_ips", "interval_min", "iface"):
        if d.get(k) not in (None, ""):
            body[k] = d[k]
    if "rotate" in d:
        body["rotate"] = bool(d["rotate"])
    r = node_call(n, "portfw-edit", "POST", body, timeout=120)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    _refresh_cache([n["id"]])
    return {"ok": True, "name": r.get("name")}


def api_portfw_next(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    r = node_call(n, "portfw-next", "POST", {"name": d["name"]}, timeout=60)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    _refresh_cache([n["id"]])
    return {"ok": True, "active": r.get("active")}


def api_portfw_del(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    r = node_call(n, "delete", "POST", {"name": d["name"]})
    _refresh_cache([n["id"]])
    return {"ok": bool(r.get("ok")), "msg": r.get("error", "")}


def _flat_ips(ping):
    return [ip for ips in (ping.get("ips") or {}).values() for ip in ips]


def _node_ip_tags(nid):
    """Each current live IP of a node, tagged with which peer node(s) it's tunneled to and the tunnel
    type of each — so the operator can tell where an IP is used (and pick a free one for a drifted link).
    Each peer entry is {node, type}; an IP with no peers is 'free'."""
    n = get_node(nid)
    if not n:
        return []
    live = []
    for ip in _flat_ips(_cached_ping(nid)):
        if ip not in live:
            live.append(ip)
    peers = {}
    for L in load_links():
        if L.get("a_node") == nid and L.get("a_ip"):
            peers.setdefault(L["a_ip"], []).append({"node": L.get("b_name") or "", "type": L.get("type") or ""})
        if L.get("b_node") == nid and L.get("b_ip"):
            peers.setdefault(L["b_ip"], []).append({"node": L.get("a_name") or "", "type": L.get("type") or ""})
    host = n.get("host")
    out = []
    for ip in live:
        pl = [p for p in peers.get(ip, []) if p["node"]]
        out.append({"ip": ip, "host": ip == host, "peers": pl, "free": (not pl)})
    return out


def api_node_ips(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    return {"online": bool(_cached_ping(n["id"]).get("ok")), "ips": _node_ip_tags(n["id"])}


def api_link_rebuild_info(d):
    """For the manual-rebuild picker: each side's current IPs (tagged) + which side has drifted."""
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")

    def side(node_key, ip_key, name_key):
        nid = L.get(node_key)
        p = _cached_ping(nid)
        live = _flat_ips(p)
        return {"node_id": nid, "node": L.get(name_key) or (get_node(nid) or {}).get("name", ""),
                "cur_ip": L.get(ip_key), "online": bool(p.get("ok")),
                "drifted": bool(p.get("ok")) and L.get(ip_key) not in live,
                "multi": len(live) > 1, "ips": _node_ip_tags(nid)}

    return {"id": L["id"], "name": L.get("name"),
            "a": side("a_node", "a_ip", "a_name"), "b": side("b_node", "b_ip", "b_name")}


def api_settings(d):
    return get_settings()


def api_settings_set(d):
    obj = validate_settings(d or {})
    with _settings_lock:
        _settings.clear()
        _settings.update(obj)
    save_json(SETTINGS_FILE, obj)
    return {"ok": True, "settings": obj}


def api_checkin_impl(source_ip, d):
    """Node -> central check-in. Authenticated by the node's own token (NOT a panel session). Lets a node
    whose public IP changed tell the panel where it moved to, so control traffic can find it again — the
    reconciler then heals the tunnels. We only adopt the new address when the panel currently CAN'T reach
    the node at its stored host, so a working DNS name / static host is never clobbered."""
    tok = str((d or {}).get("token") or "")
    if not tok:
        return {"ok": False, "error": "token required"}
    changed = False
    host = None
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if hmac.compare_digest(str(x.get("token", "")), tok)), None)
        if not n:
            return {"ok": False, "error": "unknown node"}
        host = n.get("host")
        if (source_ip and is_ipv4(source_ip) and n.get("host") != source_ip
                and not _cached_ping(n["id"]).get("ok")):
            n["host"], host, changed = source_ip, source_ip, True
            save_json(NODES_FILE, nodes)
        nid = n["id"]
    if changed:
        _refresh_cache([nid])  # re-probe at the new address at once so the fleet view + reconciler catch up
    return {"ok": True, "updated": changed, "host": host}


API = {
    "nodes": api_nodes, "node-names": api_node_names, "summary": api_summary,
    "settings": api_settings, "settings-set": api_settings_set,
    "node-add": api_node_add, "node-edit": api_node_edit, "node-del": api_node_del,
    "node-test": api_node_test, "node-meta": api_node_meta, "node-stats": api_node_stats,
    "node-ips": api_node_ips, "link-rebuild-info": api_link_rebuild_info,
    "traffic": api_node_traffic, "fleet": api_fleet,
    "create-tunnel": api_create_tunnel, "edit-link": api_edit_link, "check-link": api_check_link,
    "rebuild-link": api_rebuild_link, "delete-link": api_delete_link,
    "portfw": api_portfw, "portfw-list": api_portfw_list, "portfw-edit": api_portfw_edit,
    "portfw-next": api_portfw_next, "portfw-del": api_portfw_del,
    "agent-upload": api_agent_upload, "agent-info": api_agent_info, "agent-push": api_agent_push,
}
MUTATIONS = {"node-add", "node-edit", "node-del", "create-tunnel", "edit-link", "rebuild-link",
             "delete-link", "portfw", "portfw-edit", "portfw-next", "portfw-del",
             "agent-upload", "agent-push", "settings-set"}

# ----------------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-central"
    timeout = 60   # per-connection socket timeout so a slow/silent client can't pin a worker thread forever (slowloris)

    def log_message(self, *a):
        pass

    def _conf(self):
        return self.server.conf

    def _user(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return check_token(self._conf(), c["tnl_session"].value) if "tnl_session" in c else None

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        n = min(max(n, 0), 1048576)   # 1MB — headroom for the agent-upload source (JSON-escaped)
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}   # a top-level array/string/number must not reach handlers as non-dict

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML if self._user() else LOGIN_HTML, "text/html; charset=utf-8")
        elif path.startswith("/api/"):
            self._api(path[5:], "GET")
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/login":
            self._login()
        elif path == "/api/checkin":
            self._checkin()  # node -> central; token-authenticated inside, no panel session required
        elif path == "/api/logout":
            secure = "; Secure" if self._conf().get("tls") else ""
            self._send(200, {"ok": True}, extra={"Set-Cookie": "tnl_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" + secure})
        elif path.startswith("/api/"):
            self._api(path[5:], "POST")
        else:
            self._send(404, {"error": "not found"})

    def _login(self):
        ip = self.client_address[0]
        if rate_limited(ip):
            self._send(429, {"error": "too many attempts, wait a few minutes"})
            return
        d = self._body()
        conf = self._conf()
        time.sleep(0.3)
        if str(d.get("user", "")) == conf.get("user") and verify_password(conf, str(d.get("pass", ""))):
            secure = "; Secure" if conf.get("tls") else ""   # set conf["tls"]=true when TLS-fronted so the cookie never rides plain HTTP
            cookie = f"tnl_session={make_token(conf, conf['user'])}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict{secure}"
            self._send(200, {"ok": True}, extra={"Set-Cookie": cookie})
        else:
            note_fail(ip)
            self._send(401, {"error": "wrong username or password"})

    def _checkin(self):
        res = api_checkin_impl(self.client_address[0], self._body())
        self._send(200 if res.get("ok") else 401, res)

    def _api(self, cmd, method):
        if not self._user():
            self._send(401, {"error": "not logged in"})
            return
        if cmd not in API:
            self._send(404, {"error": "unknown endpoint"})
            return
        if cmd in MUTATIONS:
            if method != "POST":
                self._send(405, {"error": "use POST"})
                return
            if self.headers.get("X-Requested-With") != "tnl-central":
                self._send(403, {"error": "bad request"})
                return
        d = self._body() if method == "POST" else query_dict(self.path)  # GET query powers pagination+search
        try:
            self._send(200, API[cmd](d))
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"internal error: {str(e)[:120]}"})

# ----------------------------------------------------------------------------- UI

LOGIN_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ورود · کنترل فلیت</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;800&display=swap');
:root{--acc:#4d6bf0;--acc2:#12a5b8;--page:#eef1f6;--card:#ffffff;--tx:#232b36;--sub:#727e8c;--bord:#e5e9f0;--field:#f4f6fa;--bad:#d1524a;--hi:transparent}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{height:100%}body{font-family:Vazirmatn,Tahoma,sans-serif;color:var(--tx);background:var(--page);min-height:100%;display:flex;align-items:center;justify-content:center;padding:18px}
body::before{content:'';position:fixed;inset:0;z-index:-1;background:radial-gradient(620px 420px at 85% -6%,color-mix(in srgb,var(--acc) 16%,transparent),transparent 70%),radial-gradient(520px 400px at -10% 40%,color-mix(in srgb,var(--acc2) 10%,transparent),transparent 70%)}
.box{position:relative;overflow:hidden;width:340px;border-radius:18px;padding:26px 22px;background:var(--card);border:1px solid var(--bord);box-shadow:0 22px 54px -26px rgba(40,60,100,.28)}
h1{font-size:20px;font-weight:800;display:flex;align-items:center;gap:9px}h1 b{color:var(--acc)}
.chip{width:36px;height:36px;border-radius:12px;display:inline-flex;align-items:center;justify-content:center;background:color-mix(in srgb,var(--acc) 16%,transparent);border:1px solid color-mix(in srgb,var(--acc) 30%,transparent);box-shadow:0 0 18px -2px color-mix(in srgb,var(--acc) 45%,transparent)}
.chip svg{width:19px;height:19px;stroke:var(--acc);fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}
p.s{color:var(--sub);font-size:12.5px;margin:8px 2px 18px}
label{display:block;font-size:12px;color:var(--sub);margin:14px 2px 7px}
input{width:100%;padding:12px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-size:14px;font-family:inherit}
input:focus{outline:none;border-color:color-mix(in srgb,var(--acc) 60%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 16%,transparent)}
button{width:100%;margin-top:22px;padding:13px;border:0;border-radius:12px;background:var(--acc);color:#fff;font-weight:800;font-size:14px;font-family:inherit;cursor:pointer;box-shadow:0 10px 24px -12px color-mix(in srgb,var(--acc) 70%,transparent)}
button:active{transform:scale(.98)}
.e{color:var(--bad);font-size:12.5px;margin-top:14px;min-height:18px;text-align:center}
</style></head><body>
<form class="box" onsubmit="return login(event)">
<h1><span class="chip"><svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></span> <span><b>tnl</b> کنترل فلیت</span></h1>
<p class="s">برای ورود، نام کاربری و رمز را وارد کنید</p>
<label>نام کاربری</label><input id="u" autocomplete="username" autofocus>
<label>رمز عبور</label><input id="p" type="password" autocomplete="current-password">
<button>ورود</button><div class="e" id="e"></div></form>
<script>
async function login(ev){ev.preventDefault();var e=document.getElementById('e');e.textContent='';
 var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:u.value,pass:p.value})});
 var j=await r.json().catch(()=>({}));if(r.ok)location.href='/';else e.textContent=j.error||'ورود ناموفق';return false}
</script></body></html>"""

INDEX_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>tnl · کنترل فلیت</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;800&display=swap');
:root{--acc:#4d6bf0;--acc2:#12a5b8;--ok:#2f9e6f;--bad:#d1524a;--gold:#bd7f18;
--page:#eef1f6;--card:#ffffff;--side:#ffffff;--glass:#f1f4f8;--field:#f4f6fa;--bord:#e5e9f0;
--tx:#232b36;--sub:#727e8c;--chart1:#6d5cf0;--chart2:#12a5b8;--hi:transparent;--dsh:0 10px 26px -18px rgba(40,60,100,.2);
--accw:#eef1fe;--okw:#e8f6ef;--badw:#fbeceb;--warnw:#f7efe0;--sh-sm:0 1px 2px rgba(20,30,50,.05)}
body.dark{--acc:#6f8dff;--acc2:#3fd0e0;--ok:#4ec99a;--bad:#f0736a;--gold:#e0a83a;
--page:#0e1420;--card:#161f2e;--side:#111826;--glass:#1a2333;--field:#131c29;--bord:#243040;
--tx:#e6ecf4;--sub:#8b98aa;--chart1:#8f9dff;--chart2:#3fd0e0;--hi:transparent;--dsh:0 14px 34px -20px rgba(0,0,0,.6);
--accw:rgba(111,141,255,.14);--okw:rgba(78,201,154,.13);--badw:rgba(240,115,106,.13);--warnw:rgba(224,168,58,.12);--sh-sm:0 1px 2px rgba(0,0,0,.3)}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{height:100%;background:var(--page)}
body{font-family:Vazirmatn,Tahoma,sans-serif;color:var(--tx);background:var(--page);min-height:100vh}
.shell{display:flex;min-height:100vh}
.side{width:236px;flex:0 0 236px;background:var(--side);border-inline-start:1px solid var(--bord);padding:18px 13px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;z-index:40}
.sbrand{display:flex;align-items:center;gap:9px;padding:2px 6px 6px;font-size:17px;font-weight:800}
.sbrand small{display:block;font-size:11px;color:var(--sub);font-weight:600}
.logo{width:34px;height:34px;border-radius:11px;background:var(--acc);color:#fff;display:grid;place-items:center;font-size:16px;flex:0 0 auto;box-shadow:0 6px 14px -6px var(--acc)}
.nav{display:flex;flex-direction:column;gap:2px;margin-top:14px}
.navi{display:flex;align-items:center;gap:11px;padding:10px 11px;border-radius:11px;font-size:13px;color:var(--sub);cursor:pointer;transition:.15s}
.navi .ic{width:18px;height:18px}
.navi .ct{margin-inline-start:auto;font-size:11px;font-weight:700;color:var(--sub);background:var(--glass);border:1px solid var(--bord);padding:0 7px;border-radius:20px;min-width:22px;text-align:center}
.navi:hover{background:var(--glass)}
.navi.on{color:var(--acc);background:var(--accw);font-weight:700}
.navi.on .ct{color:var(--acc);background:transparent;border-color:color-mix(in srgb,var(--acc) 30%,transparent)}
.live{margin-top:14px;padding:12px;border-radius:13px;background:var(--glass);border:1px solid var(--bord)}
.live .lr{display:flex;justify-content:space-between;align-items:center;font-size:11.5px;color:var(--sub)}
.live .lr b{color:var(--tx);font-size:13.5px}.live .lr b.ok{color:var(--ok)}
.livebar{height:6px;border-radius:6px;background:var(--bord);margin:7px 0 10px;overflow:hidden}
.livebar span{display:block;height:100%;border-radius:6px;background:linear-gradient(90deg,var(--acc),var(--ok));transition:width .4s}
.livefresh{margin-top:9px;font-size:10.5px;color:var(--sub);display:flex;align-items:center;gap:6px}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--ok);flex:0 0 auto;animation:pulse 2.2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--ok) 55%,transparent)}70%{box-shadow:0 0 0 6px transparent}}
.sfoot{margin-top:auto;display:flex;gap:8px;padding-top:14px}
.sfoot button{flex:1;display:inline-flex;align-items:center;justify-content:center;gap:6px;font-size:12px;padding:9px 0;border-radius:11px;border:1px solid var(--bord);background:transparent;color:var(--sub);cursor:pointer;font-family:inherit}
.sfoot button:hover{background:var(--glass)}.sfoot .ic{width:15px;height:15px}
.main{flex:1;min-width:0;max-width:1120px;padding:22px 26px 64px}
.mtop{display:none;align-items:center;justify-content:space-between;gap:11px;padding:10px 14px;position:sticky;top:0;z-index:30;background:var(--side);border:1px solid var(--bord);border-radius:14px;box-shadow:var(--dsh)}
.mtop .sbrand{font-size:14px;padding:0;letter-spacing:.3px}
.hb{width:38px;height:38px;border-radius:11px;border:1px solid var(--bord);background:transparent;color:var(--tx);display:grid;place-items:center;cursor:pointer;flex:0 0 auto}.hb .ic{width:20px;height:20px}
.backdrop{display:none;position:fixed;inset:0;background:rgba(15,22,35,.42);z-index:35}
.chip{width:32px;height:32px;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;color:var(--hue,var(--acc));background:color-mix(in srgb,var(--hue,var(--acc)) 13%,transparent);border:1px solid color-mix(in srgb,var(--hue,var(--acc)) 26%,transparent)}
.chip svg,.ic svg{width:100%;height:100%;display:block}.chip .ic{width:16px;height:16px}
.ic{display:inline-flex;width:1.15em;height:1.15em;vertical-align:-3px;flex:0 0 auto;stroke:currentColor}
@media(max-width:840px){
 .side{position:fixed;right:0;left:auto;top:0;width:250px;flex-basis:250px;transform:translateX(100%);transition:transform .25s;box-shadow:-20px 0 50px -24px rgba(20,30,60,.4)}
 body.navopen .side{transform:translateX(0)}
 body.navopen .backdrop{display:block}
 .mtop{display:flex}
 .main{padding:16px 15px 60px;max-width:none}
}
h1{font-size:18px;font-weight:800;display:flex;align-items:center;gap:8px;margin:4px 2px 3px}
.sub{color:var(--sub);font-size:12.5px;margin:0 2px 16px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.card{position:relative;overflow:hidden;border-radius:15px;padding:14px;margin-bottom:11px;background:var(--card);border:1px solid var(--bord);box-shadow:var(--dsh)}
.grid .card{margin-bottom:0}
.hero{border-radius:24px;padding:18px 16px 15px;background:linear-gradient(140deg,color-mix(in srgb,var(--acc) 22%,var(--card)),color-mix(in srgb,var(--acc2) 11%,var(--card)) 55%,color-mix(in srgb,var(--card) 94%,transparent));border:1px solid color-mix(in srgb,var(--acc) 32%,transparent);box-shadow:0 18px 44px -18px color-mix(in srgb,var(--acc) 50%,transparent),inset 0 1px 0 var(--hi);margin-bottom:14px}
.k{color:var(--sub);font-size:11.5px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.hero .v{font-size:30px;font-weight:800;text-shadow:0 0 26px color-mix(in srgb,var(--acc) 50%,transparent)}
.hsub{margin-top:8px;font-size:11.5px;color:var(--sub);display:inline-flex;gap:5px;align-items:center;background:color-mix(in srgb,var(--tx) 7%,transparent);border:1px solid var(--bord);border-radius:12px;padding:4px 10px}
.v{font-size:22px;font-weight:800}.stat .v{font-size:22px}
.sec{font-size:12.5px;font-weight:700;color:var(--sub);margin:20px 4px 9px;display:flex;align-items:center;gap:7px}
.sec::after{content:'';flex:1;height:1px;background:linear-gradient(to left,var(--bord),transparent)}
.chart{width:100%;height:auto;display:block}
.legend{display:flex;gap:6px;font-size:11px;color:var(--sub);margin-top:8px;align-items:center}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;vertical-align:1px}
.seg{display:flex;align-items:center;gap:14px}.donut{flex:0 0 116px}
.segs{flex:1;display:flex;flex-direction:column;gap:4px;font-size:13px}
.segs div{display:flex;justify-content:space-between;align-items:center}.segs b{font-weight:800}
.nrow{display:flex;align-items:center;gap:11px}
.ndot{width:10px;height:10px;border-radius:50%;background:var(--sub);flex:0 0 auto;box-shadow:0 0 8px var(--sub)}
.ndot.on{background:var(--ok);box-shadow:0 0 9px color-mix(in srgb,var(--ok) 80%,transparent)}
.ndot.off{background:var(--bad);box-shadow:0 0 9px color-mix(in srgb,var(--bad) 70%,transparent)}
.name{font-weight:700;font-size:15px}.grow{flex:1}.muted{color:var(--sub)}.mono{font-family:ui-monospace,Consolas,monospace;direction:ltr;overflow-wrap:anywhere}
.kv{color:var(--sub);font-size:12px;margin-top:12px;display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:6px 14px;overflow-wrap:anywhere}
.kv>span{min-width:0}
.kv.stack{grid-template-columns:1fr;gap:7px 0}
.kv b{color:var(--tx);font-weight:600}
.badge{font-size:11px;border-radius:10px;padding:3px 9px;font-weight:700}
.badge.ok{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.badge.bad{background:color-mix(in srgb,var(--bad) 13%,transparent);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 32%,transparent)}
.badge.na{background:var(--glass);color:var(--sub);border:1px solid var(--bord)}
.badge.warn{background:color-mix(in srgb,var(--gold) 15%,transparent);color:var(--gold);border:1px solid color-mix(in srgb,var(--gold) 34%,transparent)}
.tag{font-size:10.5px;text-transform:uppercase;letter-spacing:.4px;border:1px solid color-mix(in srgb,var(--acc) 40%,transparent);color:var(--acc);border-radius:8px;padding:2px 8px;font-weight:700}
.tag.sit{color:var(--gold);border-color:color-mix(in srgb,var(--gold) 40%,transparent)}
.tag.gre{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.nact{display:flex;gap:8px;margin-top:13px;flex-wrap:wrap}
button.act{display:inline-flex;align-items:center;gap:5px;background:var(--glass);border:1px solid var(--bord);color:var(--tx);border-radius:11px;padding:8px 12px;cursor:pointer;font-size:12.5px;font-family:inherit}
button.act:active{transform:scale(.97)}button.act .ic{width:14px;height:14px}
button.act.danger{color:var(--bad)}button.act.danger:hover{border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
label{display:block;font-size:12px;color:var(--sub);margin:13px 2px 6px}
input,select{width:100%;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-size:13.5px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:color-mix(in srgb,var(--acc) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}
.edit{margin-top:13px;padding:13px;border-radius:13px;background:var(--field);border:1px solid var(--bord)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
.primary{margin-top:18px;background:var(--acc);color:#fff;border:0;font-weight:800;padding:12px 18px;border-radius:12px;cursor:pointer;font-family:inherit;box-shadow:0 9px 20px -11px color-mix(in srgb,var(--acc) 70%,transparent)}
.primary:active{transform:scale(.98)}
.ghost{margin-top:18px;margin-inline-start:8px;background:var(--glass);border:1px solid var(--bord);color:var(--sub);padding:12px 16px;border-radius:14px;cursor:pointer;font-family:inherit}
.msg{margin-top:13px;font-size:12.5px;min-height:18px}.msg.ok{color:var(--ok)}.msg.err{color:var(--bad)}
.chh{font-weight:700;margin-bottom:3px}.chl{padding:1.5px 0;line-height:1.6}
.link{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.arrow{color:var(--acc);font-weight:800;font-size:16px}
.msbtn{width:100%;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-size:13.5px;cursor:pointer;text-align:start;display:flex;align-items:center;justify-content:space-between;font-family:inherit}
.msbtn.ph{color:var(--sub)}.msbtn .cv{color:var(--sub);transition:.2s;font-size:12px}.msbtn.open .cv{transform:rotate(180deg);color:var(--acc)}
.mslist{margin-top:7px;border:1px solid var(--bord);border-radius:12px;overflow:hidden;background:var(--card)}
.msrow{display:flex;align-items:center;gap:10px;padding:11px 12px;cursor:pointer;border-bottom:1px solid var(--bord)}
.msrow:last-child{border-bottom:0}.msrow:hover{background:var(--glass)}
.msrow.sel{background:color-mix(in srgb,var(--acc) 12%,transparent)}
.mscheck{width:19px;height:19px;border-radius:6px;border:1.6px solid var(--sub);flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;font-size:12px;font-weight:800}
.msrow.sel .mscheck{background:var(--acc);border-color:var(--acc);color:#fff}
.tgl{display:flex;align-items:center;gap:9px;margin-top:6px}
.tglsw{width:44px;height:25px;border-radius:14px;background:var(--glass);border:1px solid var(--bord);position:relative;cursor:pointer;transition:.2s;flex:0 0 auto}
.tglsw::after{content:'';position:absolute;top:2px;inset-inline-start:2px;width:19px;height:19px;border-radius:50%;background:var(--sub);transition:.2s}
.tglsw.on{background:color-mix(in srgb,var(--acc) 32%,transparent);border-color:color-mix(in srgb,var(--acc) 55%,transparent)}
.tglsw.on::after{inset-inline-start:21px;background:var(--acc)}
.modalov{position:fixed;inset:0;z-index:58;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,.5);backdrop-filter:blur(3px);animation:fade .18s ease both}
.modal{width:344px;max-width:100%;border-radius:20px;padding:20px;background:linear-gradient(180deg,color-mix(in srgb,#fff 5%,color-mix(in srgb,var(--card) 92%,transparent)),color-mix(in srgb,var(--card) 88%,transparent));border:1px solid color-mix(in srgb,var(--tx) 12%,transparent);box-shadow:0 24px 60px -20px rgba(0,0,0,.7),inset 0 1px 0 var(--hi)}
.mtext{font-size:14px;line-height:1.85}.mbtns{display:flex;gap:9px;margin-top:17px}
.mbtns .primary,.mbtns .ghost{margin:0}
.mbtns .primary{background:linear-gradient(180deg,color-mix(in srgb,var(--bad) 92%,#fff),var(--bad));color:#fff;box-shadow:0 10px 22px -12px color-mix(in srgb,var(--bad) 55%,transparent)}
@keyframes fade{from{opacity:0}to{opacity:1}}
.toast{position:fixed;left:50%;bottom:26px;transform:translate(-50%,20px);z-index:60;max-width:88%;padding:12px 18px;border-radius:14px;font-size:13px;background:var(--card);border:1px solid var(--bord);box-shadow:var(--dsh);opacity:0;transition:.3s;pointer-events:none}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:color-mix(in srgb,var(--bad) 45%,transparent);color:var(--bad)}
.toast.ok{border-color:color-mix(in srgb,var(--ok) 45%,transparent);color:var(--ok)}
.toolbar{display:flex;gap:9px;align-items:center;margin:2px 0 12px;flex-wrap:wrap}
.search{flex:1;min-width:150px;padding:10px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-size:13px;font-family:inherit}
.search:focus{outline:none;border-color:color-mix(in srgb,var(--acc) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}
.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:12px 0 2px;flex-wrap:wrap}
.pbtn{background:var(--glass);border:1px solid var(--bord);color:var(--tx);border-radius:11px;padding:8px 14px;cursor:pointer;font-family:inherit;font-size:12.5px}
.pbtn:disabled{opacity:.4;cursor:default}.pbtn:not(:disabled):active{transform:scale(.97)}
.pinfo{color:var(--sub);font-size:12px;min-width:120px;text-align:center}
.mssearch{width:100%;padding:9px 12px;border:0;border-bottom:1px solid var(--bord);background:transparent;color:var(--tx);font-size:13px;font-family:inherit;outline:none}
@media(prefers-reduced-motion:no-preference){#view>*{animation:rise .45s cubic-bezier(.22,.61,.36,1) both}}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
/* desktop: node/tunnel/portfw cards in two columns */
@media(min-width:900px){
 #nodeList,#linkList,#pfList{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:start}
 #nodeList{align-items:stretch}   /* node cards in a row match height so an offline node can't leave a ragged gap */
 #nodeList>.card,#linkList>.card,#pfList>.card{margin-bottom:0}
 #nodeList>.card.muted,#linkList>.card.muted,#pfList>.card.muted{grid-column:1/-1}
}
.pagehd{display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap;margin:2px 2px 14px}
.pagehd h1{margin:0}.pagehd .sub{margin:4px 0 0}
.pagehd .actbtn{margin-inline-start:auto;display:inline-flex;align-items:center;gap:6px;background:var(--acc);color:#fff;border:0;font-weight:700;font-size:12.5px;padding:9px 15px;border-radius:11px;cursor:pointer;font-family:inherit}
.pagehd .actbtn .ic{width:15px;height:15px}
.skrow{display:flex;align-items:center;gap:11px}
.sk{background:linear-gradient(90deg,var(--glass) 25%,var(--field) 50%,var(--glass) 75%);background-size:200% 100%;border-radius:7px;animation:shim 1.3s infinite}
@keyframes shim{from{background-position:200% 0}to{background-position:-200% 0}}
.emptybox{text-align:center;padding:30px 16px}
.emptybox .ei{width:52px;height:52px;border-radius:15px;margin:0 auto 13px;display:grid;place-items:center;background:var(--accw);color:var(--acc)}
.emptybox .ei .ic{width:26px;height:26px}
.emptybox h3{margin:0 0 5px;font-size:15px}.emptybox p{margin:0 0 15px;font-size:12.5px;color:var(--sub)}
.selbtn{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;padding:9px 13px;border-radius:12px;border:1px solid var(--bord);background:var(--card);color:var(--tx);cursor:pointer;font-family:inherit}
.selbtn.on{background:var(--accw);color:var(--acc);border-color:color-mix(in srgb,var(--acc) 32%,transparent);font-weight:700}.selbtn .ic{width:15px;height:15px}
.cardck{position:absolute;top:12px;inset-inline-start:12px;z-index:3;width:22px;height:22px;border-radius:7px;border:1.7px solid var(--sub);background:var(--card);cursor:pointer;display:none;align-items:center;justify-content:center;color:#fff;font-size:13px;font-weight:800}
.selmode .cardck{display:inline-flex}
.cardck.on{background:var(--acc);border-color:var(--acc)}
.selmode>.card{padding-inline-start:44px}
.card.selon{outline:2px solid var(--acc);outline-offset:-1px}
.selbar{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:56;display:flex;align-items:center;gap:9px;background:var(--acc);color:#fff;padding:9px 12px 9px 16px;border-radius:14px;box-shadow:0 16px 36px -14px rgba(40,60,120,.55);font-size:12.5px;font-weight:700;max-width:92vw;flex-wrap:wrap}
.selbar button{background:rgba(255,255,255,.18);border:0;color:#fff;font-size:12px;padding:7px 12px;border-radius:10px;cursor:pointer;font-family:inherit;display:inline-flex;align-items:center;gap:5px}
.selbar button:hover{background:rgba(255,255,255,.3)}.selbar .ic{width:14px;height:14px}
@media(prefers-reduced-motion:reduce){.sk,.pulse{animation:none}}
/* ===== popup modal shell (edit forms + node details) — gated behind .wide so confirmBox's .modal is untouched ===== */
.modal.wide{width:414px;max-width:100%;display:flex;flex-direction:column;max-height:min(88vh,760px);padding:0;overflow:hidden;background:var(--card);animation:modrise .2s cubic-bezier(.2,.7,.3,1)}
@keyframes modrise{from{opacity:0;transform:translateY(10px) scale(.985)}to{opacity:1;transform:none}}
.msticky{flex:0 0 auto;padding:15px 18px 12px;border-bottom:1px solid var(--bord);background:var(--card);display:flex;align-items:center;gap:10px}
.msticky .ttl{min-width:0}
.msticky h3{margin:0;font-size:15px;font-weight:800;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.msticky .sb{margin:2px 0 0;font-size:11px;color:var(--sub);display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.msticky .mx{margin-inline-start:auto;border:1px solid var(--bord);background:var(--field);color:var(--sub);width:30px;height:30px;border-radius:9px;cursor:pointer;display:grid;place-items:center;font-size:16px;line-height:1;flex:0 0 auto;font-family:inherit}
.msticky .mx:hover{background:var(--badw);color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,transparent)}
.msticky .medi{width:30px;height:30px;border-radius:9px;background:var(--accw);color:var(--acc);display:grid;place-items:center;flex:0 0 auto}
.msticky .medi .ic{width:16px;height:16px}
.mbody{flex:1 1 auto;min-height:0;overflow-y:auto;overflow-x:hidden;padding:14px 18px 16px;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:var(--bord) transparent}
.mbody::-webkit-scrollbar{width:8px}
.mbody::-webkit-scrollbar-track{background:transparent;margin:6px 0}
.mbody::-webkit-scrollbar-thumb{background:var(--bord);border-radius:99px;border:2px solid transparent;background-clip:padding-box}
.mbody::-webkit-scrollbar-thumb:hover{background:var(--sub)}
.mbody label.first{margin-top:2px}
.mfoot{flex:0 0 auto;padding:12px 18px 15px;border-top:1px solid var(--bord);background:var(--card);display:flex;gap:10px}
.mfoot .primary,.mfoot .ghost{flex:1;margin:0}
.lpill{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;font-weight:700;color:var(--ok);background:var(--okw);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent);border-radius:20px;padding:2px 8px}
.lpill .pd{width:6px;height:6px;border-radius:50%;background:var(--ok);animation:lpulse 1.4s infinite}
@keyframes lpulse{0%,100%{opacity:1}50%{opacity:.25}}
/* node-details content */
.nd-head{display:flex;align-items:center;gap:8px;padding-bottom:12px;border-bottom:1px solid var(--bord);margin-bottom:14px}
.nd-head .dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto}
.nd-head .dot.ok{background:var(--ok);box-shadow:0 0 0 3px var(--okw)}
.nd-head .dot.bad{background:var(--bad);box-shadow:0 0 0 3px var(--badw)}
.nd-id{display:flex;flex-direction:column;gap:1px;min-width:0}
.nd-name{font-size:14px;font-weight:700;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nd-hp{font-size:11.5px;color:var(--sub);font-variant-numeric:tabular-nums;direction:ltr;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nd-head .nd-ping{margin-inline-start:auto;flex:0 0 auto}
.gauges{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:16px}
.gauge{background:var(--field);border:1px solid var(--bord);border-radius:14px;padding:12px 4px 10px;text-align:center}
.gwrap{position:relative;width:84px;height:84px;margin:0 auto}
.gtrack{stroke:color-mix(in srgb,var(--tx) 9%,transparent)}
.gfill{transition:stroke-dashoffset .8s cubic-bezier(.3,.8,.3,1),stroke .4s}
.gfill.ok{stroke:var(--ok)}.gfill.warn{stroke:var(--gold)}.gfill.crit{stroke:var(--bad)}
.gc{position:absolute;inset:0;display:flex;align-items:center;justify-content:center}
.gc b{font-size:20px;font-weight:800;font-variant-numeric:tabular-nums;color:var(--tx)}
.gc b i{font-size:11px;font-weight:700;font-style:normal;color:var(--sub)}
.gl{margin-top:8px;font-size:12px;font-weight:700;color:var(--tx)}
.gsub{font-size:10.5px;color:var(--sub);margin-top:2px;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
.nd-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.nd-tile{display:flex;flex-direction:column;gap:2px;background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:9px 10px;min-width:0}
.nd-tile.nd-wide{grid-column:1/-1}
.nd-tile .medi{color:var(--acc)}.nd-tile .medi .ic{width:15px;height:15px}
.nd-tile>span{font-size:11px;color:var(--sub)}
.nd-tile b{font-size:12.5px;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-variant-numeric:tabular-nums}
.nd-tile b.ltr{direction:ltr;text-align:right}
.nd-off{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center;padding:26px 10px;background:var(--badw);border:1px solid var(--bord);border-radius:12px}
.nd-off .ic{width:30px;height:30px;color:var(--bad)}.nd-off b{font-size:14px;color:var(--tx)}.nd-off span{font-size:12px;color:var(--sub)}
/* traffic section (node-details) */
.nd-sec{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:800;color:var(--sub);margin:2px 2px 10px}
.nd-sec .ic{width:15px;height:15px;color:var(--acc)}
.nd-divider{height:1px;background:var(--bord);margin:15px 0 13px}
.din{color:var(--ok)}.dout{color:var(--acc)}
.tf-chart{background:var(--field);border:1px solid var(--bord);border-radius:13px;padding:10px 12px 6px;margin-bottom:11px}
.tf-top{display:flex;gap:14px;font-size:12px;margin-bottom:4px;font-variant-numeric:tabular-nums}.tf-top b{font-size:14px;font-weight:800}
.tf-spk{width:100%;height:46px;display:block}
.ttiles{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}
.ttile{background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:9px 11px}
.ttile>span{font-size:11px}.ttile b{display:block;font-size:14px;margin-top:2px;font-variant-numeric:tabular-nums;direction:ltr;text-align:right}
#view .gauges{margin-bottom:0}#view .ttiles{margin-bottom:0}   /* overview reuses node-detail gauges/tiles in a standalone card — drop the modal's trailing gap */
.tf-tuns .tf-row{display:flex;align-items:center;gap:8px;padding:8px 2px;border-top:1px solid var(--bord);font-size:12px}
.tf-tuns .tf-row:first-child{border-top:0}
.tf-nm{display:flex;align-items:center;gap:6px;min-width:0;font-weight:700}.tf-nm .mono{font-size:11.5px}
.tf-fig{margin-inline-start:auto;display:flex;align-items:center;gap:10px;white-space:nowrap;font-variant-numeric:tabular-nums}.tf-fig .tot{color:var(--sub)}
/* traffic line on the tunnel card */
.ltraf{margin-top:10px;padding-top:9px;border-top:1px dashed var(--bord);display:flex;align-items:center;gap:13px;font-size:12px;font-variant-numeric:tabular-nums}.ltraf .tot{color:var(--sub);margin-inline-start:auto}
.bigrow{display:flex;gap:18px;align-items:baseline;margin-bottom:4px}.bigrow .b{font-size:22px;font-weight:800;font-variant-numeric:tabular-nums}
.subline{font-size:12px;color:var(--sub);font-variant-numeric:tabular-nums}
/* slimmed node card: plain meta labels (NOT boxed — distinct from the .chip icon badge) */
.nchips{display:flex;flex-wrap:wrap;gap:8px 15px;margin-top:9px}
.nchip{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:var(--sub)}
.nchip b{color:var(--tx);font-weight:700}.nchip .ic{width:13px;height:13px;color:var(--sub)}
/* uptime bar on the node card */
.upwrap{margin-top:11px}
.uptop{display:flex;align-items:center;font-size:11.5px;color:var(--sub);margin-bottom:6px}.uptop b{color:var(--tx)}.uptop .r{margin-inline-start:auto}
.upbar{display:flex;gap:2px;height:22px}
.upbar i{flex:1;border-radius:2px;background:var(--ok);min-width:1px}.upbar i.d{background:var(--bad)}
/* agent update page */
.agrow{display:flex;align-items:center;gap:10px;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--card);margin-bottom:8px;flex-wrap:wrap;box-shadow:var(--dsh)}
.agrow .name{font-weight:700;font-size:14px}.agrow .ver{font-size:11.5px;color:var(--sub)}
.agrow .agres{flex-basis:100%;margin:2px 0 0;min-height:0;font-size:11.5px}
.drop{border:1.5px dashed color-mix(in srgb,var(--acc) 45%,transparent);border-radius:13px;padding:18px;text-align:center;background:var(--accw);color:var(--sub);font-size:12.5px;cursor:pointer;margin-top:4px}.drop b{color:var(--acc)}
.banner{display:flex;align-items:center;gap:12px}.banner .v{font-size:13.5px;font-weight:800}
/* icon-only card action buttons */
.nact.iconly .act{padding:8px 11px}
.nact.iconly .act .ic{width:15px;height:15px}
/* prominent check-all button */
.chkall{display:inline-flex;align-items:center;gap:6px;background:#2f9e6f;color:#fff;border:0;font-weight:800;font-size:13px;padding:12px 18px;border-radius:12px;cursor:pointer;font-family:inherit;box-shadow:0 9px 20px -11px color-mix(in srgb,var(--ok) 70%,transparent)}
body.dark .chkall{background:#1f7a56}   /* darker green so white text keeps AA contrast in dark mode */
.chkall .ic{width:15px;height:15px}
.chkall:active{transform:scale(.97)}
/* tunnels toolbar: make «افزودن تونل» and «بررسی اتصال همگانی» pixel-identical (equal width + height + font) */
.tbtnrow{display:flex;gap:9px;margin:18px 0 12px}
.tbtnrow>button{flex:1 1 0;min-width:0;display:inline-flex;align-items:center;justify-content:center;gap:6px;margin:0;font-size:13px;line-height:1.2;padding:12px 14px;border-radius:12px}
.tbtnrow>button .ic{width:15px;height:15px}
/* command palette (Ctrl+K) */
.modalov.palov{align-items:flex-start;padding-top:64px}
.pal{width:460px;max-width:94%;background:var(--card);border:1px solid var(--bord);border-radius:16px;box-shadow:0 30px 70px -24px rgba(0,0,0,.55);overflow:hidden;max-height:70vh;display:flex;flex-direction:column;animation:modrise .18s ease}
.palin{display:flex;align-items:center;gap:9px;padding:13px 15px;border-bottom:1px solid var(--bord);flex:0 0 auto}
.palin .ic{width:17px;height:17px;color:var(--sub)}.palin input{flex:1;border:0;background:transparent;color:var(--tx);font-size:15px;font-family:inherit;outline:none}
.palin kbd,.palfoot kbd{font-size:10px;color:var(--sub);border:1px solid var(--bord);border-radius:5px;padding:1px 6px;background:var(--field)}
.pallist{overflow-y:auto;padding-bottom:6px}
.palsec{font-size:10.5px;font-weight:700;color:var(--sub);padding:9px 15px 4px}
.palrow{display:flex;align-items:center;gap:10px;padding:9px 15px;cursor:pointer;font-size:13px}
.palrow.sel{background:var(--accw)}
.palrow .gi{width:26px;height:26px;border-radius:8px;background:var(--field);display:grid;place-items:center;color:var(--acc);flex:0 0 auto}.palrow .gi .ic{width:14px;height:14px}
.palrow .sub{color:var(--sub);font-size:11.5px;margin-inline-start:auto;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.palfoot{display:flex;gap:14px;padding:9px 15px;border-top:1px solid var(--bord);font-size:10.5px;color:var(--sub);flex:0 0 auto}
/* equal-height node cards + compact offline state */
#nodeList>.card.node{display:flex;flex-direction:column}
#nodeList>.card.node .nact{margin-top:auto;padding-top:16px}
#nodeList>.card.node>.msg,#linkList>.card>.msg{margin-top:0;min-height:0}   /* collapse the trailing status line when empty so cards aren't padded out below the buttons */
#nodeList>.card.node>.msg:not(:empty),#linkList>.card>.msg:not(:empty){margin-top:10px}  /* breathe only when a result actually shows */
/* tunnel card: two node tiles (name + status pill + address) with ↔ between them, then a 2-col meta grid */
.tninfo{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:center;margin-top:2px}
.tnnode{background:var(--field);border:1px solid var(--bord);border-radius:12px;padding:10px 12px;min-width:0}
.tnhead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:5px}
.tnnode .tnn{font-size:13px;font-weight:800;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.tnnode .tna{font-size:13px;font-weight:700;color:var(--sub);overflow-wrap:anywhere}
.tnst{font-size:9px;font-weight:800;flex:0 0 auto;padding:2px 7px;border-radius:7px;line-height:1.35;border:1px solid color-mix(in srgb,currentColor 42%,transparent);background:color-mix(in srgb,currentColor 12%,transparent)}
.tnarrow{color:var(--acc);font-weight:800;font-size:19px;text-align:center}
.tnmeta{display:grid;grid-template-columns:1fr 1fr;gap:7px 15px;margin-top:12px;font-size:11.5px;color:var(--sub)}.tnmeta b{color:var(--tx);font-weight:700}.tnmeta>span{display:flex;align-items:center;gap:5px;min-width:0}
/* portfw card: two columns — ports on one side, destinations/rotation on the other */
.pfcols{display:grid;grid-template-columns:1fr 1fr;gap:6px 16px;margin-top:12px}
.pfcol{display:flex;flex-direction:column;gap:7px}
.pfrow{font-size:12px;color:var(--sub)}.pfrow b{color:var(--tx);font-weight:700}
.card.node .noff{flex:1 1 auto;display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:wrap;text-align:center;padding:9px 10px;margin:9px 0 1px;background:var(--badw);border:1px dashed var(--bord);border-radius:10px}
.card.node .noff .ic{width:15px;height:15px;color:var(--bad)}
.card.node .noff b{font-size:12px;color:var(--bad)}.card.node .noff span{font-size:11px;color:var(--sub)}
/* semantic action-button colors */
button.act.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 42%,transparent)}
button.act.info{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 38%,transparent)}
button.act.warn{color:#fb923c;border-color:color-mix(in srgb,#fb923c 46%,transparent)}
button.act.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,transparent)}
@media(prefers-reduced-motion:reduce){.modal.wide{animation:none}.gfill{transition:none}.lpill .pd{animation:none}}
/* IP tag rows (node details) + rebuild IP picker — additive, new classes only */
.ndips{margin-top:2px}
.iptag{display:flex;align-items:center;gap:8px;padding:8px 2px;border-bottom:1px solid var(--bord)}
.iptag .tgs{margin-inline-start:auto;display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
.rbrow{display:flex;align-items:center;gap:9px;padding:10px 11px;border:1.5px solid var(--bord);border-radius:11px;background:var(--field);margin-bottom:7px;cursor:pointer;transition:.15s}
.rbrow:hover{border-color:color-mix(in srgb,var(--acc) 50%,var(--bord))}
.rbrow.sel{border-color:var(--acc);background:var(--accw)}
.rbrow .rbdot{width:15px;height:15px;border-radius:50%;border:2px solid var(--sub);flex:0 0 auto;position:relative}
.rbrow.sel .rbdot{border-color:var(--acc)}
.rbrow.sel .rbdot::after{content:"";position:absolute;inset:3px;border-radius:50%;background:var(--acc)}
.rbrow .rbtags{margin-inline-start:auto;display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
/* IP peer chips (node details + picker): tap a node chip to reveal the tunnel type */
.ippeer{display:inline-flex;align-items:center;gap:5px}
.ipchip{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:3px 8px;border-radius:8px;background:var(--accw);color:var(--acc);cursor:pointer;user-select:none}
.ippeer .iptyp{display:none;font-size:10px;font-weight:800;padding:3px 7px;border-radius:6px}
.ippeer.show .iptyp{display:inline-flex}
.iptyp.vxlan{color:var(--acc);background:var(--accw)}
.iptyp.gre{color:var(--ok);background:color-mix(in srgb,var(--ok) 15%,transparent)}
.iptyp.sit{color:#a855f7;background:rgba(168,85,247,.15)}
.ipfree{font-size:10.5px;font-weight:700;color:var(--sub);border:1px dashed var(--bord);padding:2px 8px;border-radius:8px}
/* settings: mode field + minimal mode popup */
.setfield{width:100%;display:flex;align-items:center;padding:11px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-family:inherit;font-weight:800;font-size:14px;cursor:pointer}
.setfield .val{color:var(--gold)}
.setfield .cv{margin-inline-start:auto;color:var(--sub)}
.modal.modesheet{max-width:320px;padding:6px}
.modelist{padding:2px}
.mopt{display:flex;align-items:center;gap:12px;padding:14px 13px;border-radius:11px;cursor:pointer}
.mopt.on{background:var(--accw)}
.mopt .mrad{width:19px;height:19px;border-radius:50%;border:2px solid var(--sub);flex:0 0 auto;position:relative}
.mopt.on .mrad{border-color:var(--acc)}
.mopt.on .mrad::after{content:"";position:absolute;inset:3px;border-radius:50%;background:var(--acc)}
.mopt .mt{font-weight:800;font-size:15.5px}
.mopt .mdf{margin-inline-start:auto;font-size:10px;font-weight:800;color:var(--gold);background:var(--goldw,color-mix(in srgb,var(--gold) 16%,transparent));padding:3px 9px;border-radius:20px}
/* dropdown-as-popup list (scrollable + search) */
.modal.sssheet{max-width:360px;padding:8px}
.sspop{display:flex;flex-direction:column;min-height:0}
.sspop .sspopq{margin-bottom:8px;flex:0 0 auto}
.sspoplist{overflow:auto;max-height:min(58vh,420px);min-height:0}
.toast .ic{width:15px;height:15px;display:inline-block;vertical-align:-3px;margin-inline-end:4px}
</style></head><body>
<div class="backdrop" onclick="drawer(false)"></div>
<div class="shell">
 <aside class="side" id="side">
  <div class="sbrand"><span class="logo"><span class="ic" data-ic="shield"></span></span><span>tnl<small>کنترل فلیت</small></span></div>
  <nav class="nav" id="nav">
   <a class="navi" data-t="overview"><span class="ic" data-ic="dash"></span> نمای کلی</a>
   <a class="navi" data-t="nodes"><span class="ic" data-ic="server"></span> نودها<span class="ct" id="ct_nodes"></span></a>
   <a class="navi" data-t="tunnels"><span class="ic" data-ic="link"></span> تونل‌ها<span class="ct" id="ct_tunnels"></span></a>
   <a class="navi" data-t="portfw"><span class="ic" data-ic="globe"></span> پورت‌فوروارد<span class="ct" id="ct_portfw"></span></a>
   <a class="navi" data-t="settings"><span class="ic" data-ic="cog"></span> تنظیمات</a>
  </nav>
  <div class="sfoot"><button id="thbtn" onclick="toggleTheme()"><span class="ic" data-ic="moon"></span> تم</button><button onclick="logout()"><span class="ic" data-ic="logout"></span> خروج</button></div>
 </aside>
 <main class="main">
  <div class="mtop"><button class="hb" onclick="drawer(true)"><span class="ic" data-ic="menu"></span></button><div class="sbrand"><span class="logo" style="width:28px;height:28px;font-size:14px"><span class="ic" data-ic="shield"></span></span><span>TUNNEL-MANAGER</span></div></div>
  <div id="view"></div>
 </main>
</div>
<script>
var H={'Content-Type':'application/json','X-Requested-With':'tnl-central'};
function j(u){return fetch('/api/'+u).then(function(r){return r.json()})}
function post(u,b){return fetch('/api/'+u,{method:'POST',headers:H,body:JSON.stringify(b||{})}).then(async function(r){return{ok:r.ok,d:await r.json().catch(function(){return{}})}})}
function logout(){post('logout').then(function(){location.href='/'})}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function el(id){return document.getElementById(id)}
function v(id){var e=el(id);return e?e.value.trim():''}
function setT(id,t){var e=el(id);if(e&&e.textContent!==String(t))e.textContent=t}
function setHTML(box,html){if(!box)return;if(box._html===html)return;box._html=html;box.innerHTML=html}  // compare against the LAST ASSIGNED string (innerHTML read-back is re-serialized and never matches) — skip identical re-renders: no flicker/lag on mobile
function num(x){x=+x;return isFinite(x)?x:0}
function fmtup(s){s=+s||0;var d=Math.floor(s/86400),h=Math.floor(s%86400/3600);return d+'روز '+h+'س'}
function fmtBytes(n){n=num(n);var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?(n<10?n.toFixed(2):n<100?n.toFixed(1):Math.round(n)):Math.round(n))+' '+u[i]}
function fmtRate(b){b=num(b);var u=['bps','Kbps','Mbps','Gbps'],i=0;while(b>=1000&&i<3){b/=1000;i++}return (i?(b<10?b.toFixed(1):Math.round(b)):Math.round(b))+' '+u[i]}
function tfRow(t){return '<div class="tf-row"><div class="tf-nm"><span class="mono">'+esc(t.name)+'</span><span class="tag '+esc(t.type)+'">'+esc(t.type)+'</span></div><div class="tf-fig"><span class="din">↓'+fmtRate(t.rx_bps)+'</span><span class="dout">↑'+fmtRate(t.tx_bps)+'</span><span class="tot">'+fmtBytes(num(t.rx_total)+num(t.tx_total))+'</span></div></div>'}
function dualSpark(id,a,b){var svg=el(id);if(!svg||!a.length)return;var vb=svg.getAttribute('viewBox').split(' '),W=+vb[2],H=+vb[3],pad=3;
 var mx=Math.max.apply(null,a.concat(b).concat([1]));
 function P(v){if(v.length<2)v=v.concat(v);return 'M'+v.map(function(x,k){return (pad+k*(W-2*pad)/(v.length-1)).toFixed(1)+','+(H-pad-(num(x)/mx)*(H-2*pad)).toFixed(1)}).join(' L')}
 var okc=cssv('--ok'),acc=cssv('--acc'),din=P(a),lx=(pad+(a.length-1)*(W-2*pad)/Math.max(1,a.length-1)).toFixed(1);
 svg.innerHTML='<defs><linearGradient id="tg'+id+'" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="'+okc+'" stop-opacity=".22"/><stop offset="1" stop-color="'+okc+'" stop-opacity="0"/></linearGradient></defs>'+
  '<path d="'+din+' L'+lx+','+(H-pad)+' L'+pad+','+(H-pad)+' Z" fill="url(#tg'+id+')"/>'+
  '<path d="'+din+'" fill="none" stroke="'+okc+'" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/>'+
  '<path d="'+P(b)+'" fill="none" stroke="'+acc+'" stroke-width="1.8" stroke-linejoin="round" stroke-linecap="round"/>'}
function cssv(n){return getComputedStyle(document.body).getPropertyValue(n).trim()||'#888'}
var _S='stroke="currentColor" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"';
var IC={
 shield:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>',
 dash:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 20h16M7 20v-7M12 20V8M17 20v-4"/></svg>',
 server:'<svg viewBox="0 0 24 24" '+_S+'><rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/></svg>',
 link:'<svg viewBox="0 0 24 24" '+_S+'><path d="M9 7H6a4 4 0 000 8h3M15 7h3a4 4 0 010 8h-3M8 11h8"/></svg>',
 bolt:'<svg viewBox="0 0 24 24" '+_S+'><path d="M13 3L4 14h7l-1 7 9-11h-7z"/></svg>',
 globe:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/></svg>',
 activity:'<svg viewBox="0 0 24 24" '+_S+'><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>',
 plus:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 5v14M5 12h14"/></svg>',
 pen:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M14 6l4 4"/></svg>',
 trash:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
 redo:'<svg viewBox="0 0 24 24" '+_S+'><path d="M21 12a9 9 0 11-2.64-6.36M21 4v4h-4"/></svg>',
 moon:'<svg viewBox="0 0 24 24" '+_S+'><path d="M20 14a8 8 0 01-10-10 8 8 0 1010 10z"/></svg>',
 sun:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/></svg>',
 logout:'<svg viewBox="0 0 24 24" '+_S+'><path d="M15 12H4M9 7l-5 5 5 5M14 4h4a2 2 0 012 2v12a2 2 0 01-2 2h-4"/></svg>',
 menu:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 6h16M4 12h16M4 18h16"/></svg>',
 check:'<svg viewBox="0 0 24 24" '+_S+'><path d="M20 6 9 17l-5-5"/></svg>',
 info:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/></svg>',
 plugoff:'<svg viewBox="0 0 24 24" '+_S+'><path d="M9 2v6M15 2v6M6 8h12v3a6 6 0 01-12 0zM12 17v5"/><path d="M3 3l18 18"/></svg>',
 cpu:'<svg viewBox="0 0 24 24" '+_S+'><rect x="7" y="7" width="10" height="10" rx="2"/><path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/></svg>',
 clock:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
 cores:'<svg viewBox="0 0 24 24" '+_S+'><rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/></svg>',
 pin:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 21s7-6 7-11a7 7 0 10-14 0c0 5 7 11 7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>',
 os:'<svg viewBox="0 0 24 24" '+_S+'><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
 traf:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 20V8M10 20V4M16 20v-7M22 20H2"/></svg>',
 cog:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
 warn:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 3l9 16H3z"/><path d="M12 10v4M12 17h.01"/></svg>',
 okc:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="9"/><path d="M8.4 12.4l2.4 2.4 4.7-5.4"/></svg>',
 xc:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>',
 grid:'<svg viewBox="0 0 24 24" '+_S+'><rect x="4" y="4" width="7" height="7" rx="1"/><rect x="13" y="4" width="7" height="7" rx="1"/><rect x="4" y="13" width="7" height="7" rx="1"/><rect x="13" y="13" width="7" height="7" rx="1"/></svg>',
 search:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>'
};
function ic(n,c){return '<span class="ic"'+(c?' style="color:'+c+'"':'')+'>'+(IC[n]||'')+'</span>'}
function paintIcons(root){(root||document).querySelectorAll('[data-ic]').forEach(function(e){e.innerHTML=IC[e.dataset.ic]||''})}
function toggleTheme(){var d=document.body.classList.toggle('dark');try{localStorage.setItem('tnl_dark',d?'1':'')}catch(e){}el('thbtn').innerHTML=ic(d?'sun':'moon')+' تم';refresh()}
try{if(localStorage.getItem('tnl_dark'))document.body.classList.add('dark')}catch(e){}
paintIcons();el('thbtn').innerHTML=ic(document.body.classList.contains('dark')?'sun':'moon')+' تم';

function area(id,vals,color){var svg=el(id);if(!svg)return;var W=520,Hh=150,pad=12,bh=6;
 vals=vals.slice();if(vals.length<2)vals=vals.concat(vals.length?[vals[0]]:[0,0]);
 var max=Math.max.apply(null,vals.concat([1])),ch=Hh-pad-bh;
 var pts=vals.map(function(x,i){return[pad+i*(W-2*pad)/(vals.length-1),pad+ch-(x/max)*ch]});
 var cl=function(y){return Math.max(pad,Math.min(pad+ch,y))};
 var line='M'+pts[0][0].toFixed(1)+','+pts[0][1].toFixed(1);
 for(var i=0;i<pts.length-1;i++){var p0=pts[i-1]||pts[i],p1=pts[i],p2=pts[i+1],p3=pts[i+2]||p2;
  line+='C'+(p1[0]+(p2[0]-p0[0])/6).toFixed(1)+','+cl(p1[1]+(p2[1]-p0[1])/6).toFixed(1)+' '+(p2[0]-(p3[0]-p1[0])/6).toFixed(1)+','+cl(p2[1]-(p3[1]-p1[1])/6).toFixed(1)+' '+p2[0].toFixed(1)+','+p2[1].toFixed(1)}
 var ar=line+' L'+pts[pts.length-1][0].toFixed(1)+','+(pad+ch)+' L'+pts[0][0].toFixed(1)+','+(pad+ch)+' Z';
 svg.setAttribute('viewBox','0 0 '+W+' '+Hh);
 svg.innerHTML='<defs><linearGradient id="g'+id+'" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="'+color+'" stop-opacity=".5"/><stop offset=".6" stop-color="'+color+'" stop-opacity=".14"/><stop offset="1" stop-color="'+color+'" stop-opacity="0"/></linearGradient></defs><line x1="'+pad+'" y1="'+(pad+ch)+'" x2="'+(W-pad)+'" y2="'+(pad+ch)+'" stroke="'+cssv('--sub')+'" stroke-opacity=".22"/><path d="'+ar+'" fill="url(#g'+id+')"/><path d="'+line+'" fill="none" stroke="'+color+'" stroke-width="2.6" stroke-linecap="round"/>'}
function donut(id,parts){var svg=el(id);if(!svg)return;var CIR=2*Math.PI*46,total=parts.reduce(function(a,p){return a+p[1]},0)||1,off=0;
 var g='<circle cx="60" cy="60" r="46" fill="none" stroke="'+cssv('--sub')+'" stroke-opacity=".14" stroke-width="15"/>';
 parts.forEach(function(p){var len=p[1]/total*CIR;if(len>0.4){g+='<circle cx="60" cy="60" r="46" fill="none" stroke="'+p[2]+'" stroke-width="15" stroke-dasharray="'+Math.max(1,len-1).toFixed(1)+' '+CIR.toFixed(1)+'" stroke-dashoffset="'+(-off).toFixed(1)+'" transform="rotate(-90 60 60)" stroke-linecap="round"/>'}off+=len});
 g+='<text x="60" y="57" text-anchor="middle" font-size="21" font-weight="800" fill="'+cssv('--tx')+'" font-family="Vazirmatn,Tahoma">'+parts[0][1]+'</text><text x="60" y="76" text-anchor="middle" font-size="10" fill="'+cssv('--sub')+'" font-family="Vazirmatn,Tahoma">آنلاین</text>';
 svg.innerHTML=g}
function ring(pct,color){pct=Math.max(0,Math.min(100,pct||0));var C=(2*Math.PI*15).toFixed(1),o=(C*(1-pct/100)).toFixed(1);
 return '<svg viewBox="0 0 40 40" style="width:44px;height:44px;flex:0 0 auto"><circle cx="20" cy="20" r="15" fill="none" stroke="var(--bord)" stroke-width="4"/><circle cx="20" cy="20" r="15" fill="none" stroke="'+color+'" stroke-width="4" stroke-linecap="round" stroke-dasharray="'+C+'" stroke-dashoffset="'+o+'" transform="rotate(-90 20 20)" style="transition:stroke-dashoffset .5s"/><text x="20" y="24" text-anchor="middle" font-size="11" fill="var(--tx)" font-family="Vazirmatn,Tahoma">'+Math.round(pct)+'</text></svg>'}
function dotc(c){return '<i class="dot" style="background:'+c+'"></i>'}
function ramColor(p){return p>85?'#e0564f':p>60?'#fbbf24':'#2ea875'}
function nodeIps(id){var n=NODES.find(function(x){return x.id==id});if(!n||!n.info||!n.info.ips)return [];
 var out=[],ips=n.info.ips;Object.keys(ips).forEach(function(k){(ips[k]||[]).forEach(function(ip){if(out.indexOf(ip)<0)out.push(ip)})});return out}
function subnetDefaultJS(type,tid){return type=='sit'?('fd00:'+tid+'::/64'):('192.168.'+tid+'.0/24')}
function ipItems(ips){return ips.map(function(x){return {v:x,label:x}})}

var cur='overview',NODES=[],FLEET=[],HIST=[],FRXHIST=[],FTXHIST=[],PF=[],TT=0,editingId=null,EDID=null,selTargets={},SEL={},SSI={},SSCB={},CHK={},CHECKING=0;
var SELN={},SELT={},selN=false,selT=false;  // bulk-select state (nodes / tunnels)
var LIM=25,PG={nodes:0,tunnels:0,portfw:0,agent:0},QRY={nodes:'',tunnels:'',portfw:'',agent:''},TOT={nodes:0,tunnels:0,portfw:0,agent:0},SEARCH_T=0,createTries=0,pfTries=0,AGMETA=null,PAL=null,PALIDX=0,PALITEMS=[],PALDATA={nodes:[],tuns:[]};
var TYPEITEMS=[{v:'vxlan',label:'VXLAN'},{v:'gre',label:'GRE'},{v:'sit',label:'SIT (IPv6)'}];
var SUBNETRANGES=[{v:'192.168',label:'خودکار · 192.168.x (پیشنهادی)'},{v:'10',label:'خودکار · 10.x'},{v:'172.16',label:'خودکار · 172.16.x'},{v:'custom',label:'دلخواه (دستی وارد کن)'}];
var SUBNETRANGES2=[{v:'192.168',label:'192.168.x'},{v:'10',label:'10.x'},{v:'172.16',label:'172.16.x'}];
document.querySelectorAll('#nav .navi').forEach(function(p){p.onclick=function(){cur=p.dataset.t;drawer(false);render()}});
function setnav(){document.querySelectorAll('#nav .navi').forEach(function(p){p.classList.toggle('on',p.dataset.t==cur)})}
function drawer(open){document.body.classList.toggle('navopen',!!open)}
async function updateSidebar(){var s=await j('summary').catch(function(){return{}});
 setT('ct_nodes',num(s.nodes_total));setT('ct_tunnels',num(s.links));setT('ct_portfw',num(s.portfw));
}

// ===== styled single-select dropdown (same look as the node/target lists) =====
// items:[{v,label,sub}]  key:unique id  cb:optional fn-name called after a pick
function ssHTML(key,items,sel,ph,cb){SSI[key]=items;SSCB[key]=cb||'';
 if(sel==null&&items.length)sel=items[0].v;SEL[key]=sel;
 var cur=items.filter(function(x){return String(x.v)==String(sel)})[0];
 return '<button type="button" class="msbtn'+(cur?'':' ph')+'" id="ssb_'+key+'" onclick="ssToggle(\\''+key+'\\')"><span id="sst_'+key+'">'+(cur?esc(cur.label):esc(ph||'انتخاب کنید'))+'</span><span class="cv">⌄</span></button>'}
function ssRow(key,it){return '<div class="msrow'+(String(it.v)==String(SEL[key])?' sel':'')+'" data-v="'+esc(it.v)+'" onclick="ssPick(\\''+key+'\\',this)"><span class="mscheck"></span><span>'+esc(it.label)+'</span>'+(it.sub?'<span class="muted mono" style="font-size:11px;margin-inline-start:auto">'+esc(it.sub)+'</span>':'')+'</div>'}
var SS_OV={};
function ssToggle(key){var items=SSI[key]||[];if(!items.length)return;  // open the list as a centered popup (scrolls; search for long lists)
 var search=items.length>10?'<input class="search sspopq" placeholder="جستجو…" oninput="msFilter(this)" autocomplete="off">':'';
 SS_OV[key]=openModal('<div class="sspop">'+search+'<div class="sspoplist">'+items.map(function(it){return ssRow(key,it)}).join('')+'</div></div>',{cls:'sssheet'})}
function ssPick(key,row){var val=row.getAttribute('data-v');SEL[key]=val;
 var items=SSI[key]||[],cur=items.filter(function(x){return String(x.v)==String(val)})[0];
 setT('sst_'+key,cur?cur.label:val);var b=el('ssb_'+key);if(b)b.classList.remove('ph');
 if(SS_OV[key]){closeModal(SS_OV[key]);SS_OV[key]=null}
 if(SSCB[key]&&window[SSCB[key]])window[SSCB[key]]()}
function ssVal(key){return SEL[key]||''}
// click-away: close any open styled list when clicking outside it
document.addEventListener('click',function(e){document.querySelectorAll('.mslist').forEach(function(l){
 if(l.style.display=='none')return;var b=l.previousElementSibling;
 if(l.contains(e.target)||(b&&b.contains(e.target)))return;
 l.style.display='none';if(b&&b.classList)b.classList.remove('open')})});

// ===== styled confirm modal + toast (replace native alert/confirm) =====
function confirmBox(msg,yes){return new Promise(function(resolve){
 var ov=document.createElement('div');ov.className='modalov';
 ov.innerHTML='<div class="modal"><div class="mtext"></div><div class="mbtns"><button class="primary myes"></button><button class="ghost mno">انصراف</button></div></div>';
 ov.querySelector('.mtext').textContent=msg;ov.querySelector('.myes').textContent=yes||'تأیید و حذف';
 document.body.appendChild(ov);
 function done(val){ov.remove();document.removeEventListener('keydown',onk);resolve(val)}
 function onk(e){if(e.key!='Escape')return;var a=document.querySelectorAll('.modalov');if(a[a.length-1]!==ov)return;e.stopImmediatePropagation();done(false)}
 document.addEventListener('keydown',onk);
 ov.querySelector('.myes').onclick=function(){done(true)};
 ov.querySelector('.mno').onclick=function(){done(false)};
 ov.onclick=function(e){if(e.target==ov)done(false)};
 ov.querySelector('.myes').focus()})}
function toast(msg,kind){var t=document.createElement('div');t.className='toast '+(kind||'');
 t.innerHTML=(kind=='ok'?ic('okc'):kind=='err'?ic('xc'):'')+'<span>'+esc(msg)+'</span>';
 document.body.appendChild(t);setTimeout(function(){t.classList.add('show')},10);
 setTimeout(function(){t.classList.remove('show');setTimeout(function(){t.remove()},320)},3400)}

// ===== pagination + search =====
function toolbar(kind,ph){return '<div class="toolbar"><input id="q_'+kind+'" class="search" placeholder="'+ph+'" value="'+esc(QRY[kind]||'')+'" oninput="onSearch(\\''+kind+'\\')"><div class="pager" id="pg_'+kind+'"></div></div>'}
function pagerBottom(kind){return '<div class="pager" id="pgb_'+kind+'"></div>'}
function renderPager(kind){var total=TOT[kind]||0,pages=Math.max(1,Math.ceil(total/LIM)),cur=Math.min(PG[kind]+1,pages);
 var h='<button class="pbtn" '+(PG[kind]<=0?'disabled':'')+' onclick="goPage(\\''+kind+'\\',-1)">قبلی</button><span class="pinfo">صفحه '+cur+' از '+pages+' · '+total+' مورد</span><button class="pbtn" '+(cur>=pages?'disabled':'')+' onclick="goPage(\\''+kind+'\\',1)">بعدی</button>';
 var a=el('pg_'+kind),b=el('pgb_'+kind);if(a)a.innerHTML=pages>1?h:'';if(b)b.innerHTML=pages>1?h:''}
function goPage(kind,delta){var pages=Math.max(1,Math.ceil((TOT[kind]||0)/LIM));PG[kind]=Math.max(0,Math.min(pages-1,PG[kind]+delta));refresh()}
function onSearch(kind){clearTimeout(SEARCH_T);SEARCH_T=setTimeout(function(){QRY[kind]=v('q_'+kind);PG[kind]=0;refresh()},280)}
function msFilter(inp){var q=inp.value.trim().toLowerCase(),list=inp.parentNode;
 list.querySelectorAll('.msrow').forEach(function(r){r.style.display=(!q||r.textContent.toLowerCase().indexOf(q)>=0)?'':'none'})}
function subnetForBase(type,tid,base){if(type=='sit')return 'fd00:'+tid+'::/64';if(base=='10')return '10.'+tid+'.0.0/24';if(base=='172.16')return '172.16.'+tid+'.0/24';return '192.168.'+tid+'.0/24'}
function recalcEditSubnet(){if(!EDID)return;var L=FLEET.filter(function(x){return x.id==EDID})[0];if(!L)return;
 var f=el('e_sub_'+EDID);if(f)f.value=subnetForBase(ssVal('lt_'+EDID),L.tunnel_id,ssVal('lsr_'+EDID))}

// ===== bulk select (nodes / tunnels) =====
function ckN(id){return '<span class="cardck'+(SELN[id]?' on':'')+'" onclick="event.stopPropagation();toggleSelN(\\''+id+'\\')">'+(SELN[id]?'✓':'')+'</span>'}
function ckT(id){return '<span class="cardck'+(SELT[id]?' on':'')+'" onclick="event.stopPropagation();toggleSelT(\\''+id+'\\')">'+(SELT[id]?'✓':'')+'</span>'}
function toggleSelN(id){if(SELN[id])delete SELN[id];else SELN[id]=1;refreshNodes();renderSelbar()}
function toggleSelT(id){if(SELT[id])delete SELT[id];else SELT[id]=1;refreshTunnels();renderSelbar()}
function selModeBtn(kind){var on=kind=='nodes'?selN:selT;return '<button class="selbtn'+(on?' on':'')+'" onclick="toggleSelMode(\\''+kind+'\\')">'+ic('check')+(on?'لغوِ انتخاب':'انتخابِ گروهی')+'</button>'}
function toggleSelMode(kind){if(kind=='nodes'){selN=!selN;if(!selN)SELN={};var b=el('nodeList');if(b)b.classList.toggle('selmode',selN);refreshNodes()}
 else{selT=!selT;if(!selT)SELT={};var b=el('linkList');if(b)b.classList.toggle('selmode',selT);refreshTunnels()}
 var w=el('selw_'+kind);if(w)w.innerHTML=selModeBtn(kind);renderSelbar()}
function clearSel(){SELN={};SELT={};selN=false;selT=false;['nodes','tunnels'].forEach(function(k){var w=el('selw_'+k);if(w)w.innerHTML=selModeBtn(k)});
 var a=el('nodeList'),b=el('linkList');if(a)a.classList.remove('selmode');if(b)b.classList.remove('selmode');
 if(cur=='nodes')refreshNodes();else if(cur=='tunnels')refreshTunnels();renderSelbar()}
function renderSelbar(){var bar=el('selbar');var kind=cur=='nodes'?'nodes':cur=='tunnels'?'tunnels':'';
 var on=kind=='nodes'?selN:kind=='tunnels'?selT:false;var sel=kind=='nodes'?SELN:SELT;var n=on?Object.keys(sel).length:0;
 if(!on||!n){if(bar)bar.remove();return}
 var acts=kind=='nodes'
  ?'<button onclick="bulkNodes(\\'test\\')">'+ic('bolt')+'تست</button><button onclick="bulkNodes(\\'del\\')">'+ic('trash')+'حذف</button>'
  :'<button onclick="bulkTun(\\'check\\')">'+ic('activity')+'بررسی</button><button onclick="bulkTun(\\'rebuild\\')">'+ic('redo')+'بازسازی</button><button onclick="bulkTun(\\'del\\')">'+ic('trash')+'حذف</button>';
 if(!bar){bar=document.createElement('div');bar.className='selbar';bar.id='selbar';document.body.appendChild(bar)}
 bar.innerHTML='<span>'+n+' '+(kind=='nodes'?'نود':'تونل')+' انتخاب شده</span>'+acts+'<button onclick="clearSel()">لغو</button>'}
async function bulkNodes(action){var ids=Object.keys(SELN);if(!ids.length)return;
 if(action=='del'){if(!await confirmBox(ids.length+' نود از رجیستری حذف شود؟ (تونل‌هایشان دست‌نخورده می‌ماند)'))return;
  for(var i=0;i<ids.length;i++)await post('node-del',{id:ids[i]});toast(ids.length+' نود حذف شد','ok');SELN={};selN=false}
 else if(action=='test'){toast('در حال تستِ '+ids.length+' نود…');var okc=0;
  for(var i=0;i<ids.length;i++){var r=await post('node-test',{id:ids[i]});if(r.d&&r.d.ok)okc++}toast(okc+'/'+ids.length+' نود آنلاین','ok')}
 var w=el('selw_nodes');if(w)w.innerHTML=selModeBtn('nodes');var b=el('nodeList');if(b)b.classList.toggle('selmode',selN);refreshNodes();renderSelbar()}
async function bulkTun(action){var ids=Object.keys(SELT);if(!ids.length)return;
 if(action=='check'){CHECKING++;try{for(var i=0;i<ids.length;i++)await checkLink(ids[i])}finally{CHECKING--}toast('بررسیِ '+ids.length+' تونل تمام شد','ok');renderSelbar();return}
 if(action=='del'){if(!await confirmBox(ids.length+' تونل روی هر دو نود حذف شود؟'))return;
  for(var i=0;i<ids.length;i++)await post('delete-link',{id:ids[i]});toast(ids.length+' تونل حذف شد','ok');SELT={};selT=false}
 else if(action=='rebuild'){if(!await confirmBox(ids.length+' تونل از نو ساخته شود؟'))return;toast('در حال بازسازی…');var okc=0;
  for(var i=0;i<ids.length;i++){var r=await post('rebuild-link',{id:ids[i]});if(r.ok&&r.d.ok)okc++}toast(okc+'/'+ids.length+' تونل بازسازی شد','ok');SELT={};selT=false}
 var w=el('selw_tunnels');if(w)w.innerHTML=selModeBtn('tunnels');var b=el('linkList');if(b)b.classList.toggle('selmode',selT);refreshTunnels();renderSelbar()}

// ===== Overview
function statc(id,label,hue,icon){return '<div class="card stat"><div class="k"><span class="chip" style="--hue:'+hue+'">'+ic(icon,hue)+'</span> '+label+'</div><div class="v" id="'+id+'">—</div></div>'}
function overviewSkel(){el('view').innerHTML='<h1>'+ic('dash','var(--acc)')+' نمای کلی</h1><p class="sub">وضعیت لحظه‌ای فلیت</p>'+
 '<div class="hero"><div class="k">'+ic('shield','#34d399')+' سلامت لینک‌ها</div><div class="v" id="o_health">—</div><div class="hsub" id="o_hsub">در حال دریافت…</div></div>'+
 '<div class="grid">'+statc('o_nodes','نود آنلاین','#60a5fa','server')+statc('o_links','لینک تونل','#a78bfa','link')+statc('o_tun','تونل نودها','#2dd4bf','bolt')+statc('o_pf','پورت‌فوروارد','#fb923c','globe')+'</div>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' مصرفِ زندهٔ منابع فلیت</div><div class="card"><div class="gauges">'+gaugeHTML('ocpu','CPU')+gaugeHTML('oram','RAM')+gaugeHTML('odisk','دیسک')+'</div></div>'+
 '<div class="sec">'+ic('traf','var(--acc)')+' ترافیک فلیت<span class="lpill"><span class="pd"></span>زنده</span></div><div class="card"><div class="tf-chart"><div class="tf-top"><span class="din">↓ <b id="o_frx">—</b></span><span class="dout">↑ <b id="o_ftx">—</b></span></div><svg id="o_traf" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">↓ ورودیِ کل</span><b id="o_ftin">—</b></div><div class="ttile"><span class="dout">↑ خروجیِ کل</span><b id="o_ftout">—</b></div></div></div>'+
 '<div class="sec">'+ic('server','var(--acc)')+' وضعیت نودها</div><div class="card"><div class="seg"><svg id="o_donut" class="donut" viewBox="0 0 120 120"></svg><div class="segs" id="o_seg"></div></div></div>'}
async function refreshOverview(){var s=await j('summary');if(!el('o_health'))return;
 var on=num(s.nodes_online),tot=num(s.nodes_total),off=tot-on,links=num(s.links);
 var hp=links?Math.round(num(s.links_healthy)/links*100):100;
 setT('o_health',hp+'٪');setT('o_hsub',num(s.links_healthy)+' از '+links+' لینک سالم');
 el('o_nodes').innerHTML='<span dir="ltr">'+on+' / '+tot+'</span>';setT('o_links',links);setT('o_tun',num(s.tunnels));setT('o_pf',num(s.portfw));
 var ram=num(s.ram_pct);
 setGauge('ocpu',s.cpu_pct,'لود '+(s.load_avg!=null?s.load_avg:'—'));
 setGauge('oram',ram,num(s.mem_used_mb)+' / '+num(s.mem_total_mb)+' م‌ب');
 setGauge('odisk',s.disk_pct,s.disk_used_mb!=null?(Math.round(num(s.disk_used_mb)/1024)+' / '+Math.round(num(s.disk_total_mb)/1024)+' گیگ'):'—');
 var frx=num(s.fleet_rx_bps),ftx=num(s.fleet_tx_bps);
 setT('o_frx',fmtRate(frx));setT('o_ftx',fmtRate(ftx));
 setT('o_ftin',fmtBytes(s.fleet_rx_total));setT('o_ftout',fmtBytes(s.fleet_tx_total));
 FRXHIST.push(frx);FTXHIST.push(ftx);if(FRXHIST.length>26){FRXHIST.shift();FTXHIST.shift()}dualSpark('o_traf',FRXHIST,FTXHIST);
 donut('o_donut',[['آنلاین',on,cssv('--ok')],['آفلاین',off,cssv('--bad')]]);
 el('o_seg').innerHTML='<div><span>'+dotc(cssv('--ok'))+' آنلاین</span><b>'+on+'</b></div><div><span>'+dotc(cssv('--bad'))+' آفلاین</span><b>'+off+'</b></div><div><span>'+dotc(cssv('--chart1'))+' مصرف رم</span><b>'+ram+'٪</b></div>'}

// ===== Nodes
function nodesSkel(){el('view').innerHTML='<h1>'+ic('server','var(--acc)')+' نودها</h1><p class="sub">افزودن و وضعیت زنده‌ی نودها</p>'+
 '<button class="primary" onclick="openNodeAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+'افزودن نود</button>'+
 '<div class="sec">'+ic('server','var(--acc)')+' نودهای فلیت</div>'+toolbar('nodes','جستجوی نام یا آی‌پی…')+'<div id="nodeList"></div>'+pagerBottom('nodes')}
function openNodeAddModal(){var b='<div class="grid2"><div><label class="first">نام</label><input id="n_name" placeholder="frankfurt-1"></div><div><label class="first">هاست / آی‌پی</label><input id="n_host" placeholder="203.0.113.10"></div></div><div class="grid2"><div><label>پورت agent</label><input id="n_port" placeholder="8099"></div><div><label>توکن نود</label><input id="n_tok" placeholder="توکن نود"></div></div><label>پروکسیِ کنترل (اختیاری) — پنل از این پروکسی به این نود وصل می‌شود</label><input id="n_proxy" placeholder="socks5://host:1080  یا  http://user:pass@host:8080"><div class="msg" id="n_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>افزودنِ نود</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="addNode()">افزودن و اتصال</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
async function refreshNodes(){if(editingId)return;var r=await j('nodes?offset='+(PG.nodes*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.nodes));NODES=r.nodes||[];TOT.nodes=num(r.total);var box=el('nodeList');if(!box)return;
 setHTML(box,NODES.length?NODES.map(nodeCard).join(''):'<div class="card muted">'+(QRY.nodes?'موردی یافت نشد.':'هنوز نودی اضافه نشده — دکمهٔ «افزودن نود» بالا.')+'</div>');renderPager('nodes')}
function kv(k,val){return '<span>'+k+': <b>'+val+'</b></span>'}
function proxyScheme(p){if(!p)return '';var i=p.indexOf('://');return (i>0?p.slice(0,i):'socks5').toLowerCase()}
// ===== popup modal shell (edit forms + node-details) =====
function openModal(html,opts){opts=opts||{};
 var ov=document.createElement('div');ov.className='modalov';
 ov.innerHTML='<div class="modal wide'+(opts.cls?' '+opts.cls:'')+'">'+html+'</div>';
 document.body.appendChild(ov);editingId='modal';
 try{document.body.style.overflow='hidden'}catch(e){}
 ov.addEventListener('mousedown',function(e){if(e.target===ov)closeModal(ov)});
 ov._esc=function(e){if(e.key!='Escape')return;var a=document.querySelectorAll('.modalov');if(a[a.length-1]!==ov)return;e.stopImmediatePropagation();closeModal(ov)};document.addEventListener('keydown',ov._esc);
 ov._onclose=opts.onclose;
 var f=ov.querySelector('input,select,textarea');if(f){try{f.focus()}catch(e){}}
 return ov}
function closeModal(ov){if(!ov||ov._closed)return;ov._closed=true;
 document.removeEventListener('keydown',ov._esc);
 if(ov._onclose){try{ov._onclose()}catch(e){}}
 ov.remove();editingId=null;EDID=null;
 try{if(!document.querySelector('.modalov'))document.body.style.overflow=''}catch(e){}
 refresh().catch(function(){})}
function glvl(p){return p>=88?'crit':p>=70?'warn':'ok'}
function gaugeHTML(key,label){return '<div class="gauge"><div class="gwrap"><svg width="84" height="84"><circle class="gtrack" cx="42" cy="42" r="33" fill="none" stroke-width="8"/><circle id="g_'+key+'" class="gfill ok" cx="42" cy="42" r="33" fill="none" stroke-width="8" stroke-linecap="round" stroke-dasharray="207.3" stroke-dashoffset="207.3" transform="rotate(-90 42 42)"/></svg><div class="gc"><b id="gt_'+key+'">—</b></div></div><div class="gl">'+label+'</div><div class="gsub" id="gs_'+key+'">…</div></div>'}
function setGauge(key,pct,sub){var C=207.3,g=el('g_'+key),t=el('gt_'+key),s=el('gs_'+key);if(!g)return;
 pct=Math.max(0,Math.min(100,Math.round(num(pct))));
 g.setAttribute('stroke-dashoffset',(C*(1-pct/100)).toFixed(1));g.setAttribute('class','gfill '+glvl(pct));
 t.innerHTML=pct+'<i>٪</i>';if(s&&sub!=null)s.textContent=sub}
function ndTile(icn,label,val,wide,ltr){return '<div class="nd-tile'+(wide?' nd-wide':'')+'"><span class="medi">'+ic(icn)+'</span><span>'+label+'</span><b'+(ltr?' class="ltr"':'')+'>'+val+'</b></div>'}
function ndApplyStats(s){var rp=s.mem_total_mb?Math.round(num(s.mem_used_mb)/num(s.mem_total_mb)*100):0;
 setGauge('cpu',s.cpu_pct,'لود '+((s.load||[])[0]||'—'));
 setGauge('ram',rp,num(s.mem_used_mb)+' / '+num(s.mem_total_mb)+' م‌ب');
 setGauge('disk',s.disk_pct,s.disk_used_mb!=null?(Math.round(num(s.disk_used_mb)/1024)+' / '+Math.round(num(s.disk_total_mb)/1024)+' گیگ'):'—')}
function ndSetHead(ov,online){var dot=ov.querySelector('.nd-head .dot');if(dot)dot.className='dot '+(online?'ok':'bad');
 var bd=ov.querySelector('.nd-head .nd-ping');if(bd){bd.className='badge '+(online?'ok':'bad')+' nd-ping';bd.textContent=online?'آنلاین':'آفلاین'}
 var sb=ov.querySelector('.msticky .sb');if(sb)sb.innerHTML=online?'<span class="lpill"><span class="pd"></span>زنده</span> به‌روزرسانی هر ۲ ثانیه':'آفلاین — آخرین مقادیر'}
function nodeDetails(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;var i=n.info||{},s=i.stats||{};
 var head='<div class="nd-head"><span class="dot '+(n.online?'ok':'bad')+'"></span><div class="nd-id"><b class="nd-name">'+esc(n.name)+'</b><span class="nd-hp">'+esc(n.host)+':'+esc(n.port)+'</span></div>'+(n.proxy?'<span class="tag" style="margin-inline-start:6px">پروکسی</span>':'')+'<span class="badge '+(n.online?'ok':'bad')+' nd-ping">'+(n.online?'آنلاین':'آفلاین')+'</span></div>';
 var mb;
 if(n.online){var g='<div class="gauges">'+gaugeHTML('cpu','CPU')+gaugeHTML('ram','RAM')+gaugeHTML('disk','دیسک')+'</div>';
  var traf='<div class="nd-sec">'+ic('traf')+' ترافیک<span class="lpill" style="margin-inline-start:auto"><span class="pd"></span>زنده</span></div><div class="tf-chart"><div class="tf-top"><span class="din">↓ <b id="tf_rin">—</b></span><span class="dout">↑ <b id="tf_rout">—</b></span></div><svg id="tf_spark" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">↓ ورودیِ کل</span><b id="tf_tin">—</b></div><div class="ttile"><span class="dout">↑ خروجیِ کل</span><b id="tf_tout">—</b></div></div><div id="tf_tuns" class="tf-tuns"></div>';
  var tiles='<div class="nd-grid">'+ndTile('os','سیستم‌عامل',esc(s.os||'?'),false,true)+ndTile('clock','آپ‌تایم',s.uptime?fmtup(s.uptime):'?')+ndTile('cores','تعداد هسته',num(s.cpus)||'?')+ndTile('link','تونل',num(i.tunnels))+ndTile('globe','پورت‌فوروارد',num(i.portfw))+ndTile('shield','پروکسیِ کنترل',n.proxy?esc(proxyScheme(n.proxy)):'—')+ndTile('server','میزبان',esc(i.hostname||'?'),true,true)+ndTile('pin','آی‌پی',esc(n.host),true,true)+'</div>';
  mb=head+g+traf+'<div class="nd-divider"></div>'+tiles+'<div class="nd-divider"></div><div class="nd-sec">'+ic('pin')+' آی‌پی‌ها<span class="muted" style="margin-inline-start:auto;font-size:11px;font-weight:500">تونل‌شده / آزاد</span></div><div id="nd_ips" class="ndips"><div class="muted" style="font-size:11.5px;padding:6px 2px">…</div></div>'}
 else{mb=head+'<div class="nd-off">'+ic('plugoff')+'<b>در دسترس نیست</b>'+(i.error?'<span>'+esc(i.error)+'</span>':'')+'</div>'}
 var sub=n.online?'<span class="lpill"><span class="pd"></span>زنده</span> به‌روزرسانی هر ۲ ثانیه':'وضعیت نود';
 var html='<div class="msticky"><span class="medi">'+ic('info')+'</span><div class="ttl"><h3>مشخصات نود</h3><div class="sb">'+sub+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+mb+'</div><div class="mfoot"><button class="primary" onclick="ndRetest(\\''+id+'\\')">تستِ اتصال</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">بستن</button></div>';
 var ov=openModal(html,{cls:'ndsheet',onclose:function(){if(ov._iv){clearInterval(ov._iv);ov._iv=0}}});
 if(n.online){ndApplyStats(s);var tfin=[],tfout=[];
  j('node-ips?id='+id).then(function(r){if(ov._closed)return;var ib=el('nd_ips');if(ib)ib.innerHTML=ipTagsHTML(r&&r.ips)}).catch(function(){});
  var poll=function(){
   j('node-stats?id='+id).then(function(r){if(ov._closed)return;if(r&&r.online&&r.stats){ndApplyStats(r.stats);ndSetHead(ov,true)}else{ndSetHead(ov,false)}}).catch(function(){});
   j('traffic?id='+id).then(function(r){if(ov._closed||!r||!r.node)return;var nd=r.node;
    setT('tf_rin',fmtRate(nd.rx_bps));setT('tf_rout',fmtRate(nd.tx_bps));setT('tf_tin',fmtBytes(nd.rx_total));setT('tf_tout',fmtBytes(nd.tx_total));
    tfin.push(num(nd.rx_bps));tfout.push(num(nd.tx_bps));if(tfin.length>30){tfin.shift();tfout.shift()}dualSpark('tf_spark',tfin,tfout);
    var tb=el('tf_tuns');if(tb)tb.innerHTML=(r.tunnels&&r.tunnels.length)?r.tunnels.map(tfRow).join(''):'<div class="muted" style="font-size:11.5px;padding:7px 2px">تونلی روی این نود نیست</div>'}).catch(function(){})};
  poll();ov._iv=setInterval(poll,2500)}}
function ndRetest(id){j('node-stats?id='+id).then(function(r){if(r&&r.online){toast('آنلاین','ok')}else{toast('آفلاین: '+((r&&r.error)||'در دسترس نیست'),'err')}}).catch(function(){toast('خطا در بررسی','err')})}
function openNodeEdit(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;
 var b='<div class="grid2"><div><label class="first">نام</label><input id="e_name_'+id+'" value="'+esc(n.name)+'"></div><div><label class="first">هاست / آی‌پی</label><input id="e_host_'+id+'" value="'+esc(n.host)+'"></div></div><div class="grid2"><div><label>پورت</label><input id="e_port_'+id+'" value="'+esc(n.port)+'"></div><div><label>توکن</label><input id="e_tok_'+id+'" placeholder="خالی = توکن فعلی بماند"></div></div><label>پروکسیِ کنترل (خالی = بدون پروکسی)</label><input id="e_proxy_'+id+'" value="'+esc(n.proxy||'')+'" placeholder="socks5://host:1080 یا http://user:pass@host:8080"><div class="msg" id="em_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>ویرایشِ نود</h3><div class="sb">'+esc(n.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveEdit(\\''+id+'\\')">ذخیره</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
function openLinkEdit(id){var l=FLEET.find(function(x){return x.id==id});if(!l)return;EDID=id;
 var b='<div class="grid2"><div><label class="first">نوع تونل</label>'+ssHTML('lt_'+id,TYPEITEMS,l.type,'نوع','recalcEditSubnet')+'</div><div><label class="first">رنجِ لوکال</label>'+ssHTML('lsr_'+id,SUBNETRANGES2,'192.168','رنج','recalcEditSubnet')+'</div></div><label>سابنت</label><input id="e_sub_'+id+'" value="'+esc(l.subnet)+'"><div class="muted" style="font-size:11.5px;margin-top:9px">تغییر نوع یا سابنت، تونل را روی هر دو نود بازسازی می‌کند (شناسه '+esc(l.tunnel_id)+' حفظ می‌شود).</div><div class="msg" id="lem_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('link')+'</span><div class="ttl"><h3>ویرایشِ تونل</h3><div class="sb">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveLinkEdit(\\''+id+'\\')">ذخیره و بازسازی</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>',{onclose:function(){EDID=null}})}
function openPfEdit(i){var p=PF[i];if(!p)return;EDID='pf'+i;var rotOn=p.switch_interval>0;
 var b='<div class="grid2"><div><label class="first">پورتِ ورودی</label><input id="pe_lp_'+i+'" value="'+esc(p.listen_port)+'"></div><div><label class="first">پورتِ مقصد</label><input id="pe_dp_'+i+'" value="'+esc(p.dst_port)+'"></div></div><label>آی‌پی(های) مقصد — با کاما جدا کن</label><input id="pe_ips_'+i+'" value="'+esc((p.dst_ips||[]).join(', '))+'"><label>چرخش بینِ مقصدها</label><div class="tgl"><span class="tglsw'+(rotOn?' on':'')+'" id="pe_tgl_'+i+'" onclick="pfTgl('+i+')"></span><span class="muted" id="pe_tgllbl_'+i+'">'+(rotOn?'روشن':'خاموش')+'</span></div><div id="pe_intwrap_'+i+'" style="'+(rotOn?'':'display:none')+'"><label>بازهٔ چرخش (دقیقه)</label><input id="pe_int_'+i+'" value="'+esc(rotOn?(p.switch_interval/60):5)+'"></div><div class="muted" style="font-size:11.5px;margin-top:9px">چرخش فقط با ۲ آی‌پیِ مقصد یا بیشتر فعال می‌شود.</div><div class="msg" id="pem_'+i+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>ویرایشِ پورت‌فوروارد</h3><div class="sb">'+esc(p.node)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="savePfEdit('+i+')">ذخیره</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
function nodeCard(n){var i=n.info||{};
 var badge=n.online?'<span class="badge ok">آنلاین</span>':(n.pending?'<span class="badge na">در حال بررسی…</span>':'<span class="badge bad">آفلاین</span>');
 var head='<div class="nrow"><span class="ndot '+(n.online?'on':'off')+'"></span><div style="min-width:0"><div class="name">'+esc(n.name)+(n.proxy?' <span class="tag" style="font-size:9.5px;padding:1px 6px">پروکسی</span>':'')+'</div><div class="muted mono" style="font-size:12px">'+esc(n.host)+':'+esc(n.port)+'</div></div><span class="grow"></span>'+badge+'</div>';
 var body=n.online?'<div class="nchips"><span class="nchip">'+ic('link')+'تونل <b>'+num(i.tunnels)+'</b></span><span class="nchip">'+ic('globe')+'پورت‌فوروارد <b>'+num(i.portfw)+'</b></span>'+(i.version?'<span class="nchip">'+ic('cpu')+'ایجنت v<b>'+num(i.version)+'</b></span>':'')+(n.proxy?'<span class="nchip">'+ic('shield')+'<b>'+esc(proxyScheme(n.proxy))+'</b></span>':'')+'</div>':'<div class="noff">'+ic('plugoff')+'<b>در دسترس نیست</b>'+(i.error?'<span>· '+esc(i.error)+'</span>':'')+'</div>';
 var acts='<div class="nact iconly"><button class="act ok" title="تست" onclick="testNode(\\''+n.id+'\\')">'+ic('bolt')+'</button><button class="act info" title="مشخصات" onclick="nodeDetails(\\''+n.id+'\\')">'+ic('info')+'</button><button class="act warn" title="ویرایش" onclick="openNodeEdit(\\''+n.id+'\\')">'+ic('pen')+'</button><button class="act danger" title="حذف" onclick="delNode(\\''+n.id+'\\',\\''+esc(n.name)+'\\')">'+ic('trash')+'</button></div>';
 return '<div class="card node">'+head+body+upBar(n)+acts+'<div class="msg" id="ntm_'+n.id+'"></div></div>'}
function upBar(n){var r=n.uptime||[];if(!r.length)return '';
 var up=r.reduce(function(a,b){return a+b},0),pct=Math.round(up/r.length*100);
 return '<div class="upwrap"><div class="uptop">آپتایم<b style="margin-inline-start:6px">'+pct+'٪</b><span class="r">'+(r.length*2)+' دقیقهٔ اخیر</span></div><div class="upbar">'+r.map(function(v){return '<i'+(v?'':' class="d"')+'></i>'}).join('')+'</div></div>'}
async function saveEdit(id){var m=el('em_'+id);var name=v('e_name_'+id),host=v('e_host_'+id),port=v('e_port_'+id),tok=v('e_tok_'+id);
 if(!name||!host||!port){m.className='msg err';m.textContent='نام، هاست و پورت لازم است';return}
 m.className='msg';m.textContent='در حال ذخیره…';
 var r=await post('node-edit',{id:id,name:name,host:host,port:port,token:tok,proxy:v('e_proxy_'+id)});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=r.d.error||'ناموفق'}}
async function addNode(){var m=el('n_msg');var name=v('n_name'),host=v('n_host'),port=v('n_port'),tok=v('n_tok');
 if(!name||!host||!port||!tok){m.className='msg err';m.textContent='لطفاً نام، هاست، پورت و توکن را پر کن';return}
 m.className='msg';m.textContent='در حال اتصال…';
 var r=await post('node-add',{name:name,host:host,port:port,token:tok,proxy:v('n_proxy')});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast('نود اضافه شد'+(r.d.online?' · آنلاین':' · آفلاین: '+(r.d.error||'')),r.d.online?'ok':'err')}
 else{m.className='msg err';m.textContent=r.d.error||'ناموفق'}}
async function testNode(id){var m=el('ntm_'+id);if(m){m.className='msg';m.textContent='در حال تست…'}
 var t0=performance.now();var r=await post('node-test',{id:id});var ms=Math.round(performance.now()-t0);
 var info=(r.d&&r.d.info)||{};if(!m)return;
 if(r.d&&r.d.ok){m.className='msg ok';m.innerHTML=CK+esc(' آنلاین — '+(info.hostname||'')+' · '+ms+'ms')}
 else{m.className='msg err';m.textContent='آفلاین: '+(info.error||'در دسترس نیست')+' · '+ms+'ms'}}
async function delNode(id,nm){if(!await confirmBox('نود «'+nm+'» حذف شود؟ تونل‌هایش دست‌نخورده می‌مانند؛ فقط از رجیستری حذف می‌شود.'))return;await post('node-del',{id:id});editingId=null;refreshNodes()}

// ===== Tunnels
function tunnelsSkel(){CHK={};el('view').innerHTML='<h1>'+ic('link','var(--acc)')+' تونل‌ها</h1><p class="sub">هر لینک نود‌به‌نود جداگانه است — بررسی، ویرایش و حذف مستقل دارد</p>'+
 '<div class="tbtnrow"><button class="primary" onclick="openCreateModal()">'+ic('plus')+'افزودن تونل</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+'بررسی اتصال همگانی</button></div>'+
 toolbar('tunnels','جستجوی نام نود / نوع / شناسه…')+'<div id="linkList"></div>'+pagerBottom('tunnels')}
function sideB(online,h){
 if(!online)return '<span class="badge bad">نود آفلاین</span>';          // به agentِ نود وصل نشد
 if(!h)return '<span class="badge bad">قطع</span>';                      // تونل روی نود نیست
 if(h.up==null)return '<span class="badge na">در حال بررسی…</span>';     // هنوز پروب نشده
 if(!h.up)return '<span class="badge bad">قطع</span>';                    // اینترفیس پایین
 if(h.peer_ping===true)return '<span class="badge ok">متصل'+CK+'</span>';     // پینگِ پیر برقرار = ترافیک رد می‌شود
 if(h.peer_ping===false)return '<span class="badge warn">بدون پینگ</span>'; // بالا ولی پیر جواب نمی‌دهد
 return '<span class="badge na">بالا</span>'}                             // بالا، پینگ نامشخص
function fmtms(x){return (x>=10?Math.round(x):Math.round(x*10)/10)+'ms'}
function pingInfo(h){var p=[];if(h.rtt_ms!=null)p.push('پینگ '+fmtms(h.rtt_ms));if(h.loss_pct!=null)p.push(h.loss_pct>0?('اتلاف '+(Math.round(h.loss_pct*10)/10)+'٪'):'بدون اتلاف');return p.join(' · ')}
function sideTxt(online,h){
 if(!online)return 'نود آفلاین (به agent وصل نشد — شاید پورت/توکن عوض شده)';
 if(!h)return 'قطع (تونل روی نود نیست)';
 if(h.up==null)return 'در حال بررسی…';
 if(!h.up)return 'قطع (اینترفیس پایین)';
 if(h.peer_ping===true){var e=pingInfo(h);return 'متصل'+(e?' · '+e:'')}
 if(h.peer_ping===false)return 'پینگ جواب نداد'+(h.loss_pct!=null?' (اتلاف '+(Math.round(h.loss_pct)||100)+'٪)':'');
 return 'بالا (پینگ نامشخص)'}
function sideMini(online,h){
 if(!online||!h)return {t:'قطع',c:'var(--bad)'};
 if(h.up==null)return {t:'…',c:'var(--sub)'};
 if(!h.up)return {t:'قطع',c:'var(--bad)'};
 if(h.peer_ping===false)return {t:'نیم‌بند',c:'var(--gold)'};
 return {t:'متصل',c:'var(--ok)'}}
function linkCard(l){
 var sa=sideMini(l.a_online,l.a_health),sb=sideMini(l.b_online,l.b_health);
 var body='<div class="tninfo">'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="tnst" id="lba_'+l.id+'" style="color:'+sa.c+'">'+esc(sa.t)+'</span></div><div class="tna mono">'+esc(l.a_ip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="tnst" id="lbb_'+l.id+'" style="color:'+sb.c+'">'+esc(sb.t)+'</span></div><div class="tna mono">'+esc(l.b_ip)+'</div></div>'+
  '</div>'+
  '<div class="tnmeta"><span>سابنت: <b class="mono">'+esc(l.subnet)+'</b></span><span>شناسه: <b>'+esc(l.tunnel_id)+'</b></span><span>اینترفیس: <b class="mono">'+esc(l.name)+'</b></span><span>نوع: <span class="tag '+esc(l.type)+'">'+esc(l.type)+'</span></span></div>';
 var c=CHK[l.id];var msg='<div class="msg '+(c?c.cls:'')+'" id="lchk_'+l.id+'">'+(c?c.html:'')+'</div>';
 var traf=(l.rx_total!=null||l.rx_bps!=null)?'<div class="ltraf"><span class="din">↓ '+fmtRate(l.rx_bps)+'</span><span class="dout">↑ '+fmtRate(l.tx_bps)+'</span><span class="tot">مجموع ↓'+fmtBytes(l.rx_total)+' ↑'+fmtBytes(l.tx_total)+'</span></div>':'';
 var acts='<div class="nact iconly"><button class="act ok" title="بررسی اتصال" onclick="checkLink(\\''+l.id+'\\')">'+ic('activity')+'</button><button class="act" title="بازسازی" onclick="rebuildLink(\\''+l.id+'\\')">'+ic('redo')+'</button><button class="act warn" title="ویرایش" onclick="openLinkEdit(\\''+l.id+'\\')">'+ic('pen')+'</button><button class="act danger" title="حذف" onclick="delLink(\\''+l.id+'\\')">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>آی‌پیِ یکی از نودها عوض شده — این تونل نیاز به بازسازی دارد. دکمهٔ «بازسازی» را بزن.</span></div>':'';
 return '<div class="card">'+drift+body+traf+acts+msg+'</div>'}
async function refreshTunnels(){if(editingId||CHECKING)return;var f=await j('fleet?offset='+(PG.tunnels*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.tunnels));FLEET=f.links||[];TOT.tunnels=num(f.total);var box=el('linkList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(linkCard).join(''):'<div class="card muted">'+(QRY.tunnels?'موردی یافت نشد.':'هنوز لینکی نیست — دکمهٔ «افزودن تونل» بالا.')+'</div>');renderPager('tunnels')}
async function saveLinkEdit(id){var m=el('lem_'+id);var type=ssVal('lt_'+id),subnet=v('e_sub_'+id);
 if(!type){m.className='msg err';m.textContent='نوع تونل لازم است';return}
 m.className='msg';m.textContent='در حال بازسازی تونل روی دو نود…';
 var r=await post('edit-link',{id:id,type:type,subnet:subnet});
 if(r.ok&&r.d.ok){delete CHK[id];closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=r.d.error||r.d.msg||'ناموفق'}}
function setChk(id,cls,html){CHK[id]={cls:cls,html:html};var m=el('lchk_'+id);if(m){m.className='msg '+cls;m.innerHTML=html}}
function chkLines(hdr,a,b){return '<div class="chh">'+hdr+'</div><div class="chl">'+esc(a)+'</div><div class="chl">'+esc(b)+'</div>'}
async function checkLink(id){CHECKING++;
 try{
  setChk(id,'',esc('در حال بررسی اتصال (پینگِ زنده روی دو سر)…'));
  var r=await post('check-link',{id:id});
  var L=FLEET.filter(function(x){return x.id==id})[0]||{};
  if(!(r.ok&&r.d.ok)){setChk(id,'err',esc((r.d&&(r.d.error||r.d.msg))||'ناموفق'));return}
  var d=r.d,ab=el('lba_'+id),bb=el('lbb_'+id),sa=sideMini(d.a_online,d.a_health),sb=sideMini(d.b_online,d.b_health);
  if(ab){ab.style.color=sa.c;ab.textContent=sa.t}if(bb){bb.style.color=sb.c;bb.textContent=sb.t}
  var aup=d.a_online&&d.a_health&&d.a_health.up,bup=d.b_online&&d.b_health&&d.b_health.up;
  var pinged=(d.a_health&&d.a_health.peer_ping===true)||(d.b_health&&d.b_health.peer_ping===true);
  var okAll=aup&&bup&&pinged;
  setChk(id,okAll?'ok':'err',chkLines(okAll?CK+' اتصال برقرار':XK+' مشکل در اتصال',
    (L.a_name||'A')+': '+sideTxt(d.a_online,d.a_health),(L.b_name||'B')+': '+sideTxt(d.b_online,d.b_health)));
 }finally{CHECKING--}}
async function checkAll(){var b=el('chkAllBtn');if(!FLEET.length){toast('تونلی برای بررسی نیست','err');return}
 if(b){b.disabled=true;b.style.opacity='.6'}CHECKING++;  // hold guard across the whole batch
 try{await Promise.all(FLEET.map(function(l){return checkLink(l.id)}))}
 finally{CHECKING--;if(b){b.disabled=false;b.style.opacity=''}}
 toast('بررسیِ همهٔ تونل‌ها تمام شد','ok')}
async function rebuildLink(id){
 var _L=FLEET.filter(function(x){return x.id==id})[0];
 if(_L&&_L.drift){openRebuildPicker(id);return}   // IP drifted -> let the operator pick the new IP
 if(!await confirmBox('این تونل روی هر دو نود از نو ساخته شود؟ (حذف و ساختِ مجدد با همان تنظیمات)'))return;
 CHECKING++;
 try{setChk(id,'',esc('در حال بازسازیِ تونل روی دو نود…'));
  var r=await post('rebuild-link',{id:id});
  if(r.ok&&r.d.ok){setChk(id,'ok',CK+esc('تونل از نو ساخته شد — با «بررسی اتصال» تستش کن'));toast('بازسازی شد','ok')}
  else setChk(id,'err',esc((r.d&&(r.d.error||r.d.msg))||'بازسازی ناموفق'));
 }finally{CHECKING--}}
// ===== IP tags + rebuild IP picker (opens on بازسازی for a drift-flagged tunnel) =====
var LINKI='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px"><path d="M9 7H6a4 4 0 000 8h3M15 7h3a4 4 0 010 8h-3M8 11h8"/></svg>';
var CK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-inline-start:3px"><path d="M20 6 9 17l-5-5"/></svg>';
var XK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-inline-start:3px"><path d="M18 6 6 18M6 6l12 12"/></svg>';
function ipChips(x){var t=(x.peers||[]).map(function(p){
  return '<span class="ippeer" onclick="ipTog(event,this)"><span class="ipchip">'+LINKI+' '+esc(p.node)+'</span><span class="iptyp '+esc(p.type)+'">'+esc(p.type)+'</span></span>'});
 if(x.free)t.push('<span class="ipfree">آزاد</span>');return t.join('')}
function ipTog(ev,el){if(ev)ev.stopPropagation();el.classList.toggle('show')}
function ipTagsHTML(ips){ips=ips||[];if(!ips.length)return '<div class="muted" style="font-size:11.5px;padding:6px 2px">آی‌پی‌ای گزارش نشد</div>';
 return ips.map(function(x){return '<div class="iptag"><span class="mono" style="direction:ltr;font-size:12.5px">'+esc(x.ip)+'</span><span class="tgs">'+ipChips(x)+'</span></div>'}).join('')}
var _rbSel={},_rbOv=null;
function openRebuildPicker(id){
 j('link-rebuild-info?id='+id).then(function(r){
  if(!r||!r.id){toast('اطلاعاتِ لینک در دسترس نیست','err');return}
  _rbSel={};var secs='';
  [['a','a_ip'],['b','b_ip']].forEach(function(pp){var side=r[pp[0]],key=pp[1];
   if(!side||!side.drifted)return;
   var free=(side.ips||[]).filter(function(x){return x.free})[0];
   _rbSel[key]=free?free.ip:(((side.ips||[])[0]||{}).ip||'');
   secs+='<div class="nd-sec">'+esc(side.node)+' — آی‌پیِ جدید</div><div class="rbsec">'+
     (side.ips&&side.ips.length?side.ips.map(function(x){return rbRow(key,x)}).join(''):'<div class="muted" style="font-size:12px;padding:4px 2px">آی‌پیِ قابلِ انتخابی نیست</div>')+'</div>'});
  if(!secs){toast('این تونل driftی ندارد','ok');refreshTunnels();return}
  var body='<div style="color:var(--sub);font-size:12px;margin-bottom:12px">آی‌پیِ قبلی دیگر روی نود نیست. آی‌پیِ جدیدِ این تونل را انتخاب کن — تگ‌ها نشان می‌دهند هر آی‌پی به کجا وصل است.</div>'+secs;
  _rbOv=openModal('<div class="msticky"><span class="medi">'+ic('redo')+'</span><div class="ttl"><h3>بازسازیِ تونل</h3><div class="sb">'+esc(r.name||'')+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+body+'</div><div class="mfoot"><button class="primary" onclick="doRebuildPick(\\''+id+'\\')">'+ic('redo')+'بازسازی</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>');
 }).catch(function(){toast('خطا در دریافتِ اطلاعات','err')})}
function rbRow(key,x){var sel=_rbSel[key]==x.ip;
 return '<div class="rbrow'+(sel?' sel':'')+'" data-ip="'+esc(x.ip)+'" onclick="rbPick(\\''+key+'\\',this)"><span class="rbdot"></span><span class="mono" style="direction:ltr;font-size:13px">'+esc(x.ip)+'</span><span class="rbtags">'+ipChips(x)+'</span></div>'}
function rbPick(key,row){_rbSel[key]=row.getAttribute('data-ip');
 var sec=row.closest('.rbsec')||row.parentNode;sec.querySelectorAll('.rbrow').forEach(function(r){r.classList.remove('sel')});
 row.classList.add('sel')}
async function doRebuildPick(id){var body={id:id};if(_rbSel.a_ip)body.a_ip=_rbSel.a_ip;if(_rbSel.b_ip)body.b_ip=_rbSel.b_ip;
 toast('در حال بازسازی…');
 var r=await post('rebuild-link',body);
 if(r.ok&&r.d.ok){toast('بازسازی شد','ok');if(_rbOv)closeModal(_rbOv);delete CHK[id];refreshTunnels()}
 else toast((r.d&&(r.d.error||r.d.msg))||'بازسازی ناموفق','err')}
async function delLink(id){if(!await confirmBox('این تونل روی هر دو نود حذف شود؟'))return;var r=await post('delete-link',{id:id});if(!r.d.ok&&r.d.msg)toast('حذف ناقص: '+r.d.msg,'err');delete CHK[id];editingId=null;refreshTunnels()}

// ===== Create
async function openCreateModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});selTargets={};
 if(on.length<2){toast('حداقل ۲ نودِ آنلاین لازم است','err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<label class="first">نودِ مبدأ</label>'+ssHTML('c_a',items,items[0].v,'نودِ مبدأ','fillTargets')+'<div id="c_srcip"></div><label>نوع تونل</label>'+ssHTML('c_type',TYPEITEMS,'vxlan','نوع','onCreateType')+'<label>نودِ مقصد (یک یا چند)</label><button type="button" class="msbtn ph" id="c_tgt_btn" onclick="toggleTgtList()"><span id="c_tgt_lbl">انتخابِ نودهای مقصد</span><span class="cv">⌄</span></button><div id="c_tgtips"></div><label>سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه، بدون تداخل)</label>'+ssHTML('c_snr',SUBNETRANGES,'192.168','رنج','onSubnetRange')+'<div id="c_snc_wrap" style="display:none"><label>سابنتِ دلخواه (فقط برای یک مقصد)</label><input id="c_subnet" placeholder="مثلا 192.168.99.0/24 یا fd00:99::/64"></div><div class="msg" id="c_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>افزودنِ تونل</h3><div class="sb">یک مبدأ + یک یا چند مقصد</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreate()">ساخت تونل</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>',{cls:'edit'});
 fillTargets()}
function onSubnetRange(){var w=el('c_snc_wrap');if(w)w.style.display=(ssVal('c_snr')=='custom')?'block':'none'}
function fillTargets(){selTargets={};updateTgt();renderSrcIp();renderTgtIps()}  // reset on source change; list builds on open
var _tgtOv=null;
function toggleTgtList(){var a=ssVal('c_a');var on=NODES.filter(function(n){return n.online&&n.id!=a});  // destination = multi-select popup
 var search=on.length>10?'<input class="search sspopq" placeholder="جستجو…" oninput="msFilter(this)" autocomplete="off">':'';
 var rows=on.length?on.map(function(n){return '<div class="msrow'+(selTargets[n.id]?' sel':'')+'" data-id="'+n.id+'" onclick="tgtToggle(\\''+n.id+'\\')"><span class="mscheck"></span><span>'+esc(n.name)+'</span><span class="muted mono" style="font-size:11px;margin-inline-start:auto">'+esc(n.host)+'</span></div>'}).join(''):'<div class="muted" style="padding:11px 12px">نودِ آنلاینِ دیگری نیست</div>';
 _tgtOv=openModal('<div class="sspop">'+search+'<div class="sspoplist" id="c_tgt_list">'+rows+'</div></div><div style="padding:10px 6px 2px"><button class="primary" style="width:100%" onclick="if(_tgtOv){closeModal(_tgtOv);_tgtOv=null}">تمام</button></div>',{cls:'sssheet'})}
function tgtToggle(id){if(selTargets[id])delete selTargets[id];else selTargets[id]=1;
 var row=document.querySelector('#c_tgt_list .msrow[data-id="'+id+'"]');if(row)row.classList.toggle('sel',!!selTargets[id]);updateTgt();renderTgtIps()}
function updateTgt(){var b=el('c_tgt_btn'),l=el('c_tgt_lbl');if(!l)return;var n=Object.keys(selTargets).length;
 l.textContent=n?(n+' نود انتخاب شده'):'انتخابِ نودهای مقصد';b.classList.toggle('ph',!n)}
function renderSrcIp(){var w=el('c_srcip');if(!w)return;var ips=nodeIps(ssVal('c_a'));
 w.innerHTML=ips.length>1?('<label>آی‌پیِ نودِ مبدأ (چند آی‌پی دارد — یکی را برای تونل انتخاب کن)</label>'+ssHTML('c_aip',ipItems(ips),(SEL['c_aip']&&ips.indexOf(SEL['c_aip'])>=0?SEL['c_aip']:ips[0]),'آی‌پی','')):''}
function renderTgtIps(){var w=el('c_tgtips');if(!w)return;var html='';Object.keys(selTargets).forEach(function(id){var ips=nodeIps(id);
 if(ips.length>1){var k='c_bip_'+id;html+='<label>آی‌پیِ مقصد «'+esc(nodeName(id))+'» (چند آی‌پی دارد)</label>'+ssHTML(k,ipItems(ips),(SEL[k]&&ips.indexOf(SEL[k])>=0?SEL[k]:ips[0]),'آی‌پی','')}});
 w.innerHTML=html}
function onCreateType(){var f=el('c_subnet');if(!f||!f.value.trim())return;var wantV6=(ssVal('c_type')=='sit');
 if((f.value.indexOf(':')>=0)!=wantV6)f.value=''}
function nodeName(id){var n=NODES.find(function(x){return x.id==id});return n?n.name:id}
async function doCreate(){var m=el('c_msg');m.className='msg';var a=ssVal('c_a');var tgts=Object.keys(selTargets);
 if(!tgts.length){m.className='msg err';m.textContent='حداقل یک نودِ مقصد انتخاب کن';return}
 var type=ssVal('c_type'),range=ssVal('c_snr'),custom=v('c_subnet'),aip=ssVal('c_aip'),okc=0,errs=[];
 if(range=='custom'&&tgts.length>1){m.className='msg err';m.textContent='سابنتِ دلخواه فقط برای یک مقصد است؛ برای چند مقصد یک رنجِ خودکار انتخاب کن';return}
 for(var i=0;i<tgts.length;i++){m.className='msg';m.textContent='در حال ساخت '+(i+1)+'/'+tgts.length+'…';
  var body={a_node:a,b_node:tgts[i],type:type,a_ip:aip,b_ip:ssVal('c_bip_'+tgts[i])};
  if(range=='custom')body.subnet=custom;else body.subnet_base=range;
  var r=await post('create-tunnel',body);
  if(r.ok&&r.d.ok)okc++;else errs.push(nodeName(tgts[i])+': '+(r.d.error||r.d.msg||'ناموفق'))}
 if(!errs.length){closeModal(m.closest('.modalov'));toast(okc+' تونل ساخته شد','ok')}else{m.className='msg err';m.textContent=okc+'/'+tgts.length+' — '+errs.join(' | ')}}

// ===== Port-forward
function portfwSkel(){el('view').innerHTML='<h1>'+ic('globe','var(--acc)')+' پورت‌فوروارد</h1><p class="sub">فوروارد پورت روی یک نود (با چرخشِ چند مقصد)</p>'+
 '<button class="primary" onclick="openPfAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+'افزودن پورت‌فوروارد</button>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' پورت‌فورواردهای فعال</div>'+toolbar('portfw','جستجوی نود / نام…')+'<div id="pfList"></div>'+pagerBottom('portfw');
 refreshPortfw()}
async function openPfAddModal(){var r=await j('node-names');var on=(r.nodes||[]).filter(function(n){return n.online});
 if(!on.length){toast('هیچ نودِ آنلاینی نیست','err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<label class="first">نود</label>'+ssHTML('pf_node',items,items[0].v,'نود','')+'<div class="grid2"><div><label>پورتِ ورودی</label><input id="pf_lp" placeholder="8080"></div><div><label>پورتِ مقصد</label><input id="pf_dp" placeholder="443"></div></div><label>آی‌پی(های) مقصد — با کاما جدا کن</label><input id="pf_ips" placeholder="10.0.0.1, 10.0.0.2"><label>چرخش هر (دقیقه) — اگر چند آی‌پی دادی</label><input id="pf_int" placeholder="5"><div class="msg" id="pf_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>افزودنِ پورت‌فوروارد</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doPortfw()">افزودن</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
async function refreshPortfw(){if(editingId)return;var box=el('pfList');if(!box)return;var r=await j('portfw-list?offset='+(PG.portfw*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.portfw));PF=(r.portfw||[]).filter(function(x){return x.name});TOT.portfw=num(r.total);
 setHTML(box,PF.length?PF.map(pfCard).join(''):'<div class="card muted">'+(QRY.portfw?'موردی یافت نشد.':'پورت‌فورواردی نیست.')+'</div>');renderPager('portfw')}
function pfCard(p,i){var h=p.health||{};
 var st=h.rule?(h.reachable?'<span class="badge ok">فعال · مقصد'+CK+'</span>':'<span class="badge bad">قانون'+CK+' · مقصد'+XK+'</span>'):'<span class="badge bad">غیرفعال</span>';
 var rotOn=p.switch_interval>0,multi=(p.dst_ips||[]).length>1;
 var head='<div class="link"><span class="name">'+esc(p.node)+'</span><span class="grow"></span><span class="tag" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 40%,transparent)">portfw</span>'+st+'</div>';
 var live=(multi&&h.active)?'<div class="pfrow">هم‌اکنون روی: <b class="mono" id="pfact_'+i+'" style="color:var(--ok)">'+esc(h.active)+'</b></div>':'';
 var body='<div class="pfcols"><div class="pfcol">'+
   '<div class="pfrow">اینترفیس: <b class="mono">'+esc(p.iface)+'</b></div>'+
   '<div class="pfrow">پورتِ ورودی: <b>'+esc(p.listen_port)+'</b></div>'+
   '<div class="pfrow">پورتِ مقصد: <b>'+esc(p.dst_port)+'</b></div>'+
  '</div><div class="pfcol">'+
   '<div class="pfrow">مقصدها: <b class="mono">'+esc((p.dst_ips||[]).join('، '))+'</b></div>'+
   live+
   '<div class="pfrow">چرخش: <b>'+(rotOn?((p.switch_interval/60)+' دقیقه'):'خاموش')+'</b></div>'+
  '</div></div>';
 var acts='<div class="nact iconly">'+((multi&&h.active)?'<button class="act" title="چرخش الان" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 46%,transparent)" onclick="pfNext('+i+')">'+ic('redo')+'</button>':'')+'<button class="act warn" title="ویرایش" onclick="openPfEdit('+i+')">'+ic('pen')+'</button><button class="act danger" title="حذف" onclick="delPf('+i+')">'+ic('trash')+'</button></div>';
 return '<div class="card">'+head+body+acts+'</div>'}
function pfTgl(i){var sw=el('pe_tgl_'+i),on=!sw.classList.contains('on');sw.classList.toggle('on',on);
 setT('pe_tgllbl_'+i,on?'روشن':'خاموش');var w=el('pe_intwrap_'+i);if(w)w.style.display=on?'block':'none'}
async function savePfEdit(i){var p=PF[i];if(!p)return;var m=el('pem_'+i);var lp=v('pe_lp_'+i),dp=v('pe_dp_'+i),ips=v('pe_ips_'+i);
 if(!lp||!dp||!ips){m.className='msg err';m.textContent='پورت‌ها و آی‌پیِ مقصد لازم است';return}
 var rot=el('pe_tgl_'+i).classList.contains('on'),intv=v('pe_int_'+i);
 m.className='msg';m.textContent='در حال ذخیره…';
 var r=await post('portfw-edit',{node:p.node_id,name:p.name,listen_port:lp,dst_port:dp,dst_ips:ips,rotate:rot,interval_min:intv||5});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=r.d.error||r.d.msg||'ناموفق'}}
async function doPortfw(){var m=el('pf_msg');var node=ssVal('pf_node'),lp=v('pf_lp'),dp=v('pf_dp'),ips=v('pf_ips'),intv=v('pf_int');
 if(!node||!lp||!dp||!ips){m.className='msg err';m.textContent='نود، پورتِ ورودی/مقصد و آی‌پی لازم است';return}
 m.className='msg';m.textContent='در حال ساخت…';
 var r=await post('portfw',{node:node,listen_port:lp,dst_port:dp,dst_ips:ips,interval_min:intv||5});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast('پورت‌فوروارد ساخته شد: '+r.d.name,'ok')}
 else{m.className='msg err';m.textContent=r.d.error||'ناموفق'}}
async function pfNext(i){var p=PF[i];if(!p)return;var b=el('pfact_'+i),old=b?b.textContent:'';if(b)b.textContent='…';
 var r=await post('portfw-next',{node:p.node_id,name:p.name});
 if(r.ok&&r.d.ok){if(b)b.textContent=r.d.active;toast('چرخش انجام شد ← '+r.d.active,'ok')}
 else{if(b)b.textContent=old;toast((r.d&&(r.d.error||r.d.msg))||'چرخش ناموفق','err')}}
async function delPf(i){var p=PF[i];if(!p)return;if(!await confirmBox('این پورت‌فوروارد حذف شود؟'))return;await post('portfw-del',{node:p.node_id,name:p.name});editingId=null;refreshPortfw()}

// ===== agent push-update page =====
function agentBody(){return ''+
 '<div class="card" id="ag_stored" style="margin-bottom:12px"></div>'+
 '<div class="card" style="margin-bottom:12px"><div class="k"><span class="chip" style="--hue:#34d399">'+ic('plus','#34d399')+'</span> بارگذاریِ ایجنتِ جدید</div>'+
  '<input type="file" id="ag_file" accept=".py" style="display:none" onchange="agPick(this)">'+
  '<div class="drop" id="ag_drop" onclick="el(\\'ag_file\\').click()">فایلِ <b>tnl-node.py</b> را انتخاب کن — قبل از ذخیره صحتِ کد بررسی می‌شود</div>'+
  '<textarea id="ag_paste" placeholder="یا کدِ ایجنت را اینجا پیست کن…" style="display:none;width:100%;height:120px;margin-top:10px;padding:11px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-family:ui-monospace,monospace;font-size:12px;direction:ltr"></textarea>'+
  '<div style="display:flex;gap:9px;margin-top:12px;align-items:center"><button class="primary" onclick="agUpload()">بارگذاری و ذخیره</button><button class="ghost" onclick="agTogglePaste()">پیستِ کد</button></div><div class="msg" id="ag_msg"></div></div>'+
 '<div class="sec">'+ic('server','var(--acc)')+' نودهای فلیت</div>'+
 '<div class="toolbar"><input id="q_agent" class="search" placeholder="جستجوی نود…" oninput="onSearch(\\'agent\\')"><button class="primary" onclick="agPush(\\'all\\')">بروزرسانیِ همه</button></div>'+
 '<div id="agList"></div>'+pagerBottom('agent')}
function agentSkel(){el('view').innerHTML='<h1>'+ic('redo','var(--acc)')+' بروزرسانیِ ایجنت</h1><p class="sub">آپدیت و ری‌استارتِ ایجنتِ نودها از پنل، بدونِ SSH</p>'+agentBody();refreshAgent()}
async function refreshAgent(){var info=await j('agent-info').catch(function(){return{none:true}});AGMETA=info;
 var sb=el('ag_stored');if(sb)sb.innerHTML=(info&&!info.none)?
  '<div class="banner"><span class="chip">'+ic('cpu')+'</span><div><div class="v">ایجنتِ ذخیره‌شده: v'+num(info.version)+' · <span class="mono">'+esc(String(info.sha256||'').slice(0,12))+'</span></div><div class="muted" style="font-size:11.5px">'+Math.round(num(info.size)/1024)+' کیلوبایت</div></div><span class="grow"></span><span class="badge ok">آمادهٔ پوش</span></div>'
  :'<div class="emptybox"><div class="ei">'+ic('redo')+'</div><h3>هنوز ایجنتی بارگذاری نشده</h3><p>فایلِ tnl-node.py را بالا بارگذاری کن تا قابلِ پوش شود</p></div>';
 var box=el('agList');if(!box)return;
 var r=await j('nodes?offset='+(PG.agent*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.agent));var nodes=r.nodes||[];TOT.agent=num(r.total);
 box.innerHTML=nodes.length?nodes.map(agRow).join(''):'<div class="card muted">موردی نیست</div>';renderPager('agent')}
function agRow(n){var i=n.info||{};var ver=i.version?('v'+num(i.version)):'—';var st,dis;
 if(!n.online){st='<span class="badge na">آفلاین</span>';dis=1}
 else if(AGMETA&&!AGMETA.none&&i.sha256===AGMETA.sha256){st='<span class="badge ok">به‌روز</span>';dis=1}
 else if(AGMETA&&!AGMETA.none){st='<span class="badge warn">نیازمند بروزرسانی</span>';dis=0}
 else{st='';dis=1}
 return '<div class="agrow"><span class="ndot '+(n.online?'on':'off')+'"></span><span class="name">'+esc(n.name)+'</span><span class="ver mono">'+ver+'</span>'+st+'<span class="grow"></span><button class="act info"'+(dis?' disabled':'')+' onclick="agPush(\\''+n.id+'\\')">'+ic('redo')+'بروزرسانی</button><div class="msg agres" id="agres_'+n.id+'"></div></div>'}
function agPick(inp){var f=inp.files&&inp.files[0];if(!f)return;var rd=new FileReader();rd.onload=function(){window._agCode=rd.result;var d=el('ag_drop');if(d)d.innerHTML='فایل انتخاب شد: <b>'+esc(f.name)+'</b> · '+Math.round(f.size/1024)+'KB — حالا «بارگذاری و ذخیره» را بزن'};rd.readAsText(f)}
function agTogglePaste(){var t=el('ag_paste');if(t)t.style.display=(t.style.display=='none')?'block':'none'}
async function agUpload(){var m=el('ag_msg');var code=window._agCode||v('ag_paste');
 if(!code||!code.trim()){m.className='msg err';m.textContent='اول فایل را انتخاب یا کد را پیست کن';return}
 m.className='msg';m.textContent='در حال بررسی و ذخیره…';
 var r=await post('agent-upload',{code:code});
 if(r.ok&&r.d.ok){m.className='msg ok';m.textContent='ذخیره شد: v'+r.d.version+' · '+r.d.sha256;window._agCode=null;refreshAgent()}
 else{m.className='msg err';m.textContent=r.d.error||'ناموفق'}}
async function agPush(target){if(!AGMETA||AGMETA.none){toast('اول یک ایجنت بارگذاری کن','err');return}
 var ids;
 if(target=='all'){var r=await j('node-names');ids=(r.nodes||[]).filter(function(n){return n.online}).map(function(n){return n.id});
  if(!ids.length){toast('نودِ آنلاینی نیست','err');return}
  if(!await confirmBox('ایجنت روی '+ids.length+' نودِ آنلاین آپدیت و ری‌استارت شود؟','بله، همه'))return}
 else{ids=[target];var mm=el('agres_'+target);if(mm){mm.className='msg agres';mm.textContent='در حال ارسال…'}}
 var res=await post('agent-push',{ids:ids});var rs=(res.d&&res.d.results)||[];var ok=0;
 rs.forEach(function(x){var m=el('agres_'+x.id);
  if(x.ok&&x.already){ok++;if(m){m.className='msg agres ok';m.innerHTML='از قبل به‌روز'+CK}}
  else if(x.ok){ok++;if(m){m.className='msg agres ok';m.innerHTML='به‌روز شد'+CK+' · در حال ری‌استارت…'}}
  else if(x.offline){if(m){m.className='msg agres';m.textContent='آفلاین — رد شد'}}
  else{if(m){m.className='msg agres err';m.textContent='ناموفق: '+(x.error||'')}}});
 if(target=='all')toast(ok+'/'+rs.length+' نود بروزرسانی شد',ok?'ok':'err');
 setTimeout(function(){if(cur=='agent'||cur=='settings')refreshAgent()},4500)}
function refresh(){var p;if(cur=='overview')p=refreshOverview();else if(cur=='nodes')p=refreshNodes();else if(cur=='tunnels')p=refreshTunnels();else if(cur=='portfw')p=refreshPortfw();else if(cur=='agent')p=refreshAgent();else if(cur=='settings'&&el('agList'))p=refreshAgent();return Promise.resolve(p)}
function render(){setnav();editingId=null;
 if(cur=='overview')overviewSkel();else if(cur=='nodes')nodesSkel();else if(cur=='tunnels')tunnelsSkel();else if(cur=='portfw'){portfwSkel();return}else if(cur=='agent'){agentSkel();return}else if(cur=='settings'){settingsSkel();refreshSettings();return}
 refresh()}
// ===== settings (loaded once on nav; NOT re-fetched on the 6s tick so the form is never clobbered mid-edit) =====
function settingsSkel(){el('view').innerHTML='<h1>'+ic('cog','var(--acc)')+' تنظیمات</h1><p class="sub">رفتار خودکارِ پنل و بازه‌های بررسی</p><div id="setBox"><div class="card muted">در حال بارگذاری…</div></div>'}
var _setMode='alert',_modeOv=null;
function modeLabel(m){return m=='auto'?'خودکار':'هشدار'}
async function refreshSettings(){var s=await j('settings').catch(function(){return{}});var box=el('setBox');if(!box)return;
 _setMode=(s.reconcile_mode=='auto')?'auto':'alert';
 var row=function(t,d,ctl){return '<div style="display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap;padding:12px 0;border-bottom:1px solid var(--bord)"><div style="min-width:190px"><b>'+t+'</b><div class="muted" style="font-size:12px;margin-top:3px">'+d+'</div></div><div style="min-width:200px;flex:0 0 auto">'+ctl+'</div></div>'};
 box.innerHTML='<div class="card">'+
  row('وقتی آی‌پیِ نود عوض شد','روی این بزن تا انتخاب کنی','<button type="button" class="setfield" onclick="openModePopup()"><span class="val" id="set_mode_val">'+modeLabel(_setMode)+'</span><span class="cv">▾</span></button>')+
  row('بازهٔ بررسیِ ترمیم (ثانیه)','۵ تا ۳۶۰۰','<input id="set_rec" class="search" type="number" min="5" max="3600" value="'+(num(s.reconcile_interval)||15)+'">')+
  row('بازهٔ پایشِ فلیت (ثانیه)','۱ تا ۶۰','<input id="set_poll" class="search" type="number" min="1" max="60" value="'+(num(s.poll_interval)||2)+'">')+
  '<div class="tbtnrow" style="margin:14px 0 0;align-items:center"><button class="primary" onclick="saveSettings()">'+ic('check')+'ذخیره</button><span class="msg" id="set_msg" style="align-self:center"></span></div>'+
  '</div>'+
  '<div class="sec" style="margin-top:8px">'+ic('redo','var(--acc)')+' بروزرسانیِ ایجنت</div>'+agentBody();
 refreshAgent()}
function openModePopup(){var opt=function(m,df){return '<div class="mopt'+(_setMode==m?' on':'')+'" onclick="pickMode(\\''+m+'\\')"><span class="mrad"></span><span class="mt">'+modeLabel(m)+'</span>'+(df?'<span class="mdf">پیش‌فرض</span>':'')+'</div>'};
 _modeOv=openModal('<div class="modelist">'+opt('auto',false)+opt('alert',true)+'</div>',{cls:'modesheet'})}
function pickMode(m){_setMode=m;setT('set_mode_val',modeLabel(m));if(_modeOv){closeModal(_modeOv);_modeOv=null}}
async function saveSettings(){var m=el('set_msg');if(m){m.className='msg';m.textContent='در حال ذخیره…'}
 var r=await post('settings-set',{reconcile_mode:_setMode,reconcile_interval:v('set_rec'),poll_interval:v('set_poll')});
 if(r.ok&&r.d.ok){if(m){m.className='msg';m.textContent=''}toast('تنظیمات ذخیره شد','ok')}
 else{if(m){m.className='msg err';m.textContent=(r.d&&(r.d.error||r.d.msg))||'ناموفق'}}}
function tick(){if(document.hidden){clearTimeout(TT);TT=setTimeout(tick,6000);return}  // don't burn cycles (or queue work) while the tab is hidden
 updateSidebar();refresh().catch(function(){}).then(function(){clearTimeout(TT);TT=setTimeout(tick,6000)})}
document.addEventListener('visibilitychange',function(){if(!document.hidden){clearTimeout(TT);tick()}});
// ===== command palette (Ctrl+K) =====
document.addEventListener('keydown',function(e){if(!((e.ctrlKey||e.metaKey)&&(e.key=='k'||e.key=='K')))return;
 if(PAL){e.preventDefault();closePal();return}
 var tn=e.target&&e.target.tagName;
 if(tn=='INPUT'||tn=='SELECT'||tn=='TEXTAREA'||document.querySelector('.modalov'))return;  // don't hijack typing or stack over an open modal
 e.preventDefault();openPal()});
function openPal(){if(PAL)return;var ov=document.createElement('div');ov.className='modalov palov';
 ov.innerHTML='<div class="pal"><div class="palin">'+ic('search')+'<input id="pal_q" placeholder="جستجوی نود، تونل یا دستور…" autocomplete="off"><kbd>Esc</kbd></div><div class="pallist" id="pal_list"></div><div class="palfoot"><span><kbd>↑</kbd><kbd>↓</kbd> حرکت</span><span><kbd>↵</kbd> انتخاب</span><span><kbd>Esc</kbd> بستن</span></div></div>';
 document.body.appendChild(ov);PAL=ov;editingId='pal';try{document.body.style.overflow='hidden'}catch(e){}
 ov.addEventListener('mousedown',function(e){if(e.target===ov)closePal()});
 var inp=el('pal_q');inp.addEventListener('input',function(){palRender(inp.value)});inp.addEventListener('keydown',palKey);
 PALDATA={nodes:[],tuns:[]};
 j('node-names').then(function(r){PALDATA.nodes=r.nodes||[];palRender(inp.value)}).catch(function(){});
 j('fleet?limit=100').then(function(r){PALDATA.tuns=r.links||[];palRender(inp.value)}).catch(function(){});
 palRender('');inp.focus()}
function closePal(){if(!PAL)return;PAL.remove();PAL=null;editingId=null;try{if(!document.querySelector('.modalov'))document.body.style.overflow=''}catch(e){}}
function palNav(p){cur=p;closePal();render()}
function palActions(){return [
 {i:'dash',label:'نمای کلی',act:function(){palNav('overview')}},{i:'server',label:'نودها',act:function(){palNav('nodes')}},
 {i:'link',label:'تونل‌ها',act:function(){palNav('tunnels')}},{i:'globe',label:'پورت‌فوروارد',act:function(){palNav('portfw')}},
 {i:'plus',label:'افزودن تونل',act:function(){cur='tunnels';closePal();render();setTimeout(openCreateModal,300)}},{i:'redo',label:'بروزرسانیِ ایجنت',act:function(){palNav('agent')}},
 {i:'activity',label:'تستِ همهٔ تونل‌های صفحه',act:function(){cur='tunnels';closePal();render();setTimeout(function(){if(window.checkAll)checkAll()},600)}},
 {i:document.body.classList.contains('dark')?'sun':'moon',label:'تغییرِ تمِ روشن/تیره',act:function(){closePal();toggleTheme()}}]}
function palRender(q){q=(q||'').trim().toLowerCase();
 var nodes=(PALDATA.nodes||[]).filter(function(n){return !q||n.name.toLowerCase().indexOf(q)>=0||(n.host||'').indexOf(q)>=0}).slice(0,6)
  .map(function(n){return {i:'server',label:esc(n.name),sub:esc(n.host),act:function(){cur='nodes';QRY.nodes=n.name;PG.nodes=0;closePal();render()}}});
 var tuns=(PALDATA.tuns||[]).filter(function(l){return !q||((l.a_name||'')+' '+(l.b_name||'')+' '+(l.name||'')+' '+(l.type||'')).toLowerCase().indexOf(q)>=0}).slice(0,6)
  .map(function(l){return {i:'link',label:esc(l.a_name)+' ↔ '+esc(l.b_name),sub:esc(l.name),act:function(){cur='tunnels';QRY.tunnels=l.name;PG.tunnels=0;closePal();render()}}});
 var acts=palActions().filter(function(a){return !q||a.label.toLowerCase().indexOf(q)>=0});
 var groups=[['نودها',nodes],['تونل‌ها',tuns],['دستورها',acts]];PALITEMS=[];var html='';
 groups.forEach(function(g){if(!g[1].length)return;html+='<div class="palsec">'+g[0]+'</div>';
  g[1].forEach(function(it){var idx=PALITEMS.length;PALITEMS.push(it);
   html+='<div class="palrow" onmouseenter="PALIDX='+idx+';palHi()" onclick="palGo('+idx+')"><span class="gi">'+ic(it.i)+'</span>'+it.label+(it.sub?'<span class="sub mono">'+it.sub+'</span>':'')+'</div>'})});
 if(!PALITEMS.length)html='<div class="palrow" style="cursor:default;color:var(--sub)">موردی یافت نشد</div>';
 var lst=el('pal_list');if(lst)lst.innerHTML=html;PALIDX=0;palHi()}
function palHi(){document.querySelectorAll('#pal_list .palrow').forEach(function(r,i){r.classList.toggle('sel',i==PALIDX)})}
function palGo(i){var it=PALITEMS[i];if(it&&it.act)it.act()}
function palKey(e){if(e.key=='ArrowDown'){e.preventDefault();PALIDX=Math.min(PALIDX+1,PALITEMS.length-1);palHi();palSc()}
 else if(e.key=='ArrowUp'){e.preventDefault();PALIDX=Math.max(PALIDX-1,0);palHi();palSc()}
 else if(e.key=='Enter'){e.preventDefault();palGo(PALIDX)}else if(e.key=='Escape'){e.preventDefault();closePal()}}
function palSc(){var r=document.querySelectorAll('#pal_list .palrow')[PALIDX];if(r)r.scrollIntoView({block:'nearest'})}
render();updateSidebar();TT=setTimeout(tick,6000);
</script></body></html>"""

# ----------------------------------------------------------------------------- install / main

SERVICE = "tnl-central.service"


def svc(*a):
    subprocess.run(["systemctl", *a, SERVICE])


def service_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", SERVICE]).returncode == 0


def central_ip():
    r = subprocess.run(["bash", "-c", "ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1"],
                       capture_output=True, text=True)
    return r.stdout.strip() or "central-ip"


def set_password(conf):
    conf["user"] = input(f"Username [{conf.get('user', 'admin')}]: ").strip() or conf.get("user", "admin")
    while True:
        p1, p2 = getpass.getpass("Password: "), getpass.getpass("Repeat: ")
        if p1 and p1 == p2:
            break
        print("  empty or mismatch, try again.")
    salt, h = hash_password(p1)
    conf["salt"], conf["hash"] = salt, h
    conf["secret"] = secrets.token_hex(32)   # rotate the signing secret on every password change → invalidates all outstanding sessions
    conf.setdefault("port", 8080)
    save_json(WEB_CONF, conf)


def write_service():
    with open(SERVICE_FILE, "w") as f:
        f.write(f"""[Unit]
Description=tnl central panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env python3 {INSTALLED} --serve
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
""")
    subprocess.run(["systemctl", "daemon-reload"])


def do_install():
    os.makedirs(CENTRAL_DIR, exist_ok=True)
    os.chmod(CENTRAL_DIR, 0o700)
    if os.path.realpath(SELF_PATH) != INSTALLED:  # copy to a stable path so the unit never breaks if moved
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
    conf = load_conf() if os.path.isfile(WEB_CONF) else {}
    conf["port"] = int(input(f"Panel port [{conf.get('port', 8080)}]: ").strip() or conf.get("port", 8080))
    set_password(conf)
    write_service()
    svc("enable")
    svc("restart")
    print("[✔] tnl-central installed and started.")
    print(f"[→] open  http://{central_ip()}:{conf['port']}/   (user: {conf.get('user')})")


def change_port():
    if not os.path.isfile(WEB_CONF):
        print("Not configured yet - run Install first.")
        return
    conf = load_conf()
    p = input(f"New panel port [{conf.get('port', 8080)}]: ").strip()
    if not p:
        return
    conf["port"] = int(p)
    save_json(WEB_CONF, conf)
    if os.path.isfile(SERVICE_FILE):
        svc("restart")
    print(f"[✔] port set to {conf['port']} — open http://{central_ip()}:{conf['port']}/")


def change_password():
    if not os.path.isfile(WEB_CONF):
        print("Not configured yet - run Install first.")
        return
    set_password(load_conf())
    if os.path.isfile(SERVICE_FILE):
        svc("restart")
    print("[✔] password updated.")


def uninstall():
    if input("Uninstall the central panel? [y/N]: ").strip().lower() != "y":
        return
    svc("stop")
    svc("disable")
    try:
        os.remove(SERVICE_FILE)
    except FileNotFoundError:
        pass
    subprocess.run(["systemctl", "daemon-reload"])
    print(f"[✔] service removed (node registry & links kept in {CENTRAL_DIR}).")


def do_restart():
    if not os.path.isfile(SERVICE_FILE):
        print("Not installed yet - run Install first.")
        return
    print("[*] restarting the panel...")
    svc("restart")
    print("[✔] restarted, panel active." if service_active()
          else "[!] restarted but not active - check Status / logs.")


def status():
    exists = os.path.isfile(SERVICE_FILE)
    conf = load_conf() if os.path.isfile(WEB_CONF) else {}
    print()
    print(f"  service : {'active' if service_active() else ('installed, stopped' if exists else 'not installed')}")
    print(f"  url     : http://{central_ip()}:{conf.get('port', '-')}/")
    print(f"  user    : {conf.get('user', '-')}")
    print(f"  nodes   : {len(load_nodes())}")
    print(f"  links   : {len(load_links())}")
    print()


def menu():
    if os.geteuid() != 0:
        print("Run as root (sudo).")
        sys.exit(1)
    os.makedirs(CENTRAL_DIR, exist_ok=True)
    while True:
        exists = os.path.isfile(SERVICE_FILE)
        st = "active" if service_active() else ("stopped" if exists else "not installed")
        print(f"\n=== tnl-central . control plane   [{st}] ===")
        print("  1) Install / reinstall")
        print("  2) Show URL")
        print("  3) Restart service (apply an updated file)")
        print("  4) Change port")
        print("  5) Change password")
        print("  6) Status")
        print("  7) Uninstall")
        print("  8) Exit")
        c = input("choice: ").strip()
        try:
            if c == "1":
                do_install()
            elif c == "2":
                conf = load_conf() if os.path.isfile(WEB_CONF) else {}
                print(f"  http://{central_ip()}:{conf.get('port', 8080)}/")
            elif c == "3":
                do_restart()
            elif c == "4":
                change_port()
            elif c == "5":
                change_password()
            elif c == "6":
                status()
            elif c == "7":
                uninstall()
            elif c == "8":
                break
            else:
                print("invalid.")
        except Exception as e:
            print(f"[!] {e}")


def serve():
    if not os.path.isfile(WEB_CONF):
        print("Not configured. Run the setup menu:  sudo python3 tnl-central.py")
        sys.exit(1)
    conf = load_conf()
    global _CENTRAL_PORT
    _CENTRAL_PORT = int(conf.get("port", 8080))  # advertised to nodes so they can call back /api/checkin
    _seed_settings()  # load settings.json into memory (defaults if absent) for the loops
    _tf_load()  # restore lifetime traffic totals from disk so they survive a central restart
    threading.Thread(target=poller_loop, daemon=True).start()  # warm the fleet cache in the background
    threading.Thread(target=traffic_persist_loop, daemon=True).start()  # flush traffic totals every 60s
    threading.Thread(target=reconcile_loop, daemon=True).start()  # heal peer remote_ip after a node's IP changes
    httpd = ThreadingHTTPServer(("0.0.0.0", int(conf.get("port", 8080))), Handler)
    httpd.conf = conf
    print(f"tnl-central on http://0.0.0.0:{conf.get('port', 8080)}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--serve":
        serve()
    elif arg == "--install":
        if os.geteuid() != 0:
            print("Run as root (sudo).")
            sys.exit(1)
        do_install()
    elif arg == "--set-pass":
        if os.geteuid() != 0:
            print("Run as root (sudo).")
            sys.exit(1)
        change_password()
    else:
        menu()


if __name__ == "__main__":
    main()
