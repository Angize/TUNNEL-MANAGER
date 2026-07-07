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
import tempfile
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
UPTIME_FILE = os.path.join(CENTRAL_DIR, "uptime.json")     # persisted per-minute up/down history so the bar survives restarts
AGENT_FILE = os.path.join(CENTRAL_DIR, "agent.py")          # the node-agent source the operator uploaded, pushed to nodes
AGENT_META = os.path.join(CENTRAL_DIR, "agent.meta.json")   # {version, sha256, size, uploaded_ts}
CORE_BLOB = os.path.join(CENTRAL_DIR, "core.bin")        # a custom core binary the operator uploaded, pushed to nodes
CORE_BLOB_META = os.path.join(CENTRAL_DIR, "core.meta.json")  # {sha256, size, name, uploaded_ts}
SERVICE_FILE = "/etc/systemd/system/tnl-central.service"
SELF_PATH = os.path.realpath(__file__)
INSTALLED = os.path.join(CENTRAL_DIR, "tnl-central.py")  # stable path the systemd unit points at

SESSION_TTL = 8 * 3600
PBKDF2_ITERS = 150_000
TYPES = ("vxlan", "gre", "sit", "ipip", "l2tpv3", "fou", "ipsec", "core")
IPIP_FAMILY = ("ipip", "fou")  # both are proto-4 ipip tunnels keyed only by (local,remote) — one per ip-pair
# Ciphers the custom core accepts (see TUNNEL-MANAGER-CORE). "auto" resolves core-side to a fixed
# choice so both ends match; "none" disables encryption. Kept in sync with the core's crypto factory.
CORE_CIPHERS = ("auto", "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "xchacha20-poly1305", "none")
CORE_RAW_PROFILES = ("bip", "ipip", "gre", "icmp", "udp", "tcp")   # raw-transport encapsulation profiles
_reg_lock = threading.Lock()     # serialize every nodes.json / links.json read-modify-write
_agent_lock = threading.Lock()   # serialize agent.py + agent.meta.json writes so they never tear apart
_core_blob_lock = threading.Lock()   # serialize the custom core binary + its meta writes
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
        "uptime_window": 1,         # uptime-bar span in hours (1/3/6/8/12/24); always 60 cells, each = window/60
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
    if "uptime_window" in d and d["uptime_window"] not in (None, ""):
        w = int(d["uptime_window"])
        out["uptime_window"] = w if w in (1, 3, 6, 8, 12, 24) else 1
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
    try:  # close the connected socket on any handshake failure instead of leaking it to GC
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
    except Exception:
        s.close()
        raise


def _http_connect_socket(ph, pp, pu, pw, dh, dp, timeout):
    """Open a socket to dh:dp through an HTTP CONNECT proxy."""
    s = socket.create_connection((ph, pp), timeout)
    try:  # close the connected socket on any handshake failure instead of leaking it to GC
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
    except Exception:
        s.close()
        raise


def _node_call_proxied(node, proxy, endpoint, method, body, timeout):
    dh, dp = node["host"], int(node["port"])
    pu = urllib.parse.urlparse(proxy if "://" in proxy else "socks5://" + proxy)
    scheme = (pu.scheme or "socks5").lower()
    if not pu.hostname or not pu.port:
        return {"ok": False, "offline": True, "error": "bad proxy address"}
    sock = None
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
        sock = None  # conn.close() closed the tunneled socket; nothing left to clean up
        try:
            return json.loads(raw.decode())
        except Exception:
            return {"ok": False, "error": f"HTTP {r.status}"}
    except Exception as e:
        return {"ok": False, "offline": True, "error": ("proxy: " + str(e).split("] ")[-1])[:90]}
    finally:
        if sock is not None:  # request/response raised after the tunnel was up -> close the fd, don't lean on GC
            try:
                sock.close()
            except Exception:
                pass


_SIGN_KEY = None


def _signing_keys():
    """Ensure the panel's RSA update-signing keypair exists in the config dir; return (priv_path, pub_pem).
    The private key (600, panel-only) signs update / core-install payloads; nodes hold only the public key
    and verify with it — so a stolen node token can no longer authorize a malicious root-code push."""
    global _SIGN_KEY
    if _SIGN_KEY:
        return _SIGN_KEY
    priv = os.path.join(CENTRAL_DIR, "sign_key.pem")
    if not os.path.isfile(priv):
        subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], check=True, capture_output=True)
        os.chmod(priv, 0o600)
    pub = subprocess.run(["openssl", "rsa", "-in", priv, "-pubout"], check=True, capture_output=True).stdout.decode()
    _SIGN_KEY = (priv, pub)
    return _SIGN_KEY


def _sign_sha(sha_hex):
    """RSA-SHA256 signature (base64) over the sha256 hex string a code push carries; '' if unavailable
    (an unprovisioned node ignores it; a provisioned node then rejects the unsigned push, fail-closed)."""
    try:
        priv, _ = _signing_keys()
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv],
                             input=str(sha_hex).encode(), check=True, capture_output=True).stdout
        return base64.b64encode(sig).decode()
    except Exception:
        return ""


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
            out = json.loads(r.read().decode())
            return out if isinstance(out, dict) else {"ok": False, "error": "non-dict node response"}
    except urllib.error.HTTPError as e:
        try:
            out = json.loads(e.read().decode())
            return out if isinstance(out, dict) else {"ok": False, "error": f"HTTP {e.code}"}
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
_uh = {}                   # node_id -> {"ring":[1/0,...], "bts":ts, "dn":bool} — rolling per-minute up/down history
_uh_lock = threading.Lock()
UPTIME_BUCKET = 60         # seconds per uptime sample (one minute; a bucket is DOWN if unreachable any time in it)
UPTIME_KEEP = 1440         # ring length -> 24h of per-minute history (aggregated to 60 cells for display)
_tomb = {}                 # node_id -> expiry ts: a node deleted mid-poll must not have its cache resurrected
_tomb_lock = threading.Lock()


def _cache_get(nid):
    with _pc_lock:
        e = _pc.get(nid)
        return dict(e) if e else None


def _poll_node(n):
    ping = node_call(n, "ping", "GET", timeout=6)
    lst = node_call(n, "list", "GET", timeout=12)
    now = time.time()
    with _tomb_lock:  # node deleted while this poll was in flight? don't resurrect its cache/traffic/uptime
        exp = _tomb.get(n["id"])
        if exp and now < exp:
            return
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
    inflight = set()            # node ids whose poll from a previous sweep hasn't finished yet
    inflight_lock = threading.Lock()

    def _run(n):
        try:
            _poll_node(n)
        finally:
            with inflight_lock:
                inflight.discard(n["id"])

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
            with _tomb_lock:  # expire delete-tombstones (their in-flight poll has long finished)
                for nid in [k for k, exp in _tomb.items() if time.time() > exp]:
                    _tomb.pop(nid, None)
            with _node_locks_guard:  # drop per-node build locks for removed nodes (skip any currently held)
                for nid in [k for k in _node_locks if k not in valid]:
                    lk = _node_locks.get(nid)
                    if lk is not None and not lk.locked():
                        _node_locks.pop(nid, None)
            if nodes:
                # Only submit nodes that aren't still being polled from an earlier
                # sweep. Otherwise a fleet of slow/unreachable nodes would pile a
                # fresh copy of every node onto the (unbounded) work queue each
                # sweep — growing memory and starving fresh submissions behind old
                # ones exactly during an outage. Skipping in-flight nodes bounds the
                # queue to at most one poll per node.
                with inflight_lock:
                    todo = [n for n in nodes if n["id"] not in inflight]
                    inflight.update(n["id"] for n in todo)
                # submit the batch, then move on after the deadline — one trickling node can't freeze the fleet
                futures_wait([ex.submit(_run, n) for n in todo], timeout=SWEEP_DEADLINE)
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

TF_IF_MAX = 512            # max interfaces tracked per node — a compromised node must not grow this map unbounded
TF_IF_KEY_MAX = 32         # max interface-name length stored (Linux ifname is <=15; slack for exotic names)
TF_CTR_CEIL = 1 << 64      # /proc counters are uint64 — reject implausibly large values (bigint-accumulation DoS)
TF_IF_PRUNE_MISSES = 15    # prune an iface not reported for this many consecutive sweeps


def _tf_valid_key(key):
    return (isinstance(key, str) and 1 <= len(key) <= TF_IF_KEY_MAX
            and re.match(r"^[A-Za-z0-9_.@:-]+$", key) is not None)


def _tf_ingest(nid, net, up, now):
    if not isinstance(net, dict):
        return
    with _tf_lock:
        e = _tf.get(nid)
        if e is None:
            e = _tf[nid] = {"prev_ts": 0.0, "prev_up": None, "if": {}, "seed": {}}
        if e["prev_ts"] and now < e["prev_ts"]:   # overlapping polls: an out-of-order stale sample would
            return                                # roll the baseline/clock backwards and re-count -> drop it
        dt = (now - e["prev_ts"]) if e["prev_ts"] else 0
        reboot = e["prev_up"] is not None and up is not None and up < e["prev_up"]
        emit = (0 < dt <= TF_MAX_GAP) and not reboot   # normal sample: emit rate + accumulate bytes
        gap = dt > TF_MAX_GAP and not reboot            # long stall: keep the bytes, suppress the smeared rate
        ifs = e["if"]
        for key, v in net.items():
            if not _tf_valid_key(key):                  # ignore malformed / abusive interface keys (len/charset)
                continue
            if not (isinstance(v, list) and len(v) == 2):
                continue
            try:
                rx, tx = int(v[0]), int(v[1])
            except (TypeError, ValueError):
                continue
            if not (0 <= rx < TF_CTR_CEIL and 0 <= tx < TF_CTR_CEIL):
                continue                                # counters are uint64 on the wire -> reject implausible bigints
            s = ifs.get(key)
            if s is None:                               # first sample -> baseline; restore lifetime cum from seed
                if len(ifs) >= TF_IF_MAX:
                    continue                            # per-node iface cap: a node can't grow this map unbounded
                sd = e["seed"].get(key)
                ifs[key] = {"prx": rx, "ptx": tx, "rx_bps": 0.0, "tx_bps": 0.0,
                            "crx": sd[0] if sd else 0, "ctx": sd[1] if sd else 0, "miss": 0}
                continue
            s["miss"] = 0                               # reported this sweep -> reset its prune counter
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
        stale = []
        for key, s in e["if"].items():    # an iface that dropped out of the report (deleted / mid-rebuild /
            if key not in net:            # no default route) must decay its rate, else it shows phantom throughput
                s["rx_bps"] = 0.0
                s["tx_bps"] = 0.0
                s["miss"] = s.get("miss", 0) + 1   # ...and after enough absent sweeps, prune it so a node that
                if s["miss"] > TF_IF_PRUNE_MISSES:  # rotates iface names cannot grow the map (paired with TF_IF_MAX)
                    stale.append(key)
        for key in stale:
            e["if"].pop(key, None)
        e["prev_ts"] = now
        e["prev_up"] = up


def _tf_forget(nid, keys):
    """Drop per-iface accounting state (rates + lifetime cum + seed) for deleted tunnels/port-forwards,
    so a later tunnel that reuses the same name doesn't inherit the removed one's lifetime totals."""
    if not keys:
        return
    with _tf_lock:
        e = _tf.get(nid)
        if not e:
            return
        for k in keys:
            e["if"].pop(k, None)
            e["seed"].pop(k, None)


def _tf_reset(nid, keys):
    """Zero the lifetime totals (crx/ctx) and drop the seed for the given iface keys, but keep the live
    baseline (prx/ptx) so running counters don't re-count — the 'total' figure just restarts from zero."""
    if not keys:
        return
    with _tf_lock:
        e = _tf.get(nid)
        for k in keys:
            if e:
                s = e["if"].get(k)
                if s:
                    s["crx"] = 0
                    s["ctx"] = 0
                e["seed"].pop(k, None)


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


def _uh_cells(nid, window_hours, cells=60):
    """Aggregate the per-minute ring into exactly `cells` bars for the given window (hours). Each bar
    spans window/cells minutes -> down(0) if any minute in it was down, up(1) if all up, None if no data
    yet (rendered gray). Uptime-kuma style: fixed bar count, coarser bars for a longer window."""
    try:
        wh = int(window_hours)
    except Exception:
        wh = 1
    if wh not in (1, 3, 6, 8, 12, 24):
        wh = 1
    per = wh  # minutes per cell (cells*per = wh*60 minutes covered)
    total = cells * per
    with _uh_lock:
        e = _uh.get(nid)
        ring = list(e["ring"]) if e else []
    ring = ring[-total:]
    slots = [None] * (total - len(ring)) + ring  # front-pad missing history with no-data
    out = []
    for i in range(cells):
        chunk = [x for x in slots[i * per:(i + 1) * per] if x is not None]
        out.append(None if not chunk else (0 if 0 in chunk else 1))
    return out


def _uh_snapshot():
    with _uh_lock:
        return {nid: list(e["ring"]) for nid, e in _uh.items() if e.get("ring")}


def _uh_load():
    try:
        with open(UPTIME_FILE) as f:
            data = json.load(f)
    except Exception:
        return
    now = time.time()
    with _uh_lock:
        for nid, ring in (data or {}).items():
            if isinstance(ring, list):  # bts=now so the offline gap isn't backfilled as up/down
                _uh[nid] = {"ring": [1 if x else 0 for x in ring][-UPTIME_KEEP:], "bts": now, "dn": False}


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
            valid = {n["id"] for n in load_nodes()}
            save_json(TRAFFIC_FILE, {k: v for k, v in _tf_snapshot().items() if k in valid})
            save_json(UPTIME_FILE, {k: v for k, v in _uh_snapshot().items() if k in valid})  # persist uptime history
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


def _tunnel_extra(src):
    """Type-specific fields that must reach BOTH tunnel ends identically: the UDP port (l2tpv3/fou/core),
    the shared key (IPsec psk / core AEAD psk) and the core cipher. Read from a stored link record
    (edit/rebuild) or a create request. NOTE: the core role is per-node, so it is NOT here — inject it
    separately with _core_role()."""
    e = {}
    if src.get("port"):
        e["port"] = src["port"]
    if src.get("psk"):
        e["psk"] = src["psk"]
    if src.get("cipher"):
        e["cipher"] = src["cipher"]
    if src.get("transport"):
        e["transport"] = src["transport"]
    if src.get("obfs"):
        e["obfs"] = True
    if src.get("cover"):                 # TLS camouflage (HTTPS cover); core TCP-only
        e["cover"] = True
        if src.get("cover_sni"):
            e["cover_sni"] = src["cover_sni"]
    if src.get("raw_profile"):           # raw-IP carrier encapsulation (transport=raw only)
        e["raw_profile"] = src["raw_profile"]
    if src.get("flux_carrier"):          # flux moving-target carrier (transport=flux only)
        e["flux_carrier"] = src["flux_carrier"]
    if src.get("flux_rotate_secs"):      # flux epoch length in seconds
        e["flux_rotate_secs"] = src["flux_rotate_secs"]
    if src.get("flux_shape"):            # flux statistical size profile
        e["flux_shape"] = src["flux_shape"]
    if src.get("flux_epoch_offset"):     # flux manual "rotate now" epoch bump
        e["flux_epoch_offset"] = src["flux_epoch_offset"]
    if src.get("fec"):                   # flux FEC (loss recovery); carry the block geometry too
        e["fec"] = True
        e["fec_data"] = src.get("fec_data") or 10
        e["fec_parity"] = src.get("fec_parity") or 3
    if src.get("ws_host"):               # ws (WebSocket/CDN) Host header + TLS SNI
        e["ws_host"] = src["ws_host"]
    if src.get("ws_path"):               # ws request path
        e["ws_path"] = src["ws_path"]
    if src.get("ws_tls"):                # ws client speaks wss (TLS to the CDN edge)
        e["ws_tls"] = True
    if src.get("edge_ip"):               # ws client dials this CDN edge instead of the origin
        e["edge_ip"] = src["edge_ip"]
    if src.get("gso"):                   # TUN segmentation offload (throughput)
        e["gso"] = True
    if src.get("spoof_src"):             # forge the outer source (raw bip; client only, node applies by role)
        e["spoof_src"] = src["spoof_src"]
    if src.get("spoof_dst"):             # decoy destination (raw bip; the node wires the AF_PACKET side by role)
        e["spoof_dst"] = src["spoof_dst"]
    return e


def _core_role(L, node_id):
    """Which role a given node plays in an core link. The record stores server_side ('a'|'b'); the node
    on that side listens (server), the other dials (client). Returns None for non-core links."""
    if L.get("type") != "core":
        return None
    server_node = L.get("b_node") if L.get("server_side") == "b" else L.get("a_node")
    return "server" if node_id == server_node else "client"

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


def _redact_proxy(proxy):
    """Strip any user:pass@ userinfo from a proxy URL before it is serialized toward the browser —
    a node's control-proxy credentials must never leave the server (they also ride plain HTTP)."""
    return re.sub(r"://[^/@]*@", "://", str(proxy or "").strip())


def _node_view(n):
    base = {"id": n["id"], "name": n["name"], "host": n["host"], "port": n["port"], "proxy": _redact_proxy(n.get("proxy")),
            "uptime": _uh_cells(n["id"], get_settings().get("uptime_window", 1))}
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
    return {"nodes": [_node_view(n) for n in page], "total": total, "offset": off, "limit": lim,
            "uptime_window": get_settings().get("uptime_window", 1)}


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


def api_spoof_probe(d):
    """Ask a node whether IP spoofing (decoy) can run on it — local CAP_NET_RAW / AF_PACKET capability
    only (it can't prove the datacenter forwards a forged source). The create/edit forms call this for
    both ends to enable or disable the spoofing controls and show the reason when it can't."""
    n = get_node(str(d.get("node") or ""))
    if not n:
        return {"ok": False, "reason": "node not found"}
    r = node_call(n, "spoof-probe", "GET", timeout=20)
    if not isinstance(r, dict) or ("ok" not in r and "reason" not in r):
        return {"ok": False, "reason": (r.get("error") if isinstance(r, dict) else None) or "نود پاسخ نداد"}
    return {"ok": bool(r.get("ok")), "reason": r.get("reason") or "",
            "cap_net_raw": bool(r.get("cap_net_raw")), "af_packet": bool(r.get("af_packet")),
            "node": n["name"]}


def _link_side_health(L, node_key):
    lst = _cached_list(L[node_key])
    if lst.get("configs") is None:
        return None, False  # node unreachable / not yet cached
    return (lst.get("health") or {}).get(L["name"]), True


def _cpu_snap():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), idle


def central_stats():
    """CPU/RAM/disk/load of the CENTRAL host itself (this panel's server), read live from /proc."""
    st = {"cpus": os.cpu_count()}
    try:
        t1, i1 = _cpu_snap(); time.sleep(0.1); t2, i2 = _cpu_snap(); dt = t2 - t1
        st["cpu_pct"] = round((1 - (i2 - i1) / dt) * 100) if dt > 0 else 0
    except Exception:
        pass
    try:
        mt = ma = 0
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mt = int(line.split()[1])
                elif line.startswith("MemAvailable:"):
                    ma = int(line.split()[1])
        st["mem_total_mb"], st["mem_used_mb"] = mt // 1024, (mt - ma) // 1024
        st["ram_pct"] = round((mt - ma) / mt * 100) if mt else 0
    except Exception:
        pass
    try:
        s = os.statvfs("/")
        avail = s.f_bavail * s.f_frsize
        used = (s.f_blocks - s.f_bfree) * s.f_frsize
        st["disk_total_mb"] = (s.f_blocks * s.f_frsize) // (1024 * 1024)
        st["disk_used_mb"] = used // (1024 * 1024)
        st["disk_pct"] = round(used / (used + avail) * 100) if (used + avail) else 0
    except Exception:
        pass
    try:
        with open("/proc/loadavg") as f:
            st["load"] = f.read().split()[:3]
    except Exception:
        pass
    return st


UP_CRIT = 85    # a node metric at/above this is "critical" (red)
UP_WARN = 60    # at/above this is "warning" (amber)
PING_BAD = 150  # tunnel rtt (ms) above this counts as a real quality problem


def api_summary(d):
    nodes = load_nodes()
    links = load_links()
    try:
        with open(AGENT_META) as f:
            stored_ver = json.load(f).get("version")
    except Exception:
        stored_ver = None

    on = tun = pf = mu = mt = du = dt = 0
    heat, crit, alerts, outdated = [], [], [], 0
    worst = {"disk": None, "ram": None, "cpu": None}
    for n in nodes:
        nid, nm = n["id"], n.get("name", "")
        p = _cached_ping(nid)
        if not p.get("ok"):
            heat.append({"id": nid, "name": nm, "pct": None, "online": False})
            if _cache_get(nid):  # actually probed and found offline (not merely un-probed yet)
                alerts.append({"level": "bad", "kind": "node", "id": nid, "msg": f"نودِ «{nm}» آفلاین است"})
            continue
        on += 1
        tun += _sint(p.get("tunnels")); pf += _sint(p.get("portfw"))
        if stored_ver and p.get("version") and _sint(p.get("version")) < _sint(stored_ver):
            outdated += 1
        s = p.get("stats") if isinstance(p.get("stats"), dict) else {}
        mu += _sint(s.get("mem_used_mb")); mt += _sint(s.get("mem_total_mb"))
        du += _sint(s.get("disk_used_mb")); dt += _sint(s.get("disk_total_mb"))
        cpu = round(_sflt(s.get("cpu_pct")))
        disk = round(_sflt(s.get("disk_pct")))
        ram = round(_sint(s.get("mem_used_mb")) / _sint(s.get("mem_total_mb")) * 100) if _sint(s.get("mem_total_mb")) else 0
        for key, val, lab in (("disk", disk, "دیسک"), ("ram", ram, "رم"), ("cpu", cpu, "CPU")):
            if worst[key] is None or val > worst[key]["pct"]:
                worst[key] = {"name": nm, "id": nid, "pct": val}
            if val >= UP_CRIT:
                alerts.append({"level": "bad", "kind": key, "id": nid, "msg": f"{lab}ِ «{nm}» به {val}٪ رسیده"})
        w = max(cpu, ram, disk)
        heat.append({"id": nid, "name": nm, "pct": w, "online": True})
        if w >= UP_CRIT:
            crit.append(nid)

    nmap = {n["id"]: n.get("name", "") for n in nodes}
    up = noping = down = drift_n = 0
    types = {"vxlan": 0, "gre": 0, "sit": 0}
    worst_tun = None
    rtts = []
    for L in links:
        if L.get("type") == "core":
            continue  # core tunnels have their own panel + health; keep these counters
                      # (and the `links` total below, which subtracts cores) consistent,
                      # and avoid emitting link/drift alerts that navigate to the tunnels
                      # page where core links are filtered out
        types[L.get("type", "")] = types.get(L.get("type", ""), 0) + 1
        ah, _a = _link_side_health(L, "a_node")
        bh, _b = _link_side_health(L, "b_node")
        both_up = isinstance(ah, dict) and ah.get("up") and isinstance(bh, dict) and bh.get("up")
        if both_up:
            pinged = (ah.get("peer_ping") is True) or (bh.get("peer_ping") is True)
            if pinged:
                up += 1
            else:
                noping += 1
            # worst view of the tunnel = the higher loss / rtt reported by either end
            sides = [h for h in (ah, bh) if isinstance(h, dict)]
            lrtt = max([_sflt(h.get("rtt_ms")) for h in sides if h.get("rtt_ms") is not None] or [0])
            lloss = max([_sflt(h.get("loss_pct")) for h in sides] or [0])
            if lrtt > 0:
                rtts.append(lrtt)
            # only a *real* quality problem qualifies: packet loss, or genuinely high ping
            if lloss > 0 or lrtt > PING_BAD:
                cand = {"name": L.get("name"),
                        "a": nmap.get(L.get("a_node"), L.get("a_name", "")),
                        "b": nmap.get(L.get("b_node"), L.get("b_name", "")),
                        "rtt": lrtt if lrtt > 0 else None, "loss": lloss}
                # rank by loss first (most important), then by rtt
                if worst_tun is None or (cand["loss"], _sflt(cand["rtt"])) > (worst_tun["loss"], _sflt(worst_tun["rtt"])):
                    worst_tun = cand
        else:
            down += 1
            alerts.append({"level": "bad", "kind": "link", "id": L["id"], "msg": f"تونلِ «{L.get('name')}» قطع است"})
        if link_drift(L["id"]):
            drift_n += 1
            alerts.append({"level": "warn", "kind": "drift", "id": L["id"], "msg": f"تونلِ «{L.get('name')}» نیازمندِ بازسازی است"})
    if outdated:
        alerts.append({"level": "warn", "kind": "agent", "msg": f"{outdated} نود ایجنتِ قدیمی دارد"})

    win = get_settings().get("uptime_window", 1)
    ups, downcnt = [], 0
    for n in nodes:
        vals = [c for c in _uh_cells(n["id"], win) if c is not None]
        if vals:
            ups.append(sum(vals) / len(vals) * 100)
            if 0 in vals:
                downcnt += 1

    frx_bps = ftx_bps = frx = ftx = 0
    with _tf_lock:
        for e in _tf.values():
            nd = e.get("if", {}).get("_node")
            if nd:
                frx_bps += nd["rx_bps"]; ftx_bps += nd["tx_bps"]; frx += nd["crx"]; ftx += nd["ctx"]

    offline = len(nodes) - on
    score = max(0, min(100, 100 - offline * 8 - len(crit) * 6 - down * 10 - drift_n * 4 - noping * 3))
    n_core = sum(1 for L in links if L.get("type") == "core")
    return {"nodes_online": on, "nodes_total": len(nodes),
            "links": len(links) - n_core, "core": n_core,
            "links_healthy": up, "tunnels": tun, "portfw": pf,
            "health_score": score,
            "central": central_stats(),
            "heat": heat, "worst": worst,
            "crit": len(crit), "outdated": outdated,
            "alerts": alerts[:10],
            "link_up": up, "link_noping": noping, "link_down": down, "link_drift": drift_n,
            "link_types": types, "worst_tunnel": worst_tun,
            "fleet_avg_ping": round(sum(rtts) / len(rtts)) if rtts else None,
            "uptime_avg": round(sum(ups) / len(ups), 1) if ups else 100, "uptime_down_nodes": downcnt, "uptime_window": win,
            "mem_used_mb": mu, "mem_total_mb": mt, "disk_used_mb": du, "disk_total_mb": dt,
            "fleet_rx_bps": frx_bps, "fleet_tx_bps": ftx_bps,
            "fleet_rx_total": frx, "fleet_tx_total": ftx}


def _name_taken(nodes, name, exclude_id=None):
    """A node name must be unique across the fleet (case-insensitive), so it always identifies one node."""
    key = str(name).strip().lower()
    return any(n.get("id") != exclude_id and str(n.get("name", "")).strip().lower() == key for n in nodes)


def _host_taken(nodes, host, exclude_id=None):
    """One node per host/IP — a second node on the same address is never needed."""
    key = str(host).strip().lower()
    return any(n.get("id") != exclude_id and str(n.get("host", "")).strip().lower() == key for n in nodes)


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
    if len(token) < 16:   # token-strength floor: reject weak manual tokens (auto-provisioned ones are long)
        raise ValueError("token too short — use at least 16 characters")
    proxy = valid_proxy(d.get("proxy"))
    node = {"id": secrets.token_hex(5), "name": name, "host": host, "port": port, "token": token, "proxy": proxy}
    with _reg_lock:
        nodes = load_nodes()
        if _name_taken(nodes, name):
            raise ValueError(f"نودی با نامِ «{name}» از قبل وجود دارد — یک نامِ یکتا انتخاب کن")
        if _host_taken(nodes, host):
            raise ValueError(f"نودی با آی‌پیِ «{host}» از قبل وجود دارد")
        nodes.append(node)
        save_json(NODES_FILE, nodes)
    p = node_call(node, "ping", "GET")
    _refresh_cache([node["id"]])
    if p.get("ok"):                      # node reachable → provision the signing key FIRST, then stage-push the core
        try:
            # Pin the panel's update-signing key before any code push, so even the first core install is
            # signature-verified — closes the bootstrap window where an unprovisioned node accepts unsigned
            # pushes. First-set-only on the node side; best-effort, provision-key can retry if this blips.
            _, _pub = _signing_keys()
            node_call(get_node(node["id"]) or node, "set-update-key", "POST", {"pubkey": _pub}, timeout=15)
        except Exception:
            pass
        _push_staged_on_add(get_node(node["id"]) or {**node, "arch": p.get("arch")})
    return {"ok": True, "id": node["id"], "online": bool(p.get("ok")),
            "error": "" if p.get("ok") else p.get("error", "unreachable")}


# ----------------------------------------------------------------------------- SSH auto-provision
# The panel can SSH into a fresh server, install the (public) node agent non-interactively, read the
# generated token back and register the node — all steps streamed to the operator via a polling job.
NODE_RAW_URL = "https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER-NODE/main/tnl-node.py"
_INSTALL_STEPS = [("ssh", "اتصالِ SSH"), ("download", "دانلودِ ایجنت"),
                  ("install", "نصب و راه‌اندازیِ سرویس"), ("register", "ثبت و اتصال در پنل")]
_INSTALL_LABELS = dict(_INSTALL_STEPS)
_install_jobs = {}
_install_lock = threading.Lock()


def _scrub(s):
    return re.sub(r"TNL_NODE_TOKEN=\S+", "TNL_NODE_TOKEN=***", s or "")[-1400:]


def _install_get(jid):
    with _install_lock:
        j = _install_jobs.get(jid)
        return json.loads(json.dumps(j)) if j else None  # deep copy for a race-free read


def _install_step(jid, key, state, detail=None, log=None):
    with _install_lock:
        j = _install_jobs.get(jid)
        if not j:
            return
        for s in j["steps"]:
            if s["key"] == key:
                s["state"] = state
                if detail is not None:
                    s["detail"] = detail
                if log is not None:
                    s["log"] = _scrub(log)
                break


def _install_finish(jid, ok, banner):
    with _install_lock:
        j = _install_jobs.get(jid)
        if j:
            j["done"], j["ok"], j["banner"] = True, ok, banner


SSH_KNOWN_HOSTS = os.path.join(CENTRAL_DIR, "known_hosts")


def _ssh_argv(cfg, remote_cmd):
    # TOFU: accept a host key the first time we see a node (needed for unattended
    # provisioning) but PERSIST it and reject any later change. The old
    # "StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null" trusted every key
    # blindly on every connect, so an on-path attacker could MITM the install
    # session and capture the SSH password / inject a malicious agent as root.
    opts = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
            "-o", "ConnectTimeout=15", "-p", str(cfg["port"])]
    target = f"{cfg['user']}@{cfg['host']}"
    if cfg.get("keyfile"):
        return ["ssh", "-i", cfg["keyfile"], "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"] + opts + [target, remote_cmd], None
    return ["sshpass", "-e", "ssh"] + opts + [target, remote_cmd], dict(os.environ, SSHPASS=cfg.get("password", ""))


def _ssh_run(cfg, remote_cmd, timeout):
    argv, env = _ssh_argv(cfg, remote_cmd)
    try:
        p = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", "SSH timeout"


def _install_worker(jid, cfg, name, agent_port, proxy):
    def fail(key, msg, log=""):
        _install_step(jid, key, "err", msg, log)
        _install_finish(jid, False, f"نصب در مرحلهٔ «{_INSTALL_LABELS[key]}» متوقف شد")

    try:
        _install_step(jid, "ssh", "run")
        rc, out, err = _ssh_run(cfg, "echo TNL_SSH_OK", 30)
        if rc == 127:
            return fail("ssh", "ابزارِ SSH روی سرورِ مرکزی نیست",
                        "برای احرازِ رمز، sshpass لازم است:  sudo apt install -y sshpass\n(یا از کلیدِ خصوصی استفاده کن)")
        if rc != 0 or "TNL_SSH_OK" not in out:
            return fail("ssh", "اتصالِ SSH ناموفق", (err or out).strip())
        _install_step(jid, "ssh", "ok", f"{cfg['user']}@{cfg['host']}:{cfg['port']} — وصل شد")

        _install_step(jid, "download", "run")
        dl = f"(curl -fsSL {NODE_RAW_URL} -o /tmp/tnl-node.py || wget -qO /tmp/tnl-node.py {NODE_RAW_URL}) && echo TNL_DL_OK"
        rc, out, err = _ssh_run(cfg, dl, 90)
        if rc != 0 or "TNL_DL_OK" not in out:
            return fail("download", "دانلودِ ایجنت ناموفق (curl/wget؟ دسترسیِ اینترنت؟)", (err or out).strip())
        _install_step(jid, "download", "ok", "tnl-node.py دریافت شد")

        _install_step(jid, "install", "run", "نصبِ وابستگی‌ها ممکن است چند دقیقه طول بکشد…")
        sudo = "" if cfg["user"] == "root" else "sudo -n "
        rc, out, err = _ssh_run(cfg, f"{sudo}python3 /tmp/tnl-node.py --auto-install {agent_port}", 900)
        combined = ((out or "") + "\n" + (err or "")).strip()
        if rc != 0 or "TNL_INSTALL_OK" not in out:
            return fail("install", "نصب/راه‌اندازیِ سرویس ناموفق", combined)
        m = re.search(r"TNL_NODE_TOKEN=(\S+)", out)
        if not m:
            return fail("install", "توکن از خروجیِ نصب خوانده نشد", combined)
        token = m.group(1)
        _install_step(jid, "install", "ok", "ایجنت نصب و اجرا شد")

        _install_step(jid, "register", "run")
        node = {"id": secrets.token_hex(5), "name": name, "host": cfg["host"],
                "port": agent_port, "token": token, "proxy": proxy}
        with _reg_lock:
            nodes = load_nodes()
            if _name_taken(nodes, name):  # a same-name node was added during the (minutes-long) install
                return fail("register", f"نودی با نامِ «{name}» در این فاصله اضافه شد — نام باید یکتا باشد")
            if _host_taken(nodes, cfg["host"]):
                return fail("register", f"نودی با آی‌پیِ «{cfg['host']}» در این فاصله اضافه شد")
            nodes.append(node)
            save_json(NODES_FILE, nodes)
        _refresh_cache([node["id"]])
        online = False
        for _ in range(6):  # the service just started; give it a few seconds to answer
            if node_call(node, "ping", "GET").get("ok"):
                online = True
                break
            time.sleep(2)
        with _install_lock:
            _install_jobs[jid]["node_id"] = node["id"]
        if online:                       # push the staged core now so the node is ready before any tunnel build
            _push_staged_on_add(get_node(node["id"]) or node)
        _install_step(jid, "register", "ok" if online else "warn",
                      "نود وصل شد و آنلاین است" if online else "ثبت شد ولی هنوز پاسخ نمی‌دهد (پورتِ ایجنت را به سرورِ مرکزی باز کن)")
        _install_finish(jid, True, f"«{name}» نصب و وصل شد" if online else f"«{name}» ثبت شد؛ در انتظارِ آنلاین‌شدن")
    except Exception as e:
        fail("install", "خطای غیرمنتظره", str(e))
    finally:
        kf = cfg.get("keyfile")
        if kf:
            try:
                os.remove(kf)
            except Exception:
                pass


def api_node_install(d):
    _require(d, ["name", "ssh_host"])
    name = str(d["name"]).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise ValueError("bad node name")
    host = str(d["ssh_host"]).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("bad host")
    _exist = load_nodes()
    if _name_taken(_exist, name):
        raise ValueError(f"نودی با نامِ «{name}» از قبل وجود دارد — یک نامِ یکتا انتخاب کن")
    if _host_taken(_exist, host):
        raise ValueError(f"نودی با آی‌پیِ «{host}» از قبل وجود دارد")
    ssh_port = int(d.get("ssh_port") or 22)
    if not 1 <= ssh_port <= 65535:
        raise ValueError("bad ssh port")
    user = str(d.get("ssh_user") or "root").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", user):
        raise ValueError("bad ssh user")
    agent_port = int(d.get("agent_port") or 8099)
    if not 1 <= agent_port <= 65535:
        raise ValueError("bad agent port")
    proxy = valid_proxy(d.get("proxy"))
    password = str(d.get("ssh_pass") or "")
    key = str(d.get("ssh_key") or "").strip()
    if not password and not key:
        raise ValueError("رمزِ SSH یا کلیدِ خصوصی لازم است")
    cfg = {"host": host, "port": ssh_port, "user": user, "password": password}
    if key:
        fd, kp = tempfile.mkstemp(prefix="tnlkey_")
        with os.fdopen(fd, "w") as f:
            f.write(key if key.endswith("\n") else key + "\n")
        os.chmod(kp, 0o600)
        cfg["keyfile"], cfg["password"] = kp, ""
    now = int(time.time())
    jid = secrets.token_hex(6)
    with _install_lock:
        for k in [k for k, v in _install_jobs.items() if now - v.get("ts", now) > 3600]:  # prune stale
            _install_jobs.pop(k, None)
        _install_jobs[jid] = {"steps": [{"key": k, "label": l, "state": "wait", "detail": "", "log": ""}
                                        for k, l in _INSTALL_STEPS],
                              "done": False, "ok": False, "banner": "", "node_id": None, "ts": now}
    threading.Thread(target=_install_worker, args=(jid, cfg, name, agent_port, proxy), daemon=True).start()
    return {"ok": True, "job": jid}


def api_node_install_status(d):
    _require(d, ["job"])
    j = _install_get(d["job"])
    if not j:
        raise ValueError("job not found")
    # "ok" = this poll is valid (ALWAYS true for a live job); the install's own success is "success".
    # (j carries its own "ok" = install result; exposing it as the response "ok" made every running poll
    #  look like a failed request to the browser, which then gave up with "ارتباط با پنل قطع شد".)
    return {**j, "ok": True, "success": bool(j.get("ok"))}


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
        if _name_taken(nodes, name, exclude_id=d["id"]):  # can't rename onto another node's name
            raise ValueError(f"نودِ دیگری با نامِ «{name}» وجود دارد — نام باید یکتا باشد")
        if _host_taken(nodes, host, exclude_id=d["id"]):  # can't move onto another node's IP
            raise ValueError(f"نودِ دیگری با آی‌پیِ «{host}» وجود دارد")
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
    nid = d["id"]
    wipe = bool(d.get("wipe"))
    out = {"ok": True, "wiped": wipe}
    if wipe:  # full wipe is ALL-OR-NOTHING: if the node side fails, touch nothing so nothing is half-removed
        n = get_node(nid)
        if not n:
            raise ValueError("نود پیدا نشد")
        r = node_call(n, "wipe", "POST", {}, timeout=60)
        if not r.get("ok"):
            raise ValueError("پاک‌سازیِ سمتِ نود ناموفق: " + (r.get("error") or r.get("msg") or "در دسترس نیست")
                             + " — چیزی از پنل حذف نشد. اگر سرور از دسترس خارج است یا ایجنتش قدیمی است، «فقط از پنل جدا کن» را بزن.")
        with _reg_lock:  # wipe succeeded -> drop this node's links from the registry
            links = load_links()
            mine = [L for L in links if L.get("a_node") == nid or L.get("b_node") == nid]
            mine_ids = {L["id"] for L in mine}
            save_json(LINKS_FILE, [L for L in links if L["id"] not in mine_ids])
        def _del_peer_half(L):  # tear the peer's half of each tunnel down too, so no orphan is left behind
            peer_id = L["b_node"] if L["a_node"] == nid else L["a_node"]
            pn = get_node(peer_id)
            if not pn:
                return
            with _PairLock(nid, peer_id):  # serialize with a rebuild on this pair so it can't recreate the peer half
                node_call(pn, "delete", "POST", {"name": L["name"]}, timeout=8)  # best-effort, short deadline
        parallel_map(_del_peer_half, mine, workers=32)  # fan out: N offline peers must not serialize to N*timeout
        out["links_removed"] = len(mine)
    with _reg_lock:
        save_json(NODES_FILE, [n for n in load_nodes() if n["id"] != nid])
    with _pc_lock:
        _pc.pop(nid, None)
    with _tf_lock:
        _tf.pop(nid, None)
    with _uh_lock:
        _uh.pop(nid, None)
    with _tomb_lock:  # block an in-flight poll (submitted before this delete) from re-inserting the popped cache
        _tomb[nid] = time.time() + 20
    return out


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
    portfw = []
    lst = _cached_list(n["id"])
    for c in (lst.get("configs") or []):
        if c.get("type") != "portfw":
            continue
        t = ifs.get("pf:" + str(c.get("name") or ""))
        if t:
            portfw.append({"name": c.get("name"), "type": "portfw",
                           "rx_bps": t["rx_bps"], "tx_bps": t["tx_bps"],
                           "rx_total": t["crx"], "tx_total": t["ctx"]})
    return {"online": online,
            "node": {"rx_bps": node.get("rx_bps", 0.0), "tx_bps": node.get("tx_bps", 0.0),
                     "rx_total": node.get("crx", 0), "tx_total": node.get("ctx", 0)},
            "tunnels": tunnels, "portfw": portfw}


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


def api_agent_fetch_git(d):
    """Download the latest node agent from its public GitHub repo, validate it (same gates as an
    upload) and store it as the current agent so it can be pushed to the fleet."""
    try:
        req = urllib.request.Request(NODE_RAW_URL, headers={"User-Agent": "tnl-central"})
        with urllib.request.urlopen(req, timeout=30) as r:
            src = r.read(300000).decode("utf-8", "replace")
    except Exception as e:
        raise ValueError(f"دریافت از گیت‌هاب ناموفق: {str(e)[:120]}")
    if not src.strip():
        raise ValueError("فایلِ دریافتی خالی است")
    if len(src.encode()) > 262144:
        raise ValueError("فایلِ دریافتی بیش از حد بزرگ است")
    try:
        compile(src, "tnl-node.py", "exec")
    except SyntaxError as e:
        raise ValueError("کدِ دریافتی نامعتبر: " + str(e))
    if '"agent": "tnl-node"' not in src:
        raise ValueError("فایلِ دریافتی ایجنتِ نود نیست")
    m = re.search(r'"version":\s*(\d+)', src)
    if not m:
        raise ValueError("نسخهٔ ایجنت در کدِ دریافتی پیدا نشد")
    ver, sha = int(m.group(1)), hashlib.sha256(src.encode()).hexdigest()
    with _agent_lock:
        save_text(AGENT_FILE, src)
        save_json(AGENT_META, {"version": ver, "sha256": sha, "size": len(src.encode()),
                               "uploaded_ts": int(time.time()), "source": "git"})
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
    if not isinstance(d.get("ids"), list):
        raise ValueError("ids must be a list")
    ids = [i for i in dict.fromkeys(d["ids"]) if get_node(i)]

    def push_one(nid):
        n = get_node(nid)
        if not n:                                        # deleted between the filter and here -> report it, don't crash the whole push
            return {"id": nid, "ok": False, "offline": True, "restarting": False, "already": False, "error": "node removed"}
        r = node_call(n, "update", "POST", {"code": src, "sha256": meta["sha256"], "sig": _sign_sha(meta["sha256"])}, timeout=30)
        return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")),
                "restarting": bool(r.get("restarting")), "already": bool(r.get("already")), "error": r.get("error") or r.get("msg") or ""}

    return {"results": parallel_map(push_one, ids)}  # poller re-reads each node's version within ~2s after it bounces


_CORE_RELEASES_API = "https://api.github.com/repos/Angize/TUNNEL-MANAGER-CORE/releases"
_core_versions_cache = {"ts": 0.0, "data": None}
_core_versions_lock = threading.Lock()


def api_core_versions(d):
    """The core versions the operator can install/downgrade to — the core repo's GitHub releases,
    newest first, plus a "latest" option. Cached ~5 min; degrades to just "latest" if the API is
    unreachable so the control still works."""
    now = time.time()
    with _core_versions_lock:
        if _core_versions_cache["data"] is None or now - _core_versions_cache["ts"] > 300:
            vers = []
            try:
                req = urllib.request.Request(_CORE_RELEASES_API,
                                             headers={"User-Agent": "tnl-central", "Accept": "application/vnd.github+json"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    for rel in json.loads(r.read().decode()):
                        tag = rel.get("tag_name")
                        if not tag or rel.get("draft"):
                            continue
                        vers.append({"id": tag, "label": rel.get("name") or tag, "prerelease": bool(rel.get("prerelease"))})
            except Exception:
                pass
            _core_versions_cache["data"] = vers
            _core_versions_cache["ts"] = now
        vers = list(_core_versions_cache["data"] or [])
    out = list(vers)  # newest first
    if out:  # tag the newest real release "(latest)" instead of a synthetic "latest" item
        out[0] = {**out[0], "label": (out[0].get("label") or out[0]["id"]) + " (latest)", "latest": True}
    info = _core_blob_info()
    if info:                                          # offer the operator-uploaded binary as its own choice
        out.append({"id": "custom", "label": "باینریِ آپلودشده" + (" · " + info["name"] if info.get("name") else ""),
                    "custom": True, "sha256": info.get("sha256", "")[:12], "size": info.get("size")})
    return {"versions": out, "staged": _staged_info()}   # staged = the core the panel has ready to push


def _core_blob_info():
    """Metadata for the custom core binary the operator uploaded, or None if none is stored."""
    try:
        with open(CORE_BLOB_META) as f:
            m = json.load(f)
        if os.path.isfile(CORE_BLOB):
            return m
    except Exception:
        pass
    return None


def api_core_upload(d):
    """Store a custom core binary (base64) in the panel so it can be pushed to nodes as version 'custom'.
    Verifies it looks like a Linux ELF and isn't absurdly small/large before saving."""
    _require(d, ["data"])
    try:
        raw = base64.b64decode(d["data"], validate=True)
    except Exception:
        raise ValueError("فایل base64 نامعتبر است")
    if len(raw) < 100000:
        raise ValueError("فایل خیلی کوچک است — این باینریِ هسته نیست")
    if len(raw) > 15 * 1024 * 1024:
        raise ValueError("فایل بیش از حد بزرگ است")
    if raw[:4] != b"\x7fELF":                       # a Linux core binary must be an ELF — reject anything else early
        raise ValueError("این یک باینریِ ELF لینوکسی نیست")
    sha = hashlib.sha256(raw).hexdigest()
    name = str(d.get("name") or "core.bin")[:80]
    with _core_blob_lock:
        with open(CORE_BLOB, "wb") as f:
            f.write(raw)
        save_json(CORE_BLOB_META, {"sha256": sha, "size": len(raw), "name": name, "uploaded_ts": int(time.time())})
    return {"ok": True, "sha256": sha[:12], "size": len(raw), "name": name}


# ----------------------------------------------------------------------------- core delivery (panel is the source)
# The NODE never downloads the core (nodes may have no internet — e.g. an Iran node). The panel is the
# single source: it stages the binary on its own disk (downloaded from GitHub, per arch) and pushes
# verified bytes to nodes via core-install. Everything below is that staging + push machinery.
_CORE_REL_DL = "https://github.com/Angize/TUNNEL-MANAGER-CORE/releases"
_CORE_TAG_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")  # release-tag charset: forbids "/" and ".." so a version can't traverse the GitHub path
CORE_STAGE_DIR = os.path.join(CENTRAL_DIR, "core-stage")            # tnl-core-<arch> binaries, ready to push
CORE_STAGE_META = os.path.join(CENTRAL_DIR, "core-stage.meta.json")  # {version, arches, ts}
_core_stage_lock = threading.Lock()


def _resolve_core_version(version):
    """Turn "latest"/"" into the newest concrete release tag, so a staged/pushed node records a real
    version rather than the abstract "latest". Falls back to "latest" if the release list is unknown."""
    version = (version or "latest").strip() or "latest"
    if version != "latest":
        if version in (".", "..") or not _CORE_TAG_RE.match(version):
            raise ValueError("نسخهٔ هسته نامعتبر است — فقط حروف/عدد و کاراکترهای «._+-» مجاز است")
        return version
    for v in (api_core_versions({}).get("versions") or []):
        if v.get("id") and v["id"] != "custom":
            return v["id"]
    return "latest"


def _dl(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "tnl-central"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _fetch_release(version, arch):
    """Download + verify a core release asset (binary + its .sha256) from GitHub. Returns (raw, sha).
    Raises on any failure — this is the ONLY place that talks to GitHub for the core binary."""
    asset = f"tnl-core-linux-{arch}"
    base = (f"{_CORE_REL_DL}/latest/download/{asset}" if version in ("latest", "")
            else f"{_CORE_REL_DL}/download/{version}/{asset}")
    sha = _dl(base + ".sha256", 30).decode().split()[0].strip().lower()
    if len(sha) != 64:
        raise RuntimeError("checksum unavailable from the release")
    raw = _dl(base, 180)
    if hashlib.sha256(raw).hexdigest() != sha:
        raise RuntimeError("release checksum mismatch")
    return raw, sha


def _staged_info():
    """{version, arches, ts} for the core currently staged on the panel, or None if nothing is staged."""
    try:
        with open(CORE_STAGE_META) as f:
            info = json.load(f)
        return info if info.get("version") else None
    except Exception:
        return None


def _stage_core(version):
    """Download the resolved version for amd64 (required) and arm64 (best-effort) and persist it on the
    panel as the staged core, ready to push to internet-less nodes. Returns {version, arches}. Raises if
    the panel itself cannot fetch the amd64 asset (e.g. the panel has no internet)."""
    rel = _resolve_core_version(version)
    os.makedirs(CORE_STAGE_DIR, exist_ok=True)
    got, shas, sizes = [], {}, {}
    with _core_stage_lock:
        for arch in ("amd64", "arm64"):
            try:
                raw, sha = _fetch_release(rel, arch)
            except Exception:
                if arch == "amd64":
                    raise
                continue           # arm64 is optional; fetched on demand at push time if a node needs it
            with open(os.path.join(CORE_STAGE_DIR, f"tnl-core-{arch}"), "wb") as f:
                f.write(raw)
            got.append(arch)
            shas[arch] = sha       # per-arch sha lets the panel tell which nodes are out of date
            sizes[arch] = len(raw)
        save_json(CORE_STAGE_META, {"version": rel, "arches": got, "sha": shas, "size": sizes, "ts": int(time.time())})
    return {"version": rel, "arches": got}


def _staged_bytes(arch):
    """(raw, sha, version) for the staged core at arch — fetching+persisting that arch on demand if the
    staged version is set but its file isn't present yet. None if nothing is staged (or the arch can't
    be fetched and isn't cached)."""
    info = _staged_info()
    if not info:
        return None
    ver = info["version"]
    p = os.path.join(CORE_STAGE_DIR, f"tnl-core-{arch}")
    if not os.path.isfile(p):
        try:
            raw, sha = _fetch_release(ver, arch)
        except Exception:
            return None
        os.makedirs(CORE_STAGE_DIR, exist_ok=True)
        with open(p, "wb") as f:
            f.write(raw)
        return raw, sha, ver
    with open(p, "rb") as f:
        raw = f.read()
    return raw, hashlib.sha256(raw).hexdigest(), ver


def _push_staged(node):
    """Push the staged core to one node via core-install (no node download). Returns a result dict."""
    b = _staged_bytes(node.get("arch") or "amd64")
    if not b:
        return {"ok": False, "error": "هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن"}
    raw, sha, ver = b
    return node_call(node, "core-install", "POST",
                     {"data": base64.b64encode(raw).decode(), "sha256": sha, "version": ver, "sig": _sign_sha(sha)}, timeout=200)


def _push_staged_on_add(node):
    """Best-effort: push the staged core to a freshly-added node so it is ready before any tunnel build.
    Silent on failure (the node may be briefly unreachable; the build path relays as a fallback)."""
    try:
        if _staged_info():
            _push_staged(node)
    except Exception:
        pass


def _node_tunnel(node, body):
    """node_call the tunnel op; if a core tunnel fails because the node has no core binary (it never
    downloads its own), push the staged binary from the panel and retry once — so building a core tunnel
    on an internet-less node just works. If the panel has nothing staged, surface a clear message."""
    r = node_call(node, "tunnel", "POST", body, timeout=200)
    err = str(r.get("error") or r.get("msg") or "")
    if not r.get("ok") and "core not installed" in err:
        pr = _push_staged(node)
        if not pr.get("ok"):
            r["error"] = f"هسته روی نودِ «{node.get('name', '?')}» نصب نیست و پنل هم چیزی برای پوش ندارد — اول یک نسخه دانلود کن"
            return r
        r = node_call(node, "tunnel", "POST", body, timeout=200)
    return r


def api_core_stage(d):
    """Download a core version onto the PANEL and keep it staged (ready to push). This is the
    'get from GitHub' action for the core. version defaults to latest."""
    info = _stage_core(str((d or {}).get("version") or "latest").strip())
    return {"ok": True, **info}


def api_core_update(d):
    """Install a core version on the given node ids and restart their core tunnels. The panel stages the
    version (downloads it once) and PUSHES the bytes to each node — nodes never download. `version` is a
    release tag, "latest", or "custom" (the operator-uploaded binary)."""
    _require(d, ["ids", "version"])
    version = str(d.get("version") or "latest").strip()
    if not isinstance(d.get("ids"), list):
        raise ValueError("ids must be a list")
    ids = [i for i in dict.fromkeys(d["ids"]) if get_node(i)]

    if version == "custom":                          # push the operator-uploaded blob's bytes directly
        info = _core_blob_info()
        if not info:
            raise ValueError("هیچ باینریِ سفارشی‌ای بارگذاری نشده")
        with _core_blob_lock:
            with open(CORE_BLOB, "rb") as f:
                raw = f.read()
        b64, sha = base64.b64encode(raw).decode(), info["sha256"]

        def one_custom(nid):
            n = get_node(nid)
            if not n:
                return {"id": nid, "ok": False, "error": "node removed"}
            r = node_call(n, "core-install", "POST", {"data": b64, "sha256": sha, "version": "custom", "sig": _sign_sha(sha)}, timeout=200)
            err = r.get("error") or r.get("msg") or ("; ".join(r["errors"]) if r.get("errors") else "")
            return {"id": nid, "ok": bool(r.get("ok")), "version": r.get("version"),
                    "restarted": r.get("restarted"), "core_sha": r.get("core_sha"), "unchanged": bool(r.get("unchanged")), "error": err}

        return {"results": parallel_map(one_custom, ids)}

    _stage_core(version)   # download the chosen version onto the panel first (raises if the panel is offline)

    def one(nid):
        n = get_node(nid)
        if not n:
            return {"id": nid, "ok": False, "error": "node removed"}
        r = _push_staged(n)
        err = r.get("error") or r.get("msg") or ("; ".join(r["errors"]) if r.get("errors") else "")
        return {"id": nid, "ok": bool(r.get("ok")), "version": r.get("version"),
                "restarted": r.get("restarted"), "core_sha": r.get("core_sha"), "unchanged": bool(r.get("unchanged")), "error": err}

    return {"results": parallel_map(one, ids)}


def api_core_push(d):
    """Push the currently-staged core to the given node ids (the 'push the ready binary' per-node action).
    No download, no version pick — just deliver what the panel already has staged."""
    _require(d, ["ids"])
    if not _staged_info():
        raise ValueError("هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن")
    if not isinstance(d.get("ids"), list):
        raise ValueError("ids must be a list")
    ids = [i for i in dict.fromkeys(d["ids"]) if get_node(i)]

    def one(nid):
        n = get_node(nid)
        if not n:
            return {"id": nid, "ok": False, "error": "node removed"}
        r = _push_staged(n)
        err = r.get("error") or r.get("msg") or ("; ".join(r["errors"]) if r.get("errors") else "")
        return {"id": nid, "ok": bool(r.get("ok")), "version": r.get("version"),
                "restarted": r.get("restarted"), "core_sha": r.get("core_sha"), "unchanged": bool(r.get("unchanged")), "error": err}

    return {"results": parallel_map(one, ids)}


def api_fleet(d):
    off, lim, q = _paginate(d)
    nodes = {n["id"]: n for n in load_nodes()}
    # resolve node names LIVE from the registry so a renamed node shows its current name here too
    kind = (d or {}).get("kind")   # "core" -> only core links; "tunnels" -> everything else; None -> all
    links = []
    for L in load_links():
        if kind == "core" and L.get("type") != "core":
            continue
        if kind == "tunnels" and L.get("type") == "core":
            continue
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
            side = "b" if L.get("view_side") == "b" else "a"   # figures are shown from ONE chosen node's iface
            nid = L["b_node"] if side == "b" else L["a_node"]  # (rx/tx are that node's; the peer sees the mirror)
            s = (_tf.get(nid) or {}).get("if", {}).get(L["name"])   # no silent fallback to the other side
            if s:
                tfl[L["id"]] = {"rx_bps": s["rx_bps"], "tx_bps": s["tx_bps"],
                                "rx_total": s["crx"], "tx_total": s["ctx"]}
    out = []
    for L in page:
        la, lb = _cached_list(L["a_node"]), _cached_list(L["b_node"])
        ah = (la.get("health") or {}).get(L["name"]) if la.get("configs") is not None else None
        bh = (lb.get("health") or {}).get(L["name"]) if lb.get("configs") is not None else None
        a_ips = [ip for ips in (_cached_ping(L["a_node"]).get("ips") or {}).values() for ip in ips]
        b_ips = [ip for ips in (_cached_ping(L["b_node"]).get("ips") or {}).values() for ip in ips]
        side = "b" if L.get("view_side") == "b" else "a"
        pub = {k: v for k, v in L.items() if k != "psk"}   # never expose the IPsec key to the browser
        out.append({**pub, "a_online": bool(la.get("ok")) or la.get("configs") is not None,
                    "b_online": bool(lb.get("ok")) or lb.get("configs") is not None,
                    "a_health": ah, "b_health": bh, "a_ips": a_ips, "b_ips": b_ips,
                    "view_side": side, "view_name": (L["b_name"] if side == "b" else L["a_name"]),
                    "drift": link_drift(L["id"]), **tfl.get(L["id"], {})})
    return {"links": out, "total": total, "offset": off, "limit": lim}


def api_link_view(d):
    """Toggle which node's iface the tunnel's traffic figures are read from (a<->b)."""
    _require(d, ["id"])
    with _reg_lock:
        links = load_links()
        side = None
        for x in links:
            if x["id"] == d["id"]:
                side = "a" if x.get("view_side") == "b" else "b"   # flip
                x["view_side"] = side
                break
        if side is None:
            raise ValueError("link not found")
        save_json(LINKS_FILE, links)
    return {"ok": True, "view_side": side}


def api_traffic_reset(d):
    """Zero the cumulative traffic total for a tunnel (both ends) or a port-forward; live rates untouched."""
    d = d or {}
    if d.get("id"):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)
        if not L:
            raise ValueError("link not found")
        _tf_reset(L["a_node"], [L["name"]])
        _tf_reset(L["b_node"], [L["name"]])
        return {"ok": True}
    if d.get("node") and d.get("name"):
        n = get_node(d["node"])
        if not n:
            raise ValueError("node not found")
        _tf_reset(n["id"], ["pf:" + str(d["name"])])
        return {"ok": True}
    raise ValueError("missing id or node/name")


def _link_nodes(d):
    L = next((x for x in load_links() if x.get("id") == (d or {}).get("id")), None)
    return (L["a_node"], L["b_node"]) if L else (None, None)


def _default_tunnel_port(ttype, tid):
    if ttype == "vxlan":
        return 4789
    if ttype in ("l2tpv3", "fou", "core"):
        return 20000 + int(tid)
    return None


def _port_bindings(ttype, port, transport, server_side, tid, A, B):
    """The (node, port, proto) sockets a tunnel will actually LISTEN on — the set whose
    freeness must be verified before building. Scope per the tunnel model:
      core (bip): only the server node binds; the client dials from a random ephemeral
                    port, so it is never checked. proto follows transport (udp|tcp).
      fou/l2tpv3/vxlan: BOTH nodes decap on that UDP port.
      gre/sit/ipip/ipsec: no listening L4 port -> nothing to check."""
    p = int(port or _default_tunnel_port(ttype, tid) or 0)
    if not p:
        return []
    if ttype == "core":
        srv = A if (server_side or "a") == "a" else B
        t = (transport or "udp").lower()
        if t in ("raw", "flux"):
            return []                        # raw-IP / rotating-protocol carrier — no fixed L4 port to portcheck
        return [(srv, p, "tcp" if t in ("tcp", "ws") else "udp")]  # ws is a TCP/WebSocket carrier
    if ttype in ("fou", "l2tpv3", "vxlan"):
        return [(A, p, "udp"), (B, p, "udp")]
    return []


def _guard_port_conflicts(bindings, exclude=frozenset()):
    """Ask each target node whether the port it will bind is already in use (by ANY
    service — Xray/nginx/x-ui/…, not just our tunnels) and raise a clear Persian error
    if so. `exclude` holds (node_id, port, proto) tuples the edited tunnel already owns,
    so a tunnel never conflicts with itself. Nodes too old to know `portcheck` (or briefly
    unreachable) are skipped rather than hard-blocked."""
    for node, port, proto in bindings:
        if (node["id"], int(port), proto) in exclude:
            continue
        r = node_call(node, "portcheck", "POST", {"port": port, "proto": proto}, timeout=10)
        if not r.get("ok"):
            continue  # unknown endpoint (old agent) / offline -> can't verify, don't block the build
        if r.get("busy"):
            who = str(r.get("who") or "").strip()
            tail = f" — {who}" if who else ""
            raise ValueError(f"پورتِ {port}/{proto.upper()} روی نودِ «{node['name']}» اشغال است{tail}؛ یک پورتِ دیگر انتخاب کن")


def _spoof_fields(d, transport, profile, cipher, cur=None):
    """Validate and return the raw-bip IP-spoofing fields to store on a core link. Spoofing forges the
    outer IPv4 addresses so an on-path censor sees a decoy instead of the real server; it only applies
    to transport=raw + profile=bip + crypto on. spoof_dst is the decoy destination; spoof_src an
    optional forged source. The node applies these per role (see tnl-node _core_config). cur (the
    existing link) supplies edit defaults so an edit that omits the fields keeps the stored values
    (mirroring _flux_fields/_ws_fields/_fec_fields) instead of silently wiping the decoy config."""
    out = {}
    if transport != "raw" or profile != "bip" or cipher == "none":
        return out
    cur = cur or {}
    src = str((d["spoof_src"] if "spoof_src" in d else cur.get("spoof_src")) or "").strip()
    dst = str((d["spoof_dst"] if "spoof_dst" in d else cur.get("spoof_dst")) or "").strip()
    if src and not is_ipv4(src):
        raise ValueError("آی‌پیِ مبدأِ جعلی نامعتبر است (باید IPv4 باشد)")
    if dst and not is_ipv4(dst):
        raise ValueError("آی‌پیِ طُعمه (مقصد) نامعتبر است (باید IPv4 باشد)")
    if src:
        out["spoof_src"] = src
    if dst:
        out["spoof_dst"] = dst
    return out


def _flux_fields(d, transport, cipher, cur=None):
    """Validate and return the flux carrier fields to store on a core link. flux is a polymorphic
    moving-target transport whose IP protocol (raw carrier) or UDP ports (udp carrier) rotate every
    epoch on a clock-derived schedule both ends compute with no wire signal. Crypto is mandatory —
    the rotating shape is derived from the AEAD PSK. cur (the existing link) supplies edit defaults."""
    out = {}
    if transport != "flux":
        return out
    if cipher == "none":
        raise ValueError("حاملِ flux به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
    cur = cur or {}
    carrier = str(d.get("flux_carrier") or cur.get("flux_carrier") or "udp").strip().lower()
    if carrier not in ("udp", "raw", "stun"):
        raise ValueError("حاملِ flux نامعتبر است (udp / stun / raw)")
    out["flux_carrier"] = carrier
    rot = int(d.get("flux_rotate_secs") or cur.get("flux_rotate_secs") or 600)
    if rot < 10 or rot > 86400:
        raise ValueError("بازهٔ چرخشِ flux باید بین ۱۰ تا ۸۶۴۰۰ ثانیه باشد")
    out["flux_rotate_secs"] = rot
    shape = str(d.get("flux_shape") or cur.get("flux_shape") or "random").strip().lower()
    if shape not in ("random", "quic", "video", "webrtc"):
        raise ValueError("پروفایلِ شکلِ flux نامعتبر است")
    out["flux_shape"] = shape
    # The manual epoch offset ("rotate now") is not a form field: preserve it across edits,
    # and let a caller (api_flux_rotate) pass an explicit bumped value.
    out["flux_epoch_offset"] = int(d.get("flux_epoch_offset") or cur.get("flux_epoch_offset") or 0)
    return out


def _fec_fields(d, transport, cur=None):
    """FEC (forward error correction) on the datagram carriers (udp/raw/flux): repairs lost
    packets from parity so a throttled/high-loss link stays usable without retransmits. It is
    ignored on tcp/ws (TCP is already reliable). Both ends get the same setting (this link).
    cur (the existing link) supplies edit defaults. Returns {} when off / not applicable."""
    out = {}
    if transport not in ("udp", "raw", "flux"):
        return out
    cur = cur or {}
    fec = bool(d.get("fec")) if ("fec" in d) else bool(cur.get("fec"))
    if not fec:
        return out
    out["fec"] = True
    fd = int(d.get("fec_data") or cur.get("fec_data") or 10)
    fp = int(d.get("fec_parity") or cur.get("fec_parity") or 3)
    if fd < 1 or fp < 1 or fd + fp > 255:
        raise ValueError("مقادیرِ FEC نامعتبر است (داده و پریتی هر کدام ≥۱، مجموع ≤۲۵۵)")
    out["fec_data"] = fd
    out["fec_parity"] = fp
    return out


def _ws_fields(d, transport, cur=None):
    """Validate and return the ws (WebSocket/CDN) carrier fields. ws_host is the Host
    header + TLS SNI (the fronting/origin domain); ws_path the request path; ws_tls makes
    the client speak wss to a CDN edge. cur supplies edit defaults."""
    out = {}
    if transport != "ws":
        return out
    cur = cur or {}
    # "key in d" (not `or cur`) so an explicit empty value from an edit CLEARS the field; an
    # omitted key keeps the stored one. The ws form always sends these keys, so blanking works.
    host = str((d["ws_host"] if "ws_host" in d else cur.get("ws_host")) or "").strip()
    if host and not re.match(r"^[A-Za-z0-9.-]{1,253}$", host):
        raise ValueError("دامنهٔ WebSocket (ws_host) نامعتبر است")
    if host:
        out["ws_host"] = host
    path = str((d["ws_path"] if "ws_path" in d else cur.get("ws_path")) or "").strip()
    if path:
        if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", path):
            raise ValueError("مسیرِ WebSocket (ws_path) نامعتبر است (باید با / شروع شود)")
        out["ws_path"] = path
    tls = d.get("ws_tls") if ("ws_tls" in d) else cur.get("ws_tls")
    if bool(tls):
        if not host:
            raise ValueError("برای wss (TLS به CDN) باید دامنه (ws_host) را وارد کنی")
        out["ws_tls"] = True
    edge = str((d["edge_ip"] if "edge_ip" in d else cur.get("edge_ip")) or "").strip()  # CDN edge; explicit empty clears
    if edge:
        eh = edge.rpartition(":")[0] or edge
        if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", eh):
            raise ValueError("آدرسِ لبهٔ CDN (edge_ip) نامعتبر است")
        out["edge_ip"] = edge
    return out


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
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"نودِ «{A['name']}» آفلاین است")
    if not pb.get("ok"):
        raise ValueError(f"نودِ «{B['name']}» آفلاین است")
    a_ips = [ip for ips in pa.get("ips", {}).values() for ip in ips]
    b_ips = [ip for ips in pb.get("ips", {}).values() for ip in ips]
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()  # operator's explicit pick
    if want_a and want_a not in a_ips:
        raise ValueError(f"آی‌پیِ «{want_a}» روی نودِ «{A['name']}» نیست")
    if want_b and want_b not in b_ips:
        raise ValueError(f"آی‌پیِ «{want_b}» روی نودِ «{B['name']}» نیست")
    a_ip = want_a or (a_ips[0] if a_ips else None)
    b_ip = want_b or (b_ips[0] if b_ips else None)
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("could not determine node IPs")
    if a_ip == b_ip:
        raise ValueError("آی‌پیِ دو سرِ تونل یکی است؛ برای هر طرف یک آی‌پیِ متفاوت انتخاب کن")
    new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])  # block only a TRUE duplicate: same type on the same ip-pair
    for L in load_links():  # (a multi-ip pair may legitimately have several tunnels on different ips)
        same_pair = frozenset([(L.get("a_node"), L.get("a_ip")), (L.get("b_node"), L.get("b_ip"))]) == new_pair
        if L.get("type") == ttype and same_pair:
            raise ValueError(f"یک تونلِ {ttype} با همین آی‌پی‌ها بینِ این دو نود از قبل هست")
        if ttype in IPIP_FAMILY and L.get("type") in IPIP_FAMILY and same_pair:  # ipip/fou can't share an ip-pair
            raise ValueError(f"تونلِ «{L.get('name')}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.")
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
    _cs = str(d.get("subnet") or "").strip()
    if _cs and "/" not in _cs:
        raise ValueError("سابنت باید پیشوند داشته باشد — مثلاً 192.168.9.0/24")
    subnet = norm_subnet(ttype, tid, d.get("subnet"), d.get("subnet_base"))
    name = f"core{tid}" if ttype == "core" else f"{ttype}{tid}"   # core interface is core<id>
    extra = {}   # values generated ONCE here so both ends match and edit/rebuild can replay them
    if ttype in ("l2tpv3", "fou", "core"):
        port = int(d.get("port") or 0) or (20000 + tid)
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (۱ تا ۶۵۵۳۵)")
        extra["port"] = port
    if ttype == "vxlan":   # VXLAN UDP port is settable (default 4789) — stored so edit/rebuild replay it
        port = int(d.get("port") or 4789)
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (۱ تا ۶۵۵۳۵)")
        extra["port"] = port
    if ttype == "ipsec":
        extra["psk"] = secrets.token_hex(32)   # shared ESP key material for both sides
    server_side = None
    if ttype == "core":
        cipher = str(d.get("cipher") or "auto").strip().lower()
        if cipher not in CORE_CIPHERS:
            raise ValueError("روشِ رمزنگاری نامعتبر است")
        extra["cipher"] = cipher
        if cipher != "none":
            extra["psk"] = secrets.token_hex(32)   # shared AEAD key, never sent to the browser
        transport = str(d.get("transport") or "udp").strip().lower()
        if transport not in ("udp", "tcp", "raw", "flux", "ws"):
            raise ValueError("حاملِ اتصال نامعتبر است")
        extra["transport"] = transport
        if transport == "raw":                     # raw-IP carrier: which protocol wraps the sealed frame
            if cipher == "none":
                raise ValueError("حاملِ raw به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
            profile = str(d.get("raw_profile") or "bip").strip().lower()
            if profile not in CORE_RAW_PROFILES:
                raise ValueError("پروفایلِ raw نامعتبر است")
            extra["raw_profile"] = profile
            extra.update(_spoof_fields(d, transport, profile, cipher))   # decoy / source spoofing (bip only)
        if transport == "flux":                    # polymorphic moving-target carrier (udp|raw), crypto required
            extra.update(_flux_fields(d, transport, cipher))
        if transport == "ws":                      # WebSocket carrier (CDN-frontable)
            extra.update(_ws_fields(d, transport))
        extra.update(_fec_fields(d, transport))    # FEC (datagram carriers only); {} elsewhere
        if bool(d.get("obfs")):                    # anti-DPI needs the AEAD key
            if cipher == "none":
                raise ValueError("استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
            extra["obfs"] = True
        cover = bool(d.get("cover")) and transport == "tcp"   # TLS cover (HTTPS camouflage) is TCP-only; ignore on UDP/raw
        if cover and cipher == "none":   # the REALITY-style cover carries a PSK-authenticated token — it needs the AEAD key
            raise ValueError("پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        cover_sni = str(d.get("cover_sni") or "").strip()
        if cover_sni and not re.match(r"^[A-Za-z0-9.-]{1,253}$", cover_sni):
            raise ValueError("دامنهٔ نمایشی (SNI) نامعتبر است")
        if cover and not cover_sni:   # required: no imposed default SNI
            raise ValueError("برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی")
        if cover:
            extra["cover"] = True
            extra["cover_sni"] = cover_sni
        if bool(d.get("gso")):                     # TUN segmentation offload (throughput); any transport
            extra["gso"] = True
        server_side = "b" if str(d.get("server_side")) == "b" else "a"  # which node listens (operator's pick)
    # Refuse to build if the chosen port is already taken on a node that will bind it.
    _guard_port_conflicts(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B))
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name, **extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name, **extra}
    if ttype == "core":
        a_body["role"] = "server" if server_side == "a" else "client"
        b_body["role"] = "server" if server_side == "b" else "client"
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')}")
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        rr = node_call(A, "delete", "POST", {"name": name})  # roll back A side
        warn = "" if rr.get("ok") else f" — هشدار: '{name}' روی {A['name']} پاک نشد، دستی تمیزش کن"
        raise ValueError(f"نودِ «{B['name']}»: {rb.get('error') or rb.get('msg')} (تغییرات روی {A['name']} برگردانده شد){warn}")
    try:
        with _reg_lock:  # atomic append so a concurrent delete-link can't lose/resurrect a record
            links = load_links()
            links.append({"id": secrets.token_hex(6), "name": name, "type": ttype, "subnet": subnet,
                          "tunnel_id": tid, "a_node": A["id"], "a_name": A["name"], "a_ip": a_ip,
                          "b_node": B["id"], "b_name": B["name"], "b_ip": b_ip, "created": int(time.time()),
                          **extra, **({"server_side": server_side} if ttype == "core" else {})})
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
    # Serialize with create/edit/rebuild on the same node pair. Without this lock a
    # delete can interleave with an in-flight rebuild: the rebuild tears both ends
    # down, delete removes the record, then the rebuild recreates the interfaces
    # with no registry record behind them -> permanent orphan tunnels.
    with _PairLock(L["a_node"], L["b_node"]):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)  # re-read under the lock
        if not L:
            return {"ok": True}  # a concurrent op already deleted it
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
        _tf_forget(L["a_node"], [L["name"]])   # drop stale traffic totals so a reused tunnel name starts fresh
        _tf_forget(L["b_node"], [L["name"]])
        _refresh_cache([L["a_node"], L["b_node"]])
        return {"ok": True}


def _restore_link(A, B, L):
    """Best-effort rebuild of the OLD tunnel on both sides (used to roll back a failed edit)."""
    tid = int(L["tunnel_id"])
    for N, self_ip, peer_ip in ((A, L["a_ip"], L["b_ip"]), (B, L["b_ip"], L["a_ip"])):
        if N:
            body = {"type": L["type"], "self_ip": self_ip, "peer_ip": peer_ip,
                    "subnet": L["subnet"], "id": tid, "name": L["name"], **_tunnel_extra(L)}
            role = _core_role(L, N["id"])
            if role:
                body["role"] = role
            node_call(N, "tunnel", "POST", body, timeout=200)


def api_edit_link(d):
    a, b = _link_nodes(d)
    with _PairLock(a, b):  # serialize only with ops touching the same node(s)
        return _edit_link_impl(d)


def api_flux_rotate(d):
    """'Rotate now' for a flux link: bump the manual epoch offset by one and rebuild both
    ends with it. Both ends get the same offset, so the moving target jumps a shape ahead
    fleet-wide with no wire signal. Delegates to the edit path (which does the clean
    both-ends-down rebuild); only the offset changes, everything else stays as stored."""
    d = d or {}
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")
    if L.get("type") != "core" or (L.get("transport") != "flux"):
        raise ValueError("چرخشِ الان فقط برای لینکِ h-flux است")
    nxt = int(L.get("flux_epoch_offset") or 0) + 1
    a, b = _link_nodes({"id": d["id"]})
    with _PairLock(a, b):
        return _edit_link_impl({"id": d["id"], "type": "core", "flux_epoch_offset": nxt})


def _edit_link_impl(d):
    _require(d, ["id", "type"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("link not found")
    ttype = d["type"]
    if ttype not in TYPES:
        raise ValueError("bad type")
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise ValueError("a node of this link is no longer registered")
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"نودِ «{A['name']}» آفلاین است")
    if not pb.get("ok"):
        raise ValueError(f"نودِ «{B['name']}» آفلاین است")
    tid = int(L["tunnel_id"])
    a_ips = [ip for ips in pa.get("ips", {}).values() for ip in ips]
    b_ips = [ip for ips in pb.get("ips", {}).values() for ip in ips]
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()  # operator's explicit pick
    if want_a and want_a not in a_ips:
        raise ValueError(f"آی‌پیِ «{want_a}» روی نودِ «{A['name']}» نیست")
    if want_b and want_b not in b_ips:
        raise ValueError(f"آی‌پیِ «{want_b}» روی نودِ «{B['name']}» نیست")
    a_ip = (want_a if want_a in a_ips else
            (L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)))
    b_ip = (want_b if want_b in b_ips else
            (L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)))
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("could not determine node IPs")
    if a_ip == b_ip:
        raise ValueError("آی‌پیِ دو سرِ تونل یکی است؛ برای هر طرف یک آی‌پیِ متفاوت انتخاب کن")
    new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])  # block only a TRUE duplicate: same type on the same ip-pair
    for x in load_links():
        if x.get("id") == L["id"]:
            continue
        same_pair = frozenset([(x.get("a_node"), x.get("a_ip")), (x.get("b_node"), x.get("b_ip"))]) == new_pair
        if x.get("type") == ttype and same_pair:
            raise ValueError(f"یک تونلِ {ttype} با همین آی‌پی‌ها بینِ این دو نود از قبل هست")
        if ttype in IPIP_FAMILY and x.get("type") in IPIP_FAMILY and same_pair:  # ipip/fou can't share an ip-pair
            raise ValueError(f"تونلِ «{x.get('name')}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.")
    _cs = str(d.get("subnet") or "").strip()
    if _cs and "/" not in _cs:
        raise ValueError("سابنت باید پیشوند داشته باشد — مثلاً 192.168.9.0/24")
    # Fall back to the stored subnet when the request omits it, so a PARTIAL edit (e.g. flux
    # "rotate now", which sends only the epoch offset) doesn't silently reset a custom overlay
    # subnet to the type default and renumber both ends of the tunnel.
    subnet = norm_subnet(ttype, tid, d.get("subnet") or L.get("subnet"))
    old_name = L["name"]
    name_changed = ttype != L["type"]  # the interface name encodes the type (vxlanNN vs greNN)
    new_name = (f"core{tid}" if ttype == "core" else f"{ttype}{tid}") if name_changed else old_name
    extra = {}   # computed BEFORE the no-change check so a port-only edit isn't silently dropped as "unchanged"
    if ttype in ("l2tpv3", "fou", "core"):
        port = int(d.get("port") or 0) or (L.get("port") if L.get("type") in ("l2tpv3", "fou", "core") else 0) or (20000 + tid)
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (۱ تا ۶۵۵۳۵)")
        extra["port"] = port
    if ttype == "vxlan":
        port = int(d.get("port") or 0) or (L.get("port") if L.get("type") == "vxlan" else 0) or 4789
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (۱ تا ۶۵۵۳۵)")
        extra["port"] = port
    if ttype == "ipsec":
        extra["psk"] = L.get("psk") if (L.get("type") == "ipsec" and L.get("psk")) else secrets.token_hex(32)
    server_side = None
    if ttype == "core":
        cipher = str(d.get("cipher") or L.get("cipher") or "auto").strip().lower()
        if cipher not in CORE_CIPHERS:
            raise ValueError("روشِ رمزنگاری نامعتبر است")
        extra["cipher"] = cipher
        if cipher != "none":   # keep the existing key when crypto stays on; make one when turning it on
            extra["psk"] = L.get("psk") or secrets.token_hex(32)
        transport = str(d.get("transport") or L.get("transport") or "udp").strip().lower()
        if transport not in ("udp", "tcp", "raw", "flux", "ws"):
            raise ValueError("حاملِ اتصال نامعتبر است")
        extra["transport"] = transport
        if transport == "raw":                     # raw-IP carrier: which protocol wraps the sealed frame
            if cipher == "none":
                raise ValueError("حاملِ raw به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
            profile = str(d.get("raw_profile") or L.get("raw_profile") or "bip").strip().lower()
            if profile not in CORE_RAW_PROFILES:
                raise ValueError("پروفایلِ raw نامعتبر است")
            extra["raw_profile"] = profile
            extra.update(_spoof_fields(d, transport, profile, cipher, L))   # decoy / source spoofing (bip only); L preserves omitted fields
        if transport == "flux":                    # polymorphic moving-target carrier (udp|raw), crypto required
            extra.update(_flux_fields(d, transport, cipher, L))
        if transport == "ws":                      # WebSocket carrier (CDN-frontable)
            extra.update(_ws_fields(d, transport, L))
        extra.update(_fec_fields(d, transport, L)) # FEC (datagram carriers only); {} elsewhere
        # obfs/gso fall back to the stored value when the request omits the key, so a PARTIAL edit
        # (flux "rotate now" sends neither) doesn't strip the anti-DPI layer or the throughput
        # offload. A full form edit always sends both as booleans, so it still overrides correctly.
        if (bool(d.get("obfs")) if "obfs" in d else bool(L.get("obfs"))):
            if cipher == "none":
                raise ValueError("استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
            extra["obfs"] = True
        cover = bool(d.get("cover")) and transport == "tcp"   # TLS cover (HTTPS camouflage) is TCP-only; ignore on UDP/raw
        if cover and cipher == "none":   # the REALITY-style cover carries a PSK-authenticated token — it needs the AEAD key
            raise ValueError("پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        cover_sni = str(d.get("cover_sni") or "").strip()
        if cover_sni and not re.match(r"^[A-Za-z0-9.-]{1,253}$", cover_sni):
            raise ValueError("دامنهٔ نمایشی (SNI) نامعتبر است")
        if cover and not cover_sni:   # required: no imposed default SNI
            raise ValueError("برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی")
        if cover:
            extra["cover"] = True
            extra["cover_sni"] = cover_sni
        if (bool(d.get("gso")) if "gso" in d else bool(L.get("gso"))):   # TUN segmentation offload; fall back to stored on a partial edit
            extra["gso"] = True
        server_side = d.get("server_side") if d.get("server_side") in ("a", "b") else (L.get("server_side") or "a")
    # Compare against the effective stored port: a record created before the
    # settable-port feature has no "port" key, so fall back to the type's default
    # (4789 for vxlan, 20000+id otherwise). Without this a no-op edit of a legacy
    # link reads as changed and forces a needless rebuild (a brief outage).
    _defport = 4789 if ttype == "vxlan" else (20000 + tid)
    port_same = ("port" not in extra) or (extra["port"] == (L.get("port") or _defport))
    core_same = ttype != "core" or (
        extra.get("cipher") == L.get("cipher") and server_side == (L.get("server_side") or "a")
        and (extra.get("transport") or "udp") == (L.get("transport") or "udp")
        and bool(extra.get("obfs")) == bool(L.get("obfs"))
        and bool(extra.get("cover")) == bool(L.get("cover"))
        and (extra.get("cover_sni") or "") == (L.get("cover_sni") or "")
        and (extra.get("raw_profile") or "") == (L.get("raw_profile") or "")
        and (extra.get("flux_carrier") or "") == (L.get("flux_carrier") or "")
        and (extra.get("flux_rotate_secs") or 0) == (L.get("flux_rotate_secs") or 0)
        and (extra.get("flux_shape") or "") == (L.get("flux_shape") or "")
        and (extra.get("flux_epoch_offset") or 0) == (L.get("flux_epoch_offset") or 0)
        and (extra.get("ws_host") or "") == (L.get("ws_host") or "")
        and (extra.get("ws_path") or "") == (L.get("ws_path") or "")
        and bool(extra.get("ws_tls")) == bool(L.get("ws_tls"))
        and (extra.get("edge_ip") or "") == (L.get("edge_ip") or "")
        and (extra.get("spoof_src") or "") == (L.get("spoof_src") or "")
        and (extra.get("spoof_dst") or "") == (L.get("spoof_dst") or "")
        and bool(extra.get("fec")) == bool(L.get("fec"))
        and (extra.get("fec_data") or 0) == (L.get("fec_data") or 0)
        and (extra.get("fec_parity") or 0) == (L.get("fec_parity") or 0)
        and bool(extra.get("gso")) == bool(L.get("gso")))
    # Non-core links may short-circuit an unchanged edit (avoids a needless outage). Core links must
    # NOT: the button is "save AND rebuild", and a core edit always does a clean both-ends-down rebuild
    # below (the only reliable way to un-wedge a tunnel), so never silently no-op it.
    if ttype != "core" and ttype == L["type"] and subnet == L["subnet"] and a_ip == L["a_ip"] and b_ip == L["b_ip"] and port_same and core_same:
        return {"ok": True, "unchanged": True, "name": old_name}
    # Port-conflict guard: only verify bindings that DIFFER from what this tunnel already
    # occupies (its current port/proto/server node are excluded so it can't clash with
    # itself). A binding that is unchanged needs no check; a new/changed one must be free.
    _own = frozenset((N["id"], p, pr) for N, p, pr in
                     _port_bindings(L.get("type"), L.get("port"), L.get("transport"), L.get("server_side"), tid, A, B))
    _guard_port_conflicts(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B), exclude=_own)
    # Pre-delete BOTH ends before rebuilding when the iface name changed (shared veth/OVS ids) OR for
    # any core link. Core needs it because an in-place, one-end-at-a-time restart leaves the peer running
    # its old crypto session: the freshly restarted server latches onto the stale still-live client and
    # never re-handshakes, so the tunnel stays wedged. Tearing both ends down together (exactly what the
    # standalone rebuild does) forces a clean simultaneous re-handshake. This is why "save & rebuild" used
    # to leave a core tunnel dead while a separate "rebuild" fixed it.
    if name_changed or ttype == "core":
        node_call(A, "delete", "POST", {"name": old_name})
        node_call(B, "delete", "POST", {"name": old_name})
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": new_name, "enabled": L.get("enabled", True), **extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": new_name, "enabled": L.get("enabled", True), **extra}
    if ttype == "core":
        a_body["role"] = "server" if server_side == "a" else "client"
        b_body["role"] = "server" if server_side == "b" else "client"
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        _restore_link(A, B, L)
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')} (تونلِ قبلی بازگردانده شد)")
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        if name_changed:
            node_call(A, "delete", "POST", {"name": new_name})
            node_call(B, "delete", "POST", {"name": new_name})
        _restore_link(A, B, L)
        raise ValueError(f"نودِ «{B['name']}»: {rb.get('error') or rb.get('msg')} (تونلِ قبلی بازگردانده شد)")
    with _reg_lock:
        links = load_links()
        for x in links:
            if x["id"] == L["id"]:
                x.update({"name": new_name, "type": ttype, "subnet": subnet, "a_ip": a_ip, "b_ip": b_ip})
                for k in ("port", "psk", "cipher", "transport", "obfs", "cover", "cover_sni", "raw_profile", "flux_carrier", "flux_rotate_secs", "flux_shape", "flux_epoch_offset", "fec", "fec_data", "fec_parity", "ws_host", "ws_path", "ws_tls", "edge_ip", "gso", "spoof_src", "spoof_dst"):   # keep only the extras this type uses; drop the rest
                    if k in extra:
                        x[k] = extra[k]
                    else:
                        x.pop(k, None)
                if ttype == "core":
                    x["server_side"] = server_side
                else:
                    x.pop("server_side", None)
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
        raise ValueError(f"نودِ «{A['name']}» آفلاین است")
    if not pb.get("ok"):
        raise ValueError(f"نودِ «{B['name']}» آفلاین است")
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
    if ttype in IPIP_FAMILY:  # rebuild may re-bind to a different live IP — don't land an ipip/fou onto a pair another owns
        new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])
        for x in load_links():
            if (x.get("id") != L["id"] and x.get("type") in IPIP_FAMILY
                    and frozenset([(x.get("a_node"), x.get("a_ip")), (x.get("b_node"), x.get("b_ip"))]) == new_pair):
                raise ValueError(f"بازسازی ممکن نیست: تونلِ «{x.get('name')}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.")
    node_call(A, "delete", "POST", {"name": name})  # tear down both ends first
    node_call(B, "delete", "POST", {"name": name})
    extra = _tunnel_extra(L)   # same UDP port / key / cipher as before
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name, "enabled": L.get("enabled", True), **extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name, "enabled": L.get("enabled", True), **extra}
    if ttype == "core":   # role is per-node, replayed from the stored server_side
        a_body["role"], b_body["role"] = _core_role(L, A["id"]), _core_role(L, B["id"])
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        _restore_link(A, B, L)   # both ends were pre-deleted; best-effort rebuild to the prior state
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')} (تلاش برای بازگردانی)")
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        _restore_link(A, B, L)
        raise ValueError(f"نودِ «{B['name']}»: {rb.get('error') or rb.get('msg')} (تلاش برای بازگردانی)")
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


def api_link_toggle(d):
    """Turn a tunnel on/off — bring its interface down/up on both nodes without rebuilding it. The panel
    record's `enabled` flag is the source of truth and is replayed to the nodes on edit/rebuild too, so a
    disabled tunnel stays down across reboots."""
    _require(d, ["id"])
    enabled = bool(d.get("enabled"))
    a, b = _link_nodes(d)  # resolve the two node ids so we can serialize with any in-flight edit/rebuild on this pair
    if not a or not b:
        raise ValueError("link not found")
    # Hold the pair lock across BOTH the record flip and the node push, so a concurrent edit/rebuild can't
    # interleave and leave a node in the opposite `enabled` state from the record. Lock order mirrors the
    # edit/rebuild paths: _PairLock outer, _reg_lock inner (deadlock-free).
    with _PairLock(a, b):
        with _reg_lock:
            links = load_links()
            L = next((x for x in links if x["id"] == d["id"]), None)
            if not L:
                raise ValueError("link not found")
            L["enabled"] = enabled
            save_json(LINKS_FILE, links)
        sides = {}
        for tag, nid in (("a", L["a_node"]), ("b", L["b_node"])):
            N = get_node(nid)
            if N:
                sides[tag] = node_call(N, "link-enable", "POST", {"name": L["name"], "enabled": enabled}, timeout=90)
        _refresh_cache([L["a_node"], L["b_node"]])
    both = len(sides) == 2 and all((sides.get(t) or {}).get("ok") for t in ("a", "b"))
    return {"ok": True, "enabled": enabled, "both": both, "sides": sides}


# --------------------------------------------------------------------------- link reconciler
# When a node's public IP changes, apply_all() on THAT node self-heals its own local_ip — but the
# PEER still points remote_ip at the old address, so the tunnel stays down until an operator rebuilds
# it. This loop closes the gap: it watches every link for a stored endpoint IP that has drifted off
# the node's live IP set, and rebuilds the link — which rewrites remote_ip on the peer AND the record.

RECONCILE_GAP = 15       # default seconds between reconcile sweeps (overridable via settings)
RECONCILE_RETRY = 60     # per-link cool-down so a failing rebuild can't hammer the pair
_reconcile_last = {}     # link_id -> last rebuild-attempt ts (touched only by the single reconcile thread)


def _reconcile_once():
    mode = get_settings().get("reconcile_mode", "alert")   # match settings_defaults(): default to alert-only, never auto-rebuild
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
        try:
            r = api_rebuild_link({"id": L["id"]})  # single-IP side(s): rebuild binds to the only live IP
            if r.get("ok"):
                _set_drift(L["id"], False)          # healed -> no cool-down (drift cleared, won't retry)
            else:
                _reconcile_last[L["id"]] = now      # ran and definitively failed -> back off before retrying
        except Exception:
            _reconcile_last[L["id"]] = now          # errored after a real attempt -> back off, don't hammer


def reconcile_loop():
    while True:
        time.sleep(max(5, int(get_settings().get("reconcile_interval", RECONCILE_GAP) or RECONCILE_GAP)))
        try:
            _reconcile_once()
        except Exception:
            pass


def _pf_field(k, v):
    """Validate+coerce ONE port-forward field before it is forwarded to a root node's iptables/ip
    handler. Port-forward is the fleet's most injection-prone endpoint (dst_ips/listen_ip/iface feed
    straight into `ip`/`iptables`), yet unlike every sibling tunnel-build endpoint it was relayed
    unvalidated. Raise ValueError on anything malformed so central never becomes the conduit; return
    the coerced value."""
    if k in ("listen_port", "dst_port"):
        p = _sint(v)
        if not 1 <= p <= 65535:
            raise ValueError(f"bad {k} (1..65535)")
        return p
    if k == "dst_ips":
        ips = v if isinstance(v, list) else [v]
        ips = [str(x).strip() for x in ips]
        if not ips or not all(is_ipv4(x) for x in ips):
            raise ValueError("dst_ips must be a non-empty list of IPv4 addresses")
        return ips
    if k == "listen_ip":
        s = str(v).strip()
        if not is_ipv4(s):
            raise ValueError("bad listen_ip")
        return s
    if k == "iface":
        s = str(v).strip()
        if not re.match(r"^[A-Za-z0-9._-]{1,15}$", s):   # Linux ifname charset + 15-char limit
            raise ValueError("bad iface")
        return s
    if k == "interval_min":
        m = _sint(v)
        if not 1 <= m <= 1440:
            raise ValueError("bad interval_min (1..1440)")
        return m
    return v


def api_portfw(d):
    _require(d, ["node", "listen_port", "dst_port", "dst_ips"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    body = {"listen_port": _pf_field("listen_port", d["listen_port"]),
            "dst_port": _pf_field("dst_port", d["dst_port"]),
            "dst_ips": _pf_field("dst_ips", d["dst_ips"]),
            "interval_min": _pf_field("interval_min", d.get("interval_min", 5))}
    if d.get("iface"):
        body["iface"] = _pf_field("iface", d["iface"])
    if d.get("listen_ip"):
        body["listen_ip"] = _pf_field("listen_ip", d["listen_ip"])
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
        node_ips = _flat_ips(_cached_ping(n["id"]))
        node_ip = node_ips[0] if len(node_ips) == 1 else ""  # single-IP node: its sole IP is the effective listen IP
        tf = _tf_read(n["id"])
        for c in r["configs"]:
            if c.get("type") != "portfw":
                continue
            if q and q not in n["name"].lower() and q not in str(c.get("name", "")).lower():
                continue
            t = tf.get("pf:" + str(c.get("name") or ""))  # live rx/tx rates + lifetime totals (may be absent)
            bw = ({"rx_bps": t["rx_bps"], "tx_bps": t["tx_bps"], "rx_total": t["crx"], "tx_total": t["ctx"]}
                  if t else {"rx_bps": 0.0, "tx_bps": 0.0, "rx_total": 0, "tx_total": 0})
            all_pf.append({"node": n["name"], "node_id": n["id"], "name": c.get("name"),
                           "iface": c.get("iface"), "listen_port": c.get("listen_port"),
                           "listen_ip": c.get("listen_ip") or "", "node_ip": node_ip,
                           "dst_port": c.get("dst_port"), "dst_ips": c.get("dst_ips", []),
                           "switch_interval": c.get("switch_interval", 0), "health": h.get(c.get("name")),
                           **bw})
    return {"portfw": all_pf[off:off + lim], "total": len(all_pf), "offset": off, "limit": lim}


def api_portfw_edit(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    body = {"name": d["name"]}
    for k in ("listen_port", "dst_port", "dst_ips", "interval_min", "iface", "listen_ip"):
        if d.get(k) not in (None, ""):
            body[k] = _pf_field(k, d[k])
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
    if r.get("ok"):
        _tf_forget(n["id"], ["pf:" + str(d["name"])])   # drop stale totals so a reused portfw id starts fresh
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
            peers.setdefault(L["a_ip"], []).append({"node": L.get("b_name") or "", "type": L.get("type") or "", "name": L.get("name") or ""})
        if L.get("b_node") == nid and L.get("b_ip"):
            peers.setdefault(L["b_ip"], []).append({"node": L.get("a_name") or "", "type": L.get("type") or "", "name": L.get("name") or ""})
    pf = {}  # ip -> [portfw names] using it (an IP carrying a forward is in use, not free)
    only_ip = live[0] if len(live) == 1 else ""   # single-IP node: a forward with no pin still uses that lone IP
    for c in (_cached_list(nid).get("configs") or []):
        if c.get("type") == "portfw":
            ip = c.get("listen_ip") or only_ip
            if ip:
                pf.setdefault(ip, []).append(c.get("name") or "")
    host = n.get("host")
    out = []
    for ip in live:
        pl = [p for p in peers.get(ip, []) if p["node"]]
        pfl = [x for x in pf.get(ip, []) if x]
        out.append({"ip": ip, "host": ip == host, "peers": pl, "pf": pfl, "free": (not pl and not pfl)})
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
        save_json(SETTINGS_FILE, obj)   # write under the lock — concurrent settings-set share one .tmp path and would corrupt it
    return {"ok": True, "settings": obj}


def api_signing_pubkey(d):
    """Return the panel's update-signing PUBLIC key (PEM) — safe to expose; the operator provisions it to nodes."""
    _, pub = _signing_keys()
    return {"pubkey": pub}


def api_provision_key(d):
    """Push the panel's public signing key to a node so it thereafter accepts ONLY signed code pushes.
    First-set on the node side; re-provisioning the identical key is a no-op."""
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("node not found")
    _, pub = _signing_keys()
    r = node_call(n, "set-update-key", "POST", {"pubkey": pub}, timeout=15)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    return {"ok": True}


def api_checkin_impl(source_ip, d):
    """Node -> central check-in. Authenticated by the node's own token (NOT a panel session). Lets a node
    whose public IP changed tell the panel where it moved to, so control traffic can find it again — the
    reconciler then heals the tunnels. We only adopt the new address when the panel currently CAN'T reach
    the node at its stored host, so a working DNS name / static host is never clobbered."""
    tok = str((d or {}).get("token") or "")
    if not tok:
        return {"ok": False, "error": "token required"}
    with _reg_lock:
        n = next((x for x in load_nodes() if hmac.compare_digest(str(x.get("token", "")), tok)), None)
        if not n:
            return {"ok": False, "error": "unknown node"}
        n_snap, host = dict(n), n.get("host")
    if not (source_ip and is_ipv4(source_ip) and host != source_ip):
        return {"ok": True, "updated": False, "host": host}
    # probe the CONFIGURED host LIVE (not the cached poll, which may have transiently failed); a working
    # DNS/static host must never be clobbered on a blip. node_call runs outside _reg_lock (no network in-lock).
    if node_call(n_snap, "ping", "GET", timeout=5).get("ok"):
        return {"ok": True, "updated": False, "host": host}
    probe = dict(n_snap)
    probe["host"] = source_ip
    if not node_call(probe, "ping", "GET", timeout=5).get("ok"):
        return {"ok": True, "updated": False, "host": host}  # old host down but new addr doesn't reach us -> reject
    with _reg_lock:  # re-find under lock (registry may have changed during the probes) and persist
        nodes = load_nodes()
        n = next((x for x in nodes if hmac.compare_digest(str(x.get("token", "")), tok)), None)
        if not n:
            return {"ok": False, "error": "unknown node"}
        n["host"], host, nid = source_ip, source_ip, n["id"]
        save_json(NODES_FILE, nodes)
    _refresh_cache([nid])  # re-probe at the new address at once so the fleet view + reconciler catch up
    return {"ok": True, "updated": True, "host": host}


API = {
    "nodes": api_nodes, "node-names": api_node_names, "summary": api_summary,
    "spoof-probe": api_spoof_probe,
    "settings": api_settings, "settings-set": api_settings_set,
    "node-add": api_node_add, "node-edit": api_node_edit, "node-del": api_node_del,
    "node-install": api_node_install, "install-status": api_node_install_status,
    "node-test": api_node_test, "node-meta": api_node_meta, "node-stats": api_node_stats,
    "node-ips": api_node_ips, "link-rebuild-info": api_link_rebuild_info,
    "traffic": api_node_traffic, "fleet": api_fleet,
    "create-tunnel": api_create_tunnel, "edit-link": api_edit_link, "check-link": api_check_link,
    "rebuild-link": api_rebuild_link, "delete-link": api_delete_link, "link-toggle": api_link_toggle,
    "flux-rotate": api_flux_rotate,
    "link-view": api_link_view, "traffic-reset": api_traffic_reset,
    "portfw": api_portfw, "portfw-list": api_portfw_list, "portfw-edit": api_portfw_edit,
    "portfw-next": api_portfw_next, "portfw-del": api_portfw_del,
    "agent-upload": api_agent_upload, "agent-info": api_agent_info, "agent-push": api_agent_push,
    "agent-fetch-git": api_agent_fetch_git,
    "core-versions": api_core_versions, "core-update": api_core_update,
    "core-upload": api_core_upload, "core-stage": api_core_stage, "core-push": api_core_push,
    "signing-pubkey": api_signing_pubkey, "provision-key": api_provision_key,
}
MUTATIONS = {"node-add", "node-install", "node-edit", "node-del", "create-tunnel", "edit-link", "rebuild-link",
             "delete-link", "link-toggle", "flux-rotate", "link-view", "traffic-reset", "portfw", "portfw-edit", "portfw-next", "portfw-del",
             "agent-upload", "agent-push", "agent-fetch-git", "settings-set", "core-update", "core-upload", "core-stage", "core-push",
             "provision-key"}

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
        # defense-in-depth CSP: the UI leans on inline scripts/handlers/styles and a Google-Fonts @import,
        # so 'unsafe-inline' is required for script/style; everything else is locked down.
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                         "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        # never cache: live JSON polls must stay fresh, and the HTML shell must never serve a stale
        # (old-JS) page after the panel is updated on the server — that stranded users on old behavior.
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self, cap=1048576):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        n = min(max(n, 0), cap)   # 1MB default — headroom for the agent-upload source (JSON-escaped)
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

    def _client_ip(self):
        # Behind a trusted TLS-terminating proxy (conf['tls']) every request shares the proxy's TCP address,
        # so keying the login limiter on it would let one attacker lock out ALL clients. Use the forwarded IP —
        # but ONLY when the direct TCP peer is actually a trusted proxy. Otherwise a client could spoof
        # X-Forwarded-For on every request to dodge the brute-force limiter entirely. The terminator normally
        # runs on loopback; set conf['trusted_proxies'] (a list of IPs) if it sits on another host.
        peer = self.client_address[0]
        conf = self._conf()
        if conf.get("tls"):
            trusted = conf.get("trusted_proxies")
            if isinstance(trusted, list) and trusted:
                peer_trusted = peer in trusted
            else:
                try:
                    peer_trusted = ipaddress.ip_address(peer).is_loopback
                except ValueError:
                    peer_trusted = False
            if peer_trusted:
                first = (self.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
                if first:
                    return first
        return peer

    def _login(self):
        ip = self._client_ip()
        if rate_limited(ip):
            self._send(429, {"error": "too many attempts, wait a few minutes"})
            return
        d = self._body()
        conf = self._conf()
        time.sleep(0.3)
        # Always run the (expensive) PBKDF2 check, even when the username is wrong,
        # so response time doesn't reveal whether a username exists. compare_digest
        # keeps the username check constant-time too.
        user_ok = hmac.compare_digest(str(d.get("user", "")), str(conf.get("user") or ""))
        pass_ok = verify_password(conf, str(d.get("pass", "")))
        if user_ok and pass_ok:
            secure = "; Secure" if conf.get("tls") else ""   # set conf["tls"]=true when TLS-fronted so the cookie never rides plain HTTP
            cookie = f"tnl_session={make_token(conf, conf['user'])}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict{secure}"
            self._send(200, {"ok": True}, extra={"Set-Cookie": cookie})
        else:
            note_fail(ip)
            self._send(401, {"error": "wrong username or password"})

    def _checkin(self):
        ip = self._client_ip()
        if rate_limited(ip):   # per-source-IP brute-force cap on token guessing (same limiter as _login)
            self._send(429, {"error": "too many attempts, wait a few minutes"})
            return
        try:  # like _api: a handler exception (e.g. mid-refresh) must still yield a clean response
            res = api_checkin_impl(self.client_address[0], self._body())
        except ValueError as e:
            self._send(400, {"error": str(e)})
            return
        except Exception as e:
            self._send(500, {"error": f"internal error: {str(e)[:120]}"})
            return
        if not res.get("ok"):
            note_fail(ip)
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
        # a custom core binary (base64) needs far more than the 1MB default; everything else keeps the tight cap
        d = self._body(cap=20971520 if cmd == "core-upload" else 1048576) if method == "POST" else query_dict(self.path)
        try:
            self._send(200, API[cmd](d))
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:
            self._send(500, {"error": f"internal error: {str(e)[:120]}"})

# ----------------------------------------------------------------------------- UI

LOGIN_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>ورود · کنترل فلیت</title>
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
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>tnl · کنترل فلیت</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;800&display=swap');
:root{--acc:#4d6bf0;--acc2:#12a5b8;--ok:#2f9e6f;--bad:#d1524a;--gold:#bd7f18;
--page:#eef1f6;--card:#ffffff;--side:#ffffff;--glass:#f1f4f8;--field:#f4f6fa;--bord:#e5e9f0;
--tx:#232b36;--sub:#727e8c;--chart1:#6d5cf0;--chart2:#12a5b8;--hi:transparent;--dsh:0 10px 26px -18px rgba(40,60,100,.2);
--accw:#eef1fe;--okw:#e8f6ef;--badw:#fbeceb;--warnw:#f7efe0;--goldw:color-mix(in srgb,var(--gold) 16%,transparent);--sh-sm:0 1px 2px rgba(20,30,50,.05)}
body.dark{--acc:#6f8dff;--acc2:#3fd0e0;--ok:#4ec99a;--bad:#f0736a;--gold:#e0a83a;
--page:#0e1420;--card:#161f2e;--side:#111826;--glass:#1a2333;--field:#131c29;--bord:#243040;
--tx:#e6ecf4;--sub:#8b98aa;--chart1:#8f9dff;--chart2:#3fd0e0;--hi:transparent;--dsh:0 14px 34px -20px rgba(0,0,0,.6);
--accw:rgba(111,141,255,.14);--okw:rgba(78,201,154,.13);--badw:rgba(240,115,106,.13);--warnw:rgba(224,168,58,.12);--sh-sm:0 1px 2px rgba(0,0,0,.3)}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
html{height:100%;background:var(--page)}
body{font-family:Vazirmatn,Tahoma,sans-serif;color:var(--tx);background:var(--page);min-height:100vh;touch-action:manipulation}
.shell{display:flex;min-height:100vh}
.side{width:236px;flex:0 0 236px;background:var(--side);border-inline-start:1px solid var(--bord);padding:18px 13px;display:flex;flex-direction:column;position:sticky;top:0;height:100vh;overflow-y:auto;z-index:40}
.sbrand{display:flex;align-items:center;gap:9px;padding:2px 6px 6px;font-size:17px;font-weight:800;direction:ltr}
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
.mtop .sbrand{font-size:14px;padding:0;letter-spacing:.3px;direction:ltr}
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
/* accordion tunnel/core cards */
.card.acc{padding:0}
.card.acc.off{opacity:.72}
.chead{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;user-select:none}
.chead:hover{background:color-mix(in srgb,var(--acc) 4%,transparent)}
.hmain{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1}
.hrow1{display:flex;align-items:center;gap:8px;min-width:0}
.hrow2{display:flex;align-items:center;gap:10px;font-size:10.5px;color:var(--sub);white-space:nowrap;font-variant-numeric:tabular-nums}
.card.open .hrow2{display:none}
.hname{font-size:13.5px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:40%}
.ctag{font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px;background:var(--field);color:var(--sub);flex:0 0 auto}
.ctag.core{background:var(--accw);color:var(--acc)}
.hpeers{margin-inline-start:auto;display:flex;align-items:center;gap:5px;font-size:11.5px;font-weight:700;white-space:nowrap;color:var(--tx)}
.chev{width:16px;height:16px;color:var(--sub);transition:transform .2s;flex:0 0 auto}
.card.open .chev{transform:rotate(180deg)}
.cbody{max-height:0;overflow:hidden;transition:max-height .28s ease}
.card.open .cbody{max-height:720px}
.cbody-in{padding:12px 14px 14px;border-top:1px solid var(--bord)}
.offtxt{color:var(--bad);font-weight:700}
.offbadge{margin-top:11px;font-size:11.5px;color:var(--bad);display:flex;gap:7px;align-items:flex-start;line-height:1.6}
.tsw{width:38px;height:22px;border-radius:20px;background:var(--bord);position:relative;flex:0 0 auto;cursor:pointer;transition:.15s}
.tsw::after{content:"";position:absolute;top:3px;right:3px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.15s;box-shadow:0 1px 2px rgba(0,0,0,.3)}
.tsw.on{background:var(--ok)}.tsw.on::after{right:19px}
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
.tag.portfw{color:#fb923c;border-color:color-mix(in srgb,#fb923c 40%,transparent)}
.tag.ipip{color:#14b8a6;border-color:color-mix(in srgb,#14b8a6 45%,transparent)}
.tag.l2tpv3{color:#8b5cf6;border-color:color-mix(in srgb,#8b5cf6 45%,transparent)}
.tag.fou{color:#ec4899;border-color:color-mix(in srgb,#ec4899 45%,transparent)}
.tag.ipsec{color:#f43f5e;border-color:color-mix(in srgb,#f43f5e 45%,transparent)}
.nact{display:flex;gap:8px;margin-top:13px;flex-wrap:wrap}
button.act{display:inline-flex;align-items:center;gap:5px;background:var(--glass);border:1px solid var(--bord);color:var(--tx);border-radius:11px;padding:8px 12px;cursor:pointer;font-size:12.5px;font-family:inherit}
button.act:active{transform:scale(.97)}button.act .ic{width:14px;height:14px}
button.act.danger{color:var(--bad)}button.act.danger:hover{border-color:color-mix(in srgb,var(--bad) 45%,transparent)}
label{display:block;font-size:12px;color:var(--sub);margin:13px 2px 6px}
input,select{width:100%;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-size:13.5px;font-family:inherit}
input:focus,select:focus{outline:none;border-color:color-mix(in srgb,var(--acc) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}
.edit{margin-top:13px;padding:13px;border-radius:13px;background:var(--field);border:1px solid var(--bord)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:0 14px}
.ipsec{display:flex;align-items:center;gap:6px;font-weight:700;color:var(--tx);font-size:13px;margin:16px 2px 8px}
.primary{margin-top:18px;background:var(--acc);color:#fff;border:0;font-weight:800;padding:12px 18px;border-radius:12px;cursor:pointer;font-family:inherit;box-shadow:0 9px 20px -11px color-mix(in srgb,var(--acc) 70%,transparent)}
.primary:active{transform:scale(.98)}
.ghost{margin-top:18px;margin-inline-start:8px;background:var(--glass);border:1px solid var(--bord);color:var(--sub);padding:12px 16px;border-radius:14px;cursor:pointer;font-family:inherit}
.msg{margin-top:13px;font-size:12.5px;min-height:18px}.msg.ok{color:var(--ok)}.msg.err{color:var(--bad)}
.msg:empty{margin-top:0;min-height:0}
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
/* ===== overview: accurate fleet stats ===== */
.ohero{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.oscore{font-size:44px;font-weight:800;line-height:1;font-variant-numeric:tabular-nums}
.oscore-l{font-size:11.5px;color:var(--sub);margin-top:3px}
.ochips{display:flex;gap:7px;flex-wrap:wrap;margin-inline-start:auto;justify-content:flex-end}
.ochip{font-size:11px;font-weight:700;padding:4px 10px;border-radius:20px;background:var(--field);border:1px solid var(--bord);white-space:nowrap}
.ochip b{font-weight:800;font-variant-numeric:tabular-nums}
.ochip.a{background:var(--accw);color:var(--acc);border-color:transparent}
.ochip.o{background:var(--okw);color:var(--ok);border-color:transparent}
.ochip.w{background:var(--warnw);color:var(--gold);border-color:transparent}
.ochip.b{background:var(--badw);color:var(--bad);border-color:transparent}
.oalert{display:flex;align-items:center;gap:10px;padding:10px 2px;border-bottom:1px solid var(--bord)}
.oalert:last-child{border-bottom:0}
.oalert .msg{font-size:12.5px;font-weight:600;min-width:0}.oalert .msg b{font-weight:800}
.oalert .go{margin-inline-start:auto;font-size:11px;color:var(--acc);font-weight:700;white-space:nowrap;cursor:pointer}
.ohcard{overflow:visible}
.oheat{display:flex;gap:4px;align-items:flex-end;height:66px;direction:ltr;position:relative}
.hbar{flex:1;border-radius:5px 5px 3px 3px;min-height:8px;cursor:pointer;transition:filter .12s}
.hbar:active{filter:brightness(1.12)}
.htip{position:absolute;bottom:calc(100% + 7px);transform:translateX(-50%);direction:rtl;background:var(--tx);color:var(--card);font-size:11px;font-weight:700;padding:4px 9px;border-radius:8px;white-space:nowrap;pointer-events:none;z-index:6;box-shadow:0 5px 16px rgba(0,0,0,.28)}
.htip span{opacity:.65;font-weight:600}
.htip::after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);border:5px solid transparent;border-top-color:var(--tx)}
.heat-lg{display:flex;gap:14px;margin-top:10px;font-size:11px;color:var(--sub);flex-wrap:wrap;justify-content:center}
.heat-lg span{display:inline-flex;align-items:center;gap:5px}.heat-lg i{width:9px;height:9px;border-radius:3px;display:inline-block}
.otrack{width:9px;height:9px;border-radius:3px;display:inline-block}
.wrow{display:flex;align-items:center;gap:10px;padding:8px 2px;border-bottom:1px solid var(--bord)}
.wrow:last-child{border-bottom:0}
.wrow .wk{font-size:12px;color:var(--sub);min-width:40px}.wrow .wnm{font-weight:800;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px}
.wrow .wbar{flex:1;height:7px;border-radius:20px;background:color-mix(in srgb,var(--sub) 20%,transparent);overflow:hidden;margin:0 4px}
.wrow .wbar i{display:block;height:100%;border-radius:20px}
.wrow .wpc{font-weight:800;font-size:12.5px;min-width:36px;text-align:left;font-variant-numeric:tabular-nums;direction:ltr}
.tst{display:flex;gap:9px}
.tst .tb{flex:1;text-align:center;background:var(--field);border:1px solid var(--bord);border-radius:12px;padding:11px 4px}
.tst .tb .n{font-size:20px;font-weight:800;font-variant-numeric:tabular-nums}.tst .tb .l{font-size:11px;color:var(--sub)}
.typebar{display:flex;height:12px;border-radius:20px;overflow:hidden;margin-top:11px;background:color-mix(in srgb,var(--sub) 16%,transparent)}
.typebar i{height:100%}
.typleg{display:flex;gap:12px;margin-top:8px;font-size:11px;color:var(--sub);justify-content:center;flex-wrap:wrap}
.typleg span{display:inline-flex;align-items:center;gap:5px}.typleg b{color:var(--tx)}
.onote{font-size:11.5px;color:var(--sub);background:var(--field);border:1px dashed var(--bord);border-radius:11px;padding:9px 11px;margin-top:11px}.onote b{color:var(--tx)}
.ostat2{display:grid;grid-template-columns:1fr 1fr;gap:11px;margin-bottom:11px}
.ostat2 .card{margin:0;text-align:center;padding:14px 10px}
.ostat2 .big{font-size:24px;font-weight:800;font-variant-numeric:tabular-nums}
.tf-tuns .tf-row{display:flex;align-items:center;gap:8px;padding:8px 2px;border-top:1px solid var(--bord);font-size:12px}
.tf-tuns .tf-row:first-child{border-top:0}
.tf-nm{display:flex;align-items:center;gap:6px;min-width:0;font-weight:700}.tf-nm .mono{font-size:11.5px}
.tf-fig{margin-inline-start:auto;display:flex;align-items:center;gap:10px;white-space:nowrap;font-variant-numeric:tabular-nums}.tf-fig .tot{color:var(--sub)}
/* traffic line on the tunnel card */
.ltraf{margin-top:10px;padding-top:9px;border-top:1px dashed var(--bord);display:flex;align-items:center;gap:13px;font-size:12px;font-variant-numeric:tabular-nums}.ltraf .tot{color:var(--sub);margin-inline-start:auto;display:flex;align-items:center;gap:6px}
.iso{direction:ltr;unicode-bidi:isolate}   /* keep a value+unit (and its ↓/↑) LTR so it never jumbles inside the RTL layout */
.tot .iso{display:inline-flex;gap:8px}
.act.flip{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 40%,transparent)}
.act.reset{color:var(--gold);border-color:color-mix(in srgb,var(--gold) 40%,transparent)}
.bigrow{display:flex;gap:18px;align-items:baseline;margin-bottom:4px}.bigrow .b{font-size:22px;font-weight:800;font-variant-numeric:tabular-nums}
.subline{font-size:12px;color:var(--sub);font-variant-numeric:tabular-nums}
/* slimmed node card: plain meta labels (NOT boxed — distinct from the .chip icon badge) */
.nchips{display:grid;grid-template-columns:auto auto;justify-content:start;gap:7px 16px;margin-top:9px}
.nchip{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:var(--sub)}
.nchip b{color:var(--tx);font-weight:700}.nchip .ic{width:13px;height:13px;color:var(--sub)}
/* uptime bar on the node card */
.upwrap{margin-top:11px}
.uptop{display:flex;align-items:center;font-size:11.5px;color:var(--sub);margin-bottom:6px}.uptop b{color:var(--tx)}.uptop .r{margin-inline-start:auto}
.upbar{display:flex;gap:2px;height:22px;direction:ltr}
.upbar i{flex:1;border-radius:2px;background:var(--ok);min-width:1px}.upbar i.d{background:var(--bad)}.upbar i.g{background:color-mix(in srgb,var(--sub) 28%,transparent)}
/* agent update page */
.agrow{display:flex;align-items:center;gap:10px;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--card);margin-bottom:8px;flex-wrap:wrap;box-shadow:var(--dsh)}
.agrow .name{font-weight:700;font-size:14px}.agrow .ver{font-size:11.5px;color:var(--sub)}
.agrow .agres{flex-basis:100%;margin:2px 0 0;min-height:0;font-size:11.5px}
.drop{border:1.5px dashed color-mix(in srgb,var(--acc) 45%,transparent);border-radius:13px;padding:18px;text-align:center;background:var(--accw);color:var(--sub);font-size:12.5px;cursor:pointer;margin-top:4px}.drop b{color:var(--acc)}
.banner{display:flex;align-items:center;gap:12px}.banner .v{font-size:13.5px;font-weight:800}
/* --- unified agent+core card (compact) --- */
.agx-uni{padding:13px}
.agx-uni .k{margin-bottom:10px}
.agx-uni .k .grow{flex:1}
.agx-meta{display:flex;flex-wrap:wrap;gap:5px 10px;align-items:center;font-size:11.5px;color:var(--sub);background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:8px 11px;margin-bottom:11px}
.agx-meta .sep{width:3px;height:3px;border-radius:50%;background:var(--sub);opacity:.5}
.agx-act{display:flex;gap:7px;flex-wrap:wrap}
.agx-act .primary,.agx-act .ghost{margin-top:0;padding:8px 13px;font-size:12px;border-radius:10px;display:inline-flex;align-items:center;gap:6px}
.agx-act .primary{flex:1;justify-content:center}
.agx-hint{font-size:10.5px;color:var(--sub);margin-top:8px;line-height:1.6}
.agx-div{height:1px;background:var(--bord);margin:12px -2px}
.agx-corlab{display:flex;align-items:center;gap:7px;font-size:12px;font-weight:800;margin-bottom:9px}
.agx-corlab .now{margin-inline-start:auto;font-weight:600;color:var(--sub);font-size:11px}
.agx-corrow{display:flex;gap:7px;align-items:center;flex-wrap:wrap}
.agx-corrow #cor_ver_box{flex:1;min-width:120px}
.agx-corrow .msbtn{margin-top:0;padding:8px 11px;font-size:12px;border-radius:10px}
.agx-mini{flex:0 0 auto;display:inline-flex;align-items:center;gap:5px;padding:8px 12px;border-radius:10px;font-family:inherit;font-weight:800;font-size:11.5px;cursor:pointer;border:1px solid transparent}
.agx-mini.pri{background:#8b5cf6;color:#fff}
.agx-mini.gho{background:var(--field);color:var(--tx);border:1px solid var(--bord)}
/* --- compact node row + per-node core picker --- */
.agx-row{position:relative;display:flex;align-items:center;gap:9px;background:var(--card);border:1px solid var(--bord);border-radius:12px;padding:9px 11px;margin-bottom:8px;flex-wrap:wrap;box-shadow:var(--dsh)}
.agx-row .nm{font-weight:800;font-size:13px}
.agx-pill{font-size:10.5px;font-weight:700;padding:2px 6px;border-radius:6px;font-family:ui-monospace,monospace;direction:ltr;background:var(--field);color:var(--sub);border:1px solid var(--bord)}
.agx-pill.cor{background:color-mix(in srgb,#8b5cf6 12%,transparent);color:#8b5cf6;border-color:color-mix(in srgb,#8b5cf6 26%,transparent)}
.agx-col{display:flex;flex-direction:column;gap:5px;flex:0 0 auto}
.agx-btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;font-family:inherit;font-weight:800;font-size:10.5px;padding:5px 10px;border-radius:8px;cursor:pointer;min-width:74px;border:1px solid var(--bord);background:var(--glass);color:var(--tx)}
.agx-btn .ic{width:13px;height:13px}
.agx-btn.cor{background:color-mix(in srgb,#8b5cf6 13%,transparent);color:#8b5cf6;border-color:color-mix(in srgb,#8b5cf6 30%,transparent)}
.agx-btn.up{background:color-mix(in srgb,var(--gold) 15%,transparent);color:var(--gold);border-color:color-mix(in srgb,var(--gold) 34%,transparent)}
.agx-btn:disabled{opacity:.45;cursor:not-allowed}
.agx-right{display:flex;flex-direction:column;gap:7px;min-width:0}
.agx-l1{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.agx-l2{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.agx-colb{display:flex;flex-direction:column;gap:5px;flex:0 0 auto;margin-inline-start:auto}
.stx{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;font-weight:700;color:var(--sub)}
.ico{width:18px;height:18px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-weight:900;font-size:12px}
.ico .ic{width:11px;height:11px}
.ico.ok{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
.ico.up{background:color-mix(in srgb,var(--gold) 20%,transparent);color:var(--gold)}
.ico.na{background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)}
.ico.offl{background:color-mix(in srgb,var(--sub) 18%,transparent);color:var(--sub)}
.agx-row .agres{flex-basis:100%;margin:2px 0 0;min-height:0;font-size:11.5px}
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
/* IP peer chip: tap to swap the label in place between node name and interface name */
.ippeer{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:4px 10px;border-radius:8px;background:var(--accw);color:var(--acc);cursor:pointer;user-select:none;transition:transform .12s,background .15s,color .15s}
.ippeer:active{transform:scale(.95)}
.ippeer .ipn{display:inline-flex;align-items:center;gap:4px}
.ippeer .ipi{display:none}
.ippeer.show .ipn{display:none}
.ippeer.show .ipi{display:inline}
.ippeer.show{background:var(--acc);color:#fff}
/* ===== add-node: mode switch + SSH auto-install progress ===== */
.seg{display:flex;background:var(--field);border:1px solid var(--bord);border-radius:12px;padding:4px;gap:4px;margin-bottom:14px}
.seg button{flex:1;border:0;background:transparent;color:var(--sub);font-family:inherit;font-weight:800;font-size:13px;padding:9px;border-radius:9px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:6px}
.seg button.on{background:var(--card);color:var(--acc);box-shadow:0 1px 3px rgba(20,30,50,.12)}
.seg button .ic{width:15px;height:15px}
.autonote{display:flex;gap:8px;align-items:flex-start;font-size:11.5px;color:var(--sub);background:var(--warnw);border:1px solid color-mix(in srgb,var(--gold) 30%,transparent);border-radius:11px;padding:10px 12px;margin-bottom:13px}
.autonote .ic{color:var(--gold);flex:0 0 auto;margin-top:1px}
.spoofsec{margin-top:12px;padding:12px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field)}
.spoofhd{display:flex;gap:8px;align-items:center;font-size:12.5px;font-weight:800;margin-bottom:2px}
.spoofhd .ic{color:var(--acc)}
.spoofcap{display:flex;gap:8px;align-items:flex-start;font-size:11px;line-height:1.65;border-radius:10px;padding:9px 11px;margin-top:10px}
.spoofcap .ic{flex:0 0 auto;margin-top:1px}
.spoofcap.ok{background:var(--okw);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.spoofcap.no{background:var(--badw);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 30%,transparent)}
.spoofcap.wait{background:var(--field);color:var(--sub);border:1px solid var(--bord)}
.spoofcap b{font-weight:800}
.authbox{border:1px solid var(--bord);border-radius:13px;background:var(--field);padding:11px;margin-top:16px;margin-bottom:12px}
.authhd{display:flex;align-items:center;gap:8px;margin-bottom:10px}
.authhd .t{font-size:12.5px;font-weight:800}
.authseg{margin-inline-start:auto;display:flex;background:var(--card);border:1px solid var(--bord);border-radius:9px;padding:3px;gap:3px}
.authseg button{border:0;background:transparent;color:var(--sub);font-family:inherit;font-weight:800;font-size:11.5px;padding:5px 12px;border-radius:7px;cursor:pointer}
.authseg button.on{background:var(--acc);color:#fff}
.authbox .fld2{width:100%;padding:11px 12px;border:1px solid var(--bord);border-radius:11px;background:var(--card);color:var(--tx);font-size:13px;font-family:inherit}
.authbox textarea.fld2{font-family:ui-monospace,Consolas,monospace;font-size:11px;direction:ltr;resize:vertical;min-height:74px}
.iwrap{margin-top:14px;border-top:1px solid var(--bord);padding-top:6px}
.ibanner{display:flex;align-items:center;gap:8px;border-radius:11px;padding:10px 12px;font-size:12.5px;font-weight:800;margin:8px 0 6px}
.ibanner.run{background:var(--accw);color:var(--acc)}
.ibanner.ok{background:var(--okw);color:var(--ok)}
.ibanner.err{background:var(--badw);color:var(--bad)}
.istep{display:flex;align-items:flex-start;gap:11px;padding:9px 0}
.istep-i{flex:0 0 auto;width:24px;height:24px;border-radius:50%;display:grid;place-items:center}
.istep-i.ok{background:var(--okw);color:var(--ok)}.istep-i.err{background:var(--badw);color:var(--bad)}
.istep-i.warn{background:var(--warnw);color:var(--gold)}.istep-i.warn .ic{width:14px;height:14px}
.istep-i.run{background:var(--accw)}.istep-i.wait{background:var(--field);border:1px solid var(--bord)}
.istep-b{min-width:0;flex:1}.istep-t{font-weight:700;font-size:13.5px}.istep.err .istep-t{color:var(--bad)}
.istep-s{color:var(--sub);font-size:11.5px}
.ispin{width:13px;height:13px;border:2.5px solid var(--accw);border-top-color:var(--acc);border-radius:50%;animation:isp 1s linear infinite}
@keyframes isp{to{transform:rotate(360deg)}}
.ilog{margin:8px 0 2px;background:#0c1220;border:1px solid var(--bord);border-radius:10px;padding:9px 11px;font-family:ui-monospace,Consolas,monospace;direction:ltr;text-align:left;font-size:10.5px;line-height:1.6;color:#d3ddea;white-space:pre-wrap;max-height:170px;overflow:auto}
.primary.done{background:var(--ok);box-shadow:none}
.bspin{display:block;margin:1px auto;width:19px;height:19px;border:3px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:isp .9s linear infinite}
button.act:disabled{opacity:.4;cursor:default}button.act:disabled:active{transform:none}
/* ===== delete-node: two-mode chooser ===== */
.medi.medi-bad{background:var(--badw);color:var(--bad)}
.delopt{display:block;width:100%;text-align:start;border:1px solid var(--bord);background:var(--field);border-radius:13px;padding:13px 14px;margin-bottom:11px;cursor:pointer;font-family:inherit;color:var(--tx);transition:border-color .14s,background .14s}
.delopt:hover{border-color:var(--acc)}.delopt:disabled{opacity:.5;pointer-events:none}
.delopt .do-t{display:flex;align-items:center;gap:8px;font-weight:800;font-size:14px}
.delopt .do-t .ic{width:17px;height:17px;color:var(--acc)}
.delopt .do-s{color:var(--sub);font-size:11.5px;margin-top:5px;padding-inline-start:25px}
.delopt.danger{border-color:color-mix(in srgb,var(--bad) 35%,transparent);background:var(--badw)}
.delopt.danger:hover{border-color:var(--bad)}
.delopt.danger .do-t,.delopt.danger .do-t .ic{color:var(--bad)}
.delopt.danger .do-s{color:color-mix(in srgb,var(--bad) 72%,var(--sub))}
.ipfree{font-size:10.5px;font-weight:700;color:var(--sub);border:1px dashed var(--bord);padding:2px 8px;border-radius:8px}
.ippf{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:4px 9px;border-radius:8px;background:color-mix(in srgb,#fb923c 15%,transparent);color:#fb923c}.ippf .ic{width:12px;height:12px}
/* settings: mode field + minimal mode popup */
.setfield{width:100%;display:flex;align-items:center;padding:11px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-family:inherit;font-weight:800;font-size:14px;cursor:pointer}
/* compact settings rows (option B) */
.setrow{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid var(--bord)}
.setrow:last-of-type{border-bottom:0}
.setlbl b{font-size:13px;font-weight:700;color:var(--tx)}
.setlbl span{display:block;font-size:11px;color:var(--sub);margin-top:1px}
.setctl{flex:0 0 auto;min-width:118px;max-width:150px}
.setctl>*{width:100%}
.setctl .setfield{padding:8px 12px;font-size:13px}
.setctl input.search{padding:8px 12px}
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
.tag.core{color:#8b5cf6;border-color:color-mix(in srgb,#8b5cf6 40%,transparent);background:color-mix(in srgb,#8b5cf6 12%,transparent)}
body.dark .tag.core{color:#a78bfa}
.tag.obfs{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent);text-transform:none;letter-spacing:0}
.tglbox{display:flex;align-items:center;gap:10px;margin-top:10px;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--field)}
.tglbox .tt{flex:1}.tglbox .tt b{font-size:12.5px;font-weight:700;display:block}
.tglbox .tt small{font-size:10.5px;color:var(--sub);display:block;margin-top:1px;line-height:1.5}
.tglbox.dis{opacity:.45;pointer-events:none}
.rl{font-size:9px;font-weight:800;border-radius:5px;padding:1px 5px;letter-spacing:.2px;flex:0 0 auto}
.rl.srv{color:var(--acc);background:var(--accw)}
.rl.cli{color:var(--gold);background:var(--goldw)}
.enclock{color:var(--ok);font-weight:700;display:inline-flex;align-items:center;gap:3px;direction:ltr}
.enclock .ic{width:12px;height:12px}
.enc{color:var(--bad);font-weight:700;display:inline-flex;align-items:center;gap:3px}.enc .ic{width:12px;height:12px}
/* two meta columns aligned EXACTLY under the two node boxes (same grid + hidden arrow as .tninfo) */
.enmeta{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:start;margin-top:11px;font-size:11.5px;color:var(--sub)}
.enmeta .emcol{min-width:0;display:flex;flex-direction:column;gap:4px}
.enmeta .emcol>div{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.enmeta .emcol>div.wrap{white-space:normal;overflow:visible}
.enmeta .emcol b{color:var(--tx);font-weight:700}
.enmeta .earrow{visibility:hidden}
.enmeta .emcol>div.feat{display:flex;align-items:center;gap:5px;flex-wrap:wrap;white-space:normal;overflow:visible}
.enmeta .emcol>div.tagrow{overflow:visible;white-space:nowrap}
.enmeta .feat .nofeat{opacity:.55}
.enmeta .emcol>div.enc-line{white-space:nowrap;overflow:visible}
.enmeta .enc-line .encval{color:var(--ok);font-weight:700;direction:ltr}
.stat{margin-inline-start:auto;display:inline-flex;align-items:center;gap:5px}
.sdot{width:7px;height:7px;border-radius:50%;flex:0 0 auto}
.sdot.ok{background:var(--ok);box-shadow:0 0 0 3px var(--okw)}
.sdot.warn{background:var(--gold);box-shadow:0 0 0 3px var(--goldw)}
.sdot.bad{background:var(--bad);box-shadow:0 0 0 3px var(--badw)}
.sdot.na{background:var(--sub)}
.stw{font-size:10px;font-weight:800}
.stw.warn{color:var(--gold)}.stw.bad{color:var(--bad)}.stw.na{color:var(--sub)}
.seg2{display:flex;gap:8px;margin:2px 0 11px}
.seg2 .segopt{flex:1;border:1.5px solid var(--bord);background:var(--field);border-radius:11px;padding:9px 8px;text-align:center;cursor:pointer;font-family:inherit;color:var(--tx);display:flex;flex-direction:column;gap:1px}
.seg2 .segopt b{font-size:12.5px;font-weight:800}
.seg2 .segopt span{font-size:10px;color:var(--sub)}
.pgrid{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:2px 0 4px}
.ptile{position:relative;border:1.5px solid var(--bord);background:var(--field);border-radius:12px;padding:9px 10px;cursor:pointer;font-family:inherit;text-align:start;color:var(--tx)}
.ptile .pn{font-size:13px;font-weight:800;direction:ltr;letter-spacing:.3px;text-transform:uppercase}
.ptile .pmeta{margin-top:2px;font-size:10px;color:var(--sub)}
.ptile.on{border-color:color-mix(in srgb,var(--acc) 60%,transparent);background:var(--accw)}
.ptile.on .pn{color:var(--acc)}
.ptile .best{position:absolute;top:7px;inset-inline-start:7px;font-size:9px;font-weight:800;color:var(--ok);background:var(--okw);border-radius:20px;padding:1px 6px}
.ptile .pwarn{position:absolute;top:9px;inset-inline-start:9px;width:7px;height:7px;border-radius:50%;background:var(--gold)}
.seg2 .segopt.on{border-color:var(--acc);background:var(--accw)}
.seg2 .segopt.on span{color:color-mix(in srgb,var(--acc) 80%,var(--sub))}
</style></head><body>
<div class="backdrop" onclick="drawer(false)"></div>
<div class="shell">
 <aside class="side" id="side">
  <div class="sbrand"><span class="logo"><span class="ic" data-ic="shield"></span></span><span>TUNNEL-MANAGER<small>کنترل فلیت</small></span></div>
  <nav class="nav" id="nav">
   <a class="navi" data-t="overview"><span class="ic" data-ic="dash"></span> نمای کلی</a>
   <a class="navi" data-t="nodes"><span class="ic" data-ic="server"></span> نودها<span class="ct" id="ct_nodes"></span></a>
   <a class="navi" data-t="tunnels"><span class="ic" data-ic="link"></span> تونل‌ها<span class="ct" id="ct_tunnels"></span></a>
   <a class="navi" data-t="portfw"><span class="ic" data-ic="globe"></span> پورت‌فوروارد<span class="ct" id="ct_portfw"></span></a>
   <a class="navi" data-t="core"><span class="ic" data-ic="cpu"></span> هستهٔ اختصاصی<span class="ct" id="ct_core"></span></a>
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
function tfRow(t){return '<div class="tf-row"><div class="tf-nm"><span class="mono">'+esc(t.name)+'</span><span class="tag '+esc(t.type)+'">'+esc(t.type)+'</span></div><div class="tf-fig"><span class="din iso">↓'+fmtRate(t.rx_bps)+'</span><span class="dout iso">↑'+fmtRate(t.tx_bps)+'</span><span class="tot iso">'+fmtBytes(num(t.rx_total)+num(t.tx_total))+'</span></div></div>'}
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
 lock:'<svg viewBox="0 0 24 24" '+_S+'><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
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
 swap:'<svg viewBox="0 0 24 24" '+_S+'><path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/></svg>',
 reset:'<svg viewBox="0 0 24 24" '+_S+'><path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5M12 8v4l3 2"/></svg>',
 moon:'<svg viewBox="0 0 24 24" '+_S+'><path d="M20 14a8 8 0 01-10-10 8 8 0 1010 10z"/></svg>',
 sun:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/></svg>',
 logout:'<svg viewBox="0 0 24 24" '+_S+'><path d="M15 12H4M9 7l-5 5 5 5M14 4h4a2 2 0 012 2v12a2 2 0 01-2 2h-4"/></svg>',
 menu:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 6h16M4 12h16M4 18h16"/></svg>',
 check:'<svg viewBox="0 0 24 24" '+_S+'><path d="M20 6 9 17l-5-5"/></svg>',
 dl:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 3v12m0 0 4-4m-4 4-4-4M4 21h16"/></svg>',
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
 search:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>',
 chev:'<svg viewBox="0 0 24 24" '+_S+'><path d="M6 9l6 6 6-6"/></svg>'
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

var cur='overview',NODES=[],FLEET=[],HIST=[],FRXHIST=[],FTXHIST=[],PF=[],TT=0,editingId=null,EDID=null,selTargets={},SEL={},SSI={},SSCB={},CHK={},CHECKING=0,UPWIN=1;
var SELN={},SELT={},selN=false,selT=false;  // bulk-select state (nodes / tunnels)
var LIM=25,PG={nodes:0,tunnels:0,portfw:0,agent:0,core:0},QRY={nodes:'',tunnels:'',portfw:'',agent:'',core:''},TOT={nodes:0,tunnels:0,portfw:0,agent:0,core:0},SEARCH_T=0,createTries=0,pfTries=0,AGMETA=null,PAL=null,PALIDX=0,PALITEMS=[],PALDATA={nodes:[],tuns:[]};
var CORE_CIPHERS=[{v:'auto',label:'خودکار'},{v:'aes-256-gcm',label:'aes-256-gcm'},{v:'aes-128-gcm',label:'aes-128-gcm'},{v:'chacha20-poly1305',label:'chacha20-poly1305'},{v:'xchacha20-poly1305',label:'xchacha20-poly1305'},{v:'none',label:'بدونِ رمز'}];
var TYPEITEMS=[{v:'vxlan',label:'VXLAN'},{v:'gre',label:'GRE'},{v:'sit',label:'SIT (IPv6)'},{v:'ipip',label:'IPIP'},{v:'l2tpv3',label:'L2TPv3'},{v:'fou',label:'IPIP-over-FOU'},{v:'ipsec',label:'IPsec'}];
var SUBNETRANGES=[{v:'192.168',label:'خودکار · 192.168.x (پیشنهادی)'},{v:'10',label:'خودکار · 10.x'},{v:'172.16',label:'خودکار · 172.16.x'},{v:'custom',label:'دلخواه (دستی وارد کن)'}];
var SUBNETRANGES2=[{v:'192.168',label:'192.168.x'},{v:'10',label:'10.x'},{v:'172.16',label:'172.16.x'}];
document.querySelectorAll('#nav .navi').forEach(function(p){p.onclick=function(){cur=p.dataset.t;drawer(false);render()}});
function setnav(){document.querySelectorAll('#nav .navi').forEach(function(p){p.classList.toggle('on',p.dataset.t==cur)})}
function drawer(open){document.body.classList.toggle('navopen',!!open)}
async function updateSidebar(){var s=await j('summary').catch(function(){return{}});
 setT('ct_nodes',num(s.nodes_total));setT('ct_tunnels',num(s.links));setT('ct_portfw',num(s.portfw));setT('ct_core',num(s.core));
}

// ===== styled single-select dropdown (same look as the node/target lists) =====
// items:[{v,label,sub}]  key:unique id  cb:optional fn-name called after a pick
function ssHTML(key,items,sel,ph,cb){SSI[key]=items;SSCB[key]=cb||'';
 if(sel==null&&items.length)sel=items[0].v;SEL[key]=sel;
 var cur=items.filter(function(x){return String(x.v)==String(sel)})[0];
 return '<button type="button" class="msbtn'+(cur?'':' ph')+'" id="ssb_'+key+'" onclick="ssToggle(\\''+key+'\\')"><span id="sst_'+key+'">'+(cur?esc(cur.label):esc(ph||'انتخاب کنید'))+'</span><span class="cv">'+ic('chev')+'</span></button>'}
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
function toolbar(kind,ph){return '<div class="toolbar"><input id="q_'+kind+'" class="search" placeholder="'+ph+'" value="'+esc(QRY[kind]||'')+'" oninput="onSearch(\\''+kind+'\\')"></div>'}
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
 var f=el('e_sub_'+EDID);if(f)f.value=subnetForBase(ssVal('lt_'+EDID),L.tunnel_id,ssVal('lsr_'+EDID));renderEditPort(EDID)}
var LEDTYPE='',LEDPORT='';
function renderEditPort(id){var w=el('lpx_'+id);if(!w)return;var t=ssVal('lt_'+id);
 var pre=(t==LEDTYPE&&LEDPORT!=null)?String(LEDPORT):'';
 if(t=='vxlan')w.innerHTML='<label>پورتِ UDP (خالی = 4789)</label><input id="le_port_'+id+'" inputmode="numeric" placeholder="4789" value="'+esc(pre)+'">';
 else if(t=='l2tpv3'||t=='fou')w.innerHTML='<label>پورتِ UDP (خالی = خودکار از شناسه)</label><input id="le_port_'+id+'" inputmode="numeric" placeholder="مثلا 51820" value="'+esc(pre)+'">';
 else w.innerHTML=''}

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
function go(t){cur=t;drawer(false);render()}
function ocol(p){return p>85?cssv('--bad'):p>60?cssv('--gold'):cssv('--ok')}
function heatTip(ev,bar){ev.stopPropagation();var box=bar.parentNode;var tip=box.querySelector('.htip');
 if(!tip){tip=document.createElement('div');tip.className='htip';box.appendChild(tip)}
 tip.innerHTML='<span>'+esc(bar.dataset.nm)+'</span> '+bar.dataset.info;
 tip.style.left=(bar.offsetLeft+bar.offsetWidth/2)+'px';tip.style.display='block';
 clearTimeout(box._tt);box._tt=setTimeout(function(){if(tip)tip.style.display='none'},2400)}
function overviewSkel(){el('view').innerHTML='<h1>'+ic('dash','var(--acc)')+' نمای کلی</h1><p class="sub">آمارِ دقیقِ فلیت — بدونِ میانگینِ گمراه‌کننده</p>'+
 '<div class="card ohero"><div><div class="oscore" id="o_score">—</div><div class="oscore-l">سلامتِ فلیت</div></div><div class="ochips" id="o_chips"></div></div>'+
 '<div class="sec">'+ic('warn','var(--acc)')+' نیازمندِ توجه</div><div class="card" id="o_alerts"><div class="muted" style="padding:8px 0">…</div></div>'+
 '<div class="sec">'+ic('grid','var(--acc)')+' همهٔ نودها یک‌نگاه</div><div class="card ohcard"><div class="oheat" id="o_heat"></div><div class="heat-lg"><span><i style="background:var(--ok)"></i>سالم</span><span><i style="background:var(--gold)"></i>هشدار (>۶۰٪)</span><span><i style="background:var(--bad)"></i>بحرانی (>۸۵٪)</span></div><div class="muted" style="text-align:center;margin-top:6px;font-size:11px" id="o_heat_c"></div></div>'+
 '<div class="sec">'+ic('server','var(--acc)')+' سرورِ مرکزی (این پنل)</div><div class="card"><div class="gauges">'+gaugeHTML('scpu','CPU')+gaugeHTML('sram','RAM')+gaugeHTML('sdisk','دیسک')+'</div></div>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' پرمصرف‌ترین نودها</div><div class="card" id="o_worst"><div class="muted" style="padding:8px 0">…</div></div>'+
 '<div class="sec">'+ic('link','var(--acc)')+' وضعیتِ تفکیکیِ تونل‌ها</div><div class="card"><div class="tst" id="o_tst"></div><div class="typebar" id="o_typebar"></div><div class="typleg" id="o_typleg"></div><div id="o_wtun"></div></div>'+
 '<div class="sec">'+ic('traf','var(--acc)')+' ترافیکِ فلیت<span class="lpill"><span class="pd"></span>زنده</span></div><div class="card"><div class="tf-chart"><div class="tf-top"><span class="din iso">↓ <b id="o_frx">—</b></span><span class="dout iso">↑ <b id="o_ftx">—</b></span></div><svg id="o_traf" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">↓ ورودیِ کل</span><b id="o_ftin">—</b></div><div class="ttile"><span class="dout">↑ خروجیِ کل</span><b id="o_ftout">—</b></div></div></div>'+
 '<div class="sec">'+ic('clock','var(--acc)')+' آپ‌تایم</div><div class="ostat2"><div class="card"><div class="big" id="o_uptime" style="color:var(--ok)">—</div><div class="muted" style="font-size:11.5px" id="o_uptime_l">میانگینِ آپ‌تایم</div></div><div class="card"><div class="big" id="o_updown">—</div><div class="muted" style="font-size:11.5px">نود قطعی داشته</div></div></div>'}
async function refreshOverview(){var s=await j('summary');if(!el('o_score'))return;
 var on=num(s.nodes_online),tot=num(s.nodes_total),links=num(s.links),alerts=s.alerts||[];
 // ---- health score + chips
 var sc=num(s.health_score),scol=sc>=85?cssv('--ok'):sc>=60?cssv('--gold'):cssv('--bad');
 var se=el('o_score');se.textContent=sc;se.style.color=scol;
 el('o_chips').innerHTML='<span class="ochip a">نود <b dir="ltr">'+on+'/'+tot+'</b></span>'+
  '<span class="ochip o">لینکِ سالم <b dir="ltr">'+num(s.link_up)+'/'+links+'</b></span>'+
  '<span class="ochip a">تونل <b>'+num(s.tunnels)+'</b></span>'+
  (alerts.length?'<span class="ochip b">هشدار <b>'+alerts.length+'</b></span>':'<span class="ochip o">بدونِ هشدار</span>');
 // ---- alerts feed
 var goMap={node:'nodes',link:'tunnels',drift:'tunnels',disk:'nodes',ram:'nodes',cpu:'nodes',agent:'settings'};
 var goLbl={nodes:'نودها',tunnels:'تونل‌ها',settings:'تنظیمات'};
 el('o_alerts').innerHTML=alerts.length?alerts.map(function(a){var c=a.level=='bad'?cssv('--bad'):cssv('--gold');var g=goMap[a.kind]||'nodes';return '<div class="oalert"><span class="dot" style="background:'+c+'"></span><span class="msg">'+esc(a.msg)+'</span><span class="go" onclick="go(\\''+g+'\\')">'+goLbl[g]+' →</span></div>'}).join(''):'<div style="text-align:center;padding:10px 0;font-size:12.5px;color:var(--ok);display:flex;align-items:center;justify-content:center;gap:7px">'+ic('okc','var(--ok)')+' همه‌چیز مرتب است — هشداری نیست</div>';
 // ---- heat row (every node at a glance; height = worst metric)
 var heat=s.heat||[];
 setHTML(el('o_heat'),heat.length?heat.map(function(h){var nm=esc(h.name);if(!h.online)return '<div class="hbar" onclick="heatTip(event,this)" data-nm="'+nm+'" data-info="آفلاین" title="'+nm+' — آفلاین" style="height:10px;background:color-mix(in srgb,var(--sub) 35%,transparent)"></div>';var p=num(h.pct);return '<div class="hbar" onclick="heatTip(event,this)" data-nm="'+nm+'" data-info="'+p+'٪" title="'+nm+' — '+p+'٪" style="height:'+(12+p*0.54)+'px;background:'+ocol(p)+'"></div>'}).join(''):'<div class="muted" style="font-size:12px">نودی نیست</div>');
 setT('o_heat_c',(heat.length||0)+' نود · هر میله = بدترین متریکِ آن نود (دیسک/رم/CPU) · خاکستری = آفلاین');
 // ---- central server gauges
 var c=s.central||{},cl=(c.load||[])[0];
 setGauge('scpu',c.cpu_pct,'لود '+(cl!=null?cl:'—')+' · '+(num(c.cpus)||'?')+' هسته');
 setGauge('sram',c.ram_pct,c.mem_used_mb!=null?(num(c.mem_used_mb)+' / '+num(c.mem_total_mb)+' م‌ب'):'—');
 setGauge('sdisk',c.disk_pct,c.disk_used_mb!=null?(Math.round(num(c.disk_used_mb)/1024)+' / '+Math.round(num(c.disk_total_mb)/1024)+' گیگ'):'—');
 // ---- worst nodes per metric
 var w=s.worst||{},wr=function(k,o){if(!o)return '';var p=num(o.pct),cc=ocol(p);return '<div class="wrow"><span class="wk">'+k+'</span><span class="wnm">'+esc(o.name)+'</span><span class="wbar"><i style="width:'+p+'%;background:'+cc+'"></i></span><span class="wpc" style="color:'+cc+'">'+p+'٪</span></div>'};
 var wh=wr('دیسک',w.disk)+wr('رم',w.ram)+wr('CPU',w.cpu);
 el('o_worst').innerHTML=wh||'<div class="muted" style="text-align:center;padding:8px 0;font-size:12.5px">نودِ آنلاینی نیست</div>';
 // ---- tunnel status breakdown
 var lu=num(s.link_up),ln=num(s.link_noping),ld=num(s.link_down),ldr=num(s.link_drift);
 el('o_tst').innerHTML='<div class="tb"><div class="n" style="color:var(--ok)">'+lu+'</div><div class="l">متصل</div></div>'+
  '<div class="tb"><div class="n" style="color:var(--gold)">'+ln+'</div><div class="l">بدونِ پینگ</div></div>'+
  '<div class="tb"><div class="n" style="color:'+(ld?'var(--bad)':'var(--tx)')+'">'+ld+'</div><div class="l">قطع</div></div>'+
  '<div class="tb"><div class="n" style="color:'+(ldr?'var(--gold)':'var(--tx)')+'">'+ldr+'</div><div class="l">نیازمندِ بازسازی</div></div>';
 var ty=s.link_types||{};
 var TYD=[['vxlan','var(--acc)'],['gre','var(--ok)'],['sit','#a855f7'],['ipip','#14b8a6'],['l2tpv3','#8b5cf6'],['fou','#ec4899'],['ipsec','#f43f5e']];
 var tt=0;TYD.forEach(function(x){tt+=num(ty[x[0]])});tt=tt||1;
 el('o_typebar').innerHTML=TYD.map(function(x){return '<i style="width:'+(num(ty[x[0]])/tt*100)+'%;background:'+x[1]+'"></i>'}).join('');
 el('o_typleg').innerHTML=TYD.filter(function(x){return num(ty[x[0]])>0}).map(function(x){return '<span><i class="otrack" style="background:'+x[1]+'"></i>'+x[0]+' <b>'+num(ty[x[0]])+'</b></span>'}).join('')||'<span class="muted">تونلی نیست</span>';
 var wt=s.worst_tunnel;
 if(wt){var pr=(wt.a&&wt.b)?' <span dir="ltr" style="color:var(--tx);font-weight:800">'+esc(wt.a)+' ↔ '+esc(wt.b)+'</span>':'';
  setHTML(el('o_wtun'),'<div class="onote">📡 بدترین کیفیت: تونلِ <b>'+esc(wt.name)+'</b>'+pr+(num(wt.loss)>0?' · اتلاف <b style="color:var(--bad)">'+Math.round(num(wt.loss))+'٪</b>':'')+(wt.rtt!=null?' · پینگ <b>'+Math.round(num(wt.rtt))+'ms</b>':'')+'</div>');}
 else{setHTML(el('o_wtun'),'<div class="onote">✅ کیفیتِ همهٔ تونل‌ها خوب است'+(s.fleet_avg_ping!=null?' · میانگینِ پینگِ فلیت <b style="color:var(--tx)">'+num(s.fleet_avg_ping)+'ms</b>':'')+'</div>');}
 // ---- fleet traffic
 var frx=num(s.fleet_rx_bps),ftx=num(s.fleet_tx_bps);
 setT('o_frx',fmtRate(frx));setT('o_ftx',fmtRate(ftx));
 setT('o_ftin',fmtBytes(s.fleet_rx_total));setT('o_ftout',fmtBytes(s.fleet_tx_total));
 FRXHIST.push(frx);FTXHIST.push(ftx);if(FRXHIST.length>26){FRXHIST.shift();FTXHIST.shift()}dualSpark('o_traf',FRXHIST,FTXHIST);
 // ---- uptime
 var uw=num(s.uptime_window)||1;
 setT('o_uptime',num(s.uptime_avg)+'٪');setT('o_uptime_l','میانگینِ آپ‌تایمِ '+uw+' ساعتِ اخیر');
 setT('o_updown',num(s.uptime_down_nodes))}

// ===== Nodes
function nodesSkel(){el('view').innerHTML='<h1>'+ic('server','var(--acc)')+' نودها</h1><p class="sub">افزودن و وضعیت زنده‌ی نودها</p>'+
 '<button class="primary" onclick="openNodeAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+'افزودن نود</button>'+
 '<div class="sec">'+ic('server','var(--acc)')+' نودهای فلیت</div>'+toolbar('nodes','جستجوی نام یا آی‌پی…')+'<div id="nodeList"></div>'+pagerBottom('nodes')}
var _naddMode='auto';
function openNodeAddModal(){_naddMode='auto';_authMode='pass';_installDone=null;_instStop();
 var seg='<div class="seg" id="nadd_seg"><button data-m="auto" class="on" onclick="naddSwitch(\\'auto\\')">'+ic('bolt')+'خودکار</button><button data-m="manual" onclick="naddSwitch(\\'manual\\')">'+ic('pen')+'دستی</button></div>';
 var auto='<div id="nadd_auto">'+
   '<div class="autonote">'+ic('bolt')+'<span>مشخصاتِ SSHِ سرورِ نود را بده؛ پنل خودش وارد می‌شود، ایجنت را نصب می‌کند، توکن می‌سازد و نود را وصل می‌کند.</span></div>'+
   '<div class="grid2"><div><label class="first">نامِ نود</label><input id="a_name" placeholder="DE02"></div><div><label class="first">آی‌پیِ سرور</label><input id="a_host" placeholder="5.75.197.55"></div></div>'+
   '<div class="grid2"><div><label>پورتِ SSH</label><input id="a_sshport" placeholder="22"></div><div><label>کاربرِ SSH</label><input id="a_user" placeholder="root"></div></div>'+
   '<div class="grid2"><div><label>پورتِ ایجنت</label><input id="a_aport" placeholder="8099"></div><div><label>پروکسیِ کنترل (اختیاری)</label><input id="a_proxy" placeholder="socks5://host:1080"></div></div>'+
   '<div class="authbox"><div class="authhd"><span class="t">احرازِ هویتِ SSH</span><span class="authseg" id="a_authseg"><button type="button" data-am="pass" class="on" onclick="authMode(\\'pass\\')">رمز</button><button type="button" data-am="key" onclick="authMode(\\'key\\')">کلیدِ خصوصی</button></span></div>'+
    '<input id="a_pass" class="fld2" type="password" placeholder="رمزِ SSH سرور" autocomplete="new-password">'+
    '<textarea id="a_key" class="fld2" rows="3" style="display:none" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>'+
    '<div class="muted" id="a_authhint" style="font-size:11px;margin-top:7px">رمزِ SSH سرور — ذخیره نمی‌شود، فقط لحظهٔ نصب استفاده می‌شود.</div></div>'+
   '<div id="nadd_prog"></div></div>';
 var manual='<div id="nadd_manual" style="display:none"><div class="grid2"><div><label class="first">نام</label><input id="n_name" placeholder="frankfurt-1"></div><div><label class="first">هاست / آی‌پی</label><input id="n_host" placeholder="203.0.113.10"></div></div><div class="grid2"><div><label>پورت agent</label><input id="n_port" placeholder="8099"></div><div><label>توکن نود</label><input id="n_tok" placeholder="توکن نود"></div></div><label>پروکسیِ کنترل (اختیاری) — پنل از این پروکسی به این نود وصل می‌شود</label><input id="n_proxy" placeholder="socks5://host:1080  یا  http://user:pass@host:8080"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>افزودنِ نود</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+seg+auto+manual+'<div class="msg" id="n_msg"></div></div><div class="mfoot"><button class="primary" id="nadd_go" onclick="naddSubmit()">'+ic('bolt')+'نصب و اتصالِ خودکار</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
function naddSwitch(m){_naddMode=m;_installDone=null;_instStop();
 var a=el('nadd_auto'),mn=el('nadd_manual');if(a)a.style.display=m=='auto'?'':'none';if(mn)mn.style.display=m=='manual'?'':'none';
 document.querySelectorAll('#nadd_seg button').forEach(function(b){b.classList.toggle('on',b.dataset.m==m)});
 var btn=el('nadd_go');if(btn){btn.disabled=false;btn.className='primary';btn.innerHTML=(m=='auto'?ic('bolt')+'نصب و اتصالِ خودکار':ic('plus')+'افزودن و اتصال')}
 var pr=el('nadd_prog');if(pr&&m=='manual')pr.innerHTML='';
 var msg=el('n_msg');if(msg){msg.className='msg';msg.textContent=''}}
var _installDone=null;  // null = idle/retry, 'ok' = finished successfully (button just closes)
function naddSubmit(){if(_naddMode=='auto'){if(_installDone=='ok'){var ov=el('nadd_go').closest('.modalov');if(ov)closeModal(ov);return}return doAutoInstall()}return addNode()}
function instIcon(st){return st=='ok'?'<span class="istep-i ok">'+CK+'</span>':st=='err'?'<span class="istep-i err">'+XK+'</span>':st=='warn'?'<span class="istep-i warn">'+ic('warn')+'</span>':st=='run'?'<span class="istep-i run"><span class="ispin"></span></span>':'<span class="istep-i wait"></span>'}
// live install: reveal steps one-by-one on a CLIENT clock (elapsed-time based, so Android timer-
// throttling can't collapse them), clamped to the backend's real progress. ONE self-terminating loop
// that stops the instant the modal closes — no leaked/duplicate pollers, no infinite retry.
var _inst=null,_MINSPIN=600;
var _INSTEPS=[{label:'اتصالِ SSH',detail:'در حالِ اتصال…'},{label:'دانلودِ ایجنت',detail:'در انتظار…'},{label:'نصب و راه‌اندازیِ سرویس',detail:'در انتظار…'},{label:'ثبت و اتصال در پنل',detail:'در انتظار…'}];
function _instStop(){if(_inst){_inst.cancelled=true;if(_inst.timer)clearTimeout(_inst.timer);_inst=null}}
function _instPoll(c){j('install-status?job='+encodeURIComponent(c.job)+'&_='+Date.now())
 .then(function(d){c.polling=false;
   if(d&&d.ok){c.failN=0;c.steps=d.steps||[];c.confirmed=c.steps.map(function(s){return s.state});if(d.banner)c.banner=d.banner;c.bDone=!!d.done;c.bOk=!!d.success}
   else if(d&&/not found/.test(d.error||'')){c.err='وضعیتِ نصب یافت نشد';c.bDone=true;c.bOk=false}
   else{c.failN++;if(c.failN>=45){c.err='ارتباط با پنل قطع شد';c.bDone=true;c.bOk=false}}})
 .catch(function(){c.polling=false;c.failN++;if(c.failN>=45){c.err='ارتباط با پنل قطع شد';c.bDone=true;c.bOk=false}})}
function _instRender(c){var box=el('nadd_prog');if(!box)return;var anim=!c.finished;
 var bicon=anim?'<span class="ispin"></span>':(c.bOk?CK:XK);
 var btext=anim?'در حالِ نصب…':(c.err||c.banner||'انجام شد');   // don't flash the backend's "done" banner while steps are still revealing
 var html='<div class="ibanner '+(anim?'run':(c.bOk?'ok':'err'))+'">'+bicon+'<span>'+esc(btext)+'</span></div>';
 var steps=c.steps||[],conf=c.confirmed||[];
 for(var i=0;i<c.revealIdx;i++){var s=steps[i]||{},cst=conf[i]||'',disp;
   // a step ONLY ticks when the backend actually confirmed it 'ok'; still-running shows a spinner while
   // animating, and an unconfirmed step at a failed/aborted finish shows an error — never a false tick.
   if(cst=='ok')disp='ok';else if(cst=='warn')disp='warn';else if(cst=='err')disp='err';else if(anim)disp='run';else disp='err';
   var lg=(disp=='err'&&s.log)?'<div class="ilog">'+esc(s.log)+'</div>':'';
   html+='<div class="istep '+disp+'">'+instIcon(disp)+'<div class="istep-b"><div class="istep-t">'+esc(s.label||'')+'</div>'+(s.detail?'<div class="istep-s">'+esc(s.detail)+'</div>':'')+lg+'</div></div>'}
 setHTML(box,'<div class="iwrap">'+html+'</div>')}
function _instFinish(c){c.finished=true;_instRender(c);var btn=el('nadd_go');
 if(c.bOk){_installDone='ok';if(btn){btn.disabled=false;btn.className='primary done';btn.innerHTML=CK+' انجام شد'}toast(c.banner||'نود نصب شد','ok');refreshNodes().catch(function(){})}
 else{_installDone=null;if(btn){btn.disabled=false;btn.className='primary';btn.innerHTML=ic('bolt')+' تلاشِ مجدد'}}
 if(c.timer)clearTimeout(c.timer);_inst=null}
function _instNow(){return (window.performance&&performance.now)?performance.now():Date.now()}
function _instTick(){var c=_inst;if(!c)return;
 if(c.cancelled||!el('nadd_prog')){_instStop();return}   // modal closed -> loop dies (no leak)
 var now=_instNow();
 if(!c.polling&&now-c.lastPoll>=380){c.polling=true;c.lastPoll=now;_instPoll(c)}
 var conf=c.confirmed||[],started=0;
 for(var i=0;i<conf.length;i++){if(conf[i]&&conf[i]!='wait')started=i+1}
 var cur=c.revealIdx-1,curTerm=cur<0||(conf[cur]&&conf[cur]!='wait'&&conf[cur]!='run');
 if(c.revealIdx<started&&now-c.lastReveal>=_MINSPIN&&curTerm){c.revealIdx++;c.lastReveal=now}  // advance one step per beat, never past the backend
 if(!c.finished&&c.bDone&&c.revealIdx>=started&&now-c.lastReveal>=_MINSPIN&&(started>0||c.err)){_instFinish(c);return}
 _instRender(c);c.timer=setTimeout(_instTick,150)}
var _authMode='pass';
function authMode(m){_authMode=m;
 var pf=el('a_pass'),kf=el('a_key'),h=el('a_authhint');
 if(pf)pf.style.display=(m=='pass')?'':'none';if(kf)kf.style.display=(m=='key')?'':'none';
 document.querySelectorAll('#a_authseg button').forEach(function(b){b.classList.toggle('on',b.dataset.am==m)});
 if(h)h.textContent=(m=='key')?'کلیدِ خصوصیِ SSH — امن‌تر از رمز؛ به sshpass هم نیازی نیست.':'رمزِ SSH سرور — ذخیره نمی‌شود، فقط لحظهٔ نصب استفاده می‌شود.';
 var f=(m=='pass')?pf:kf;if(f){try{f.focus()}catch(e){}}}
function agBtnBusy(btn,on,label){if(!btn)return;btn.disabled=on;
 btn.innerHTML=on?'<span class="bspin"></span>':label}
async function doAutoInstall(){if(_inst)return;var m=el('n_msg'),btn=el('nadd_go');   // never start a second install while one is live
 var name=v('a_name'),host=v('a_host');
 var pass=_authMode=='pass'?v('a_pass'):'',key=_authMode=='key'&&el('a_key')?el('a_key').value.trim():'';
 if(!name||!host){m.className='msg err';m.textContent='نام و آی‌پیِ سرور لازم است';return}
 if(!pass&&!key){m.className='msg err';m.textContent=(_authMode=='key'?'کلیدِ خصوصی':'رمزِ SSH')+' لازم است';return}
 _installDone=null;m.className='msg';m.textContent='';agBtnBusy(btn,true);
 // show the FIRST step (SSH), spinning, the instant install is clicked — no "در حالِ نصب…" placeholder gap
 var pr=el('nadd_prog');if(pr){pr.innerHTML='<div class="iwrap"><div class="ibanner run"><span class="ispin"></span><span>در حالِ نصب…</span></div><div class="istep run"><span class="istep-i run"><span class="ispin"></span></span><div class="istep-b"><div class="istep-t">'+esc(_INSTEPS[0].label)+'</div><div class="istep-s">'+esc(_INSTEPS[0].detail)+'</div></div></div></div>';pr.scrollIntoView({behavior:'smooth',block:'center'})}
 var r=await post('node-install',{name:name,ssh_host:host,ssh_port:v('a_sshport'),ssh_user:v('a_user'),agent_port:v('a_aport'),ssh_pass:pass,ssh_key:key,proxy:v('a_proxy')}).catch(function(){return{ok:false,d:{}}});
 if(!(r.ok&&r.d.ok)){m.className='msg err';m.textContent=(r.d&&r.d.error)||'ناموفق';if(pr)pr.innerHTML='';agBtnBusy(btn,false,ic('bolt')+'نصب و اتصالِ خودکار');return}
 // seed step 0 as revealed+running so the reveal continues seamlessly from the skeleton (no flicker back to the banner)
 _inst={job:r.d.job,steps:_INSTEPS.map(function(s){return{label:s.label,detail:s.detail}}),confirmed:['run','wait','wait','wait'],banner:'در حالِ نصب…',bDone:false,bOk:false,err:'',revealIdx:1,lastReveal:_instNow(),lastPoll:0,polling:false,failN:0,finished:false,cancelled:false,timer:null};
 _instTick()}
async function refreshNodes(){if(editingId)return;var r=await j('nodes?offset='+(PG.nodes*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.nodes));NODES=r.nodes||[];TOT.nodes=num(r.total);UPWIN=num(r.uptime_window)||1;var box=el('nodeList');if(!box)return;
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
 ov.remove();
 if(!document.querySelector('.modalov')){editingId=null;EDID=null}  // only clear edit state when the LAST modal closes — a nested dropdown popup must not wipe the parent edit modal's EDID
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
  var traf='<div class="nd-sec">'+ic('traf')+' ترافیک<span class="lpill" style="margin-inline-start:auto"><span class="pd"></span>زنده</span></div><div class="tf-chart"><div class="tf-top"><span class="din iso">↓ <b id="tf_rin">—</b></span><span class="dout iso">↑ <b id="tf_rout">—</b></span></div><svg id="tf_spark" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">↓ ورودیِ کل</span><b id="tf_tin">—</b></div><div class="ttile"><span class="dout">↑ خروجیِ کل</span><b id="tf_tout">—</b></div></div><div id="tf_tuns" class="tf-tuns"></div>';
  var tiles='<div class="nd-grid">'+ndTile('os','سیستم‌عامل',esc(s.os||'?'),false,true)+ndTile('clock','آپ‌تایم',s.uptime?fmtup(s.uptime):'?')+ndTile('cores','تعداد هسته',num(s.cpus)||'?')+ndTile('link','تونل',num(i.tunnels))+ndTile('globe','پورت‌فوروارد',num(i.portfw))+ndTile('shield','پروکسیِ کنترل',n.proxy?esc(proxyScheme(n.proxy)):'—')+ndTile('server','میزبان',esc(i.hostname||'?'),true,true)+ndTile('pin','آی‌پی',esc(n.host),true,true)+'</div>';
  mb=head+g+traf+'<div class="nd-divider"></div>'+tiles+'<div class="nd-divider"></div><div class="nd-sec">'+ic('pin')+' آی‌پی‌ها<span class="muted" style="margin-inline-start:auto;font-size:11px;font-weight:500">تونل‌شده / پورت‌فوروارد / آزاد</span></div><div id="nd_ips" class="ndips"><div class="muted" style="font-size:11.5px;padding:6px 2px">…</div></div>'}
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
    var rows=(r.tunnels||[]).concat(r.portfw||[]);
    var tb=el('tf_tuns');if(tb)tb.innerHTML=rows.length?rows.map(tfRow).join(''):'<div class="muted" style="font-size:11.5px;padding:7px 2px">تونل یا پورت‌فورواردی روی این نود نیست</div>'}).catch(function(){})};
  poll();ov._iv=setInterval(poll,2500)}}
function ndRetest(id){j('node-stats?id='+id).then(function(r){if(r&&r.online){toast('آنلاین','ok')}else{toast('آفلاین: '+((r&&r.error)||'در دسترس نیست'),'err')}}).catch(function(){toast('خطا در بررسی','err')})}
function openNodeEdit(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;
 var b='<div class="grid2"><div><label class="first">نام</label><input id="e_name_'+id+'" value="'+esc(n.name)+'"></div><div><label class="first">هاست / آی‌پی</label><input id="e_host_'+id+'" value="'+esc(n.host)+'"></div></div><div class="grid2"><div><label>پورت</label><input id="e_port_'+id+'" value="'+esc(n.port)+'"></div><div><label>توکن</label><input id="e_tok_'+id+'" placeholder="خالی = توکن فعلی بماند"></div></div><label>پروکسیِ کنترل (خالی = بدون پروکسی)</label><input id="e_proxy_'+id+'" value="'+esc(n.proxy||'')+'" placeholder="socks5://host:1080 یا http://user:pass@host:8080"><div class="msg" id="em_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>ویرایشِ نود</h3><div class="sb">'+esc(n.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveEdit(\\''+id+'\\')">ذخیره</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
function ipEndField(side,id,nm,ips,cur){var lab='<label class="first">آی‌پیِ '+esc(nm)+'</label>';
 ips=(ips&&ips.length)?ips:(cur?[cur]:[]);
 if(ips.length>1)return '<div>'+lab+ssHTML('lip'+side+'_'+id,ips.map(function(x){return{v:x,label:x}}),(cur&&ips.indexOf(cur)>=0)?cur:ips[0],'آی‌پی','')+'</div>';
 return '<div>'+lab+'<input class="mono" value="'+esc(cur||ips[0]||'—')+'" disabled style="opacity:.6"></div>'}
function openLinkEdit(id){var l=FLEET.find(function(x){return x.id==id});if(!l)return;EDID=id;LEDTYPE=l.type;LEDPORT=(l.port==null?'':l.port);
 var multi=((l.a_ips||[]).length>1)||((l.b_ips||[]).length>1);
 var b='<div class="grid2"><div><label class="first">نوع تونل</label>'+ssHTML('lt_'+id,TYPEITEMS,l.type,'نوع','recalcEditSubnet')+'</div><div><label class="first">رنجِ لوکال</label>'+ssHTML('lsr_'+id,SUBNETRANGES2,'192.168','رنج','recalcEditSubnet')+'</div></div><label>سابنت</label><input id="e_sub_'+id+'" value="'+esc(l.subnet)+'"><div id="lpx_'+id+'"></div>'+
  '<div class="muted" style="font-weight:700;color:var(--tx);margin:16px 2px 9px;display:flex;align-items:center;gap:6px">'+ic('pin','var(--acc)')+'آی‌پیِ هر سرِ تونل'+(multi?' <span class="tag" style="font-size:9.5px;padding:1px 7px">مولتی‌آی‌پی</span>':'')+'</div>'+
  '<div class="grid2">'+ipEndField('a',id,l.a_name,l.a_ips,l.a_ip)+ipEndField('b',id,l.b_name,l.b_ips,l.b_ip)+'</div>'+
  '<div class="muted" style="font-size:11.5px;margin-top:9px">اگر نودی چند آی‌پی دارد، انتخاب کن تونل روی کدام آی‌پی بسته شود. تغییرِ نوع، سابنت یا آی‌پی، تونل را روی هر دو نود بازسازی می‌کند (شناسه '+esc(l.tunnel_id)+' حفظ می‌شود).</div><div class="msg" id="lem_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('link')+'</span><div class="ttl"><h3>ویرایشِ تونل</h3><div class="sb">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveLinkEdit(\\''+id+'\\')">ذخیره و بازسازی</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>',{onclose:function(){EDID=null}});
 renderEditPort(id)}
async function openPfEdit(i){var p=PF[i];if(!p)return;EDID='pf'+i;var rotOn=p.switch_interval>0;
 var r=await j('node-names');NODES=r.nodes||[];var ips=nodeIps(p.node_id);   // load node IPs for the listen-IP picker
 var lipsec=(ips.length>1)?'<label class="first">آی‌پیِ ورودی (شنود)</label>'+ssHTML('pe_lip',ipItems(ips),(p.listen_ip&&ips.indexOf(p.listen_ip)>=0?p.listen_ip:ips[0]),'آی‌پی','')+'<div class="muted" style="font-size:11px;margin:-3px 2px 12px">پورت فقط روی این آی‌پی فوروارد می‌شود</div>':'';
 var fc=lipsec?'':' class="first"';
 var b=lipsec+'<div class="grid2"><div><label'+fc+'>پورتِ ورودی</label><input id="pe_lp_'+i+'" value="'+esc(p.listen_port)+'"></div><div><label'+fc+'>پورتِ مقصد</label><input id="pe_dp_'+i+'" value="'+esc(p.dst_port)+'"></div></div><label>آی‌پی(های) مقصد — با کاما جدا کن</label><input id="pe_ips_'+i+'" value="'+esc((p.dst_ips||[]).join(', '))+'"><label>چرخش بینِ مقصدها</label><div class="tgl"><span class="tglsw'+(rotOn?' on':'')+'" id="pe_tgl_'+i+'" onclick="pfTgl('+i+')"></span><span class="muted" id="pe_tgllbl_'+i+'">'+(rotOn?'روشن':'خاموش')+'</span></div><div id="pe_intwrap_'+i+'" style="'+(rotOn?'':'display:none')+'"><label>بازهٔ چرخش (دقیقه)</label><input id="pe_int_'+i+'" value="'+esc(rotOn?(p.switch_interval/60):5)+'"></div><div class="muted" style="font-size:11.5px;margin-top:9px">چرخش فقط با ۲ آی‌پیِ مقصد یا بیشتر فعال می‌شود.</div><div class="msg" id="pem_'+i+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>ویرایشِ پورت‌فوروارد</h3><div class="sb">'+esc(p.node)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="savePfEdit('+i+')">ذخیره</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
function nodeCard(n){var i=n.info||{};
 var badge=n.online?'<span class="badge ok">آنلاین</span>':(n.pending?'<span class="badge na">در حال بررسی…</span>':'<span class="badge bad">آفلاین</span>');
 var head='<div class="nrow"><span class="ndot '+(n.online?'on':'off')+'"></span><div style="min-width:0"><div class="name">'+esc(n.name)+(n.proxy?' <span class="tag" style="font-size:9.5px;padding:1px 6px">پروکسی</span>':'')+'</div><div class="muted mono" style="font-size:12px">'+esc(n.host)+':'+esc(n.port)+'</div></div><span class="grow"></span>'+badge+'</div>';
 var body=n.online?'<div class="nchips"><span class="nchip">'+ic('link')+'تونل <b>'+num(i.tunnels)+'</b></span><span class="nchip">'+ic('globe')+'پورت‌فوروارد <b>'+num(i.portfw)+'</b></span>'+(i.version?'<span class="nchip">'+ic('cpu')+'ایجنت v<b>'+num(i.version)+'</b></span>':'')+((i.core_sha&&String(i.core_sha).length)?'<span class="nchip" title="نسخهٔ هسته">'+ic('cpu')+'هسته <b>'+esc(i.core_ver||'?')+'</b></span>':'<span class="nchip" title="هسته روی نود نصب نیست" style="color:var(--sub)">'+ic('cpu')+'هسته <b>نصب نیست</b></span>')+(n.proxy?'<span class="nchip">'+ic('shield')+'<b>'+esc(proxyScheme(n.proxy))+'</b></span>':'')+'</div>':'<div class="noff">'+ic('plugoff')+'<b>در دسترس نیست</b>'+(i.error?'<span>· '+esc(i.error)+'</span>':'')+'</div>';
 var acts='<div class="nact iconly"><button class="act ok" title="تست" onclick="testNode(\\''+n.id+'\\')">'+ic('bolt')+'</button><button class="act info" title="مشخصات" onclick="nodeDetails(\\''+n.id+'\\')">'+ic('info')+'</button><button class="act warn" title="ویرایش" onclick="openNodeEdit(\\''+n.id+'\\')">'+ic('pen')+'</button><button class="act danger" title="حذف" data-nid="'+esc(n.id)+'" data-nm="'+esc(n.name)+'" onclick="delNode(this)">'+ic('trash')+'</button></div>';
 return '<div class="card node">'+head+body+upBar(n)+acts+'<div class="msg" id="ntm_'+n.id+'"></div></div>'}
function upBar(n){var r=n.uptime||[];  // 60 cells: 1=up(green), 0=down(red), null=no-data(gray)
 var up=0,tot=0;for(var i=0;i<r.length;i++){if(r[i]!=null){tot++;if(r[i])up++}}
 var pct=tot?Math.round(up/tot*100):0;
 var cells=r.map(function(v){return '<i class="'+(v==null?'g':(v?'':'d'))+'"></i>'}).join('');
 return '<div class="upwrap"><div class="uptop">آپتایم<b style="margin-inline-start:6px">'+pct+'٪</b><span class="r">'+UPWIN+' ساعتِ اخیر</span></div><div class="upbar">'+cells+'</div></div>'}
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
function delNode(btn){var id=btn.getAttribute('data-nid');var nm=btn.getAttribute('data-nm');
 var b='<div class="muted" style="font-size:12.5px;margin-bottom:13px">می‌خواهی نود چطور حذف شود؟ یکی را انتخاب کن:</div>'+
  '<button type="button" class="delopt" onclick="doDelNode(\\''+id+'\\',false)"><div class="do-t">'+ic('logout')+'فقط از پنل جدا کن</div><div class="do-s">نود و تونل‌هایش دست‌نخورده می‌مانند و کار می‌کنند؛ فقط از رجیستریِ این پنل حذف می‌شود. بعداً می‌توانی دوباره اضافه‌اش کنی.</div></button>'+
  '<button type="button" class="delopt danger" onclick="doDelNode(\\''+id+'\\',true)"><div class="do-t">'+ic('warn')+'پاک‌سازیِ کاملِ نود</div><div class="do-s">روی خودِ سرورِ نود همه‌چیز پاک می‌شود: همهٔ تونل‌ها، ایجنت، سرویسِ systemd، توکن و فایل‌های JSON. سمتِ نودهای مقابل هم تونل‌ها بسته می‌شوند. برگشت‌ناپذیر است!</div></button>'+
  '<div class="msg" id="del_msg"></div>';
 openModal('<div class="msticky"><span class="medi medi-bad">'+ic('trash')+'</span><div class="ttl"><h3>حذفِ نود</h3><div class="sb">'+esc(nm)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>')}
async function doDelNode(id,wipe){var m=el('del_msg');
 if(wipe&&!await confirmBox('مطمئنی؟ کلِ نود روی سرور — تونل‌ها، ایجنت و توکن — پاک می‌شود و برگشت ندارد.','بله، پاک کن'))return;
 if(m){m.className='msg';m.textContent=wipe?'در حال پاک‌سازیِ نود…':'در حال جدا کردن…'}
 document.querySelectorAll('.delopt').forEach(function(b){b.disabled=true});
 var r=await post('node-del',{id:id,wipe:wipe});
 if(r.ok&&r.d.ok){editingId=null;var ov=m?m.closest('.modalov'):null;
  toast(wipe?'نود کاملاً پاک‌سازی شد':'نود از پنل جدا شد','ok');
  if(ov)closeModal(ov);else refreshNodes()}
 else{if(m){m.className='msg err';m.textContent=(r.d&&r.d.error)||'ناموفق'}document.querySelectorAll('.delopt').forEach(function(b){b.disabled=false})}}

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
function sideState(online,h){  // k: dot color class, w: the word to show ONLY when there's a problem
 if(!online||!h)return {k:'bad',w:'قطع'};
 if(h.up==null)return {k:'na',w:'…'};
 if(!h.up)return {k:'bad',w:'قطع'};
 if(h.peer_ping===false)return {k:'warn',w:'نیم‌بند'};
 return {k:'ok',w:''}}   // connected -> clean, just the green dot
function sideDot(online,h){var s=sideState(online,h);   // shared by tunnel + core cards
 return (s.w?'<span class="stw '+s.k+'">'+esc(s.w)+'</span>':'')+'<span class="sdot '+s.k+'"'+(s.w?'':' title="متصل"')+'></span>'}
function metaCols(l){   // two meta columns placed exactly under the two node boxes
 var sub='<div>سابنت: <b class="mono">'+esc(l.subnet)+'</b></div>';
 var idr='<div>شناسه: <b>'+esc(l.tunnel_id)+'</b></div>';
 var ifc='<div>اینترفیس: <b class="mono">'+esc(l.name)+'</b></div>';
 var typ='<div class="tagrow">نوع: <span class="tag '+esc(l.type)+'">'+esc(l.type)+'</span></div>';
 var right,left;
 if(l.type=='ipsec'){right=sub+idr+ifc;left=typ+'<div class="wrap">رمزنگاری: <span class="enc">'+ic('lock','var(--bad)')+'رمزنگاری‌شده</span></div>'}
 else if((l.type=='l2tpv3'||l.type=='fou'||l.type=='vxlan')&&l.port){right=sub+idr+ifc;left=typ+'<div>پورتِ UDP: <b class="mono">'+esc(l.port)+'</b></div>'}
 else{right=sub+ifc;left=idr+typ}   // plain (gre/ipip/sit, or vxlan without a custom port): balanced 2+2
 return '<div class="enmeta"><div class="emcol">'+right+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+left+'</div></div>'}
// ===== accordion cards (collapsed row -> click to expand) + on/off toggle =====
var TOPEN={};   // per-link open state, kept across the periodic re-render
var CHEVI='<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>';
function cardTog(id,e){TOPEN[id]=!TOPEN[id];var c=el('c_'+id);if(c)c.classList.toggle('open',TOPEN[id])}
async function toggleLink(id,e){e.stopPropagation();var L=FLEET.filter(function(x){return x.id==id})[0];if(!L)return;
 var next=(L.enabled===false);L.enabled=next;   // optimistic flip
 var c=el('c_'+id);if(c){var sw=c.querySelector('.tsw');if(sw)sw.classList.toggle('on',next);c.classList.toggle('off',!next)}
 var r=await post('link-toggle',{id:id,enabled:next});
 if(!(r.ok&&r.d.ok)){L.enabled=!next;toast('ناموفق','err')}else{toast(next?'روشن شد':'خاموش شد','ok')}
 refreshFleet()}
function accDot(l,side){if(l.enabled===false)return '<span class="sdot na" title="خاموش"></span>';
 var s=sideState(side=='a'?l.a_online:l.b_online, side=='a'?l.a_health:l.b_health);return '<span class="sdot '+s.k+'"></span>'}
function accStat(l,side){if(l.enabled===false)return '<span class="stw na">خاموش</span><span class="sdot na"></span>';
 return side=='a'?sideDot(l.a_online,l.a_health):sideDot(l.b_online,l.b_health)}
function accHead(l,isCore){var on=l.enabled!==false;
 var typ=isCore?'<span class="ctag core">Core</span>':'<span class="ctag">'+esc((l.type||'').toUpperCase())+'</span>';
 var off=on?'':'<span class="offtxt" style="font-size:11px">خاموش</span>';
 return '<div class="chead" onclick="cardTog(\\''+l.id+'\\',event)">'+
  '<div class="tsw'+(on?' on':'')+'" onclick="toggleLink(\\''+l.id+'\\',event)" title="روشن/خاموشِ تونل"></div>'+
  '<div class="hmain"><div class="hrow1"><span class="hname">'+esc(l.name)+'</span>'+typ+off+
   '<span class="hpeers">'+accDot(l,'a')+esc(l.a_name)+' ↔ '+esc(l.b_name)+accDot(l,'b')+'</span></div></div>'+CHEVI+'</div>'}
function accBodyTraf(l){if(l.enabled===false)return '<div class="offbadge">'+ic('warn','var(--bad)')+'<span>این تونل خاموش است — اینترفیس down شده. توگلِ بالا را بزن تا دوباره بالا بیاید.</span></div>';
 var hasT=(l.rx_total!=null||l.rx_bps!=null);
 var tot=hasT?'<span class="iso"><b class="din">↓'+fmtBytes(l.rx_total)+'</b><b class="dout">↑'+fmtBytes(l.tx_total)+'</b></span>':'<b class="mono">—</b>';
 var rates=hasT?'<span class="din iso">↓ '+fmtRate(l.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(l.tx_bps)+'</span>':'<span class="muted" style="font-size:11px">دادهٔ زنده از این سر نیست</span>';
 return '<div class="ltraf">'+rates+'<span class="tot">مجموع '+tot+'</span></div>'}
function accShell(l,isCore,inner){var open=!!TOPEN[l.id];
 return '<div class="card acc'+(l.enabled===false?' off':'')+(open?' open':'')+'" id="c_'+l.id+'">'+accHead(l,isCore)+
  '<div class="cbody"><div class="cbody-in">'+inner+'</div></div></div>'}
function linkCard(l){
 var body='<div class="tninfo">'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="stat" id="lba_'+l.id+'">'+accStat(l,'a')+'</span></div><div class="tna mono">'+esc(l.a_ip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="stat" id="lbb_'+l.id+'">'+accStat(l,'b')+'</span></div><div class="tna mono">'+esc(l.b_ip)+'</div></div>'+
  '</div>'+
  metaCols(l);
 var c=CHK[l.id];var msg='<div class="msg '+(c?c.cls:'')+'" id="lchk_'+l.id+'">'+(c?c.html:'')+'</div>';
 var flip='<button class="act flip" onclick="flipView(\\''+l.id+'\\')" title="تعویضِ دیدِ مصرف — فعلاً: '+esc(l.view_name||'—')+'">'+ic('swap')+'</button>';
 var acts='<div class="nact iconly"><button class="act ok" title="تستِ پینگ" onclick="checkLink(\\''+l.id+'\\')">'+ic('activity')+'</button>'+flip+'<button class="act reset" title="ریستِ حجمِ کل" onclick="resetTraffic(\\''+l.id+'\\')">'+ic('reset')+'</button><button class="act warn" title="ویرایش" onclick="openLinkEdit(\\''+l.id+'\\')">'+ic('pen')+'</button><button class="act" title="بازسازی" onclick="rebuildLink(\\''+l.id+'\\')">'+ic('redo')+'</button><button class="act danger" title="حذف" onclick="delLink(\\''+l.id+'\\')">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>آی‌پیِ یکی از نودها عوض شده — این تونل نیاز به بازسازی دارد. دکمهٔ «بازسازی» را بزن.</span></div>':'';
 return accShell(l,false,drift+body+accBodyTraf(l)+acts+msg)}
async function refreshTunnels(){if(editingId||CHECKING)return;var f=await j('fleet?kind=tunnels&offset='+(PG.tunnels*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.tunnels));FLEET=f.links||[];TOT.tunnels=num(f.total);var box=el('linkList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(linkCard).join(''):'<div class="card muted">'+(QRY.tunnels?'موردی یافت نشد.':'هنوز لینکی نیست — دکمهٔ «افزودن تونل» بالا.')+'</div>');renderPager('tunnels')}
async function saveLinkEdit(id){var m=el('lem_'+id);var type=ssVal('lt_'+id),subnet=v('e_sub_'+id);
 if(!type){m.className='msg err';m.textContent='نوع تونل لازم است';return}
 var L=FLEET.find(function(x){return x.id==id})||{};
 var a_ip=ssVal('lipa_'+id)||L.a_ip||'',b_ip=ssVal('lipb_'+id)||L.b_ip||'';
 m.className='msg';m.textContent='در حال بازسازی تونل روی دو نود…';
 var body={id:id,type:type,subnet:subnet,a_ip:a_ip,b_ip:b_ip};var pe=el('le_port_'+id);if(pe)body.port=pe.value.trim();
 var r=await post('edit-link',body);
 if(r.ok&&r.d.ok){delete CHK[id];closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=r.d.error||r.d.msg||'ناموفق'}}
function setChk(id,cls,html){CHK[id]={cls:cls,html:html};var m=el('lchk_'+id);if(m){m.className='msg '+cls;m.innerHTML=html}}
function chkLines(hdr,a,b){return '<div class="chh">'+hdr+'</div><div class="chl">'+esc(a)+'</div><div class="chl">'+esc(b)+'</div>'}
async function checkLink(id){CHECKING++;
 try{
  setChk(id,'',esc('در حال بررسی اتصال (پینگِ زنده روی دو سر)…'));
  var r=await post('check-link',{id:id});
  var L=FLEET.filter(function(x){return x.id==id})[0]||{};
  if(!(r.ok&&r.d.ok)){setChk(id,'err',esc((r.d&&(r.d.error||r.d.msg))||'ناموفق'));return}
  var d=r.d,ab=el('lba_'+id),bb=el('lbb_'+id);
  if(ab)ab.innerHTML=sideDot(d.a_online,d.a_health);if(bb)bb.innerHTML=sideDot(d.b_online,d.b_health);
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
async function flipView(id){var r=await post('link-view',{id:id});
 if(r.ok&&r.d.ok){var L=FLEET.filter(function(x){return x.id==id})[0];var nm=L?(r.d.view_side=='b'?L.b_name:L.a_name):'';
  setChk(id,'ok',ic('swap')+esc('دیدِ مصرف به نودِ «'+nm+'» تغییر یافت.'));
  setTimeout(function(){if(CHK[id]){CHK[id]=null;var m=el('lchk_'+id);if(m){m.className='msg';m.innerHTML=''}}},4000);
  refreshFleet()}
 else{toast('ناموفق','err')}}
async function resetTraffic(id){if(!await confirmBox('حجمِ کلِ این تونل صفر شود؟ (نرخِ زنده دست‌نخورده می‌ماند)'))return;var r=await post('traffic-reset',{id:id});if(r.ok&&r.d.ok){toast('حجمِ کل صفر شد','ok');refreshFleet()}else{toast((r.d&&(r.d.error||r.d.msg))||'ناموفق','err')}}
async function resetPfTraffic(i){var p=PF[i];if(!p)return;if(!await confirmBox('حجمِ کلِ این پورت‌فوروارد صفر شود؟'))return;var r=await post('traffic-reset',{node:p.node_id,name:p.name});if(r.ok&&r.d.ok){toast('حجمِ کل صفر شد','ok');refreshPortfw()}else{toast((r.d&&(r.d.error||r.d.msg))||'ناموفق','err')}}
// ===== IP tags + rebuild IP picker (opens on بازسازی for a drift-flagged tunnel) =====
var LINKI='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px"><path d="M9 7H6a4 4 0 000 8h3M15 7h3a4 4 0 010 8h-3M8 11h8"/></svg>';
var CK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-inline-start:3px"><path d="M20 6 9 17l-5-5"/></svg>';
var XK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-inline-start:3px"><path d="M18 6 6 18M6 6l12 12"/></svg>';
function ipChips(x){var t=(x.peers||[]).map(function(p){
  return '<span class="ippeer" onclick="ipTog(event,this)" title="بزن تا بینِ نامِ نود و اینترفیس جابه‌جا شود"><span class="ipn">'+LINKI+' '+esc(p.node)+'</span><span class="ipi">'+esc(p.name||p.type)+'</span></span>'});
 (x.pf||[]).forEach(function(nm){t.push('<span class="ippf">'+ic('globe')+' پورت‌فوروارد · '+esc(nm)+'</span>')});
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
 if(r.ok&&r.d.ok){toast('بازسازی شد','ok');if(_rbOv)closeModal(_rbOv);delete CHK[id];refreshFleet()}
 else toast((r.d&&(r.d.error||r.d.msg))||'بازسازی ناموفق','err')}
async function delLink(id){if(!await confirmBox('این تونل روی هر دو نود حذف شود؟'))return;var r=await post('delete-link',{id:id});if(!r.d.ok&&r.d.msg)toast('حذف ناقص: '+r.d.msg,'err');delete CHK[id];editingId=null;refreshFleet()}

// ===== Create
// one endpoint's IP field for the create forms: multi-IP -> dropdown; single-IP -> disabled box (like the edit form)
function ipField(k,ips,lab){
 if(ips.length>1)return '<label class="first">'+lab+'</label>'+ssHTML(k,ipItems(ips),(SEL[k]&&ips.indexOf(SEL[k])>=0?SEL[k]:ips[0]),'آی‌پی','');
 delete SEL[k];return '<label class="first">'+lab+'</label><input class="mono" value="'+esc(ips[0]||'—')+'" disabled style="opacity:.6">'}
function ipSecTitle(){return '<div class="ipsec">'+ic('pin','var(--acc)')+'آی‌پیِ هر سرِ تونل</div>'}
async function openCreateModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});selTargets={};
 if(on.length<2){toast('حداقل ۲ نودِ آنلاین لازم است','err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<div class="grid2"><div><label class="first">نودِ مبدأ</label>'+ssHTML('c_a',items,items[0].v,'نودِ مبدأ','onCreateSrc')+'</div>'+
  '<div><label class="first">نودِ مقصد</label>'+ssHTML('c_b',items,items[1].v,'نودِ مقصد','onCreateDst')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="c_srcip"></div><div id="c_dstip"></div></div>'+
  '<label>نوع تونل</label>'+ssHTML('c_type',TYPEITEMS,'vxlan','نوع','onCreateType')+'<div id="c_typex"></div>'+
  '<label>سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه، بدون تداخل)</label>'+ssHTML('c_snr',SUBNETRANGES,'192.168','رنج','onSubnetRange')+'<div id="c_snc_wrap" style="display:none"><label>سابنتِ دلخواه</label><input id="c_subnet" placeholder="مثلا 192.168.99.0/24 یا fd00:99::/64"></div><div class="msg" id="c_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>افزودنِ تونل</h3><div class="sb">سیستمی · یک مبدأ ↔ یک مقصد</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreate()">ساخت تونل</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>',{cls:'edit'});
 renderSrcIp();renderDstIp();renderTypeExtra()}
function onSubnetRange(){var w=el('c_snc_wrap');if(w)w.style.display=(ssVal('c_snr')=='custom')?'block':'none'}
function onCreateSrc(){renderSrcIp()}
function onCreateDst(){renderDstIp()}
function renderDstIp(){var w=el('c_dstip');if(!w)return;w.innerHTML=ipField('c_bip',nodeIps(ssVal('c_b')),'آی‌پیِ نودِ مقصد')}
function renderSrcIp(){var w=el('c_srcip');if(!w)return;w.innerHTML=ipField('c_aip',nodeIps(ssVal('c_a')),'آی‌پیِ نودِ مبدأ')}
function onCreateType(){var f=el('c_subnet');if(f&&f.value.trim()){var wantV6=(ssVal('c_type')=='sit');
  if((f.value.indexOf(':')>=0)!=wantV6)f.value=''}
 renderTypeExtra()}
function renderTypeExtra(){var w=el('c_typex');if(!w)return;var t=ssVal('c_type');
 if(t=='l2tpv3'||t=='fou'){w.innerHTML='<label>پورتِ UDP (اختیاری — خالی = خودکار از شناسه)</label><input id="c_port" inputmode="numeric" placeholder="مثلا 51820"><div class="muted" style="font-size:11px;margin:6px 2px 11px">روی UDP سوار می‌شود؛ برای دورزدنِ فیلتر می‌توانی پورتِ دلخواه بگذاری.</div>'}
 else if(t=='vxlan'){w.innerHTML='<label>پورتِ UDP (خالی = 4789)</label><input id="c_port" inputmode="numeric" placeholder="4789"><div class="muted" style="font-size:11px;margin:6px 2px 11px">پورتِ استانداردِ VXLAN؛ برای دورزدنِ فیلتر می‌توانی عوضش کنی (مثلاً 443).</div>'}
 else if(t=='ipsec'){w.innerHTML='<div class="autonote" style="margin-bottom:11px">'+ic('shield')+'<span>رمزنگاری‌شده (ESP). کلید خودکار ساخته و امن به هر دو سر داده می‌شود — بدونِ دیمنِ خارجی.</span></div>'}
 else w.innerHTML=''}
function nodeName(id){var n=NODES.find(function(x){return x.id==id});return n?n.name:id}
async function doCreate(){var m=el('c_msg');m.className='msg';var a=ssVal('c_a'),b=ssVal('c_b');
 if(a==b){m.className='msg err';m.textContent='دو نودِ متفاوت انتخاب کن';return}
 var type=ssVal('c_type'),range=ssVal('c_snr'),custom=v('c_subnet');
 var aip=el('ssb_c_aip')?ssVal('c_aip'):'',bip=el('ssb_c_bip')?ssVal('c_bip'):'';   // only send an IP when its picker exists (multi-IP node)
 var body={a_node:a,b_node:b,type:type,a_ip:aip,b_ip:bip};
 if(range=='custom')body.subnet=custom;else body.subnet_base=range;
 if((type=='l2tpv3'||type=='fou'||type=='vxlan')&&el('c_port')&&v('c_port'))body.port=v('c_port');
 m.textContent='در حال ساختِ تونل…';
 var r=await post('create-tunnel',body);
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast('تونل ساخته شد','ok');refreshTunnels()}
 else{m.className='msg err';m.textContent=(r.d&&(r.d.error||r.d.msg))||'ناموفق'}}

// ===== Custom core (packet/core) — its own view, list and create form
function coreSkel(){CHK={};el('view').innerHTML='<h1>'+ic('cpu','var(--acc)')+' هستهٔ اختصاصی</h1><p class="sub">تونل‌های هستهٔ اختصاصی (Go) — حالتِ packet/core با رمزنگاریِ داخلی، جدا از تونل‌های سیستمی</p>'+
 '<div class="tbtnrow"><button class="primary" onclick="openCoreModal()">'+ic('plus')+'تونلِ هسته</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+'بررسی اتصال همگانی</button></div>'+
 toolbar('core','جستجوی نام نود / شناسه…')+'<div id="corList"></div>'+pagerBottom('core')}
async function refreshCore(){if(editingId||CHECKING)return;var f=await j('fleet?kind=core&offset='+(PG.core*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.core));FLEET=f.links||[];TOT.core=num(f.total);var box=el('corList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(coreCard).join(''):'<div class="card muted">'+(QRY.core?'موردی یافت نشد.':'هنوز تونلِ هسته‌ای نیست — دکمهٔ «تونلِ هسته» بالا را بزن.')+'</div>');renderPager('core')}
function coreMeta(l){   // right col under box A, left col under box B (lock at the START, green)
 var sub='<div>سابنت: <b class="mono">'+esc(l.subnet)+'</b></div>';
 var tr=(l.transport=='tcp')?'TCP':(l.transport=='raw')?('RAW·'+esc((l.raw_profile||'bip').toUpperCase())):(l.transport=='flux')?('FLUX·'+esc((l.flux_carrier||'udp').toUpperCase())):(l.transport=='ws')?(l.ws_tls?'WSS':'WS'):'UDP';
 var prt=(l.transport!='raw'&&l.transport!='flux'&&l.port)?'<div>پورت: <b class="mono">'+esc(l.port)+'</b></div>':'';
 var car='<div>حامل: <b class="mono">'+tr+'</b></div>';
 var ifc='<div>اینترفیس: <b class="mono">'+esc(l.name)+'</b></div>';
 var typ='<div class="tagrow">نوع: <span class="tag core">Core</span></div>';
 var feats=[];if(l.obfs)feats.push('<span class="tag obfs">obfs</span>');if(l.cover)feats.push('<span class="tag obfs">TLS</span>');if(l.gso)feats.push('<span class="tag obfs">GSO</span>');if(l.fec)feats.push('<span class="tag obfs">FEC '+((l.fec_data||10)+'+'+(l.fec_parity||3))+'</span>');
 var cap='<div class="feat">قابلیت‌ها: '+(feats.length?feats.join(' '):'<span class="nofeat">—</span>')+'</div>';
 var encv=(l.cipher&&l.cipher!='none')
   ?'<span class="encval">'+esc(l.cipher=='auto'?'aes-256-gcm':l.cipher)+'</span>'
   :'<b>بدونِ رمز</b>';
 var enc='<div class="enc-line">رمزنگاری: '+encv+'</div>';
 return '<div class="enmeta"><div class="emcol">'+sub+prt+car+ifc+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+typ+cap+enc+'</div></div>'}
function coreCard(l){
 var srvA=(l.server_side!='b');   // which end listens; stored on the record
 var body='<div class="tninfo">'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="rl '+(srvA?'srv':'cli')+'">'+(srvA?'سرور':'کلاینت')+'</span><span class="stat" id="lba_'+l.id+'">'+accStat(l,'a')+'</span></div><div class="tna mono">'+esc(l.a_ip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="rl '+(srvA?'cli':'srv')+'">'+(srvA?'کلاینت':'سرور')+'</span><span class="stat" id="lbb_'+l.id+'">'+accStat(l,'b')+'</span></div><div class="tna mono">'+esc(l.b_ip)+'</div></div>'+
  '</div>'+
  coreMeta(l);
 var c=CHK[l.id];var msg='<div class="msg '+(c?c.cls:'')+'" id="lchk_'+l.id+'">'+(c?c.html:'')+'</div>';
 var flip='<button class="act flip" onclick="flipView(\\''+l.id+'\\')" title="تعویضِ دیدِ مصرف — فعلاً: '+esc(l.view_name||'—')+'">'+ic('swap')+'</button>';
 var acts='<div class="nact iconly"><button class="act ok" title="تستِ پینگ" onclick="checkLink(\\''+l.id+'\\')">'+ic('activity')+'</button>'+flip+'<button class="act reset" title="ریستِ حجمِ کل" onclick="resetTraffic(\\''+l.id+'\\')">'+ic('reset')+'</button><button class="act warn" title="ویرایش" onclick="openCoreEdit(\\''+l.id+'\\')">'+ic('pen')+'</button><button class="act" title="بازسازی" onclick="rebuildLink(\\''+l.id+'\\')">'+ic('redo')+'</button><button class="act danger" title="حذف" onclick="delLink(\\''+l.id+'\\')">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>آی‌پیِ یکی از نودها عوض شده — بازسازی لازم است.</span></div>':'';
 return accShell(l,true,drift+body+accBodyTraf(l)+acts+msg)}
var _corSrv='a',_corTr='udp',_corObfs=false,_corCover=false,_corRawProfile='bip',_corGso=false,_corFluxCarrier='udp',_corFluxRotate=600,_corFluxShape='random',_corWsTls=false,_corFec=false,_corFecData=10,_corFecParity=3;
var COR_RAW_PROFILES=[{v:'bip',m:'proto 253 · نیتیو',tag:'بهینه'},{v:'icmp',m:'proto 1 · شبیهِ ping'},{v:'gre',m:'proto 47 · GRE',warn:1},{v:'ipip',m:'proto 4 · IP-in-IP',warn:1},{v:'udp',m:'proto 17 · UDP'},{v:'tcp',m:'proto 6 · TCP جعلی'}];
function rawTiles(px,sel){return COR_RAW_PROFILES.map(function(p){return '<button type="button" class="ptile'+(p.v==sel?' on':'')+'" data-p="'+p.v+'" onclick="'+px+'SetProfile(\\''+p.v+'\\')">'+(p.tag?'<span class="best">'+p.tag+'</span>':'')+(p.warn?'<span class="pwarn" title="ممکن است از NAT رد نشود"></span>':'')+'<div class="pn">'+p.v+'</div><div class="pmeta">'+p.m+'</div></button>'}).join('')}
function corSetTr(t){_corTr=t;['udp','tcp','raw','flux','ws'].forEach(function(x){var b=el('e_tr_'+x);if(b)b.classList.toggle('on',t==x)});var w=el('e_trword');if(w)w.textContent=(t=='tcp'?'TCP':(t=='raw'?'raw-IP':(t=='flux'?'flux':(t=='ws'?'ws/TCP':'UDP'))));corRawVis();corFluxVis();corWsVis();corPortGate();corCoverGate();corFecGate();corSpoofVis()}
function corFluxVis(){var w=el('e_fluxblk');if(w)w.style.display=(_corTr=='flux')?'':'none';fluxTick()}
function corWsVis(){var w=el('e_wsblk');if(w)w.style.display=(_corTr=='ws')?'':'none'}
function corToggleWsTls(){_corWsTls=!_corWsTls;var s=el('e_wstls');if(s)s.classList.toggle('on',_corWsTls)}
function corSetFluxCarrier(c){_corFluxCarrier=c;var g=el('e_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fc]'),function(t){t.classList.toggle('on',t.getAttribute('data-fc')==c)});fluxTick()}
function corSetFluxShape(s){_corFluxShape=s;var g=el('e_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fs]'),function(t){t.classList.toggle('on',t.getAttribute('data-fs')==s)})}
function corFluxRotChg(){_corFluxRotate=parseInt(ssVal('e_fluxrot'))||600;fluxTick()}
function corFecDatagram(){return _corTr=='udp'||_corTr=='raw'||_corTr=='flux'}
function corToggleFec(){if(!corFecDatagram())return;_corFec=!_corFec;var s=el('e_fecsw');if(s)s.classList.toggle('on',_corFec);var r=el('e_fecrates');if(r)r.style.display=_corFec?'':'none'}
function corSetFecRate(d,p){_corFecData=d;_corFecParity=p;var g=el('e_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function corFecGate(){var dg=corFecDatagram(),row=el('e_fecrow');if(!dg){_corFec=false;var s=el('e_fecsw');if(s)s.classList.remove('on');var r=el('e_fecrates');if(r)r.style.display='none'}if(row)row.classList.toggle('dis',!dg)}
async function doFluxRotate(id){var r=await post('flux-rotate',{id:id});if(r.ok&&r.d.ok){toast('چرخش انجام شد — تونل بازسازی شد','ok');fluxTick()}else{toast((r.d&&(r.d.error||r.d.msg))||'ناموفق','err')}}
// ---- IP spoofing (decoy) section — shared markup + per-form logic. Only for raw + bip.
function spoofSection(idp,fnp){return '<div class="spoofsec" id="'+idp+'spoofblk" style="display:none">'
 +'<div class="spoofhd">'+ic('shield')+'جعلِ آی‌پی (استتار)</div>'
 +'<div class="tglbox" id="'+idp+'decoyrow"><div class="tglsw" id="'+idp+'decoysw" onclick="'+fnp+'ToggleDecoy()"></div><div class="tt"><b>جعلِ مقصد (Decoy)</b><small>روی سیم وانمود می‌شود ترافیک به آی‌پیِ زیر می‌رود، ولی واقعاً به سرورت می‌رسد.</small></div></div>'
 +'<div id="'+idp+'decoyiprow" style="display:none;margin:8px 0 2px"><input id="'+idp+'decoyip" class="mono" placeholder="آی‌پیِ طُعمه (مقصدِ جعلی) — مثلاً 185.51.200.10" inputmode="numeric"></div>'
 +'<div class="tglbox" id="'+idp+'srcrow"><div class="tglsw" id="'+idp+'srcsw" onclick="'+fnp+'ToggleSrc()"></div><div class="tt"><b>جعلِ مبدأ</b><small>آی‌پیِ مبدأِ واقعی روی سیم مخفی می‌شود (اختیاری).</small></div></div>'
 +'<div id="'+idp+'srciprow" style="display:none;margin:8px 0 2px"><input id="'+idp+'srcip" class="mono" placeholder="آی‌پیِ مبدأِ جعلی — مثلاً 198.51.100.9" inputmode="numeric"></div>'
 +'<div class="spoofcap wait" id="'+idp+'cap">…</div></div>'}
async function spoofProbePair(a,b){try{
  var ra=await j('spoof-probe?node='+encodeURIComponent(a));
  var rb=(a==b)?ra:await j('spoof-probe?node='+encodeURIComponent(b));
  if(ra.ok&&rb.ok)return {ok:true,html:'<b>هر دو نود از نظرِ فنی مجازند.</b> ولی اینکه واقعاً کار کند به خروجیِ دیتاسنتر و مسیر هم بستگی دارد — این چک فقط قابلیتِ نودها را می‌سنجد، نه آن را؛ با ساختِ تونل قطعی می‌شود.'};
  var bad=(!ra.ok)?ra:rb;
  return {ok:false,html:'<b>غیرفعال — روی نودِ «'+esc(bad.node||'?')+'» نمی‌شود.</b> علت: '+esc(bad.reason||'نامشخص')};
 }catch(e){return {ok:false,html:'<b>بررسی ناموفق بود.</b> نتوانستم امکانِ جعل را از نودها بپرسم.'}}}
function spoofApplyCap(idp,ok,html,offFn){var cap=el(idp+'cap');if(cap){cap.className='spoofcap '+(ok?'ok':'no');cap.innerHTML=(ok?ic('okc'):ic('xc'))+'<span>'+html+'</span>'}
 var dr=el(idp+'decoyrow'),sr=el(idp+'srcrow');
 if(dr)dr.classList.toggle('dis',!ok);if(sr)sr.classList.toggle('dis',!ok);
 if(!ok&&offFn)offFn()}
// ---- flux (polymorphic moving-target carrier) — shared markup + live epoch status.
var FLUX_ROTS=[{v:'600',label:'هر ۱۰ دقیقه (پیش‌فرض)'},{v:'300',label:'هر ۵ دقیقه'},{v:'1800',label:'هر ۳۰ دقیقه'},{v:'3600',label:'هر ۱ ساعت'}];
var FLUX_SHAPES=[{v:'random',n:'تصادفی',m:'بدونِ تقلید'},{v:'quic',n:'QUIC',m:'شبیهِ HTTP/3'},{v:'video',n:'ویدیوکال',m:'بسته‌های بزرگ'},{v:'webrtc',n:'WebRTC',m:'RTPِ کوچک'}];
// FEC redundancy presets: data+parity, overhead label, and the max burst loss they repair.
var FEC_RATES=[{d:10,p:2,n:'سبک',ov:'۲۰٪ سربار'},{d:10,p:3,n:'متعادل',ov:'۳۰٪ سربار'},{d:8,p:4,n:'قوی',ov:'۵۰٪ سربار'}];
function fluxSection(idp,fnp,fc,rot,shp,rotId){return '<div id="'+idp+'fluxblk" style="display:none">'
 +'<label>حاملِ flux</label>'
 +'<div class="pgrid">'
 +'<button type="button" class="ptile'+(fc=='udp'?' on':'')+'" data-fc="udp" onclick="'+fnp+'SetFluxCarrier(\\'udp\\')"><span class="best">اینترنت</span><div class="pn">udp</div><div class="pmeta">UDPِ واقعی · پورت می‌چرخد</div></button>'
 +'<button type="button" class="ptile'+(fc=='stun'?' on':'')+'" data-fc="stun" onclick="'+fnp+'SetFluxCarrier(\\'stun\\')"><span class="best">WebRTC</span><div class="pn">stun</div><div class="pmeta">هدرِ STUN · شبیهِ تماسِ تصویری</div></button>'
 +'<button type="button" class="ptile'+(fc=='raw'?' on':'')+'" data-fc="raw" onclick="'+fnp+'SetFluxCarrier(\\'raw\\')"><span class="pwarn" title="فقط هم‌سگمنت / L2"></span><div class="pn">raw</div><div class="pmeta">protoِ IP خام · فقط L2</div></button>'
 +'</div>'
 +'<label>پروفایلِ شکل — شبیهِ چه ترافیکی</label>'
 +'<div class="pgrid">'+FLUX_SHAPES.map(function(p){return '<button type="button" class="ptile'+(p.v==(shp||'random')?' on':'')+'" data-fs="'+p.v+'" onclick="'+fnp+'SetFluxShape(\\''+p.v+'\\')"><div class="pn">'+p.n+'</div><div class="pmeta">'+p.m+'</div></button>'}).join('')+'</div>'
 +'<label>بازهٔ چرخش</label>'+ssHTML(idp+'fluxrot',FLUX_ROTS,String(rot||600),'بازه',fnp+'FluxRotChg')
 +'<div id="'+idp+'fluxstat" style="margin-top:10px;font-size:11.5px;padding:8px 11px;border-radius:9px;line-height:1.8;background:color-mix(in srgb,var(--ok) 9%,transparent);border:1px solid color-mix(in srgb,var(--ok) 28%,transparent)">…</div>'
 +(rotId?'<button type="button" class="ghost" style="margin-top:9px;width:100%;display:inline-flex;align-items:center;justify-content:center;gap:6px" onclick="doFluxRotate(\\''+rotId+'\\')">'+ic('redo')+'چرخشِ الان (epoch را جلو می‌برد؛ لحظه‌ای قطع)</button>':'')
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">شکلِ سیم هر بازه <b>بی‌سیگنال</b> می‌چرخد — هر دو سر از ساعت یک epoch می‌سازند. <b>udp/stun</b> رویِ اینترنت رد می‌شوند؛ <b>raw</b> فقط هم‌سگمنت. رمزنگاری الزامی است.</div>'
 +'</div>'}
// ---- FEC (forward error correction) — a general feature box shown for every carrier, but
// active only on the datagram carriers (udp/raw/flux); greyed on tcp/ws (TCP is already reliable).
function fecSection(idp,fnp,fec,fd,fp,dg){return '<div id="'+idp+'fecrow" class="tglbox'+(dg?'':' dis')+'" style="margin-top:11px"><div class="tglsw'+(fec&&dg?' on':'')+'" id="'+idp+'fecsw" onclick="'+fnp+'ToggleFec()"></div><div class="tt"><b>تصحیحِ خطا (FEC)</b><small>پکت‌های گم‌شده را با پریتی و بدونِ ری‌ترنسمیت بازسازی می‌کند — برای لینکِ پُرافت/throttle. سربارِ پهنای‌باند دارد؛ فقط رو حاملِ دیتاگرامی (udp/raw/flux)، رو tcp/ws بی‌اثر.</small></div></div>'
 +'<div id="'+idp+'fecrates" style="'+(fec?'':'display:none')+'"><label>نرخِ افزونگیِ FEC</label><div class="pgrid">'+FEC_RATES.map(function(r){var sel=(r.d==(fd||10)&&r.p==(fp||3));return '<button type="button" class="ptile'+(sel?' on':'')+'" data-fd="'+r.d+'" data-fp="'+r.p+'" onclick="'+fnp+'SetFecRate('+r.d+','+r.p+')"><div class="pn">'+r.d+'+'+r.p+'</div><div class="pmeta">'+r.n+'</div><div class="pmeta" style="color:var(--warn)">'+r.ov+'</div></button>'}).join('')+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">«۱۰+۳» یعنی هر ۱۰ پکتِ داده، ۳ پکتِ پریتی؛ گیرنده تا ۳ تا از هر ۱۳ تا را گم کند بازسازی می‌کند. هر دو سرِ تونل یک تنظیم می‌گیرند.</div></div>'}
// ---- ws (WebSocket / CDN) — shared markup.
function wsSection(idp,fnp,host,path,tls,edge){return '<div id="'+idp+'wsblk" style="display:none">'
 +'<label>دامنهٔ فرانت (Host / SNI)</label><input id="'+idp+'wshost" placeholder="مثلاً cdn.example.com" value="'+esc(host||'')+'">'
 +'<div class="tglbox" style="margin-top:11px"><div class="tglsw'+(tls?' on':'')+'" id="'+idp+'wstls" onclick="'+fnp+'ToggleWsTls()"></div><div class="tt"><b>wss (TLS به CDN)</b><small>کلاینت با TLS به لبهٔ CDN وصل می‌شود؛ سرور پشتِ CDN ساده می‌ماند. برای فرانتینگ لازم است.</small></div></div>'
 +'<label>آی‌پیِ لبهٔ CDN (اختیاری) — کلاینت به‌جای مبدأ به این وصل می‌شود</label><input id="'+idp+'wsedge" class="mono" placeholder="مثلاً 104.16.0.1 یا 104.16.0.1:443" value="'+esc(edge||'')+'">'
 +'<label>مسیر (path)</label><input id="'+idp+'wspath" placeholder="/" value="'+esc(path||'')+'">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">ترافیک شبیهِ WebSocket رویِ CDN دیده می‌شود (collateral freedom). سرور را پشتِ یک CDN (مثل Cloudflare) با همین دامنه بگذار. اگر <b>لبهٔ CDN</b> را پر کنی، کلاینت مستقیم به لبه وصل می‌شود و دامنه فقط در Host/SNI می‌رود؛ خالی بگذاری، به آی‌پیِ مبدأ وصل می‌شود. رمزنگاری/استتار مثلِ TCP اعمال می‌شود.</div>'
 +'</div>'}
function fluxStatText(fc,rot){var now=Math.floor(Date.now()/1000);rot=rot||600;var ep=Math.floor(now/rot),nx=rot-(now%rot),mm=Math.floor(nx/60),ss=nx%60;
 return '<b style="color:var(--ok)">شکلِ زنده</b> · epoch <span class="mono">#'+ep+'</span> · حامل <span class="mono">'+fc+'</span> · چرخشِ بعدی تا <b>'+mm+':'+(ss<10?'0':'')+ss+'</b> دیگر';}
function fluxTick(){[['e_',_corTr,_corFluxCarrier,_corFluxRotate],['ee_',_eeTr,_eeFluxCarrier,_eeFluxRotate]].forEach(function(a){
 var w=el(a[0]+'fluxstat');if(w&&a[1]=='flux')w.innerHTML=fluxStatText(a[2],a[3]);});}
setInterval(fluxTick,1000);
var _corDecoy=false,_corSrc=false,_corSpoofOk=false;
function corSpoofVis(){var w=el('e_spoofblk');if(!w)return;var show=(_corTr=='raw'&&_corRawProfile=='bip');w.style.display=show?'':'none';if(show)corSpoofProbe()}
async function corSpoofProbe(){var cap=el('e_cap');if(!cap)return;cap.className='spoofcap wait';cap.innerHTML='بررسیِ امکانِ جعل روی نودها…';
 var res=await spoofProbePair(ssVal('e_a'),ssVal('e_b'));_corSpoofOk=res.ok;
 spoofApplyCap('e_',res.ok,res.html,function(){_corDecoy=false;_corSrc=false;
  var d=el('e_decoysw'),s=el('e_srcsw');if(d)d.classList.remove('on');if(s)s.classList.remove('on');
  var di=el('e_decoyiprow'),si=el('e_srciprow');if(di)di.style.display='none';if(si)si.style.display='none'})}
function corToggleDecoy(){if(!_corSpoofOk)return;_corDecoy=!_corDecoy;el('e_decoysw').classList.toggle('on',_corDecoy);el('e_decoyiprow').style.display=_corDecoy?'':'none'}
function corToggleSrc(){if(!_corSpoofOk)return;_corSrc=!_corSrc;el('e_srcsw').classList.toggle('on',_corSrc);el('e_srciprow').style.display=_corSrc?'':'none'}
function corRawVis(){var w=el('e_rawblk');if(w)w.style.display=(_corTr=='raw')?'':'none'}
function corPortGate(){var p=el('e_port');if(!p)return;var np=(_corTr=='raw'||_corTr=='flux');p.disabled=np;if(np)p.value='';p.placeholder=(_corTr=='flux')?'flux پورت ثابت ندارد':(np?'raw پورت ندارد':'20050')}
function corSetProfile(p){_corRawProfile=p;var g=el('e_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});corSpoofVis()}
function corToggleGso(){_corGso=!_corGso;var s=el('e_gso');if(s)s.classList.toggle('on',_corGso)}
function corToggleObfs(){if(ssVal('e_cipher')=='none')return;_corObfs=!_corObfs;var s=el('e_obfs');if(s)s.classList.toggle('on',_corObfs)}
function corToggleCover(){if(_corTr!='tcp')return;_corCover=!_corCover;var s=el('e_cover');if(s)s.classList.toggle('on',_corCover);corSniVis()}
function corSniVis(){var w=el('e_snirow');if(w)w.style.display=(_corCover&&_corTr=='tcp')?'':'none'}
function corCoverGate(){var tcp=_corTr=='tcp',row=el('e_coverrow'),s=el('e_cover');if(!tcp){_corCover=false;if(s)s.classList.remove('on')}if(row)row.classList.toggle('dis',!tcp);corSniVis()}
function onCorCipher(){var none=ssVal('e_cipher')=='none',row=el('e_obfsrow'),s=el('e_obfs');
 if(none){_corObfs=false;if(s)s.classList.remove('on')}if(row)row.classList.toggle('dis',none)}
async function openCoreModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(on.length<2){toast('حداقل ۲ نودِ آنلاین لازم است','err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});_corSrv='a';_corTr='udp';_corObfs=false;_corCover=false;_corRawProfile='bip';_corGso=false;_corDecoy=false;_corSrc=false;_corSpoofOk=false;_corFluxCarrier='udp';_corFluxRotate=600;_corFluxShape='random';_corWsTls=false;_corFec=false;_corFecData=10;_corFecParity=3;
 var b='<div class="grid2"><div><label class="first">نودِ مبدأ</label>'+ssHTML('e_a',items,items[0].v,'نودِ مبدأ','onCorNode')+'</div>'+
  '<div><label class="first">نودِ مقصد</label>'+ssHTML('e_b',items,items[1].v,'نودِ مقصد','onCorNode')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="e_aip"></div><div id="e_bip"></div></div>'+
  '<label>نقش‌ها — کدام نود listen کند (سرور)</label><div class="seg2" id="e_roles"><button type="button" class="segopt on" id="e_srv_a" onclick="corSetSrv(\\'a\\')"></button><button type="button" class="segopt" id="e_srv_b" onclick="corSetSrv(\\'b\\')"></button></div>'+
  '<div class="muted" style="font-size:11px;margin:-5px 2px 11px">نودِ سرور پورتِ <span id="e_trword">UDP</span> را باز می‌کند؛ نودِ کلاینت (معمولاً پشتِ NAT) به آن وصل می‌شود.</div>'+
  '<div class="autonote">'+ic('warn')+'<span><b>توصیه: سرور را سمتِ خارج بگذار.</b> اگر نودِ ایران پشتِ NAT باشد یا پورتش فیلتر شود، ایران‌سرور وصل نمی‌شود. اگر آی‌پیِ عمومیِ باز داشته باشد ممکن است کار کند، ولی ورودی به ایران بیشتر فیلتر/پایش می‌شود و کم‌دوام‌تر است.</span></div>'+
  '<label>روشِ رمزنگاری</label>'+ssHTML('e_cipher',CORE_CIPHERS,'auto','رمز','onCorCipher')+
  '<label>حاملِ اتصال</label><div class="seg2"><button type="button" class="segopt on" id="e_tr_udp" onclick="corSetTr(\\'udp\\')"><b>UDP</b><span>دیتاگرام</span></button><button type="button" class="segopt" id="e_tr_tcp" onclick="corSetTr(\\'tcp\\')"><b>TCP</b><span>پایدارتر</span></button><button type="button" class="segopt" id="e_tr_raw" onclick="corSetTr(\\'raw\\')"><b>RAW</b><span>پکتِ خام</span></button><button type="button" class="segopt" id="e_tr_flux" onclick="corSetTr(\\'flux\\')"><b>FLUX</b><span>جهش‌پذیر</span></button><button type="button" class="segopt" id="e_tr_ws" onclick="corSetTr(\\'ws\\')"><b>WS</b><span>CDN</span></button></div>'+
  '<div id="e_rawblk" style="display:none"><label>پروفایلِ کپسوله‌سازی (raw)</label><div class="pgrid" id="e_pg">'+rawTiles('cor','bip')+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">هر دو طرف باید یک پروفایل داشته باشند. <b>bip</b> بهینه است؛ نقطهٔ طلایی یعنی ممکن است از NATِ ایران رد نشود. حاملِ raw به <b>root</b> و رمزنگاری نیاز دارد.</div></div>'+
  fluxSection('e_','cor','udp',600,'random',null)+
  wsSection('e_','cor','','',false,'')+
  spoofSection('e_','cor')+
  '<div class="tglbox" id="e_obfsrow"><div class="tglsw" id="e_obfs" onclick="corToggleObfs()"></div><div class="tt"><b>استتار در برابرِ DPI</b><small>حذفِ امضا · پَدینگ/جیتر · مقاومت در برابرِ probe. رمزنگاری لازم است.</small></div></div>'+
  '<div class="tglbox dis" id="e_coverrow"><div class="tglsw" id="e_cover" onclick="corToggleCover()"></div><div class="tt"><b>پوششِ TLS (شبیهِ HTTPS)</b><small>ترافیک شبیهِ HTTPS دیده می‌شود و در برابرِ پروبِ فعال هم مقاوم است. فقط با حاملِ TCP.</small></div></div>'+
  '<div id="e_snirow" style="display:none"><label>سایتِ پوشش (SNI) — الزامی</label><input id="e_sni" placeholder="مثلاً یک سایتِ HTTPSِ واقعی و محبوب"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">سرور برای هر اتصالِ ناشناس (پروب/فیلترچی) <b>واقعاً به این سایت وصل می‌شود</b> و ترافیک را به آن پراکسی می‌کند، پس پروب گواهیِ اصلیِ همان سایت را می‌بیند (مقاوم در برابرِ پروبِ فعال). پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد — ترجیحاً روی یک CDNِ بزرگ.</div></div>'+
  '<div class="tglbox" id="e_gsorow"><div class="tglsw" id="e_gso" onclick="corToggleGso()"></div><div class="tt"><b>شتاب‌دهیِ GSO/GRO</b><small>عبورِ حجیم را سریع‌تر می‌کند (پکت‌های بزرگ، syscallِ کمتر). فقط لینوکس؛ اگر پشتیبانی نشود بی‌اثر است.</small></div></div>'+
  fecSection('e_','cor',false,10,3,true)+
  '<label>سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه)</label>'+ssHTML('e_snr',SUBNETRANGES,'192.168','رنج','onCorSubRange')+'<div id="e_snc"></div>'+
  '<label>پورت (خالی=خودکار · می‌توانی 443 بگذاری)</label><input id="e_port" inputmode="numeric" placeholder="20050">'+
  '<div class="msg" id="e_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('cpu')+'</span><div class="ttl"><h3>تونلِ هسته</h3><div class="sb">هستهٔ اختصاصی · packet/core</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreateCore()">ساختِ تونل</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>',{cls:'edit'});
 corRoleLbls();renderCorIps();corCoverGate();corPortGate()}
function onCorNode(){renderCorIps();corRoleLbls();if(el('e_spoofblk')&&_corTr=='raw'&&_corRawProfile=='bip')corSpoofProbe()}
function renderCorIps(){['a','b'].forEach(function(side){var w=el('e_'+side+'ip');if(!w)return;
 var ips=nodeIps(ssVal('e_'+side)),lab=(side=='a')?'آی‌پیِ نودِ مبدأ':'آی‌پیِ نودِ مقصد';
 w.innerHTML=ipField('e_'+side+'ip_sel',ips,lab)})}
function onCorSubRange(){var w=el('e_snc');if(!w)return;w.innerHTML=(ssVal('e_snr')=='custom')?'<label>سابنتِ دلخواه</label><input id="e_subnet" placeholder="مثلا 192.168.99.0/24">':''}
function corRoleLbls(){var an=nodeName(ssVal('e_a')),bn=nodeName(ssVal('e_b')),a=el('e_srv_a'),b=el('e_srv_b');
 if(a)a.innerHTML='<b>'+esc(an)+' سرور</b><span>'+esc(bn)+' کلاینت</span>';
 if(b)b.innerHTML='<b>'+esc(bn)+' سرور</b><span>'+esc(an)+' کلاینت</span>'}
function corSetSrv(s){_corSrv=s;var a=el('e_srv_a'),b=el('e_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b')}
async function doCreateCore(){var m=el('e_msg');m.className='msg';var a=ssVal('e_a'),bb=ssVal('e_b');
 if(a==bb){m.className='msg err';m.textContent='دو نودِ متفاوت انتخاب کن';return}
 var body={a_node:a,b_node:bb,type:'core',server_side:_corSrv,cipher:ssVal('e_cipher'),transport:_corTr,obfs:_corObfs,cover:(_corCover&&_corTr=='tcp'),gso:_corGso};
 if(_corTr=='raw'){if(ssVal('e_cipher')=='none'){m.className='msg err';m.textContent='حاملِ raw به رمزنگاری نیاز دارد';return}body.raw_profile=_corRawProfile}
 if(_corTr=='flux'){if(ssVal('e_cipher')=='none'){m.className='msg err';m.textContent='حاملِ flux به رمزنگاری نیاز دارد';return}body.flux_carrier=_corFluxCarrier;body.flux_rotate_secs=_corFluxRotate;body.flux_shape=_corFluxShape}
 if(corFecDatagram()){body.fec=_corFec;if(_corFec){body.fec_data=_corFecData;body.fec_parity=_corFecParity}}
 if(_corTr=='ws'){body.ws_host=(v('e_wshost')||'').trim();body.ws_path=(v('e_wspath')||'').trim();body.ws_tls=_corWsTls;body.edge_ip=(v('e_wsedge')||'').trim();if(_corWsTls&&!body.ws_host){m.className='msg err';m.textContent='برای wss باید دامنه (Host) را وارد کنی';return}}
 if(_corTr=='raw'&&_corRawProfile=='bip'&&_corSpoofOk){
  if(_corDecoy){var dip=(v('e_decoyip')||'').trim();if(!dip){m.className='msg err';m.textContent='آی‌پیِ طُعمه (مقصدِ جعلی) را وارد کن';return}body.spoof_dst=dip}
  if(_corSrc){var sip=(v('e_srcip')||'').trim();if(sip)body.spoof_src=sip}}
 if(body.cover){var sni=(v('e_sni')||'').trim();if(!sni){m.className='msg err';m.textContent='برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی';return}body.cover_sni=sni}
 var aip=el('ssb_e_aip_sel')?ssVal('e_aip_sel'):'';if(aip)body.a_ip=aip;
 var bip=el('ssb_e_bip_sel')?ssVal('e_bip_sel'):'';if(bip)body.b_ip=bip;
 var range=ssVal('e_snr');if(range=='custom'){var sub=v('e_subnet');if(sub)body.subnet=sub}else{body.subnet_base=range}
 var port=v('e_port');if(port)body.port=port;
 m.textContent='در حال ساختِ تونلِ هسته روی دو نود…';
 var r=await post('create-tunnel',body);
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast('تونلِ هسته ساخته شد','ok');refreshCore()}
 else{m.className='msg err';m.textContent=r.d.error||r.d.msg||'ناموفق'}}
// ===== core edit (cipher / role / port / subnet / ips -> rebuild both ends)
var _eeSrv='a',_eeTr='udp',_eeObfs=false,_eeCover=false,_eeRawProfile='bip',_eeGso=false,_eeFluxCarrier='udp',_eeFluxRotate=600,_eeFluxShape='random',_eeWsTls=false,_eeFec=false,_eeFecData=10,_eeFecParity=3;
function ceSetTr(t){_eeTr=t;['udp','tcp','raw','flux','ws'].forEach(function(x){var b=el('ee_tr_'+x);if(b)b.classList.toggle('on',t==x)});ceRawVis();ceFluxVis();ceWsVis();cePortGate();ceCoverGate();ceFecGate();ceSpoofVis()}
function ceFluxVis(){var w=el('ee_fluxblk');if(w)w.style.display=(_eeTr=='flux')?'':'none';fluxTick()}
function ceWsVis(){var w=el('ee_wsblk');if(w)w.style.display=(_eeTr=='ws')?'':'none'}
function ceToggleWsTls(){_eeWsTls=!_eeWsTls;var s=el('ee_wstls');if(s)s.classList.toggle('on',_eeWsTls)}
function ceSetFluxCarrier(c){_eeFluxCarrier=c;var g=el('ee_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fc]'),function(t){t.classList.toggle('on',t.getAttribute('data-fc')==c)});fluxTick()}
function ceSetFluxShape(s){_eeFluxShape=s;var g=el('ee_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fs]'),function(t){t.classList.toggle('on',t.getAttribute('data-fs')==s)})}
function ceFluxRotChg(){_eeFluxRotate=parseInt(ssVal('ee_fluxrot'))||600;fluxTick()}
function ceFecDatagram(){return _eeTr=='udp'||_eeTr=='raw'||_eeTr=='flux'}
function ceToggleFec(){if(!ceFecDatagram())return;_eeFec=!_eeFec;var s=el('ee_fecsw');if(s)s.classList.toggle('on',_eeFec);var r=el('ee_fecrates');if(r)r.style.display=_eeFec?'':'none'}
function ceSetFecRate(d,p){_eeFecData=d;_eeFecParity=p;var g=el('ee_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function ceFecGate(){var dg=ceFecDatagram(),row=el('ee_fecrow');if(!dg){_eeFec=false;var s=el('ee_fecsw');if(s)s.classList.remove('on');var r=el('ee_fecrates');if(r)r.style.display='none'}if(row)row.classList.toggle('dis',!dg)}
var _eeDecoy=false,_eeSrc=false,_eeSpoofOk=false,_eeNodesArr=['',''];
function ceSpoofVis(){var w=el('ee_spoofblk');if(!w)return;var show=(_eeTr=='raw'&&_eeRawProfile=='bip');w.style.display=show?'':'none';if(show)ceSpoofProbe()}
async function ceSpoofProbe(){var cap=el('ee_cap');if(!cap)return;cap.className='spoofcap wait';cap.innerHTML='بررسیِ امکانِ جعل روی نودها…';
 var res=await spoofProbePair(_eeNodesArr[0],_eeNodesArr[1]);_eeSpoofOk=res.ok;
 spoofApplyCap('ee_',res.ok,res.html,function(){_eeDecoy=false;_eeSrc=false;
  var d=el('ee_decoysw'),s=el('ee_srcsw');if(d)d.classList.remove('on');if(s)s.classList.remove('on');
  var di=el('ee_decoyiprow'),si=el('ee_srciprow');if(di)di.style.display='none';if(si)si.style.display='none'})}
function ceToggleDecoy(){if(!_eeSpoofOk)return;_eeDecoy=!_eeDecoy;el('ee_decoysw').classList.toggle('on',_eeDecoy);el('ee_decoyiprow').style.display=_eeDecoy?'':'none'}
function ceToggleSrc(){if(!_eeSpoofOk)return;_eeSrc=!_eeSrc;el('ee_srcsw').classList.toggle('on',_eeSrc);el('ee_srciprow').style.display=_eeSrc?'':'none'}
function ceSpoofPrefill(l){var di=el('ee_decoyip'),si=el('ee_srcip');if(di&&l.spoof_dst)di.value=l.spoof_dst;if(si&&l.spoof_src)si.value=l.spoof_src;
 _eeDecoy=!!l.spoof_dst;_eeSrc=!!l.spoof_src;
 var d=el('ee_decoysw'),s=el('ee_srcsw');if(d)d.classList.toggle('on',_eeDecoy);if(s)s.classList.toggle('on',_eeSrc);
 var dr=el('ee_decoyiprow'),sr=el('ee_srciprow');if(dr)dr.style.display=_eeDecoy?'':'none';if(sr)sr.style.display=_eeSrc?'':'none'}
function ceRawVis(){var w=el('ee_rawblk');if(w)w.style.display=(_eeTr=='raw')?'':'none'}
function cePortGate(){var p=el('ee_port');if(!p)return;var np=(_eeTr=='raw'||_eeTr=='flux');p.disabled=np;if(np)p.value='';p.placeholder=(_eeTr=='flux')?'flux پورت ثابت ندارد':(np?'raw پورت ندارد':'20050')}
function ceSetProfile(p){_eeRawProfile=p;var g=el('ee_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});ceSpoofVis()}
function ceToggleGso(){_eeGso=!_eeGso;var s=el('ee_gso');if(s)s.classList.toggle('on',_eeGso)}
function ceToggleObfs(){if(ssVal('ee_cipher')=='none')return;_eeObfs=!_eeObfs;var s=el('ee_obfs');if(s)s.classList.toggle('on',_eeObfs)}
function ceToggleCover(){if(_eeTr!='tcp')return;_eeCover=!_eeCover;var s=el('ee_cover');if(s)s.classList.toggle('on',_eeCover);ceSniVis()}
function ceSniVis(){var w=el('ee_snirow');if(w)w.style.display=(_eeCover&&_eeTr=='tcp')?'':'none'}
function ceCoverGate(){var tcp=_eeTr=='tcp',row=el('ee_coverrow'),s=el('ee_cover');if(!tcp){_eeCover=false;if(s)s.classList.remove('on')}if(row)row.classList.toggle('dis',!tcp);ceSniVis()}
function onEeCipher(){var none=ssVal('ee_cipher')=='none',row=el('ee_obfsrow'),s=el('ee_obfs');
 if(none){_eeObfs=false;if(s)s.classList.remove('on')}if(row)row.classList.toggle('dis',none)}
function openCoreEdit(id){var l=FLEET.filter(function(x){return x.id==id})[0];if(!l){toast('یافت نشد','err');return}
 editingId=id;_eeSrv=(l.server_side=='b')?'b':'a';_eeTr=(['tcp','raw','flux','ws'].indexOf(l.transport)>=0)?l.transport:'udp';_eeObfs=!!l.obfs;_eeCover=!!l.cover&&_eeTr=='tcp';_eeRawProfile=l.raw_profile||'bip';_eeGso=!!l.gso;_eeDecoy=!!l.spoof_dst;_eeSrc=!!l.spoof_src;_eeSpoofOk=false;_eeNodesArr=[l.a_node,l.b_node];_eeFluxCarrier=l.flux_carrier||'udp';_eeFluxRotate=l.flux_rotate_secs||600;_eeFluxShape=l.flux_shape||'random';_eeWsTls=!!l.ws_tls;_eeFec=!!l.fec;_eeFecData=l.fec_data||10;_eeFecParity=l.fec_parity||3;
 var aips=l.a_ips||[],bips=l.b_ips||[];
 function ipsel(side,cur,ips,nm){var k='ee_'+side+'ip';if(ips.length>1){var lab=(side=='a')?'آی‌پیِ نودِ مبدأ':'آی‌پیِ نودِ مقصد';return '<label>'+lab+' <small>(چند آی‌پی دارد — یکی را برای تونل انتخاب کن)</small></label>'+ssHTML(k,ipItems(ips),(ips.indexOf(cur)>=0?cur:ips[0]),'آی‌پی','')}return ''}
 var b='<div class="muted" style="font-size:12px;margin-bottom:10px">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+' · <span class="mono">'+esc(l.name)+'</span></div>'+
  ipsel('a',l.a_ip,aips,l.a_name)+ipsel('b',l.b_ip,bips,l.b_name)+
  '<label>نقش‌ها — کدام نود listen کند (سرور)</label><div class="seg2"><button type="button" class="segopt'+(_eeSrv=='a'?' on':'')+'" id="ee_srv_a" onclick="ceSetSrv(\\'a\\')"></button><button type="button" class="segopt'+(_eeSrv=='b'?' on':'')+'" id="ee_srv_b" onclick="ceSetSrv(\\'b\\')"></button></div>'+
  '<div class="autonote">'+ic('warn')+'<span><b>توصیه: سرور را سمتِ خارج بگذار.</b> اگر نودِ ایران پشتِ NAT باشد یا پورتش فیلتر شود، ایران‌سرور وصل نمی‌شود. اگر آی‌پیِ عمومیِ باز داشته باشد ممکن است کار کند، ولی ورودی به ایران بیشتر فیلتر/پایش می‌شود و کم‌دوام‌تر است.</span></div>'+
  '<label>روشِ رمزنگاری</label>'+ssHTML('ee_cipher',CORE_CIPHERS,(l.cipher||'auto'),'رمز','onEeCipher')+
  '<label>حاملِ اتصال</label><div class="seg2"><button type="button" class="segopt'+(_eeTr=='udp'?' on':'')+'" id="ee_tr_udp" onclick="ceSetTr(\\'udp\\')"><b>UDP</b><span>دیتاگرام</span></button><button type="button" class="segopt'+(_eeTr=='tcp'?' on':'')+'" id="ee_tr_tcp" onclick="ceSetTr(\\'tcp\\')"><b>TCP</b><span>پایدارتر</span></button><button type="button" class="segopt'+(_eeTr=='raw'?' on':'')+'" id="ee_tr_raw" onclick="ceSetTr(\\'raw\\')"><b>RAW</b><span>پکتِ خام</span></button><button type="button" class="segopt'+(_eeTr=='flux'?' on':'')+'" id="ee_tr_flux" onclick="ceSetTr(\\'flux\\')"><b>FLUX</b><span>جهش‌پذیر</span></button><button type="button" class="segopt'+(_eeTr=='ws'?' on':'')+'" id="ee_tr_ws" onclick="ceSetTr(\\'ws\\')"><b>WS</b><span>CDN</span></button></div>'+
  '<div id="ee_rawblk" style="display:'+((_eeTr=='raw')?'':'none')+'"><label>پروفایلِ کپسوله‌سازی (raw)</label><div class="pgrid" id="ee_pg">'+rawTiles('ce',_eeRawProfile)+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">هر دو طرف باید یک پروفایل داشته باشند. <b>bip</b> بهینه است؛ نقطهٔ طلایی یعنی ممکن است از NAT رد نشود. حاملِ raw به <b>root</b> و رمزنگاری نیاز دارد.</div></div>'+
  fluxSection('ee_','ce',_eeFluxCarrier,_eeFluxRotate,_eeFluxShape,id)+
  wsSection('ee_','ce',l.ws_host,l.ws_path,_eeWsTls,l.edge_ip)+
  spoofSection('ee_','ce')+
  '<div class="tglbox'+((l.cipher=='none')?' dis':'')+'" id="ee_obfsrow"><div class="tglsw'+(_eeObfs?' on':'')+'" id="ee_obfs" onclick="ceToggleObfs()"></div><div class="tt"><b>استتار در برابرِ DPI</b><small>حذفِ امضا · پَدینگ/جیتر · مقاومت در برابرِ probe. رمزنگاری لازم است.</small></div></div>'+
  '<div class="tglbox'+((_eeTr!='tcp')?' dis':'')+'" id="ee_coverrow"><div class="tglsw'+(_eeCover?' on':'')+'" id="ee_cover" onclick="ceToggleCover()"></div><div class="tt"><b>پوششِ TLS (شبیهِ HTTPS)</b><small>ترافیک شبیهِ HTTPS دیده می‌شود و در برابرِ پروبِ فعال هم مقاوم است. فقط با حاملِ TCP.</small></div></div>'+
  '<div id="ee_snirow" style="display:'+((_eeCover&&_eeTr=='tcp')?'':'none')+'"><label>سایتِ پوشش (SNI) — الزامی</label><input id="ee_sni" placeholder="مثلاً یک سایتِ HTTPSِ واقعی و محبوب" value="'+esc(l.cover_sni||'')+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">سرور پروب‌های ناشناس را <b>واقعاً به این سایت وصل و پراکسی می‌کند</b>، پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد (ترجیحاً روی CDNِ بزرگ).</div></div>'+
  '<div class="tglbox" id="ee_gsorow"><div class="tglsw'+(_eeGso?' on':'')+'" id="ee_gso" onclick="ceToggleGso()"></div><div class="tt"><b>شتاب‌دهیِ GSO/GRO</b><small>عبورِ حجیم را سریع‌تر می‌کند (پکت‌های بزرگ، syscallِ کمتر). فقط لینوکس.</small></div></div>'+
  fecSection('ee_','ce',_eeFec,_eeFecData,_eeFecParity,(_eeTr=='udp'||_eeTr=='raw'||_eeTr=='flux'))+
  '<div class="grid2"><div><label>پورت (می‌توانی 443)</label><input id="ee_port" inputmode="numeric" value="'+esc(l.port||'')+'" placeholder="20050"></div><div><label>سابنتِ داخلی</label><input id="ee_subnet" class="mono" value="'+esc(l.subnet||'')+'"></div></div>'+
  '<div class="muted" style="font-size:11px;margin:2px 2px 0">ذخیره، تونل را روی هر دو نود از نو می‌سازد (لحظه‌ای قطع می‌شود).</div>'+
  '<div class="msg" id="ee_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>ویرایشِ تونلِ هسته</h3><div class="sb">'+esc(l.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCoreEdit(\\''+id+'\\')">ذخیره و بازسازی</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>',{cls:'edit'});
 ceRoleLbls(l);cePortGate();ceSpoofPrefill(l);ceSpoofVis();ceFluxVis();ceWsVis()}
function ceRoleLbls(l){var a=el('ee_srv_a'),b=el('ee_srv_b');
 if(a)a.innerHTML='<b>'+esc(l.a_name)+' سرور</b><span>'+esc(l.b_name)+' کلاینت</span>';
 if(b)b.innerHTML='<b>'+esc(l.b_name)+' سرور</b><span>'+esc(l.a_name)+' کلاینت</span>'}
function ceSetSrv(s){_eeSrv=s;var a=el('ee_srv_a'),b=el('ee_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b')}
async function doCoreEdit(id){var m=el('ee_msg');m.className='msg';m.textContent='در حال ذخیره و بازسازیِ دو سر…';
 var l=FLEET.filter(function(x){return x.id==id})[0]||{};
 var body={id:id,type:'core',server_side:_eeSrv,cipher:ssVal('ee_cipher'),transport:_eeTr,obfs:_eeObfs,cover:(_eeCover&&_eeTr=='tcp'),gso:_eeGso};
 if(_eeTr=='raw'){if(ssVal('ee_cipher')=='none'){m.className='msg err';m.textContent='حاملِ raw به رمزنگاری نیاز دارد';return}body.raw_profile=_eeRawProfile}
 if(_eeTr=='flux'){if(ssVal('ee_cipher')=='none'){m.className='msg err';m.textContent='حاملِ flux به رمزنگاری نیاز دارد';return}body.flux_carrier=_eeFluxCarrier;body.flux_rotate_secs=_eeFluxRotate;body.flux_shape=_eeFluxShape}
 if(ceFecDatagram()){body.fec=_eeFec;if(_eeFec){body.fec_data=_eeFecData;body.fec_parity=_eeFecParity}}
 if(_eeTr=='ws'){body.ws_host=(v('ee_wshost')||'').trim();body.ws_path=(v('ee_wspath')||'').trim();body.ws_tls=_eeWsTls;body.edge_ip=(v('ee_wsedge')||'').trim();if(_eeWsTls&&!body.ws_host){m.className='msg err';m.textContent='برای wss باید دامنه (Host) را وارد کنی';return}}
 if(_eeTr=='raw'&&_eeRawProfile=='bip'){
  // Always send both spoof fields (empty when the toggle is off) so an edit that turns the
  // decoy/source OFF actually CLEARS it — the backend keys on presence, so an omitted field
  // would otherwise be read as "unchanged" and the old decoy would silently persist.
  var dip=(_eeDecoy&&_eeSpoofOk)?(v('ee_decoyip')||'').trim():'';
  var sip=(_eeSrc&&_eeSpoofOk)?(v('ee_srcip')||'').trim():'';
  if(_eeDecoy&&_eeSpoofOk&&!dip){m.className='msg err';m.textContent='آی‌پیِ طُعمه (مقصدِ جعلی) را وارد کن';return}
  body.spoof_dst=dip;body.spoof_src=sip}
 if(body.cover){var sni=(v('ee_sni')||'').trim();if(!sni){m.className='msg err';m.textContent='برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی';return}body.cover_sni=sni}
 var aip=el('ssb_ee_aip')?ssVal('ee_aip'):(l.a_ip||'');if(aip)body.a_ip=aip;
 var bip=el('ssb_ee_bip')?ssVal('ee_bip'):(l.b_ip||'');if(bip)body.b_ip=bip;
 var sub=v('ee_subnet');if(sub)body.subnet=sub;var port=v('ee_port');if(port)body.port=port;
 var r=await post('edit-link',body);
 if(r.ok&&r.d.ok){editingId=null;closeModal(m.closest('.modalov'));toast(r.d.unchanged?'تغییری نبود':'ذخیره و بازسازی شد','ok');refreshCore()}
 else{m.className='msg err';m.textContent=(r.d&&(r.d.error||r.d.msg))||'ناموفق'}}

// ===== Port-forward
function portfwSkel(){el('view').innerHTML='<h1>'+ic('globe','var(--acc)')+' پورت‌فوروارد</h1><p class="sub">فوروارد پورت روی یک نود (با چرخشِ چند مقصد)</p>'+
 '<button class="primary" onclick="openPfAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+'افزودن پورت‌فوروارد</button>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' پورت‌فورواردهای فعال</div>'+toolbar('portfw','جستجوی نود / نام…')+'<div id="pfList"></div>'+pagerBottom('portfw');
 refreshPortfw()}
async function openPfAddModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(!on.length){toast('هیچ نودِ آنلاینی نیست','err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<label class="first">نود</label>'+ssHTML('pf_node',items,items[0].v,'نود','renderPfLip')+'<div id="pf_lipwrap"></div><div class="grid2"><div><label>پورتِ ورودی</label><input id="pf_lp" placeholder="8080"></div><div><label>پورتِ مقصد</label><input id="pf_dp" placeholder="443"></div></div><label>آی‌پی(های) مقصد — با کاما جدا کن</label><input id="pf_ips" placeholder="10.0.0.1, 10.0.0.2"><label>چرخش هر (دقیقه) — اگر چند آی‌پی دادی</label><input id="pf_int" placeholder="5"><div class="msg" id="pf_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>افزودنِ پورت‌فوروارد</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doPortfw()">افزودن</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">انصراف</button></div>');
 renderPfLip()}
function renderPfLip(){var w=el('pf_lipwrap');if(!w)return;var ips=nodeIps(ssVal('pf_node'));
 if(ips.length>1){w.innerHTML='<label>آی‌پیِ ورودی (شنود) — پورت فقط روی این آی‌پی فوروارد می‌شود</label>'+ssHTML('pf_lip',ipItems(ips),(SEL['pf_lip']&&ips.indexOf(SEL['pf_lip'])>=0?SEL['pf_lip']:ips[0]),'آی‌پی','')}
 else{w.innerHTML='';delete SEL['pf_lip']}}   // single-IP node: no picker, and no stale pick
async function refreshPortfw(){if(editingId)return;var box=el('pfList');if(!box)return;var r=await j('portfw-list?offset='+(PG.portfw*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.portfw));PF=(r.portfw||[]).filter(function(x){return x.name});TOT.portfw=num(r.total);
 setHTML(box,PF.length?PF.map(pfCard).join(''):'<div class="card muted">'+(QRY.portfw?'موردی یافت نشد.':'پورت‌فورواردی نیست.')+'</div>');renderPager('portfw')}
function pfCard(p,i){var h=p.health||{};
 var st=h.rule?(h.reachable?'<span class="badge ok">فعال · مقصد'+CK+'</span>':'<span class="badge bad">قانون'+CK+' · مقصد'+XK+'</span>'):'<span class="badge bad">غیرفعال</span>';
 var rotOn=p.switch_interval>0,multi=(p.dst_ips||[]).length>1;
 var lip=p.listen_ip||p.node_ip||'';   // effective listen IP: the pin (multi-IP) or the node's sole IP (single-IP)
 var rotchip=rotOn?'<span class="tag" style="display:inline-flex;align-items:center;gap:4px;color:var(--gold);border-color:color-mix(in srgb,var(--gold) 34%,transparent);background:var(--goldw);direction:ltr">'+ic('redo')+(p.switch_interval/60)+'m</span>':'';
 var head='<div class="link"><span class="name">'+esc(p.node)+'</span><span class="grow"></span>'+rotchip+'<span class="tag" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 40%,transparent)">portfw</span>'+st+'</div>';
 var live=(multi&&h.active)?'<div class="wrap">هم‌اکنون روی: <b class="mono" id="pfact_'+i+'" style="color:var(--ok)">'+esc(h.active)+'</b></div>':'';
 var body='<div class="enmeta"><div class="emcol">'+
   '<div>اینترفیس: <b class="mono">'+esc(p.iface)+'</b></div>'+
   (lip?'<div>آی‌پیِ ورودی: <b class="mono" style="color:var(--acc)">'+esc(lip)+'</b></div>':'')+
   '<div>پورتِ ورودی: <b class="mono">'+esc(p.listen_port)+'</b></div>'+
  '</div><span class="tnarrow earrow">↔</span><div class="emcol">'+
   '<div>پورتِ مقصد: <b>'+esc(p.dst_port)+'</b></div>'+
   '<div class="wrap">مقصدها: <b class="mono">'+esc((p.dst_ips||[]).join('، '))+'</b></div>'+
   live+
  '</div></div>';
 var traf='<div class="ltraf"><span class="din iso">↓ '+fmtRate(p.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(p.tx_bps)+'</span><span class="tot">مجموع <span class="iso"><b class="din">↓'+fmtBytes(p.rx_total)+'</b><b class="dout">↑'+fmtBytes(p.tx_total)+'</b></span></span></div>';
 var acts='<div class="nact iconly"><button class="act reset" title="ریستِ حجمِ کل" onclick="resetPfTraffic('+i+')">'+ic('reset')+'</button>'+((multi&&h.active)?'<button class="act" title="چرخش الان" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 46%,transparent)" onclick="pfNext('+i+')">'+ic('redo')+'</button>':'')+'<button class="act warn" title="ویرایش" onclick="openPfEdit('+i+')">'+ic('pen')+'</button><button class="act danger" title="حذف" onclick="delPf('+i+')">'+ic('trash')+'</button></div>';
 return '<div class="card">'+head+body+traf+acts+'</div>'}
function pfTgl(i){var sw=el('pe_tgl_'+i),on=!sw.classList.contains('on');sw.classList.toggle('on',on);
 setT('pe_tgllbl_'+i,on?'روشن':'خاموش');var w=el('pe_intwrap_'+i);if(w)w.style.display=on?'block':'none'}
async function savePfEdit(i){var p=PF[i];if(!p)return;var m=el('pem_'+i);var lp=v('pe_lp_'+i),dp=v('pe_dp_'+i),ips=v('pe_ips_'+i);
 if(!lp||!dp||!ips){m.className='msg err';m.textContent='پورت‌ها و آی‌پیِ مقصد لازم است';return}
 var rot=el('pe_tgl_'+i).classList.contains('on'),intv=v('pe_int_'+i);
 m.className='msg';m.textContent='در حال ذخیره…';
 var lip=el('ssb_pe_lip')?ssVal('pe_lip'):'';   // only multi-IP nodes expose the picker; empty ⇒ node keeps old pin
 var r=await post('portfw-edit',{node:p.node_id,name:p.name,listen_port:lp,dst_port:dp,dst_ips:ips,rotate:rot,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=r.d.error||r.d.msg||'ناموفق'}}
async function doPortfw(){var m=el('pf_msg');var node=ssVal('pf_node'),lp=v('pf_lp'),dp=v('pf_dp'),ips=v('pf_ips'),intv=v('pf_int');
 if(!node||!lp||!dp||!ips){m.className='msg err';m.textContent='نود، پورتِ ورودی/مقصد و آی‌پی لازم است';return}
 m.className='msg';m.textContent='در حال ساخت…';
 var lip=el('ssb_pf_lip')?ssVal('pf_lip'):'';   // only when the picker exists (multi-IP node)
 var r=await post('portfw',{node:node,listen_port:lp,dst_port:dp,dst_ips:ips,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast('پورت‌فوروارد ساخته شد: '+r.d.name,'ok')}
 else{m.className='msg err';m.textContent=r.d.error||'ناموفق'}}
async function pfNext(i){var p=PF[i];if(!p)return;var b=el('pfact_'+i),old=b?b.textContent:'';if(b)b.textContent='…';
 var r=await post('portfw-next',{node:p.node_id,name:p.name});
 if(r.ok&&r.d.ok){if(b)b.textContent=r.d.active;toast('چرخش انجام شد ← '+r.d.active,'ok')}
 else{if(b)b.textContent=old;toast((r.d&&(r.d.error||r.d.msg))||'چرخش ناموفق','err')}}
async function delPf(i){var p=PF[i];if(!p)return;if(!await confirmBox('این پورت‌فوروارد حذف شود؟'))return;await post('portfw-del',{node:p.node_id,name:p.name});editingId=null;refreshPortfw()}

// ===== agent push-update page =====
function agentBody(){return ''+
 '<div class="card agx-uni">'+   // AGENT card
  '<div class="k"><span class="chip" style="--hue:var(--acc)">'+ic('cpu','var(--acc)')+'</span> ایجنتِ نودها<span class="grow"></span><span id="ag_status"></span></div>'+
  '<div class="agx-meta" id="ag_meta"></div>'+
  '<div class="agx-act">'+
    '<button class="primary" id="ag_git_btn" onclick="agFetchGit()">'+ic('redo')+'دریافت از گیت‌هاب</button>'+
    '<button class="ghost" onclick="el(\\'ag_file\\').click()">'+ic('plus')+'فایلِ ایجنت</button>'+
  '</div>'+
  '<button class="primary" style="width:100%;margin-top:9px" onclick="agPush(\\'all\\')">'+ic('redo')+'پوشِ ایجنت به همهٔ نودها</button>'+
  '<input type="file" id="ag_file" accept=".py" style="display:none" onchange="agPick(this)">'+
  '<div class="msg" id="ag_git_msg"></div><div class="msg" id="ag_msg"></div>'+
 '</div>'+
 '<div class="card agx-uni">'+   // CORE card — matched to the agent card
  '<div class="k"><span class="chip" style="--hue:#8b5cf6">'+ic('cpu','#8b5cf6')+'</span> هستهٔ داده<span class="grow"></span><span id="cor_status"></span></div>'+
  '<div class="agx-meta" id="cor_meta"></div>'+
  '<div id="cor_ver_box" style="margin-bottom:9px"></div>'+
  '<div class="agx-act">'+
    '<button class="primary" style="background:#8b5cf6" title="دانلودِ نسخهٔ انتخابی روی پنل (آماده‌ی پوش به نودها)" onclick="corStage()">'+ic('redo')+'دریافت از گیت‌هاب</button>'+
    '<button class="ghost" title="آپلودِ فایلِ باینریِ هسته به‌عنوان نسخهٔ custom" onclick="el(\\'cor_file\\').click()">'+ic('plus')+'باینری</button>'+
  '</div>'+
  '<button class="primary" style="width:100%;margin-top:9px;background:#8b5cf6" onclick="corPushAll()">'+ic('redo')+'نصبِ هسته روی همهٔ نودها</button>'+
  '<input type="file" id="cor_file" style="display:none" onchange="agCorPick(this)">'+
  '<div class="agx-hint">⚠️ دو سرِ هر تونلِ هسته باید نسخهٔ یکسان داشته باشند؛ اگر نسخهٔ یک نود را عوض کردی، نودِ طرفِ مقابل را هم به همان نسخه ببر وگرنه آن تونل قطع می‌شود.</div>'+
  '<div class="msg" id="cor_msg"></div>'+
 '</div>'+
 '<div class="sec">'+ic('server','var(--acc)')+' نودهای فلیت</div>'+
 '<div class="toolbar"><input id="q_agent" class="search" placeholder="جستجوی نود…" oninput="onSearch(\\'agent\\')"></div>'+
 '<div id="agList"></div>'+pagerBottom('agent')}
function agentSkel(){el('view').innerHTML='<h1>'+ic('cpu','var(--acc)')+' ایجنت و هسته</h1><p class="sub">آپدیت و ری‌استارتِ ایجنت و هستهٔ نودها از پنل، بدونِ SSH</p>'+agentBody();refreshAgent()}
async function refreshAgent(){var info=await j('agent-info').catch(function(){return{none:true}});AGMETA=info;
 var st=el('ag_status'),mt=el('ag_meta');
 if(st)st.innerHTML=(info&&!info.none)?'<span class="badge ok">آمادهٔ پوش</span>':'<span class="badge na">خالی</span>';
 if(mt)mt.innerHTML=(info&&!info.none)?
  '<span>ایجنت</span><span class="mono">v'+num(info.version)+'</span><span class="sep"></span><span class="mono">'+esc(String(info.sha256||'').slice(0,12))+'</span><span class="sep"></span><span>'+Math.round(num(info.size)/1024)+' کیلوبایت</span>'
  :'<span class="muted">هنوز ایجنتی بارگذاری نشده — «دریافت از گیت‌هاب» یا «فایلِ ایجنت».</span>';
 loadCoreVersions();
 var box=el('agList');if(!box)return;
 var r=await j('nodes?offset='+(PG.agent*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.agent));var nodes=r.nodes||[];TOT.agent=num(r.total);
 box.innerHTML=nodes.length?nodes.map(agRow).join(''):'<div class="card muted">موردی نیست</div>';renderPager('agent')}
var CORVERS=[],STAGED=null;
async function loadCoreVersions(want){
 var r=await j('core-versions').catch(function(){return{versions:[]}});
 CORVERS=r.versions||[];STAGED=r.staged||null;
 var stt=el('cor_status');
 if(stt)stt.innerHTML=STAGED?'<span class="badge ok">آمادهٔ پوش</span>':'<span class="badge na">خالی</span>';
 var mt=el('cor_meta');
 if(mt){
  if(STAGED){var a=(STAGED.arches&&STAGED.arches[0])||'amd64';var sh=(STAGED.sha&&STAGED.sha[a])||'';var sz=(STAGED.size&&STAGED.size[a])||0;
   mt.innerHTML='<span>هسته</span><span class="mono">'+esc(STAGED.version)+'</span>'+(sh?'<span class="sep"></span><span class="mono">'+esc(String(sh).slice(0,12))+'</span>':'')+(sz?'<span class="sep"></span><span>'+(sz/1048576).toFixed(1)+' مگابایت</span>':'')+((STAGED.arches||[]).length?'<span class="sep"></span><span>'+STAGED.arches.join(' · ')+'</span>':'');}
  else mt.innerHTML='<span class="muted">هنوز هسته‌ای روی پنل دانلود نشده — «دریافت از گیت‌هاب» را بزن تا آماده‌ی پوش شود.</span>';
 }
 var box=el('cor_ver_box');if(!box)return;   // styled dropdown (matches every other list in the panel)
 var items=CORVERS.map(function(x){return {v:x.id,label:x.label||x.id}});
 var sel=want||ssVal('corver')||(items.length?items[0].v:'');   // default to the newest real version (no synthetic "latest")
 if(!items.filter(function(x){return String(x.v)==String(sel)}).length)sel=items.length?items[0].v:'';
 box.innerHTML=ssHTML('corver',items,sel,'انتخاب نسخه','')}
async function corStage(){var ver=ssVal('corver')||'latest';var m=el('cor_msg');m.className='msg';m.textContent='در حال دانلودِ هسته روی پنل…';
 var res=await post('core-stage',{version:ver});
 if(res.ok&&res.d&&res.d.ok){m.className='msg ok';m.innerHTML='هستهٔ «'+esc(res.d.version)+'» روی پنل آماده شد'+((res.d.arches||[]).length?' ('+res.d.arches.join(', ')+')':'')+CK;loadCoreVersions()}
 else{m.className='msg err';m.textContent=(res.d&&(res.d.error||res.d.msg))||'ناموفق — پنل به گیت‌هاب دسترسی دارد؟'}}
async function corPushStaged(id){var m=el('agres_'+id);if(m){m.className='msg agres';m.textContent='در حال پوشِ هستهٔ آماده…'}
 var res=await post('core-push',{ids:[id]});var x=((res.d&&res.d.results)||[])[0]||{};
 if(m){if(x.ok){m.className='msg agres ok';m.innerHTML=(x.unchanged?'هسته از قبل به‌روز بود':'هسته به‌روز شد')+CK}
  else{m.className='msg agres err';m.textContent='ناموفق: '+(x.error||'')}}
 setTimeout(refreshAgent,4000)}
async function corPushAll(){var ver=ssVal('corver');if(!ver){toast('اول نسخه را انتخاب کن','err');return}
 var r=await j('node-names');var ids=(r.nodes||[]).filter(function(n){return n.online}).map(function(n){return n.id});
 if(!ids.length){toast('نودِ آنلاینی نیست','err');return}
 if(!await confirmBox('هستهٔ نسخهٔ «'+ver+'» روی '+ids.length+' نودِ آنلاین نصب و تونل‌های هسته ری‌استارت شوند؟','بله، همه'))return;
 ids.forEach(function(id){var m=el('agres_'+id);if(m){m.className='msg agres';m.textContent='در حال نصبِ هسته…'}});   // per-node status, like پوشِ همه
 var res=await post('core-update',{ids:ids,version:ver});var rs=(res.d&&res.d.results)||[];var ok=0;
 rs.forEach(function(x){var m=el('agres_'+x.id);
  if(x.ok){ok++;if(m){m.className='msg agres ok';m.innerHTML=(x.unchanged?'هسته از قبل به‌روز بود':'هسته به‌روز شد')+CK}}
  else if(x.offline){if(m){m.className='msg agres';m.textContent='آفلاین — رد شد'}}
  else{if(m){m.className='msg agres err';m.textContent='ناموفق: '+(x.error||'')}}});
 toast(ok+'/'+rs.length+' نود بروزرسانی شد',ok?'ok':'err');
 setTimeout(refreshAgent,4500)}
async function corPush(id,ver){if(!ver){toast('نسخه را انتخاب کن','err');return}
 var m=el('agres_'+id);if(m){m.className='msg agres';m.textContent='در حال نصبِ هستهٔ '+ver+'…'}
 var res=await post('core-update',{ids:[id],version:ver});var x=((res.d&&res.d.results)||[])[0]||{};
 if(m){if(x.ok){m.className='msg agres ok';m.innerHTML='هسته → '+esc(x.version||ver)+' · '+num(x.restarted)+' تونل ری‌استارت'+CK}
  else if(x.offline){m.className='msg agres';m.textContent='آفلاین — رد شد'}
  else{m.className='msg agres err';m.textContent='ناموفق: '+(x.error||'')}}
 setTimeout(refreshAgent,4000)}
function agCorPick(inp){var f=inp.files&&inp.files[0];if(!f)return;inp.value='';
 var m=el('cor_msg');m.className='msg';m.textContent='در حال خواندن و آپلودِ باینری…';
 var rd=new FileReader();
 rd.onload=function(){var b=String(rd.result||'');var i=b.indexOf(',');agCorUpload(i>=0?b.slice(i+1):b,f.name)};
 rd.onerror=function(){m.className='msg err';m.textContent='خواندنِ فایل ناموفق'};
 rd.readAsDataURL(f)}
async function agCorUpload(b64,name){var m=el('cor_msg');
 var res=await post('core-upload',{data:b64,name:name});
 if(res.ok&&res.d&&res.d.ok){m.className='msg ok';m.innerHTML='باینری ذخیره شد: '+esc(name)+' · '+Math.round(res.d.size/1024)+'KB · <span class="mono">'+esc(res.d.sha256)+'</span>'+CK+' — «نصبِ همه» را بزن یا از منوی هر نود';
  await loadCoreVersions('custom')}
 else{m.className='msg err';m.textContent=(res.d&&res.d.error)||'ناموفق'}}
function agRow(n){var i=n.info||{};var agver=i.version?('v'+num(i.version)):'—';
 var cinst=!!(i.core_sha&&String(i.core_sha).length);            // core_sha empty => no binary on the node
 var carch=i.arch||'amd64';var ssha=(STAGED&&STAGED.sha&&STAGED.sha[carch])||'';
 var agup=!!(AGMETA&&!AGMETA.none&&i.sha256!==AGMETA.sha256);    // agent update available
 var cup=!!(STAGED&&(!cinst||(ssha&&String(i.core_sha)!==String(ssha).slice(0,12))));  // core update available/missing
 // status = a colored icon only (no به‌روز/آپدیت text); full text lives in the tooltip.
 function stx(lbl,cls,icon,tip){return '<span class="stx" title="'+tip+'">'+lbl+' <span class="ico '+cls+'">'+icon+'</span></span>'}
 // agent status + button-enable
 var agbdg,agdis;
 if(!n.online){agbdg=stx('ایجنت','offl','—','آفلاین');agdis=1}
 else if(!AGMETA||AGMETA.none){agbdg='';agdis=1}
 else if(agup){agbdg=stx('ایجنت','up',ic('redo'),'ایجنت: آپدیت دارد');agdis=0}
 else{agbdg=stx('ایجنت','ok',ic('check'),'ایجنت: به‌روز');agdis=1}
 // core status + button-enable
 var cbdg,cdis;
 if(!n.online){cbdg=stx('هسته','offl','—','آفلاین');cdis=1}
 else if(!cinst){cbdg=stx('هسته','na',ic('dl'),'هسته: نصب نیست');cdis=!STAGED}
 else if(cup){cbdg=stx('هسته','up',ic('redo'),'هسته: آپدیت دارد');cdis=0}
 else{cbdg=stx('هسته','ok',ic('check'),'هسته: به‌روز');cdis=1}
 var corpill=cinst?'<span class="agx-pill cor" title="نسخهٔ هسته">⚙ '+esc(i.core_ver||'?')+'</span>':'';
 return '<div class="agx-row">'+
   '<div class="agx-right">'+
     '<div class="agx-l1"><span class="ndot '+(n.online?'on':'off')+'"></span><span class="nm">'+esc(n.name)+'</span><span class="agx-pill">'+agver+'</span>'+corpill+'</div>'+
     '<div class="agx-l2">'+agbdg+cbdg+'</div>'+
   '</div>'+
   '<div class="agx-colb">'+
     '<button class="agx-btn'+(agup&&n.online?' up':'')+'"'+(agdis?' disabled':'')+' onclick="agPush(\\''+n.id+'\\')">'+ic('redo')+'ایجنت</button>'+
     '<button class="agx-btn'+(cup&&n.online?' up':'')+'"'+(cdis?' disabled':'')+' onclick="corPushStaged(\\''+n.id+'\\')" title="پوشِ هستهٔ آماده‌ی روی پنل به این نود">'+ic('redo')+'هسته</button>'+
   '</div>'+
   '<div class="msg agres" id="agres_'+n.id+'"></div></div>'}
var _corOv=null;
function corMenu(btn){var id=btn.getAttribute('data-nid');var cur=btn.getAttribute('data-cur');if(!CORVERS.length){toast('نسخه‌ها هنوز آماده نیست','err');return}   // centered popup, like every other list
 var rows=CORVERS.map(function(x){return '<div class="msrow'+(String(x.id)==String(cur)?' sel':'')+'" data-v="'+esc(x.id)+'" data-nid="'+esc(id)+'" onclick="corPick(this)"><span class="mscheck"></span><span>'+esc(x.label||x.id)+'</span><span class="muted mono" style="font-size:11px;margin-inline-start:auto">'+esc(x.id)+'</span></div>'}).join('');
 _corOv=openModal('<div class="sspop"><div style="padding:4px 4px 9px;font-size:11.5px;color:var(--sub);font-weight:800">هستهٔ این نود را ببر به نسخهٔ:</div><div class="sspoplist">'+rows+'</div></div>',{cls:'sssheet'})}
function corPick(row){var id=row.getAttribute('data-nid');var ver=row.getAttribute('data-v');if(_corOv){closeModal(_corOv);_corOv=null}corPush(id,ver)}
function agPick(inp){var f=inp.files&&inp.files[0];if(!f)return;inp.value='';var rd=new FileReader();rd.onload=function(){window._agCode=rd.result;agUpload()};rd.readAsText(f)}
async function agUpload(){var m=el('ag_msg');var code=window._agCode;
 if(!code||!code.trim()){m.className='msg err';m.textContent='اول فایلِ ایجنت را انتخاب کن';return}
 m.className='msg';m.textContent='در حال بررسی و ذخیره…';
 var r=await post('agent-upload',{code:code});
 if(r.ok&&r.d.ok){m.className='msg ok';m.textContent='ذخیره شد: v'+r.d.version+' · '+r.d.sha256;window._agCode=null;refreshAgent()}
 else{m.className='msg err';m.textContent=r.d.error||'ناموفق'}}
async function agFetchGit(){var m=el('ag_git_msg'),btn=el('ag_git_btn');
 m.className='msg';m.textContent='در حال دریافت از گیت‌هاب…';if(btn)btn.disabled=true;
 var r=await post('agent-fetch-git',{});
 if(!(r.ok&&r.d.ok)){m.className='msg err';m.textContent=r.d.error||'ناموفق';if(btn)btn.disabled=false;return}
 m.className='msg ok';m.innerHTML='دریافت شد: v'+r.d.version+' · <span class="mono">'+esc(r.d.sha256)+'</span> — حالا «پوشِ همه» را بزن'+CK;
 if(btn)btn.disabled=false;
 await refreshAgent()}
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
function refresh(){var p;if(cur=='overview')p=refreshOverview();else if(cur=='nodes')p=refreshNodes();else if(cur=='tunnels')p=refreshTunnels();else if(cur=='core')p=refreshCore();else if(cur=='portfw')p=refreshPortfw();else if(cur=='agent')p=refreshAgent();else if(cur=='settings'&&el('agList'))p=refreshAgent();return Promise.resolve(p)}
function render(){setnav();editingId=null;
 if(cur=='overview')overviewSkel();else if(cur=='nodes')nodesSkel();else if(cur=='tunnels')tunnelsSkel();else if(cur=='core')coreSkel();else if(cur=='portfw'){portfwSkel();return}else if(cur=='agent'){agentSkel();return}else if(cur=='settings'){settingsSkel();refreshSettings();return}
 refresh()}
function refreshFleet(){return cur=='core'?refreshCore():refreshTunnels()}
// ===== settings (loaded once on nav; NOT re-fetched on the 6s tick so the form is never clobbered mid-edit) =====
function settingsSkel(){el('view').innerHTML='<h1>'+ic('cog','var(--acc)')+' تنظیمات</h1><p class="sub">رفتار خودکارِ پنل و بازه‌های بررسی</p><div id="setBox"><div class="card muted">در حال بارگذاری…</div></div>'}
var _setMode='alert',_modeOv=null;
function modeLabel(m){return m=='auto'?'خودکار':'هشدار'}
async function refreshSettings(){var s=await j('settings').catch(function(){return{}});var box=el('setBox');if(!box)return;
 _setMode=(s.reconcile_mode=='auto')?'auto':'alert';
 var row=function(t,d,ctl){return '<div class="setrow"><div class="setlbl"><b>'+t+'</b><span>'+d+'</span></div><div class="setctl">'+ctl+'</div></div>'};
 box.innerHTML='<div class="card">'+
  row('وقتی آی‌پیِ نود عوض شد','هشدار بده یا خودکار ترمیم کن','<button type="button" class="setfield" onclick="openModePopup()"><span class="val" id="set_mode_val">'+modeLabel(_setMode)+'</span><span class="cv">'+ic('chev')+'</span></button>')+
  row('بازهٔ بررسیِ ترمیم (ثانیه)','۵ تا ۳۶۰۰','<input id="set_rec" class="search" type="number" min="5" max="3600" value="'+(num(s.reconcile_interval)||15)+'">')+
  row('بازهٔ پایشِ فلیت (ثانیه)','۱ تا ۶۰','<input id="set_poll" class="search" type="number" min="1" max="60" value="'+(num(s.poll_interval)||2)+'">')+
  row('پنجرهٔ نوارِ آپ‌تایم','۶۰ خانه؛ هر خانه = پنجره ÷ ۶۰',ssHTML('set_upwin',[{v:'1',label:'۱ ساعت'},{v:'3',label:'۳ ساعت'},{v:'6',label:'۶ ساعت'},{v:'8',label:'۸ ساعت'},{v:'12',label:'۱۲ ساعت'},{v:'24',label:'۲۴ ساعت'}],String(num(s.uptime_window)||1),'',''))+
  '<div class="tbtnrow" style="margin:14px 0 0;align-items:center"><button class="primary" onclick="saveSettings()">'+ic('check')+'ذخیره</button><span class="msg" id="set_msg" style="align-self:center"></span></div>'+
  '</div>'+
  '<div class="sec" style="margin-top:8px">'+ic('redo','var(--acc)')+' بروزرسانیِ ایجنت</div>'+agentBody();
 refreshAgent()}
function openModePopup(){var opt=function(m,df){return '<div class="mopt'+(_setMode==m?' on':'')+'" onclick="pickMode(\\''+m+'\\')"><span class="mrad"></span><span class="mt">'+modeLabel(m)+'</span>'+(df?'<span class="mdf">پیش‌فرض</span>':'')+'</div>'};
 _modeOv=openModal('<div class="modelist">'+opt('auto',false)+opt('alert',true)+'</div>',{cls:'modesheet'})}
function pickMode(m){_setMode=m;setT('set_mode_val',modeLabel(m));if(_modeOv){closeModal(_modeOv);_modeOv=null}}
async function saveSettings(){var m=el('set_msg');if(m){m.className='msg';m.textContent='در حال ذخیره…'}
 var r=await post('settings-set',{reconcile_mode:_setMode,reconcile_interval:v('set_rec'),poll_interval:v('set_poll'),uptime_window:ssVal('set_upwin')});
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
    try:                              # stage the latest core now so nodes (incl. internet-less ones) get it by push
        info = _stage_core("latest")
        print(f"[✔] staged core {info['version']} ({', '.join(info['arches'])}) — ready to push to nodes")
    except Exception as e:
        print(f"[!] could not pre-download the core ({e}); stage it later from the panel (هستهٔ داده → دریافت از گیت‌هاب)")
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


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that caps concurrent worker threads. The stock server spawns one
    unbounded thread per connection, so a connection flood (e.g. slow POST /api/login, each
    buffering a 1 MB body) spawns unbounded root threads/RAM until OOM. Here process_request
    blocks on a bounded semaphore, so at most _MAX_WORKERS requests run at once; excess
    connections wait in the listen backlog (or are refused) instead of exhausting the box."""
    daemon_threads = True
    request_queue_size = 128
    _MAX_WORKERS = 256
    _sem = threading.BoundedSemaphore(_MAX_WORKERS)

    def process_request(self, request, client_address):
        self._sem.acquire()
        try:
            super().process_request(request, client_address)  # spawns the worker thread
        except BaseException:
            self._sem.release()  # thread never started -> don't leak the slot
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._sem.release()


def serve():
    if not os.path.isfile(WEB_CONF):
        print("Not configured. Run the setup menu:  sudo python3 tnl-central.py")
        sys.exit(1)
    conf = load_conf()
    global _CENTRAL_PORT
    _CENTRAL_PORT = int(conf.get("port", 8080))  # advertised to nodes so they can call back /api/checkin
    _seed_settings()  # load settings.json into memory (defaults if absent) for the loops
    try:
        _signing_keys()  # generate the update-signing keypair on first boot so pushes can be signed
    except Exception as e:
        print(f"warning: could not init signing key (openssl missing?): {e}")
    _tf_load()  # restore lifetime traffic totals from disk so they survive a central restart
    _uh_load()  # restore per-minute uptime history so the uptime bar survives a restart
    threading.Thread(target=poller_loop, daemon=True).start()  # warm the fleet cache in the background
    threading.Thread(target=traffic_persist_loop, daemon=True).start()  # flush traffic totals every 60s
    threading.Thread(target=reconcile_loop, daemon=True).start()  # heal peer remote_ip after a node's IP changes
    httpd = BoundedThreadingHTTPServer(("0.0.0.0", int(conf.get("port", 8080))), Handler)
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
