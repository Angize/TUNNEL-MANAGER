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
from concurrent.futures import ThreadPoolExecutor
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
_settings_lock = threading.RLock()  # reentrant: api_settings_set holds it across validate_settings() -> get_settings()
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

# Operational self-heal / pool-health timing knobs, exposed fleet-wide in Settings and stamped into
# every core config on build/rebuild. Defaults MUST match the core's compiled-in defaults (tuning.go)
# so an unchanged knob is a no-op. Each scalar has a (min, max) clamp matching the core's clamp; the
# core clamps again, so the panel is convenience-validation, not the authority. suspect_backoff is a
# list of positive seconds (the retest schedule). Grouped by category for the Settings UI.
_TUNING_DEFAULTS = {
    # دستهٔ ۱ — سلامتِ استخر (Pool health FSM)
    "suspect_backoff": [30, 60, 120, 300, 600],
    "dead_retest_secs": 1800,
    "pin_ttl_secs": 30,
    "data_fail_threshold": 2,
    "data_good_window_secs": 120,
    # دستهٔ ۲ — تشخیصِ مرگ / self-heal
    "idle_mult": 4,
    "idle_min_secs": 60,
    "session_stale_mult": 3,
    "session_stale_min_secs": 10,
    "ping_loss_threshold": 3,
    "min_liveness_secs": 20,
    "probe_timeout_secs": 5,
    # دستهٔ ۳ — چرخش (Rotation)
    "flux_rotate_default_secs": 600,
}
_TUNING_RANGES = {
    "dead_retest_secs": (5, 86400), "pin_ttl_secs": (1, 3600),
    "data_fail_threshold": (1, 100), "data_good_window_secs": (1, 86400),
    "idle_mult": (1, 100), "idle_min_secs": (1, 86400),
    "session_stale_mult": (1, 100), "session_stale_min_secs": (1, 86400),
    "ping_loss_threshold": (1, 100), "min_liveness_secs": (1, 3600),
    "probe_timeout_secs": (1, 120), "flux_rotate_default_secs": (1, 86400),
}


def _validate_tuning(raw, base=None):
    """Merge a partial tuning update onto the current tuning (or defaults), coercing+clamping each knob
    to its range. Unknown keys and malformed values are ignored (the knob keeps its prior value), so a
    bad field can never poison the stored settings. suspect_backoff must be a non-empty list of positive
    ints or it is left unchanged."""
    out = dict(_TUNING_DEFAULTS)
    if isinstance(base, dict):
        out.update({k: base[k] for k in _TUNING_DEFAULTS if k in base})
    if not isinstance(raw, dict):
        return out
    for k, (lo, hi) in _TUNING_RANGES.items():
        if k in raw and raw[k] not in (None, ""):
            try:
                out[k] = max(lo, min(hi, int(raw[k])))
            except (TypeError, ValueError):
                pass
    if "suspect_backoff" in raw:
        sb = raw["suspect_backoff"]
        if isinstance(sb, (list, tuple)):
            steps = []
            for x in sb:
                try:
                    iv = int(x)
                except (TypeError, ValueError):
                    continue
                if 1 <= iv <= 86400:
                    steps.append(iv)
            if steps:
                out["suspect_backoff"] = steps
    return out


def _settings_tuning():
    """The tuning overrides to stamp into a core config: only the knobs that DIFFER from the core's
    built-in defaults, so an unchanged knob is omitted and the core keeps its own default (panel and
    core defaults stay in lock-step automatically). Returns {} when everything is at default."""
    s = get_settings().get("tuning")
    if not isinstance(s, dict):   # a hand-edited settings.json could make this a truthy non-dict; guard so
        s = {}                    # a build never crashes on `.get` — fall back to all-defaults (empty diff)
    out = {}
    for k, dv in _TUNING_DEFAULTS.items():
        v = s.get(k, dv)
        if k == "suspect_backoff":
            try:
                lv = [int(x) for x in v]
            except (TypeError, ValueError):
                continue
            if lv != dv:
                out[k] = lv
        else:
            try:
                iv = int(v)
            except (TypeError, ValueError):
                continue
            if iv != dv:
                out[k] = iv
    return out


def settings_defaults():
    return {
        "reconcile_mode": "alert",  # default. "alert" = only flag a drifted tunnel; the operator clicks
                                    # بازسازی on the affected one. "auto" = panel rebuilds it itself (single-IP).
        "reconcile_interval": 15,   # seconds between reconcile sweeps (5–3600)
        "poll_interval": 2,         # seconds the fleet poller rests between sweeps (0.3–60, fractional OK)
        "ui_interval": 2,           # seconds the UI waits between live redraws / modal polls (0.3–60, fractional OK)
        "uptime_window": 1,         # uptime-bar span in hours (1/3/6/8/12/24); always 60 cells, each = window/60
        "ech_refresh_mins": 15,     # minutes between background ECH re-fetches for ECH links (0 = off; min 1)
        "tuning": dict(_TUNING_DEFAULTS),  # operational self-heal / pool-health timings (see _TUNING_DEFAULTS)
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
        out["poll_interval"] = max(0.3, min(60.0, round(float(d["poll_interval"]), 2)))  # fractional (sub-second) OK
    if "ui_interval" in d and d["ui_interval"] not in (None, ""):
        out["ui_interval"] = max(0.3, min(60.0, round(float(d["ui_interval"]), 2)))       # fractional (sub-second) OK
    if "uptime_window" in d and d["uptime_window"] not in (None, ""):
        w = int(d["uptime_window"])
        out["uptime_window"] = w if w in (1, 3, 6, 8, 12, 24) else 1
    if "ech_refresh_mins" in d and d["ech_refresh_mins"] not in (None, ""):
        m = round(float(d["ech_refresh_mins"]), 2)
        out["ech_refresh_mins"] = 0.0 if m <= 0 else max(1.0, min(1440.0, m))  # 0 = off; else 1min–24h
    if "tuning" in d:
        out["tuning"] = _validate_tuning(d["tuning"], out.get("tuning"))
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


def _tombed(nid, ts):
    """True if this node was deleted recently enough (short tombstone) that an in-flight poll must
    NOT resurrect its cache/traffic/uptime."""
    with _tomb_lock:
        exp = _tomb.get(nid)
        return bool(exp and ts < exp)


def _poll_node(n):
    ping = node_call(n, "ping", "GET", timeout=6)
    t_ping = time.time()   # stamp the rate at ping-return time, not after the slower list call
    # Publish traffic + uptime from the ping IMMEDIATELY — don't make the live rate wait for the
    # (slower) list call. The rate's dt uses this accurate ping timestamp, so it's correct even at a
    # sub-second poll interval.
    if not _tombed(n["id"], t_ping):
        if ping.get("ok"):
            s = ping.get("stats") or {}
            _tf_ingest(n["id"], s.get("net"), s.get("uptime"), t_ping)
        else:               # unreachable -> decay rates to 0 so a dead node isn't counted as still flowing
            _tf_zero_rates(n["id"])
        _uh_sample(n["id"], bool(ping.get("ok")), t_ping)
    lst = node_call(n, "list", "GET", timeout=12)   # health/configs (for tunnel up/down status)
    now = time.time()
    if _tombed(n["id"], now):  # node deleted while this poll was in flight? don't resurrect its cache
        return
    with _pc_lock:  # publish ping+list together so readers never see a torn (fresh-ping / stale-list) pair
        _pc[n["id"]] = {"ping": ping, "list": lst, "ping_ts": t_ping, "list_ts": now}


def _refresh_cache(nids):
    """Synchronously refresh the cache for a few nodes (after a mutation) so the UI updates at once."""
    nodes = {n["id"]: n for n in load_nodes()}
    parallel_map(_poll_node, [nodes[i] for i in dict.fromkeys(nids) if i in nodes])


_warm_inflight = set()          # node ids being warmed by a background _ensure_cached poll
_warm_lock = threading.Lock()


def _ensure_cached(nodes):
    """Warm the cache for a page's nodes WITHOUT blocking the request. A node the poller hasn't
    reached yet (cold start / just-added / poller behind on a slow fleet) is polled in the
    BACKGROUND — the request returns whatever is cached right now (an uncached node reads as offline
    until the poll lands, and the UI's periodic refresh picks it up seconds later). This is the fix
    for the page hanging on reload: a slow/unreachable node used to block /api/nodes here for up to
    ping+list (~18s). Polls are deduped so repeated reloads don't pile up on the same node."""
    miss = [n for n in nodes if not _cache_get(n["id"])]
    if not miss:
        return
    with _warm_lock:
        miss = [n for n in miss if n["id"] not in _warm_inflight]
        for n in miss:
            _warm_inflight.add(n["id"])
    if not miss:
        return

    def _warm():
        try:
            parallel_map(_poll_node, miss)
        finally:
            with _warm_lock:
                for n in miss:
                    _warm_inflight.discard(n["id"])

    threading.Thread(target=_warm, daemon=True).start()


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
                # Fire each due node's poll and immediately loop — do NOT wait for the batch to finish.
                # A slow/offline node stays in `inflight` (so it's never resubmitted mid-flight) but it can
                # no longer delay the others: every healthy node is resampled each poll_interval, so live
                # rates/status stay fresh even while part of the fleet is unreachable. Workers publish into
                # the cache as each finishes; `inflight` bounds the queue to at most one poll per node.
                for n in todo:
                    ex.submit(_run, n)
        except Exception:
            pass
        time.sleep(max(0.3, float(get_settings().get("poll_interval", POLL_GAP) or POLL_GAP)))  # fractional/sub-second OK


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
    """Record up/down into the rolling uptime ring as a per-bucket UP-FRACTION (up polls / total polls
    in the bucket), so a short blip counts by its REAL duration — a 5s outage is ~5s of downtime, not a
    whole minute/cell. One bucket per UPTIME_BUCKET seconds; the ring holds floats in [0,1]."""
    with _uh_lock:
        e = _uh.get(nid)
        if e is None:
            _uh[nid] = {"ring": [], "bts": now, "up": 1 if up else 0, "tot": 1}
            return
        e["up"] = e.get("up", 0) + (1 if up else 0)
        e["tot"] = e.get("tot", 0) + 1
        if now - e["bts"] >= UPTIME_BUCKET:
            frac = e["up"] / e["tot"] if e["tot"] else 1.0   # fraction of this bucket the node was reachable
            missed = min(int((now - e["bts"]) / UPTIME_BUCKET), UPTIME_KEEP)  # backfill a multi-bucket gap, don't compress it
            e["ring"].extend([frac] * missed)
            if len(e["ring"]) > UPTIME_KEEP:
                e["ring"] = e["ring"][-UPTIME_KEEP:]
            e["bts"] = now
            e["up"], e["tot"] = 0, 0


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
        out.append(None if not chunk else (0 if min(chunk) < 1.0 else 1))  # red if ANY downtime in the cell (visual)
    return out


def _uh_pct(nid, window_hours):
    """True TIME-WEIGHTED uptime % over the window: the mean of the per-bucket up-fractions (each ~1
    minute), so a 5-second blip lowers it by ~5s/window — not by a whole cell/minute like counting red
    bars would. Returns 100.0 when there is no history yet."""
    try:
        wh = int(window_hours)
    except Exception:
        wh = 1
    if wh not in (1, 3, 6, 8, 12, 24):
        wh = 1
    with _uh_lock:
        e = _uh.get(nid)
        ring = list(e["ring"]) if e else []
    ring = ring[-(wh * 60):]
    if not ring:
        return 100.0
    return round(sum(ring) / len(ring) * 100, 2)


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
            if isinstance(ring, list):  # bts=now so the offline gap isn't backfilled; floats in [0,1]
                _uh[nid] = {"ring": [max(0.0, min(1.0, float(x))) for x in ring][-UPTIME_KEEP:], "bts": now, "up": 0, "tot": 0}


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


# Pool blacklists are panel-side only (the operator's memory of which edges are burned); the node/core
# never consume them, so strip them from any node body. _tunnel_extra (rebuild) already omits them by
# construction — this keeps the create/edit node bodies consistent with that.
_PANEL_ONLY_KEYS = ("ws_edge_ips_burned", "ws_edge_snis_burned")

# IP-rotation config lives in the LINK record and is consumed by _core_rotation_bodies to derive each
# node's PER-ROLE fields (peer_ips/src_ips on the client, pool_listen on the server). The raw keys must
# NOT be spread into a node body as-is (the node whitelists only the per-role fields), so drop them.
_ROTATION_KEYS = ("ip_rotate", "a_ip_pool", "b_ip_pool", "rotate_secs", "auto_burn")


def _node_extra(extra):
    skip = _PANEL_ONLY_KEYS + _ROTATION_KEYS
    return {k: v for k, v in extra.items() if k not in skip}


def _apply_core_rotation(body, is_client, own_pool, peer_pool, rotate_secs, auto_burn):
    """Set a core node's per-role IP-rotation fields in place. The CLIENT gets its own node's IPs as the
    source pool (src_ips) and the peer node's IPs as the destination pool (peer_ips) plus the rotation
    settings; the SERVER binds exactly its OWN selected pool IPs (pool_listen + listen_ips) so the core
    opens one socket per IP — the reply then egresses from the exact IP the client dialed, and the
    server accepts only on the pool IPs rather than every host IP."""
    if is_client:
        if peer_pool:
            body["peer_ips"] = list(peer_pool)   # the server's IPs — the client cycles the destination
        if own_pool:
            body["src_ips"] = list(own_pool)      # this node's own IPs — the client cycles the source
        body["peer_rotate_secs"] = rotate_secs
        body["peer_auto_burn"] = auto_burn
    else:
        body["pool_listen"] = True                # accept the client dialing any of this server's IPs
        if own_pool:
            body["listen_ips"] = list(own_pool)   # bind exactly these (this server's own selected IPs)
        if peer_pool:
            # The CLIENT's source pool (the IPs it sends FROM as it rotates its source). raw/flux servers
            # receive via a raw/AF_PACKET socket that sees every host and pre-filter by the learned peer
            # source, so a rotated client source would be dropped pre-crypto and never re-learned — the
            # tunnel dies on a source rotation until a rebuild. Handing the server the client's known
            # sources lets a rotated-but-expected source reach crypto and re-bind. udp/tcp re-learn on
            # their own (bound socket per source); the node only forwards this for raw/flux.
            body["peer_src_ips"] = list(peer_pool)


def _core_rotation_bodies(src, a_body, b_body):
    """Apply IP rotation to BOTH core node bodies from a create/edit request or a stored link `src`
    (which carries ip_rotate + a_ip_pool/b_ip_pool + rotate_secs/auto_burn). a_body is node A, b_body
    node B; the client/server split comes from each body's already-set role. No-op when rotation is off
    or the transport isn't direct (peer_ips/src_ips are meaningless on ws)."""
    if not src.get("ip_rotate") or src.get("transport") not in ("udp", "tcp", "raw", "flux"):
        return
    ap, bp = list(src.get("a_ip_pool") or []), list(src.get("b_ip_pool") or [])
    rs, ab = max(0, min(86400, int(src.get("rotate_secs") or 0))), bool(src.get("auto_burn"))
    _apply_core_rotation(a_body, a_body.get("role") == "client", ap, bp, rs, ab)  # A: own=ap, peer=bp
    _apply_core_rotation(b_body, b_body.get("role") == "client", bp, ap, rs, ab)  # B: own=bp, peer=ap


def _apply_core_tuning(a_body, b_body):
    """Stamp the fleet-wide operational-timing overrides (only the knobs that differ from the core's
    built-in defaults) onto BOTH core node bodies. Called from EVERY core build path — create, edit and
    rebuild — so a tunnel picks up the current Settings timing on any (re)build, uniformly. Empty diff
    (all knobs at default) leaves both bodies untouched so the core keeps its own defaults."""
    tn = _settings_tuning()
    if tn:
        a_body["tuning"] = tn
        b_body["tuning"] = tn


def _tunnel_extra(src, refetch_ech=True):
    """Type-specific fields that must reach BOTH tunnel ends identically: the UDP port (l2tpv3/fou/core),
    the shared key (IPsec psk / core AEAD psk) and the core cipher. Read from a stored link record
    (edit/rebuild) or a create request. NOTE: the core role is per-node, so it is NOT here — inject it
    separately with _core_role(). refetch_ech=False reuses the stored per-SNI ECH verbatim (no DNS
    fetch, never raises) — used only as a last-resort restore path when a fresh fetch failed."""
    e = {}
    if src.get("port"):
        e["port"] = src["port"]
    if src.get("psk"):
        e["psk"] = src["psk"]
    if src.get("cipher"):
        e["cipher"] = src["cipher"]
    if src.get("transport"):
        e["transport"] = src["transport"]
    if src.get("dead_after_secs"):        # per-tunnel self-heal deadline (client uses it; 0/unset = default)
        e["dead_after_secs"] = max(10, min(300, int(src["dead_after_secs"])))
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
    if src.get("fake_desync"):           # fake-packet desync (raw/flux client anti-DPI); carry the decoy knobs
        e["fake_desync"] = True
        e["fake_ttl"] = src.get("fake_ttl") or 4
        e["fake_count"] = src.get("fake_count") or 2
        e["fake_mode"] = src.get("fake_mode") or "ttl"
    if src.get("ws_host"):               # ws (WebSocket/CDN) Host header + TLS SNI
        e["ws_host"] = src["ws_host"]
    if src.get("ws_path"):               # ws request path
        e["ws_path"] = src["ws_path"]
    if src.get("ws_tls"):                # ws client speaks wss (TLS to the CDN edge)
        e["ws_tls"] = True
    if src.get("sni_split"):             # SNI fragmentation: split the wss ClientHello across TCP segments
        e["sni_split"] = True
        if src.get("split_pos"):
            e["split_pos"] = int(src["split_pos"])
        if src.get("sni_mode") in ("disorder", "fake"):   # anti-reassembly modes (low-TTL head / fake overlap)
            e["sni_mode"] = src["sni_mode"]
            if src.get("split_ttl"):
                e["split_ttl"] = int(src["split_ttl"])
    if src.get("ws_xhttp"):              # xhttp mode (bypasses WebSocket block)
        e["ws_xhttp"] = True
        if src.get("ws_xhttp_mode") in ("packet", "stream", "grpc"):  # upstream style: packet-up | stream-one | grpc
            e["ws_xhttp_mode"] = src["ws_xhttp_mode"]
    if src.get("ech"):                   # ECH: hide the SNI (carries ws_ech, the base64 config)
        e["ech"] = True
        host = src.get("ws_host")
        if refetch_ech and host:
            # Re-fetch fresh on rebuild — a stored single-edge ws_ech goes stale when the CDN rotates
            # its key (~hourly), and a stale key fails the ws-upgrade (same failure the pool branch
            # guards). NO fallback: raise rather than replay a stale key (caller runs this BEFORE teardown).
            ec = _fetch_ech(host)
            if not ec:
                raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — بازسازی متوقف شد (ECH روشن است ولی رکوردِ HTTPS/ech= در دسترس نیست)." % host)
            e["ws_ech"] = ec
        elif src.get("ws_ech"):
            e["ws_ech"] = src["ws_ech"]  # restore path (refetch_ech=False): reuse the stored key verbatim
    if src.get("edge_ip"):               # ws client dials this CDN edge instead of the origin
        e["edge_ip"] = src["edge_ip"]
    if src.get("ws_pool") and src.get("ws_edge_ips") and src.get("ws_edge_snis"):  # rotating edge pool (clean lists only)
        e["ws_pool"] = True
        e["ws_tls"] = True
        e["ws_edge_ips"] = src["ws_edge_ips"]
        # Re-fetch each SNI's ECHConfigList fresh on rebuild — a stored key goes stale when the CDN
        # rotates it (~hourly on Cloudflare) and a stale key fails the ws-upgrade on EVERY edge (the
        # whole pool goes dark and only a recreate recovers). NO fallback: if ECH is on and a key
        # can't be fetched, the rebuild FAILS (raises) rather than replaying a stale/empty key — the
        # caller must run this BEFORE tearing the tunnel down so a failure leaves it intact. (The
        # restore path passes refetch_ech=False to reuse the stored key verbatim without raising.)
        pool_ech = bool(src.get("ech"))
        hosts = [s.get("host") for s in src["ws_edge_snis"] if isinstance(s, dict) and s.get("host")]
        ech_map = _fetch_ech_map(hosts) if (pool_ech and refetch_ech) else {}   # concurrent — not host-by-host
        psnis = []
        for s in src["ws_edge_snis"]:
            if not (isinstance(s, dict) and s.get("host")):
                continue
            h = s.get("host")
            if refetch_ech:
                ec = ech_map.get(h, "") if pool_ech else ""
                if pool_ech and not ec:
                    raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — بازسازی متوقف شد (ECH روشن است ولی رکوردِ HTTPS/ech= در دسترس نیست)." % h)
            else:
                ec = s.get("ech", "") if pool_ech else ""   # last-resort restore: reuse the stored key verbatim
            psnis.append({"host": h, "ech": ec, "path": s.get("path") or src.get("ws_path") or "/"})
        e["ws_edge_snis"] = psnis
        _rs = src.get("ws_rotate_secs")   # 0 = rotation off (failover-only); a truthiness `or 600` would force 600
        e["ws_rotate_secs"] = int(_rs) if _rs is not None else 600
        e["ws_auto_burn"] = bool(src.get("ws_auto_burn"))
        e["ws_warm_standby"] = bool(src.get("ws_warm_standby"))   # make-before-break failover
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
    _uw = get_settings().get("uptime_window", 1)
    base = {"id": n["id"], "name": n["name"], "host": n["host"], "port": n["port"], "proxy": _redact_proxy(n.get("proxy")),
            "uptime": _uh_cells(n["id"], _uw), "uptime_pct": _uh_pct(n["id"], _uw)}  # cells=visual bar, pct=time-weighted %
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
            types["core"] = types.get("core", 0) + 1   # count core tunnels in the overview breakdown too
            if link_drift(L["id"]):
                drift_n += 1
            elif _link_up(L):
                up += 1
            else:
                down += 1
            continue  # but emit NO link/drift alert for core: those navigate to the tunnels page, which hides core
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

    _sset = get_settings()
    win = _sset.get("uptime_window", 1)
    ups, downcnt = [], 0
    for n in nodes:
        cells = _uh_cells(n["id"], win)
        if any(c is not None for c in cells):
            ups.append(_uh_pct(n["id"], win))   # time-weighted, not red-cell-counting
            if any(c == 0 for c in cells):
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
            "links": len(links) - n_core, "core": n_core, "link_total": len(links),
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
            "fleet_rx_total": frx, "fleet_tx_total": ftx,
            "ev_seq": _ev_seq_get(), "log_count": len(load_events()),
            "ui_interval": _sset.get("ui_interval", 2), "poll_interval": _sset.get("poll_interval", 2)}


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
            with _PairLock(peer_id, peer_id):  # lock ONLY the peer (nid is being wiped/removed): a shared nid lock
                node_call(pn, "delete", "POST", {"name": L["name"]}, timeout=8)  # would serialize all N calls -> N*timeout. Still mutually excludes a rebuild on this pair (it holds peer_id too).
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
_core_versions_cache = {"ts": 0.0, "attempt": 0.0, "data": None}
_core_versions_lock = threading.Lock()
_core_versions_refreshing = False


def _fetch_core_versions():
    """Fetch the core repo's GitHub releases (SLOW — runs OFF the request path). Returns the version
    list, or None on failure so the caller keeps the existing cache instead of blanking it."""
    try:
        req = urllib.request.Request(_CORE_RELEASES_API,
                                     headers={"User-Agent": "tnl-central", "Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            vers = []
            for rel in json.loads(r.read().decode()):
                tag = rel.get("tag_name")
                if not tag or rel.get("draft"):
                    continue
                vers.append({"id": tag, "label": rel.get("name") or tag, "prerelease": bool(rel.get("prerelease"))})
            return vers
    except Exception:
        return None


def _core_versions_refresh_bg():
    global _core_versions_refreshing
    try:
        vers = _fetch_core_versions()
        with _core_versions_lock:
            if vers is not None:  # success -> publish; failure -> keep the old cache, just record the attempt
                _core_versions_cache["data"] = vers
                _core_versions_cache["ts"] = time.time()
    finally:
        with _core_versions_lock:
            _core_versions_refreshing = False


def api_core_versions(d):
    """The core versions the operator can install/downgrade to — the core repo's GitHub releases,
    newest first, plus a "latest" tag. Served INSTANTLY from cache; when the cache is stale a refresh
    runs in the BACKGROUND (deduped, min 60s between attempts) so a slow/blocked GitHub — common from
    the deployment region — never blocks the settings/agent page load. Degrades to whatever is cached
    (or just the uploaded/staged binary) until a refresh succeeds."""
    global _core_versions_refreshing
    now = time.time()
    with _core_versions_lock:
        fresh = _core_versions_cache["data"] is not None and now - _core_versions_cache["ts"] <= 300
        recent_attempt = now - _core_versions_cache["attempt"] < 60
        if not fresh and not recent_attempt and not _core_versions_refreshing:
            _core_versions_refreshing = True
            _core_versions_cache["attempt"] = now
            threading.Thread(target=_core_versions_refresh_bg, daemon=True).start()
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
    # Cache still cold (its refresh is async) — this is an explicit operator stage/install action, not
    # a page load, so a one-off synchronous fetch here is fine and avoids recording the abstract "latest".
    fetched = _fetch_core_versions()
    if fetched:
        with _core_versions_lock:
            _core_versions_cache["data"] = fetched
            _core_versions_cache["ts"] = time.time()
        for v in fetched:
            if v.get("id"):
                return v["id"]
    return "latest"


def _dl(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "tnl-central"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def _fetch_release(version, arch):
    """Download + verify a core release asset (binary + its .sha256) from GitHub. Returns (raw, sha).
    Raises on any failure — this is the ONLY place that talks to GitHub for the core binary."""
    if arch not in ("amd64", "arm64"):   # never interpolate an unvetted arch into a GitHub asset URL
        raise ValueError("معماریِ نامعتبر — فقط amd64 یا arm64 مجاز است")
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
    if arch not in ("amd64", "arm64"):   # arch reaches a local file path + a GitHub asset URL — whitelist
        raise ValueError("معماریِ نامعتبر — فقط amd64 یا arm64 مجاز است")
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
            return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")), "version": r.get("version"),
                    "restarted": r.get("restarted"), "core_sha": r.get("core_sha"), "unchanged": bool(r.get("unchanged")), "error": err}

        return {"results": parallel_map(one_custom, ids)}

    _stage_core(version)   # download the chosen version onto the panel first (raises if the panel is offline)

    def one(nid):
        n = get_node(nid)
        if not n:
            return {"id": nid, "ok": False, "error": "node removed"}
        r = _push_staged(n)
        err = r.get("error") or r.get("msg") or ("; ".join(r["errors"]) if r.get("errors") else "")
        return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")), "version": r.get("version"),
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
        return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")), "version": r.get("version"),
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
        rec = {**pub, "a_online": bool(la.get("ok")) or la.get("configs") is not None,
               "b_online": bool(lb.get("ok")) or lb.get("configs") is not None,
               "a_health": ah, "b_health": bh, "a_ips": a_ips, "b_ips": b_ips,
               "view_side": side, "view_name": (L["b_name"] if side == "b" else L["a_name"]),
               "drift": link_drift(L["id"]), **tfl.get(L["id"], {})}
        # Live active pool IP: the CLIENT node writes .peerpool (active destination) / .srcpool (active
        # source); surface it per side so the card shows the IP the tunnel is really on right now (the
        # server's box = active destination, the client's box = active source). Present only when that
        # side actually rotates (>=2 in its pool -> the node wrote the file).
        if L.get("type") == "core" and L.get("ip_rotate"):
            srvA = (L.get("server_side") != "b")
            cl = lb if srvA else la  # the client is the non-server node
            pd = (cl.get("pools") or {}).get(L["name"]) or {}
            dact = str(pd.get("dst") or "").split(":")[0]  # active destination (bare IP)
            sact = str(pd.get("src") or "").split(":")[0]  # active source (bare IP)
            a_act, b_act = (dact, sact) if srvA else (sact, dact)
            if a_act:
                rec["a_ip_active"], rec["a_ip_rot"] = a_act, True
            if b_act:
                rec["b_ip_active"], rec["b_ip_rot"] = b_act, True
        out.append(rec)
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
        _tf_reset(n["id"], ["pf:" + _pf_name(d["name"])])
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


def _port_bindings(ttype, port, transport, server_side, tid, A, B, a_ip=None, b_ip=None, a_pool=None, b_pool=None):
    """The (node, ip, port, proto) sockets a tunnel will actually LISTEN on — the set whose
    freeness must be verified before building. The core server binds its self_ip:port, so the
    bind IP is carried too: two ws tunnels on one host but different IPs share a port without a
    false conflict. Scope per the tunnel model:
      core (bip): only the server node binds; the client dials from a random ephemeral port, so it
                    is never checked. proto follows transport (udp|tcp). A UNpooled server binds its
                    single self_ip; a udp/tcp server UNDER a destination pool binds EACH of its
                    selected pool IPs explicitly (one socket/listener per IP), so every one is a
                    distinct binding to check — a_pool/b_pool carry that selected set.
      fou/l2tpv3/vxlan: BOTH nodes decap on that UDP port (any-IP, ip=None).
      gre/sit/ipip/ipsec: no listening L4 port -> nothing to check."""
    p = int(port or _default_tunnel_port(ttype, tid) or 0)
    if not p:
        return []
    if ttype == "core":
        server_a = (server_side or "a") == "a"
        srv = A if server_a else B
        srv_ip = a_ip if server_a else b_ip
        srv_pool = (a_pool if server_a else b_pool) or []
        t = (transport or "udp").lower()
        if t in ("raw", "flux"):
            return []                        # raw-IP / rotating-protocol carrier — no fixed L4 port to portcheck
        proto = "tcp" if t in ("tcp", "ws") else "udp"  # ws is a TCP/WebSocket carrier
        pool_ips = [ip for ip in srv_pool if ip] if t in ("udp", "tcp") else []
        if pool_ips:
            return [(srv, ip, p, proto) for ip in pool_ips]  # pooled server: one bind per selected IP
        return [(srv, srv_ip, p, proto)]
    if ttype in ("fou", "l2tpv3", "vxlan"):
        return [(A, None, p, "udp"), (B, None, p, "udp")]
    return []


def _guard_port_conflicts(bindings, exclude=frozenset()):
    """Ask each target node whether the port it will bind is already in use (by ANY
    service — Xray/nginx/x-ui/…, not just our tunnels) and raise a clear Persian error
    if so. `exclude` holds (node_id, ip, port, proto) tuples the edited tunnel already owns,
    so a tunnel never conflicts with itself — including, for a pooled server, every one of its
    selected pool IPs (each is a distinct binding now that the server binds them explicitly rather
    than 0.0.0.0). Nodes too old to know `portcheck` (or briefly unreachable) are skipped rather
    than hard-blocked."""
    for node, ip, port, proto in bindings:
        if (node["id"], ip or "", int(port), proto) in exclude:
            continue
        r = node_call(node, "portcheck", "POST", {"port": port, "proto": proto, "ip": ip or ""}, timeout=10)
        if not r.get("ok"):
            continue  # unknown endpoint (old agent) / offline -> can't verify, don't block the build
        if r.get("busy"):
            who = str(r.get("who") or "").strip()
            tail = f" — {who}" if who else ""
            onip = f" (روی {ip})" if ip else ""
            raise ValueError(f"پورتِ {port}/{proto.upper()} روی نودِ «{node['name']}»{onip} اشغال است{tail}؛ یک پورتِ دیگر انتخاب کن")


def _core_bind_keys(bindings):
    """Normalize _port_bindings output to a comparable key set {(node_id, ip, port, proto)}."""
    return {(n["id"], ip or "", int(p), pr) for n, ip, p, pr in bindings}


def _core_l4_conflict(new_binds, exclude_id=None):
    """Registry-level conflict check for a core tunnel. Core is CARRIER-MULTIPLEXED on its server IP:
    only udp/tcp/ws bind an EXCLUSIVE kernel port (returned by _port_bindings), so two core tunnels
    truly clash ONLY when their server (node, ip, port, L4-proto) coincide. raw/flux return no bindings
    — they use shared raw/AF_PACKET sockets and every frame is AEAD-authenticated, so any number
    coexist on one server IP (each drops the others' frames). So a raw-vs-udp, a udp:9000-vs-udp:9001,
    or a udp-vs-tcp-on-the-same-port pair on the same IPs is fine; only a same (ip,port,proto) L4 bind
    is a real conflict. This catches a conflict even when the other tunnel is currently DOWN (the live
    _guard_port_conflicts only sees running binds); the two together also catch non-tunnel services on
    the port. Returns the first conflicting stored core link (or None); exclude_id skips self on edit."""
    keys = _core_bind_keys(new_binds)
    if not keys:  # raw/flux (or no port) — nothing exclusive to clash on
        return None
    for L in load_links():
        if L.get("type") != "core" or L.get("id") == exclude_id:
            continue
        LA, LB = get_node(L.get("a_node")), get_node(L.get("b_node"))
        if not LA or not LB:  # orphaned link (a node was deleted) — can't compute its bind
            continue
        eb = _port_bindings("core", L.get("port"), L.get("transport"), L.get("server_side"),
                            L.get("tunnel_id"), LA, LB, L.get("a_ip"), L.get("b_ip"),
                            L.get("a_ip_pool"), L.get("b_ip_pool"))
        if keys & _core_bind_keys(eb):
            return L
    return None


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


def _desync_fields(d, transport, cur=None):
    """Fake-packet desync (anti-DPI): the client emits decoy packets that reach an on-path DPI but
    not the server, mis-syncing a stateful DPI while the real session is untouched. raw/flux forge
    whole IPv4 decoys; tcp/ws inject decoy TCP segments on the kernel connection's 4-tuple. Not on
    plain udp (no injection hook). cur (the existing link) supplies edit defaults so a partial edit
    keeps the stored config. Returns {} when off / not applicable — so switching to udp cleanly
    drops the fields."""
    out = {}
    if transport not in ("raw", "flux", "tcp", "ws"):
        return out
    cur = cur or {}
    on = bool(d.get("fake_desync")) if ("fake_desync" in d) else bool(cur.get("fake_desync"))
    if not on:
        return out
    out["fake_desync"] = True
    ttl = int(d.get("fake_ttl") or cur.get("fake_ttl") or 4)
    if ttl < 1 or ttl > 255:
        raise ValueError("TTLِ طعمه باید بین ۱ تا ۲۵۵ باشد")
    out["fake_ttl"] = ttl
    cnt = int(d.get("fake_count") or cur.get("fake_count") or 2)
    if cnt < 1 or cnt > 64:
        raise ValueError("تعدادِ طعمه باید بین ۱ تا ۶۴ باشد")
    out["fake_count"] = cnt
    mode = str(d.get("fake_mode") or cur.get("fake_mode") or "ttl").strip().lower()
    if mode not in ("ttl", "badsum", "both"):
        raise ValueError("حالتِ طعمه نامعتبر است")
    out["fake_mode"] = mode
    return out


_ECH_RE = re.compile(r'ech="?([A-Za-z0-9+/=]+)"?')
_GENERIC_RE = re.compile(r'\\#\s+\d+\s+([0-9A-Fa-f][0-9A-Fa-f\s]+)')


def _ech_from_svcb(raw):
    """Parse HTTPS/SVCB RDATA (2-byte priority + target name + SvcParams) and return the base64 of
    SvcParamKey 5 (ech), or '' if absent/malformed. Used when a resolver returns the RFC 3597
    generic form (\\# len hex) instead of the presentation form."""
    try:
        i = 2  # skip 2-byte SvcPriority
        while i < len(raw) and raw[i] != 0:   # skip the target name (length-prefixed labels)
            i += 1 + raw[i]
        i += 1                                 # skip the root (zero-length) label
        while i + 4 <= len(raw):
            key = int.from_bytes(raw[i:i + 2], "big"); i += 2
            ln = int.from_bytes(raw[i:i + 2], "big"); i += 2
            val = raw[i:i + ln]; i += ln
            if key == 5:                       # SvcParamKey 5 == ech
                return base64.b64encode(val).decode()
    except Exception:
        pass
    return ""


def _ech_from_text(s):
    """Pull the base64 ECHConfigList out of a record string in either the presentation form
    (ech="...") or the RFC 3597 generic form (\\# len hex...). '' if neither is present."""
    m = _ECH_RE.search(s)
    if m:
        return m.group(1)
    g = _GENERIC_RE.search(s)
    if g:
        try:
            return _ech_from_svcb(bytes.fromhex(re.sub(r"\s", "", g.group(1))))
        except Exception:
            pass
    return ""


def _fetch_ech(host):
    """Return the base64 ECHConfigList from host's HTTPS (type 65) DNS record — for THIS host only
    (no fallback to another domain's key). To kill the transient "not found" that a single slow or
    stale resolver caused, we RACE dig + several public DoH resolvers (Cloudflare & Google, by name
    and by IP for censorship resilience) in parallel and take the first that returns an ech=, and
    RETRY the whole race a few times with a short backoff (helps a record that was just published and
    is still propagating). Handles both the presentation (ech=...) and RFC 3597 generic forms.
    Returns '' only when no source yields an ECH key after all rounds. Never raises."""
    import urllib.request, concurrent.futures, time
    host = str(host or "").strip()
    if not host or not re.match(r"^[A-Za-z0-9.-]{1,253}$", host):
        return ""

    def via_dig():
        try:
            out = subprocess.run(["dig", "+short", "HTTPS", host],
                                 capture_output=True, timeout=6).stdout.decode("utf-8", "replace")
            return _ech_from_text(out)
        except Exception:
            return ""

    def via_doh(base):
        try:
            req = urllib.request.Request("%s?name=%s&type=HTTPS" % (base, host),
                                         headers={"accept": "application/dns-json", "user-agent": "tnl-central"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            for ans in data.get("Answer", []):
                if ans.get("type") in (65, "65", "HTTPS"):
                    v = _ech_from_text(str(ans.get("data", "")))
                    if v:
                        return v
        except Exception:
            pass
        return ""

    doh = ["https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query",
           "https://dns.google/resolve", "https://8.8.8.8/resolve"]
    tasks = [via_dig] + [(lambda b=b: via_doh(b)) for b in doh]
    for attempt in range(3):
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks))
        futs = [ex.submit(t) for t in tasks]
        found = ""
        try:
            for f in concurrent.futures.as_completed(futs, timeout=8):
                try:
                    v = f.result()
                except Exception:
                    v = ""
                if v:
                    found = v
                    break
        except Exception:
            pass
        ex.shutdown(wait=False)   # return as soon as one source answers; don't wait on slow ones
        if found:
            return found
        if attempt < 2:
            time.sleep(0.8)
    return ""


def _fetch_ech_map(hosts):
    """Fetch the ECHConfigList for MANY hosts CONCURRENTLY. _fetch_ech already races resolvers per
    host, but calling it host-by-host serializes a whole pool — a 64-host pool with blackholed DoH
    could hold the caller (and the _PairLock, blocking reconcile) for minutes. Returns {host: ech};
    ech is '' when a host has no key. Never raises."""
    import concurrent.futures
    uniq = list(dict.fromkeys(h for h in hosts if h))
    if not uniq:
        return {}
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(uniq))) as ex:
        futs = {ex.submit(_fetch_ech, h): h for h in uniq}
        for f in concurrent.futures.as_completed(futs):
            try:
                out[futs[f]] = f.result() or ""
            except Exception:
                out[futs[f]] = ""
    return out


def _sni_split_fields(d, cur):
    """SNI fragmentation fields, shared by the single-edge and pool ws builders. Splits the wss
    ClientHello so the cleartext SNI crosses a TCP segment boundary — a stateless SNI-blocklist DPI
    can't match the full hostname (a cheap complement to ECH). split_pos is the byte offset into the
    ClientHello (0 = auto: middle of the hostname). Returns {} when off; caller ensures wss is on."""
    on = d.get("sni_split") if ("sni_split" in d) else cur.get("sni_split")
    if not on:
        return {}
    sp = int((d.get("split_pos") if "split_pos" in d else cur.get("split_pos")) or 0)
    if sp < 0 or sp > 1400:
        raise ValueError("split_pos باید بین ۰ تا ۱۴۰۰ باشد (۰ = خودکار، وسطِ دامنه)")
    out = {"sni_split": True}
    if sp:
        out["split_pos"] = sp
    # mode: "split" (دو سگمنتِ in-order) | "disorder" (سگمنتِ سرْ با TTL پایین) | "fake" (ClientHelloِ
    # جعلی با SNIِ فریب روی همان seq، ضدِ DPIِ بازسازی‌کننده)
    mode = str((d.get("sni_mode") if "sni_mode" in d else cur.get("sni_mode")) or "split").strip().lower()
    if mode not in ("split", "disorder", "fake"):
        raise ValueError("حالتِ SNI نامعتبر است (split / disorder / fake)")
    if mode != "split":
        out["sni_mode"] = mode
        st = int((d.get("split_ttl") if "split_ttl" in d else cur.get("split_ttl")) or 0)
        if st < 0 or st > 255:
            raise ValueError("split_ttl باید بین ۰ تا ۲۵۵ باشد (۰ = پیش‌فرض)")
        if st:
            out["split_ttl"] = st
    return out


def _ws_fields(d, transport, cur=None):
    """Validate and return the ws (WebSocket/CDN) carrier fields. ws_host is the Host
    header + TLS SNI (the fronting/origin domain); ws_path the request path; ws_tls makes
    the client speak wss to a CDN edge. cur supplies edit defaults."""
    out = {}
    if transport != "ws":
        return out
    cur = cur or {}
    # Edge pool overrides the single-edge fields: when on, delegate to the pool builder.
    if (d.get("ws_pool") if "ws_pool" in d else cur.get("ws_pool")):
        return _ws_pool_fields(d, cur)
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
    # ECH (Encrypted ClientHello): hides the SNI so an SNI-blocklisting censor can't see the
    # real domain. It rides the TLS ClientHello, so it only makes sense with wss. We fetch the
    # ECHConfigList from the domain's HTTPS DNS record over DoH here (the panel has clean
    # internet; the in-country client's DNS is often poisoned) and store the base64 on the link
    # so the node can forward it verbatim. Re-fetched on every save so a rotated key stays fresh.
    ech = d.get("ech") if ("ech" in d) else cur.get("ech")
    if ech:
        if not out.get("ws_tls"):
            raise ValueError("ECH به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن")
        cfg = _fetch_ech(host)
        if not cfg:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد)" % host)
        out["ech"] = True
        out["ws_ech"] = cfg
    # xhttp: carry the stream over a GET(down)+POST(up) HTTP request pair instead of a
    # WebSocket upgrade, so it passes a CDN/account that blocks WebSocket. Independent of
    # wss (works over plain http too, though wss is the usual fronting choice). Single-edge
    # only — the pool branch above returns before here, so xhttp never combines with a pool.
    xh = d.get("ws_xhttp") if ("ws_xhttp" in d) else cur.get("ws_xhttp")
    if bool(xh):
        out["ws_xhttp"] = True
        # Upstream style: packet-up (default, many short POSTs — most CDN-compatible) or grpc (a
        # single full-duplex request as a real gRPC call, so a CDN streams it over h2c instead of
        # buffering; needs wss). The legacy plain "stream" value canonicalizes to grpc.
        mode = str((d.get("ws_xhttp_mode") if "ws_xhttp_mode" in d else cur.get("ws_xhttp_mode")) or "").strip().lower()
        if mode in ("stream", "grpc"):
            out["ws_xhttp_mode"] = "grpc"
    ss = _sni_split_fields(d, cur)  # SNI fragmentation (wss only)
    if ss:
        if not out.get("ws_tls"):
            raise ValueError("تقسیمِ SNI به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن")
        out.update(ss)
    return out


# An edge IP must be a real IPv4 (four 0-255 octets) or a real domain (labels + alphabetic
# TLD); an SNI must be a real domain. This rejects both "876889767" (no dots) and
# "543.45534.453453" (dotted but neither a valid IP nor a domain). Mirrors the browser
# _ip4Re / _domRe so the client and server reject the same inputs.
_IP4_RE = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
_DOMAIN_RE = r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"


def _ws_rotate_default(d, cur):
    """ws_rotate_secs with 0 (rotation off / failover-only) PRESERVED: the request's value when it
    sends one, else the stored value (even 0), else 600 — never coerce a legitimate 0 to 600 with a
    truthiness `or`."""
    if "ws_rotate_secs" in d and d.get("ws_rotate_secs") is not None:
        return d["ws_rotate_secs"]
    v = cur.get("ws_rotate_secs")
    return 600 if v is None else v


def _ws_pool_fields(d, cur=None):
    """Validate + build the ws edge-POOL fields. The form sends clean/burned edge-IP lists and
    clean/burned SNI host lists (+ rotation); we fetch the ECHConfigList for each clean SNI and
    store the pool. A non-empty pool overrides the single ws_host/edge_ip and is always wss.
    Clean lists go to the node; the burned lists are panel-side memory so a burned IP/SNI is not
    re-sent as clean. Missing input on an edit falls back to the stored value (key-presence keyed)."""
    cur = cur or {}

    def _list(key):
        return (d[key] if key in d else cur.get(key)) or []

    def _ips(key):
        seen, res = set(), []
        for x in _list(key):
            x = str(x).strip()
            if not x or x in seen:
                continue
            h = x.rpartition(":")[0] or x
            p = x.rpartition(":")[2] if ":" in x else ""
            if not (re.match(_IP4_RE, h) or re.match(_DOMAIN_RE, h)) or (p and not (p.isdigit() and 1 <= int(p) <= 65535)):
                raise ValueError("آی‌پیِ لبهٔ نامعتبر (باید IPv4 یا دامنهٔ معتبر باشد): %s" % x)
            seen.add(x)
            res.append(x)
        return res

    def _hosts(key):
        seen, res = set(), []
        for x in _list(key):
            x = str(x).strip().lower()
            if not x or x in seen:
                continue
            if not re.match(_DOMAIN_RE, x):
                raise ValueError("دامنهٔ (SNI) نامعتبر (باید یک دامنهٔ معتبر باشد): %s" % x)
            seen.add(x)
            res.append(x)
        return res

    clean_ips, burned_ips = _ips("ws_edge_ips"), _ips("ws_edge_ips_burned")
    clean_hosts, burned_hosts = _hosts("ws_edge_snis"), _hosts("ws_edge_snis_burned")
    if not clean_ips or not clean_hosts:
        raise ValueError("استخر به حداقل یک IP تمیز و یک دامنهٔ تمیز نیاز دارد (سوخته‌ها کافی نیستند)")
    if len(clean_ips) + len(burned_ips) > 64 or len(clean_hosts) + len(burned_hosts) > 64:
        raise ValueError("استخر خیلی بزرگ است (حداکثر ۶۴)")
    path = str((d["ws_path"] if "ws_path" in d else cur.get("ws_path")) or "").strip() or "/"
    if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", path):
        raise ValueError("مسیر (path) نامعتبر است")
    # ECH is driven by the shared "ech" toggle (same one as the single edge): when on we fetch the
    # ECHConfigList for each clean SNI (dig-first) to hide the SNI; when off every SNI is used with
    # no ECH. Re-fetch FRESH on every save — the CDN rotates its ECH key (~hourly on Cloudflare), so
    # a reused/stored key goes stale and would fail the ws-upgrade on every edge. NO fallback: if ECH
    # is on and a SNI's key can't be fetched, the save FAILS (we never store an empty or stale key),
    # matching the single-edge ws path.
    ech_on = bool(d.get("ech") if "ech" in d else cur.get("ech"))
    ech_map = _fetch_ech_map(clean_hosts) if ech_on else {}   # concurrent — never serialize the pool host-by-host
    snis = []
    for h in clean_hosts:
        ec = ech_map.get(h, "") if ech_on else ""
        if ech_on and not ec:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد). استخر با ECH روشن ساخته نمی‌شود." % h)
        snis.append({"host": h, "ech": ec, "path": path})
    res = {
        "ws_pool": True,
        "ws_tls": True,
        "ech": ech_on,   # shared toggle; per-SNI ECHConfigList lives inside ws_edge_snis
        "ws_xhttp": bool(d.get("ws_xhttp") if "ws_xhttp" in d else cur.get("ws_xhttp")),  # xhttp carrier over the pool
        "ws_edge_ips": clean_ips,
        "ws_edge_ips_burned": burned_ips,
        "ws_edge_snis": snis,                # [{host,ech,path}] — sent to the node + stored
        "ws_edge_snis_burned": burned_hosts,  # host list — panel-side only
        "ws_rotate_secs": max(0, min(28800, int(_ws_rotate_default(d, cur)))),   # 0 (rotation off) preserved, not coerced to 600
        "ws_auto_burn": bool(d.get("ws_auto_burn") if "ws_auto_burn" in d else cur.get("ws_auto_burn")),
        "ws_warm_standby": bool(d.get("ws_warm_standby") if "ws_warm_standby" in d else cur.get("ws_warm_standby")),
        "ws_path": path,
    }
    # xhttp upstream style over the pool (only stored when non-default, mirroring the single edge).
    if res["ws_xhttp"]:
        mode = str((d.get("ws_xhttp_mode") if "ws_xhttp_mode" in d else cur.get("ws_xhttp_mode")) or "").strip().lower()
        if mode in ("stream", "grpc"):
            res["ws_xhttp_mode"] = "grpc"
    res.update(_sni_split_fields(d, cur))  # SNI fragmentation (the pool is always wss)
    return res


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
        # core is carrier-multiplexed (see _core_l4_conflict): several core tunnels may share an IP pair
        # as long as their server L4 binds don't clash, so it is NOT blocked here by ip-pair alone —
        # the precise per-carrier/port check runs after the carrier is known.
        if L.get("type") == ttype and same_pair and ttype != "core":
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
        extra.update(_desync_fields(d, transport)) # fake-packet desync (raw/flux only); {} elsewhere
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
        # IP rotation (direct transports): the operator picks a subset of each node's IPs to cycle.
        # Stored in the link so edit/rebuild replay it; assigned per-role by _core_rotation_bodies.
        if transport in ("udp", "tcp", "raw", "flux") and bool(d.get("ip_rotate")):
            ap = [s for s in (str(ip).strip() for ip in (d.get("a_ip_pool") or [])) if s in a_ips]
            bp = [s for s in (str(ip).strip() for ip in (d.get("b_ip_pool") or [])) if s in b_ips]
            if a_ip not in ap:
                ap = [a_ip] + ap   # the tunnel's primary IP anchors each side's pool
            if b_ip not in bp:
                bp = [b_ip] + bp
            if len(ap) >= 2 or len(bp) >= 2:   # at least one side actually has enough to rotate
                extra["ip_rotate"] = True
                extra["a_ip_pool"], extra["b_ip_pool"] = ap, bp
                extra["rotate_secs"] = max(0, min(86400, int(d.get("rotate_secs") or 0)))
                extra["auto_burn"] = bool(d.get("auto_burn"))
    # Precise same-server-IP conflict: another core tunnel that binds the SAME (server ip, port, L4
    # proto). Different carrier, different port, or a raw/flux carrier (shared sockets) is allowed.
    if ttype == "core":
        _clash = _core_l4_conflict(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")))
        if _clash:
            raise ValueError(f"تونلِ core «{_clash.get('name')}» از قبل روی همین آی‌پی و پورتِ سرور هست؛ پورت یا حاملِ متفاوت انتخاب کن (حامل‌های دیگر/پورت‌های دیگر روی همین آی‌پی مجازند)")
    # Refuse to build if the chosen port is already taken on a node that will bind it.
    _guard_port_conflicts(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")))
    node_extra = _node_extra(extra)
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name, **node_extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name, **node_extra}
    if ttype == "core":
        a_body["role"] = "server" if server_side == "a" else "client"
        b_body["role"] = "server" if server_side == "b" else "client"
        _core_rotation_bodies(extra, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
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


def _restore_link(A, B, L, extra=None):
    """Best-effort rebuild of the OLD tunnel on both sides (roll back a failed edit/rebuild). NEVER
    raises — a restore failure must not mask the real error or leave the tunnel down. `extra` may be
    passed pre-computed (rebuild already ran _tunnel_extra(L) before teardown); otherwise it is
    computed here, and if the fresh-ECH fetch raises we fall back to the stored key verbatim so the
    old tunnel still comes back up instead of a misleading ECH error stranding it."""
    tid = int(L["tunnel_id"])
    if extra is None:
        try:
            extra = _tunnel_extra(L)                     # prefer a fresh ECH key
        except Exception:
            extra = _tunnel_extra(L, refetch_ech=False)  # last resort: stored key verbatim, never raises
    _rot = L.get("ip_rotate") and L.get("transport") in ("udp", "tcp", "raw", "flux")
    _ap, _bp = list(L.get("a_ip_pool") or []), list(L.get("b_ip_pool") or [])
    _rs, _ab = max(0, min(86400, int(L.get("rotate_secs") or 0))), bool(L.get("auto_burn"))
    for N, self_ip, peer_ip, own, peer in ((A, L["a_ip"], L["b_ip"], _ap, _bp), (B, L["b_ip"], L["a_ip"], _bp, _ap)):
        if N:
            body = {"type": L["type"], "self_ip": self_ip, "peer_ip": peer_ip,
                    "subnet": L["subnet"], "id": tid, "name": L["name"], **extra}
            role = _core_role(L, N["id"])
            if role:
                body["role"] = role
                if _rot:   # replay the stored IP-rotation pools for this node's role
                    _apply_core_rotation(body, role == "client", own, peer, _rs, _ab)
            try:
                node_call(N, "tunnel", "POST", body, timeout=200)
            except Exception:
                pass   # best-effort; swallow so restore never masks the original failure


def api_edit_link(d):
    a, b = _link_nodes(d)
    with _PairLock(a, b):  # serialize only with ops touching the same node(s)
        return _edit_link_impl(d)


def api_edge_status(d):
    """Poll the ws edge pool's live health for a link: read the client node's core status file
    (active edge + per-entry health FSM) and return it so the panel can render سالم/موقت/دائمی
    with live retest countdowns. It does NOT persist anything into the link's stored lists — the
    core's health is transient and self-healing (a temporary block clears on its own retest), so
    baking it into the operator's permanent burned list would defeat the auto-recovery. The
    operator's clean/burned curation stays exactly as they set it."""
    d = d or {}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core":
        return {"ok": True, "pool": False, "active": "", "health": [], "events": []}
    # Any core tunnel may have a status file: a ws pool writes the rich pool state, and a datagram
    # client (udp/raw/flux) writes a lightweight event ring (self-heal reasons). Read whichever
    # exists; `pool` stays accurate so pool-only UI keeps behaving.
    is_pool = bool(L.get("ws_pool"))
    server_side = L.get("server_side", "a")
    client_id = L.get("b_node") if server_side == "a" else L.get("a_node")
    node = get_node(client_id)
    if not node:
        return {"ok": True, "pool": is_pool, "active": "", "health": [], "events": [], "error": "client node not found"}
    r = node_call(node, "edge-status", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": True, "pool": is_pool, "active": "", "health": [], "events": [], "error": r.get("error") or r.get("msg")}
    health = []
    for h in (r.get("health") or []):
        if not isinstance(h, dict):
            continue
        health.append({
            "key": str(h.get("key") or ""),
            "kind": "sni" if str(h.get("kind")) == "sni" else "ip",
            "state": str(h.get("state") or "healthy"),
            "fails": int(h.get("fails") or 0),
            "next_retest_unix": int(h.get("next_retest_unix") or 0),
        })
    # Use the CLIENT NODE's clock as "now" (it shares the core's clock that stamped next_retest_unix),
    # so retest countdowns are correct even if the panel's clock is skewed from the node's. `ts` is the
    # status file's write time -> the UI can flag a stale file (dead tunnel) as offline. Fall back to
    # the panel clock only if an older node build didn't send `now`.
    node_now = int(r.get("now") or 0) or int(time.time())
    return {"ok": True, "pool": is_pool, "active": str(r.get("active") or ""),
            "health": health, "events": (r.get("events") or []), "now": node_now, "ts": int(r.get("ts") or 0)}


def api_pool_probe_now(d):
    """Live 'probe now' for a ws edge pool: tell the client node to SIGHUP the running core so
    it retests every suspect/dead edge at once (no rebuild). Returns fresh status via the next poll."""
    d = d or {}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ws_pool"):
        raise ValueError("این لینک استخرِ لبه ندارد")
    server_side = L.get("server_side", "a")
    client_id = L.get("b_node") if server_side == "a" else L.get("a_node")
    node = get_node(client_id)
    if not node:
        raise ValueError("نودِ کلاینت پیدا نشد")
    r = node_call(node, "pool-probe-now", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "پروب ناموفق بود"}
    return {"ok": True}


def api_pool_select(d):
    """Live 'pin this edge': tell the client node to write a command file the running core polls
    so it jumps its rotation onto THIS specific IP/SNI (kind+key) and re-dials onto it — no
    rebuild, TUN stays up. Backs the per-edge select button."""
    d = d or {}
    _require(d, ["id", "kind", "key"])
    if d["kind"] not in ("ip", "sni"):
        raise ValueError("kind باید ip یا sni باشد")
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ws_pool"):
        raise ValueError("این لینک استخرِ لبه ندارد")
    server_side = L.get("server_side", "a")
    client_id = L.get("b_node") if server_side == "a" else L.get("a_node")
    node = get_node(client_id)
    if not node:
        raise ValueError("نودِ کلاینت پیدا نشد")
    r = node_call(node, "pool-select", "POST", {"name": L.get("name"), "kind": d["kind"], "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "انتخاب ناموفق بود"}
    now = int(time.time())
    _ev_suppress[d["id"]] = now + 45  # operator pin: don't log the edge change it causes
    try:  # prune expired entries so the map can't grow unbounded (esp. after links are deleted)
        for k, ts in list(_ev_suppress.items()):
            if ts < now:
                _ev_suppress.pop(k, None)
    except RuntimeError:
        pass  # a concurrent pin mutated it mid-iteration; the next call prunes
    return {"ok": True}


def _peer_pool_client(d):
    """Resolve (link, client node) for a direct-transport IP-rotation link, raising a clear error when
    the link isn't a pooled core or its client node is gone. Shared by the peer-pool live-status ops."""
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ip_rotate"):
        raise ValueError("این لینک استخرِ آی‌پی ندارد")
    server_side = L.get("server_side", "a")
    client_id = L.get("b_node") if server_side == "a" else L.get("a_node")
    node = get_node(client_id)
    if not node:
        raise ValueError("نودِ کلاینت پیدا نشد")
    return L, node


_PEER_ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]{1,64}$")  # IPv4/IPv6/ip:port only


def _peer_addr_ok(s):
    """A pool endpoint is always a bare IP or ip:port. Reject anything else BEFORE it reaches the panel
    UI: these strings originate from the client node's status file (attacker-influenceable if a node is
    compromised) and are rendered into the live view, so a strict IP charset whitelist here neutralizes
    any injection at the source, independent of how the JS renders it."""
    return bool(s) and bool(_PEER_ADDR_RE.match(s))


def _peer_sec_norm(sec):
    """Normalize one pool section (dst/src) from the node into the shape the panel reads, dropping any
    endpoint that isn't a clean IP/ip:port (defense-in-depth against a malicious/malformed node)."""
    sec = sec if isinstance(sec, dict) else {}
    health = []
    for h in (sec.get("health") or []):
        if not isinstance(h, dict):
            continue
        key = str(h.get("key") or "")
        if not _peer_addr_ok(key):
            continue
        health.append({"key": key, "state": str(h.get("state") or "healthy"),
                       "fails": int(h.get("fails") or 0), "next_retest_unix": int(h.get("next_retest_unix") or 0)})
    active = str(sec.get("active") or "")
    pin = str(sec.get("pin") or "")
    return {"active": active if _peer_addr_ok(active) else "",
            "addrs": [x for x in (str(v) for v in (sec.get("addrs") or [])) if _peer_addr_ok(x)][:64],
            "burned": [x for x in (str(v) for v in (sec.get("burned") or [])) if _peer_addr_ok(x)][:64],
            "health": health, "pin": pin if _peer_addr_ok(pin) else "", "ts": int(sec.get("ts") or 0)}


def api_peer_status(d):
    """Live status of a direct-transport IP-rotation link: ask the client node for BOTH pools —
    destination (the server IPs it dials) and source (this node's own egress IPs) — each with the
    active endpoint, the per-endpoint health FSM (suspect/dead + retest countdown), and any manual
    pin. `now` is the client node's clock (which stamped the retest times) so countdowns stay correct."""
    d = d or {}
    empty = {"active": "", "addrs": [], "burned": [], "health": [], "pin": "", "ts": 0}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ip_rotate"):
        return {"ok": True, "pool": False, "now": int(time.time()), "dst": dict(empty), "src": dict(empty)}
    server_side = L.get("server_side", "a")
    client_id = L.get("b_node") if server_side == "a" else L.get("a_node")
    node = get_node(client_id)
    if not node:
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": "client node not found"}
    r = node_call(node, "peer-status", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": r.get("error") or r.get("msg")}
    node_now = int(r.get("now") or 0) or int(time.time())
    return {"ok": True, "pool": True, "now": node_now, "dst": _peer_sec_norm(r.get("dst")), "src": _peer_sec_norm(r.get("src"))}


def api_peer_probe_now(d):
    """'Probe now' for a direct-transport pool: SIGHUP the client's core to retest every burned
    endpoint at once (re-admit it to rotation) with no rebuild. Fresh state arrives via the next poll."""
    L, node = _peer_pool_client(d or {})
    r = node_call(node, "peer-probe-now", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "پروب ناموفق بود"}
    return {"ok": True}


def api_peer_select(d):
    """'Pin this IP' for a direct-transport pool: tell the client node to write a command file the core
    polls so it jumps onto THIS endpoint (side 'src' pins the source pool, else the destination) and
    re-points onto it — no rebuild, TUN stays up. Backs the per-IP pin button."""
    d = d or {}
    _require(d, ["id", "key"])
    side = "src" if str(d.get("side")) == "src" else "dst"
    L, node = _peer_pool_client(d)
    r = node_call(node, "peer-select", "POST", {"name": L.get("name"), "side": side, "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "انتخاب ناموفق بود"}
    return {"ok": True}


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
        # core is carrier-multiplexed (see _core_l4_conflict): several core tunnels may share an IP pair
        # as long as their server L4 binds don't clash, so it is NOT blocked here by ip-pair alone — the
        # precise per-carrier/port check runs below (with exclude_id, so an edit never conflicts with
        # itself). This mirrors the create path; without the core exemption, EDITING one of two coexisting
        # core tunnels on the same IP pair would wrongly fail even when they don't technically clash.
        if x.get("type") == ttype and same_pair and ttype != "core":
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
        extra.update(_desync_fields(d, transport, L)) # fake-packet desync (raw/flux only); {} elsewhere; L preserves omitted fields
        # obfs/gso fall back to the stored value when the request omits the key, so a PARTIAL edit
        # (flux "rotate now" sends neither) doesn't strip the anti-DPI layer or the throughput
        # offload. A full form edit always sends both as booleans, so it still overrides correctly.
        if (bool(d.get("obfs")) if "obfs" in d else bool(L.get("obfs"))):
            if cipher == "none":
                raise ValueError("استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
            extra["obfs"] = True
        # cover/cover_sni fall back to the stored value when the request omits the key, so a PARTIAL
        # edit (a future tcp-link partial save) doesn't silently strip the TLS cover — matching obfs/gso.
        cover = (bool(d.get("cover")) if "cover" in d else bool(L.get("cover"))) and transport == "tcp"
        if cover and cipher == "none":   # the REALITY-style cover carries a PSK-authenticated token — it needs the AEAD key
            raise ValueError("پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        cover_sni = str((d["cover_sni"] if "cover_sni" in d else L.get("cover_sni")) or "").strip()
        if cover_sni and not re.match(r"^[A-Za-z0-9.-]{1,253}$", cover_sni):
            raise ValueError("دامنهٔ نمایشی (SNI) نامعتبر است")
        if cover and not cover_sni:   # required: no imposed default SNI
            raise ValueError("برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی")
        if cover:
            extra["cover"] = True
            extra["cover_sni"] = cover_sni
        if (bool(d.get("gso")) if "gso" in d else bool(L.get("gso"))):   # TUN segmentation offload; fall back to stored on a partial edit
            extra["gso"] = True
        # dead_after_secs (per-tunnel self-heal deadline): honor a set value, fall back to stored on a
        # partial edit (key absent), and allow clearing back to default by sending 0/empty (falsy → omit).
        _da_src = d.get("dead_after_secs") if "dead_after_secs" in d else L.get("dead_after_secs")
        if _da_src:
            extra["dead_after_secs"] = max(10, min(300, int(_da_src)))
        # IP rotation: a full form edit sends ip_rotate + pools; a partial edit (e.g. flux "rotate now")
        # omits them, so preserve the stored rotation config. Assigned per-role by _core_rotation_bodies.
        if "ip_rotate" in d:
            if transport in ("udp", "tcp", "raw", "flux") and bool(d.get("ip_rotate")):
                ap = [s for s in (str(ip).strip() for ip in (d.get("a_ip_pool") or [])) if s in a_ips]
                bp = [s for s in (str(ip).strip() for ip in (d.get("b_ip_pool") or [])) if s in b_ips]
                if a_ip not in ap:
                    ap = [a_ip] + ap
                if b_ip not in bp:
                    bp = [b_ip] + bp
                if len(ap) >= 2 or len(bp) >= 2:
                    extra["ip_rotate"] = True
                    extra["a_ip_pool"], extra["b_ip_pool"] = ap, bp
                    extra["rotate_secs"] = max(0, min(86400, int(d.get("rotate_secs") or 0)))
                    extra["auto_burn"] = bool(d.get("auto_burn"))
        elif L.get("ip_rotate"):   # partial edit — carry the stored rotation config forward unchanged
            for _k in _ROTATION_KEYS:
                if L.get(_k) is not None:
                    extra[_k] = L[_k]
        server_side = d.get("server_side") if d.get("server_side") in ("a", "b") else (L.get("server_side") or "a")
    # Compare against the effective stored port: a record created before the
    # settable-port feature has no "port" key, so fall back to the type's default
    # (4789 for vxlan, 20000+id otherwise). Without this a no-op edit of a legacy
    # link reads as changed and forces a needless rebuild (a brief outage).
    _defport = 4789 if ttype == "vxlan" else (20000 + tid)
    port_same = ("port" not in extra) or (extra["port"] == (L.get("port") or _defport))
    # Non-core links may short-circuit an unchanged edit (avoids a needless outage). Core links must
    # NOT: the button is "save AND rebuild", and a core edit always does a clean both-ends-down rebuild
    # below (the only reliable way to un-wedge a tunnel), so never silently no-op it — which is exactly
    # why the guard leads with `ttype != "core"` and no per-field core comparison is needed here.
    if ttype != "core" and ttype == L["type"] and subnet == L["subnet"] and a_ip == L["a_ip"] and b_ip == L["b_ip"] and port_same:
        return {"ok": True, "unchanged": True, "name": old_name}
    # Port-conflict guard: only verify bindings that DIFFER from what this tunnel already
    # occupies (its current port/proto/server node are excluded so it can't clash with
    # itself). A binding that is unchanged needs no check; a new/changed one must be free.
    # A pooled server now binds each SELECTED pool IP explicitly (Task B), so _own expands to that exact
    # per-IP set — a rebuild that keeps the same pool finds every new binding already in _own and skips
    # it, with no IP-agnostic hack needed (the old 0.0.0.0 monopoly is gone). A newly ADDED pool IP is
    # not in _own, so it is genuinely checked; a CHANGED port is a different binding and is checked too.
    _own = frozenset((N["id"], ip or "", p, pr) for N, ip, p, pr in
                     _port_bindings(L.get("type"), L.get("port"), L.get("transport"), L.get("server_side"), tid, A, B, L.get("a_ip"), L.get("b_ip"), L.get("a_ip_pool"), L.get("b_ip_pool")))
    # Same precise same-server-IP core conflict as create, but skip THIS tunnel (an edit that keeps its
    # own binding must not clash with itself).
    if ttype == "core":
        _clash = _core_l4_conflict(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")), exclude_id=L.get("id"))
        if _clash:
            raise ValueError(f"تونلِ core «{_clash.get('name')}» از قبل روی همین آی‌پی و پورتِ سرور هست؛ پورت یا حاملِ متفاوت انتخاب کن")
    _guard_port_conflicts(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")), exclude=_own)
    # Pre-delete BOTH ends before rebuilding when the iface name changed (shared veth/OVS ids) OR for
    # any core link. Core needs it because an in-place, one-end-at-a-time restart leaves the peer running
    # its old crypto session: the freshly restarted server latches onto the stale still-live client and
    # never re-handshakes, so the tunnel stays wedged. Tearing both ends down together (exactly what the
    # standalone rebuild does) forces a clean simultaneous re-handshake. This is why "save & rebuild" used
    # to leave a core tunnel dead while a separate "rebuild" fixed it.
    if name_changed or ttype == "core":
        node_call(A, "delete", "POST", {"name": old_name})
        node_call(B, "delete", "POST", {"name": old_name})
    node_extra = _node_extra(extra)
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": new_name, "enabled": L.get("enabled", True), **node_extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": new_name, "enabled": L.get("enabled", True), **node_extra}
    if ttype == "core":
        a_body["role"] = "server" if server_side == "a" else "client"
        b_body["role"] = "server" if server_side == "b" else "client"
        _core_rotation_bodies(extra, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
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
                for k in ("port", "psk", "cipher", "transport", "obfs", "cover", "cover_sni", "raw_profile", "flux_carrier", "flux_rotate_secs", "flux_shape", "flux_epoch_offset", "fec", "fec_data", "fec_parity", "ws_host", "ws_path", "ws_tls", "sni_split", "split_pos", "sni_mode", "split_ttl", "ws_xhttp", "ws_xhttp_mode", "ech", "ws_ech", "edge_ip", "ws_pool", "ws_edge_ips", "ws_edge_ips_burned", "ws_edge_snis", "ws_edge_snis_burned", "ws_rotate_secs", "ws_auto_burn", "ws_warm_standby", "gso", "spoof_src", "spoof_dst", "fake_desync", "fake_ttl", "fake_count", "fake_mode", "dead_after_secs") + _ROTATION_KEYS:   # keep only the extras this type uses (incl. IP-rotation); drop the rest so an edit that turns rotation off actually clears the stored pools
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
    extra = _tunnel_extra(L)   # same UDP port / key / cipher as before; also re-fetches fresh ECH and
                               # MAY RAISE — do it BEFORE teardown so a fetch failure leaves the tunnel intact
    node_call(A, "delete", "POST", {"name": name})  # tear down both ends first
    node_call(B, "delete", "POST", {"name": name})
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name, "enabled": L.get("enabled", True), **extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name, "enabled": L.get("enabled", True), **extra}
    if ttype == "core":   # role is per-node, replayed from the stored server_side
        a_body["role"], b_body["role"] = _core_role(L, A["id"]), _core_role(L, B["id"])
        _core_rotation_bodies(L, a_body, b_body)   # replay the stored IP-rotation pools
        _apply_core_tuning(a_body, b_body)         # re-stamp current fleet-wide timing on rebuild
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        _restore_link(A, B, L, extra)   # reuse the extra already fetched above — no second ECH fetch, no raise
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')} (تلاش برای بازگردانی)")
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        _restore_link(A, B, L, extra)
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


# --------------------------------------------------------------------------- automatic ECH refresh
# A CDN (Cloudflare) rotates its ECH key roughly hourly; a stale stored ECHConfigList then fails the
# ws-upgrade on EVERY edge and the tunnel goes dark (only a manual rebuild recovered it). The client
# core and the in-country node sit behind poisoned DNS, so ONLY the panel can re-resolve the key.
# This background loop re-fetches ECH for every ECH-enabled core link and:
#   - key present, tunnel healthy  -> freshen the stored record silently (the live core self-heals
#     in-band via retry_configs; the fresh stored key just keeps restarts/rebuilds valid) — no drop.
#   - pool DOWN (core reachable, no active edge) -> rebuild with the fresh key. LEVEL-triggered on the
#     down STATE, not edge-triggered on the key change: a stale-ECH pool stays down across many cycles
#     but the key only *changes* once, so gating the rebuild on the change let a down tunnel sit dark
#     forever (the record was freshened on cycle 1, then _ech_write returned False and the down-check
#     was never reached again — the exact 1.5h stall). Rebuild once per down-episode (and again if the
#     key rotates mid-episode); reset when the pool recovers.
#   - record REMOVED (confirmed by _ECH_EMPTY_CYCLES consecutive empty fetches, so a transient DoH
#     blip can't strip a good key) -> degrade the link to plain wss so it can't hard-fail, + rebuild.
_ECH_EMPTY_CYCLES = 3   # consecutive empty fetches before an ECH record counts as truly REMOVED (blip guard)
_ech_empty = {}         # (link_id, host) -> consecutive-empty count
_ech_empty_lock = threading.Lock()
_ech_down_rebuilt = set()  # link_ids already rebuilt during their CURRENT down-episode (touched only by the single ech_refresh_loop thread)


def _ech_link_hosts(L):
    """(kind, hosts) for an ECH-carrying core link, else None. Single edge carries one ws_host; a pool
    carries one ech per ws_edge_snis entry."""
    if L.get("type") != "core" or not L.get("ech") or not L.get("enabled", True):
        return None
    if L.get("ws_pool") and L.get("ws_edge_snis"):
        hosts = [s.get("host") for s in L["ws_edge_snis"] if isinstance(s, dict) and s.get("host")]
        return ("pool", hosts) if hosts else None
    if L.get("ws_host"):
        return ("single", [L.get("ws_host")])
    return None


def _link_is_down(lid):
    """True only when the client core is REACHABLE but not carrying data (active edge empty) — the
    'ECH rotation broke the live tunnel' signal. A merely-offline node returns an error and is treated
    as not-actionable (a rebuild can't help it)."""
    try:
        st = api_edge_status({"id": lid})
    except Exception:
        return False
    return bool(st.get("ok")) and not st.get("error") and not str(st.get("active") or "")


def _ech_write(lid, kind, updates, degrade):
    """Under the registry lock, apply refreshed per-host ECH (updates: host->new_key) or, on a
    confirmed removal, turn ECH off. Returns (changed, chmap): changed is True if the stored record
    actually changed; chmap maps each host whose key rotated to its new base64 key (empty on degrade)."""
    changed = False
    chmap = {}
    with _reg_lock:
        links = load_links()
        for x in links:
            if x.get("id") != lid:
                continue
            if degrade:
                if x.get("ech"):
                    x["ech"] = False          # confirmed removed -> plain wss so a rebuild can't hard-fail on a missing key
                    x.pop("ws_ech", None)
                    changed = True
                for s in (x.get("ws_edge_snis") or []):
                    if isinstance(s, dict) and s.get("ech"):
                        s["ech"] = ""
                        changed = True
            elif kind == "single":
                nk = updates.get(x.get("ws_host"), "")
                if nk and nk != x.get("ws_ech", ""):
                    x["ws_ech"] = nk
                    chmap[x.get("ws_host")] = nk
                    changed = True
            else:
                for s in (x.get("ws_edge_snis") or []):
                    if not isinstance(s, dict):
                        continue
                    nk = updates.get(s.get("host"), "")
                    if nk and nk != s.get("ech", ""):
                        s["ech"] = nk
                        chmap[s.get("host")] = nk
                        changed = True
            break
        if changed:
            save_json(LINKS_FILE, links)
    return changed, chmap


def _ech_safe_rebuild(lid):
    """Rebuild the link (re-fetches ECH itself; applies the fresh/now-off key to both ends). Returns True
    on success, False on ANY failure — never raises, so the caller can log the ACTUAL outcome instead of
    an optimistic guess (a failed rebuild leaves the tunnel down and must not read as success)."""
    try:
        api_rebuild_link({"id": lid})
        return True
    except Exception:
        return False


def _ech_refresh_once():
    try:
        _mins_label = "%g" % float(get_settings().get("ech_refresh_mins", 15) or 15)   # the interval, for the log tag
    except Exception:
        _mins_label = "15"
    for L in load_links():
        hk = _ech_link_hosts(L)
        if not hk:
            continue
        kind, hosts = hk
        lid, nm = L.get("id"), L.get("name")
        ech_map = _fetch_ech_map(hosts)   # concurrent DNS fetch — NO lock held here
        updates, empty_flags = {}, []
        for h in hosts:
            nk = ech_map.get(h, "")
            key = (lid, h)
            if nk:
                with _ech_empty_lock:
                    _ech_empty.pop(key, None)
                updates[h] = nk
            else:
                with _ech_empty_lock:
                    _ech_empty[key] = _ech_empty.get(key, 0) + 1
                    empty_flags.append(_ech_empty[key] >= _ECH_EMPTY_CYCLES)
        removed = bool(hosts) and len(empty_flags) == len(hosts) and all(empty_flags)  # every host gone, persistently
        if removed:
            if _ech_write(lid, kind, {}, degrade=True)[0]:
                if _ech_safe_rebuild(lid):   # log the ACTUAL outcome, not an optimistic guess
                    log_event("warn", "ech", f"رکوردِ ECHِ تونلِ «{nm}» حذف شد؛ به wss ساده تنزل یافت و بازسازی شد",
                              f"Tunnel “{nm}” ECH record vanished; degraded to plain wss and rebuilt")
                else:
                    log_event("bad", "ech", f"رکوردِ ECHِ تونلِ «{nm}» حذف شد؛ تنزل به wss ساده شد ولی بازسازی شکست خورد — هنوز قطع",
                              f"Tunnel “{nm}” ECH record vanished; degraded to plain wss but the rebuild FAILED — still down")
            continue
        changed, chmap = _ech_write(lid, kind, updates, degrade=False)   # freshen the stored key (keeps restarts/rebuilds valid)
        if changed and chmap:
            # Two boxes per host (like the reactive event): the domain and its fresh base64 ECHConfigList.
            dfa = "\n".join("دامنه: %s\nکلیدِ ECH: %s" % (h, k) for h, k in chmap.items())
            den = "\n".join("host: %s\nECH key: %s" % (h, k) for h, k in chmap.items())
            log_event("ok", "ech",
                      "کلیدِ ECHِ تونلِ «%s» با تایمرِ زمان‌بندی‌شده تازه شد (هر %s دقیقه)" % (nm, _mins_label),
                      "Tunnel “%s” ECH key refreshed by the scheduled timer (every %s min)" % (nm, _mins_label),
                      dfa, den)
        # Down-detection needs a live status file, which only a pool writes; a single edge is left to
        # Layer 1 (the core's in-band retry) + the freshened stored key. For a pool, rebuild one we can
        # SEE is down — LEVEL-triggered on the down state, NOT gated on the key changing THIS cycle (that
        # gating is what let a persistently-down pool sit dark: the record is freshened once, then never
        # changes again). Rebuild once per down-episode, and again if the key rotates while still down;
        # reset the episode when the pool recovers.
        if kind == "pool" and _link_is_down(lid):
            if lid not in _ech_down_rebuilt or changed:   # the live core didn't self-heal in-band -> rebuild with the fresh key
                _ech_down_rebuilt.add(lid)
                if _ech_safe_rebuild(lid):   # log the ACTUAL outcome; a failed rebuild must not read as success
                    log_event("ok", "ech", f"تونلِ «{nm}» قطع بود و کلیدِ ECH چرخیده بود؛ با کلیدِ تازه بازسازی شد",
                              f"Tunnel “{nm}” was down with a rotated ECH key; rebuilt with the fresh key")
                else:
                    log_event("bad", "ech", f"تونلِ «{nm}» قطع است و بازسازی با کلیدِ تازهٔ ECH شکست خورد — هنوز قطع",
                              f"Tunnel “{nm}” is down and the ECH rebuild FAILED — still down")
                    _ech_down_rebuilt.discard(lid)   # let the NEXT cycle retry (don't burn the episode on a failed rebuild)
        else:
            _ech_down_rebuilt.discard(lid)   # healthy pool / single edge / not down -> clear the episode (a future drop rebuilds again)


def ech_refresh_loop():
    while True:
        try:
            mins = float(get_settings().get("ech_refresh_mins", 15) or 0)
        except Exception:
            mins = 15.0
        time.sleep(60.0 if mins <= 0 else max(60.0, mins * 60.0))  # min 1 real minute; re-check the knob when off
        if mins <= 0:
            continue   # disabled from Settings — keep re-reading the knob every minute
        try:
            _ech_refresh_once()
        except Exception:
            pass


# --------------------------------------------------------------------------- system event log
# A rolling, persisted record of things the SYSTEM did on its own — node up/down, tunnel up/down
# (with a best-effort reason), and AUTOMATIC edge-IP changes — i.e. the events an operator would
# otherwise never see. Operator-driven actions (create/edit/delete, manual pin/rotate, toggling a
# tunnel off) are deliberately NOT logged: the detector only records STATE TRANSITIONS it observes,
# newly-added/removed entities are seeded silently, disabled tunnels are skipped, and a manual pin
# suppresses the edge-change it causes. Each event stores both fa+en text so it renders in either UI
# language regardless of when it was recorded.
EVENTS_FILE = os.path.join(CENTRAL_DIR, "events.json")
EVENTS_SEQ_FILE = os.path.join(CENTRAL_DIR, "events.seq")  # monotonic total-ever counter (survives the 500-cap)
EVENTS_CAP = 500
_events_lock = threading.Lock()
_ev_seq_total = None  # lazy-loaded; the sidebar 'logs' badge = this minus what the client last saw
_ev_state = {"init": False, "nodes": {}, "links": {}, "edge": {}, "evseq": {}, "links_coarse_down": set()}  # last-seen state (in-memory)
_ev_suppress = {}  # link_id -> unix ts until which an edge auto-change is suppressed (operator pin)

# Map the CORE's stable reason codes (it saw the real error) to bilingual text for the log. This is
# the precise, core-level "why" the operator asked for — not the panel's coarse guess.
_EV_DOWN_CODE = {
    "ping_timeout": ("بی‌پاسخ ماند (keepalive) — گلوگاه/بلاک‌هول یا سرِ مقابل خاموش", "no keepalive response — throttled/blackholed or peer down"),
    "reset": ("اتصال ریست شد (RST — احتمالاً کشتنِ DPI)", "connection reset (RST — likely DPI)"),
    "refused": ("اتصال رد شد (connection refused)", "connection refused"),
    "timeout": ("مهلتِ اتصال تمام شد / بی‌مسیر", "timeout / unreachable"),
    "eof": ("اتصال بسته شد (EOF)", "connection closed (EOF)"),
    "tls": ("دستِ TLS شکست خورد (احتمالاً SNI بلاک شده)", "TLS handshake failed (SNI blocked?)"),
    "ws_upgrade": ("ارتقاءِ WebSocket رد شد (Origin/CDN)", "WebSocket upgrade refused (origin/CDN)"),
    "closed": ("اتصال قطع شد", "connection dropped"),
    "dropped": ("اتصال قطع شد", "connection dropped"),
    # datagram transports (udp/raw/flux) — connectionless self-heal reasons
    "stale": ("سشن کهنه شد (سرِ مقابل خاموش/ری‌استارت؟) — در حالِ دست‌دادنِ مجدد", "session went stale (peer down/restarted?) — re-handshaking"),
    "keepalive": ("keepalive بی‌پاسخ ماند — گلوگاه/بلاک‌هول یا سرِ مقابل خاموش", "no keepalive — throttled/blackholed or peer down"),
    "handshake": ("دست‌دادن شکست خورد (سرِ مقابل نبود/فیلتر شد)", "handshake failed (peer down/filtered)"),
}
_EV_UP_CODE = {
    "reconnect": ("پس از افتِ سشن، خودکار وصل شد (self-heal)", "auto-recovered after a session drop (self-heal)"),
    "connect": ("تونل وصل شد", "tunnel connected"),
}
_EV_BURN_CODE = {
    "ip_blocked": ("آی‌پیِ لبه بلاک است (روی SNIِ سالم هم جواب نداد)", "edge IP blocked (failed even with a healthy SNI)"),
    "sni_blocked": ("دامنه (SNI) بلاک است (روی آی‌پیِ سالم هم جواب نداد)", "SNI blocked (failed even on a healthy IP)"),
    "throttle": ("آی‌پیِ لبه گلوگاه/کند شد (دست داد ولی دیتا مرد)", "edge IP throttled (handshake OK but data died)"),
}
# Intentional IP MOVES on a datagram rotation pool (udp/raw/flux — tcp is connection-oriented and re-dials
# instead of emitting these). The core reports these as a
# "down" because they cause a brief re-handshake, but they are NOT faults — a proactive/failover rotation
# or an operator pin. Render them as informational (ok) events, not a red "disconnected". (level, fa, en)
_EV_ROT_CODE = {
    "peer-rotate": ("ok", "آی‌پیِ مقصد را چرخاند (self-heal/زمان‌بندی‌شده)", "rotated the destination IP"),
    "src-rotate":  ("ok", "آی‌پیِ مبدأ را چرخاند", "rotated the source IP"),
    "peer-pin":    ("ok", "روی آی‌پیِ مقصدِ پین‌شده رفت", "moved to the pinned destination IP"),
    "src-pin":     ("ok", "روی آی‌پیِ مبدأِ پین‌شده رفت", "moved to the pinned source IP"),
}


def _ev_core_text(kind, code, detail, nm):
    """Render a core event into (level, kind, title_fa, title_en, detail_fa, detail_en) for
    log_event(*...). Splitting title from detail lets the UI show the reason on its own line."""
    key = str(detail or "")
    if key.startswith("ip:"):
        key = key[3:]
    elif key.startswith("sni:"):
        key = key[4:]
    if kind == "down":
        rot = _EV_ROT_CODE.get(code)
        if rot:   # an intentional rotation/pin, not a fault — informational, not a red "disconnected"
            lvl, fa, en = rot
            return (lvl, "rot", f"تونلِ «{nm}»: {fa}", f"Tunnel “{nm}”: {en}", "", "")
        rf, re_ = _EV_DOWN_CODE.get(code, ("اتصال قطع شد", "connection dropped"))
        return ("bad", "link", f"تونلِ «{nm}» قطع شد", f"Tunnel “{nm}” disconnected", rf, re_)
    if kind == "up":
        rf, re_ = _EV_UP_CODE.get(code, ("تونل وصل شد", "tunnel connected"))
        return ("ok", "link", f"تونلِ «{nm}» دوباره وصل شد", f"Tunnel “{nm}” reconnected", rf, re_)
    if kind == "burn":
        rf, re_ = _EV_BURN_CODE.get(code, ("سوخته شد", "sidelined"))
        return ("warn", "edge", f"لبهٔ «{key}» تونلِ «{nm}» سوخت", f"Edge “{key}” of “{nm}” burned", rf, re_)
    if kind == "heal":
        # A previously-sidelined member recovered and is back in the rotation pool. Three flavors:
        # peer-retest/src-retest are the DIRECT-transport pool's destination/source IP recovering on the
        # data plane; the default (ws edge pool) is a background probe recovery. Distinct from the
        # active-carrier up/reconnect above.
        if code == "peer-retest":
            return ("ok", "edge", f"آی‌پیِ مقصدِ «{key}» تونلِ «{nm}» دوباره سالم شد و به استخر برگشت",
                    f"Destination IP “{key}” of “{nm}” is healthy again — back in the pool",
                    "داده روی این آی‌پی دوباره برقرار شد", "data flowing again on this IP")
        if code == "src-retest":
            return ("ok", "edge", f"آی‌پیِ مبدأِ «{key}» تونلِ «{nm}» دوباره سالم شد و به استخر برگشت",
                    f"Source IP “{key}” of “{nm}” is healthy again — back in the pool",
                    "داده روی این آی‌پی دوباره برقرار شد", "data flowing again on this IP")
        return ("ok", "edge", f"لبهٔ «{key}» تونلِ «{nm}» با retest ترمیم شد و به استخر برگشت",
                f"Edge “{key}” of “{nm}” recovered via retest — back in the pool",
                "بازآزماییِ پس‌زمینه موفق شد", "background retest succeeded")
    if kind == "ech":
        # REACTIVE in-band self-heal reported by the core (Layer 1): the live handshake hit a stale ECH
        # key and healed inline. Tagged distinctly from the panel's SCHEDULED ech_refresh timer (below),
        # so the operator can tell the two apart. detail is "<host> <fresh base64 ECHConfigList>" — split
        # it so the (long) key lands in its OWN labeled box instead of being dumped inline in the message.
        host, _, k = key.partition(" ")
        dfa = ("دامنه: %s\n" % host if host else "") + ("کلیدِ تازهٔ ECH: %s" % k if k else "")
        den = ("host: %s\n" % host if host else "") + ("fresh ECH key: %s" % k if k else "")
        return ("ok", "ech", f"کلیدِ ECHِ تونلِ «{nm}» درجا self-heal شد (واکنشی/in-band)",
                f"Tunnel “{nm}” ECH self-healed in-band (reactive)", dfa, den)
    return None


def load_events():
    try:
        with open(EVENTS_FILE) as f:
            evs = json.load(f)
        return evs if isinstance(evs, list) else []
    except (OSError, ValueError):
        return []


def _ev_seq_get():
    """Monotonic count of ALL events ever logged. Unlike len(events) it keeps growing past the
    500-cap, so the sidebar 'logs' unread badge (this minus the client's last-seen value) stays
    correct forever. Seeds from the current file size on first use after this feature shipped."""
    global _ev_seq_total
    if _ev_seq_total is None:
        try:
            with open(EVENTS_SEQ_FILE) as f:
                _ev_seq_total = int(json.load(f))
        except (OSError, ValueError, TypeError):
            _ev_seq_total = len(load_events())
    return _ev_seq_total


def log_event(level, kind, fa, en, dfa="", den=""):
    """Append one system event (newest first), capped at EVENTS_CAP. level: ok|warn|bad.
    fa/en are the one-line TITLE; dfa/den are an optional detail/reason that may contain "\\n" for
    multiple lines (e.g. an edge switch's from/to) — the UI renders each line separately."""
    global _ev_seq_total
    with _events_lock:
        evs = load_events()
        evs.insert(0, {"ts": int(time.time()), "level": level, "kind": kind,
                       "fa": fa, "en": en, "dfa": dfa, "den": den})
        if len(evs) > EVENTS_CAP:
            evs = evs[:EVENTS_CAP]
        try:
            save_json(EVENTS_FILE, evs)
        except OSError:
            pass
        _ev_seq_total = _ev_seq_get() + 1  # bump the monotonic counter for the unread badge
        try:
            save_json(EVENTS_SEQ_FILE, _ev_seq_total)
        except OSError:
            pass


def _node_online(nid):
    return bool(_cached_ping(nid).get("ok"))


def _link_up(L):
    ah, _a = _link_side_health(L, "a_node")
    bh, _b = _link_side_health(L, "b_node")
    return isinstance(ah, dict) and ah.get("up") and isinstance(bh, dict) and bh.get("up")


def _link_down_reason(L, nmap):
    """Best-effort classification of WHY a tunnel went down, from signals the panel already has."""
    for key in ("a_node", "b_node"):
        nid = L.get(key)
        if _cache_get(nid) and not _node_online(nid):
            nm = nmap.get(nid, nid)
            return (f"نودِ «{nm}» آفلاین است", f"node “{nm}” is offline")
    if link_drift(L["id"]):
        return ("IP عوض شده — نیازمندِ بازسازی", "IP changed — needs rebuild")
    if L.get("type") == "core" and L.get("ws_pool"):
        try:
            r = api_edge_status({"id": L["id"]})
            h = (r or {}).get("health") or []
            if r and r.get("pool") and h and not any(e.get("state") == "healthy" for e in h):
                return ("همهٔ لبه‌های استخر بلاک/سوخته‌اند", "all pool edges are blocked/burned")
        except Exception:
            pass
    return ("قابلِ دسترسی نیست (کریر/سرِ مقابل)", "unreachable (carrier/peer)")


def _events_once():
    nodes = load_nodes()
    links = load_links()
    nmap = {n["id"]: n.get("name", "") for n in nodes}
    first = not _ev_state["init"]

    # --- nodes: online <-> offline (only for nodes actually probed at least once) ---
    seen = set()
    for n in nodes:
        nid = n["id"]
        seen.add(nid)
        if not _cache_get(nid):
            continue
        online = _node_online(nid)
        prev = _ev_state["nodes"].get(nid)
        _ev_state["nodes"][nid] = online
        if first or prev is None or prev == online:
            continue
        nm = n.get("name", "")
        if online:
            log_event("ok", "node", f"نودِ «{nm}» آنلاین شد", f"Node “{nm}” came online")
        else:
            log_event("bad", "node", f"نودِ «{nm}» آفلاین شد", f"Node “{nm}” went offline")
    for nid in [k for k in _ev_state["nodes"] if k not in seen]:
        _ev_state["nodes"].pop(nid, None)

    # --- tunnels: up <-> down (skip operator-disabled ones; reason on the down edge) ---
    seen = set()
    for L in links:
        lid = L["id"]
        seen.add(lid)
        if not L.get("enabled", True):
            _ev_state["links"].pop(lid, None)  # operator turned it off -> not a system event
            _ev_state["links_coarse_down"].discard(lid)  # clear paired state too (lid stays in `seen`, so the tail cleanup skips it)
            continue
        # need both ends reachable to judge "up"; if a node isn't probed yet, hold state as-is
        a_probed = _cache_get(L.get("a_node")) is not None
        b_probed = _cache_get(L.get("b_node")) is not None
        if not (a_probed and b_probed):
            continue
        up = bool(_link_up(L))
        prev = _ev_state["links"].get(lid)
        _ev_state["links"][lid] = up
        if first or prev is None or prev == up:
            continue
        nm = L.get("name", "")
        pool_core = L.get("type") == "core" and L.get("ws_pool")
        if up:
            # A ws-pool core records its own precise reconnect ("up") in the event ring, so don't
            # ALSO emit a coarse one — UNLESS this link's down was itself coarse (a client node was
            # offline, so the core was dead and logged nothing); then pair it coarsely too.
            if pool_core and lid not in _ev_state["links_coarse_down"]:
                pass  # the paired "up" comes from the core event ring
            else:
                log_event("ok", "link", f"تونلِ «{nm}» وصل شد", f"Tunnel “{nm}” connected")
            _ev_state["links_coarse_down"].discard(lid)
        else:
            # A ws-pool tunnel's core records the PRECISE down reason itself (see the edge section) —
            # don't also emit a coarse one here, unless a client node is offline (the core is dead
            # then and can't report). Non-pool tunnels always use the coarse classification.
            a_off = _cache_get(L.get("a_node")) and not _node_online(L.get("a_node"))
            b_off = _cache_get(L.get("b_node")) and not _node_online(L.get("b_node"))
            if pool_core and not (a_off or b_off):
                pass  # core-sourced precise "down" (and its paired "up") come from the event ring
            else:
                rf, re_ = _link_down_reason(L, nmap)
                log_event("bad", "link", f"تونلِ «{nm}» قطع شد", f"Tunnel “{nm}” disconnected", rf, re_)
                if pool_core:
                    _ev_state["links_coarse_down"].add(lid)  # coarse (node-offline) down -> pair with a coarse up
    for lid in [k for k in _ev_state["links"] if k not in seen]:
        _ev_state["links"].pop(lid, None)
        _ev_state["links_coarse_down"].discard(lid)

    # --- core tunnels: PRECISE core-recorded events (down reason + burns for a ws pool;
    #     self-heal/reconnect reasons for a udp/raw/flux datagram client; in-band ECH self-heal for a
    #     single-edge ws/xhttp client) and — for a pool — the automatic edge-IP change. The core saw
    #     the real error; the panel just renders it. Any core with a status file qualifies: a pool, a
    #     datagram transport, or a single-edge ws/xhttp. Only plain tcp cores write no status file. ---
    seen = set()
    now = int(time.time())
    for L in links:
        if L.get("type") != "core" or not L.get("enabled", True):
            continue
        is_pool = bool(L.get("ws_pool"))
        tr = str(L.get("transport") or "").lower()
        if not is_pool and tr not in ("udp", "raw", "flux", "ws"):
            continue  # no core status file -> nothing precise to read (single-edge ws writes one; plain tcp doesn't)
        lid = L["id"]
        seen.add(lid)
        nm = L.get("name", "")
        try:
            r = api_edge_status({"id": lid})
        except Exception:
            r = None
        if not r:
            continue

        # core event ring (down/up/burn) — consume each exactly once by seq; seed silently on first pass
        evs = r.get("events") or []
        mx = max([0] + [int(e.get("seq") or 0) for e in evs])
        if first:
            _ev_state["evseq"][lid] = mx
        else:
            last = _ev_state["evseq"].get(lid, 0)
            for e in sorted(evs, key=lambda x: int(x.get("seq") or 0)):
                if int(e.get("seq") or 0) <= last:
                    continue
                txt = _ev_core_text(str(e.get("kind") or ""), str(e.get("code") or ""), str(e.get("detail") or ""), nm)
                if txt:
                    log_event(*txt)
            _ev_state["evseq"][lid] = max(last, mx)

        if not is_pool:
            continue  # datagram: event ring only — no active-edge concept to diff

        # automatic active-edge switch (suppressed briefly after an operator pin)
        active = str(r.get("active") or "")
        prev = _ev_state["edge"].get(lid)
        _ev_state["edge"][lid] = active
        if first or prev is None or prev == active or not active:
            continue
        if _ev_suppress.get(lid, 0) > now:  # operator pinned this edge -> not a system event
            continue
        log_event("warn", "edge", f"لبهٔ تونلِ «{nm}» خودکار عوض شد", f"Tunnel “{nm}” edge auto-switched",
                  f"از: {prev}\nبه: {active}", f"from: {prev}\nto: {active}")
    for lid in [k for k in _ev_state["edge"] if k not in seen]:
        _ev_state["edge"].pop(lid, None)
    for lid in [k for k in _ev_state["evseq"] if k not in seen]:
        _ev_state["evseq"].pop(lid, None)

    _ev_state["init"] = True


def events_loop():
    while True:
        time.sleep(15)
        try:
            _events_once()
        except Exception:
            pass


def api_events(d):
    d = d or {}
    lim = max(1, min(EVENTS_CAP, _sint((d or {}).get("limit")) or 200))
    return {"ok": True, "events": load_events()[:lim]}


def api_events_clear(d):
    with _events_lock:
        try:
            save_json(EVENTS_FILE, [])
        except OSError:
            pass
    return {"ok": True}


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
        # The forms send this as a comma/space-separated STRING ("10.0.0.1, 10.0.0.2"); a rebuild/API
        # caller may send a real list. Split a string so multi-target (rotating) port-forward validates
        # instead of failing with the whole string treated as one bogus IP.
        raw = v if isinstance(v, list) else re.split(r"[\s,]+", str(v))
        ips = [str(x).strip() for x in raw if str(x).strip()]
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


def _pf_name(v):
    """Validate a port-forward / chain identifier before it reaches the node's iptables/ip handlers,
    the delete path, or the traffic-store key. The name is a raw identifier central never generated
    itself (the caller supplies it on edit/next/del/reset), so — like every sibling portfw field — it
    must be constrained instead of relayed as-is. Same safe charset as node NAME/iface (letters, digits
    and «._-», 1..40 chars). Defense-in-depth so central never becomes the conduit for an unvalidated
    identifier; raises a clear Persian ValueError on anything malformed; returns the stripped name."""
    s = str(v).strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,40}$", s):
        raise ValueError("نامِ پورت‌فوروارد نامعتبر است — فقط حروف/عدد و «._-» (۱ تا ۴۰ کاراکتر) مجاز است")
    return s


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
    body = {"name": _pf_name(d["name"])}
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
    r = node_call(n, "portfw-next", "POST", {"name": _pf_name(d["name"])}, timeout=60)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    _refresh_cache([n["id"]])
    return {"ok": True, "active": r.get("active")}


def api_portfw_del(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    name = _pf_name(d["name"])
    r = node_call(n, "delete", "POST", {"name": name})
    if r.get("ok"):
        _tf_forget(n["id"], ["pf:" + name])   # drop stale totals so a reused portfw id starts fresh
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
    with _settings_lock:   # atomic read-modify-write (RLock so validate_settings' get_settings re-enters);
        obj = validate_settings(d or {})   # a concurrent set can't now merge onto a stale snapshot and clobber
        _settings.clear()
        _settings.update(obj)
        save_json(SETTINGS_FILE, obj)   # write under the lock — concurrent settings-set share one .tmp path and would corrupt it
    return {"ok": True, "settings": obj}


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
    "node-test": api_node_test, "node-stats": api_node_stats,
    "node-ips": api_node_ips, "link-rebuild-info": api_link_rebuild_info,
    "traffic": api_node_traffic, "fleet": api_fleet,
    "create-tunnel": api_create_tunnel, "edit-link": api_edit_link, "check-link": api_check_link,
    "rebuild-link": api_rebuild_link, "delete-link": api_delete_link, "link-toggle": api_link_toggle,
    "flux-rotate": api_flux_rotate, "edge-status": api_edge_status,
    "pool-probe-now": api_pool_probe_now, "pool-select": api_pool_select,
    "peer-status": api_peer_status, "peer-probe-now": api_peer_probe_now, "peer-select": api_peer_select,
    "link-view": api_link_view, "traffic-reset": api_traffic_reset,
    "events": api_events, "events-clear": api_events_clear,
    "portfw": api_portfw, "portfw-list": api_portfw_list, "portfw-edit": api_portfw_edit,
    "portfw-next": api_portfw_next, "portfw-del": api_portfw_del,
    "agent-upload": api_agent_upload, "agent-info": api_agent_info, "agent-push": api_agent_push,
    "agent-fetch-git": api_agent_fetch_git,
    "core-versions": api_core_versions, "core-update": api_core_update,
    "core-upload": api_core_upload, "core-stage": api_core_stage, "core-push": api_core_push,
}
MUTATIONS = {"node-add", "node-install", "node-edit", "node-del", "create-tunnel", "edit-link", "rebuild-link",
             "delete-link", "link-toggle", "flux-rotate", "edge-status", "pool-probe-now", "pool-select",
             "peer-status", "peer-probe-now", "peer-select",
             "link-view", "traffic-reset", "events-clear", "portfw", "portfw-edit", "portfw-next", "portfw-del",
             "agent-upload", "agent-push", "agent-fetch-git", "settings-set", "core-update", "core-upload", "core-stage", "core-push"}

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
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;-webkit-text-size-adjust:100%;text-size-adjust:100%}
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
<h1><span class="chip"><svg viewBox="0 0 24 24"><path d="M12 3l8 3v6c0 5-4 8-8 9-4-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg></span> <span><b>tnl</b> <span id="lg_brand">کنترل فلیت</span></span></h1>
<p class="s" id="lg_sub">برای ورود، نام کاربری و رمز را وارد کنید</p>
<label id="lg_luser">نام کاربری</label><input id="u" autocomplete="username" autofocus>
<label id="lg_lpass">رمز عبور</label><input id="p" type="password" autocomplete="current-password">
<button id="lg_btn">ورود</button><div class="e" id="e"></div></form>
<script>
var L2={fa:{brand:"کنترل فلیت",sub:"برای ورود، نام کاربری و رمز را وارد کنید",user:"نام کاربری",pass:"رمز عبور",go:"ورود",fail:"ورود ناموفق",title:"ورود · tnl"},
 en:{brand:"Fleet control",sub:"Enter your username and password to sign in",user:"Username",pass:"Password",go:"Sign in",fail:"Login failed",title:"Sign in · tnl"}};
var LG='fa';try{var _l=localStorage.getItem('tnl_lang');if(_l=='en')LG='en'}catch(e){}
(function(){var d=L2[LG],dir=(LG=='fa')?'rtl':'ltr';document.documentElement.lang=LG;document.documentElement.dir=dir;
 function set(id,t){var e=document.getElementById(id);if(e)e.textContent=t}
 set('lg_brand',d.brand);set('lg_sub',d.sub);set('lg_luser',d.user);set('lg_lpass',d.pass);set('lg_btn',d.go);try{document.title=d.title}catch(e){}})();
async function login(ev){ev.preventDefault();var e=document.getElementById('e');e.textContent='';
 var r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:u.value,pass:p.value})});
 var j=await r.json().catch(()=>({}));if(r.ok)location.href='/';else e.textContent=j.error||L2[LG].fail;return false}
</script></body></html>"""

INDEX_HTML = """<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no"><title>tnl · کنترل فلیت</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;700;800&display=swap');
:root{--acc:#4d6bf0;--acc2:#12a5b8;--ok:#2f9e6f;--bad:#d1524a;--gold:#bd7f18;
--page:#eef1f6;--card:#ffffff;--side:#ffffff;--glass:#f1f4f8;--field:#f4f6fa;--bord:#e5e9f0;
--tx:#232b36;--sub:#727e8c;--chart1:#6d5cf0;--chart2:#12a5b8;--hi:transparent;--dsh:0 10px 26px -18px rgba(40,60,100,.2);
--accw:#eef1fe;--okw:#e8f6ef;--badw:#fbeceb;--warnw:#f7efe0;--goldw:color-mix(in srgb,var(--gold) 16%,transparent);--sh-sm:0 1px 2px rgba(20,30,50,.05);--sk-base:#d7dde8;--sk-hi:#f3f6fb}
body.dark{--acc:#6f8dff;--acc2:#3fd0e0;--ok:#4ec99a;--bad:#f0736a;--gold:#e0a83a;
--page:#0e1420;--card:#161f2e;--side:#111826;--glass:#1a2333;--field:#131c29;--bord:#243040;
--tx:#e6ecf4;--sub:#8b98aa;--chart1:#8f9dff;--chart2:#3fd0e0;--hi:transparent;--dsh:0 14px 34px -20px rgba(0,0,0,.6);
--accw:rgba(111,141,255,.14);--okw:rgba(78,201,154,.13);--badw:rgba(240,115,106,.13);--warnw:rgba(224,168,58,.12);--sh-sm:0 1px 2px rgba(0,0,0,.3);--sk-base:#1f2a3a;--sk-hi:#36465f}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;-webkit-text-size-adjust:100%;text-size-adjust:100%}
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
.navi .ctwrap{margin-inline-end:auto;display:flex;gap:4px;align-items:center;direction:ltr}  /* [total][unread] L->R, pinned to the far LEFT edge like other counts. NOTE: the wrap is direction:ltr, so in the RTL nav row the auto margin must sit on inline-END (=physical right=main-start) to push the cluster left — margin-inline-START:auto would (wrongly) shove it toward the label. */
.navi .ctwrap .ct{margin-inline-start:0}
.navi .ct.ctun{color:#fff;background:var(--acc);border-color:transparent;min-width:20px}  /* unread-logs badge: accent, distinct from the neutral total */
.navi.on .ct.ctun{color:#fff;background:var(--acc);border-color:transparent}
.live{margin-top:14px;padding:12px;border-radius:13px;background:var(--glass);border:1px solid var(--bord)}
.live .lr{display:flex;justify-content:space-between;align-items:center;font-size:11.5px;color:var(--sub)}
.live .lr b{color:var(--tx);font-size:13.5px}.live .lr b.ok{color:var(--ok)}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--ok) 55%,transparent)}70%{box-shadow:0 0 0 6px transparent}}
.main{flex:1;min-width:0;max-width:1120px;padding:22px 26px 64px}
.mtop{display:none;align-items:center;justify-content:space-between;gap:11px;padding:10px 14px;position:sticky;top:0;z-index:30;background:var(--side);border:1px solid var(--bord);border-radius:14px;box-shadow:var(--dsh)}
.mtop .sbrand{font-size:14px;padding:0;letter-spacing:.3px;direction:ltr}
.hb{width:38px;height:38px;border-radius:11px;border:1px solid var(--bord);background:transparent;color:var(--tx);display:grid;place-items:center;cursor:pointer;flex:0 0 auto}.hb .ic{width:20px;height:20px}
.backdrop{display:none;position:fixed;inset:0;background:rgba(15,22,35,.42);z-index:35}
.chip{width:32px;height:32px;border-radius:10px;display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;color:var(--hue,var(--acc));background:color-mix(in srgb,var(--hue,var(--acc)) 13%,transparent);border:1px solid color-mix(in srgb,var(--hue,var(--acc)) 26%,transparent)}
.chip svg,.ic svg{width:100%;height:100%;display:block}.chip .ic{width:16px;height:16px}
.ic{display:inline-flex;width:1.15em;height:1.15em;vertical-align:-3px;flex:0 0 auto;stroke:currentColor}
@media(max-width:840px){
 .side{position:fixed;top:0;width:250px;flex-basis:250px;transition:transform .25s}
 /* RTL (fa): drawer docks/opens from the RIGHT; LTR (en): from the LEFT */
 [dir="rtl"] .side{right:0;left:auto;transform:translateX(100%);box-shadow:-20px 0 50px -24px rgba(20,30,60,.4)}
 [dir="ltr"] .side{left:0;right:auto;transform:translateX(-100%);box-shadow:20px 0 50px -24px rgba(20,30,60,.4)}
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
.v{font-size:22px;font-weight:800}.stat .v{font-size:22px}
.sec{font-size:12.5px;font-weight:700;color:var(--sub);margin:20px 4px 9px;display:flex;align-items:center;gap:7px}
.sec::after{content:'';flex:1;height:1px;background:linear-gradient(to left,var(--bord),transparent)}
.chart{width:100%;height:auto;display:block}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;vertical-align:1px}
.seg{display:flex;align-items:center;gap:14px}.donut{flex:0 0 116px}
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
@media(prefers-reduced-motion:no-preference){#view>*{animation:rise .45s cubic-bezier(.22,.61,.36,1) both}}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
/* desktop: node/tunnel/portfw cards in two columns */
@media(min-width:900px){
 #nodeList,#linkList,#pfList{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:start}
 #nodeList{align-items:stretch}   /* node cards in a row match height so an offline node can't leave a ragged gap */
 #nodeList>.card,#linkList>.card,#pfList>.card{margin-bottom:0}
 #nodeList>.card.muted,#linkList>.card.muted,#pfList>.card.muted{grid-column:1/-1}
}
/* skeleton shimmer: a visible placeholder grey (--sk-base) with a clearly brighter sweep (--sk-hi),
   so it reads as a loading placeholder in BOTH themes (the old glass/field pair was near-invisible in light). */
.sk{display:block;background:linear-gradient(90deg,var(--sk-base) 0%,var(--sk-base) 38%,var(--sk-hi) 50%,var(--sk-base) 62%,var(--sk-base) 100%);background-color:var(--sk-base);background-size:220% 100%;border-radius:7px;animation:shim 1.25s ease-in-out infinite}
@keyframes shim{from{background-position:200% 0}to{background-position:-200% 0}}
@media (prefers-reduced-motion:reduce){.sk{animation:none}}
/* skeleton loading: shimmer bars laid out INSIDE the real card classes (skNodeCard/skAccCard/
   skPfCard/skAgRow), so each page's loading state is pixel-identical to its loaded card. */
@media(prefers-reduced-motion:reduce){.sk{animation:none}}
/* ===== system-log category filter: a SINGLE horizontal row that scrolls sideways (never wraps) ===== */
.logchips{display:flex;gap:8px;flex-wrap:nowrap;overflow-x:auto;overflow-y:hidden;margin:0 0 12px;padding:2px 1px 8px;-webkit-overflow-scrolling:touch;scrollbar-width:thin}
.logchips::-webkit-scrollbar{height:7px}
.logchips::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--sub) 40%,transparent);border-radius:99px}
.logchips::-webkit-scrollbar-track{background:transparent}
.fchip{flex:0 0 auto;font-size:12.5px;font-weight:600;color:var(--sub);background:var(--card);border:1px solid var(--bord);border-radius:999px;padding:6px 13px;cursor:pointer;display:flex;align-items:center;gap:7px;user-select:none;white-space:nowrap;transition:background .12s,color .12s,border-color .12s}
.fchip:hover{border-color:color-mix(in srgb,var(--acc) 45%,var(--bord))}
.fchip.on{color:#fff;background:var(--acc);border-color:var(--acc)}
.fchip .ct{font-size:10.5px;font-weight:800;background:color-mix(in srgb,var(--sub) 18%,transparent);border-radius:999px;padding:0 6px;min-width:17px;text-align:center}
.fchip.on .ct{background:rgba(255,255,255,.25);color:#fff}
.lcat{font-size:10px;font-weight:700;border-radius:999px;padding:1px 8px;flex:0 0 auto;white-space:nowrap;line-height:1.7}
.lcat-tunnel{color:#4d80f0;background:color-mix(in srgb,#4d80f0 15%,transparent)}
.lcat-rot{color:#12a5b8;background:color-mix(in srgb,#12a5b8 16%,transparent)}
.lcat-ech{color:#8a63f0;background:color-mix(in srgb,#8a63f0 16%,transparent)}
.lcat-node{color:var(--gold);background:color-mix(in srgb,var(--gold) 16%,transparent)}
.lcat-sys{color:var(--sub);background:color-mix(in srgb,var(--sub) 15%,transparent)}
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
.oheat{display:flex;gap:6px;align-items:flex-end;justify-content:center;height:66px;direction:ltr;position:relative}
.hbar{flex:1 1 0;max-width:56px;border-radius:5px 5px 3px 3px;min-height:8px;cursor:pointer;transition:filter .12s}
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
.tnarrow{color:var(--acc);font-weight:800;font-size:19px;text-align:center}
/* portfw card: two columns — ports on one side, destinations/rotation on the other */
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
.settcat{font-size:11.5px;font-weight:800;color:var(--acc);letter-spacing:.02em;margin:16px 2px 2px;padding-top:12px;border-top:1px dashed var(--bord)}
.settcat:first-of-type{border-top:none;padding-top:0}
.setctl input.wtxt{max-width:150px;text-align:left;direction:ltr;font-family:ui-monospace,Consolas,monospace;font-size:12px}
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
/* core modal two-tab bar (آی‌پی‌ها / تنظیمات) — accent-wash active, matching .navi.on */
.ctabs{display:flex;gap:8px;margin:2px 0 6px}
.ctab{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;height:42px;border-radius:12px;background:var(--field);color:var(--sub);border:1px solid transparent;font-weight:700;font-size:13.5px;cursor:pointer;font-family:inherit;transition:.15s}
.ctab svg{width:16px;height:16px}
.ctab.on{background:var(--accw);color:var(--acc);border-color:color-mix(in srgb,var(--acc) 30%,transparent)}
.ctabp{display:none}.ctabp.on{display:block}
/* rotation multi-IP pool (icon-only status, like the ws CDN pool): pick which of a node's IPs to cycle */
.rpool{border:1px solid var(--bord);border-radius:11px;overflow:hidden;background:var(--field)}
.rrow{display:flex;align-items:center;gap:7px;padding:0 9px;min-height:40px;border-bottom:1px solid var(--bord);cursor:pointer;user-select:none}
.rrow:last-child{border-bottom:none}
.rrow .sic{width:18px;height:18px;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;color:var(--sub);opacity:.4}
.rrow .sic svg{width:18px;height:18px}
.rrow.on{box-shadow:inset -3px 0 0 var(--ok)}
.rrow.on .sic{color:var(--ok);opacity:1}
.rrow .rip{flex:1;text-align:center;font-family:var(--mono);font-size:12.5px;direction:ltr;letter-spacing:-.02em}
.rhint{font-size:11px;color:var(--sub);text-align:center;margin-top:8px;line-height:1.7}
.plist{border:1px solid var(--bord);border-radius:10px;overflow:hidden;background:var(--field)}
.prow{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:0 12px;min-height:42px;border-bottom:1px solid var(--bord)}
.prow:last-child{border-bottom:none}
.prow .pb{border:1px solid var(--bord);background:var(--glass);color:var(--sub);width:26px;height:26px;border-radius:7px;cursor:pointer;font-size:12px;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center}
.pempty{text-align:center;font-size:11px;color:var(--sub);padding:14px 0}
.pacc{border:1px solid var(--bord);border-radius:12px;overflow:hidden;background:var(--field);margin-top:12px}
.pacchd{display:flex;align-items:center;justify-content:space-between;padding:11px 13px;cursor:pointer;gap:10px}
.pacct{font-size:13px;font-weight:700}
.paccs{margin-top:5px;display:flex;gap:5px;flex-wrap:wrap}
.pbadge{font-size:10px;font-weight:700;border-radius:99px;padding:1px 8px}
.pbadge.ok{background:rgba(78,201,154,.16);color:var(--ok)}
.pbadge.bad{background:rgba(240,115,106,.16);color:var(--bad)}
.pbadge.warn{background:rgba(224,165,92,.18);color:var(--warn,#e0a55c)}
.pchev{color:var(--sub);transition:transform .2s;font-size:12px;flex:0 0 auto}
.pchev.open{transform:rotate(180deg)}
.paccbody{padding:0 11px 11px}
/* edge health rows — colored start-stripe card, right-aligned IP, icon state + icon actions */
.erow{display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid var(--bord);border-radius:10px;border-inline-start-width:3px;border-inline-start-color:var(--bord);flex-wrap:wrap;row-gap:7px}
.erow.ok{border-inline-start-color:var(--ok)}
.erow.warn{border-inline-start-color:var(--warn)}
.erow.bad{border-inline-start-color:var(--bad)}
.erow.dead .eip{text-decoration:line-through;color:var(--sub)}
.estat{flex:0 0 auto;display:grid;place-items:center}
.estat .ic{width:16px;height:16px}
.estat.ok{color:var(--ok)}.estat.warn{color:var(--warn)}.estat.bad{color:var(--bad)}.estat.mut{color:var(--sub)}
/* IP takes the whole first line on narrow screens (basis 150px), so it never truncates and the
   retest + action buttons wrap onto a second line; on a wide row everything stays on one line. */
.eip{flex:1 1 150px;min-width:0;font-family:ui-monospace,Consolas,monospace;direction:ltr;text-align:right;unicode-bidi:isolate;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ert{display:inline-flex;align-items:center;gap:6px;flex:0 0 auto}
.eacts{display:flex;gap:5px;flex:0 0 auto;margin-inline-start:auto}
.eib{width:28px;height:28px;border:1px solid var(--bord);background:transparent;color:var(--sub);border-radius:8px;cursor:pointer;display:grid;place-items:center;flex:0 0 auto;padding:0}
.eib .ic{width:15px;height:15px}
.eib:hover{border-color:var(--acc);color:var(--acc)}
.eib.del:hover{border-color:var(--bad);color:var(--bad)}
.eib.on{border-color:var(--ok);color:var(--ok)}
.pcd{font-family:ui-monospace,Consolas,monospace;font-size:10.5px;color:var(--sub);direction:ltr;font-variant-numeric:tabular-nums;flex:0 0 auto}
.pbar{display:inline-block;width:44px;height:5px;border-radius:3px;background:var(--bord);overflow:hidden;flex:0 0 auto}
.pbar>i{display:block;height:100%;background:var(--warn,#e0a55c);transition:width .5s linear}
.pbar.bad>i{background:var(--bad)}
/* live peer-pool status (direct-transport rotation): مقصد + مبدأ boxes of health rows + per-IP pin */
.peerlive{margin-top:12px;border:1px solid var(--bord);border-radius:12px;background:var(--field);padding:11px 12px;display:flex;flex-direction:column;gap:10px}
.peerlive .pllabel{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:700}
.peerlive .plprobe{margin-inline-start:auto;font-size:11px;padding:5px 10px;height:auto;display:inline-flex;align-items:center;gap:5px}
.peerlive .plprobe .ic{width:13px;height:13px}
.plbox{display:flex;flex-direction:column;gap:6px}
.plbox .plbl{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--sub);font-weight:700}
.plbox .plbadges{margin-inline-start:auto;display:inline-flex;gap:5px}
.plbox .rpool{border:none;background:transparent;display:flex;flex-direction:column;gap:6px;overflow:visible}
/* peer-pool row is a COLUMN: top line (icon+ip+actions) then the retest countdown UNDER it, indented */
.erow.pcol{flex-direction:column;align-items:stretch;flex-wrap:nowrap;row-gap:0}
.erow.pcol .etop{display:flex;align-items:center;gap:8px}
.erow.pcol .ecd{display:flex;align-items:center;gap:8px;margin-top:7px;margin-inline-start:24px}
.erow.pcol .ecd .pbar{flex:1 1 auto;width:auto;max-width:180px}
.eib.aim.on{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 55%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent)}
.prow.active{background:color-mix(in srgb,var(--ok) 9%,transparent);box-shadow:inset 3px 0 0 var(--ok)}
.tglbox.dis{opacity:.45;pointer-events:none}
.rl{font-size:9px;font-weight:800;border-radius:5px;padding:1px 5px;letter-spacing:.2px;flex:0 0 auto}
.rl.srv{color:var(--acc);background:var(--accw)}
.rl.cli{color:var(--gold);background:var(--goldw)}
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
.cedge{margin-top:10px;background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:8px 12px}
.cedge.live{background:color-mix(in srgb,var(--ok) 8%,transparent);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}
.cedge .ct{font-size:10.5px;color:var(--sub);display:flex;align-items:center;gap:6px}
.cedge .cdot{width:8px;height:8px;border-radius:50%;background:var(--ok);flex:0 0 auto}
.cedge .cv{direction:ltr;text-align:right;font-size:12.5px;font-weight:700;margin-top:3px;word-break:break-all;color:var(--tx)}
.cedge.live .cv{color:var(--ok)}
.cedge .echips{display:flex;flex-wrap:nowrap;gap:6px;margin-top:8px;min-width:0}
.cedge .echip{font-family:ui-monospace,Consolas,monospace;direction:ltr;unicode-bidi:isolate;font-size:12.5px;font-weight:700;padding:5px 11px;border-radius:9px;background:var(--card);border:1px solid var(--bord);color:var(--tx);white-space:nowrap;min-width:0;overflow:hidden;text-overflow:ellipsis;font-variant-numeric:tabular-nums}
.cedge .echip.ip{flex:0 0 auto}      /* IP:port always shown in full */
.cedge .echip.dom{flex:0 1 auto;font-weight:600;color:var(--sub)}   /* domain shrinks with … if the row is tight */
.cedge .echip.wait{font-family:inherit;font-weight:600;color:var(--sub)}
.enmeta .emcol>div.enc-line{white-space:nowrap;overflow:visible}
.enmeta .enc-line .encval{color:var(--ok);font-weight:700;direction:ltr}
.stat{margin-inline-start:auto;display:inline-flex;align-items:center;gap:5px}
.cprot{display:inline-flex;align-items:center;flex:0 0 auto;margin-inline-start:auto}
.cprot + .stat{margin-inline-start:0}
.cprot .rotmark{display:inline-flex;color:var(--acc);cursor:help}
.cprot .rotmark .ic{width:13px;height:13px}
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
  <div class="sbrand"><span class="logo"><span class="ic" data-ic="shield"></span></span><span>TUNNEL-MANAGER<small id="brandsub">کنترل فلیت</small></span></div>
  <nav class="nav" id="nav">
   <a class="navi" data-t="overview"><span class="ic" data-ic="dash"></span> <span class="nlbl">نمای کلی</span></a>
   <a class="navi" data-t="nodes"><span class="ic" data-ic="server"></span> <span class="nlbl">نودها</span><span class="ct" id="ct_nodes"></span></a>
   <a class="navi" data-t="tunnels"><span class="ic" data-ic="link"></span> <span class="nlbl">تونل‌ها</span><span class="ct" id="ct_tunnels"></span></a>
   <a class="navi" data-t="portfw"><span class="ic" data-ic="globe"></span> <span class="nlbl">پورت‌فوروارد</span><span class="ct" id="ct_portfw"></span></a>
   <a class="navi" data-t="core"><span class="ic" data-ic="cpu"></span> <span class="nlbl">هستهٔ اختصاصی</span><span class="ct" id="ct_core"></span></a>
   <a class="navi" data-t="logs"><span class="ic" data-ic="activity"></span> <span class="nlbl">لاگ</span><span class="ctwrap"><span class="ct" id="ct_logs"></span><span class="ct ctun" id="ct_logs_un" style="display:none"></span></span></a>
   <a class="navi" data-t="settings"><span class="ic" data-ic="cog"></span> <span class="nlbl">تنظیمات</span></a>
   <a class="navi" data-t="logout"><span class="ic" data-ic="logout"></span> <span class="nlbl">خروج</span></a>
  </nav>
 </aside>
 <main class="main">
  <div class="mtop"><button class="hb" onclick="drawer(true)"><span class="ic" data-ic="menu"></span></button><div class="sbrand"><span class="logo" style="width:28px;height:28px;font-size:14px"><span class="ic" data-ic="shield"></span></span><span>TUNNEL-MANAGER</span></div><button class="hb" id="thbtn2" onclick="toggleTheme()"><span class="ic" data-ic="moon"></span></button></div>
  <div id="view"></div>
 </main>
</div>
<script>
// ===== i18n — Persian (default) + English. localStorage 'tnl_lang' is the source of truth. =====
var LANG='fa';
try{var _sl=localStorage.getItem('tnl_lang');if(_sl=='fa'||_sl=='en')LANG=_sl}catch(e){}
var I18N={fa:{
 nav_overview:"نمای کلی",nav_nodes:"نودها",nav_tunnels:"تونل‌ها",nav_portfw:"پورت‌فوروارد",nav_core:"هستهٔ اختصاصی",nav_logs:"لاگ",nav_settings:"تنظیمات",nav_logout:"خروج",
 logs_title:"لاگِ سیستم",logs_sub:"رویدادهای خودکارِ سیستم — قطع/وصلِ نود و تونل و تغییرِ خودکارِ لبه (کارهای دستیِ شما اینجا نمی‌آید)",logs_empty:"هنوز رویدادی ثبت نشده",logs_clear:"پاک‌کردنِ لاگ",logs_cleared:"لاگ پاک شد",logs_clear_confirm:"همهٔ لاگ‌ها پاک شوند؟",logs_refresh:"تازه‌سازی",
 logc_all:"همه",logc_tunnel:"تونل",logc_rot:"چرخش/استخر",logc_ech:"ECH",logc_node:"نود",logc_sys:"سیستم",logc_err:"فقط خطاها",logc_none:"در این دسته لاگی نیست",
 brand_sub:"کنترل فلیت",theme:"تم",lang_label:"زبان",
 save:"ذخیره",save_rebuild:"ذخیره و بازسازی",cancel:"انصراف",add:"افزودن",close:"بستن",confirm_del:"تأیید و حذف",yes_all:"بله، همه",
 online:"آنلاین",offline:"آفلاین",failed:"ناموفق",saving:"در حال ذخیره…",checking:"در حال بررسی…",sending:"در حال ارسال…",loading:"در حال بارگذاری…",
 no_results:"موردی یافت نشد.",live:"زنده",select:"انتخاب کنید",ip:"آی‌پی",err_check:"خطا در بررسی",not_available:"در دسترس نیست",
 prev:"قبلی",next:"بعدی",page:"صفحه",of:"از",items:"مورد",search:"جستجو…",
 disk:"دیسک",cpu_cores:"تعداد هسته",os:"سیستم‌عامل",uptime:"آپ‌تایم",host:"میزبان",proxy:"پروکسی",
 // overview
 ov_sub:"آمارِ دقیقِ فلیت — بدونِ میانگینِ گمراه‌کننده",ov_health:"سلامتِ فلیت",ov_attention:"نیازمندِ توجه",ov_allnodes:"همهٔ نودها یک‌نگاه",
 st_healthy:"سالم",st_warn:"هشدار (>۶۰٪)",st_crit:"بحرانی (>۸۵٪)",ov_central:"سرورِ مرکزی (این پنل)",ov_worst:"پرمصرف‌ترین نودها",
 ov_tunbreak:"وضعیتِ تفکیکیِ تونل‌ها",ov_traffic:"ترافیکِ فلیت",ov_uptime:"آپ‌تایم",ov_rxtot:"↓ ورودیِ کل",ov_txtot:"↑ خروجیِ کل",
 ov_uptime_avg:"میانگینِ آپ‌تایم",ov_down_nodes:"نود قطعی داشته",ov_chip_node:"نود",ov_chip_uplink:"لینکِ سالم",ov_chip_tunnel:"تونل",ov_chip_alert:"هشدار",ov_chip_noalert:"بدونِ هشدار",
 ov_noalert:"همه‌چیز مرتب است — هشداری نیست",ov_no_nodes:"نودی نیست",ov_no_online:"نودِ آنلاینی نیست",ov_no_tunnel:"تونلی نیست",
 ov_heat_note:"نود · هر میله = بدترین متریکِ آن نود (دیسک/رم/CPU) · خاکستری = آفلاین",
 tst_connected:"متصل",tst_noping:"بدونِ پینگ",tst_down:"قطع",tst_rebuild:"نیازمندِ بازسازی",
 ov_worst_q:"بدترین کیفیت: تونلِ",ov_loss:"اتلاف",ov_ping:"پینگ",ov_all_good:"کیفیتِ همهٔ تونل‌ها خوب است",ov_fleet_ping:"میانگینِ پینگِ فلیت",
 ov_uptime_lbl:"میانگینِ آپ‌تایمِ",ov_hours_recent:"ساعتِ اخیر",load:"لود",
 // nodes
 nodes_sub:"افزودن و وضعیت زنده‌ی نودها",add_node:"افزودن نود",nodes_fleet:"نودهای فلیت",nodes_search:"جستجوی نام یا آی‌پی…",
 nodes_empty:"هنوز نودی اضافه نشده — دکمهٔ «افزودن نود» بالا.",
 tip_test:"تست",tip_details:"مشخصات",tip_edit:"ویرایش",tip_delete:"حذف",
 nd_tunnels:"تونل",nd_portfw:"پورت‌فوروارد",nd_agent:"ایجنت",nd_core:"هسته",nd_core_missing:"نصب نیست",nd_ctrlproxy:"پروکسیِ کنترل",
 uptime_bar:"آپتایم",node_min2:"حداقل ۲ نودِ آنلاین لازم است",
 // tunnels
 tun_sub:"هر لینک نود‌به‌نود جداگانه است — بررسی، ویرایش و حذف مستقل دارد",add_tunnel:"افزودن تونل",check_all:"بررسی اتصال همگانی",
 tun_search:"جستجوی نام نود / نوع / شناسه…",tun_empty:"هنوز لینکی نیست — دکمهٔ «افزودن تونل» بالا.",
 st_off:"خاموش",st_half:"نیم‌بند",st_disc:"قطع",tip_ping:"تستِ پینگ",tip_reset:"ریستِ حجمِ کل",tip_rebuild:"بازسازی",tip_toggle:"روشن/خاموشِ تونل",
 subnet:"سابنت",tid:"شناسه",iface:"اینترفیس",ttype:"نوع",udp_port:"پورتِ UDP",enc:"رمزنگاری",encrypted:"رمزنگاری‌شده",total:"مجموع",
 no_live_side:"دادهٔ زنده از این سر نیست",tun_off_note:"این تونل خاموش است — اینترفیس down شده. توگلِ بالا را بزن تا دوباره بالا بیاید.",
 turned_on:"روشن شد",turned_off:"خاموش شد",
 // core view
 core_sub:"تونل‌های هستهٔ اختصاصی (Go) — حالتِ packet/core با رمزنگاریِ داخلی، جدا از تونل‌های سیستمی",core_add:"تونلِ هسته",
 core_search:"جستجوی نام نود / شناسه…",core_empty:"هنوز تونلِ هسته‌ای نیست — دکمهٔ «تونلِ هسته» بالا را بزن.",
 server:"سرور",client:"کلاینت",carrier:"حامل",port:"پورت",caps:"قابلیت‌ها",no_cipher:"بدونِ رمز",cdn_edge:"لبهٔ CDN",active_edge:"لبهٔ فعالِ فعلی (زنده)",
 // portfw
 pf_sub:"فوروارد پورت روی یک نود (با چرخشِ چند مقصد)",pf_add:"افزودن پورت‌فوروارد",pf_active:"پورت‌فورواردهای فعال",pf_search:"جستجوی نود / نام…",
 pf_empty:"پورت‌فورواردی نیست.",pf_no_online:"هیچ نودِ آنلاینی نیست",
 // settings
 set_sub:"رفتار خودکارِ پنل و بازه‌های بررسی",set_saved:"تنظیمات ذخیره شد",
 // toasts common
 t_rebuilt:"بازسازی شد",t_reset_done:"حجمِ کل صفر شد",
},en:{
 nav_overview:"Overview",nav_nodes:"Nodes",nav_tunnels:"Tunnels",nav_portfw:"Port-forward",nav_core:"Core",nav_logs:"Logs",nav_settings:"Settings",nav_logout:"Log out",
 logs_title:"System log",logs_sub:"Automatic system events — node/tunnel up-down and automatic edge switches (your manual actions are not shown here)",logs_empty:"No events recorded yet",logs_clear:"Clear log",logs_cleared:"Log cleared",logs_clear_confirm:"Clear all logs?",logs_refresh:"Refresh",
 logc_all:"All",logc_tunnel:"Tunnel",logc_rot:"Rotation",logc_ech:"ECH",logc_node:"Node",logc_sys:"System",logc_err:"Errors only",logc_none:"No events in this category",
 brand_sub:"Fleet control",theme:"Theme",lang_label:"Language",
 save:"Save",save_rebuild:"Save & rebuild",cancel:"Cancel",add:"Add",close:"Close",confirm_del:"Confirm & delete",yes_all:"Yes, all",
 online:"Online",offline:"Offline",failed:"Failed",saving:"Saving…",checking:"Checking…",sending:"Sending…",loading:"Loading…",
 no_results:"No results.",live:"Live",select:"Select",ip:"IP",err_check:"Check failed",not_available:"Unreachable",
 prev:"Previous",next:"Next",page:"Page",of:"of",items:"items",search:"Search…",
 disk:"Disk",cpu_cores:"Cores",os:"OS",uptime:"Uptime",host:"Host",proxy:"Proxy",
 ov_sub:"Precise fleet stats — no misleading averages",ov_health:"Fleet health",ov_attention:"Needs attention",ov_allnodes:"All nodes at a glance",
 st_healthy:"Healthy",st_warn:"Warning (>60%)",st_crit:"Critical (>85%)",ov_central:"Central server (this panel)",ov_worst:"Busiest nodes",
 ov_tunbreak:"Tunnel status breakdown",ov_traffic:"Fleet traffic",ov_uptime:"Uptime",ov_rxtot:"↓ Total in",ov_txtot:"↑ Total out",
 ov_uptime_avg:"Average uptime",ov_down_nodes:"nodes had downtime",ov_chip_node:"Nodes",ov_chip_uplink:"Links up",ov_chip_tunnel:"Tunnels",ov_chip_alert:"Alerts",ov_chip_noalert:"No alerts",
 ov_noalert:"All good — no alerts",ov_no_nodes:"No nodes",ov_no_online:"No node online",ov_no_tunnel:"No tunnels",
 ov_heat_note:"nodes · each bar = that node's worst metric (disk/RAM/CPU) · gray = offline",
 tst_connected:"Connected",tst_noping:"No ping",tst_down:"Down",tst_rebuild:"Needs rebuild",
 ov_worst_q:"Worst quality: tunnel",ov_loss:"loss",ov_ping:"ping",ov_all_good:"All tunnels are in good shape",ov_fleet_ping:"fleet avg ping",
 ov_uptime_lbl:"Average uptime over the last",ov_hours_recent:"hours",load:"load",
 nodes_sub:"Add nodes and watch them live",add_node:"Add node",nodes_fleet:"Fleet nodes",nodes_search:"Search name or IP…",
 nodes_empty:"No nodes yet — use the \\"Add node\\" button above.",
 tip_test:"Test",tip_details:"Details",tip_edit:"Edit",tip_delete:"Delete",
 nd_tunnels:"Tunnels",nd_portfw:"Port-forward",nd_agent:"agent",nd_core:"core",nd_core_missing:"not installed",nd_ctrlproxy:"Control proxy",
 uptime_bar:"Uptime",node_min2:"At least 2 online nodes required",
 tun_sub:"Every node-to-node link is separate — check, edit and delete each independently",add_tunnel:"Add tunnel",check_all:"Check all links",
 tun_search:"Search node name / type / ID…",tun_empty:"No links yet — use the \\"Add tunnel\\" button above.",
 st_off:"Off",st_half:"Partial",st_disc:"Down",tip_ping:"Ping test",tip_reset:"Reset total",tip_rebuild:"Rebuild",tip_toggle:"Tunnel on/off",
 subnet:"Subnet",tid:"ID",iface:"Interface",ttype:"Type",udp_port:"UDP port",enc:"Encryption",encrypted:"Encrypted",total:"Total",
 no_live_side:"No live data from this end",tun_off_note:"This tunnel is off — the interface is down. Toggle it above to bring it back up.",
 turned_on:"Turned on",turned_off:"Turned off",
 core_sub:"Custom-core (Go) tunnels — packet/core mode with built-in encryption, separate from system tunnels",core_add:"Core tunnel",
 core_search:"Search node name / ID…",core_empty:"No core tunnels yet — use the \\"Core tunnel\\" button above.",
 server:"Server",client:"Client",carrier:"Carrier",port:"Port",caps:"Features",no_cipher:"No cipher",cdn_edge:"CDN edge",active_edge:"Current active edge (live)",
 pf_sub:"Forward a port on a node (with multi-target rotation)",pf_add:"Add port-forward",pf_active:"Active port-forwards",pf_search:"Search node / name…",
 pf_empty:"No port-forwards.",pf_no_online:"No node is online",
 set_sub:"Panel automation and check intervals",set_saved:"Settings saved",
 t_rebuilt:"Rebuilt",t_reset_done:"Total reset to zero",
}};
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k];for(var k in x.en)I18N.en[k]=x.en[k]})({fa:{
 ram:"رم",cores_word:"هسته",unit_mb:"م‌ب",unit_gb:"گیگ",refresh2s:"به‌روزرسانیِ زنده",
 // node details
 nd_title:"مشخصات نود",nd_status:"وضعیت نود",nd_off_last:"آفلاین — آخرین مقادیر",nd_conn_test:"تستِ اتصال",nd_traffic:"ترافیک",nd_ips:"آی‌پی‌ها",
 ip_leg:"تونل‌شده / پورت‌فوروارد / آزاد",ip_none:"آی‌پی‌ای گزارش نشد",free:"آزاد",nd_no_tp:"تونل یا پورت‌فورواردی روی این نود نیست",nd_ctrlproxy:"پروکسیِ کنترل",
 // node edit / add
 nd_edit:"ویرایشِ نود",f_name:"نام",f_host_ip:"هاست / آی‌پی",f_port:"پورت",f_token:"توکن",tok_keep:"خالی = توکن فعلی بماند",
 f_ctrlproxy_empty:"پروکسیِ کنترل (خالی = بدون پروکسی)",need_nhp:"نام، هاست و پورت لازم است",
 
 
 
 
 connecting_dots:"در حال اتصال…",
 need_all_nhpt:"لطفاً نام، هاست، پورت و توکن را پر کن",node_added:"نود اضافه شد",
 
 inst_done:"انجام شد",
 // node delete
 nd_del:"حذفِ نود",del_how:"می‌خواهی نود چطور حذف شود؟ یکی را انتخاب کن:",del_detach_t:"فقط از پنل جدا کن",
 del_detach_s:"نود و تونل‌هایش دست‌نخورده می‌مانند و کار می‌کنند؛ فقط از رجیستریِ این پنل حذف می‌شود. بعداً می‌توانی دوباره اضافه‌اش کنی.",
 del_wipe_t:"پاک‌سازیِ کاملِ نود",del_wipe_s:"روی خودِ سرورِ نود همه‌چیز پاک می‌شود: همهٔ تونل‌ها، ایجنت، سرویسِ systemd، توکن و فایل‌های JSON. سمتِ نودهای مقابل هم تونل‌ها بسته می‌شوند. برگشت‌ناپذیر است!",
 del_wipe_confirm:"مطمئنی؟ کلِ نود روی سرور — تونل‌ها، ایجنت و توکن — پاک می‌شود و برگشت ندارد.",del_wipe_yes:"بله، پاک کن",
 del_wiping:"در حال پاک‌سازیِ نود…",del_detaching:"در حال جدا کردن…",node_wiped:"نود کاملاً پاک‌سازی شد",node_detached:"نود از پنل جدا شد",
 test_testing:"در حال تست…",node_added_online:" · آنلاین",node_added_offline:" · آفلاین: ",
 // tunnels
 t_side_off:"نود آفلاین (به agent وصل نشد — شاید پورت/توکن عوض شده)",t_side_notun:"قطع (تونل روی نود نیست)",t_side_ifdown:"قطع (اینترفیس پایین)",
 t_side_conn:"متصل",t_side_nopingr:"پینگ جواب نداد",t_side_up_unk:"بالا (پینگ نامشخص)",t_ping:"پینگ",t_loss:"اتلاف",t_noloss:"بدون اتلاف",
 no_tunnel_check:"تونلی برای بررسی نیست",checkall_done:"بررسیِ همهٔ تونل‌ها تمام شد",
 rebuild_confirm:"این تونل روی هر دو نود از نو ساخته شود؟ (حذف و ساختِ مجدد با همان تنظیمات)",rebuilding_both:"در حال بازسازیِ تونل روی دو نود…",
 rebuilt_test:"تونل از نو ساخته شد — با «بررسی اتصال» تستش کن",rebuild_failed:"بازسازی ناموفق",checking_conn:"در حال بررسی اتصال (پینگِ زنده روی دو سر)…",
 conn_ok:"اتصال برقرار",conn_bad:"مشکل در اتصال",reset_confirm:"حجمِ کلِ این تونل صفر شود؟ (نرخِ زنده دست‌نخورده می‌ماند)",
 pf_reset_confirm:"حجمِ کلِ این پورت‌فوروارد صفر شود؟",del_tun_confirm:"این تونل روی هر دو نود حذف شود؟",del_partial:"حذف ناقص: ",
 view_switched:"دیدِ مصرف به نودِ «",view_switched2:"» تغییر یافت.",drift_note:"آی‌پیِ یکی از نودها عوض شده — این تونل نیاز به بازسازی دارد. دکمهٔ «بازسازی» را بزن.",
 tip_flip:"تعویضِ دیدِ مصرف — فعلاً: ",
 // create tunnel
 add_tunnel_t:"افزودنِ تونل",create_sub:"سیستمی · یک مبدأ ↔ یک مقصد",src_node:"نودِ مبدأ",dst_node:"نودِ مقصد",
 tun_type:"نوع تونل",local_range:"سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه، بدون تداخل)",custom_subnet:"سابنتِ دلخواه",range:"رنج",
 create_tun_btn:"ساخت تونل",two_diff_nodes:"دو نودِ متفاوت انتخاب کن",creating_tun:"در حال ساختِ تونل…",tun_created:"تونل ساخته شد",
 src_ip:"آی‌پیِ نودِ مبدأ",dst_ip:"آی‌پیِ نودِ مقصد",
 rot_t:"چرخشِ آی‌پی",rot_d:"بینِ آی‌پی‌های هر نود می‌چرخد و آی‌پیِ بلاک‌شده را کنار می‌گذارد (مسیرِ مستقیم، بدونِ CDN)",
 rot_interval:"بازهٔ چرخش",rot_onfail:"فقط هنگامِ قطع",rot_1m:"هر ۱ دقیقه",rot_5m:"هر ۵ دقیقه",rot_10m:"هر ۱۰ دقیقه",
 rot_min2:"برای چرخش باید حداقل ۲ آی‌پی در هر استخر انتخاب شود",
 rot_autoburn_t:"حذفِ خودکارِ آی‌پیِ بلاک‌شده",rot_autoburn_d:"آی‌پیی که وصل نشد کنار می‌رود و روی backoff دوباره تست می‌شود؛ خوب که شد، خودش برمی‌گردد",
 rot_primary:"اصلی",
 // rebuild picker
 rb_title:"بازسازیِ تونل",rb_newip:"آی‌پیِ جدید",rb_no_ip:"آی‌پیِ قابلِ انتخابی نیست",rb_info:"آی‌پیِ قبلی دیگر روی نود نیست. آی‌پیِ جدیدِ این تونل را انتخاب کن — تگ‌ها نشان می‌دهند هر آی‌پی به کجا وصل است.",
 rb_no_link:"اطلاعاتِ لینک در دسترس نیست",rb_no_drift:"این تونل driftی ندارد",rebuilding:"در حال بازسازی…",rb_fetch_err:"خطا در دریافتِ اطلاعات",
 // core roles / meta
 core_edit_t:"ویرایشِ تونلِ هسته",not_found:"یافت نشد",no_change:"تغییری نبود",saved_rebuilt:"ذخیره و بازسازی شد",core_tun_t:"تونلِ هسته",core_tun_sub:"هستهٔ اختصاصی · packet/core",
 core_created:"تونلِ هسته ساخته شد",raw_need_enc:"حاملِ raw به رمزنگاری نیاز دارد",flux_need_enc:"حاملِ flux به رمزنگاری نیاز دارد",
 wss_need_host:"برای wss باید دامنه (Host) را وارد کنی",ech_need_wss:"ECH به wss نیاز دارد — اول wss را روشن کن",sni_need_wss:"تقسیمِ SNI به wss نیاز دارد — اول wss را روشن کن",
 xh_need_wss:"این حالت نیازمندِ wss است — اول wss (TLS به CDN) را روشن کن یا packet-up را انتخاب کن",
 decoy_need_ip:"آی‌پیِ طُعمه (مقصدِ جعلی) را وارد کن",cover_need_sni:"برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی",
 creating_core:"در حال ساختِ تونلِ هسته روی دو نود…",saving_rebuild_both:"در حال ذخیره و بازسازیِ دو سر…",
 // portfw
 pf_add_t:"افزودنِ پورت‌فوروارد",pf_edit_t:"ویرایشِ پورت‌فوروارد",pf_node:"نود",pf_listen_port:"پورتِ ورودی",pf_dst_port:"پورتِ مقصد",
 pf_dst_ips:"آی‌پی(های) مقصد — با کاما جدا کن",pf_rot_min:"چرخش هر (دقیقه) — اگر چند آی‌پی دادی",pf_rot_between:"چرخش بینِ مقصدها",
 pf_rot_interval:"بازهٔ چرخش (دقیقه)",pf_lip:"آی‌پیِ ورودی (شنود)",pf_lip_note:"پورت فقط روی این آی‌پی فوروارد می‌شود",
 pf_lip_full:"آی‌پیِ ورودی (شنود) — پورت فقط روی این آی‌پی فوروارد می‌شود",pf_rot_note:"چرخش فقط با ۲ آی‌پیِ مقصد یا بیشتر فعال می‌شود.",
 pf_need_ports:"پورت‌ها و آی‌پیِ مقصد لازم است",pf_need_all:"نود، پورتِ ورودی/مقصد و آی‌پی لازم است",creating_dots:"در حال ساخت…",
 pf_created:"پورت‌فوروارد ساخته شد: ",pf_del_confirm:"این پورت‌فوروارد حذف شود؟",pf_active_now:"هم‌اکنون روی: ",pf_targets:"مقصدها: ",
 pf_iface:"اینترفیس: ",pf_lip_lbl:"آی‌پیِ ورودی: ",pf_lp_lbl:"پورتِ ورودی: ",pf_dp_lbl:"پورتِ مقصد: ",pf_active_badge:"فعال · مقصد",
 pf_disabled:"غیرفعال",pf_rule:"قانون",pf_rotate_now:"چرخش الان",pf_rotate_done:"چرخش انجام شد ← ",pf_rotate_failed:"چرخش ناموفق",
 // settings
 set_on_ipchange:"وقتی آی‌پیِ نود عوض شد",set_on_ipchange_d:"هشدار بده یا خودکار ترمیم کن",set_rec_int:"بازهٔ بررسیِ ترمیم (ثانیه)",
 set_rec_range:"۵ تا ۳۶۰۰",set_poll_int:"بازهٔ پایشِ فلیت (ثانیه)",set_poll_range:"۰٫۳ تا ۶۰ — زیرِ ۱ هم مجاز (بارِ شبکه بالا)",set_ui_int:"بازهٔ رفرشِ نمایش (ثانیه)",set_ui_range:"۰٫۳ تا ۶۰ — نرخ/گیج‌ها با این بازه تازه می‌شوند",set_ech_int:"بازهٔ تازه‌سازیِ کلیدِ ECH (دقیقه)",set_ech_range:"۰ = خاموش، وگرنه ۱ تا ۱۴۴۰ — چرخشِ کلیدِ CDN خودکار ترمیم می‌شود",set_upwin:"پنجرهٔ نوارِ آپ‌تایم",
 set_upwin_d:"۶۰ خانه؛ هر خانه = پنجره ÷ ۶۰",set_mode_auto:"خودکار",set_mode_alert:"هشدار",set_default:"پیش‌فرض",set_agent_update:"بروزرسانیِ ایجنت",
 set_tun_hd:"زمان‌بندیِ پیشرفتهٔ self-heal",set_tun_note:"این زمان‌ها روی همهٔ تونل‌ها اعمال می‌شوند و روی هر تونل هنگامِ ساخت/بازسازیِ بعدی اثر می‌کنند. برای اعمالِ فوری، تونل را «بازسازی» کن. مقدارهای خارج از بازه در هسته کلَمپ می‌شوند.",set_tun_reset:"بازگردانی به پیش‌فرض",set_tun_saved:"زمان‌بندی ذخیره شد",set_tun_reset_confirm:"همهٔ زمان‌ها به پیش‌فرض برگردند؟",
 set_tcat_pool:"۱) سلامتِ استخر (چرخشِ IP — مستقیم و WS CDN)",set_tcat_dead:"۲) تشخیصِ مرگ / self-heal (بر پایهٔ keepalive)",set_tcat_rot:"۳) چرخش",
 set_t_suspect:"زمان‌بندیِ تستِ مجددِ «موقت‌سوخته» (ثانیه)",set_t_suspect_d:"لیستِ پله‌ها با کاما؛ هر شکست یک پله جلو، بعد از آخری → مرده",
 set_t_deadretest:"بازهٔ تستِ IPِ «مرده» (ثانیه)",set_t_deadretest_d:"IPِ مرده هر این‌قدر یک‌بار دوباره تست می‌شود",
 set_t_pinttl:"سقفِ پینِ دستی (ثانیه)",set_t_pinttl_d:"پینِ نشسته‌نشده (IPِ خراب) حداکثر این‌قدر نگه‌داشته می‌شود",
 set_t_datafail:"آستانهٔ سشنِ کوتاه",set_t_datafail_d:"چند سشنِ کوتاهِ پشت‌سرهم تا IP مشکوک شود",
 set_t_datagood:"پنجرهٔ گاردِ قطعی (ثانیه)",set_t_datagood_d:"فقط وقتی IP مقصر شود که تازگی یک سشنِ سالم بوده",
 set_t_idlemult:"ضریبِ idle (×keepalive)",set_t_idlemult_d:"مهلتِ خواندنِ ws/tcp = ضریب × keepalive",
 set_t_idlemin:"کفِ idle (ثانیه)",set_t_idlemin_d:"مهلتِ idle زیرِ این نرود",
 set_t_ssmult:"ضریبِ کهنگیِ سشن (×keepalive)",set_t_ssmult_d:"پنجرهٔ کهنگیِ udp/raw/flux = ضریب × keepalive",
 set_t_ssmin:"کفِ کهنگیِ سشن (ثانیه)",set_t_ssmin_d:"پنجرهٔ کهنگی زیرِ این نرود",
 set_t_pingloss:"آستانهٔ پینگِ ازدست‌رفته",set_t_pingloss_d:"این‌قدر keepalive بی‌پاسخ → بستنِ اتصال",
 set_t_minlive:"حداقلِ عمرِ سشنِ سالم (ثانیه)",set_t_minlive_d:"سشنِ کوتاه‌تر از این = خرابیِ داده‌ای علیهِ آن IP",
 set_t_probeto:"تایم‌اوتِ پروبِ لبه (ثانیه)",set_t_probeto_d:"سقفِ زمانِ یک پروبِ TCP+TLS",
 set_t_fluxrot:"چرخشِ پیش‌فرضِ flux (ثانیه)",set_t_fluxrot_d:"طولِ epochِ flux وقتی per-tunnel تنظیم نشده",
 h1:"ساعت",h3:"۳ ساعت",h6:"۶ ساعت",h8:"۸ ساعت",h12:"۱۲ ساعت",h24:"۲۴ ساعت",
 // generic states
 pending_check:"در حال بررسی…",off_word:"خاموش",on_word:"روشن",
},en:{
 ram:"RAM",cores_word:"cores",unit_mb:"MB",unit_gb:"GB",refresh2s:"live refresh",
 nd_title:"Node details",nd_status:"Node status",nd_off_last:"Offline — last values",nd_conn_test:"Connection test",nd_traffic:"Traffic",nd_ips:"IPs",
 ip_leg:"tunneled / port-forward / free",ip_none:"no IPs reported",free:"Free",nd_no_tp:"No tunnels or port-forwards on this node",nd_ctrlproxy:"Control proxy",
 nd_edit:"Edit node",f_name:"Name",f_host_ip:"Host / IP",f_port:"Port",f_token:"Token",tok_keep:"empty = keep current token",
 f_ctrlproxy_empty:"Control proxy (empty = none)",need_nhp:"Name, host and port are required",
 
 
 
 
 connecting_dots:"Connecting…",
 need_all_nhpt:"Please fill in name, host, port and token",node_added:"Node added",
 
 inst_done:"Done",
 nd_del:"Delete node",del_how:"How should the node be removed? Pick one:",del_detach_t:"Detach from panel only",
 del_detach_s:"The node and its tunnels stay intact and keep working; it is only removed from this panel's registry. You can add it back later.",
 del_wipe_t:"Full node wipe",del_wipe_s:"Everything is wiped on the node server: all tunnels, the agent, the systemd service, the token and JSON files. Tunnels are also torn down on the peer nodes. Irreversible!",
 del_wipe_confirm:"Are you sure? The entire node on the server — tunnels, agent and token — is wiped and cannot be recovered.",del_wipe_yes:"Yes, wipe it",
 del_wiping:"Wiping node…",del_detaching:"Detaching…",node_wiped:"Node fully wiped",node_detached:"Node detached from panel",
 test_testing:"Testing…",node_added_online:" · online",node_added_offline:" · offline: ",
 t_side_off:"Node offline (agent unreachable — port/token may have changed)",t_side_notun:"Down (tunnel not on node)",t_side_ifdown:"Down (interface down)",
 t_side_conn:"Connected",t_side_nopingr:"No ping reply",t_side_up_unk:"Up (ping unknown)",t_ping:"ping",t_loss:"loss",t_noloss:"no loss",
 no_tunnel_check:"No tunnels to check",checkall_done:"Finished checking all tunnels",
 rebuild_confirm:"Rebuild this tunnel on both nodes? (delete and recreate with the same settings)",rebuilding_both:"Rebuilding the tunnel on both nodes…",
 rebuilt_test:"Tunnel rebuilt — test it with \\"Check\\"",rebuild_failed:"Rebuild failed",checking_conn:"Checking connection (live ping on both ends)…",
 conn_ok:"Connected",conn_bad:"Connection problem",reset_confirm:"Reset this tunnel's total to zero? (live rate is untouched)",
 pf_reset_confirm:"Reset this port-forward's total to zero?",del_tun_confirm:"Delete this tunnel on both nodes?",del_partial:"Partial delete: ",
 view_switched:"Traffic view switched to node \\"",view_switched2:"\\".",drift_note:"One node's IP changed — this tunnel needs a rebuild. Click \\"Rebuild\\".",
 tip_flip:"Switch traffic view — currently: ",
 add_tunnel_t:"Add tunnel",create_sub:"System · one source ↔ one destination",src_node:"Source node",dst_node:"Destination node",
 tun_type:"Tunnel type",local_range:"Local subnet (private range — auto by ID, no overlap)",custom_subnet:"Custom subnet",range:"Range",
 create_tun_btn:"Create tunnel",two_diff_nodes:"Pick two different nodes",creating_tun:"Creating tunnel…",tun_created:"Tunnel created",
 src_ip:"Source node IP",dst_ip:"Destination node IP",
 rot_t:"IP rotation",rot_d:"Cycles among each node's IPs and sidelines a blocked one (direct path, no CDN)",
 rot_interval:"Rotation interval",rot_onfail:"Only on failure",rot_1m:"Every 1 min",rot_5m:"Every 5 min",rot_10m:"Every 10 min",
 rot_min2:"Pick at least 2 IPs per pool to rotate",
 rot_autoburn_t:"Auto-drop a blocked IP",rot_autoburn_d:"An IP that won't connect is sidelined and retested on backoff; it returns when healthy",
 rot_primary:"primary",
 rb_title:"Rebuild tunnel",rb_newip:"new IP",rb_no_ip:"No selectable IP",rb_info:"The old IP is no longer on the node. Pick this tunnel's new IP — the tags show where each IP is attached.",
 rb_no_link:"Link info unavailable",rb_no_drift:"This tunnel has no drift",rebuilding:"Rebuilding…",rb_fetch_err:"Error fetching info",
 core_edit_t:"Edit core tunnel",not_found:"Not found",no_change:"No changes",saved_rebuilt:"Saved & rebuilt",core_tun_t:"Core tunnel",core_tun_sub:"Custom core · packet/core",
 core_created:"Core tunnel created",raw_need_enc:"The raw carrier requires encryption",flux_need_enc:"The flux carrier requires encryption",
 wss_need_host:"For wss you must enter the domain (Host)",ech_need_wss:"ECH requires wss — turn on wss first",sni_need_wss:"SNI fragmentation requires wss — turn on wss first",
 xh_need_wss:"This mode requires wss — turn on wss (TLS to CDN) first, or pick packet-up",
 decoy_need_ip:"Enter the decoy (fake destination) IP",cover_need_sni:"For TLS cover you must enter the display domain (SNI)",
 creating_core:"Creating the core tunnel on both nodes…",saving_rebuild_both:"Saving and rebuilding both ends…",
 pf_add_t:"Add port-forward",pf_edit_t:"Edit port-forward",pf_node:"Node",pf_listen_port:"Listen port",pf_dst_port:"Destination port",
 pf_dst_ips:"Destination IP(s) — comma-separated",pf_rot_min:"Rotate every (minutes) — if you gave several IPs",pf_rot_between:"Rotate between targets",
 pf_rot_interval:"Rotate interval (minutes)",pf_lip:"Listen IP",pf_lip_note:"The port is forwarded only on this IP",
 pf_lip_full:"Listen IP — the port is forwarded only on this IP",pf_rot_note:"Rotation is enabled only with 2 or more destination IPs.",
 pf_need_ports:"Ports and destination IP are required",pf_need_all:"Node, listen/destination port and IP are required",creating_dots:"Creating…",
 pf_created:"Port-forward created: ",pf_del_confirm:"Delete this port-forward?",pf_active_now:"Currently on: ",pf_targets:"Targets: ",
 pf_iface:"Interface: ",pf_lip_lbl:"Listen IP: ",pf_lp_lbl:"Listen port: ",pf_dp_lbl:"Destination port: ",pf_active_badge:"Active · target",
 pf_disabled:"Inactive",pf_rule:"Rule",pf_rotate_now:"Rotate now",pf_rotate_done:"Rotated → ",pf_rotate_failed:"Rotation failed",
 set_on_ipchange:"When a node's IP changes",set_on_ipchange_d:"Alert, or auto-heal",set_rec_int:"Reconcile check interval (seconds)",
 set_rec_range:"5 to 3600",set_poll_int:"Fleet poll interval (seconds)",set_poll_range:"0.3 to 60 — sub-1s allowed (heavier load)",set_ui_int:"UI refresh interval (seconds)",set_ui_range:"0.3 to 60 — rates/gauges refresh at this cadence",set_ech_int:"ECH key refresh interval (minutes)",set_ech_range:"0 = off, else 1 to 1440 — a CDN key rotation self-heals",set_upwin:"Uptime-bar window",
 set_upwin_d:"60 cells; each cell = window ÷ 60",set_mode_auto:"Auto",set_mode_alert:"Alert",set_default:"default",set_agent_update:"Agent update",
 set_tun_hd:"Advanced self-heal timing",set_tun_note:"These apply fleet-wide and take effect on each tunnel at its next build/rebuild. To apply now, Rebuild the tunnel. Out-of-range values are clamped in the core.",set_tun_reset:"Reset to defaults",set_tun_saved:"Timing saved",set_tun_reset_confirm:"Reset all timings to defaults?",
 set_tcat_pool:"1) Pool health (IP rotation — direct & WS CDN)",set_tcat_dead:"2) Dead detection / self-heal (keepalive-based)",set_tcat_rot:"3) Rotation",
 set_t_suspect:"Suspect retest schedule (secs)",set_t_suspect_d:"Comma list of steps; each failure walks one step, past the last → dead",
 set_t_deadretest:"Dead-entry retest interval (secs)",set_t_deadretest_d:"A dead IP is retested this often",
 set_t_pinttl:"Manual-pin cap (secs)",set_t_pinttl_d:"An unlanded pin (dead IP) is held at most this long",
 set_t_datafail:"Short-session threshold",set_t_datafail_d:"Consecutive short sessions before an IP is suspected",
 set_t_datagood:"Outage-guard window (secs)",set_t_datagood_d:"Only blame an IP if some edge was healthy this recently",
 set_t_idlemult:"Idle multiplier (×keepalive)",set_t_idlemult_d:"ws/tcp read deadline = mult × keepalive",
 set_t_idlemin:"Idle floor (secs)",set_t_idlemin_d:"Idle deadline never below this",
 set_t_ssmult:"Session-stale multiplier (×keepalive)",set_t_ssmult_d:"udp/raw/flux stale window = mult × keepalive",
 set_t_ssmin:"Session-stale floor (secs)",set_t_ssmin_d:"Stale window never below this",
 set_t_pingloss:"Ping-loss threshold",set_t_pingloss_d:"This many unanswered keepalives → close the connection",
 set_t_minlive:"Min healthy session (secs)",set_t_minlive_d:"A session shorter than this is a data-plane fault against the IP",
 set_t_probeto:"Edge probe timeout (secs)",set_t_probeto_d:"Cap on a single TCP+TLS probe",
 set_t_fluxrot:"Flux default rotate (secs)",set_t_fluxrot_d:"Flux epoch length when not set per-tunnel",
 h1:"1 hour",h3:"3 hours",h6:"6 hours",h8:"8 hours",h12:"12 hours",h24:"24 hours",
 pending_check:"Checking…",off_word:"Off",on_word:"On",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k];for(var k in x.en)I18N.en[k]=x.en[k]})({fa:{
 pf_dest:"مقصد",
 // command palette
 pal_search:"جستجوی نود، تونل یا دستور…",pal_move:"حرکت",pal_pick:"انتخاب",pal_close:"بستن",pal_none:"موردی یافت نشد",
 pal_g_nodes:"نودها",pal_g_tuns:"تونل‌ها",pal_g_acts:"دستورها",
 pal_add_tun:"افزودن تونل",pal_agent:"بروزرسانیِ ایجنت",pal_checkall:"تستِ همهٔ تونل‌های صفحه",pal_theme:"تغییرِ تمِ روشن/تیره",
 // agent/core update page (partial)
 ag_title:"ایجنت و هسته",ag_sub:"آپدیت و ری‌استارتِ ایجنت و هستهٔ نودها از پنل، بدونِ SSH",
 ag_node_agent:"ایجنتِ نودها",ag_data_core:"هستهٔ داده",ag_fetch_git:"دریافت از گیت‌هاب",ag_file_btn:"فایلِ ایجنت",ag_push_all:"پوشِ ایجنت به همهٔ نودها",
 ag_binary:"باینری",ag_install_all:"نصبِ هسته روی همهٔ نودها",ag_search:"جستجوی نود…",ag_ready:"آمادهٔ پوش",ag_empty:"خالی",ag_no_item:"موردی نیست",
 ag_core_hint:"⚠️ دو سرِ هر تونلِ هسته باید نسخهٔ یکسان داشته باشند؛ اگر نسخهٔ یک نود را عوض کردی، نودِ طرفِ مقابل را هم به همان نسخه ببر وگرنه آن تونل قطع می‌شود.",
 ag_lbl_agent:"ایجنت",ag_lbl_core:"هسته",ag_up_avail:"آپدیت دارد",ag_uptodate:"به‌روز",ag_not_installed:"نصب نیست",
 ag_no_online:"نودِ آنلاینی نیست",ag_skipped_off:"آفلاین — رد شد",ag_fail:"ناموفق: ",ag_already:"از قبل به‌روز",ag_updated:"به‌روز شد",ag_restarting:" · در حال ری‌استارت…",
 ag_nodes_updated:" نود بروزرسانی شد",ag_pick_first:"اول یک ایجنت بارگذاری کن",ag_confirm_all:"ایجنت روی ",ag_confirm_all2:" نودِ آنلاین آپدیت و ری‌استارت شود؟",
 ag_pick_ver:"اول نسخه را انتخاب کن",ag_confirm_core:"هستهٔ نسخهٔ «",ag_confirm_core2:"» روی ",ag_confirm_core3:" نودِ آنلاین نصب و تونل‌های هسته ری‌استارت شوند؟",
 ag_installing_core:"در حال نصبِ هسته…",ag_core_already:"هسته از قبل به‌روز بود",ag_core_updated:"هسته به‌روز شد",
},en:{
 pf_dest:"target",
 pal_search:"Search a node, tunnel or command…",pal_move:"move",pal_pick:"select",pal_close:"close",pal_none:"No results",
 pal_g_nodes:"Nodes",pal_g_tuns:"Tunnels",pal_g_acts:"Commands",
 pal_add_tun:"Add tunnel",pal_agent:"Agent update",pal_checkall:"Check all tunnels on this page",pal_theme:"Toggle light/dark theme",
 ag_title:"Agent & core",ag_sub:"Update and restart node agents and cores from the panel, without SSH",
 ag_node_agent:"Node agent",ag_data_core:"Data core",ag_fetch_git:"Fetch from GitHub",ag_file_btn:"Agent file",ag_push_all:"Push agent to all nodes",
 ag_binary:"Binary",ag_install_all:"Install core on all nodes",ag_search:"Search node…",ag_ready:"Ready to push",ag_empty:"Empty",ag_no_item:"Nothing here",
 ag_core_hint:"⚠️ Both ends of a core tunnel must run the same version; if you change one node's version, move the peer node to the same version too, or that tunnel drops.",
 ag_lbl_agent:"agent",ag_lbl_core:"core",ag_up_avail:"update available",ag_uptodate:"up to date",ag_not_installed:"not installed",
 ag_no_online:"No node is online",ag_skipped_off:"Offline — skipped",ag_fail:"Failed: ",ag_already:"Already up to date",ag_updated:"Updated",ag_restarting:" · restarting…",
 ag_nodes_updated:" nodes updated",ag_pick_first:"Load an agent first",ag_confirm_all:"Update and restart the agent on ",ag_confirm_all2:" online nodes?",
 ag_pick_ver:"Pick a version first",ag_confirm_core:"Install core version \\"",ag_confirm_core2:"\\" on ",ag_confirm_core3:" online nodes and restart core tunnels?",
 ag_installing_core:"Installing core…",ag_core_already:"Core already up to date",ag_core_updated:"Core updated",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k];for(var k in x.en)I18N.en[k]=x.en[k]})({fa:{
 fmt_day:"روز",fmt_hr:"س",cipher_auto:"خودکار",cipher_none:"بدونِ رمز",
 edit_tun_t:"ویرایشِ تونل",ip_of:"آی‌پیِ ",multi_ip:"مولتی‌آی‌پی",ip_each_end:"آی‌پیِ هر سرِ تونل",
 link_ip_note1:"اگر نودی چند آی‌پی دارد، انتخاب کن تونل روی کدام آی‌پی بسته شود. تغییرِ نوع، سابنت یا آی‌پی، تونل را روی هر دو نود بازسازی می‌کند (شناسه ",link_ip_note2:" حفظ می‌شود).",
 le_port_4789:"پورتِ UDP (خالی = 4789)",le_port_auto:"پورتِ UDP (خالی = خودکار از شناسه)",
 ph_burned_manual:"سوخته (دستی)",ph_dead:"سوختهٔ دائمی",ph_suspect:"سوختهٔ موقت",ph_active:"سالم · لبهٔ فعال",ph_healthy:"سالم",
 pb_healthy:"سالم",pb_temp:"موقت",pb_dead:"دائمی",pb_burned:"سوخته",pool_empty:"خالی — یک مورد اضافه کن",
 peer_live_hd:"وضعیت زندهٔ استخر",peer_probe_btn:"تستِ همه",peer_st_active:"فعال",peer_st_rot:"در چرخش",peer_pinned:"روی این آی‌پی پین شد",peer_rotating:"این نود بین چند آی‌پی می‌چرخد — آی‌پیِ نشان‌داده‌شده، آی‌پیِ فعالِ فعلی است",peer_live_note:"آی‌پیِ سوخته طبق زمان‌بندی دوباره تست می‌شود و اگر سالم شد خودش به چرخش برمی‌گردد؛ با پین می‌توانید دستی روی یک آی‌پی سوییچ کنید.",
 peer_live_empty:"وضعیتِ زندهٔ آی‌پی‌ها و دکمهٔ پین، وقتی تونل روی نودِ به‌روز در حال اجراست این‌جا نمایش داده می‌شود. اگر تازه به‌روزرسانی کرده‌اید: نود را آپدیت کنید و بعد «ذخیره و بازسازی» را بزنید تا با هستهٔ جدید ساخته شود.",
 pa_restore:"بازگرداندن به چرخش",pa_testnow:"الان تست کن",pa_active_ip:"آی‌پیِ فعلی",pa_activate:"این را فعال کن",pa_pinning:"در حالِ فعال‌سازی…",
 flux_rotated:"چرخش انجام شد — تونل بازسازی شد",pool_make_first:"اول تونل را بساز",pool_probe_sent:"پروبِ فوری فرستاده شد",pool_edge_active:"این لبه فعال شد",
},en:{
 fmt_day:"d",fmt_hr:"h",cipher_auto:"Auto",cipher_none:"No cipher",
 edit_tun_t:"Edit tunnel",ip_of:"IP of ",multi_ip:"multi-IP",ip_each_end:"IP of each tunnel end",
 link_ip_note1:"If a node has several IPs, choose which one the tunnel binds to. Changing type, subnet or IP rebuilds the tunnel on both nodes (ID ",link_ip_note2:" is kept).",
 le_port_4789:"UDP port (empty = 4789)",le_port_auto:"UDP port (empty = auto from ID)",
 ph_burned_manual:"Burned (manual)",ph_dead:"Dead (permanent)",ph_suspect:"Suspect (temporary)",ph_active:"Healthy · active edge",ph_healthy:"Healthy",
 pb_healthy:"healthy",pb_temp:"temp",pb_dead:"dead",pb_burned:"burned",pool_empty:"Empty — add an entry",
 peer_live_hd:"Live pool status",peer_probe_btn:"Test all",peer_st_active:"Active",peer_st_rot:"In rotation",peer_pinned:"Pinned to this IP",peer_rotating:"This node rotates across several IPs — the IP shown is the currently-active one",peer_live_note:"A burned IP is retested on schedule and returns to rotation by itself when healthy; pin to switch to an IP manually.",
 peer_live_empty:"The live IP status and pin button appear here once the tunnel is running on an up-to-date node. If you just updated: update the node, then hit \\"Save & rebuild\\" so it's rebuilt with the new core.",
 pa_restore:"Restore to rotation",pa_testnow:"Test now",pa_active_ip:"Current IP",pa_activate:"Make this active",pa_pinning:"Activating…",
 flux_rotated:"Rotated — tunnel rebuilt",pool_make_first:"Create the tunnel first",pool_probe_sent:"Immediate probe sent",pool_edge_active:"This edge is now active",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k];for(var k in x.en)I18N.en[k]=x.en[k]})({fa:{
 // ---- core create/edit form + shared section builders (Gap 1)
 // subnet ranges
 snr_192:"خودکار · 192.168.x (پیشنهادی)",snr_10:"خودکار · 10.x",snr_172:"خودکار · 172.16.x",snr_custom:"دلخواه (دستی وارد کن)",
 // raw profiles
 rawp_best:"بهینه",rawp_warn:"ممکن است از NAT رد نشود",rawp_bip_m:"proto 253 · نیتیو",rawp_icmp_m:"proto 1 · شبیهِ ping",rawp_gre_m:"proto 47 · GRE",rawp_ipip_m:"proto 4 · IP-in-IP",rawp_udp_m:"proto 17 · UDP",rawp_tcp_m:"proto 6 · TCP جعلی",
 // ws / xhttp profiles
 wsp_ws_m:"وب‌سوکتِ استاندارد",wsp_xhttp_m:"GET/POST · دور زدنِ بلاکِ WS",xhm_packet_m:"چند POSTِ کوتاه · سازگارترین",xhm_grpc_m:"یک درخواستِ دوطرفه · رویِ CDN استریم",
 // flux rotation presets + shapes
 frot_600:"هر ۱۰ دقیقه (پیش‌فرض)",frot_300:"هر ۵ دقیقه",frot_1800:"هر ۳۰ دقیقه",frot_3600:"هر ۱ ساعت",
 fsh_random_n:"تصادفی",fsh_random_m:"بدونِ تقلید",fsh_quic_m:"شبیهِ HTTP/3",fsh_video_n:"ویدیوکال",fsh_video_m:"بسته‌های بزرگ",fsh_webrtc_m:"RTPِ کوچک",
 // fec presets
 fec_light:"سبک",fec_balanced:"متعادل",fec_strong:"قوی",fec_ov20:"۲۰٪ سربار",fec_ov30:"۳۰٪ سربار",fec_ov50:"۵۰٪ سربار",
 // flux section
 flux_carrier_lbl:"حاملِ flux",flux_udp_best:"اینترنت",flux_udp_m:"UDPِ واقعی · پورت می‌چرخد",flux_stun_m:"هدرِ STUN · شبیهِ تماسِ تصویری",flux_raw_warn:"فقط هم‌سگمنت / L2",flux_raw_m:"protoِ IP خام · فقط L2",
 flux_shape_lbl:"پروفایلِ شکل — شبیهِ چه ترافیکی",flux_rot_lbl:"بازهٔ چرخش",flux_rot_ph:"بازه",flux_rotate_btn:"چرخشِ الان (epoch را جلو می‌برد؛ لحظه‌ای قطع)",
 flux_note:"شکلِ سیم هر بازه <b>بی‌سیگنال</b> می‌چرخد — هر دو سر از ساعت یک epoch می‌سازند. <b>udp/stun</b> رویِ اینترنت رد می‌شوند؛ <b>raw</b> فقط هم‌سگمنت. رمزنگاری الزامی است.",
 flux_live:"شکلِ زنده",flux_carrier_word:"حامل",flux_next_pre:"چرخشِ بعدی تا",flux_next_post:"دیگر",
 // spoof section
 spoof_hd:"جعلِ آی‌پی (استتار)",spoof_decoy_t:"جعلِ مقصد (Decoy)",spoof_decoy_d:"روی سیم وانمود می‌شود ترافیک به آی‌پیِ زیر می‌رود، ولی واقعاً به سرورت می‌رسد.",spoof_decoy_ph:"آی‌پیِ طُعمه (مقصدِ جعلی) — مثلاً 185.51.200.10",
 spoof_src_t:"جعلِ مبدأ",spoof_src_d:"آی‌پیِ مبدأِ واقعی روی سیم مخفی می‌شود (اختیاری).",spoof_src_ph:"آی‌پیِ مبدأِ جعلی — مثلاً 198.51.100.9",spoof_checking:"بررسیِ امکانِ جعل روی نودها…",
 spoof_cap_ok:"<b>هر دو نود از نظرِ فنی مجازند.</b> ولی اینکه واقعاً کار کند به خروجیِ دیتاسنتر و مسیر هم بستگی دارد — این چک فقط قابلیتِ نودها را می‌سنجد، نه آن را؛ با ساختِ تونل قطعی می‌شود.",
 spoof_cap_bad_pre:"<b>غیرفعال — روی نودِ «",spoof_cap_bad_mid:"» نمی‌شود.</b> علت: ",spoof_reason_unknown:"نامشخص",spoof_cap_err:"<b>بررسی ناموفق بود.</b> نتوانستم امکانِ جعل را از نودها بپرسم.",
 // fec section
 fec_t:"تصحیحِ خطا (FEC)",fec_d:"پکت‌های گم‌شده را با پریتی و بدونِ ری‌ترنسمیت بازسازی می‌کند — برای لینکِ پُرافت/throttle. سربارِ پهنای‌باند دارد؛ فقط رو حاملِ دیتاگرامی (udp/raw/flux)، رو tcp/ws بی‌اثر.",fec_rate_lbl:"نرخِ افزونگیِ FEC",
 fec_note:"«۱۰+۳» یعنی هر ۱۰ پکتِ داده، ۳ پکتِ پریتی؛ گیرنده تا ۳ تا از هر ۱۳ تا را گم کند بازسازی می‌کند. هر دو سرِ تونل یک تنظیم می‌گیرند.",
 ds_t:"desync — بسته‌های طعمه (ضدِ DPI)",ds_d:"چند بستهٔ قلابی می‌فرستد تا ماشینِ حالتِ DPI گیج شود؛ نشستِ واقعی دست‌نخورده می‌ماند. روی raw/flux و روی tcp/ws (تزریقِ سگمنتِ TCP) — روی udp نه.",ds_mode_lbl:"حالتِ طعمه",ds_ttl_lbl:"TTL طعمه",ds_count_lbl:"تعدادِ طعمه",
 ds_note:"TTL کم = طعمه چند هاپ دوام می‌آورد و پیش از سرور می‌میرد (۱ برای رله‌ٔ کوتاه، ۳ تا ۵ برای مسیرِ اینترنتی تا DPI). چک‌سامِ خراب = سرور دورش می‌ریزد. تعداد = چند طعمه سرِ هر دست‌دهی.",
 ds_m_ttl_t:"TTL کم",ds_m_ttl_s:"می‌میرد سرِ راه",ds_m_bad_t:"چک‌سامِ خراب",ds_m_bad_s:"سرور دور می‌ریزد",ds_m_both_t:"هردو",ds_m_both_s:"ترکیبی",
 // ws toggle rows
 wstls_t:"wss (TLS به CDN)",wstls_d:"کلاینت با TLS به لبهٔ CDN وصل می‌شود؛ سرور پشتِ CDN ساده می‌ماند. برای فرانتینگ لازم است. فقط با حاملِ WS/CDN.",
 ech_t:"ECH — مخفی‌کردنِ SNI",ech_d:"نامِ دامنه را داخلِ ClientHello رمز می‌کند تا فیلترچیِ SNI نبیند کدام دامنه است. نیازمندِ wss؛ برای استخر برای هر دامنه خودکار گرفته می‌شود.",sni_t:"تقسیمِ SNI (ضدِ DPI)",sni_d:"ClientHello را روی مرزِ دو بستهٔ TCP می‌شکند تا نامِ دامنه در یک بسته کامل نباشد و DPIِ SNI-محور نتواند تطبیق دهد. مکملِ ارزانِ ECH؛ نیازمندِ wss.",sni_pos_lbl:"نقطهٔ برش (split_pos) — ۰ = خودکار (وسطِ دامنه)",disorder_t:"حالتِ disorder (ضدِ DPIِ بازسازی‌کننده)",disorder_d:"سگمنتِ اولِ ClientHello را با TTLِ پایین می‌فرستد تا در مسیر بمیرد و DPI بسته‌ها را بی‌ترتیب ببیند؛ کرنل با ارسالِ مجدد سرور را کامل می‌رساند. برای سانسورِ قوی‌تر که استریم را reassemble می‌کند.",sni_ttl_lbl:"TTLِ سگمنتِ سرْ (split_ttl) — ۰ = پیش‌فرض (۴)",sni_mode_lbl:"حالتِ تقسیم SNI",m_split_s:"دو سگمنتِ ساده",m_dis_s:"سگمنتِ سرْ با TTL پایین",m_fake_s:"ClientHelloِ جعلی (ضدِ reassembly)",
 // ws section
 ws_prof_lbl:"پروفایلِ CDN",ws_prof_note:"<b>WS</b> = وب‌سوکتِ استاندارد. <b>XHTTP</b> = جفتِ GET(دانلود)+POST(آپلود)؛ اکانت/CDNی را که وب‌سوکت را بلاک کرده دور می‌زند. هر دو با همین دامنه/wss/ECH فرانت می‌شوند.",
 xh_mode_lbl:"حالتِ xHTTP",xh_mode_note:"<b>packet-up</b> = چند POSTِ کوتاه؛ سازگارترین (حتی اگر CDN بدنه را بافر کند رد می‌شود). <b>gRPC</b> = یک درخواستِ کاملاً دوطرفه به‌شکلِ gRPCِ واقعی، تا Cloudflare با h2c به مبدأ وصل شود و به‌جای بافر <b>استریم</b> کند — بهترین گزینه رویِ Cloudflare. gRPC به <b>wss</b> نیاز دارد.",
 ws_pool_t:"استخرِ لبه (چرخش + بلک‌لیست)",ws_pool_d:"چند IP و چند دامنه؛ هسته می‌چرخد و سوخته‌ها را کنار می‌گذارد. خاموش = یک لبهٔ ثابت.",
 ws_host_lbl:"دامنهٔ فرانت (Host / SNI)",ph_cdn_domain:"مثلاً cdn.example.com",ws_edge_lbl:"آی‌پیِ لبهٔ CDN (اختیاری) — کلاینت به‌جای مبدأ به این وصل می‌شود",ph_edge_ip:"مثلاً 104.16.0.1 یا 104.16.0.1:443",ws_path_lbl:"مسیر (path)",
 ws_note:"ترافیک شبیهِ HTTPS رویِ CDN دیده می‌شود (collateral freedom). سرور را پشتِ یک CDN (مثل Cloudflare) بگذار، SSL روی Flexible، پورتِ مبدأ ۸۰. با <b>استخر</b> چند IP/دامنه بده تا بچرخد و سوخته‌ها کنار بروند.",
 // ws pool inner
 rot_3m:"هر ۳ دقیقه",rot_5m:"هر ۵ دقیقه",rot_10m:"هر ۱۰ دقیقه",rot_15m:"هر ۱۵ دقیقه",rot_30m:"هر ۳۰ دقیقه",rot_1h:"هر ۱ ساعت",rot_4h:"هر ۴ ساعت",rot_8h:"هر ۸ ساعت",rot_off_fo:"خاموش (فقط failover)",
 pool_ip_lbl:"آی‌پی‌های لبهٔ CDN",pool_sni_lbl:"دامنه‌ها (SNI)",pool_ab_t:"سوختهٔ خودکار",pool_ab_d:"لبهٔ بلاک‌شده خودکار کنار می‌رود و روی backoff دوباره تست می‌شود؛ خوب شد، خودش برمی‌گردد.",
 pool_warm_t:"لبهٔ یدکیِ گرم",pool_warm_d:"یک لبهٔ دومِ آماده در پس‌زمینه نگه می‌دارد؛ لبهٔ فعال که بمیرد، آنی و بدونِ قطعیِ محسوس سوییچ می‌شود. کمی ترافیکِ اضافهٔ ناچیز (فقط keepalive).",
 pool_bad_ip:"آی‌پیِ نامعتبر (مثلاً 104.16.0.1 یا 104.16.0.1:443)",pool_bad_dom:"دامنهٔ نامعتبر (مثلاً cdn.example.com)",pool_need_clean:"استخر به حداقل یک IP تمیز و یک دامنهٔ تمیز نیاز دارد",
 ech_need_wss_alert:"اول wss (TLS به CDN) را روشن کن — ECH داخلِ همان TLS کار می‌کند.",
 // core modal general
 roles_lbl:"نقش‌ها — کدام نود listen کند (سرور)",roles_note1:"نودِ سرور پورتِ",roles_note2:" را باز می‌کند؛ نودِ کلاینت (معمولاً پشتِ NAT) به آن وصل می‌شود.",
 srv_advice:"<b>توصیه: سرور را سمتِ خارج بگذار.</b> اگر نودِ ایران پشتِ NAT باشد یا پورتش فیلتر شود، ایران‌سرور وصل نمی‌شود. اگر آی‌پیِ عمومیِ باز داشته باشد ممکن است کار کند، ولی ورودی به ایران بیشتر فیلتر/پایش می‌شود و کم‌دوام‌تر است.",
 enc_method_lbl:"روشِ رمزنگاری",cipher_ph:"رمز",transport_lbl:"حاملِ اتصال",tr_udp_d:"دیتاگرام",tr_tcp_d:"پایدارتر",tr_raw_d:"پکتِ خام",tr_flux_d:"جهش‌پذیر",
 raw_prof_lbl:"پروفایلِ کپسوله‌سازی (raw)",raw_note:"هر دو طرف باید یک پروفایل داشته باشند. <b>bip</b> بهینه است؛ نقطهٔ طلایی یعنی ممکن است از NAT رد نشود. حاملِ raw به <b>root</b> و رمزنگاری نیاز دارد.",
 obfs_t:"استتار در برابرِ DPI",obfs_d:"حذفِ امضا · پَدینگ/جیتر · مقاومت در برابرِ probe. رمزنگاری لازم است.",
 cover_t:"پوششِ TLS (شبیهِ HTTPS)",cover_d:"ترافیک شبیهِ HTTPS دیده می‌شود و در برابرِ پروبِ فعال هم مقاوم است. فقط با حاملِ TCP.",
 cover_sni_lbl:"سایتِ پوشش (SNI) — الزامی",cover_sni_ph:"مثلاً یک سایتِ HTTPSِ واقعی و محبوب",
 cover_sni_note1:"سرور برای هر اتصالِ ناشناس (پروب/فیلترچی) <b>واقعاً به این سایت وصل می‌شود</b> و ترافیک را به آن پراکسی می‌کند، پس پروب گواهیِ اصلیِ همان سایت را می‌بیند (مقاوم در برابرِ پروبِ فعال). پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد — ترجیحاً روی یک CDNِ بزرگ.",
 cover_sni_note2:"سرور پروب‌های ناشناس را <b>واقعاً به این سایت وصل و پراکسی می‌کند</b>، پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد (ترجیحاً روی CDNِ بزرگ).",
 gso_t:"شتاب‌دهیِ GSO/GRO",gso_d:"عبورِ حجیم را سریع‌تر می‌کند (پکت‌های بزرگ، syscallِ کمتر). فقط لینوکس؛ اگر پشتیبانی نشود بی‌اثر است.",
 dead_after_lbl:"مهلتِ تشخیصِ قطعی / self-heal (ثانیه)",dead_after_ph:"خالی=خودکار (~۳×keepalive)",dead_after_note:"اگر این‌قدر ثانیه هیچ فریمِ معتبری نیاید، حامل «مرده» فرض و تونل دوباره برقرار/failover می‌شود. کوچک‌تر=heal سریع‌تر. خالی=پیش‌فرض. بازهٔ ۱۰ تا ۳۰۰؛ داخلی حداقل ۲×keepalive می‌شود (برای مهلتِ خیلی کوتاه، keepalive را هم کم کن).",
 core_range_lbl:"سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه)",core_port_lbl:"پورت (خالی=خودکار · می‌توانی 443 بگذاری)",core_port_lbl2:"پورت (می‌توانی 443)",core_subnet_lbl:"سابنتِ داخلی",
 core_edit_note:"ذخیره، تونل را روی هر دو نود از نو می‌سازد (لحظه‌ای قطع می‌شود).",ph_subnet:"مثلا 192.168.99.0/24",
 role_server_word:"سرور",role_client_word:"کلاینت",ip_multi_hint:"(چند آی‌پی دارد — یکی را برای تونل انتخاب کن)",
 port_flux_ph:"flux پورت ثابت ندارد",port_raw_ph:"raw پورت ندارد",port_ws_ph:"۸۰ (کلادفلر Flexible)",
},en:{
 snr_192:"Auto · 192.168.x (recommended)",snr_10:"Auto · 10.x",snr_172:"Auto · 172.16.x",snr_custom:"Custom (enter manually)",
 rawp_best:"best",rawp_warn:"may not pass through NAT",rawp_bip_m:"proto 253 · native",rawp_icmp_m:"proto 1 · ping-like",rawp_gre_m:"proto 47 · GRE",rawp_ipip_m:"proto 4 · IP-in-IP",rawp_udp_m:"proto 17 · UDP",rawp_tcp_m:"proto 6 · fake TCP",
 wsp_ws_m:"standard WebSocket",wsp_xhttp_m:"GET/POST · bypasses WS blocks",xhm_packet_m:"short POSTs · most compatible",xhm_grpc_m:"one bidi request · streams over CDN",
 frot_600:"Every 10 min (default)",frot_300:"Every 5 min",frot_1800:"Every 30 min",frot_3600:"Every 1 hour",
 fsh_random_n:"Random",fsh_random_m:"no mimicry",fsh_quic_m:"HTTP/3-like",fsh_video_n:"Video call",fsh_video_m:"large packets",fsh_webrtc_m:"small RTP",
 fec_light:"Light",fec_balanced:"Balanced",fec_strong:"Strong",fec_ov20:"20% overhead",fec_ov30:"30% overhead",fec_ov50:"50% overhead",
 flux_carrier_lbl:"Flux carrier",flux_udp_best:"internet",flux_udp_m:"real UDP · rotating port",flux_stun_m:"STUN header · looks like a video call",flux_raw_warn:"same-segment / L2 only",flux_raw_m:"raw IP proto · L2 only",
 flux_shape_lbl:"Shape profile — mimic which traffic",flux_rot_lbl:"Rotation interval",flux_rot_ph:"interval",flux_rotate_btn:"Rotate now (advances the epoch; brief drop)",
 flux_note:"The wire shape rotates <b>signal-free</b> each interval — both ends derive one epoch from the clock. <b>udp/stun</b> traverse the internet; <b>raw</b> is same-segment only. Encryption is required.",
 flux_live:"Live shape",flux_carrier_word:"carrier",flux_next_pre:"next rotation in",flux_next_post:"",
 spoof_hd:"IP spoofing (camouflage)",spoof_decoy_t:"Destination spoof (Decoy)",spoof_decoy_d:"On the wire it looks like traffic goes to the IP below, but it really reaches your server.",spoof_decoy_ph:"Decoy (fake destination) IP — e.g. 185.51.200.10",
 spoof_src_t:"Source spoof",spoof_src_d:"Hides the real source IP on the wire (optional).",spoof_src_ph:"Fake source IP — e.g. 198.51.100.9",spoof_checking:"Checking spoof capability on the nodes…",
 spoof_cap_ok:"<b>Both nodes are technically capable.</b> But whether it actually works also depends on the datacenter egress and the path — this check only measures node capability, not that; building the tunnel confirms it.",
 spoof_cap_bad_pre:"<b>Disabled — not possible on node “",spoof_cap_bad_mid:"”.</b> Reason: ",spoof_reason_unknown:"unknown",spoof_cap_err:"<b>Check failed.</b> Could not query spoof capability from the nodes.",
 fec_t:"Error correction (FEC)",fec_d:"Rebuilds lost packets with parity and no retransmit — for lossy/throttled links. Costs some bandwidth; only on datagram carriers (udp/raw/flux), no effect on tcp/ws.",fec_rate_lbl:"FEC redundancy rate",
 fec_note:"“10+3” means for every 10 data packets, 3 parity packets; the receiver can lose up to 3 of every 13 and still rebuild. Both tunnel ends use the same setting.",
 ds_t:"Fake-packet desync (anti-DPI)",ds_d:"Emits a few decoy packets to mis-sync a stateful DPI; the real session is untouched. On raw/flux and on tcp/ws (injected TCP segments) — not plain udp.",ds_mode_lbl:"Decoy mode",ds_ttl_lbl:"Decoy TTL",ds_count_lbl:"Decoy count",
 ds_note:"Low TTL = the decoy survives a few hops and dies before the server (1 for a short relay, 3–5 for an internet path to the DPI). Bad checksum = the server drops it. Count = how many decoys per handshake.",
 ds_m_ttl_t:"Low TTL",ds_m_ttl_s:"dies en route",ds_m_bad_t:"Bad checksum",ds_m_bad_s:"server drops it",ds_m_both_t:"Both",ds_m_both_s:"combined",
 wstls_t:"wss (TLS to CDN)",wstls_d:"The client connects to the CDN edge over TLS; the server stays plain behind the CDN. Required for fronting. WS/CDN carrier only.",
 ech_t:"ECH — hide the SNI",ech_d:"Encrypts the domain name inside the ClientHello so an SNI filter cannot see which domain it is. Requires wss; for a pool it is fetched automatically per domain.",sni_t:"SNI fragmentation (anti-DPI)",sni_d:"Splits the ClientHello across two TCP segments so no single packet holds the full domain name and an SNI-based DPI cannot match it. A cheap complement to ECH; requires wss.",sni_pos_lbl:"Split position (split_pos) — 0 = auto (middle of the domain)",disorder_t:"disorder mode (anti-reassembly DPI)",disorder_d:"Sends the first ClientHello segment at a low TTL so it dies in transit and the DPI sees the packets out of order; the kernel retransmits it so the server still completes. For a stronger DPI that reassembles the stream.",sni_ttl_lbl:"Head-segment TTL (split_ttl) — 0 = default (4)",sni_mode_lbl:"SNI fragmentation mode",m_split_s:"two plain segments",m_dis_s:"low-TTL head",m_fake_s:"decoy ClientHello (anti-reassembly)",
 ws_prof_lbl:"CDN profile",ws_prof_note:"<b>WS</b> = standard WebSocket. <b>XHTTP</b> = a GET(download)+POST(upload) pair; bypasses an account/CDN that blocks WebSocket. Both are fronted with the same domain/wss/ECH.",
 xh_mode_lbl:"xHTTP mode",xh_mode_note:"<b>packet-up</b> = short POSTs; most compatible (works even if the CDN buffers the body). <b>gRPC</b> = one fully bidirectional request shaped as real gRPC, so Cloudflare connects to the origin over h2c and <b>streams</b> instead of buffering — the best option on Cloudflare. gRPC requires <b>wss</b>.",
 ws_pool_t:"Edge pool (rotation + blocklist)",ws_pool_d:"Several IPs and domains; the core rotates and drops burned ones. Off = one fixed edge.",
 ws_host_lbl:"Fronting domain (Host / SNI)",ph_cdn_domain:"e.g. cdn.example.com",ws_edge_lbl:"CDN edge IP (optional) — the client connects to this instead of the origin",ph_edge_ip:"e.g. 104.16.0.1 or 104.16.0.1:443",ws_path_lbl:"Path",
 ws_note:"Traffic looks like HTTPS over the CDN (collateral freedom). Put the server behind a CDN (e.g. Cloudflare), SSL on Flexible, origin port 80. With a <b>pool</b>, give several IPs/domains to rotate and drop burned ones.",
 rot_3m:"Every 3 min",rot_5m:"Every 5 min",rot_10m:"Every 10 min",rot_15m:"Every 15 min",rot_30m:"Every 30 min",rot_1h:"Every 1 hour",rot_4h:"Every 4 hours",rot_8h:"Every 8 hours",rot_off_fo:"Off (failover only)",
 pool_ip_lbl:"CDN edge IPs",pool_sni_lbl:"Domains (SNI)",pool_ab_t:"Auto-burn",pool_ab_d:"A blocked edge is dropped automatically and retested on a backoff; when it recovers it comes back on its own.",
 pool_warm_t:"Warm standby edge",pool_warm_d:"Keeps a second edge ready in the background; when the active edge dies it switches instantly with no noticeable drop. Slight extra traffic (keepalive only).",
 pool_bad_ip:"Invalid IP (e.g. 104.16.0.1 or 104.16.0.1:443)",pool_bad_dom:"Invalid domain (e.g. cdn.example.com)",pool_need_clean:"The pool needs at least one clean IP and one clean domain",
 ech_need_wss_alert:"Turn on wss (TLS to CDN) first — ECH works inside that same TLS.",
 roles_lbl:"Roles — which node listens (server)",roles_note1:"The server node opens the",roles_note2:" port; the client node (usually behind NAT) connects to it.",
 srv_advice:"<b>Recommendation: put the server abroad.</b> If the Iran node is behind NAT or its port is filtered, an Iran-side server will not be reachable. With an open public IP it may work, but inbound to Iran is more heavily filtered/monitored and less durable.",
 enc_method_lbl:"Encryption method",cipher_ph:"cipher",transport_lbl:"Connection carrier",tr_udp_d:"datagram",tr_tcp_d:"steadier",tr_raw_d:"raw packet",tr_flux_d:"polymorphic",
 raw_prof_lbl:"Encapsulation profile (raw)",raw_note:"Both ends must use the same profile. <b>bip</b> is optimal; a gold dot means it may not pass through NAT. The raw carrier needs <b>root</b> and encryption.",
 obfs_t:"DPI camouflage",obfs_d:"Strips signatures · padding/jitter · probe resistance. Encryption required.",
 cover_t:"TLS cover (looks like HTTPS)",cover_d:"Traffic looks like HTTPS and resists active probing too. TCP carrier only.",
 cover_sni_lbl:"Cover site (SNI) — required",cover_sni_ph:"e.g. a real, popular HTTPS site",
 cover_sni_note1:"For any anonymous connection (probe/censor) the server <b>actually connects to this site</b> and proxies traffic to it, so a probe sees that site\\'s real certificate (active-probe resistant). So it must be a <b>real, reachable, unblocked, popular HTTPS site</b> — preferably on a large CDN.",
 cover_sni_note2:"The server <b>actually connects and proxies</b> anonymous probes to this site, so it must be a <b>real, reachable, unblocked, popular HTTPS site</b> (preferably on a large CDN).",
 gso_t:"GSO/GRO acceleration",gso_d:"Speeds up bulk transfer (large packets, fewer syscalls). Linux only; no effect if unsupported.",
 dead_after_lbl:"Dead-detection / self-heal deadline (seconds)",dead_after_ph:"empty = auto (~3×keepalive)",dead_after_note:"If no authenticated frame arrives for this many seconds, the carrier is declared dead and the tunnel re-establishes / fails over. Smaller = faster heal. Empty = default. Range 10–300; internally raised to at least 2×keepalive (for a very short deadline, lower keepalive too).",
 core_range_lbl:"Local subnet (private range — auto by ID)",core_port_lbl:"Port (empty = auto · you can set 443)",core_port_lbl2:"Port (you can use 443)",core_subnet_lbl:"Internal subnet",
 core_edit_note:"Saving rebuilds the tunnel on both nodes (brief drop).",ph_subnet:"e.g. 192.168.99.0/24",
 role_server_word:"server",role_client_word:"client",ip_multi_hint:"(has several IPs — pick one for the tunnel)",
 port_flux_ph:"flux has no fixed port",port_raw_ph:"raw has no port",port_ws_ph:"80 (Cloudflare Flexible)",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k];for(var k in x.en)I18N.en[k]=x.en[k]})({fa:{
 pct:"٪",list_sep:"، ",unit_kb:"کیلوبایت",unit_mb_full:"مگابایت",app_title:"tnl · کنترل فلیت",
 ip_toggle_hint:"بزن تا بینِ نامِ نود و اینترفیس جابه‌جا شود",
 // ---- node-add modal
 nadd_auto:"خودکار",nadd_manual:"دستی",nadd_title:"افزودنِ نود",
 nadd_autonote:"مشخصاتِ SSHِ سرورِ نود را بده؛ پنل خودش وارد می‌شود، ایجنت را نصب می‌کند، توکن می‌سازد و نود را وصل می‌کند.",
 nadd_node_name:"نامِ نود",nadd_srv_ip:"آی‌پیِ سرور",nadd_ssh_port:"پورتِ SSH",nadd_ssh_user:"کاربرِ SSH",
 nadd_agent_port:"پورتِ ایجنت",nadd_ctrl_proxy:"پروکسیِ کنترل (اختیاری)",nadd_ssh_auth:"احرازِ هویتِ SSH",
 nadd_pass:"رمز",nadd_privkey:"کلیدِ خصوصی",nadd_pass_ph:"رمزِ SSH سرور",
 nadd_pass_hint:"رمزِ SSH سرور — ذخیره نمی‌شود، فقط لحظهٔ نصب استفاده می‌شود.",
 nadd_key_hint:"کلیدِ خصوصیِ SSH — امن‌تر از رمز؛ به sshpass هم نیازی نیست.",
 nadd_manual_name:"نام",nadd_manual_host:"هاست / آی‌پی",nadd_agent_port2:"پورت agent",nadd_node_tok:"توکن نود",
 nadd_manual_proxy:"پروکسیِ کنترل (اختیاری) — پنل از این پروکسی به این نود وصل می‌شود",
 nadd_install_connect:"نصب و اتصالِ خودکار",nadd_add_connect:"افزودن و اتصال",
 nadd_pass_word:"رمزِ SSH",nadd_is_required:" لازم است",nadd_need_name_ip:"نام و آی‌پیِ سرور لازم است",
 // ---- live install steps
 inst_ssh:"اتصالِ SSH",inst_download:"دانلودِ ایجنت",inst_service:"نصب و راه‌اندازیِ سرویس",inst_register:"ثبت و اتصال در پنل",
 inst_connecting:"در حالِ اتصال…",inst_waiting:"در انتظار…",inst_installing:"در حالِ نصب…",inst_done:"انجام شد",
 inst_status_notfound:"وضعیتِ نصب یافت نشد",inst_panel_lost:"ارتباط با پنل قطع شد",inst_node_installed:"نود نصب شد",inst_retry:"تلاشِ مجدد",
 // ---- classic tunnel create form
 custom_subnet_ph:"مثلا 192.168.99.0/24 یا fd00:99::/64",ttype_port_ph:"مثلا 51820",
 ttype_port_auto_lbl:"پورتِ UDP (اختیاری — خالی = خودکار از شناسه)",
 ttype_l2_note:"روی UDP سوار می‌شود؛ برای دورزدنِ فیلتر می‌توانی پورتِ دلخواه بگذاری.",
 ttype_vxlan_lbl:"پورتِ UDP (خالی = 4789)",
 ttype_vxlan_note:"پورتِ استانداردِ VXLAN؛ برای دورزدنِ فیلتر می‌توانی عوضش کنی (مثلاً 443).",
 ttype_ipsec_note:"رمزنگاری‌شده (ESP). کلید خودکار ساخته و امن به هر دو سر داده می‌شود — بدونِ دیمنِ خارجی.",
 // ---- agent / core staging
 ag_word_agent:"ایجنت",ag_word_core:"هسته",ag_pick_version:"انتخاب نسخه",err_github:"ناموفق — پنل به گیت‌هاب دسترسی دارد؟",
 ag_no_agent_loaded:"هنوز ایجنتی بارگذاری نشده — «دریافت از گیت‌هاب» یا «فایلِ ایجنت».",
 ag_no_core_staged:"هنوز هسته‌ای روی پنل دانلود نشده — «دریافت از گیت‌هاب» را بزن تا آماده‌ی پوش شود.",
 cor_downloading:"در حال دانلودِ هسته روی پنل…",cor_staged_pre:"هستهٔ «",cor_staged_post:"» روی پنل آماده شد",
 cor_pushing:"در حال پوشِ هستهٔ آماده…",cor_reading_upload:"در حال خواندن و آپلودِ باینری…",cor_read_fail:"خواندنِ فایل ناموفق",
 cor_bin_saved_pre:"باینری ذخیره شد: ",cor_bin_saved_post:" — «نصبِ همه» را بزن یا از منوی هر نود",
 ag_pick_file_first:"اول فایلِ ایجنت را انتخاب کن",ag_checking_saving:"در حال بررسی و ذخیره…",ag_saved_pre:"ذخیره شد: v",
 ag_fetching_git:"در حال دریافت از گیت‌هاب…",ag_fetched_pre:"دریافت شد: v",ag_fetched_post:" — حالا «پوشِ همه» را بزن",
},en:{
 pct:"%",list_sep:", ",unit_kb:"KB",unit_mb_full:"MB",app_title:"tnl · Fleet control",
 ip_toggle_hint:"Tap to toggle between node name and interface",
 nadd_auto:"Automatic",nadd_manual:"Manual",nadd_title:"Add node",
 nadd_autonote:"Enter the node server's SSH details; the panel logs in itself, installs the agent, creates a token and connects the node.",
 nadd_node_name:"Node name",nadd_srv_ip:"Server IP",nadd_ssh_port:"SSH port",nadd_ssh_user:"SSH user",
 nadd_agent_port:"Agent port",nadd_ctrl_proxy:"Control proxy (optional)",nadd_ssh_auth:"SSH authentication",
 nadd_pass:"Password",nadd_privkey:"Private key",nadd_pass_ph:"Server SSH password",
 nadd_pass_hint:"Server SSH password — not stored, used only during installation.",
 nadd_key_hint:"SSH private key — safer than a password; sshpass is not needed either.",
 nadd_manual_name:"Name",nadd_manual_host:"Host / IP",nadd_agent_port2:"Agent port",nadd_node_tok:"Node token",
 nadd_manual_proxy:"Control proxy (optional) — the panel connects to this node through it",
 nadd_install_connect:"Install & auto-connect",nadd_add_connect:"Add & connect",
 nadd_pass_word:"SSH password",nadd_is_required:" is required",nadd_need_name_ip:"Server name and IP are required",
 inst_ssh:"SSH connection",inst_download:"Agent download",inst_service:"Install & start service",inst_register:"Register & connect in panel",
 inst_connecting:"Connecting…",inst_waiting:"Waiting…",inst_installing:"Installing…",inst_done:"Done",
 inst_status_notfound:"Install status not found",inst_panel_lost:"Lost connection to the panel",inst_node_installed:"Node installed",inst_retry:"Retry",
 custom_subnet_ph:"e.g. 192.168.99.0/24 or fd00:99::/64",ttype_port_ph:"e.g. 51820",
 ttype_port_auto_lbl:"UDP port (optional — empty = auto from ID)",
 ttype_l2_note:"Runs over UDP; you can set a custom port to bypass filtering.",
 ttype_vxlan_lbl:"UDP port (empty = 4789)",
 ttype_vxlan_note:"The standard VXLAN port; you can change it to bypass filtering (e.g. 443).",
 ttype_ipsec_note:"Encrypted (ESP). A key is auto-generated and securely delivered to both ends — no external daemon.",
 ag_word_agent:"Agent",ag_word_core:"Core",ag_pick_version:"Select version",err_github:"Failed — does the panel have GitHub access?",
 ag_no_agent_loaded:"No agent loaded yet — “Fetch from GitHub” or “Agent file”.",
 ag_no_core_staged:"No core downloaded on the panel yet — click “Fetch from GitHub” to stage it for push.",
 cor_downloading:"Downloading the core onto the panel…",cor_staged_pre:"Core “",cor_staged_post:"” is staged on the panel",
 cor_pushing:"Pushing the staged core…",cor_reading_upload:"Reading and uploading the binary…",cor_read_fail:"Failed to read the file",
 cor_bin_saved_pre:"Binary saved: ",cor_bin_saved_post:" — click “Install all” or use each node's menu",
 ag_pick_file_first:"Select the agent file first",ag_checking_saving:"Checking and saving…",ag_saved_pre:"Saved: v",
 ag_fetching_git:"Fetching from GitHub…",ag_fetched_pre:"Fetched: v",ag_fetched_post:" — now click “Push to all”",
}});
function T(k){var d=I18N[LANG]||{};if(k in d)return d[k];if(k in I18N.fa)return I18N.fa[k];return k}
// ---- backend error translator (Gap 2): backend raises Persian; translate the STATIC ones on the
// client for the EN locale. Unmatched messages (interpolated / dynamic) fall back to the original.
var ERR={
 "حالت باید auto یا alert باشد":"Mode must be auto or alert",
 "رمزِ SSH یا کلیدِ خصوصی لازم است":"SSH password or private key is required",
 "نود پیدا نشد":"Node not found",
 "کد خالی است":"The code is empty",
 "فایل بیش از حد بزرگ است":"File is too large",
 "این فایل ایجنتِ نود نیست":"This file is not the node agent",
 "نسخهٔ ایجنت در کد پیدا نشد":"Agent version not found in the code",
 "فایلِ دریافتی خالی است":"The fetched file is empty",
 "فایلِ دریافتی بیش از حد بزرگ است":"The fetched file is too large",
 "فایلِ دریافتی ایجنتِ نود نیست":"The fetched file is not the node agent",
 "نسخهٔ ایجنت در کدِ دریافتی پیدا نشد":"Agent version not found in the fetched code",
 "ابتدا یک ایجنت بارگذاری کنید":"Load an agent first",
 "فایل base64 نامعتبر است":"Invalid base64 file",
 "فایل خیلی کوچک است — این باینریِ هسته نیست":"File is too small — this is not the core binary",
 "این یک باینریِ ELF لینوکسی نیست":"This is not a Linux ELF binary",
 "نسخهٔ هسته نامعتبر است — فقط حروف/عدد و کاراکترهای «._+-» مجاز است":"Invalid core version — only letters/digits and the characters “._+-” are allowed",
 "معماریِ نامعتبر — فقط amd64 یا arm64 مجاز است":"Invalid architecture — only amd64 or arm64 allowed",
 "هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن":"No core is staged on the panel — download a version first",
 "هیچ باینریِ سفارشی‌ای بارگذاری نشده":"No custom binary has been uploaded",
 "آی‌پیِ مبدأِ جعلی نامعتبر است (باید IPv4 باشد)":"Invalid fake source IP (must be IPv4)",
 "آی‌پیِ طُعمه (مقصد) نامعتبر است (باید IPv4 باشد)":"Invalid decoy (destination) IP (must be IPv4)",
 "حاملِ flux به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)":"The flux carrier requires encryption (do not set cipher to “none”)",
 "حاملِ flux نامعتبر است (udp / stun / raw)":"Invalid flux carrier (udp / stun / raw)",
 "بازهٔ چرخشِ flux باید بین ۱۰ تا ۸۶۴۰۰ ثانیه باشد":"The flux rotation interval must be between 10 and 86400 seconds",
 "پروفایلِ شکلِ flux نامعتبر است":"Invalid flux shape profile",
 "مقادیرِ FEC نامعتبر است (داده و پریتی هر کدام ≥۱، مجموع ≤۲۵۵)":"Invalid FEC values (data and parity each ≥1, sum ≤255)",
 "دامنهٔ WebSocket (ws_host) نامعتبر است":"Invalid WebSocket domain (ws_host)",
 "مسیرِ WebSocket (ws_path) نامعتبر است (باید با / شروع شود)":"Invalid WebSocket path (ws_path) (must start with /)",
 "برای wss (TLS به CDN) باید دامنه (ws_host) را وارد کنی":"For wss (TLS to CDN) you must enter the domain (ws_host)",
 "آدرسِ لبهٔ CDN (edge_ip) نامعتبر است":"Invalid CDN edge address (edge_ip)",
 "ECH به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن":"ECH requires wss — turn on wss (TLS to CDN) first",
 "استخر به حداقل یک IP تمیز و یک دامنهٔ تمیز نیاز دارد (سوخته‌ها کافی نیستند)":"The pool needs at least one clean IP and one clean domain (burned ones do not count)",
 "استخر خیلی بزرگ است (حداکثر ۶۴)":"The pool is too large (max 64)",
 "مسیر (path) نامعتبر است":"Invalid path",
 "آی‌پیِ دو سرِ تونل یکی است؛ برای هر طرف یک آی‌پیِ متفاوت انتخاب کن":"Both tunnel ends have the same IP; pick a different IP for each end",
 "سابنت باید پیشوند داشته باشد — مثلاً 192.168.9.0/24":"The subnet must have a prefix — e.g. 192.168.9.0/24",
 "پورتِ UDP خارج از محدوده است (۱ تا ۶۵۵۳۵)":"UDP port is out of range (1 to 65535)",
 "روشِ رمزنگاری نامعتبر است":"Invalid encryption method",
 "حاملِ اتصال نامعتبر است":"Invalid connection carrier",
 "حاملِ raw به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)":"The raw carrier requires encryption (do not set cipher to “none”)",
 "پروفایلِ raw نامعتبر است":"Invalid raw profile",
 "استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)":"Camouflage requires encryption (do not set cipher to “none”)",
 "پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)":"TLS cover requires encryption (do not set cipher to “none”)",
 "دامنهٔ نمایشی (SNI) نامعتبر است":"Invalid display domain (SNI)",
 "برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی":"For TLS cover you must enter the display domain (SNI)",
 "شناسهٔ تونل خارج از محدوده است (۱ تا ۲۵۴)":"Tunnel ID is out of range (1 to 254)",
 "نامِ پورت‌فوروارد نامعتبر است — فقط حروف/عدد و «._-» (۱ تا ۴۰ کاراکتر) مجاز است":"Invalid port-forward name — only letters/digits and “._-” (1 to 40 characters) allowed",
 "این لینک استخرِ لبه ندارد":"This link has no edge pool",
 "نودِ کلاینت پیدا نشد":"Client node not found",
 "kind باید ip یا sni باشد":"kind must be ip or sni",
 "dim باید ip یا sni باشد":"dim must be ip or sni",
 "چرخشِ الان فقط برای لینکِ h-flux است":"Rotate-now is only for h-flux links",
 "پروب ناموفق بود":"Probe failed",
 "انتخاب ناموفق بود":"Selection failed",
 "چرخش ناموفق بود":"Rotation failed",
 "در حال بررسی…":"Checking…",
 "ناموفق — پنل به گیت‌هاب دسترسی دارد؟":"Failed — does the panel have GitHub access?",
 "ناموفق":"Failed"
};
function terr(msg){return (LANG==='en'&&msg&&ERR[msg])?ERR[msg]:msg}
function paintThemeBtns(){var d=document.body.classList.contains('dark');var b1=el('thbtn');if(b1)b1.innerHTML=ic(d?'sun':'moon')+' '+esc(T('theme'));var b2=el('thbtn2');if(b2)b2.innerHTML=ic(d?'sun':'moon')}
function paintNav(){try{document.title=T('app_title')}catch(e){}var n=document.getElementById('nav');if(n)n.querySelectorAll('.navi').forEach(function(p){var s=p.querySelector('.nlbl');if(s)s.textContent=T('nav_'+p.dataset.t)});var bs=el('brandsub');if(bs)bs.textContent=T('brand_sub');var fo=el('foutbtn');if(fo){var fl=fo.querySelector('.nlbl');if(fl)fl.textContent=T('nav_logout')}paintThemeBtns()}
function applyLang(lang){if(lang!='fa'&&lang!='en')lang='fa';LANG=lang;try{localStorage.setItem('tnl_lang',lang)}catch(e){}
 var dir=(lang=='fa')?'rtl':'ltr';document.documentElement.lang=lang;document.documentElement.dir=dir;try{document.body.dir=dir}catch(e){}
 paintNav();render();updateSidebar()}
(function(){var dir=(LANG=='fa')?'rtl':'ltr';document.documentElement.lang=LANG;document.documentElement.dir=dir;try{document.body.dir=dir}catch(e){}})();
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
function fmtup(s){s=+s||0;var d=Math.floor(s/86400),h=Math.floor(s%86400/3600);return d+T('fmt_day')+' '+h+T('fmt_hr')}
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
function toggleTheme(){var d=document.body.classList.toggle('dark');try{localStorage.setItem('tnl_dark',d?'1':'')}catch(e){}paintThemeBtns();refresh()}
try{if(localStorage.getItem('tnl_dark'))document.body.classList.add('dark')}catch(e){}
paintIcons();paintNav();

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
function nodeIps(id){var n=NODES.find(function(x){return x.id==id});if(!n||!n.info||!n.info.ips)return [];
 var out=[],ips=n.info.ips;Object.keys(ips).forEach(function(k){(ips[k]||[]).forEach(function(ip){if(out.indexOf(ip)<0)out.push(ip)})});return out}
function ipItems(ips){return ips.map(function(x){return {v:x,label:x}})}

var cur='overview',NODES=[],FLEET=[],HIST=[],FRXHIST=[],FTXHIST=[],PF=[],TT=0,editingId=null,EDID=null,selTargets={},SEL={},SSI={},SSCB={},CHK={},CHECKING=0,UPWIN=1,EVSEQ=0,UIV=2000,EDGEV={};   // UIV = live-refresh interval (ms); EDGEV = last active edge per link (anti-flicker)
var LIM=25,PG={nodes:0,tunnels:0,portfw:0,agent:0,core:0},QRY={nodes:'',tunnels:'',portfw:'',agent:'',core:''},TOT={nodes:0,tunnels:0,portfw:0,agent:0,core:0},SEARCH_T=0,createTries=0,pfTries=0,AGMETA=null,PAL=null,PALIDX=0,PALITEMS=[],PALDATA={nodes:[],tuns:[]};
function CORE_CIPHERS(){return [{v:'auto',label:T('cipher_auto')},{v:'aes-256-gcm',label:'aes-256-gcm'},{v:'aes-128-gcm',label:'aes-128-gcm'},{v:'chacha20-poly1305',label:'chacha20-poly1305'},{v:'xchacha20-poly1305',label:'xchacha20-poly1305'},{v:'none',label:T('cipher_none')}]}
var TYPEITEMS=[{v:'vxlan',label:'VXLAN'},{v:'gre',label:'GRE'},{v:'sit',label:'SIT (IPv6)'},{v:'ipip',label:'IPIP'},{v:'l2tpv3',label:'L2TPv3'},{v:'fou',label:'IPIP-over-FOU'},{v:'ipsec',label:'IPsec'}];
function SUBNETRANGES(){return [{v:'192.168',label:T('snr_192')},{v:'10',label:T('snr_10')},{v:'172.16',label:T('snr_172')},{v:'custom',label:T('snr_custom')}]}
var SUBNETRANGES2=[{v:'192.168',label:'192.168.x'},{v:'10',label:'10.x'},{v:'172.16',label:'172.16.x'}];
document.querySelectorAll('#nav .navi').forEach(function(p){p.onclick=function(){if(p.dataset.t=='logout'){logout();return}cur=p.dataset.t;drawer(false);render()}});
function setnav(){document.querySelectorAll('#nav .navi').forEach(function(p){p.classList.toggle('on',p.dataset.t==cur)})}
function drawer(open){document.body.classList.toggle('navopen',!!open)}
async function updateSidebar(){var s=await j('summary').catch(function(){return{}});
 setT('ct_nodes',num(s.nodes_total));setT('ct_tunnels',num(s.links));setT('ct_portfw',num(s.portfw));setT('ct_core',num(s.core));
 setT('ct_logs',num(s.log_count));   // ALWAYS the total number of logs (like the other nav counts)
 if(s.ui_interval)UIV=Math.max(300,Math.round(num(s.ui_interval)*1000));   // live-refresh cadence, from settings
 // separate UNREAD badge (accent color): events logged since the operator last opened the log page.
 EVSEQ=num(s.ev_seq);var seen=num(getLS('tnl_logs_seen'));
 if(cur=='logs'){seen=EVSEQ;setLS('tnl_logs_seen',EVSEQ)}
 var un=EVSEQ-seen;setUnread(un);
}
function setUnread(un){var e=el('ct_logs_un');if(!e)return;e.textContent=un>0?(un>99?'99+':String(un)):'';e.style.display=un>0?'':'none'}
function getLS(k){try{return localStorage.getItem(k)||''}catch(e){return ''}}
function setLS(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function markLogsSeen(){setLS('tnl_logs_seen',EVSEQ);setUnread(0)}  // clear ONLY the unread badge; the total stays

// ===== styled single-select dropdown (same look as the node/target lists) =====
// items:[{v,label,sub}]  key:unique id  cb:optional fn-name called after a pick
function ssHTML(key,items,sel,ph,cb){SSI[key]=items;SSCB[key]=cb||'';
 if(sel==null&&items.length)sel=items[0].v;SEL[key]=sel;
 var cur=items.filter(function(x){return String(x.v)==String(sel)})[0];
 return '<button type="button" class="msbtn'+(cur?'':' ph')+'" id="ssb_'+key+'" onclick="ssToggle(\\''+key+'\\')"><span id="sst_'+key+'">'+(cur?esc(cur.label):esc(_ssph(ph)))+'</span><span class="cv">'+ic('chev')+'</span></button>'}
function _ssph(ph){return ph||T('select')}
function ssRow(key,it){return '<div class="msrow'+(String(it.v)==String(SEL[key])?' sel':'')+'" data-v="'+esc(it.v)+'" onclick="ssPick(\\''+key+'\\',this)"><span class="mscheck"></span><span>'+esc(it.label)+'</span>'+(it.sub?'<span class="muted mono" style="font-size:11px;margin-inline-start:auto">'+esc(it.sub)+'</span>':'')+'</div>'}
var SS_OV={};
function ssToggle(key){var items=SSI[key]||[];if(!items.length)return;  // open the list as a centered popup (scrolls; search for long lists)
 var search=items.length>10?'<input class="search sspopq" placeholder="'+esc(T('search'))+'" oninput="msFilter(this)" autocomplete="off">':'';
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
 ov.innerHTML='<div class="modal"><div class="mtext"></div><div class="mbtns"><button class="primary myes"></button><button class="ghost mno">'+esc(T('cancel'))+'</button></div></div>';
 ov.querySelector('.mtext').textContent=msg;ov.querySelector('.myes').textContent=yes||T('confirm_del');
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
 var h='<button class="pbtn" '+(PG[kind]<=0?'disabled':'')+' onclick="goPage(\\''+kind+'\\',-1)">'+esc(T('prev'))+'</button><span class="pinfo">'+esc(T('page'))+' '+cur+' '+esc(T('of'))+' '+pages+' · '+total+' '+esc(T('items'))+'</span><button class="pbtn" '+(cur>=pages?'disabled':'')+' onclick="goPage(\\''+kind+'\\',1)">'+esc(T('next'))+'</button>';
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
 if(t=='vxlan')w.innerHTML='<label>'+esc(T('le_port_4789'))+'</label><input id="le_port_'+id+'" inputmode="numeric" placeholder="4789" value="'+esc(pre)+'">';
 else if(t=='l2tpv3'||t=='fou')w.innerHTML='<label>'+esc(T('le_port_auto'))+'</label><input id="le_port_'+id+'" inputmode="numeric" placeholder="'+esc(T('ttype_port_ph'))+'" value="'+esc(pre)+'">';
 else w.innerHTML=''}

// ===== Overview
function go(t){cur=t;drawer(false);render()}
function ocol(p){return p>85?cssv('--bad'):p>60?cssv('--gold'):cssv('--ok')}
function heatTip(ev,bar){ev.stopPropagation();var box=bar.parentNode;var tip=box.querySelector('.htip');
 if(!tip){tip=document.createElement('div');tip.className='htip';box.appendChild(tip)}
 tip.innerHTML='<span>'+esc(bar.dataset.nm)+'</span> '+bar.dataset.info;
 tip.style.left=(bar.offsetLeft+bar.offsetWidth/2)+'px';tip.style.display='block';
 clearTimeout(box._tt);box._tt=setTimeout(function(){if(tip)tip.style.display='none'},2400)}
// ===== skeleton loading cards: shown in a list container while its data loads (async), so a page
// reload never shows a blank/frozen gap. The shells mirror the real card geometry so the swap to
// live data is seamless; a page's last-known count keeps the height stable (fallback 6).
// Each skeleton mirrors the EXACT geometry of its real card (same wrapper classes, so it lands in
// the same grid/shadow/padding and the swap to live data is seamless). skb() = one shimmer bar.
function skb(w,h,r){return '<span class="sk" style="width:'+w+';height:'+(h||12)+'px'+(r!=null?';border-radius:'+r+'px':'')+'"></span>'}
function skAct(){return '<span class="sk" style="width:37px;height:33px;border-radius:11px"></span>'}
function skNodeCard(){return '<div class="card node">'+       // exact .card.node
  '<div class="nrow"><span class="sk" style="width:10px;height:10px;border-radius:50%;flex:0 0 auto"></span>'+
    '<div style="min-width:0;flex:1;display:flex;flex-direction:column;gap:7px">'+skb('46%',14)+skb('64%',11)+'</div>'+
    '<span class="grow"></span>'+skb('56px',21,10)+'</div>'+
  '<div class="nchips">'+skb('74px',13)+skb('66px',13)+skb('82px',13)+skb('58px',13)+'</div>'+
  '<div class="upwrap"><div class="uptop">'+skb('70px',11)+'<span class="grow"></span>'+skb('42px',11)+'</div><span class="sk" style="height:22px;border-radius:2px"></span></div>'+
  '<div class="nact iconly">'+skAct()+skAct()+skAct()+skAct()+'</div></div>'}
function skAccCard(core){return '<div class="card acc"><div class="chead">'+   // exact collapsed accordion header
  '<span class="sk" style="width:38px;height:22px;border-radius:20px;flex:0 0 auto"></span>'+
  '<div class="hmain"><div class="hrow1">'+skb('96px',13)+skb('40px',15,20)+
    '<span style="margin-inline-start:auto;display:flex;align-items:center;gap:5px">'+skb('58px',11)+'<span class="sk" style="width:14px;height:8px"></span>'+skb('58px',11)+'</span></div></div>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skPfCard(){return '<div class="card">'+                // exact port-forward card
  '<div class="link">'+skb('90px',15)+'<span class="grow"></span>'+skb('50px',18,20)+skb('60px',20,10)+'</div>'+
  '<div class="enmeta"><div class="emcol">'+skb('80%',12)+skb('70%',12)+skb('58%',12)+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+skb('52%',12)+skb('86%',12)+'</div></div>'+
  '<div class="ltraf">'+skb('58px',12)+skb('58px',12)+'<span class="tot" style="margin-inline-start:auto">'+skb('92px',12)+'</span></div>'+
  '<div class="nact iconly">'+skAct()+skAct()+skAct()+'</div></div>'}
function skAgRow(){return '<div class="agx-row">'+             // exact agent/update row
  '<div class="agx-right"><div class="agx-l1"><span class="sk" style="width:9px;height:9px;border-radius:50%"></span>'+skb('92px',13)+skb('42px',16,6)+'</div>'+
  '<div class="agx-l2">'+skb('118px',15,7)+skb('118px',15,7)+'</div></div>'+
  '<div class="agx-colb">'+skb('86px',26,9)+skb('86px',26,9)+'</div></div>'}
function skCards(kind){
 var arr=(kind=='nodes'?NODES:kind=='portfw'?PF:kind=='agent'?NODES:FLEET)||[];
 var n=Math.max(3,Math.min(8,num(arr.length)||6));
 var one=kind=='nodes'?skNodeCard:kind=='portfw'?skPfCard:kind=='agent'?skAgRow:function(){return skAccCard(kind=='core')};
 var out='';for(var i=0;i<n;i++)out+=one();return out}   // direct children of the list grid — no wrapper
function overviewSkel(){el('view').innerHTML='<h1>'+ic('dash','var(--acc)')+' '+esc(T('nav_overview'))+'</h1><p class="sub">'+esc(T('ov_sub'))+'</p>'+
 '<div class="card ohero"><div><div class="oscore" id="o_score">—</div><div class="oscore-l">'+esc(T('ov_health'))+'</div></div><div class="ochips" id="o_chips"></div></div>'+
 '<div class="sec">'+ic('warn','var(--acc)')+' '+esc(T('ov_attention'))+'</div><div class="card" id="o_alerts"><div class="muted" style="padding:8px 0">…</div></div>'+
 '<div class="sec">'+ic('grid','var(--acc)')+' '+esc(T('ov_allnodes'))+'</div><div class="card ohcard"><div class="oheat" id="o_heat"></div><div class="heat-lg"><span><i style="background:var(--ok)"></i>'+esc(T('st_healthy'))+'</span><span><i style="background:var(--gold)"></i>'+esc(T('st_warn'))+'</span><span><i style="background:var(--bad)"></i>'+esc(T('st_crit'))+'</span></div><div class="muted" style="text-align:center;margin-top:6px;font-size:11px" id="o_heat_c"></div></div>'+
 '<div class="sec">'+ic('server','var(--acc)')+' '+esc(T('ov_central'))+'</div><div class="card"><div class="gauges">'+gaugeHTML('scpu','CPU')+gaugeHTML('sram','RAM')+gaugeHTML('sdisk',T('disk'))+'</div></div>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' '+esc(T('ov_worst'))+'</div><div class="card" id="o_worst"><div class="muted" style="padding:8px 0">…</div></div>'+
 '<div class="sec">'+ic('link','var(--acc)')+' '+esc(T('ov_tunbreak'))+'</div><div class="card"><div class="tst" id="o_tst"></div><div class="typebar" id="o_typebar"></div><div class="typleg" id="o_typleg"></div><div id="o_wtun"></div></div>'+
 '<div class="sec">'+ic('traf','var(--acc)')+' '+esc(T('ov_traffic'))+'<span class="lpill"><span class="pd"></span>'+esc(T('live'))+'</span></div><div class="card"><div class="tf-chart"><div class="tf-top"><span class="din iso">↓ <b id="o_frx">—</b></span><span class="dout iso">↑ <b id="o_ftx">—</b></span></div><svg id="o_traf" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">'+esc(T('ov_rxtot'))+'</span><b id="o_ftin">—</b></div><div class="ttile"><span class="dout">'+esc(T('ov_txtot'))+'</span><b id="o_ftout">—</b></div></div></div>'+
 '<div class="sec">'+ic('clock','var(--acc)')+' '+esc(T('ov_uptime'))+'</div><div class="ostat2"><div class="card"><div class="big" id="o_uptime" style="color:var(--ok)">—</div><div class="muted" style="font-size:11.5px" id="o_uptime_l">'+esc(T('ov_uptime_avg'))+'</div></div><div class="card"><div class="big" id="o_updown">—</div><div class="muted" style="font-size:11.5px">'+esc(T('ov_down_nodes'))+'</div></div></div>'}
async function refreshOverview(){var s=await j('summary');if(!el('o_score'))return;
 var on=num(s.nodes_online),tot=num(s.nodes_total),links=num(s.links),alerts=s.alerts||[];
 // ---- health score + chips
 var sc=num(s.health_score),scol=sc>=85?cssv('--ok'):sc>=60?cssv('--gold'):cssv('--bad');
 var se=el('o_score');se.textContent=sc;se.style.color=scol;
 el('o_chips').innerHTML='<span class="ochip a">'+esc(T('ov_chip_node'))+' <b dir="ltr">'+on+'/'+tot+'</b></span>'+
  '<span class="ochip o">'+esc(T('ov_chip_uplink'))+' <b dir="ltr">'+num(s.link_up)+'/'+(num(s.link_total)||links)+'</b></span>'+
  '<span class="ochip a">'+esc(T('ov_chip_tunnel'))+' <b>'+num(s.tunnels)+'</b></span>'+
  (alerts.length?'<span class="ochip b">'+esc(T('ov_chip_alert'))+' <b>'+alerts.length+'</b></span>':'<span class="ochip o">'+esc(T('ov_chip_noalert'))+'</span>');
 // ---- alerts feed
 var goMap={node:'nodes',link:'tunnels',drift:'tunnels',disk:'nodes',ram:'nodes',cpu:'nodes',agent:'settings'};
 var goLbl={nodes:T('nav_nodes'),tunnels:T('nav_tunnels'),settings:T('nav_settings')};
 el('o_alerts').innerHTML=alerts.length?alerts.map(function(a){var c=a.level=='bad'?cssv('--bad'):cssv('--gold');var g=goMap[a.kind]||'nodes';return '<div class="oalert"><span class="dot" style="background:'+c+'"></span><span class="msg">'+esc(a.msg)+'</span><span class="go" onclick="go(\\''+g+'\\')">'+goLbl[g]+' →</span></div>'}).join(''):'<div style="text-align:center;padding:10px 0;font-size:12.5px;color:var(--ok);display:flex;align-items:center;justify-content:center;gap:7px">'+ic('okc','var(--ok)')+' '+esc(T('ov_noalert'))+'</div>';
 // ---- heat row (every node at a glance; height = worst metric)
 var heat=s.heat||[];
 setHTML(el('o_heat'),heat.length?heat.map(function(h){var nm=esc(h.name);if(!h.online)return '<div class="hbar" onclick="heatTip(event,this)" data-nm="'+nm+'" data-info="'+esc(T('offline'))+'" title="'+nm+' — '+esc(T('offline'))+'" style="height:10px;background:color-mix(in srgb,var(--sub) 35%,transparent)"></div>';var p=num(h.pct);return '<div class="hbar" onclick="heatTip(event,this)" data-nm="'+nm+'" data-info="'+p+T('pct')+'" title="'+nm+' — '+p+T('pct')+'" style="height:'+(12+p*0.54)+'px;background:'+ocol(p)+'"></div>'}).join(''):'<div class="muted" style="font-size:12px">'+esc(T('ov_no_nodes'))+'</div>');
 setT('o_heat_c',(heat.length||0)+' '+T('ov_heat_note'));
 // ---- central server gauges
 var c=s.central||{},cl=(c.load||[])[0];
 setGauge('scpu',c.cpu_pct,T('load')+' '+(cl!=null?cl:'—')+' · '+(num(c.cpus)||'?')+' '+T('cores_word'));
 setGauge('sram',c.ram_pct,c.mem_used_mb!=null?(num(c.mem_used_mb)+' / '+num(c.mem_total_mb)+' '+T('unit_mb')):'—');
 setGauge('sdisk',c.disk_pct,c.disk_used_mb!=null?(Math.round(num(c.disk_used_mb)/1024)+' / '+Math.round(num(c.disk_total_mb)/1024)+' '+T('unit_gb')):'—');
 // ---- worst nodes per metric
 var w=s.worst||{},wr=function(k,o){if(!o)return '';var p=num(o.pct),cc=ocol(p);return '<div class="wrow"><span class="wk">'+k+'</span><span class="wnm">'+esc(o.name)+'</span><span class="wbar"><i style="width:'+p+'%;background:'+cc+'"></i></span><span class="wpc" style="color:'+cc+'">'+p+T('pct')+'</span></div>'};
 var wh=wr(T('disk'),w.disk)+wr(T('ram'),w.ram)+wr('CPU',w.cpu);
 el('o_worst').innerHTML=wh||'<div class="muted" style="text-align:center;padding:8px 0;font-size:12.5px">'+esc(T('ov_no_online'))+'</div>';
 // ---- tunnel status breakdown
 var lu=num(s.link_up),ln=num(s.link_noping),ld=num(s.link_down),ldr=num(s.link_drift);
 el('o_tst').innerHTML='<div class="tb"><div class="n" style="color:var(--ok)">'+lu+'</div><div class="l">'+esc(T('tst_connected'))+'</div></div>'+
  '<div class="tb"><div class="n" style="color:var(--gold)">'+ln+'</div><div class="l">'+esc(T('tst_noping'))+'</div></div>'+
  '<div class="tb"><div class="n" style="color:'+(ld?'var(--bad)':'var(--tx)')+'">'+ld+'</div><div class="l">'+esc(T('tst_down'))+'</div></div>'+
  '<div class="tb"><div class="n" style="color:'+(ldr?'var(--gold)':'var(--tx)')+'">'+ldr+'</div><div class="l">'+esc(T('tst_rebuild'))+'</div></div>';
 var ty=s.link_types||{};
 var TYD=[['core','#6366f1'],['vxlan','var(--acc)'],['gre','var(--ok)'],['sit','#a855f7'],['ipip','#14b8a6'],['l2tpv3','#8b5cf6'],['fou','#ec4899'],['ipsec','#f43f5e']];
 var tt=0;TYD.forEach(function(x){tt+=num(ty[x[0]])});tt=tt||1;
 el('o_typebar').innerHTML=TYD.map(function(x){return '<i style="width:'+(num(ty[x[0]])/tt*100)+'%;background:'+x[1]+'"></i>'}).join('');
 el('o_typleg').innerHTML=TYD.filter(function(x){return num(ty[x[0]])>0}).map(function(x){return '<span><i class="otrack" style="background:'+x[1]+'"></i>'+x[0]+' <b>'+num(ty[x[0]])+'</b></span>'}).join('')||'<span class="muted">'+esc(T('ov_no_tunnel'))+'</span>';
 var wt=s.worst_tunnel;
 if(wt){var pr=(wt.a&&wt.b)?' <span dir="ltr" style="color:var(--tx);font-weight:800">'+esc(wt.a)+' ↔ '+esc(wt.b)+'</span>':'';
  setHTML(el('o_wtun'),'<div class="onote">📡 '+esc(T('ov_worst_q'))+' <b>'+esc(wt.name)+'</b>'+pr+(num(wt.loss)>0?' · '+esc(T('ov_loss'))+' <b style="color:var(--bad)">'+Math.round(num(wt.loss))+T('pct')+'</b>':'')+(wt.rtt!=null?' · '+esc(T('ov_ping'))+' <b>'+Math.round(num(wt.rtt))+'ms</b>':'')+'</div>');}
 else{setHTML(el('o_wtun'),'<div class="onote">✅ '+esc(T('ov_all_good'))+(s.fleet_avg_ping!=null?' · '+esc(T('ov_fleet_ping'))+' <b style="color:var(--tx)">'+num(s.fleet_avg_ping)+'ms</b>':'')+'</div>');}
 // ---- fleet traffic
 var frx=num(s.fleet_rx_bps),ftx=num(s.fleet_tx_bps);
 setT('o_frx',fmtRate(frx));setT('o_ftx',fmtRate(ftx));
 setT('o_ftin',fmtBytes(s.fleet_rx_total));setT('o_ftout',fmtBytes(s.fleet_tx_total));
 FRXHIST.push(frx);FTXHIST.push(ftx);if(FRXHIST.length>26){FRXHIST.shift();FTXHIST.shift()}dualSpark('o_traf',FRXHIST,FTXHIST);
 // ---- uptime
 var uw=num(s.uptime_window)||1;
 setT('o_uptime',num(s.uptime_avg)+T('pct'));setT('o_uptime_l',T('ov_uptime_lbl')+' '+uw+' '+T('ov_hours_recent'));
 setT('o_updown',num(s.uptime_down_nodes))}

// ===== Nodes
function nodesSkel(){el('view').innerHTML='<h1>'+ic('server','var(--acc)')+' '+esc(T('nav_nodes'))+'</h1><p class="sub">'+esc(T('nodes_sub'))+'</p>'+
 '<button class="primary" onclick="openNodeAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+esc(T('add_node'))+'</button>'+
 '<div class="sec">'+ic('server','var(--acc)')+' '+esc(T('nodes_fleet'))+'</div>'+toolbar('nodes',T('nodes_search'))+'<div id="nodeList">'+skCards('nodes')+'</div>'+pagerBottom('nodes')}
var _naddMode='auto';
function openNodeAddModal(){_naddMode='auto';_authMode='pass';_installDone=null;_instStop();
 var seg='<div class="seg" id="nadd_seg"><button data-m="auto" class="on" onclick="naddSwitch(\\'auto\\')">'+ic('bolt')+esc(T('nadd_auto'))+'</button><button data-m="manual" onclick="naddSwitch(\\'manual\\')">'+ic('pen')+esc(T('nadd_manual'))+'</button></div>';
 var auto='<div id="nadd_auto">'+
   '<div class="autonote">'+ic('bolt')+'<span>'+esc(T('nadd_autonote'))+'</span></div>'+
   '<div class="grid2"><div><label class="first">'+esc(T('nadd_node_name'))+'</label><input id="a_name" placeholder="DE02"></div><div><label class="first">'+esc(T('nadd_srv_ip'))+'</label><input id="a_host" placeholder="5.75.197.55"></div></div>'+
   '<div class="grid2"><div><label>'+esc(T('nadd_ssh_port'))+'</label><input id="a_sshport" placeholder="22"></div><div><label>'+esc(T('nadd_ssh_user'))+'</label><input id="a_user" placeholder="root"></div></div>'+
   '<div class="grid2"><div><label>'+esc(T('nadd_agent_port'))+'</label><input id="a_aport" placeholder="8099"></div><div><label>'+esc(T('nadd_ctrl_proxy'))+'</label><input id="a_proxy" placeholder="socks5://host:1080"></div></div>'+
   '<div class="authbox"><div class="authhd"><span class="t">'+esc(T('nadd_ssh_auth'))+'</span><span class="authseg" id="a_authseg"><button type="button" data-am="pass" class="on" onclick="authMode(\\'pass\\')">'+esc(T('nadd_pass'))+'</button><button type="button" data-am="key" onclick="authMode(\\'key\\')">'+esc(T('nadd_privkey'))+'</button></span></div>'+
    '<input id="a_pass" class="fld2" type="password" placeholder="'+esc(T('nadd_pass_ph'))+'" autocomplete="new-password">'+
    '<textarea id="a_key" class="fld2" rows="3" style="display:none" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>'+
    '<div class="muted" id="a_authhint" style="font-size:11px;margin-top:7px">'+esc(T('nadd_pass_hint'))+'</div></div>'+
   '<div id="nadd_prog"></div></div>';
 var manual='<div id="nadd_manual" style="display:none"><div class="grid2"><div><label class="first">'+esc(T('nadd_manual_name'))+'</label><input id="n_name" placeholder="frankfurt-1"></div><div><label class="first">'+esc(T('nadd_manual_host'))+'</label><input id="n_host" placeholder="203.0.113.10"></div></div><div class="grid2"><div><label>'+esc(T('nadd_agent_port2'))+'</label><input id="n_port" placeholder="8099"></div><div><label>'+esc(T('nadd_node_tok'))+'</label><input id="n_tok" placeholder="'+esc(T('nadd_node_tok'))+'"></div></div><label>'+esc(T('nadd_manual_proxy'))+'</label><input id="n_proxy" placeholder="socks5://host:1080 / http://user:pass@host:8080"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>'+esc(T('nadd_title'))+'</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+seg+auto+manual+'<div class="msg" id="n_msg"></div></div><div class="mfoot"><button class="primary" id="nadd_go" onclick="naddSubmit()">'+ic('bolt')+esc(T('nadd_install_connect'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
function naddSwitch(m){_naddMode=m;_installDone=null;_instStop();
 var a=el('nadd_auto'),mn=el('nadd_manual');if(a)a.style.display=m=='auto'?'':'none';if(mn)mn.style.display=m=='manual'?'':'none';
 document.querySelectorAll('#nadd_seg button').forEach(function(b){b.classList.toggle('on',b.dataset.m==m)});
 var btn=el('nadd_go');if(btn){btn.disabled=false;btn.className='primary';btn.innerHTML=(m=='auto'?ic('bolt')+esc(T('nadd_install_connect')):ic('plus')+esc(T('nadd_add_connect')))}
 var pr=el('nadd_prog');if(pr&&m=='manual')pr.innerHTML='';
 var msg=el('n_msg');if(msg){msg.className='msg';msg.textContent=''}}
var _installDone=null;  // null = idle/retry, 'ok' = finished successfully (button just closes)
function naddSubmit(){if(_naddMode=='auto'){if(_installDone=='ok'){var ov=el('nadd_go').closest('.modalov');if(ov)closeModal(ov);return}return doAutoInstall()}return addNode()}
function instIcon(st){return st=='ok'?'<span class="istep-i ok">'+CK+'</span>':st=='err'?'<span class="istep-i err">'+XK+'</span>':st=='warn'?'<span class="istep-i warn">'+ic('warn')+'</span>':st=='run'?'<span class="istep-i run"><span class="ispin"></span></span>':'<span class="istep-i wait"></span>'}
// live install: reveal steps one-by-one on a CLIENT clock (elapsed-time based, so Android timer-
// throttling can't collapse them), clamped to the backend's real progress. ONE self-terminating loop
// that stops the instant the modal closes — no leaked/duplicate pollers, no infinite retry.
var _inst=null,_MINSPIN=600;
function _insteps(){return [{label:T('inst_ssh'),detail:T('inst_connecting')},{label:T('inst_download'),detail:T('inst_waiting')},{label:T('inst_service'),detail:T('inst_waiting')},{label:T('inst_register'),detail:T('inst_waiting')}]}
function _instStop(){if(_inst){_inst.cancelled=true;if(_inst.timer)clearTimeout(_inst.timer);_inst=null}}
function _instPoll(c){j('install-status?job='+encodeURIComponent(c.job)+'&_='+Date.now())
 .then(function(d){c.polling=false;
   if(d&&d.ok){c.failN=0;c.steps=d.steps||[];c.confirmed=c.steps.map(function(s){return s.state});if(d.banner)c.banner=d.banner;c.bDone=!!d.done;c.bOk=!!d.success}
   else if(d&&/not found/.test(d.error||'')){c.err=T('inst_status_notfound');c.bDone=true;c.bOk=false}
   else{c.failN++;if(c.failN>=45){c.err=T('inst_panel_lost');c.bDone=true;c.bOk=false}}})
 .catch(function(){c.polling=false;c.failN++;if(c.failN>=45){c.err=T('inst_panel_lost');c.bDone=true;c.bOk=false}})}
function _instRender(c){var box=el('nadd_prog');if(!box)return;var anim=!c.finished;
 var bicon=anim?'<span class="ispin"></span>':(c.bOk?CK:XK);
 var btext=anim?T('inst_installing'):(c.err||c.banner||T('inst_done'));   // don't flash the backend's "done" banner while steps are still revealing
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
 if(c.bOk){_installDone='ok';if(btn){btn.disabled=false;btn.className='primary done';btn.innerHTML=CK+' '+esc(T('inst_done'))}toast(c.banner||T('inst_node_installed'),'ok');refreshNodes().catch(function(){})}
 else{_installDone=null;if(btn){btn.disabled=false;btn.className='primary';btn.innerHTML=ic('bolt')+' '+esc(T('inst_retry'))}}
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
 if(h)h.textContent=(m=='key')?T('nadd_key_hint'):T('nadd_pass_hint');
 var f=(m=='pass')?pf:kf;if(f){try{f.focus()}catch(e){}}}
function agBtnBusy(btn,on,label){if(!btn)return;btn.disabled=on;
 btn.innerHTML=on?'<span class="bspin"></span>':label}
async function doAutoInstall(){if(_inst)return;var m=el('n_msg'),btn=el('nadd_go');   // never start a second install while one is live
 var name=v('a_name'),host=v('a_host');
 var pass=_authMode=='pass'?v('a_pass'):'',key=_authMode=='key'&&el('a_key')?el('a_key').value.trim():'';
 if(!name||!host){m.className='msg err';m.textContent=T('nadd_need_name_ip');return}
 if(!pass&&!key){m.className='msg err';m.textContent=(_authMode=='key'?T('nadd_privkey'):T('nadd_pass_word'))+T('nadd_is_required');return}
 _installDone=null;m.className='msg';m.textContent='';agBtnBusy(btn,true);
 // show the FIRST step (SSH), spinning, the instant install is clicked — no "در حالِ نصب…" placeholder gap
 var _st0=_insteps()[0];
 var pr=el('nadd_prog');if(pr){pr.innerHTML='<div class="iwrap"><div class="ibanner run"><span class="ispin"></span><span>'+esc(T('inst_installing'))+'</span></div><div class="istep run"><span class="istep-i run"><span class="ispin"></span></span><div class="istep-b"><div class="istep-t">'+esc(_st0.label)+'</div><div class="istep-s">'+esc(_st0.detail)+'</div></div></div></div>';pr.scrollIntoView({behavior:'smooth',block:'center'})}
 var r=await post('node-install',{name:name,ssh_host:host,ssh_port:v('a_sshport'),ssh_user:v('a_user'),agent_port:v('a_aport'),ssh_pass:pass,ssh_key:key,proxy:v('a_proxy')}).catch(function(){return{ok:false,d:{}}});
 if(!(r.ok&&r.d.ok)){m.className='msg err';m.textContent=terr((r.d&&r.d.error))||T('failed');if(pr)pr.innerHTML='';agBtnBusy(btn,false,ic('bolt')+esc(T('nadd_install_connect')));return}
 // seed step 0 as revealed+running so the reveal continues seamlessly from the skeleton (no flicker back to the banner)
 _inst={job:r.d.job,steps:_insteps().map(function(s){return{label:s.label,detail:s.detail}}),confirmed:['run','wait','wait','wait'],banner:T('inst_installing'),bDone:false,bOk:false,err:'',revealIdx:1,lastReveal:_instNow(),lastPoll:0,polling:false,failN:0,finished:false,cancelled:false,timer:null};
 _instTick()}
async function refreshNodes(){if(editingId)return;var r=await j('nodes?offset='+(PG.nodes*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.nodes));NODES=r.nodes||[];TOT.nodes=num(r.total);UPWIN=num(r.uptime_window)||1;var box=el('nodeList');if(!box)return;
 setHTML(box,NODES.length?NODES.map(nodeCard).join(''):'<div class="card muted">'+(QRY.nodes?T('no_results'):T('nodes_empty'))+'</div>');renderPager('nodes')}
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
 t.innerHTML=pct+'<i>'+T('pct')+'</i>';if(s&&sub!=null)s.textContent=sub}
function ndTile(icn,label,val,wide,ltr){return '<div class="nd-tile'+(wide?' nd-wide':'')+'"><span class="medi">'+ic(icn)+'</span><span>'+label+'</span><b'+(ltr?' class="ltr"':'')+'>'+val+'</b></div>'}
function ndApplyStats(s){var rp=s.mem_total_mb?Math.round(num(s.mem_used_mb)/num(s.mem_total_mb)*100):0;
 setGauge('cpu',s.cpu_pct,T('load')+' '+((s.load||[])[0]||'—'));
 setGauge('ram',rp,num(s.mem_used_mb)+' / '+num(s.mem_total_mb)+' '+T('unit_mb'));
 setGauge('disk',s.disk_pct,s.disk_used_mb!=null?(Math.round(num(s.disk_used_mb)/1024)+' / '+Math.round(num(s.disk_total_mb)/1024)+' '+T('unit_gb')):'—')}
function ndSetHead(ov,online){var dot=ov.querySelector('.nd-head .dot');if(dot)dot.className='dot '+(online?'ok':'bad');
 var bd=ov.querySelector('.nd-head .nd-ping');if(bd){bd.className='badge '+(online?'ok':'bad')+' nd-ping';bd.textContent=online?T('online'):T('offline')}
 var sb=ov.querySelector('.msticky .sb');if(sb)sb.innerHTML=online?'<span class="lpill"><span class="pd"></span>'+esc(T('live'))+'</span> '+esc(T('refresh2s')):esc(T('nd_off_last'))}
function nodeDetails(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;var i=n.info||{},s=i.stats||{};
 var head='<div class="nd-head"><span class="dot '+(n.online?'ok':'bad')+'"></span><div class="nd-id"><b class="nd-name">'+esc(n.name)+'</b><span class="nd-hp">'+esc(n.host)+':'+esc(n.port)+'</span></div>'+(n.proxy?'<span class="tag" style="margin-inline-start:6px">'+esc(T('proxy'))+'</span>':'')+'<span class="badge '+(n.online?'ok':'bad')+' nd-ping">'+(n.online?T('online'):T('offline'))+'</span></div>';
 var mb;
 if(n.online){var g='<div class="gauges">'+gaugeHTML('cpu','CPU')+gaugeHTML('ram','RAM')+gaugeHTML('disk',T('disk'))+'</div>';
  var traf='<div class="nd-sec">'+ic('traf')+' '+esc(T('nd_traffic'))+'<span class="lpill" style="margin-inline-start:auto"><span class="pd"></span>'+esc(T('live'))+'</span></div><div class="tf-chart"><div class="tf-top"><span class="din iso">↓ <b id="tf_rin">—</b></span><span class="dout iso">↑ <b id="tf_rout">—</b></span></div><svg id="tf_spark" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">'+esc(T('ov_rxtot'))+'</span><b id="tf_tin">—</b></div><div class="ttile"><span class="dout">'+esc(T('ov_txtot'))+'</span><b id="tf_tout">—</b></div></div><div id="tf_tuns" class="tf-tuns"></div>';
  var tiles='<div class="nd-grid">'+ndTile('os',T('os'),esc(s.os||'?'),false,true)+ndTile('clock',T('uptime'),s.uptime?fmtup(s.uptime):'?')+ndTile('cores',T('cpu_cores'),num(s.cpus)||'?')+ndTile('link',T('nd_tunnels'),num(i.tunnels))+ndTile('globe',T('nd_portfw'),num(i.portfw))+ndTile('shield',T('nd_ctrlproxy'),n.proxy?esc(proxyScheme(n.proxy)):'—')+ndTile('server',T('host'),esc(i.hostname||'?'),true,true)+ndTile('pin',T('ip'),esc(n.host),true,true)+'</div>';
  mb=head+g+traf+'<div class="nd-divider"></div>'+tiles+'<div class="nd-divider"></div><div class="nd-sec">'+ic('pin')+' '+esc(T('nd_ips'))+'<span class="muted" style="margin-inline-start:auto;font-size:11px;font-weight:500">'+esc(T('ip_leg'))+'</span></div><div id="nd_ips" class="ndips"><div class="muted" style="font-size:11.5px;padding:6px 2px">…</div></div>'}
 else{mb=head+'<div class="nd-off">'+ic('plugoff')+'<b>'+esc(T('not_available'))+'</b>'+(i.error?'<span>'+esc(i.error)+'</span>':'')+'</div>'}
 var sub=n.online?'<span class="lpill"><span class="pd"></span>'+esc(T('live'))+'</span> '+esc(T('refresh2s')):esc(T('nd_status'));
 var html='<div class="msticky"><span class="medi">'+ic('info')+'</span><div class="ttl"><h3>'+esc(T('nd_title'))+'</h3><div class="sb">'+sub+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+mb+'</div><div class="mfoot"><button class="primary" onclick="ndRetest(\\''+id+'\\')">'+esc(T('nd_conn_test'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('close'))+'</button></div>';
 var ov=openModal(html,{cls:'ndsheet',onclose:function(){if(ov._iv){clearInterval(ov._iv);ov._iv=0}}});
 if(n.online){ndApplyStats(s);var tfin=[],tfout=[];
  j('node-ips?id='+id).then(function(r){if(ov._closed)return;var ib=el('nd_ips');if(ib)ib.innerHTML=ipTagsHTML(r&&r.ips)}).catch(function(){});
  var poll=function(){
   j('node-stats?id='+id).then(function(r){if(ov._closed)return;if(r&&r.online&&r.stats){ndApplyStats(r.stats);ndSetHead(ov,true)}else{ndSetHead(ov,false)}}).catch(function(){});
   j('traffic?id='+id).then(function(r){if(ov._closed||!r||!r.node)return;var nd=r.node;
    setT('tf_rin',fmtRate(nd.rx_bps));setT('tf_rout',fmtRate(nd.tx_bps));setT('tf_tin',fmtBytes(nd.rx_total));setT('tf_tout',fmtBytes(nd.tx_total));
    tfin.push(num(nd.rx_bps));tfout.push(num(nd.tx_bps));if(tfin.length>30){tfin.shift();tfout.shift()}dualSpark('tf_spark',tfin,tfout);
    var rows=(r.tunnels||[]).concat(r.portfw||[]);
    var tb=el('tf_tuns');if(tb)tb.innerHTML=rows.length?rows.map(tfRow).join(''):'<div class="muted" style="font-size:11.5px;padding:7px 2px">'+esc(T('nd_no_tp'))+'</div>'}).catch(function(){})};
  poll();ov._iv=setInterval(poll,UIV)}}   // live CPU/RAM/disk + traffic, at the settings-driven cadence
function ndRetest(id){j('node-stats?id='+id).then(function(r){if(r&&r.online){toast(T('online'),'ok')}else{toast(T('offline')+': '+((r&&r.error)||T('not_available')),'err')}}).catch(function(){toast(T('err_check'),'err')})}
function openNodeEdit(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;
 var b='<div class="grid2"><div><label class="first">'+esc(T('f_name'))+'</label><input id="e_name_'+id+'" value="'+esc(n.name)+'"></div><div><label class="first">'+esc(T('f_host_ip'))+'</label><input id="e_host_'+id+'" value="'+esc(n.host)+'"></div></div><div class="grid2"><div><label>'+esc(T('f_port'))+'</label><input id="e_port_'+id+'" value="'+esc(n.port)+'"></div><div><label>'+esc(T('f_token'))+'</label><input id="e_tok_'+id+'" placeholder="'+esc(T('tok_keep'))+'"></div></div><label>'+esc(T('f_ctrlproxy_empty'))+'</label><input id="e_proxy_'+id+'" value="'+esc(n.proxy||'')+'" placeholder="socks5://host:1080 یا http://user:pass@host:8080"><div class="msg" id="em_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('nd_edit'))+'</h3><div class="sb">'+esc(n.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveEdit(\\''+id+'\\')">'+esc(T('save'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
function ipEndField(side,id,nm,ips,cur){var lab='<label class="first">'+esc(T('ip_of'))+esc(nm)+'</label>';
 ips=(ips&&ips.length)?ips:(cur?[cur]:[]);
 if(ips.length>1)return '<div>'+lab+ssHTML('lip'+side+'_'+id,ips.map(function(x){return{v:x,label:x}}),(cur&&ips.indexOf(cur)>=0)?cur:ips[0],T('ip'),'')+'</div>';
 return '<div>'+lab+'<input class="mono" value="'+esc(cur||ips[0]||'—')+'" disabled style="opacity:.6"></div>'}
function openLinkEdit(id){var l=FLEET.find(function(x){return x.id==id});if(!l)return;EDID=id;LEDTYPE=l.type;LEDPORT=(l.port==null?'':l.port);
 var multi=((l.a_ips||[]).length>1)||((l.b_ips||[]).length>1);
 var b='<div class="grid2"><div><label class="first">'+esc(T('tun_type'))+'</label>'+ssHTML('lt_'+id,TYPEITEMS,l.type,T('ttype'),'recalcEditSubnet')+'</div><div><label class="first">'+esc(T('range'))+'</label>'+ssHTML('lsr_'+id,SUBNETRANGES2,'192.168',T('range'),'recalcEditSubnet')+'</div></div><label>'+esc(T('subnet'))+'</label><input id="e_sub_'+id+'" value="'+esc(l.subnet)+'"><div id="lpx_'+id+'"></div>'+
  '<div class="muted" style="font-weight:700;color:var(--tx);margin:16px 2px 9px;display:flex;align-items:center;gap:6px">'+ic('pin','var(--acc)')+esc(T('ip_each_end'))+(multi?' <span class="tag" style="font-size:9.5px;padding:1px 7px">'+esc(T('multi_ip'))+'</span>':'')+'</div>'+
  '<div class="grid2">'+ipEndField('a',id,l.a_name,l.a_ips,l.a_ip)+ipEndField('b',id,l.b_name,l.b_ips,l.b_ip)+'</div>'+
  '<div class="muted" style="font-size:11.5px;margin-top:9px">'+esc(T('link_ip_note1'))+esc(l.tunnel_id)+esc(T('link_ip_note2'))+'</div><div class="msg" id="lem_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('link')+'</span><div class="ttl"><h3>'+esc(T('edit_tun_t'))+'</h3><div class="sb">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveLinkEdit(\\''+id+'\\')">'+esc(T('save_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{onclose:function(){EDID=null}});
 renderEditPort(id)}
async function openPfEdit(i){var p=PF[i];if(!p)return;EDID='pf'+i;var rotOn=p.switch_interval>0;
 var r=await j('node-names');NODES=r.nodes||[];var ips=nodeIps(p.node_id);   // load node IPs for the listen-IP picker
 var lipsec=(ips.length>1)?'<label class="first">'+esc(T('pf_lip'))+'</label>'+ssHTML('pe_lip',ipItems(ips),(p.listen_ip&&ips.indexOf(p.listen_ip)>=0?p.listen_ip:ips[0]),T('ip'),'')+'<div class="muted" style="font-size:11px;margin:-3px 2px 12px">'+esc(T('pf_lip_note'))+'</div>':'';
 var fc=lipsec?'':' class="first"';
 var b=lipsec+'<div class="grid2"><div><label'+fc+'>'+esc(T('pf_listen_port'))+'</label><input id="pe_lp_'+i+'" value="'+esc(p.listen_port)+'"></div><div><label'+fc+'>'+esc(T('pf_dst_port'))+'</label><input id="pe_dp_'+i+'" value="'+esc(p.dst_port)+'"></div></div><label>'+esc(T('pf_dst_ips'))+'</label><input id="pe_ips_'+i+'" value="'+esc((p.dst_ips||[]).join(', '))+'"><label>'+esc(T('pf_rot_between'))+'</label><div class="tgl"><span class="tglsw'+(rotOn?' on':'')+'" id="pe_tgl_'+i+'" onclick="pfTgl('+i+')"></span><span class="muted" id="pe_tgllbl_'+i+'">'+(rotOn?T('on_word'):T('off_word'))+'</span></div><div id="pe_intwrap_'+i+'" style="'+(rotOn?'':'display:none')+'"><label>'+esc(T('pf_rot_interval'))+'</label><input id="pe_int_'+i+'" value="'+esc(rotOn?(p.switch_interval/60):5)+'"></div><div class="muted" style="font-size:11.5px;margin-top:9px">'+esc(T('pf_rot_note'))+'</div><div class="msg" id="pem_'+i+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('pf_edit_t'))+'</h3><div class="sb">'+esc(p.node)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="savePfEdit('+i+')">'+esc(T('save'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
function nodeCard(n){var i=n.info||{};
 var badge=n.online?'<span class="badge ok">'+esc(T('online'))+'</span>':(n.pending?'<span class="badge na">'+esc(T('pending_check'))+'</span>':'<span class="badge bad">'+esc(T('offline'))+'</span>');
 var head='<div class="nrow"><span class="ndot '+(n.online?'on':'off')+'"></span><div style="min-width:0"><div class="name">'+esc(n.name)+(n.proxy?' <span class="tag" style="font-size:9.5px;padding:1px 6px">'+esc(T('proxy'))+'</span>':'')+'</div><div class="muted mono" style="font-size:12px">'+esc(n.host)+':'+esc(n.port)+'</div></div><span class="grow"></span>'+badge+'</div>';
 var body=n.online?'<div class="nchips"><span class="nchip">'+ic('link')+esc(T('nd_tunnels'))+' <b>'+num(i.tunnels)+'</b></span><span class="nchip">'+ic('globe')+esc(T('nd_portfw'))+' <b>'+num(i.portfw)+'</b></span>'+(i.version?'<span class="nchip">'+ic('cpu')+esc(T('nd_agent'))+' v<b>'+num(i.version)+'</b></span>':'')+((i.core_sha&&String(i.core_sha).length)?'<span class="nchip">'+ic('cpu')+esc(T('nd_core'))+' <b>'+esc(i.core_ver||'?')+'</b></span>':'<span class="nchip" style="color:var(--sub)">'+ic('cpu')+esc(T('nd_core'))+' <b>'+esc(T('nd_core_missing'))+'</b></span>')+(n.proxy?'<span class="nchip">'+ic('shield')+'<b>'+esc(proxyScheme(n.proxy))+'</b></span>':'')+'</div>':'<div class="noff">'+ic('plugoff')+'<b>'+esc(T('not_available'))+'</b>'+(i.error?'<span>· '+esc(i.error)+'</span>':'')+'</div>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_test'))+'" onclick="testNode(\\''+n.id+'\\')">'+ic('bolt')+'</button><button class="act info" title="'+esc(T('tip_details'))+'" onclick="nodeDetails(\\''+n.id+'\\')">'+ic('info')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" onclick="openNodeEdit(\\''+n.id+'\\')">'+ic('pen')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" data-nid="'+esc(n.id)+'" data-nm="'+esc(n.name)+'" onclick="delNode(this)">'+ic('trash')+'</button></div>';
 return '<div class="card node">'+head+body+upBar(n)+acts+'<div class="msg" id="ntm_'+n.id+'"></div></div>'}
function upBar(n){var r=n.uptime||[];  // 60 cells: 1=up(green), 0=down(red), null=no-data(gray)
 var pct=(n.uptime_pct!=null)?n.uptime_pct:100;  // TIME-WEIGHTED % from the server (a 5s blip != a whole red cell)
 var cells=r.map(function(v){return '<i class="'+(v==null?'g':(v?'':'d'))+'"></i>'}).join('');
 return '<div class="upwrap"><div class="uptop">'+esc(T('uptime_bar'))+'<b style="margin-inline-start:6px">'+pct+T('pct')+'</b><span class="r">'+UPWIN+' '+esc(T('ov_hours_recent'))+'</span></div><div class="upbar">'+cells+'</div></div>'}
async function saveEdit(id){var m=el('em_'+id);var name=v('e_name_'+id),host=v('e_host_'+id),port=v('e_port_'+id),tok=v('e_tok_'+id);
 if(!name||!host||!port){m.className='msg err';m.textContent=T('need_nhp');return}
 m.className='msg';m.textContent=T('saving');
 var r=await post('node-edit',{id:id,name:name,host:host,port:port,token:tok,proxy:v('e_proxy_'+id)});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=terr(r.d.error||T('failed'))}}
async function addNode(){var m=el('n_msg');var name=v('n_name'),host=v('n_host'),port=v('n_port'),tok=v('n_tok');
 if(!name||!host||!port||!tok){m.className='msg err';m.textContent=T('need_all_nhpt');return}
 m.className='msg';m.textContent=T('connecting_dots');
 var r=await post('node-add',{name:name,host:host,port:port,token:tok,proxy:v('n_proxy')});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('node_added')+(r.d.online?T('node_added_online'):T('node_added_offline')+terr(r.d.error||'')),r.d.online?'ok':'err')}
 else{m.className='msg err';m.textContent=terr(r.d.error||T('failed'))}}
async function testNode(id){var m=el('ntm_'+id);if(m){m.className='msg';m.textContent=T('test_testing')}
 var t0=performance.now();var r=await post('node-test',{id:id});var ms=Math.round(performance.now()-t0);
 var info=(r.d&&r.d.info)||{};if(!m)return;
 if(r.d&&r.d.ok){m.className='msg ok';m.innerHTML=CK+esc(' '+T('online')+' — '+(info.hostname||'')+' · '+ms+'ms')}
 else{m.className='msg err';m.textContent=T('offline')+': '+(terr(info.error)||T('not_available'))+' · '+ms+'ms'}}
function delNode(btn){var id=btn.getAttribute('data-nid');var nm=btn.getAttribute('data-nm');
 var b='<div class="muted" style="font-size:12.5px;margin-bottom:13px">'+esc(T('del_how'))+'</div>'+
  '<button type="button" class="delopt" onclick="doDelNode(\\''+id+'\\',false)"><div class="do-t">'+ic('logout')+esc(T('del_detach_t'))+'</div><div class="do-s">'+esc(T('del_detach_s'))+'</div></button>'+
  '<button type="button" class="delopt danger" onclick="doDelNode(\\''+id+'\\',true)"><div class="do-t">'+ic('warn')+esc(T('del_wipe_t'))+'</div><div class="do-s">'+esc(T('del_wipe_s'))+'</div></button>'+
  '<div class="msg" id="del_msg"></div>';
 openModal('<div class="msticky"><span class="medi medi-bad">'+ic('trash')+'</span><div class="ttl"><h3>'+esc(T('nd_del'))+'</h3><div class="sb">'+esc(nm)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
async function doDelNode(id,wipe){var m=el('del_msg');
 if(wipe&&!await confirmBox(T('del_wipe_confirm'),T('del_wipe_yes')))return;
 if(m){m.className='msg';m.textContent=wipe?T('del_wiping'):T('del_detaching')}
 document.querySelectorAll('.delopt').forEach(function(b){b.disabled=true});
 var r=await post('node-del',{id:id,wipe:wipe});
 if(r.ok&&r.d.ok){editingId=null;var ov=m?m.closest('.modalov'):null;
  toast(wipe?T('node_wiped'):T('node_detached'),'ok');
  if(ov)closeModal(ov);else refreshNodes()}
 else{if(m){m.className='msg err';m.textContent=terr((r.d&&r.d.error)||T('failed'))}document.querySelectorAll('.delopt').forEach(function(b){b.disabled=false})}}

// ===== Tunnels
function tunnelsSkel(){CHK={};el('view').innerHTML='<h1>'+ic('link','var(--acc)')+' '+esc(T('nav_tunnels'))+'</h1><p class="sub">'+esc(T('tun_sub'))+'</p>'+
 '<div class="tbtnrow"><button class="primary" onclick="openCreateModal()">'+ic('plus')+esc(T('add_tunnel'))+'</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+esc(T('check_all'))+'</button></div>'+
 toolbar('tunnels',T('tun_search'))+'<div id="linkList">'+skCards('tunnels')+'</div>'+pagerBottom('tunnels')}
function fmtms(x){return (x>=10?Math.round(x):Math.round(x*10)/10)+'ms'}
function pingInfo(h){var p=[];if(h.rtt_ms!=null)p.push(T('t_ping')+' '+fmtms(h.rtt_ms));if(h.loss_pct!=null)p.push(h.loss_pct>0?(T('t_loss')+' '+(Math.round(h.loss_pct*10)/10)+T('pct')):T('t_noloss'));return p.join(' · ')}
function sideTxt(online,h){
 if(!online)return T('t_side_off');
 if(!h)return T('t_side_notun');
 if(h.up==null)return T('checking');
 if(!h.up)return T('t_side_ifdown');
 if(h.peer_ping===true){var e=pingInfo(h);return T('t_side_conn')+(e?' · '+e:'')}
 if(h.peer_ping===false)return T('t_side_nopingr')+(h.loss_pct!=null?' ('+T('t_loss')+' '+(Math.round(h.loss_pct)||100)+T('pct')+')':'');
 return T('t_side_up_unk')}
function sideState(online,h){  // k: dot color class, w: the word to show ONLY when there's a problem
 if(!online||!h)return {k:'bad',w:T('st_disc')};
 if(h.up==null)return {k:'na',w:'…'};
 if(!h.up)return {k:'bad',w:T('st_disc')};
 if(h.peer_ping===false)return {k:'warn',w:T('st_half')};
 return {k:'ok',w:''}}   // connected -> clean, just the green dot
function sideDot(online,h){var s=sideState(online,h);   // shared by tunnel + core cards
 return (s.w?'<span class="stw '+s.k+'">'+esc(s.w)+'</span>':'')+'<span class="sdot '+s.k+'"'+(s.w?'':' title="'+esc(T('tst_connected'))+'"')+'></span>'}
function metaCols(l){   // two meta columns placed exactly under the two node boxes
 var sub='<div>'+esc(T('subnet'))+': <b class="mono">'+esc(l.subnet)+'</b></div>';
 var idr='<div>'+esc(T('tid'))+': <b>'+esc(l.tunnel_id)+'</b></div>';
 var ifc='<div>'+esc(T('iface'))+': <b class="mono">'+esc(l.name)+'</b></div>';
 var typ='<div class="tagrow">'+esc(T('ttype'))+': <span class="tag '+esc(l.type)+'">'+esc(l.type)+'</span></div>';
 var right,left;
 if(l.type=='ipsec'){right=sub+idr+ifc;left=typ+'<div class="wrap">'+esc(T('enc'))+': <span class="enc">'+ic('lock','var(--bad)')+esc(T('encrypted'))+'</span></div>'}
 else if((l.type=='l2tpv3'||l.type=='fou'||l.type=='vxlan')&&l.port){right=sub+idr+ifc;left=typ+'<div>'+esc(T('udp_port'))+': <b class="mono">'+esc(l.port)+'</b></div>'}
 else{right=sub+ifc;left=idr+typ}   // plain (gre/ipip/sit, or vxlan without a custom port): balanced 2+2
 return '<div class="enmeta"><div class="emcol">'+right+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+left+'</div></div>'}
// ===== accordion cards (collapsed row -> click to expand) + on/off toggle =====
var TOPEN={};   // per-link open state, kept across the periodic re-render
// per-link+side {ip,rot}: the live active pool IP + whether it rotates. coreCard syncs it from the fleet
// data's l.*_ip_active and persists here, seeded from localStorage so a RELOAD shows the last-known
// active IP immediately instead of flashing the stored anchor (a_ip) until the first fleet fetch lands.
var PEERST=(function(){try{return JSON.parse(localStorage.getItem('tnl_peerst')||'{}')||{}}catch(e){return {}}})();
function peerStSave(){try{localStorage.setItem('tnl_peerst',JSON.stringify(PEERST))}catch(e){}}
var CHEVI='<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>';
function cardTog(id,e){TOPEN[id]=!TOPEN[id];var c=el('c_'+id);if(c)c.classList.toggle('open',TOPEN[id])}
async function toggleLink(id,e){e.stopPropagation();var L=FLEET.filter(function(x){return x.id==id})[0];if(!L)return;
 var next=(L.enabled===false);L.enabled=next;   // optimistic flip
 var c=el('c_'+id);if(c){var sw=c.querySelector('.tsw');if(sw)sw.classList.toggle('on',next);c.classList.toggle('off',!next)}
 var r=await post('link-toggle',{id:id,enabled:next});
 if(!(r.ok&&r.d.ok)){L.enabled=!next;toast(T('failed'),'err')}else{toast(next?T('turned_on'):T('turned_off'),'ok')}
 refreshFleet()}
function accDot(l,side){if(l.enabled===false)return '<span class="sdot na" title="'+esc(T('st_off'))+'"></span>';
 var s=sideState(side=='a'?l.a_online:l.b_online, side=='a'?l.a_health:l.b_health);return '<span class="sdot '+s.k+'"></span>'}
function accStat(l,side){if(l.enabled===false)return '<span class="stw na">'+esc(T('st_off'))+'</span><span class="sdot na"></span>';
 return side=='a'?sideDot(l.a_online,l.a_health):sideDot(l.b_online,l.b_health)}
function accHead(l,isCore){var on=l.enabled!==false;
 var typ=isCore?'<span class="ctag core">Core</span>':'<span class="ctag">'+esc((l.type||'').toUpperCase())+'</span>';
 var off=on?'':'<span class="offtxt" style="font-size:11px">'+esc(T('st_off'))+'</span>';
 return '<div class="chead" onclick="cardTog(\\''+l.id+'\\',event)">'+
  '<div class="tsw'+(on?' on':'')+'" onclick="toggleLink(\\''+l.id+'\\',event)" title="'+esc(T('tip_toggle'))+'"></div>'+
  '<div class="hmain"><div class="hrow1"><span class="hname">'+esc(l.name)+'</span>'+typ+off+
   '<span class="hpeers" dir="ltr">'+accDot(l,'a')+esc(l.a_name)+' ↔ '+esc(l.b_name)+accDot(l,'b')+'</span></div></div>'+CHEVI+'</div>'}
function accBodyTraf(l){if(l.enabled===false)return '<div class="offbadge">'+ic('warn','var(--bad)')+'<span>'+esc(T('tun_off_note'))+'</span></div>';
 var hasT=(l.rx_total!=null||l.rx_bps!=null);
 var tot=hasT?'<span class="iso"><b class="din">↓'+fmtBytes(l.rx_total)+'</b><b class="dout">↑'+fmtBytes(l.tx_total)+'</b></span>':'<b class="mono">—</b>';
 var rates=hasT?'<span class="din iso">↓ '+fmtRate(l.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(l.tx_bps)+'</span>':'<span class="muted" style="font-size:11px">'+esc(T('no_live_side'))+'</span>';
 return '<div class="ltraf">'+rates+'<span class="tot">'+esc(T('total'))+' '+tot+'</span></div>'}
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
 var flip='<button class="act flip" onclick="flipView(\\''+l.id+'\\')" title="'+esc(T('tip_flip'))+esc(l.view_name||'—')+'">'+ic('swap')+'</button>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_ping'))+'" onclick="checkLink(\\''+l.id+'\\')">'+ic('activity')+'</button>'+flip+'<button class="act reset" title="'+esc(T('tip_reset'))+'" onclick="resetTraffic(\\''+l.id+'\\')">'+ic('reset')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" onclick="openLinkEdit(\\''+l.id+'\\')">'+ic('pen')+'</button><button class="act" title="'+esc(T('tip_rebuild'))+'" onclick="rebuildLink(\\''+l.id+'\\')">'+ic('redo')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" onclick="delLink(\\''+l.id+'\\')">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>'+esc(T('drift_note'))+'</span></div>':'';
 return accShell(l,false,drift+body+accBodyTraf(l)+acts+msg)}
async function refreshTunnels(){if(editingId||CHECKING)return;var f=await j('fleet?kind=tunnels&offset='+(PG.tunnels*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.tunnels));FLEET=f.links||[];TOT.tunnels=num(f.total);var box=el('linkList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(linkCard).join(''):'<div class="card muted">'+(QRY.tunnels?T('no_results'):T('tun_empty'))+'</div>');renderPager('tunnels')}
async function saveLinkEdit(id){var m=el('lem_'+id);var type=ssVal('lt_'+id),subnet=v('e_sub_'+id);
 if(!type){m.className='msg err';m.textContent=T('tun_type');return}
 var L=FLEET.find(function(x){return x.id==id})||{};
 var a_ip=ssVal('lipa_'+id)||L.a_ip||'',b_ip=ssVal('lipb_'+id)||L.b_ip||'';
 m.className='msg';m.textContent=T('rebuilding_both');
 var body={id:id,type:type,subnet:subnet,a_ip:a_ip,b_ip:b_ip};var pe=el('le_port_'+id);if(pe)body.port=pe.value.trim();
 var r=await post('edit-link',body);
 if(r.ok&&r.d.ok){delete CHK[id];closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=terr(r.d.error||r.d.msg||T('failed'))}}
function setChk(id,cls,html){CHK[id]={cls:cls,html:html};var m=el('lchk_'+id);if(m){m.className='msg '+cls;m.innerHTML=html}}
function chkLines(hdr,a,b){return '<div class="chh">'+hdr+'</div><div class="chl">'+esc(a)+'</div><div class="chl">'+esc(b)+'</div>'}
async function checkLink(id){CHECKING++;
 try{
  setChk(id,'',esc(T('checking_conn')));
  var r=await post('check-link',{id:id});
  var L=FLEET.filter(function(x){return x.id==id})[0]||{};
  if(!(r.ok&&r.d.ok)){setChk(id,'err',esc(terr((r.d&&(r.d.error||r.d.msg))||T('failed'))));return}
  var d=r.d,ab=el('lba_'+id),bb=el('lbb_'+id);
  if(ab)ab.innerHTML=sideDot(d.a_online,d.a_health);if(bb)bb.innerHTML=sideDot(d.b_online,d.b_health);
  var aup=d.a_online&&d.a_health&&d.a_health.up,bup=d.b_online&&d.b_health&&d.b_health.up;
  var pinged=(d.a_health&&d.a_health.peer_ping===true)||(d.b_health&&d.b_health.peer_ping===true);
  var okAll=aup&&bup&&pinged;
  setChk(id,okAll?'ok':'err',chkLines(okAll?CK+' '+T('conn_ok'):XK+' '+T('conn_bad'),
    (L.a_name||'A')+': '+sideTxt(d.a_online,d.a_health),(L.b_name||'B')+': '+sideTxt(d.b_online,d.b_health)));
 }finally{CHECKING--}}
async function checkAll(){var b=el('chkAllBtn');if(!FLEET.length){toast(T('no_tunnel_check'),'err');return}
 if(b){b.disabled=true;b.style.opacity='.6'}CHECKING++;  // hold guard across the whole batch
 try{await Promise.all(FLEET.map(function(l){return checkLink(l.id)}))}
 finally{CHECKING--;if(b){b.disabled=false;b.style.opacity=''}}
 toast(T('checkall_done'),'ok')}
async function rebuildLink(id){
 var _L=FLEET.filter(function(x){return x.id==id})[0];
 if(_L&&_L.drift){openRebuildPicker(id);return}   // IP drifted -> let the operator pick the new IP
 if(!await confirmBox(T('rebuild_confirm')))return;
 CHECKING++;
 try{setChk(id,'',esc(T('rebuilding_both')));
  var r=await post('rebuild-link',{id:id});
  if(r.ok&&r.d.ok){setChk(id,'ok',CK+esc(' '+T('rebuilt_test')));toast(T('t_rebuilt'),'ok')}
  else setChk(id,'err',esc(terr((r.d&&(r.d.error||r.d.msg))||T('rebuild_failed'))));
 }finally{CHECKING--}}
async function flipView(id){var r=await post('link-view',{id:id});
 if(r.ok&&r.d.ok){var L=FLEET.filter(function(x){return x.id==id})[0];var nm=L?(r.d.view_side=='b'?L.b_name:L.a_name):'';
  setChk(id,'ok',ic('swap')+esc(T('view_switched')+nm+T('view_switched2')));
  setTimeout(function(){if(CHK[id]){CHK[id]=null;var m=el('lchk_'+id);if(m){m.className='msg';m.innerHTML=''}}},4000);
  refreshFleet()}
 else{toast(T('failed'),'err')}}
async function resetTraffic(id){if(!await confirmBox(T('reset_confirm')))return;var r=await post('traffic-reset',{id:id});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshFleet()}else{toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
async function resetPfTraffic(i){var p=PF[i];if(!p)return;if(!await confirmBox(T('pf_reset_confirm')))return;var r=await post('traffic-reset',{node:p.node_id,name:p.name});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshPortfw()}else{toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
// ===== IP tags + rebuild IP picker (opens on بازسازی for a drift-flagged tunnel) =====
var LINKI='<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-1px"><path d="M9 7H6a4 4 0 000 8h3M15 7h3a4 4 0 010 8h-3M8 11h8"/></svg>';
var CK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-inline-start:3px"><path d="M20 6 9 17l-5-5"/></svg>';
var XK='<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-2px;margin-inline-start:3px"><path d="M18 6 6 18M6 6l12 12"/></svg>';
function ipChips(x){var t=(x.peers||[]).map(function(p){
  return '<span class="ippeer" onclick="ipTog(event,this)" title="'+esc(T('ip_toggle_hint'))+'"><span class="ipn">'+LINKI+' '+esc(p.node)+'</span><span class="ipi">'+esc(p.name||p.type)+'</span></span>'});
 (x.pf||[]).forEach(function(nm){t.push('<span class="ippf">'+ic('globe')+' '+esc(T('nd_portfw'))+' · '+esc(nm)+'</span>')});
 if(x.free)t.push('<span class="ipfree">'+esc(T('free'))+'</span>');return t.join('')}
function ipTog(ev,el){if(ev)ev.stopPropagation();el.classList.toggle('show')}
function ipTagsHTML(ips){ips=ips||[];if(!ips.length)return '<div class="muted" style="font-size:11.5px;padding:6px 2px">'+esc(T('ip_none'))+'</div>';
 return ips.map(function(x){return '<div class="iptag"><span class="mono" style="direction:ltr;font-size:12.5px">'+esc(x.ip)+'</span><span class="tgs">'+ipChips(x)+'</span></div>'}).join('')}
var _rbSel={},_rbOv=null;
function openRebuildPicker(id){
 j('link-rebuild-info?id='+id).then(function(r){
  if(!r||!r.id){toast(T('rb_no_link'),'err');return}
  _rbSel={};var secs='';
  [['a','a_ip'],['b','b_ip']].forEach(function(pp){var side=r[pp[0]],key=pp[1];
   if(!side||!side.drifted)return;
   var free=(side.ips||[]).filter(function(x){return x.free})[0];
   _rbSel[key]=free?free.ip:(((side.ips||[])[0]||{}).ip||'');
   secs+='<div class="nd-sec">'+esc(side.node)+' — '+esc(T('rb_newip'))+'</div><div class="rbsec">'+
     (side.ips&&side.ips.length?side.ips.map(function(x){return rbRow(key,x)}).join(''):'<div class="muted" style="font-size:12px;padding:4px 2px">'+esc(T('rb_no_ip'))+'</div>')+'</div>'});
  if(!secs){toast(T('rb_no_drift'),'ok');refreshTunnels();return}
  var body='<div style="color:var(--sub);font-size:12px;margin-bottom:12px">'+esc(T('rb_info'))+'</div>'+secs;
  _rbOv=openModal('<div class="msticky"><span class="medi">'+ic('redo')+'</span><div class="ttl"><h3>'+esc(T('rb_title'))+'</h3><div class="sb">'+esc(r.name||'')+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+body+'</div><div class="mfoot"><button class="primary" onclick="doRebuildPick(\\''+id+'\\')">'+ic('redo')+esc(T('tip_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');
 }).catch(function(){toast(T('rb_fetch_err'),'err')})}
function rbRow(key,x){var sel=_rbSel[key]==x.ip;
 return '<div class="rbrow'+(sel?' sel':'')+'" data-ip="'+esc(x.ip)+'" onclick="rbPick(\\''+key+'\\',this)"><span class="rbdot"></span><span class="mono" style="direction:ltr;font-size:13px">'+esc(x.ip)+'</span><span class="rbtags">'+ipChips(x)+'</span></div>'}
function rbPick(key,row){_rbSel[key]=row.getAttribute('data-ip');
 var sec=row.closest('.rbsec')||row.parentNode;sec.querySelectorAll('.rbrow').forEach(function(r){r.classList.remove('sel')});
 row.classList.add('sel')}
async function doRebuildPick(id){var body={id:id};if(_rbSel.a_ip)body.a_ip=_rbSel.a_ip;if(_rbSel.b_ip)body.b_ip=_rbSel.b_ip;
 toast(T('rebuilding'));
 var r=await post('rebuild-link',body);
 if(r.ok&&r.d.ok){toast(T('t_rebuilt'),'ok');if(_rbOv)closeModal(_rbOv);delete CHK[id];refreshFleet()}
 else toast(terr((r.d&&(r.d.error||r.d.msg))||T('rebuild_failed')),'err')}
async function delLink(id){if(!await confirmBox(T('del_tun_confirm')))return;var r=await post('delete-link',{id:id});if(!r.d.ok&&r.d.msg)toast(T('del_partial')+r.d.msg,'err');delete CHK[id];editingId=null;refreshFleet()}

// ===== Create
// one endpoint's IP field for the create forms: multi-IP -> dropdown; single-IP -> disabled box (like the edit form)
function ipField(k,ips,lab){
 if(ips.length>1)return '<label class="first">'+lab+'</label>'+ssHTML(k,ipItems(ips),(SEL[k]&&ips.indexOf(SEL[k])>=0?SEL[k]:ips[0]),T('ip'),'');
 delete SEL[k];return '<label class="first">'+lab+'</label><input class="mono" value="'+esc(ips[0]||'—')+'" disabled style="opacity:.6">'}
async function openCreateModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});selTargets={};
 if(on.length<2){toast(T('node_min2'),'err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<div class="grid2"><div><label class="first">'+esc(T('src_node'))+'</label>'+ssHTML('c_a',items,items[0].v,T('src_node'),'onCreateSrc')+'</div>'+
  '<div><label class="first">'+esc(T('dst_node'))+'</label>'+ssHTML('c_b',items,items[1].v,T('dst_node'),'onCreateDst')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="c_srcip"></div><div id="c_dstip"></div></div>'+
  '<label>'+esc(T('tun_type'))+'</label>'+ssHTML('c_type',TYPEITEMS,'vxlan',T('ttype'),'onCreateType')+'<div id="c_typex"></div>'+
  '<label>'+esc(T('local_range'))+'</label>'+ssHTML('c_snr',SUBNETRANGES(),'192.168',T('range'),'onSubnetRange')+'<div id="c_snc_wrap" style="display:none"><label>'+esc(T('custom_subnet'))+'</label><input id="c_subnet" placeholder="'+esc(T('custom_subnet_ph'))+'"></div><div class="msg" id="c_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>'+esc(T('add_tunnel_t'))+'</h3><div class="sb">'+esc(T('create_sub'))+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreate()">'+esc(T('create_tun_btn'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 renderSrcIp();renderDstIp();renderTypeExtra()}
function onSubnetRange(){var w=el('c_snc_wrap');if(w)w.style.display=(ssVal('c_snr')=='custom')?'block':'none'}
function onCreateSrc(){renderSrcIp()}
function onCreateDst(){renderDstIp()}
function renderDstIp(){var w=el('c_dstip');if(!w)return;w.innerHTML=ipField('c_bip',nodeIps(ssVal('c_b')),T('dst_ip'))}
function renderSrcIp(){var w=el('c_srcip');if(!w)return;w.innerHTML=ipField('c_aip',nodeIps(ssVal('c_a')),T('src_ip'))}
function onCreateType(){var f=el('c_subnet');if(f&&f.value.trim()){var wantV6=(ssVal('c_type')=='sit');
  if((f.value.indexOf(':')>=0)!=wantV6)f.value=''}
 renderTypeExtra()}
function renderTypeExtra(){var w=el('c_typex');if(!w)return;var t=ssVal('c_type');
 if(t=='l2tpv3'||t=='fou'){w.innerHTML='<label>'+esc(T('ttype_port_auto_lbl'))+'</label><input id="c_port" inputmode="numeric" placeholder="'+esc(T('ttype_port_ph'))+'"><div class="muted" style="font-size:11px;margin:6px 2px 11px">'+esc(T('ttype_l2_note'))+'</div>'}
 else if(t=='vxlan'){w.innerHTML='<label>'+esc(T('ttype_vxlan_lbl'))+'</label><input id="c_port" inputmode="numeric" placeholder="4789"><div class="muted" style="font-size:11px;margin:6px 2px 11px">'+esc(T('ttype_vxlan_note'))+'</div>'}
 else if(t=='ipsec'){w.innerHTML='<div class="autonote" style="margin-bottom:11px">'+ic('shield')+'<span>'+esc(T('ttype_ipsec_note'))+'</span></div>'}
 else w.innerHTML=''}
function nodeName(id){var n=NODES.find(function(x){return x.id==id});return n?n.name:id}
async function doCreate(){var m=el('c_msg');m.className='msg';var a=ssVal('c_a'),b=ssVal('c_b');
 if(a==b){m.className='msg err';m.textContent=T('two_diff_nodes');return}
 var type=ssVal('c_type'),range=ssVal('c_snr'),custom=v('c_subnet');
 var aip=el('ssb_c_aip')?ssVal('c_aip'):'',bip=el('ssb_c_bip')?ssVal('c_bip'):'';   // only send an IP when its picker exists (multi-IP node)
 var body={a_node:a,b_node:b,type:type,a_ip:aip,b_ip:bip};
 if(range=='custom')body.subnet=custom;else body.subnet_base=range;
 if((type=='l2tpv3'||type=='fou'||type=='vxlan')&&el('c_port')&&v('c_port'))body.port=v('c_port');
 m.textContent=T('creating_tun');
 var r=await post('create-tunnel',body);
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('tun_created'),'ok');refreshTunnels()}
 else{m.className='msg err';m.textContent=terr((r.d&&(r.d.error||r.d.msg))||T('failed'))}}

// ===== Custom core (packet/core) — its own view, list and create form
function coreSkel(){CHK={};el('view').innerHTML='<h1>'+ic('cpu','var(--acc)')+' '+esc(T('nav_core'))+'</h1><p class="sub">'+esc(T('core_sub'))+'</p>'+
 '<div class="tbtnrow"><button class="primary" onclick="openCoreModal()">'+ic('plus')+esc(T('core_add'))+'</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+esc(T('check_all'))+'</button></div>'+
 toolbar('core',T('core_search'))+'<div id="corList">'+skCards('core')+'</div>'+pagerBottom('core')}
async function refreshCore(){if(editingId||CHECKING)return;var f=await j('fleet?kind=core&offset='+(PG.core*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.core));FLEET=f.links||[];TOT.core=num(f.total);var box=el('corList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(coreCard).join(''):'<div class="card muted">'+(QRY.core?T('no_results'):T('core_empty'))+'</div>');renderPager('core');if(typeof refreshCardEdges=='function')setTimeout(refreshCardEdges,300)}
function coreMeta(l){   // right col under box A, left col under box B (lock at the START, green)
 var sub='<div>'+esc(T('subnet'))+': <b class="mono">'+esc(l.subnet)+'</b></div>';
 var tr=(l.transport=='tcp')?'TCP':(l.transport=='raw')?('RAW·'+esc((l.raw_profile||'bip').toUpperCase())):(l.transport=='flux')?('FLUX·'+esc((l.flux_carrier||'udp').toUpperCase())):(l.transport=='ws')?(l.ws_xhttp?('xHTTP·'+((l.ws_xhttp_mode=='grpc'||l.ws_xhttp_mode=='stream')?'grpc':'packet')):(l.ws_tls?'WSS':'WS')):'UDP';
 var prt=(l.transport!='raw'&&l.transport!='flux'&&l.port)?'<div>'+esc(T('port'))+': <b class="mono">'+esc(l.port)+'</b></div>':'';
 var car='<div>'+esc(T('carrier'))+': <b class="mono">'+tr+'</b></div>';
 var ifc='<div>'+esc(T('iface'))+': <b class="mono">'+esc(l.name)+'</b></div>';
 var typ='<div class="tagrow">'+esc(T('ttype'))+': <span class="tag core">Core</span></div>';
 var feats=[];
 if(l.transport=='ws'&&l.ws_pool)feats.push('<span class="tag obfs">pool</span>');
 if(l.transport=='ws'&&l.ws_tls)feats.push('<span class="tag obfs">wss</span>');if(l.sni_split)feats.push('<span class="tag obfs">SNI'+(l.sni_mode||'split')+'</span>');
 if(l.transport=='ws'&&l.ech)feats.push('<span class="tag obfs">ECH</span>');
 if(l.obfs)feats.push('<span class="tag obfs">obfs</span>');if(l.cover)feats.push('<span class="tag obfs">TLS</span>');if(l.gso)feats.push('<span class="tag obfs">GSO</span>');if(l.fec)feats.push('<span class="tag obfs">FEC '+((l.fec_data||10)+'+'+(l.fec_parity||3))+'</span>');if(l.fake_desync)feats.push('<span class="tag obfs">desync</span>');
 var cap='<div class="feat">'+esc(T('caps'))+': '+(feats.length?feats.join(' '):'<span class="nofeat">—</span>')+'</div>';
 var encv=(l.cipher&&l.cipher!='none')
   ?'<span class="encval">'+esc(l.cipher=='auto'?'aes-256-gcm':l.cipher)+'</span>'
   :'<b>'+esc(T('no_cipher'))+'</b>';
 var enc='<div class="enc-line">'+esc(T('enc'))+': '+encv+'</div>';
 // WS/CDN edge box: pool -> the LIVE active edge (filled by refreshCardEdges from the core
 // status file); single edge -> the fixed SNI · edge (static, no polling).
 var edge='';
 if(l.transport=='ws'){
   if(l.ws_pool){edge='<div class="cedge live"><div class="ct"><span class="cdot"></span>'+esc(T('active_edge'))+'</div><div class="echips" id="cardedge_'+l.id+'">'+edgeChips(EDGEV[l.id]||'')+'</div></div>';}
   else{var pp=[];if(l.ws_host)pp.push(esc(l.ws_host));if(l.edge_ip)pp.push(esc(l.edge_ip));
     if(pp.length)edge='<div class="cedge"><div class="ct">'+esc(T('cdn_edge'))+'</div><div class="cv mono">'+pp.join(' · ')+'</div></div>';}
 }
 return '<div class="enmeta"><div class="emcol">'+sub+prt+car+ifc+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+typ+cap+enc+'</div></div>'+edge}
function coreCard(l){
 var srvA=(l.server_side!='b');   // which end listens; stored on the record
 // Prefer the backend's FRESH active pool IP (api_fleet reads it from the client node); sync it into the
 // cache so a RELOAD paints the last active instantly from localStorage, then fall back to that cache,
 // then the stored anchor. No separate per-tunnel poll — the fleet refresh already carries the live IP.
 var _aA=l.a_ip_active||'',_aB=l.b_ip_active||'';
 if(_aA||_aB){var ch=false,ka=l.id+'_a',kb=l.id+'_b';
   if(_aA&&(PEERST[ka]||{}).ip!==_aA){PEERST[ka]={ip:_aA,rot:!!l.a_ip_rot};ch=true}
   if(_aB&&(PEERST[kb]||{}).ip!==_aB){PEERST[kb]={ip:_aB,rot:!!l.b_ip_rot};ch=true}
   if(ch)peerStSave();}
 var _pa=PEERST[l.id+'_a']||{},_pb=PEERST[l.id+'_b']||{};
 var _aip=_aA||_pa.ip||l.a_ip,_bip=_aB||_pb.ip||l.b_ip;
 var _arot=(l.a_ip_rot||_pa.rot)?rotMark():'',_brot=(l.b_ip_rot||_pb.rot)?rotMark():'';
 var body='<div class="tninfo">'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="rl '+(srvA?'srv':'cli')+'">'+(srvA?T('server'):T('client'))+'</span><span class="cprot" id="cprot_a_'+l.id+'">'+_arot+'</span><span class="stat" id="lba_'+l.id+'">'+accStat(l,'a')+'</span></div><div class="tna mono" id="cpip_a_'+l.id+'">'+esc(_aip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="rl '+(srvA?'cli':'srv')+'">'+(srvA?T('client'):T('server'))+'</span><span class="cprot" id="cprot_b_'+l.id+'">'+_brot+'</span><span class="stat" id="lbb_'+l.id+'">'+accStat(l,'b')+'</span></div><div class="tna mono" id="cpip_b_'+l.id+'">'+esc(_bip)+'</div></div>'+
  '</div>'+
  coreMeta(l);
 var c=CHK[l.id];var msg='<div class="msg '+(c?c.cls:'')+'" id="lchk_'+l.id+'">'+(c?c.html:'')+'</div>';
 var flip='<button class="act flip" onclick="flipView(\\''+l.id+'\\')" title="'+esc(T('tip_flip'))+esc(l.view_name||'—')+'">'+ic('swap')+'</button>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_ping'))+'" onclick="checkLink(\\''+l.id+'\\')">'+ic('activity')+'</button>'+flip+'<button class="act reset" title="'+esc(T('tip_reset'))+'" onclick="resetTraffic(\\''+l.id+'\\')">'+ic('reset')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" onclick="openCoreEdit(\\''+l.id+'\\')">'+ic('pen')+'</button><button class="act" title="'+esc(T('tip_rebuild'))+'" onclick="rebuildLink(\\''+l.id+'\\')">'+ic('redo')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" onclick="delLink(\\''+l.id+'\\')">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>'+esc(T('drift_note'))+'</span></div>':'';
 return accShell(l,true,drift+body+accBodyTraf(l)+acts+msg)}
var _corSrv='a',_corTr='udp',_corObfs=false,_corCover=false,_corRawProfile='bip',_corGso=false,_corFluxCarrier='udp',_corFluxRotate=600,_corFluxShape='random',_corWsTls=false,_corEch=false,_corXhttp=false,_corXhMode='packet',_corFec=false,_corFecData=10,_corFecParity=3,_corDesync=false,_corDesyncTtl=4,_corDesyncCount=2,_corDesyncMode='ttl',_corSniSplit=false,_corSplitPos=0,_corSniMode='split',_corSplitTtl=0;
function COR_RAW_PROFILES(){return [{v:'bip',m:T('rawp_bip_m'),tag:T('rawp_best')},{v:'icmp',m:T('rawp_icmp_m')},{v:'gre',m:T('rawp_gre_m'),warn:1},{v:'ipip',m:T('rawp_ipip_m'),warn:1},{v:'udp',m:T('rawp_udp_m')},{v:'tcp',m:T('rawp_tcp_m')}]}
function rawTiles(px,sel){return COR_RAW_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==sel?' on':'')+'" data-p="'+p.v+'" onclick="'+px+'SetProfile(\\''+p.v+'\\')">'+(p.tag?'<span class="best">'+esc(p.tag)+'</span>':'')+(p.warn?'<span class="pwarn" title="'+esc(T('rawp_warn'))+'"></span>':'')+'<div class="pn">'+p.v+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function WS_PROFILES(){return [{v:'ws',m:T('wsp_ws_m')},{v:'xhttp',m:T('wsp_xhttp_m')}]}
function wsProfTiles(px,cur){return WS_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==cur?' on':'')+'" data-wp="'+p.v+'" onclick="'+px+'SetWsProf(\\''+p.v+'\\')"><div class="pn">'+p.v+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function corSetWsProf(p){_corXhttp=(p=='xhttp');var g=el('e_wspg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-wp')==p)});var mb=el('e_xhmblk');if(mb)mb.style.display=_corXhttp?'':'none';corWssGate()}
function ceSetWsProf(p){_eeXhttp=(p=='xhttp');var g=el('ee_wspg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-wp')==p)});var mb=el('ee_xhmblk');if(mb)mb.style.display=_eeXhttp?'':'none';ceWssGate()}
// xhttp upstream style: packet-up (default) | stream-one. Shown only when the XHTTP profile is picked.
function XHTTP_MODES(){return [{v:'packet',n:'packet-up',m:T('xhm_packet_m')},{v:'grpc',n:'gRPC',m:T('xhm_grpc_m')}]}
function xhModeTiles(px,cur){return XHTTP_MODES().map(function(p){return '<button type="button" class="ptile'+(p.v==cur?' on':'')+'" data-xm="'+p.v+'" onclick="'+px+'SetXhMode(\\''+p.v+'\\')"><div class="pn">'+p.n+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function corSetXhMode(m){_corXhMode=m;var g=el('e_xhmpg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-xm')==m)});corWssGate()}
function ceSetXhMode(m){_eeXhMode=m;var g=el('ee_xhmpg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-xm')==m)});ceWssGate()}
function corSetTr(t){_corTr=t;['udp','tcp','raw','flux','ws'].forEach(function(x){var b=el('e_tr_'+x);if(b)b.classList.toggle('on',t==x)});var w=el('e_trword');if(w)w.textContent=(t=='tcp'?'TCP':(t=='raw'?'raw-IP':(t=='flux'?'flux':(t=='ws'?'ws/TCP':'UDP'))));corRawVis();corFluxVis();corWsVis();corPortGate();corCoverGate();corFecGate();corSpoofVis();corDesyncGate();corRotVis('e_')}
function corFluxVis(){var w=el('e_fluxblk');if(w)w.style.display=(_corTr=='flux')?'':'none';fluxTick()}
function corWsVis(){var ws=_corTr=='ws';var w=el('e_wsblk');if(w)w.style.display=ws?'':'none';var t=el('e_wstlsrow'),e=el('e_wsechrow');if(t)t.style.display=ws?'':'none';if(e)e.style.display=ws?'':'none';var sr=el('e_snisplitrow');if(sr)sr.style.display=ws?'':'none';var sb=el('e_snisplitbody');if(sb)sb.style.display=(ws&&_corSniSplit)?'':'none';if(ws){poolVis('e_');corWssGate()}}
function corToggleWsTls(){_corWsTls=!_corWsTls;var s=el('e_wstls');if(s)s.classList.toggle('on',_corWsTls);if(!_corWsTls){if(_corEch){_corEch=false;var e=el('e_wsech');if(e)e.classList.remove('on')}if(_corSniSplit){_corSniSplit=false;var q=el('e_snisplit');if(q)q.classList.remove('on');var b=el('e_snisplitbody');if(b)b.style.display='none'}}}
function corToggleSni(){if(!_corWsTls){_corSniSplit=false;var q=el('e_snisplit');if(q)q.classList.remove('on');alert(T('sni_need_wss'));return}_corSniSplit=!_corSniSplit;var s=el('e_snisplit');if(s)s.classList.toggle('on',_corSniSplit);var b=el('e_snisplitbody');if(b)b.style.display=_corSniSplit?'':'none'}
function corSetSniMode(m){_corSniMode=m;var g=el('e_snimodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_snim_'+m)});var b=el('e_snittlbody');if(b)b.style.display=(m!='split')?'':'none'}
// wss is MANDATORY for an edge pool and for the stream/gRPC xhttp modes (all need HTTP/2 to the
// edge). In those cases force the toggle on and grey it (pointer-events:none) so it can't be turned
// off in the UI only to be silently forced back on at save — the bug the user hit. Free otherwise.
function corWssGate(){var mand=poolGet('e_').pool||(_corXhttp&&(_corXhMode=='stream'||_corXhMode=='grpc'));var row=el('e_wstlsrow'),s=el('e_wstls');if(mand){_corWsTls=true;if(s)s.classList.add('on');if(row)row.classList.add('dis')}else if(row)row.classList.remove('dis')}
function corToggleEch(){if(!_corWsTls){_corEch=false;var e=el('e_wsech');if(e)e.classList.remove('on');alert(T('ech_need_wss_alert'));return}_corEch=!_corEch;var s=el('e_wsech');if(s)s.classList.toggle('on',_corEch)}
var _poolData={};
function poolInit(pfx,l){_poolData[pfx]={pool:!!(l&&l.ws_pool),rotate:(l&&l.ws_rotate_secs!=null)?l.ws_rotate_secs:600,autoBurn:l?!!l.ws_auto_burn:true,warm:l?!!l.ws_warm_standby:false,
  open:{ip:false,sni:false},act:{ip:'',sni:''},lid:(l&&l.id)||'',
  ip:{clean:((l&&l.ws_edge_ips)||[]).slice(),burned:((l&&l.ws_edge_ips_burned)||[]).slice()},
  sni:{clean:((l&&l.ws_edge_snis)||[]).map(function(s){return typeof s=='string'?s:((s&&s.host)||'')}).filter(Boolean),burned:((l&&l.ws_edge_snis_burned)||[]).slice()}};}
function poolGet(pfx){if(!_poolData[pfx])poolInit(pfx,null);return _poolData[pfx];}
// An edge IP must be a real IPv4 (four 0-255 octets, optional :port) or a real domain
// (labels + an alphabetic TLD); an SNI must be a real domain. This rejects garbage like
// "876889767" (no dots) AND "543.45534.453453" (dotted but not a valid IP or domain).
var _ip4Re=/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
var _domRe=/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
function poolValid(kind,val){var h=val;if(kind=='ip'){var c=val.lastIndexOf(':');if(c>=0){h=val.slice(0,c);var p=val.slice(c+1);if(!(/^\d+$/.test(p)&&+p>=1&&+p<=65535))return false;}return _ip4Re.test(h)||_domRe.test(h);}return _domRe.test(val);}
// poolRemain: seconds left until an entry's next retest, using the server clock sampled at the
// last poll plus the client-side elapsed time since — so the countdown ticks smoothly between polls.
function poolRemain(d,next){if(!next||!d.srvNow)return -1;var el=d.srvNow+(Date.now()-(d.polledMs||Date.now()))/1000;return Math.max(0,Math.round(next-el));}
function poolCdTxt(r){var m=Math.floor(r/60),s=r%60;return m+':'+(s<10?'0'+s:s);}
function poolCd(d,next){var r=poolRemain(d,next);if(r<0)return '';return '<span class="pcd" data-next="'+next+'">'+poolCdTxt(r)+'</span>';}
// Backoff schedule (must mirror the core): a suspect entry's current step length by fail count;
// a dead entry retests slowly. Used to draw the fill bar (elapsed / step) like the mockup.
var _poolBackoff=[30,60,120,300,600],_poolDeadStep=1800;
function poolStepTotal(h){return h.state=='dead'?_poolDeadStep:(_poolBackoff[Math.min(h.fails||0,4)]||600);}
function poolBarPct(d,h){var tot=poolStepTotal(h),rem=poolRemain(d,h.next);if(rem<0)return -1;return Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)));}
function poolBar(d,h){var p=poolBarPct(d,h);if(p<0)return '';return '<span class="pbar'+(h.state=='dead'?' bad':'')+'" data-next="'+h.next+'" data-tot="'+poolStepTotal(h)+'"><i style="width:'+p+'%"></i></span>';}
function poolRenderKind(pfx,kind){var d=poolGet(pfx);
  var lv=d.live||{};var ns=0,nd=0;d[kind].clean.forEach(function(v){var h=lv[kind+':'+v];if(h&&h.state=='suspect')ns++;else if(h&&h.state=='dead')nd++;});
  var hd=el(pfx+'hd_'+kind);if(hd){var nb=d[kind].burned.length;hd.innerHTML='<span class="pbadge ok">'+(d[kind].clean.length-ns-nd)+' '+T('pb_healthy')+'</span>'+(ns?'<span class="pbadge warn">'+ns+' '+T('pb_temp')+'</span>':'')+(nd?'<span class="pbadge bad">'+nd+' '+T('pb_dead')+'</span>':'')+(nb?'<span class="pbadge bad">'+nb+' '+T('pb_burned')+'</span>':'');}
  var host=el(pfx+'lst_'+kind);if(!host)return;
  function row(v,st){var dead=st=='burned';var act=!dead&&d.act&&d.act[kind]===v;
    var h=(!dead)?lv[kind+':'+v]:null;
    var rowc,sc,sic,stt;   // row stripe class, state-icon color class, state icon, tooltip
    if(dead){rowc='bad';sc='mut';sic='xc';stt=T('ph_burned_manual');}
    else if(h&&h.state=='dead'){rowc='bad';sc='bad';sic='xc';stt=T('ph_dead');}
    else if(h&&h.state=='suspect'){rowc='warn';sc='warn';sic='warn';stt=T('ph_suspect');}
    else if(act){rowc='ok';sc='ok';sic='bolt';stt=T('ph_active');}
    else{rowc='ok';sc='ok';sic='okc';stt=T('ph_healthy');}
    var rt=(h&&(h.state=='suspect'||h.state=='dead'))?'<span class="ert">'+poolCd(d,h.next)+poolBar(d,h)+'</span>':'';
    var acts='';
    if(dead){
      acts='<button type="button" class="eib" title="'+esc(T('pa_restore'))+'" onclick="poolMove(\\''+pfx+'\\',\\''+kind+'\\',\\''+st+'\\',\\''+esc(v)+'\\')">'+ic('swap')+'</button>';
    }else{
      if(h&&(h.state=='suspect'||h.state=='dead')&&d.lid)acts+='<button type="button" class="eib" title="'+esc(T('pa_testnow'))+'" onclick="poolProbeNow(\\''+d.lid+'\\')">'+ic('redo')+'</button>';
      if(d.lid){var pend=d.pinPending;var isTarget=pend&&pend.kind==kind&&pend.key==v;
        if(pend)acts+='<button type="button" class="eib aim'+(act?' on':'')+'" disabled style="opacity:.45;pointer-events:none" title="'+esc(T('pa_pinning'))+'">'+(isTarget?'<span class="bspin"></span>':ic('pin'))+'</button>';
        else acts+='<button type="button" class="eib aim'+(act?' on':'')+'" title="'+(act?esc(T('pa_active_ip')):esc(T('pa_activate')))+'" onclick="poolSelect(\\''+d.lid+'\\',\\''+kind+'\\',\\''+esc(v)+'\\')">'+ic('pin')+'</button>';}
    }
    acts+='<button type="button" class="eib del" title="'+esc(T('tip_delete'))+'" onclick="poolDel(\\''+pfx+'\\',\\''+kind+'\\',\\''+st+'\\',\\''+esc(v)+'\\')">'+ic('trash')+'</button>';
    return '<div class="erow '+rowc+((dead||(h&&h.state=='dead'))?' dead':'')+'">'
     +'<span class="estat '+sc+'" title="'+stt+'">'+ic(sic)+'</span>'
     +'<span class="eip" title="'+esc(v)+'">'+esc(v)+'</span>'+rt
     +'<span class="eacts">'+acts+'</span></div>';}
  var html=d[kind].clean.map(function(v){return row(v,'clean')}).join('')+d[kind].burned.map(function(v){return row(v,'burned')}).join('');
  host.innerHTML=html||'<div class="pempty">'+esc(T('pool_empty'))+'</div>';}
function poolAccApply(pfx,kind){var d=poolGet(pfx),b=el(pfx+'body_'+kind),c=el(pfx+'chev_'+kind);if(b)b.style.display=d.open[kind]?'':'none';if(c)c.classList.toggle('open',d.open[kind]);}
function poolAcc(pfx,kind){var d=poolGet(pfx);d.open[kind]=!d.open[kind];poolAccApply(pfx,kind);}
function poolRender(pfx){['ip','sni'].forEach(function(k){poolRenderKind(pfx,k);poolAccApply(pfx,k);});var d=poolGet(pfx);var ab=el(pfx+'poolab');if(ab)ab.classList.toggle('on',d.autoBurn);var w=el(pfx+'poolwarm');if(w)w.classList.toggle('on',d.warm);}
function poolAdd(pfx,kind){var i=el(pfx+'add_'+kind);if(!i)return;var val=(i.value||'').trim();if(kind=='sni')val=val.toLowerCase();if(!val)return;if(!poolValid(kind,val)){alert(kind=='ip'?T('pool_bad_ip'):T('pool_bad_dom'));return;}var d=poolGet(pfx);if(d[kind].clean.indexOf(val)>=0||d[kind].burned.indexOf(val)>=0){i.value='';return;}d[kind].clean.push(val);i.value='';d.open[kind]=true;poolAccApply(pfx,kind);poolRenderKind(pfx,kind);}
function poolMove(pfx,kind,from,val){var d=poolGet(pfx),to=from=='clean'?'burned':'clean';d[kind][from]=d[kind][from].filter(function(x){return x!=val});if(d[kind][to].indexOf(val)<0)d[kind][to].push(val);poolRenderKind(pfx,kind);}
function poolDel(pfx,kind,from,val){var d=poolGet(pfx);d[kind][from]=d[kind][from].filter(function(x){return x!=val});poolRenderKind(pfx,kind);}
function poolToggleAB(pfx){var d=poolGet(pfx);d.autoBurn=!d.autoBurn;var ab=el(pfx+'poolab');if(ab)ab.classList.toggle('on',d.autoBurn);}
function poolToggleWarm(pfx){var d=poolGet(pfx);d.warm=!d.warm;var w=el(pfx+'poolwarm');if(w)w.classList.toggle('on',d.warm);}
function poolVis(pfx){var d=poolGet(pfx),s=el(pfx+'wshostblk'),p=el(pfx+'wspool'),t=el(pfx+'pooltgl');if(t)t.classList.toggle('on',d.pool);if(s)s.style.display=d.pool?'none':'';if(p)p.style.display=d.pool?'':'none';if(d.pool)poolRender(pfx);}
function poolToggle(pfx){poolGet(pfx).pool=!poolGet(pfx).pool;poolVis(pfx);}
function poolCollect(pfx,body){var d=poolGet(pfx);if(!d.pool){body.ws_pool=false;return true;}var rv=ssVal(pfx+'poolrot');if(rv!=='')d.rotate=+rv;if(!d.ip.clean.length||!d.sni.clean.length)return T('pool_need_clean');body.ws_pool=true;body.ws_tls=true;body.ws_edge_ips=d.ip.clean;body.ws_edge_ips_burned=d.ip.burned;body.ws_edge_snis=d.sni.clean;body.ws_edge_snis_burned=d.sni.burned;body.ws_rotate_secs=d.rotate;body.ws_auto_burn=d.autoBurn;body.ws_warm_standby=d.warm;return true;}
function corTogglePool(){poolToggle('e_');corWssGate()}
function ceTogglePool(){poolToggle('ee_');ceWssGate()}
function corSetFluxCarrier(c){_corFluxCarrier=c;var g=el('e_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fc]'),function(t){t.classList.toggle('on',t.getAttribute('data-fc')==c)});fluxTick()}
function corSetFluxShape(s){_corFluxShape=s;var g=el('e_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fs]'),function(t){t.classList.toggle('on',t.getAttribute('data-fs')==s)})}
function corFluxRotChg(){_corFluxRotate=parseInt(ssVal('e_fluxrot'))||600;fluxTick()}
function corFecDatagram(){return _corTr=='udp'||_corTr=='raw'||_corTr=='flux'}
function corToggleFec(){if(!corFecDatagram())return;_corFec=!_corFec;var s=el('e_fecsw');if(s)s.classList.toggle('on',_corFec);var r=el('e_fecrates');if(r)r.style.display=_corFec?'':'none'}
function corSetFecRate(d,p){_corFecData=d;_corFecParity=p;var g=el('e_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function corFecGate(){var dg=corFecDatagram(),row=el('e_fecrow');if(!dg){_corFec=false;var s=el('e_fecsw');if(s)s.classList.remove('on');var r=el('e_fecrates');if(r)r.style.display='none'}if(row)row.style.display=dg?'':'none'}
async function doFluxRotate(id){var r=await post('flux-rotate',{id:id});if(r.ok&&r.d.ok){toast(T('flux_rotated'),'ok');fluxTick()}else{toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
// Live edge-pool status: poll the active edge for the open edit link and reflect it (active
// row highlight + live bar), plus mirror any auto-burns the core reported. doPoolRotate signals
// the core to jump one dimension with no rebuild, then re-polls shortly after.
var _eePoolLid='';
function poolApplyStatus(pfx,st){var d=poolGet(pfx);var a=String(st.active||'').split(' · ');
  d.act={ip:(a[0]||'').trim(),sni:(a[1]||'').trim()};
  d.live={};(st.health||[]).forEach(function(h){if(h&&h.key)d.live[(h.kind=='sni'?'sni':'ip')+':'+h.key]={state:String(h.state||'healthy'),next:+h.next_retest_unix||0,fails:+h.fails||0}});
  d.srvNow=+st.now||Math.floor(Date.now()/1000);d.polledMs=Date.now();
  // release the pin lock once the chosen edge is confirmed active (or after a 12s safety timeout)
  if(d.pinPending){var pk=d.pinPending;if(d.act[pk.kind]===pk.key||(Date.now()-pk.ts>12000))d.pinPending=null;}
  poolRenderKind(pfx,'ip');poolRenderKind(pfx,'sni');}  // live health (سالم/موقت/دائمی) + active edge overlay onto the rows
async function poolTick(){if(!_eePoolLid)return;if(!poolGet('ee_').pool)return;var r=await post('edge-status',{id:_eePoolLid});if(r.ok&&r.d&&r.d.ok&&r.d.pool)poolApplyStatus('ee_',r.d);}
(function poolLoop(){setTimeout(function(){Promise.resolve(poolTick()).then(poolLoop,poolLoop)},UIV)})();   // live-cadence self-loop
// Tick the retest countdown spans between polls so «سوختهٔ موقت/دائمی» rows show a live timer.
function poolCdTick(){var d=_poolData['ee_'];if(!d||!d.live)return;['ip','sni'].forEach(function(k){var host=el('ee_lst_'+k);if(!host)return;
  Array.prototype.forEach.call(host.querySelectorAll('.pcd'),function(sp){var r=poolRemain(d,+sp.getAttribute('data-next'));if(r>=0)sp.textContent=poolCdTxt(r)});
  Array.prototype.forEach.call(host.querySelectorAll('.pbar'),function(bar){var tot=+bar.getAttribute('data-tot')||1,rem=poolRemain(d,+bar.getAttribute('data-next'));if(rem<0)return;var i=bar.firstChild;if(i)i.style.width=Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)))+'%'})})}
setInterval(poolCdTick,1000);
// "Probe now": SIGHUP the core (via node) to retest every suspect/dead edge at once.
async function poolProbeNow(lid){if(!lid){toast(T('pool_make_first'),'err');return}var r=await post('pool-probe-now',{id:lid});if(r.ok&&r.d&&r.d.ok){toast(T('pool_probe_sent'),'ok');[1200,3000,5500,8000].forEach(function(ms){setTimeout(poolTick,ms)})}else{toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
// "select this edge": pin a specific IP/SNI as the active one (exact jump, no rebuild).
async function poolSelect(lid,kind,key){if(!lid){toast(T('pool_make_first'),'err');return}
  var d=poolGet('ee_');
  if(d.pinPending)return;                                   // a pin is already in flight — ignore spam clicks
  d.pinPending={kind:kind,key:key,ts:Date.now()};           // lock ALL pin buttons until this edge is confirmed active
  poolRenderKind('ee_','ip');poolRenderKind('ee_','sni');
  var r=await post('pool-select',{id:lid,kind:kind,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('pool_edge_active'),'ok');[1200,3000,5500,8000,11000].forEach(function(ms){setTimeout(poolTick,ms)})}
  else{d.pinPending=null;poolRenderKind('ee_','ip');poolRenderKind('ee_','sni');toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
// Split the active edge "IP:port · domain" into two clean chips (IP primary, domain muted).
function edgeChips(v){v=String(v||'');
 if(!v)return '<span class="echip wait">…</span>';
 var p=v.split(' · '),ip=p[0]||'',dom=p.slice(1).join(' · ');
 var h='<span class="echip ip">'+esc(ip)+'</span>';
 if(dom)h+='<span class="echip dom">'+esc(dom)+'</span>';
 return h}
// Fleet cards: fill each pool card's «لبهٔ فعالِ فعلی» box from the core status file.
async function refreshCardEdges(){var els=document.querySelectorAll('[id^="cardedge_"]');
 await Promise.all(Array.prototype.map.call(els,function(elm){var lid=elm.id.slice(9);   // parallel, not one-by-one
  return post('edge-status',{id:lid}).then(function(r){if(r.ok&&r.d&&r.d.ok&&r.d.pool){var v=r.d.active||'';
    if(v&&v!==EDGEV[lid]){EDGEV[lid]=v;var e=el('cardedge_'+lid);if(e)e.innerHTML=edgeChips(v)}}},function(){})}))}   // only rewrite when the edge actually changed (no dash flicker)
(function edgesLoop(){setTimeout(function(){refreshCardEdges().then(edgesLoop,edgesLoop)},UIV)})();   // live-cadence self-loop
// Fleet cards for direct-transport IP-rotation tunnels show the CURRENTLY-ACTIVE pool IP in each node box
// (server box = active destination, client box = active source) plus a rotation mark on any node whose
// IPs rotate. The active IP arrives with the fleet data (api_fleet reads it from the client node), so
// coreCard just renders l.*_ip_active — no separate poll — and syncs it to localStorage for instant reload.
function rotMark(){return '<span class="rotmark" title="'+esc(T('peer_rotating'))+'">'+ic('redo')+'</span>'}
// ===== live status for a direct-transport IP-rotation pool (udp/tcp/raw/flux) — the ws edge pool's
// per-edge health/pin/probe view, adapted to the peer pool's two single-axis boxes (مقصد + مبدأ). Shown
// in the core edit modal for a running pooled tunnel; poll -> render rows (فعال / در چرخش / سوختهٔ موقت
// / سوختهٔ دائمی) with a retest countdown and a per-IP pin button, plus a "test all" (probe-now) button.
var _peerLid='';
var _peerData={dst:null,src:null,now:0,polledMs:0,pinPending:null};
async function peerTick(){if(!_peerLid||!el('ee_peerlive'))return;var r=await post('peer-status',{id:_peerLid});if(r.ok&&r.d&&r.d.ok&&r.d.pool)peerApply(r.d);}
(function peerLoop(){setTimeout(function(){Promise.resolve(peerTick()).then(peerLoop,peerLoop)},UIV)})();   // live-cadence self-loop
function peerApply(st){
  _peerData.now=+st.now||Math.floor(Date.now()/1000);_peerData.polledMs=Date.now();
  ['dst','src'].forEach(function(side){var sec=st[side]||{};var live={};
    (sec.health||[]).forEach(function(h){if(h&&h.key)live[h.key]={state:String(h.state||'healthy'),next:+h.next_retest_unix||0,fails:+h.fails||0}});
    _peerData[side]={active:String(sec.active||''),addrs:(sec.addrs||[]).map(String),pin:String(sec.pin||''),live:live};});
  if(_peerData.pinPending){var pk=_peerData.pinPending,sec=_peerData[pk.side]||{};if(sec.active===pk.key||(Date.now()-pk.ts>12000))_peerData.pinPending=null;}
  peerRender();}
function peerRemain(next){if(!next||!_peerData.now)return -1;var e=_peerData.now+(Date.now()-(_peerData.polledMs||Date.now()))/1000;return Math.max(0,Math.round(next-e));}
function peerCd(next){var r=peerRemain(next);if(r<0)return '';return '<span class="pcd" data-next="'+next+'">'+poolCdTxt(r)+'</span>';}
function peerBar(h){var tot=poolStepTotal(h),rem=peerRemain(h.next);if(rem<0)return '';var p=Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)));return '<span class="pbar'+(h.state=='dead'?' bad':'')+'" data-next="'+h.next+'" data-tot="'+tot+'"><i style="width:'+p+'%"></i></span>';}
function peerRow(side,ip){var d=_peerData[side],h=d.live[ip],act=(d.active===ip);
  var rowc,sc,sic,stt;
  if(h&&h.state=='dead'){rowc='bad';sc='bad';sic='xc';stt=T('ph_dead');}
  else if(h&&h.state=='suspect'){rowc='warn';sc='warn';sic='warn';stt=T('ph_suspect');}
  else if(act){rowc='ok';sc='ok';sic='bolt';stt=T('peer_st_active');}
  else{rowc='ok';sc='ok';sic='okc';stt=T('peer_st_rot');}
  var burned=(h&&(h.state=='suspect'||h.state=='dead'));
  // Countdown now lives UNDER the IP (its own indented line) so the box grows to two lines instead of
  // squeezing the retest timer beside the address — matches the WS-CDN-parity mockup the user approved.
  var cd=burned?'<div class="ecd">'+peerCd(h.next)+peerBar(h)+'</div>':'';
  var pend=_peerData.pinPending,isTarget=pend&&pend.side==side&&pend.key==ip,acts='';
  // Per-IP probe (↻) on a burned endpoint pulls its retest forward — same pool-wide SIGHUP the WS-CDN
  // per-row probe uses (the core retests every burned edge at once; there is no single-IP probe op).
  // Per-IP test button, only on a BURNED (suspect/dead) row — that is where it means something: it pulls
  // the pool's retest forward so the edge can rejoin rotation sooner. A healthy IP has nothing to test
  // (the direct pool has no single-IP out-of-band prober; retest = data-plane re-admission).
  if(burned&&_peerLid)acts+='<button type="button" class="eib" title="'+esc(T('pa_testnow'))+'" onclick="peerProbeNow()">'+ic('redo')+'</button>';
  // The IP goes in a data-* attribute (read via getAttribute in the handler), NOT interpolated into the
  // onclick JS string — the browser HTML-decodes an attribute before compiling a handler, so esc() alone
  // would let a crafted addr from the node's status file break out of the string (XSS). data-* is inert.
  if(pend)acts+='<button type="button" class="eib aim'+(act?' on':'')+'" disabled style="opacity:.45;pointer-events:none" title="'+esc(T('pa_pinning'))+'">'+(isTarget?'<span class="bspin"></span>':ic('pin'))+'</button>';
  else acts+='<button type="button" class="eib aim'+(act?' on':'')+'" title="'+(act?esc(T('pa_active_ip')):esc(T('pa_activate')))+'" data-side="'+side+'" data-ip="'+esc(ip)+'" onclick="peerSelect(this)">'+ic('pin')+'</button>';
  // No delete button here on purpose: an IP is removed from the pool in the rotation-config section
  // (drop it + Save rebuilds), so a second live-view delete would just be a redundant path.
  return '<div class="erow pcol '+rowc+((h&&h.state=='dead')?' dead':'')+'"><div class="etop"><span class="estat '+sc+'" title="'+stt+'">'+ic(sic)+'</span><span class="eip" title="'+esc(ip)+'">'+esc(ip)+'</span><span class="eacts">'+acts+'</span></div>'+cd+'</div>';}
function peerBox(side,lab){var d=_peerData[side];if(!d||!d.addrs.length)return '';
  var live=d.live||{},ns=0,nd=0;d.addrs.forEach(function(ip){var h=live[ip];if(h&&h.state=='suspect')ns++;else if(h&&h.state=='dead')nd++;});
  var badges='<span class="pbadge ok">'+(d.addrs.length-ns-nd)+' '+T('pb_healthy')+'</span>'+(ns?'<span class="pbadge warn">'+ns+' '+T('pb_temp')+'</span>':'')+(nd?'<span class="pbadge bad">'+nd+' '+T('pb_dead')+'</span>':'');
  return '<div class="plbox"><div class="plbl">'+esc(lab)+'<span class="plbadges">'+badges+'</span></div><div class="rpool">'+d.addrs.map(function(ip){return peerRow(side,ip)}).join('')+'</div></div>';}
function peerRender(){var host=el('ee_peerlive');if(!host)return;
  var boxes=peerBox('dst',T('dst_ip'))+peerBox('src',T('src_ip'));
  // No live data yet: rather than a blank gap (which reads as "the feature is missing"), show WHY — the
  // pool status appears only once the tunnel is running on the up-to-date node/core. peerTick only calls
  // this on a pool:true response, and _peerLid is set only for a rotating tunnel, so the hint is apt.
  if(!boxes){host.innerHTML='<div class="peerlive"><div class="pllabel">'+esc(T('peer_live_hd'))+'</div><div class="muted" style="font-size:11px;line-height:1.7">'+esc(T('peer_live_empty'))+'</div></div>';return;}
  host.innerHTML='<div class="peerlive"><div class="pllabel">'+esc(T('peer_live_hd'))+'</div>'+boxes+'<div class="muted" style="font-size:10.5px;line-height:1.7;margin-top:2px">'+esc(T('peer_live_note'))+'</div></div>';}
function peerCdTick(){if(!_peerLid)return;var host=el('ee_peerlive');if(!host)return;
  Array.prototype.forEach.call(host.querySelectorAll('.pcd'),function(sp){var r=peerRemain(+sp.getAttribute('data-next'));if(r>=0)sp.textContent=poolCdTxt(r)});
  Array.prototype.forEach.call(host.querySelectorAll('.pbar'),function(bar){var tot=+bar.getAttribute('data-tot')||1,rem=peerRemain(+bar.getAttribute('data-next'));if(rem<0)return;var i=bar.firstChild;if(i)i.style.width=Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)))+'%'})}
setInterval(peerCdTick,1000);
async function peerSelect(btn){var side=btn.getAttribute('data-side'),key=btn.getAttribute('data-ip');
  if(!_peerLid||_peerData.pinPending||!key)return;
  _peerData.pinPending={side:side,key:key,ts:Date.now()};peerRender();
  var r=await post('peer-select',{id:_peerLid,side:side,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('peer_pinned'),'ok');[1200,3000,5500,8000,11000].forEach(function(ms){setTimeout(peerTick,ms)})}
  else{_peerData.pinPending=null;peerRender();toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
async function peerProbeNow(){if(!_peerLid)return;var r=await post('peer-probe-now',{id:_peerLid});
  if(r.ok&&r.d&&r.d.ok){toast(T('pool_probe_sent'),'ok');[1200,3000,5500,8000].forEach(function(ms){setTimeout(peerTick,ms)})}
  else{toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
// ---- IP spoofing (decoy) section — shared markup + per-form logic. Only for raw + bip.
function spoofSection(idp,fnp){return '<div class="spoofsec" id="'+idp+'spoofblk" style="display:none">'
 +'<div class="spoofhd">'+ic('shield')+esc(T('spoof_hd'))+'</div>'
 +'<div class="tglbox" id="'+idp+'decoyrow"><div class="tglsw" id="'+idp+'decoysw" onclick="'+fnp+'ToggleDecoy()"></div><div class="tt"><b>'+esc(T('spoof_decoy_t'))+'</b><small>'+esc(T('spoof_decoy_d'))+'</small></div></div>'
 +'<div id="'+idp+'decoyiprow" style="display:none;margin:8px 0 2px"><input id="'+idp+'decoyip" class="mono" placeholder="'+esc(T('spoof_decoy_ph'))+'" inputmode="numeric"></div>'
 +'<div class="tglbox" id="'+idp+'srcrow"><div class="tglsw" id="'+idp+'srcsw" onclick="'+fnp+'ToggleSrc()"></div><div class="tt"><b>'+esc(T('spoof_src_t'))+'</b><small>'+esc(T('spoof_src_d'))+'</small></div></div>'
 +'<div id="'+idp+'srciprow" style="display:none;margin:8px 0 2px"><input id="'+idp+'srcip" class="mono" placeholder="'+esc(T('spoof_src_ph'))+'" inputmode="numeric"></div>'
 +'<div class="spoofcap wait" id="'+idp+'cap">…</div></div>'}
async function spoofProbePair(a,b){try{
  var ra=await j('spoof-probe?node='+encodeURIComponent(a));
  var rb=(a==b)?ra:await j('spoof-probe?node='+encodeURIComponent(b));
  if(ra.ok&&rb.ok)return {ok:true,html:T('spoof_cap_ok')};
  var bad=(!ra.ok)?ra:rb;
  return {ok:false,html:T('spoof_cap_bad_pre')+esc(bad.node||'?')+T('spoof_cap_bad_mid')+esc(terr(bad.reason)||T('spoof_reason_unknown'))};
 }catch(e){return {ok:false,html:T('spoof_cap_err')}}}
function spoofApplyCap(idp,ok,html,offFn){var cap=el(idp+'cap');if(cap){cap.className='spoofcap '+(ok?'ok':'no');cap.innerHTML=(ok?ic('okc'):ic('xc'))+'<span>'+html+'</span>'}
 var dr=el(idp+'decoyrow'),sr=el(idp+'srcrow');
 if(dr)dr.classList.toggle('dis',!ok);if(sr)sr.classList.toggle('dis',!ok);
 if(!ok&&offFn)offFn()}
// ---- flux (polymorphic moving-target carrier) — shared markup + live epoch status.
function FLUX_ROTS(){return [{v:'600',label:T('frot_600')},{v:'300',label:T('frot_300')},{v:'1800',label:T('frot_1800')},{v:'3600',label:T('frot_3600')}]}
function FLUX_SHAPES(){return [{v:'random',n:T('fsh_random_n'),m:T('fsh_random_m')},{v:'quic',n:'QUIC',m:T('fsh_quic_m')},{v:'video',n:T('fsh_video_n'),m:T('fsh_video_m')},{v:'webrtc',n:'WebRTC',m:T('fsh_webrtc_m')}]}
// FEC redundancy presets: data+parity, overhead label, and the max burst loss they repair.
function FEC_RATES(){return [{d:10,p:2,n:T('fec_light'),ov:T('fec_ov20')},{d:10,p:3,n:T('fec_balanced'),ov:T('fec_ov30')},{d:8,p:4,n:T('fec_strong'),ov:T('fec_ov50')}]}
function fluxSection(idp,fnp,fc,rot,shp,rotId){return '<div id="'+idp+'fluxblk" style="display:none">'
 +'<label>'+esc(T('flux_carrier_lbl'))+'</label>'
 +'<div class="pgrid">'
 +'<button type="button" class="ptile'+(fc=='udp'?' on':'')+'" data-fc="udp" onclick="'+fnp+'SetFluxCarrier(\\'udp\\')"><span class="best">'+esc(T('flux_udp_best'))+'</span><div class="pn">udp</div><div class="pmeta">'+esc(T('flux_udp_m'))+'</div></button>'
 +'<button type="button" class="ptile'+(fc=='stun'?' on':'')+'" data-fc="stun" onclick="'+fnp+'SetFluxCarrier(\\'stun\\')"><span class="best">WebRTC</span><div class="pn">stun</div><div class="pmeta">'+esc(T('flux_stun_m'))+'</div></button>'
 +'<button type="button" class="ptile'+(fc=='raw'?' on':'')+'" data-fc="raw" onclick="'+fnp+'SetFluxCarrier(\\'raw\\')"><span class="pwarn" title="'+esc(T('flux_raw_warn'))+'"></span><div class="pn">raw</div><div class="pmeta">'+esc(T('flux_raw_m'))+'</div></button>'
 +'</div>'
 +'<label>'+esc(T('flux_shape_lbl'))+'</label>'
 +'<div class="pgrid">'+FLUX_SHAPES().map(function(p){return '<button type="button" class="ptile'+(p.v==(shp||'random')?' on':'')+'" data-fs="'+p.v+'" onclick="'+fnp+'SetFluxShape(\\''+p.v+'\\')"><div class="pn">'+esc(p.n)+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')+'</div>'
 +'<label>'+esc(T('flux_rot_lbl'))+'</label>'+ssHTML(idp+'fluxrot',FLUX_ROTS(),String(rot||600),T('flux_rot_ph'),fnp+'FluxRotChg')
 +'<div id="'+idp+'fluxstat" style="margin-top:10px;font-size:11.5px;padding:8px 11px;border-radius:9px;line-height:1.8;background:color-mix(in srgb,var(--ok) 9%,transparent);border:1px solid color-mix(in srgb,var(--ok) 28%,transparent)">…</div>'
 +(rotId?'<button type="button" class="ghost" style="margin-top:9px;width:100%;display:inline-flex;align-items:center;justify-content:center;gap:6px" onclick="doFluxRotate(\\''+rotId+'\\')">'+ic('redo')+esc(T('flux_rotate_btn'))+'</button>':'')
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">'+T('flux_note')+'</div>'
 +'</div>'}
// ---- FEC (forward error correction) — a general feature box shown for every carrier, but
// active only on the datagram carriers (udp/raw/flux); greyed on tcp/ws (TCP is already reliable).
function fecSection(idp,fnp,fec,fd,fp,dg){return '<div id="'+idp+'fecrow" class="tglbox" style="margin-top:11px'+(dg?'':';display:none')+'"><div class="tglsw'+(fec&&dg?' on':'')+'" id="'+idp+'fecsw" onclick="'+fnp+'ToggleFec()"></div><div class="tt"><b>'+esc(T('fec_t'))+'</b><small>'+esc(T('fec_d'))+'</small></div></div>'
 +'<div id="'+idp+'fecrates" style="'+(fec?'':'display:none')+'"><label>'+esc(T('fec_rate_lbl'))+'</label><div class="pgrid">'+FEC_RATES().map(function(r){var sel=(r.d==(fd||10)&&r.p==(fp||3));return '<button type="button" class="ptile'+(sel?' on':'')+'" data-fd="'+r.d+'" data-fp="'+r.p+'" onclick="'+fnp+'SetFecRate('+r.d+','+r.p+')"><div class="pn">'+r.d+'+'+r.p+'</div><div class="pmeta">'+esc(r.n)+'</div><div class="pmeta" style="color:var(--warn)">'+esc(r.ov)+'</div></button>'}).join('')+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+esc(T('fec_note'))+'</div></div>'}
// fake-packet desync (anti-DPI) — a gated feature box shown ONLY on the raw/flux carriers (the ones
// the core builds the IPv4 header for). Shared create/edit markup; toggle reveals mode + ttl/count.
function DS_MODES(){return [{v:'ttl',t:T('ds_m_ttl_t'),s:T('ds_m_ttl_s')},{v:'badsum',t:T('ds_m_bad_t'),s:T('ds_m_bad_s')},{v:'both',t:T('ds_m_both_t'),s:T('ds_m_both_s')}]}
function desyncSection(idp,fnp,on,ttl,count,mode,show){return '<div id="'+idp+'dsrow" class="tglbox" style="margin-top:11px'+(show?'':';display:none')+'"><div class="tglsw'+(on&&show?' on':'')+'" id="'+idp+'dssw" onclick="'+fnp+'ToggleDesync()"></div><div class="tt"><b>'+esc(T('ds_t'))+'</b><small>'+esc(T('ds_d'))+'</small></div></div>'
 +'<div id="'+idp+'dsbody" style="'+(on&&show?'':'display:none')+'"><label>'+esc(T('ds_mode_lbl'))+'</label><div class="seg2" id="'+idp+'dsmodeseg">'+DS_MODES().map(function(m){return '<button type="button" class="segopt'+(m.v==(mode||'ttl')?' on':'')+'" id="'+idp+'dsm_'+m.v+'" onclick="'+fnp+'SetDesyncMode(\\''+m.v+'\\')"><b>'+esc(m.t)+'</b><span>'+esc(m.s)+'</span></button>'}).join('')+'</div>'
 +'<div class="grid2"><div><label>'+esc(T('ds_ttl_lbl'))+'</label><input id="'+idp+'dsttl" dir="ltr" inputmode="numeric" value="'+(ttl||4)+'"></div><div><label>'+esc(T('ds_count_lbl'))+'</label><input id="'+idp+'dscount" dir="ltr" inputmode="numeric" value="'+(count||2)+'"></div></div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+esc(T('ds_note'))+'</div></div>'}
function corToggleDesync(){_corDesync=!_corDesync;var s=el('e_dssw');if(s)s.classList.toggle('on',_corDesync);var b=el('e_dsbody');if(b)b.style.display=_corDesync?'':'none'}
function corSetDesyncMode(m){_corDesyncMode=m;var g=el('e_dsmodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_dsm_'+m)})}
function corDesyncGate(){var dg=(_corTr=='raw'||_corTr=='flux'||_corTr=='tcp'||_corTr=='ws'),row=el('e_dsrow');if(!dg){_corDesync=false;var s=el('e_dssw');if(s)s.classList.remove('on');var b=el('e_dsbody');if(b)b.style.display='none'}if(row)row.style.display=dg?'':'none'}
function ceToggleDesync(){_eeDesync=!_eeDesync;var s=el('ee_dssw');if(s)s.classList.toggle('on',_eeDesync);var b=el('ee_dsbody');if(b)b.style.display=_eeDesync?'':'none'}
function ceSetDesyncMode(m){_eeDesyncMode=m;var g=el('ee_dsmodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_dsm_'+m)})}
function ceDesyncGate(){var dg=(_eeTr=='raw'||_eeTr=='flux'||_eeTr=='tcp'||_eeTr=='ws'),row=el('ee_dsrow');if(!dg){_eeDesync=false;var s=el('ee_dssw');if(s)s.classList.remove('on');var b=el('ee_dsbody');if(b)b.style.display='none'}if(row)row.style.display=dg?'':'none'}
// ---- wss + ECH toggles live down in the general feature-toggle area (next to obfs / cover /
// gso), not inside the ws block, so they stay put in single AND pool mode. They are shown only
// when the carrier is WS/CDN (corWsVis/ceWsVis) and hidden otherwise, like the tcp-only cover.
function wsToggleRows(idp,fnp,tls,ech,sni,pos,mode,ttl,show){var hide=show?'':';display:none';
 return '<div class="tglbox" id="'+idp+'wstlsrow" style="margin-top:10px'+hide+'"><div class="tglsw'+(tls?' on':'')+'" id="'+idp+'wstls" onclick="'+fnp+'ToggleWsTls()"></div><div class="tt"><b>'+esc(T('wstls_t'))+'</b><small>'+esc(T('wstls_d'))+'</small></div></div>'
  +'<div class="tglbox" id="'+idp+'wsechrow" style="margin-top:9px'+hide+'"><div class="tglsw'+(ech?' on':'')+'" id="'+idp+'wsech" onclick="'+fnp+'ToggleEch()"></div><div class="tt"><b>'+esc(T('ech_t'))+'</b><small>'+esc(T('ech_d'))+'</small></div></div>'
  +'<div class="tglbox" id="'+idp+'snisplitrow" style="margin-top:9px'+hide+'"><div class="tglsw'+(sni?' on':'')+'" id="'+idp+'snisplit" onclick="'+fnp+'ToggleSni()"></div><div class="tt"><b>'+esc(T('sni_t'))+'</b><small>'+esc(T('sni_d'))+'</small></div></div>'
  +'<div id="'+idp+'snisplitbody" style="margin-top:6px'+((sni&&show)?'':';display:none')+'"><label>'+esc(T('sni_pos_lbl'))+'</label><input id="'+idp+'snisplitpos" type="number" min="0" max="1400" value="'+(pos||0)+'">'
  +'<label style="margin-top:10px;display:block">'+esc(T('sni_mode_lbl'))+'</label><div class="seg2" id="'+idp+'snimodeseg">'+SNI_MODES().map(function(m){return '<button type="button" class="segopt'+(m.v==(mode||'split')?' on':'')+'" id="'+idp+'snim_'+m.v+'" onclick="'+fnp+'SetSniMode(\\''+m.v+'\\')"><b>'+esc(m.v)+'</b><span>'+esc(m.s)+'</span></button>'}).join('')+'</div>'
  +'<div id="'+idp+'snittlbody" style="margin-top:6px'+((mode&&mode!='split')?'':';display:none')+'"><label>'+esc(T('sni_ttl_lbl'))+'</label><input id="'+idp+'splitttl" type="number" min="0" max="255" value="'+(ttl||0)+'"></div></div>';}
function SNI_MODES(){return [{v:'split',s:T('m_split_s')},{v:'disorder',s:T('m_dis_s')},{v:'fake',s:T('m_fake_s')}]}
// ---- ws (WebSocket / CDN) — shared markup.
function wsSection(idp,fnp,host,path,tls,edge,ech,xhttp,mode,lid){return '<div id="'+idp+'wsblk" style="display:none">'
 +'<label>'+esc(T('ws_prof_lbl'))+'</label><div class="pgrid" id="'+idp+'wspg">'+wsProfTiles(fnp,xhttp?'xhttp':'ws')+'</div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin:2px 2px 8px">'+T('ws_prof_note')+'</div>'
 +'<div id="'+idp+'xhmblk" style="display:'+(xhttp?'':'none')+';margin-bottom:8px"><label style="margin-top:2px">'+esc(T('xh_mode_lbl'))+'</label><div class="pgrid" id="'+idp+'xhmpg">'+xhModeTiles(fnp,(mode=='grpc'||mode=='stream')?'grpc':'packet')+'</div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin:2px 2px 0">'+T('xh_mode_note')+'</div></div>'
 +'<div class="tglbox"><div class="tglsw" id="'+idp+'pooltgl" onclick="'+fnp+'TogglePool()"></div><div class="tt"><b>'+esc(T('ws_pool_t'))+'</b><small>'+esc(T('ws_pool_d'))+'</small></div></div>'
 +'<div id="'+idp+'wshostblk" style="margin-top:11px">'
 +'<label>'+esc(T('ws_host_lbl'))+'</label><input id="'+idp+'wshost" dir="ltr" placeholder="'+esc(T('ph_cdn_domain'))+'" value="'+esc(host||'')+'">'
 +'<label>'+esc(T('ws_edge_lbl'))+'</label><input id="'+idp+'wsedge" class="mono" dir="ltr" placeholder="'+esc(T('ph_edge_ip'))+'" value="'+esc(edge||'')+'">'
 +'</div>'
 +'<div id="'+idp+'wspool" style="display:none;margin-top:11px">'+wsPoolInner(idp,fnp,lid)+'</div>'
 +'<label>'+esc(T('ws_path_lbl'))+'</label><input id="'+idp+'wspath" dir="ltr" placeholder="/" value="'+esc(path||'')+'">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">'+T('ws_note')+'</div>'
 +'</div>'}
function wsPoolInner(idp,fnp,lid){
 var rotOpts=[[180,T('rot_3m')],[300,T('rot_5m')],[600,T('rot_10m')],[900,T('rot_15m')],[1800,T('rot_30m')],[3600,T('rot_1h')],[14400,T('rot_4h')],[28800,T('rot_8h')],[0,T('rot_off_fo')]];
 // Custom styled list (like the IP picker) instead of the native <select>.
 var sel=ssHTML(idp+'poolrot',rotOpts.map(function(o){return {v:o[0],label:o[1]}}),poolGet(idp).rotate,T('flux_rot_lbl'));
 // Live "active edge" bar (edit only — a running tunnel exists). Populated by poolTick.
 // Each kind (ip / sni) is one collapsible accordion: the header shows a live «X در چرخش · Y
 // سوخته» summary and a per-dimension rotate-now icon (edit only), and the body holds the unified
 // list — every entry with a status pill (فعال / در چرخش / سوخته) — plus the add bar.
 function block(kind,label,ph){
   // per-edge selection replaced the header rotate button — pin a specific edge from its row instead.
   return '<div class="pacc"><div class="pacchd" onclick="poolAcc(\\''+idp+'\\',\\''+kind+'\\')">'
     +'<div><div class="pacct">'+label+'</div><div class="paccs" id="'+idp+'hd_'+kind+'"></div></div>'
     +'<div style="display:flex;align-items:center;gap:8px"><div class="pchev open" id="'+idp+'chev_'+kind+'">&#9662;</div></div></div>'
     +'<div class="paccbody" id="'+idp+'body_'+kind+'">'
     +'<div id="'+idp+'lst_'+kind+'" style="display:flex;flex-direction:column;gap:6px"></div>'
     +'<div style="display:flex;gap:6px;margin-top:8px"><input id="'+idp+'add_'+kind+'" class="mono" dir="ltr" style="flex:1;text-align:left" placeholder="'+ph+'"><button type="button" onclick="poolAdd(\\''+idp+'\\',\\''+kind+'\\')" style="background:var(--acc);color:#fff;border:none;border-radius:9px;min-width:42px;font-size:18px;cursor:pointer">+</button></div>'
     +'</div></div>';}
 return block('ip',T('pool_ip_lbl'),'104.16.0.1:443')
   +block('sni',T('pool_sni_lbl'),'cdn.example.com')
   +'<label style="margin-top:14px">'+esc(T('flux_rot_lbl'))+'</label>'+sel
   +'<div class="tglbox" style="margin-top:10px"><div class="tglsw on" id="'+idp+'poolab" onclick="poolToggleAB(\\''+idp+'\\')"></div><div class="tt"><b>'+esc(T('pool_ab_t'))+'</b><small>'+esc(T('pool_ab_d'))+'</small></div></div>'
   +'<div class="tglbox" style="margin-top:10px"><div class="tglsw" id="'+idp+'poolwarm" onclick="poolToggleWarm(\\''+idp+'\\')"></div><div class="tt"><b>'+esc(T('pool_warm_t'))+'</b><small>'+esc(T('pool_warm_d'))+'</small></div></div>';}
function fluxStatText(fc,rot){var now=Math.floor(Date.now()/1000);rot=rot||600;var ep=Math.floor(now/rot),nx=rot-(now%rot),mm=Math.floor(nx/60),ss=nx%60;
 return '<b style="color:var(--ok)">'+esc(T('flux_live'))+'</b> · epoch <span class="mono">#'+ep+'</span> · '+esc(T('flux_carrier_word'))+' <span class="mono">'+fc+'</span> · '+esc(T('flux_next_pre'))+' <b>'+mm+':'+(ss<10?'0':'')+ss+'</b> '+esc(T('flux_next_post'));}
function fluxTick(){[['e_',_corTr,_corFluxCarrier,_corFluxRotate],['ee_',_eeTr,_eeFluxCarrier,_eeFluxRotate]].forEach(function(a){
 var w=el(a[0]+'fluxstat');if(w&&a[1]=='flux')w.innerHTML=fluxStatText(a[2],a[3]);});}
setInterval(fluxTick,1000);
var _corDecoy=false,_corSrc=false,_corSpoofOk=false;
function corSpoofVis(){var w=el('e_spoofblk');if(!w)return;var show=(_corTr=='raw'&&_corRawProfile=='bip');w.style.display=show?'':'none';if(show)corSpoofProbe()}
async function corSpoofProbe(){var cap=el('e_cap');if(!cap)return;cap.className='spoofcap wait';cap.innerHTML=esc(T('spoof_checking'));
 var res=await spoofProbePair(ssVal('e_a'),ssVal('e_b'));_corSpoofOk=res.ok;
 spoofApplyCap('e_',res.ok,res.html,function(){_corDecoy=false;_corSrc=false;
  var d=el('e_decoysw'),s=el('e_srcsw');if(d)d.classList.remove('on');if(s)s.classList.remove('on');
  var di=el('e_decoyiprow'),si=el('e_srciprow');if(di)di.style.display='none';if(si)si.style.display='none'})}
function corToggleDecoy(){if(!_corSpoofOk)return;_corDecoy=!_corDecoy;el('e_decoysw').classList.toggle('on',_corDecoy);el('e_decoyiprow').style.display=_corDecoy?'':'none'}
function corToggleSrc(){if(!_corSpoofOk)return;_corSrc=!_corSrc;el('e_srcsw').classList.toggle('on',_corSrc);el('e_srciprow').style.display=_corSrc?'':'none'}
function corRawVis(){var w=el('e_rawblk');if(w)w.style.display=(_corTr=='raw')?'':'none'}
function corPortGate(){var p=el('e_port');if(!p)return;if(_corTr=='ws'){p.disabled=false;if(!p.value)p.value='80';p.placeholder=T('port_ws_ph');return}var np=(_corTr=='raw'||_corTr=='flux');p.disabled=np;if(np||p.value=='80')p.value='';p.placeholder=(_corTr=='flux')?T('port_flux_ph'):(np?T('port_raw_ph'):'20050')}
function corSetProfile(p){_corRawProfile=p;var g=el('e_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});corSpoofVis()}
function corToggleGso(){_corGso=!_corGso;var s=el('e_gso');if(s)s.classList.toggle('on',_corGso)}
function corToggleObfs(){if(ssVal('e_cipher')=='none')return;_corObfs=!_corObfs;var s=el('e_obfs');if(s)s.classList.toggle('on',_corObfs)}
function corToggleCover(){if(_corTr!='tcp')return;_corCover=!_corCover;var s=el('e_cover');if(s)s.classList.toggle('on',_corCover);corSniVis()}
function corSniVis(){var w=el('e_snirow');if(w)w.style.display=(_corCover&&_corTr=='tcp')?'':'none'}
function corCoverGate(){var tcp=_corTr=='tcp',row=el('e_coverrow'),s=el('e_cover');if(!tcp){_corCover=false;if(s)s.classList.remove('on')}if(row)row.style.display=tcp?'':'none';corSniVis()}
function onCorCipher(){var none=ssVal('e_cipher')=='none',row=el('e_obfsrow'),s=el('e_obfs');
 if(none){_corObfs=false;if(s)s.classList.remove('on')}if(row)row.style.display=none?'none':''}
async function openCoreModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(on.length<2){toast(T('node_min2'),'err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});_corSrv='a';_corTr='udp';_corObfs=false;_corCover=false;_corRawProfile='bip';_corGso=false;_corDecoy=false;_corSrc=false;_corSpoofOk=false;_corFluxCarrier='udp';_corFluxRotate=600;_corFluxShape='random';_corWsTls=false;_corEch=false;_corSniSplit=false;_corSplitPos=0;_corSniMode='split';_corSplitTtl=0;_corXhttp=false;_corXhMode='packet';_corFec=false;_corFecData=10;_corFecParity=3;_corDesync=false;_corDesyncTtl=4;_corDesyncCount=2;_corDesyncMode='ttl';_eePoolLid='';_peerLid='';_rotS['e_']={on:false,secs:600,aIps:[],bIps:[],aSel:{},bSel:{}};poolInit('e_',null);
 var _t1='<div class="ctabp on" data-cp="ip"><div class="grid2"><div><label class="first">'+esc(T('src_node'))+'</label>'+ssHTML('e_a',items,items[0].v,T('src_node'),'onCorNode')+'</div>'+
  '<div><label class="first">'+esc(T('dst_node'))+'</label>'+ssHTML('e_b',items,items[1].v,T('dst_node'),'onCorNode')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="e_aip"></div><div id="e_bip"></div></div>'+
  '<div id="e_rotrow"></div>'+rotSetHTML('e_')+
  '<label>'+esc(T('roles_lbl'))+'</label><div class="seg2" id="e_roles"><button type="button" class="segopt on" id="e_srv_a" onclick="corSetSrv(\\'a\\')"></button><button type="button" class="segopt" id="e_srv_b" onclick="corSetSrv(\\'b\\')"></button></div>'+
  '<div class="muted" style="font-size:11px;margin:-5px 2px 11px">'+esc(T('roles_note1'))+' <span id="e_trword">UDP</span>'+esc(T('roles_note2'))+'</div>'+
  '<div class="autonote">'+ic('warn')+'<span>'+T('srv_advice')+'</span></div></div>';
 var _t2='<div class="ctabp" data-cp="set"><label>'+esc(T('enc_method_lbl'))+'</label>'+ssHTML('e_cipher',CORE_CIPHERS(),'auto',T('cipher_ph'),'onCorCipher')+
  '<label>'+esc(T('transport_lbl'))+'</label><div class="seg2"><button type="button" class="segopt on" id="e_tr_udp" onclick="corSetTr(\\'udp\\')"><b>UDP</b><span>'+esc(T('tr_udp_d'))+'</span></button><button type="button" class="segopt" id="e_tr_tcp" onclick="corSetTr(\\'tcp\\')"><b>TCP</b><span>'+esc(T('tr_tcp_d'))+'</span></button><button type="button" class="segopt" id="e_tr_raw" onclick="corSetTr(\\'raw\\')"><b>RAW</b><span>'+esc(T('tr_raw_d'))+'</span></button><button type="button" class="segopt" id="e_tr_flux" onclick="corSetTr(\\'flux\\')"><b>FLUX</b><span>'+esc(T('tr_flux_d'))+'</span></button><button type="button" class="segopt" id="e_tr_ws" onclick="corSetTr(\\'ws\\')"><b>WS</b><span>CDN</span></button></div>'+
  '<div id="e_rawblk" style="display:none"><label>'+esc(T('raw_prof_lbl'))+'</label><div class="pgrid" id="e_pg">'+rawTiles('cor','bip')+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">'+T('raw_note')+'</div></div>'+
  fluxSection('e_','cor','udp',600,'random',null)+
  wsSection('e_','cor','','',false,'',false,false,'packet','')+
  spoofSection('e_','cor')+
  '<div class="tglbox" id="e_obfsrow"><div class="tglsw" id="e_obfs" onclick="corToggleObfs()"></div><div class="tt"><b>'+esc(T('obfs_t'))+'</b><small>'+esc(T('obfs_d'))+'</small></div></div>'+
  '<div class="tglbox" id="e_coverrow" style="display:none"><div class="tglsw" id="e_cover" onclick="corToggleCover()"></div><div class="tt"><b>'+esc(T('cover_t'))+'</b><small>'+esc(T('cover_d'))+'</small></div></div>'+
  wsToggleRows('e_','cor',false,false,false,0,'split',0,false)+
  '<div id="e_snirow" style="display:none"><label>'+esc(T('cover_sni_lbl'))+'</label><input id="e_sni" placeholder="'+esc(T('cover_sni_ph'))+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+T('cover_sni_note1')+'</div></div>'+
  '<div class="tglbox" id="e_gsorow"><div class="tglsw" id="e_gso" onclick="corToggleGso()"></div><div class="tt"><b>'+esc(T('gso_t'))+'</b><small>'+esc(T('gso_d'))+'</small></div></div>'+
  '<label>'+esc(T('dead_after_lbl'))+'</label><input id="e_deadafter" inputmode="numeric" placeholder="'+esc(T('dead_after_ph'))+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+esc(T('dead_after_note'))+'</div>'+
  fecSection('e_','cor',false,10,3,true)+
  desyncSection('e_','cor',false,4,2,'ttl',false)+
  '<label>'+esc(T('core_range_lbl'))+'</label>'+ssHTML('e_snr',SUBNETRANGES(),'192.168',T('range'),'onCorSubRange')+'<div id="e_snc"></div>'+
  '<label>'+esc(T('core_port_lbl'))+'</label><input id="e_port" inputmode="numeric" placeholder="20050"></div>';
 var b=corTabsHTML()+_t1+_t2+'<div class="msg" id="e_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('cpu')+'</span><div class="ttl"><h3>'+esc(T('core_tun_t'))+'</h3><div class="sb">'+esc(T('core_tun_sub'))+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreateCore()">'+esc(T('create_tun_btn'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 corRoleLbls();renderCorIps();corRotVis();corCoverGate();corPortGate();corDesyncGate()}
function onCorNode(){corRotVis('e_');corRoleLbls();if(el('e_spoofblk')&&_corTr=='raw'&&_corRawProfile=='bip')corSpoofProbe()}
function renderCorIps(){renderRotIps('e_')}
// ===== shared IP-rotation UI (create prefix 'e_', edit prefix 'ee_') =====
var _rotS={};
function rotSt(px){if(!_rotS[px])_rotS[px]={on:false,aIps:[],bIps:[],aSel:{},bSel:{}};return _rotS[px]}
function corTabsHTML(){return '<div class="ctabs"><button type="button" class="ctab on" data-ct="ip" onclick="corTab(this,\\'ip\\')">'+ic('pin')+'آی‌پی‌ها</button><button type="button" class="ctab" data-ct="set" onclick="corTab(this,\\'set\\')">'+ic('cpu')+'تنظیمات</button></div>'}
function corTab(btn,which){var box=btn.closest('.mbody');if(!box)return;Array.prototype.forEach.call(box.querySelectorAll('.ctab'),function(t){t.classList.toggle('on',t.getAttribute('data-ct')==which)});Array.prototype.forEach.call(box.querySelectorAll('.ctabp'),function(p){p.classList.toggle('on',p.getAttribute('data-cp')==which)});box.scrollTop=0}
function rotSetHTML(px){var st=rotSt(px),cur=String(st.secs||0);
 function opt(vv,lab){return '<option value="'+vv+'"'+(cur==vv?' selected':'')+'>'+esc(lab)+'</option>'}
 return '<div id="'+px+'rotset" style="display:none;margin-top:2px"><label class="first">'+esc(T('rot_interval'))+'</label>'+
 '<select id="'+px+'rotsecs" style="width:100%;height:44px">'+opt('0',T('rot_onfail'))+opt('60',T('rot_1m'))+opt('300',T('rot_5m'))+opt('600',T('rot_10m'))+'</select></div>'}
function rotTr(px){return px=='e_'?_corTr:_eeTr}
function rotIsDirect(px){return ['udp','tcp','raw','flux'].indexOf(rotTr(px))>=0}
function rotRefreshIps(px){var st=rotSt(px);if(px=='e_'){st.aIps=nodeIps(ssVal('e_a'));st.bIps=nodeIps(ssVal('e_b'))}}
// rotFirstSel is the first SELECTED pool IP in display order (or ''): all IPs are equal now (no
// primary/secondary), so this is just the endpoint we hand the backend as the config anchor (a_ip/
// b_ip) — the pool seed. Any selected IP works; first-in-order keeps it stable.
function rotFirstSel(px,side){var st=rotSt(px),ips=(side=='a')?st.aIps:st.bIps,sel=(side=='a')?st.aSel:st.bSel;
 for(var i=0;i<ips.length;i++){if(sel[ips[i]])return ips[i]}return ''}
function corRotVis(px){px=px||'e_';var st=rotSt(px);rotRefreshIps(px);var w=el(px+'rotrow');if(!w)return;
 var multi=(st.aIps.length>1||st.bIps.length>1)&&rotIsDirect(px);
 if(!multi){st.on=false;w.innerHTML='';var r0=el(px+'rotset');if(r0)r0.style.display='none';renderRotIps(px);return}
 w.innerHTML='<div class="tglbox" style="margin-top:12px"><div class="tglsw'+(st.on?' on':'')+'" id="'+px+'rotsw" onclick="corToggleRot(\\''+px+'\\')"></div><div class="tt"><b>'+esc(T('rot_t'))+'</b><small>'+esc(T('rot_d'))+'</small></div></div>';
 var rs=el(px+'rotset');if(rs)rs.style.display=st.on?'block':'none';renderRotIps(px)}
function corToggleRot(px){var st=rotSt(px);st.on=!st.on;var s=el(px+'rotsw');if(s)s.classList.toggle('on',st.on);var rs=el(px+'rotset');if(rs)rs.style.display=st.on?'block':'none';renderRotIps(px)}
function renderRotIps(px){var srv=(px=='e_')?_corSrv:_eeSrv;['a','b'].forEach(function(side){var w=el(px+side+'ip');if(!w)return;
 // Role-based label: a node's IPs are the DESTINATION pool when that node is the SERVER (the client dials
 // it) and the SOURCE pool when it's the client. A fixed a=src/b=dst was wrong whenever node A is the
 // server — it then mislabels the server's (destination) IPs as "source", contradicting the live view.
 var st=rotSt(px),ips=(side=='a')?st.aIps:st.bIps,isDst=(side=='a')?(srv=='a'):(srv!='a'),lab=isDst?T('dst_ip'):T('src_ip');
 if(st.on&&ips.length>1)w.innerHTML=rotPoolHTML(px,side,ips,lab);else w.innerHTML=ipField(px+side+'ip_sel',ips,lab)})}
function rotPoolHTML(px,side,ips,lab){var st=rotSt(px),sel=(side=='a')?st.aSel:st.bSel;
 var CKI='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="9"/><path d="M8.3 12.4l2.6 2.6 4.8-5.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';
 var OFI='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/></svg>';
 var rows=ips.map(function(ip){var on=!!sel[ip];
  return '<div class="rrow'+(on?' on':'')+'" onclick="rotToggleIp(\\''+px+'\\',\\''+side+'\\',this)" data-ip="'+esc(ip)+'"><span class="sic">'+(on?CKI:OFI)+'</span><span class="rip">'+esc(ip)+'</span></div>'}).join('');
 return '<label class="first">'+lab+' <span style="color:var(--acc)">('+rotCount(px,side)+')</span></label><div class="rpool">'+rows+'</div>'}
function rotCount(px,side){var st=rotSt(px),sel=(side=='a')?st.aSel:st.bSel,ips=(side=='a')?st.aIps:st.bIps,n=0;ips.forEach(function(ip){if(sel[ip])n++});return n}
function rotToggleIp(px,side,row){var st=rotSt(px),sel=(side=='a')?st.aSel:st.bSel,ip=row.getAttribute('data-ip');
 if(sel[ip]){if(rotCount(px,side)<=2){toast(T('rot_min2'),'err');return}delete sel[ip]}else sel[ip]=true;  // keep >=2 in an active rotation pool
 renderRotIps(px)}
function rotCollect(px){var st=rotSt(px);if(!st.on)return null;
 function pool(side){var ips=(side=='a')?st.aIps:st.bIps,sel=(side=='a')?st.aSel:st.bSel,out=[];ips.forEach(function(ip){if(sel[ip])out.push(ip)});return out}
 var ap=pool('a'),bp=pool('b');if(ap.length<2&&bp.length<2)return null;
 var secs=parseInt((el(px+'rotsecs')||{}).value)||0;
 // auto-burn is always on now (like the ws edge pool): a blocked IP is sidelined and retested on
 // backoff, returning to rotation when healthy — no operator toggle.
 return {ip_rotate:true,a_ip_pool:ap,b_ip_pool:bp,rotate_secs:secs,auto_burn:true,a_ip:ap[0]||'',b_ip:bp[0]||''}}
// Save-time guard: a rotation pool needs >=2 IPs to actually rotate. When the toggle is on, every side
// whose multi-select pool is shown must have >=2 selected (a 0/1-IP "pool" silently doesn't rotate).
function rotValidate(px){var st=rotSt(px);if(!st.on)return null;
 var err=null;['a','b'].forEach(function(side){var ips=(side=='a')?st.aIps:st.bIps;if(ips.length>1&&rotCount(px,side)<2)err=T('rot_min2')});
 if(err)return err;
 if(rotCount(px,'a')<2&&rotCount(px,'b')<2)return T('rot_min2');   // rotation on but no side has a pool
 return null}
function onCorSubRange(){var w=el('e_snc');if(!w)return;w.innerHTML=(ssVal('e_snr')=='custom')?'<label>'+esc(T('custom_subnet'))+'</label><input id="e_subnet" placeholder="'+esc(T('ph_subnet'))+'">':''}
function corRoleLbls(){var an=nodeName(ssVal('e_a')),bn=nodeName(ssVal('e_b')),a=el('e_srv_a'),b=el('e_srv_b');
 if(a)a.innerHTML='<b>'+esc(an)+' '+esc(T('role_server_word'))+'</b><span>'+esc(bn)+' '+esc(T('role_client_word'))+'</span>';
 if(b)b.innerHTML='<b>'+esc(bn)+' '+esc(T('role_server_word'))+'</b><span>'+esc(an)+' '+esc(T('role_client_word'))+'</span>'}
function corSetSrv(s){_corSrv=s;var a=el('e_srv_a'),b=el('e_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b');renderRotIps('e_')}
async function doCreateCore(){var m=el('e_msg');m.className='msg';var a=ssVal('e_a'),bb=ssVal('e_b');
 if(a==bb){m.className='msg err';m.textContent=T('two_diff_nodes');return}
 var body={a_node:a,b_node:bb,type:'core',server_side:_corSrv,cipher:ssVal('e_cipher'),transport:_corTr,obfs:_corObfs,cover:(_corCover&&_corTr=='tcp'),gso:_corGso};
 var _dae=parseInt(v('e_deadafter'))||0;if(_dae)body.dead_after_secs=_dae;
 if(_corTr=='raw'){if(ssVal('e_cipher')=='none'){m.className='msg err';m.textContent=T('raw_need_enc');return}body.raw_profile=_corRawProfile}
 if(_corTr=='flux'){if(ssVal('e_cipher')=='none'){m.className='msg err';m.textContent=T('flux_need_enc');return}body.flux_carrier=_corFluxCarrier;body.flux_rotate_secs=_corFluxRotate;body.flux_shape=_corFluxShape}
 if(corFecDatagram()){body.fec=_corFec;if(_corFec){body.fec_data=_corFecData;body.fec_parity=_corFecParity}}
 if(_corTr=='raw'||_corTr=='flux'||_corTr=='tcp'||_corTr=='ws'){body.fake_desync=_corDesync;if(_corDesync){body.fake_ttl=parseInt(v('e_dsttl'))||4;body.fake_count=parseInt(v('e_dscount'))||2;body.fake_mode=_corDesyncMode}}
 if(_corTr=='ws'){body.ws_path=(v('e_wspath')||'').trim();body.ws_tls=_corWsTls;body.ech=_corEch;body.sni_split=_corSniSplit;if(_corSniSplit){body.split_pos=parseInt(v('e_snisplitpos'))||0;body.sni_mode=_corSniMode;if(_corSniMode!='split')body.split_ttl=parseInt(v('e_splitttl'))||0;}body.ws_xhttp=_corXhttp;if(_corXhttp)body.ws_xhttp_mode=_corXhMode;if(poolGet('e_').pool){var pe=poolCollect('e_',body);if(pe!==true){m.className='msg err';m.textContent=pe;return}}else{body.ws_pool=false;body.ws_host=(v('e_wshost')||'').trim();body.edge_ip=(v('e_wsedge')||'').trim();if(_corWsTls&&!body.ws_host){m.className='msg err';m.textContent=T('wss_need_host');return}if(_corEch&&!_corWsTls){m.className='msg err';m.textContent=T('ech_need_wss');return}if(_corXhttp&&(_corXhMode=='stream'||_corXhMode=='grpc')&&!_corWsTls){m.className='msg err';m.textContent=T('xh_need_wss');return}}}
 if(_corTr=='raw'&&_corRawProfile=='bip'&&_corSpoofOk){
  if(_corDecoy){var dip=(v('e_decoyip')||'').trim();if(!dip){m.className='msg err';m.textContent=T('decoy_need_ip');return}body.spoof_dst=dip}
  if(_corSrc){var sip=(v('e_srcip')||'').trim();if(sip)body.spoof_src=sip}}
 if(body.cover){var sni=(v('e_sni')||'').trim();if(!sni){m.className='msg err';m.textContent=T('cover_need_sni');return}body.cover_sni=sni}
 var _rverr=rotValidate('e_');if(_rverr){m.className='msg err';m.textContent=_rverr;return}
 var _sa=rotSt('e_');
 var aip=(_sa.on&&_sa.aIps.length>1)?(rotFirstSel('e_','a')||_sa.aIps[0]||''):(el('ssb_e_aip_sel')?ssVal('e_aip_sel'):'');if(aip)body.a_ip=aip;
 var bip=(_sa.on&&_sa.bIps.length>1)?(rotFirstSel('e_','b')||_sa.bIps[0]||''):(el('ssb_e_bip_sel')?ssVal('e_bip_sel'):'');if(bip)body.b_ip=bip;
 var _rc=rotCollect('e_');if(_rc){body.ip_rotate=true;body.a_ip_pool=_rc.a_ip_pool;body.b_ip_pool=_rc.b_ip_pool;body.rotate_secs=_rc.rotate_secs;body.auto_burn=_rc.auto_burn}
 var range=ssVal('e_snr');if(range=='custom'){var sub=v('e_subnet');if(sub)body.subnet=sub}else{body.subnet_base=range}
 var port=v('e_port');if(port)body.port=port;
 m.textContent=T('creating_core');
 var r=await post('create-tunnel',body);
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('core_created'),'ok');refreshCore()}
 else{m.className='msg err';m.textContent=terr(r.d.error||r.d.msg||T('failed'))}}
// ===== core edit (cipher / role / port / subnet / ips -> rebuild both ends)
var _eeSrv='a',_eeTr='udp',_eeObfs=false,_eeCover=false,_eeRawProfile='bip',_eeGso=false,_eeFluxCarrier='udp',_eeFluxRotate=600,_eeFluxShape='random',_eeWsTls=false,_eeEch=false,_eeXhttp=false,_eeXhMode='packet',_eeFec=false,_eeFecData=10,_eeFecParity=3,_eeDesync=false,_eeDesyncTtl=4,_eeDesyncCount=2,_eeDesyncMode='ttl',_eeSniSplit=false,_eeSplitPos=0,_eeSniMode='split',_eeSplitTtl=0;
function ceSetTr(t){_eeTr=t;['udp','tcp','raw','flux','ws'].forEach(function(x){var b=el('ee_tr_'+x);if(b)b.classList.toggle('on',t==x)});ceRawVis();ceFluxVis();ceWsVis();cePortGate();ceCoverGate();ceFecGate();ceSpoofVis();ceDesyncGate();corRotVis('ee_')}
function ceFluxVis(){var w=el('ee_fluxblk');if(w)w.style.display=(_eeTr=='flux')?'':'none';fluxTick()}
function ceWsVis(){var ws=_eeTr=='ws';var w=el('ee_wsblk');if(w)w.style.display=ws?'':'none';var t=el('ee_wstlsrow'),e=el('ee_wsechrow');if(t)t.style.display=ws?'':'none';if(e)e.style.display=ws?'':'none';var sr=el('ee_snisplitrow');if(sr)sr.style.display=ws?'':'none';var sb=el('ee_snisplitbody');if(sb)sb.style.display=(ws&&_eeSniSplit)?'':'none';if(ws){poolVis('ee_');ceWssGate()}}
function ceToggleWsTls(){_eeWsTls=!_eeWsTls;var s=el('ee_wstls');if(s)s.classList.toggle('on',_eeWsTls);if(!_eeWsTls){if(_eeEch){_eeEch=false;var e=el('ee_wsech');if(e)e.classList.remove('on')}if(_eeSniSplit){_eeSniSplit=false;var q=el('ee_snisplit');if(q)q.classList.remove('on');var b=el('ee_snisplitbody');if(b)b.style.display='none'}}}
function ceToggleSni(){if(!_eeWsTls){_eeSniSplit=false;var q=el('ee_snisplit');if(q)q.classList.remove('on');alert(T('sni_need_wss'));return}_eeSniSplit=!_eeSniSplit;var s=el('ee_snisplit');if(s)s.classList.toggle('on',_eeSniSplit);var b=el('ee_snisplitbody');if(b)b.style.display=_eeSniSplit?'':'none'}
function ceSetSniMode(m){_eeSniMode=m;var g=el('ee_snimodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_snim_'+m)});var b=el('ee_snittlbody');if(b)b.style.display=(m!='split')?'':'none'}
function ceWssGate(){var mand=poolGet('ee_').pool||(_eeXhttp&&(_eeXhMode=='stream'||_eeXhMode=='grpc'));var row=el('ee_wstlsrow'),s=el('ee_wstls');if(mand){_eeWsTls=true;if(s)s.classList.add('on');if(row)row.classList.add('dis')}else if(row)row.classList.remove('dis')}
function ceToggleEch(){if(!_eeWsTls){_eeEch=false;var e=el('ee_wsech');if(e)e.classList.remove('on');alert(T('ech_need_wss_alert'));return}_eeEch=!_eeEch;var s=el('ee_wsech');if(s)s.classList.toggle('on',_eeEch)}
function ceSetFluxCarrier(c){_eeFluxCarrier=c;var g=el('ee_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fc]'),function(t){t.classList.toggle('on',t.getAttribute('data-fc')==c)});fluxTick()}
function ceSetFluxShape(s){_eeFluxShape=s;var g=el('ee_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fs]'),function(t){t.classList.toggle('on',t.getAttribute('data-fs')==s)})}
function ceFluxRotChg(){_eeFluxRotate=parseInt(ssVal('ee_fluxrot'))||600;fluxTick()}
function ceFecDatagram(){return _eeTr=='udp'||_eeTr=='raw'||_eeTr=='flux'}
function ceToggleFec(){if(!ceFecDatagram())return;_eeFec=!_eeFec;var s=el('ee_fecsw');if(s)s.classList.toggle('on',_eeFec);var r=el('ee_fecrates');if(r)r.style.display=_eeFec?'':'none'}
function ceSetFecRate(d,p){_eeFecData=d;_eeFecParity=p;var g=el('ee_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function ceFecGate(){var dg=ceFecDatagram(),row=el('ee_fecrow');if(!dg){_eeFec=false;var s=el('ee_fecsw');if(s)s.classList.remove('on');var r=el('ee_fecrates');if(r)r.style.display='none'}if(row)row.style.display=dg?'':'none'}
var _eeDecoy=false,_eeSrc=false,_eeSpoofOk=false,_eeNodesArr=['',''];
function ceSpoofVis(){var w=el('ee_spoofblk');if(!w)return;var show=(_eeTr=='raw'&&_eeRawProfile=='bip');w.style.display=show?'':'none';if(show)ceSpoofProbe()}
async function ceSpoofProbe(){var cap=el('ee_cap');if(!cap)return;cap.className='spoofcap wait';cap.innerHTML=esc(T('spoof_checking'));
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
function cePortGate(){var p=el('ee_port');if(!p)return;if(_eeTr=='ws'){p.disabled=false;if(!p.value)p.value='80';p.placeholder=T('port_ws_ph');return}var np=(_eeTr=='raw'||_eeTr=='flux');p.disabled=np;if(np||p.value=='80')p.value='';p.placeholder=(_eeTr=='flux')?T('port_flux_ph'):(np?T('port_raw_ph'):'20050')}
function ceSetProfile(p){_eeRawProfile=p;var g=el('ee_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});ceSpoofVis()}
function ceToggleGso(){_eeGso=!_eeGso;var s=el('ee_gso');if(s)s.classList.toggle('on',_eeGso)}
function ceToggleObfs(){if(ssVal('ee_cipher')=='none')return;_eeObfs=!_eeObfs;var s=el('ee_obfs');if(s)s.classList.toggle('on',_eeObfs)}
function ceToggleCover(){if(_eeTr!='tcp')return;_eeCover=!_eeCover;var s=el('ee_cover');if(s)s.classList.toggle('on',_eeCover);ceSniVis()}
function ceSniVis(){var w=el('ee_snirow');if(w)w.style.display=(_eeCover&&_eeTr=='tcp')?'':'none'}
function ceCoverGate(){var tcp=_eeTr=='tcp',row=el('ee_coverrow'),s=el('ee_cover');if(!tcp){_eeCover=false;if(s)s.classList.remove('on')}if(row)row.style.display=tcp?'':'none';ceSniVis()}
function onEeCipher(){var none=ssVal('ee_cipher')=='none',row=el('ee_obfsrow'),s=el('ee_obfs');
 if(none){_eeObfs=false;if(s)s.classList.remove('on')}if(row)row.style.display=none?'none':''}
function openCoreEdit(id){var l=FLEET.filter(function(x){return x.id==id})[0];if(!l){toast(T('not_found'),'err');return}
 editingId=id;_eeSrv=(l.server_side=='b')?'b':'a';_eeTr=(['tcp','raw','flux','ws'].indexOf(l.transport)>=0)?l.transport:'udp';_eeObfs=!!l.obfs;_eeCover=!!l.cover&&_eeTr=='tcp';_eeRawProfile=l.raw_profile||'bip';_eeGso=!!l.gso;_eeDecoy=!!l.spoof_dst;_eeSrc=!!l.spoof_src;_eeSpoofOk=false;_eeNodesArr=[l.a_node,l.b_node];_eeFluxCarrier=l.flux_carrier||'udp';_eeFluxRotate=l.flux_rotate_secs||600;_eeFluxShape=l.flux_shape||'random';_eeWsTls=!!l.ws_tls;_eeEch=!!l.ech;_eeSniSplit=!!l.sni_split;_eeSplitPos=l.split_pos||0;_eeSniMode=(l.sni_mode=='disorder'||l.sni_mode=='fake')?l.sni_mode:'split';_eeSplitTtl=l.split_ttl||0;_eeXhttp=!!l.ws_xhttp;_eeXhMode=(l.ws_xhttp_mode=='grpc'||l.ws_xhttp_mode=='stream')?'grpc':'packet';_eeFec=!!l.fec;_eeFecData=l.fec_data||10;_eeFecParity=l.fec_parity||3;_eeDesync=!!l.fake_desync;_eeDesyncTtl=l.fake_ttl||4;_eeDesyncCount=l.fake_count||2;_eeDesyncMode=l.fake_mode||'ttl';_eePoolLid=(l.ws_pool?l.id:'');poolInit('ee_',l);_peerLid=(l.ip_rotate?l.id:'');_peerData={dst:null,src:null,now:0,polledMs:0,pinPending:null};
 var aips=l.a_ips||[],bips=l.b_ips||[];
 _rotS['ee_']={on:!!l.ip_rotate,secs:(l.rotate_secs||600),aIps:aips,bIps:bips,aSel:{},bSel:{}};
 (l.a_ip_pool||[]).forEach(function(ip){_rotS['ee_'].aSel[ip]=true});(l.b_ip_pool||[]).forEach(function(ip){_rotS['ee_'].bSel[ip]=true});
 if(l.a_ip)_rotS['ee_'].aSel[l.a_ip]=true;if(l.b_ip)_rotS['ee_'].bSel[l.b_ip]=true;
 var _t1='<div class="ctabp on" data-cp="ip"><div class="muted" style="font-size:12px;margin-bottom:10px">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+' · <span class="mono">'+esc(l.name)+'</span></div>'+
  '<div class="grid2"><div id="ee_aip"></div><div id="ee_bip"></div></div>'+
  '<div id="ee_rotrow"></div>'+rotSetHTML('ee_')+'<div id="ee_peerlive"></div>'+
  '<label>'+esc(T('roles_lbl'))+'</label><div class="seg2"><button type="button" class="segopt'+(_eeSrv=='a'?' on':'')+'" id="ee_srv_a" onclick="ceSetSrv(\\'a\\')"></button><button type="button" class="segopt'+(_eeSrv=='b'?' on':'')+'" id="ee_srv_b" onclick="ceSetSrv(\\'b\\')"></button></div>'+
  '<div class="autonote">'+ic('warn')+'<span>'+T('srv_advice')+'</span></div></div>';
 var _t2='<div class="ctabp" data-cp="set"><label>'+esc(T('enc_method_lbl'))+'</label>'+ssHTML('ee_cipher',CORE_CIPHERS(),(l.cipher||'auto'),T('cipher_ph'),'onEeCipher')+
  '<label>'+esc(T('transport_lbl'))+'</label><div class="seg2"><button type="button" class="segopt'+(_eeTr=='udp'?' on':'')+'" id="ee_tr_udp" onclick="ceSetTr(\\'udp\\')"><b>UDP</b><span>'+esc(T('tr_udp_d'))+'</span></button><button type="button" class="segopt'+(_eeTr=='tcp'?' on':'')+'" id="ee_tr_tcp" onclick="ceSetTr(\\'tcp\\')"><b>TCP</b><span>'+esc(T('tr_tcp_d'))+'</span></button><button type="button" class="segopt'+(_eeTr=='raw'?' on':'')+'" id="ee_tr_raw" onclick="ceSetTr(\\'raw\\')"><b>RAW</b><span>'+esc(T('tr_raw_d'))+'</span></button><button type="button" class="segopt'+(_eeTr=='flux'?' on':'')+'" id="ee_tr_flux" onclick="ceSetTr(\\'flux\\')"><b>FLUX</b><span>'+esc(T('tr_flux_d'))+'</span></button><button type="button" class="segopt'+(_eeTr=='ws'?' on':'')+'" id="ee_tr_ws" onclick="ceSetTr(\\'ws\\')"><b>WS</b><span>CDN</span></button></div>'+
  '<div id="ee_rawblk" style="display:'+((_eeTr=='raw')?'':'none')+'"><label>'+esc(T('raw_prof_lbl'))+'</label><div class="pgrid" id="ee_pg">'+rawTiles('ce',_eeRawProfile)+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">'+T('raw_note')+'</div></div>'+
  fluxSection('ee_','ce',_eeFluxCarrier,_eeFluxRotate,_eeFluxShape,id)+
  wsSection('ee_','ce',l.ws_host,l.ws_path,_eeWsTls,l.edge_ip,_eeEch,_eeXhttp,_eeXhMode,l.id)+
  spoofSection('ee_','ce')+
  '<div class="tglbox" id="ee_obfsrow"'+((l.cipher=='none')?' style="display:none"':'')+'><div class="tglsw'+(_eeObfs?' on':'')+'" id="ee_obfs" onclick="ceToggleObfs()"></div><div class="tt"><b>'+esc(T('obfs_t'))+'</b><small>'+esc(T('obfs_d'))+'</small></div></div>'+
  '<div class="tglbox" id="ee_coverrow"'+((_eeTr!='tcp')?' style="display:none"':'')+'><div class="tglsw'+(_eeCover?' on':'')+'" id="ee_cover" onclick="ceToggleCover()"></div><div class="tt"><b>'+esc(T('cover_t'))+'</b><small>'+esc(T('cover_d'))+'</small></div></div>'+
  wsToggleRows('ee_','ce',_eeWsTls,_eeEch,_eeSniSplit,_eeSplitPos,_eeSniMode,_eeSplitTtl,_eeTr=='ws')+
  '<div id="ee_snirow" style="display:'+((_eeCover&&_eeTr=='tcp')?'':'none')+'"><label>'+esc(T('cover_sni_lbl'))+'</label><input id="ee_sni" placeholder="'+esc(T('cover_sni_ph'))+'" value="'+esc(l.cover_sni||'')+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+T('cover_sni_note2')+'</div></div>'+
  '<div class="tglbox" id="ee_gsorow"><div class="tglsw'+(_eeGso?' on':'')+'" id="ee_gso" onclick="ceToggleGso()"></div><div class="tt"><b>'+esc(T('gso_t'))+'</b><small>'+esc(T('gso_d'))+'</small></div></div>'+
  '<label>'+esc(T('dead_after_lbl'))+'</label><input id="ee_deadafter" inputmode="numeric" value="'+esc(l.dead_after_secs||'')+'" placeholder="'+esc(T('dead_after_ph'))+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+esc(T('dead_after_note'))+'</div>'+
  fecSection('ee_','ce',_eeFec,_eeFecData,_eeFecParity,(_eeTr=='udp'||_eeTr=='raw'||_eeTr=='flux'))+
  desyncSection('ee_','ce',_eeDesync,_eeDesyncTtl,_eeDesyncCount,_eeDesyncMode,(_eeTr=='raw'||_eeTr=='flux'||_eeTr=='tcp'||_eeTr=='ws'))+
  '<div class="grid2"><div><label>'+esc(T('core_port_lbl2'))+'</label><input id="ee_port" inputmode="numeric" value="'+esc(l.port||'')+'" placeholder="20050"></div><div><label>'+esc(T('core_subnet_lbl'))+'</label><input id="ee_subnet" class="mono" value="'+esc(l.subnet||'')+'"></div></div>'+
  '<div class="muted" style="font-size:11px;margin:2px 2px 0">'+esc(T('core_edit_note'))+'</div></div>';
 var b=corTabsHTML()+_t1+_t2+'<div class="msg" id="ee_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('core_edit_t'))+'</h3><div class="sb">'+esc(l.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCoreEdit(\\''+id+'\\')">'+esc(T('save_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 ceRoleLbls(l);renderRotIps('ee_');corRotVis('ee_');cePortGate();ceSpoofPrefill(l);ceSpoofVis();ceFluxVis();ceWsVis();if(_eePoolLid)setTimeout(poolTick,200);if(_peerLid)setTimeout(peerTick,200)}
function ceRoleLbls(l){var a=el('ee_srv_a'),b=el('ee_srv_b');
 if(a)a.innerHTML='<b>'+esc(l.a_name)+' '+esc(T('role_server_word'))+'</b><span>'+esc(l.b_name)+' '+esc(T('role_client_word'))+'</span>';
 if(b)b.innerHTML='<b>'+esc(l.b_name)+' '+esc(T('role_server_word'))+'</b><span>'+esc(l.a_name)+' '+esc(T('role_client_word'))+'</span>'}
function ceSetSrv(s){_eeSrv=s;var a=el('ee_srv_a'),b=el('ee_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b');renderRotIps('ee_')}
async function doCoreEdit(id){var m=el('ee_msg');m.className='msg';m.textContent=T('saving_rebuild_both');
 var l=FLEET.filter(function(x){return x.id==id})[0]||{};
 var body={id:id,type:'core',server_side:_eeSrv,cipher:ssVal('ee_cipher'),transport:_eeTr,obfs:_eeObfs,cover:(_eeCover&&_eeTr=='tcp'),gso:_eeGso};
 body.dead_after_secs=parseInt(v('ee_deadafter'))||0;
 if(_eeTr=='raw'){if(ssVal('ee_cipher')=='none'){m.className='msg err';m.textContent=T('raw_need_enc');return}body.raw_profile=_eeRawProfile}
 if(_eeTr=='flux'){if(ssVal('ee_cipher')=='none'){m.className='msg err';m.textContent=T('flux_need_enc');return}body.flux_carrier=_eeFluxCarrier;body.flux_rotate_secs=_eeFluxRotate;body.flux_shape=_eeFluxShape}
 if(ceFecDatagram()){body.fec=_eeFec;if(_eeFec){body.fec_data=_eeFecData;body.fec_parity=_eeFecParity}}
 if(_eeTr=='raw'||_eeTr=='flux'||_eeTr=='tcp'||_eeTr=='ws'){body.fake_desync=_eeDesync;if(_eeDesync){body.fake_ttl=parseInt(v('ee_dsttl'))||4;body.fake_count=parseInt(v('ee_dscount'))||2;body.fake_mode=_eeDesyncMode}}
 if(_eeTr=='ws'){body.ws_path=(v('ee_wspath')||'').trim();body.ws_tls=_eeWsTls;body.ech=_eeEch;body.sni_split=_eeSniSplit;if(_eeSniSplit){body.split_pos=parseInt(v('ee_snisplitpos'))||0;body.sni_mode=_eeSniMode;if(_eeSniMode!='split')body.split_ttl=parseInt(v('ee_splitttl'))||0;}body.ws_xhttp=_eeXhttp;if(_eeXhttp)body.ws_xhttp_mode=_eeXhMode;if(poolGet('ee_').pool){var pe2=poolCollect('ee_',body);if(pe2!==true){m.className='msg err';m.textContent=pe2;return}}else{body.ws_pool=false;body.ws_host=(v('ee_wshost')||'').trim();body.edge_ip=(v('ee_wsedge')||'').trim();if(_eeWsTls&&!body.ws_host){m.className='msg err';m.textContent=T('wss_need_host');return}if(_eeEch&&!_eeWsTls){m.className='msg err';m.textContent=T('ech_need_wss');return}if(_eeXhttp&&(_eeXhMode=='stream'||_eeXhMode=='grpc')&&!_eeWsTls){m.className='msg err';m.textContent=T('xh_need_wss');return}}}
 if(_eeTr=='raw'&&_eeRawProfile=='bip'&&_eeSpoofOk){
  // Send an explicit value for both spoof fields ONLY when the capability probe resolved OK —
  // then the toggles reflect real user intent, so an empty value legitimately CLEARS a decoy/source
  // (backend keys on presence). When the probe is pending or NOT-ok we OMIT these fields entirely,
  // so the backend PRESERVES the stored decoy: a flaky local CAP_NET_RAW probe (which even
  // force-toggles the switches off in the UI) must never silently strip a working decoy config.
  var dip=_eeDecoy?(v('ee_decoyip')||'').trim():'';
  var sip=_eeSrc?(v('ee_srcip')||'').trim():'';
  if(_eeDecoy&&!dip){m.className='msg err';m.textContent=T('decoy_need_ip');return}
  body.spoof_dst=dip;body.spoof_src=sip}
 if(body.cover){var sni=(v('ee_sni')||'').trim();if(!sni){m.className='msg err';m.textContent=T('cover_need_sni');return}body.cover_sni=sni}
 var _rverr2=rotValidate('ee_');if(_rverr2){m.className='msg err';m.textContent=_rverr2;return}
 var _sa2=rotSt('ee_');
 // Keep the stored anchor if it is still in the pool, so the anchor (a_ip/b_ip) doesn't drift to another
 // pool IP each edit (which churns the server bind and used to trip a false self port-conflict).
 var aip=(_sa2.on&&_sa2.aIps.length>1)?((_sa2.aSel[l.a_ip]&&l.a_ip)||rotFirstSel('ee_','a')||_sa2.aIps[0]||''):(el('ssb_ee_aip_sel')?ssVal('ee_aip_sel'):(l.a_ip||''));if(aip)body.a_ip=aip;
 var bip=(_sa2.on&&_sa2.bIps.length>1)?((_sa2.bSel[l.b_ip]&&l.b_ip)||rotFirstSel('ee_','b')||_sa2.bIps[0]||''):(el('ssb_ee_bip_sel')?ssVal('ee_bip_sel'):(l.b_ip||''));if(bip)body.b_ip=bip;
 var _rc2=rotCollect('ee_');body.ip_rotate=!!(_rc2);if(_rc2){body.a_ip_pool=_rc2.a_ip_pool;body.b_ip_pool=_rc2.b_ip_pool;body.rotate_secs=_rc2.rotate_secs;body.auto_burn=_rc2.auto_burn}
 var sub=v('ee_subnet');if(sub)body.subnet=sub;var port=v('ee_port');if(port)body.port=port;
 var r=await post('edit-link',body);
 if(r.ok&&r.d.ok){editingId=null;closeModal(m.closest('.modalov'));toast(r.d.unchanged?T('no_change'):T('saved_rebuilt'),'ok');refreshCore()}
 else{m.className='msg err';m.textContent=terr((r.d&&(r.d.error||r.d.msg))||T('failed'))}}

// ===== Port-forward
function portfwSkel(){el('view').innerHTML='<h1>'+ic('globe','var(--acc)')+' '+esc(T('nav_portfw'))+'</h1><p class="sub">'+esc(T('pf_sub'))+'</p>'+
 '<button class="primary" onclick="openPfAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+esc(T('pf_add'))+'</button>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' '+esc(T('pf_active'))+'</div>'+toolbar('portfw',T('pf_search'))+'<div id="pfList">'+skCards('portfw')+'</div>'+pagerBottom('portfw');
 refreshPortfw()}
async function openPfAddModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(!on.length){toast(T('pf_no_online'),'err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<label class="first">'+esc(T('pf_node'))+'</label>'+ssHTML('pf_node',items,items[0].v,T('pf_node'),'renderPfLip')+'<div id="pf_lipwrap"></div><div class="grid2"><div><label>'+esc(T('pf_listen_port'))+'</label><input id="pf_lp" placeholder="8080"></div><div><label>'+esc(T('pf_dst_port'))+'</label><input id="pf_dp" placeholder="443"></div></div><label>'+esc(T('pf_dst_ips'))+'</label><input id="pf_ips" placeholder="10.0.0.1, 10.0.0.2"><label>'+esc(T('pf_rot_min'))+'</label><input id="pf_int" placeholder="5"><div class="msg" id="pf_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>'+esc(T('pf_add_t'))+'</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doPortfw()">'+esc(T('add'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');
 renderPfLip()}
function renderPfLip(){var w=el('pf_lipwrap');if(!w)return;var ips=nodeIps(ssVal('pf_node'));
 if(ips.length>1){w.innerHTML='<label>'+esc(T('pf_lip_full'))+'</label>'+ssHTML('pf_lip',ipItems(ips),(SEL['pf_lip']&&ips.indexOf(SEL['pf_lip'])>=0?SEL['pf_lip']:ips[0]),T('ip'),'')}
 else{w.innerHTML='';delete SEL['pf_lip']}}   // single-IP node: no picker, and no stale pick
async function refreshPortfw(){if(editingId)return;var box=el('pfList');if(!box)return;var r=await j('portfw-list?offset='+(PG.portfw*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.portfw));PF=(r.portfw||[]).filter(function(x){return x.name});TOT.portfw=num(r.total);
 setHTML(box,PF.length?PF.map(pfCard).join(''):'<div class="card muted">'+(QRY.portfw?T('no_results'):T('pf_empty'))+'</div>');renderPager('portfw')}
function pfCard(p,i){var h=p.health||{};
 var st=h.rule?(h.reachable?'<span class="badge ok">'+esc(T('pf_active_badge'))+CK+'</span>':'<span class="badge bad">'+esc(T('pf_rule'))+CK+' · '+esc(T('pf_dest'))+XK+'</span>'):'<span class="badge bad">'+esc(T('pf_disabled'))+'</span>';
 var rotOn=p.switch_interval>0,multi=(p.dst_ips||[]).length>1;
 var lip=p.listen_ip||p.node_ip||'';   // effective listen IP: the pin (multi-IP) or the node's sole IP (single-IP)
 var rotchip=rotOn?'<span class="tag" style="display:inline-flex;align-items:center;gap:4px;color:var(--gold);border-color:color-mix(in srgb,var(--gold) 34%,transparent);background:var(--goldw);direction:ltr">'+ic('redo')+(p.switch_interval/60)+'m</span>':'';
 var head='<div class="link"><span class="name">'+esc(p.node)+'</span><span class="grow"></span>'+rotchip+'<span class="tag" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 40%,transparent)">portfw</span>'+st+'</div>';
 var live=(multi&&h.active)?'<div class="wrap">'+esc(T('pf_active_now'))+'<b class="mono" id="pfact_'+i+'" style="color:var(--ok)">'+esc(h.active)+'</b></div>':'';
 var body='<div class="enmeta"><div class="emcol">'+
   '<div>'+esc(T('pf_iface'))+'<b class="mono">'+esc(p.iface)+'</b></div>'+
   (lip?'<div>'+esc(T('pf_lip_lbl'))+'<b class="mono" style="color:var(--acc)">'+esc(lip)+'</b></div>':'')+
   '<div>'+esc(T('pf_lp_lbl'))+'<b class="mono">'+esc(p.listen_port)+'</b></div>'+
  '</div><span class="tnarrow earrow">↔</span><div class="emcol">'+
   '<div>'+esc(T('pf_dp_lbl'))+'<b>'+esc(p.dst_port)+'</b></div>'+
   '<div class="wrap">'+esc(T('pf_targets'))+'<b class="mono">'+esc((p.dst_ips||[]).join(T('list_sep')))+'</b></div>'+
   live+
  '</div></div>';
 var traf='<div class="ltraf"><span class="din iso">↓ '+fmtRate(p.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(p.tx_bps)+'</span><span class="tot">'+esc(T('total'))+' <span class="iso"><b class="din">↓'+fmtBytes(p.rx_total)+'</b><b class="dout">↑'+fmtBytes(p.tx_total)+'</b></span></span></div>';
 var acts='<div class="nact iconly"><button class="act reset" title="'+esc(T('tip_reset'))+'" onclick="resetPfTraffic('+i+')">'+ic('reset')+'</button>'+((multi&&h.active)?'<button class="act" title="'+esc(T('pf_rotate_now'))+'" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 46%,transparent)" onclick="pfNext('+i+')">'+ic('redo')+'</button>':'')+'<button class="act warn" title="'+esc(T('tip_edit'))+'" onclick="openPfEdit('+i+')">'+ic('pen')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" onclick="delPf('+i+')">'+ic('trash')+'</button></div>';
 return '<div class="card">'+head+body+traf+acts+'</div>'}
function pfTgl(i){var sw=el('pe_tgl_'+i),on=!sw.classList.contains('on');sw.classList.toggle('on',on);
 setT('pe_tgllbl_'+i,on?T('on_word'):T('off_word'));var w=el('pe_intwrap_'+i);if(w)w.style.display=on?'block':'none'}
async function savePfEdit(i){var p=PF[i];if(!p)return;var m=el('pem_'+i);var lp=v('pe_lp_'+i),dp=v('pe_dp_'+i),ips=v('pe_ips_'+i);
 if(!lp||!dp||!ips){m.className='msg err';m.textContent=T('pf_need_ports');return}
 var rot=el('pe_tgl_'+i).classList.contains('on'),intv=v('pe_int_'+i);
 m.className='msg';m.textContent=T('saving');
 var lip=el('ssb_pe_lip')?ssVal('pe_lip'):'';   // only multi-IP nodes expose the picker; empty ⇒ node keeps old pin
 var r=await post('portfw-edit',{node:p.node_id,name:p.name,listen_port:lp,dst_port:dp,dst_ips:ips,rotate:rot,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=terr(r.d.error||r.d.msg||T('failed'))}}
async function doPortfw(){var m=el('pf_msg');var node=ssVal('pf_node'),lp=v('pf_lp'),dp=v('pf_dp'),ips=v('pf_ips'),intv=v('pf_int');
 if(!node||!lp||!dp||!ips){m.className='msg err';m.textContent=T('pf_need_all');return}
 m.className='msg';m.textContent=T('creating_dots');
 var lip=el('ssb_pf_lip')?ssVal('pf_lip'):'';   // only when the picker exists (multi-IP node)
 var r=await post('portfw',{node:node,listen_port:lp,dst_port:dp,dst_ips:ips,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('pf_created')+r.d.name,'ok')}
 else{m.className='msg err';m.textContent=terr(r.d.error||T('failed'))}}
async function pfNext(i){var p=PF[i];if(!p)return;var b=el('pfact_'+i),old=b?b.textContent:'';if(b)b.textContent='…';
 var r=await post('portfw-next',{node:p.node_id,name:p.name});
 if(r.ok&&r.d.ok){if(b)b.textContent=r.d.active;toast(T('pf_rotate_done')+r.d.active,'ok')}
 else{if(b)b.textContent=old;toast(terr((r.d&&(r.d.error||r.d.msg))||T('pf_rotate_failed')),'err')}}
async function delPf(i){var p=PF[i];if(!p)return;if(!await confirmBox(T('pf_del_confirm')))return;await post('portfw-del',{node:p.node_id,name:p.name});editingId=null;refreshPortfw()}

// ===== agent push-update page =====
function agentBody(){return ''+
 '<div class="card agx-uni">'+   // AGENT card
  '<div class="k"><span class="chip" style="--hue:var(--acc)">'+ic('cpu','var(--acc)')+'</span> '+esc(T('ag_node_agent'))+'<span class="grow"></span><span id="ag_status"></span></div>'+
  '<div class="agx-meta" id="ag_meta"></div>'+
  '<div class="agx-act">'+
    '<button class="primary" id="ag_git_btn" onclick="agFetchGit()">'+ic('redo')+esc(T('ag_fetch_git'))+'</button>'+
    '<button class="ghost" onclick="el(\\'ag_file\\').click()">'+ic('plus')+esc(T('ag_file_btn'))+'</button>'+
  '</div>'+
  '<button class="primary" style="width:100%;margin-top:9px" onclick="agPush(\\'all\\')">'+ic('redo')+esc(T('ag_push_all'))+'</button>'+
  '<input type="file" id="ag_file" accept=".py" style="display:none" onchange="agPick(this)">'+
  '<div class="msg" id="ag_git_msg"></div><div class="msg" id="ag_msg"></div>'+
 '</div>'+
 '<div class="card agx-uni">'+   // CORE card — matched to the agent card
  '<div class="k"><span class="chip" style="--hue:#8b5cf6">'+ic('cpu','#8b5cf6')+'</span> '+esc(T('ag_data_core'))+'<span class="grow"></span><span id="cor_status"></span></div>'+
  '<div class="agx-meta" id="cor_meta"></div>'+
  '<div id="cor_ver_box" style="margin-bottom:9px"></div>'+
  '<div class="agx-act">'+
    '<button class="primary" style="background:#8b5cf6" onclick="corStage()">'+ic('redo')+esc(T('ag_fetch_git'))+'</button>'+
    '<button class="ghost" onclick="el(\\'cor_file\\').click()">'+ic('plus')+esc(T('ag_binary'))+'</button>'+
  '</div>'+
  '<button class="primary" style="width:100%;margin-top:9px;background:#8b5cf6" onclick="corPushAll()">'+ic('redo')+esc(T('ag_install_all'))+'</button>'+
  '<input type="file" id="cor_file" style="display:none" onchange="agCorPick(this)">'+
  '<div class="agx-hint">'+esc(T('ag_core_hint'))+'</div>'+
  '<div class="msg" id="cor_msg"></div>'+
 '</div>'+
 '<div class="sec">'+ic('server','var(--acc)')+' '+esc(T('nodes_fleet'))+'</div>'+
 '<div class="toolbar"><input id="q_agent" class="search" placeholder="'+esc(T('ag_search'))+'" oninput="onSearch(\\'agent\\')"></div>'+
 '<div id="agList">'+skCards('agent')+'</div>'+pagerBottom('agent')}
function agentSkel(){el('view').innerHTML='<h1>'+ic('cpu','var(--acc)')+' '+esc(T('ag_title'))+'</h1><p class="sub">'+esc(T('ag_sub'))+'</p>'+agentBody();refreshAgent()}
async function refreshAgent(){var info=await j('agent-info').catch(function(){return{none:true}});AGMETA=info;
 var st=el('ag_status'),mt=el('ag_meta');
 if(st)st.innerHTML=(info&&!info.none)?'<span class="badge ok">'+esc(T('ag_ready'))+'</span>':'<span class="badge na">'+esc(T('ag_empty'))+'</span>';
 if(mt)mt.innerHTML=(info&&!info.none)?
  '<span>'+esc(T('ag_word_agent'))+'</span><span class="mono">v'+num(info.version)+'</span><span class="sep"></span><span class="mono">'+esc(String(info.sha256||'').slice(0,12))+'</span><span class="sep"></span><span>'+Math.round(num(info.size)/1024)+' '+esc(T('unit_kb'))+'</span>'
  :'<span class="muted">'+esc(T('ag_no_agent_loaded'))+'</span>';
 loadCoreVersions();
 var box=el('agList');if(!box)return;
 var r=await j('nodes?offset='+(PG.agent*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.agent));var nodes=r.nodes||[];TOT.agent=num(r.total);
 box.innerHTML=nodes.length?nodes.map(agRow).join(''):'<div class="card muted">'+esc(T('ag_no_item'))+'</div>';renderPager('agent')}
var CORVERS=[],STAGED=null;
async function loadCoreVersions(want){
 var r=await j('core-versions').catch(function(){return{versions:[]}});
 CORVERS=r.versions||[];STAGED=r.staged||null;
 var stt=el('cor_status');
 if(stt)stt.innerHTML=STAGED?'<span class="badge ok">'+esc(T('ag_ready'))+'</span>':'<span class="badge na">'+esc(T('ag_empty'))+'</span>';
 var mt=el('cor_meta');
 if(mt){
  if(STAGED){var a=(STAGED.arches&&STAGED.arches[0])||'amd64';var sh=(STAGED.sha&&STAGED.sha[a])||'';var sz=(STAGED.size&&STAGED.size[a])||0;
   mt.innerHTML='<span>'+esc(T('ag_word_core'))+'</span><span class="mono">'+esc(STAGED.version)+'</span>'+(sh?'<span class="sep"></span><span class="mono">'+esc(String(sh).slice(0,12))+'</span>':'')+(sz?'<span class="sep"></span><span>'+(sz/1048576).toFixed(1)+' '+esc(T('unit_mb_full'))+'</span>':'')+((STAGED.arches||[]).length?'<span class="sep"></span><span>'+STAGED.arches.join(' · ')+'</span>':'');}
  else mt.innerHTML='<span class="muted">'+esc(T('ag_no_core_staged'))+'</span>';
 }
 var box=el('cor_ver_box');if(!box)return;   // styled dropdown (matches every other list in the panel)
 var items=CORVERS.map(function(x){return {v:x.id,label:x.label||x.id}});
 var sel=want||ssVal('corver')||(items.length?items[0].v:'');   // default to the newest real version (no synthetic "latest")
 if(!items.filter(function(x){return String(x.v)==String(sel)}).length)sel=items.length?items[0].v:'';
 box.innerHTML=ssHTML('corver',items,sel,T('ag_pick_version'),'')}
async function corStage(){var ver=ssVal('corver')||'latest';var m=el('cor_msg');m.className='msg';m.textContent=T('cor_downloading');
 var res=await post('core-stage',{version:ver});
 if(res.ok&&res.d&&res.d.ok){m.className='msg ok';m.innerHTML=T('cor_staged_pre')+esc(res.d.version)+T('cor_staged_post')+((res.d.arches||[]).length?' ('+res.d.arches.join(', ')+')':'')+CK;loadCoreVersions()}
 else{m.className='msg err';m.textContent=terr((res.d&&(res.d.error||res.d.msg))||T('err_github'))}}
async function corPushStaged(id){var m=el('agres_'+id);if(m){m.className='msg agres';m.textContent=T('cor_pushing')}
 var res=await post('core-push',{ids:[id]});var x=((res.d&&res.d.results)||[])[0]||{};
 if(m){if(x.ok){m.className='msg agres ok';m.innerHTML=(x.unchanged?T('ag_core_already'):T('ag_core_updated'))+CK}
  else{m.className='msg agres err';m.textContent=T('ag_fail')+terr(x.error||'')}}
 setTimeout(refreshAgent,4000)}
async function corPushAll(){var ver=ssVal('corver');if(!ver){toast(T('ag_pick_ver'),'err');return}
 var r=await j('node-names');var ids=(r.nodes||[]).filter(function(n){return n.online}).map(function(n){return n.id});
 if(!ids.length){toast(T('ag_no_online'),'err');return}
 if(!await confirmBox(T('ag_confirm_core')+ver+T('ag_confirm_core2')+ids.length+T('ag_confirm_core3'),T('yes_all')))return;
 ids.forEach(function(id){var m=el('agres_'+id);if(m){m.className='msg agres';m.textContent=T('ag_installing_core')}});   // per-node status, like پوشِ همه
 var res=await post('core-update',{ids:ids,version:ver});var rs=(res.d&&res.d.results)||[];var ok=0;
 rs.forEach(function(x){var m=el('agres_'+x.id);
  if(x.ok){ok++;if(m){m.className='msg agres ok';m.innerHTML=(x.unchanged?T('ag_core_already'):T('ag_core_updated'))+CK}}
  else if(x.offline){if(m){m.className='msg agres';m.textContent=T('ag_skipped_off')}}
  else{if(m){m.className='msg agres err';m.textContent=T('ag_fail')+terr(x.error||'')}}});
 toast(ok+'/'+rs.length+T('ag_nodes_updated'),ok?'ok':'err');
 setTimeout(refreshAgent,4500)}
function agCorPick(inp){var f=inp.files&&inp.files[0];if(!f)return;inp.value='';
 var m=el('cor_msg');m.className='msg';m.textContent=T('cor_reading_upload');
 var rd=new FileReader();
 rd.onload=function(){var b=String(rd.result||'');var i=b.indexOf(',');agCorUpload(i>=0?b.slice(i+1):b,f.name)};
 rd.onerror=function(){m.className='msg err';m.textContent=T('cor_read_fail')};
 rd.readAsDataURL(f)}
async function agCorUpload(b64,name){var m=el('cor_msg');
 var res=await post('core-upload',{data:b64,name:name});
 if(res.ok&&res.d&&res.d.ok){m.className='msg ok';m.innerHTML=T('cor_bin_saved_pre')+esc(name)+' · '+Math.round(res.d.size/1024)+'KB · <span class="mono">'+esc(res.d.sha256)+'</span>'+CK+T('cor_bin_saved_post');
  await loadCoreVersions('custom')}
 else{m.className='msg err';m.textContent=terr((res.d&&res.d.error))||T('failed')}}
function agRow(n){var i=n.info||{};var agver=i.version?('v'+num(i.version)):'—';
 var cinst=!!(i.core_sha&&String(i.core_sha).length);            // core_sha empty => no binary on the node
 var carch=i.arch||'amd64';var ssha=(STAGED&&STAGED.sha&&STAGED.sha[carch])||'';
 var agup=!!(AGMETA&&!AGMETA.none&&i.sha256!==AGMETA.sha256);    // agent update available
 var cup=!!(STAGED&&(!cinst||(ssha&&String(i.core_sha)!==String(ssha).slice(0,12))));  // core update available/missing
 // status = a colored icon only (no به‌روز/آپدیت text); full text lives in the tooltip.
 function stx(lbl,cls,icon,tip){return '<span class="stx" title="'+tip+'">'+lbl+' <span class="ico '+cls+'">'+icon+'</span></span>'}
 // agent status + button-enable
 var agbdg,agdis;var LA=T('ag_lbl_agent'),LC=T('ag_lbl_core');
 if(!n.online){agbdg=stx(LA,'offl','—',T('offline'));agdis=1}
 else if(!AGMETA||AGMETA.none){agbdg='';agdis=1}
 else if(agup){agbdg=stx(LA,'up',ic('redo'),LA+': '+T('ag_up_avail'));agdis=0}
 else{agbdg=stx(LA,'ok',ic('check'),LA+': '+T('ag_uptodate'));agdis=1}
 // core status + button-enable
 var cbdg,cdis;
 if(!n.online){cbdg=stx(LC,'offl','—',T('offline'));cdis=1}
 else if(!cinst){cbdg=stx(LC,'na',ic('dl'),LC+': '+T('ag_not_installed'));cdis=!STAGED}
 else if(cup){cbdg=stx(LC,'up',ic('redo'),LC+': '+T('ag_up_avail'));cdis=0}
 else{cbdg=stx(LC,'ok',ic('check'),LC+': '+T('ag_uptodate'));cdis=1}
 var corpill=cinst?'<span class="agx-pill cor">⚙ '+esc(i.core_ver||'?')+'</span>':'';
 return '<div class="agx-row">'+
   '<div class="agx-right">'+
     '<div class="agx-l1"><span class="ndot '+(n.online?'on':'off')+'"></span><span class="nm">'+esc(n.name)+'</span><span class="agx-pill">'+agver+'</span>'+corpill+'</div>'+
     '<div class="agx-l2">'+agbdg+cbdg+'</div>'+
   '</div>'+
   '<div class="agx-colb">'+
     '<button class="agx-btn'+(agup&&n.online?' up':'')+'"'+(agdis?' disabled':'')+' onclick="agPush(\\''+n.id+'\\')">'+ic('redo')+esc(LA)+'</button>'+
     '<button class="agx-btn'+(cup&&n.online?' up':'')+'"'+(cdis?' disabled':'')+' onclick="corPushStaged(\\''+n.id+'\\')">'+ic('redo')+esc(LC)+'</button>'+
   '</div>'+
   '<div class="msg agres" id="agres_'+n.id+'"></div></div>'}
function agPick(inp){var f=inp.files&&inp.files[0];if(!f)return;inp.value='';var rd=new FileReader();rd.onload=function(){window._agCode=rd.result;agUpload()};rd.readAsText(f)}
async function agUpload(){var m=el('ag_msg');var code=window._agCode;
 if(!code||!code.trim()){m.className='msg err';m.textContent=T('ag_pick_file_first');return}
 m.className='msg';m.textContent=T('ag_checking_saving');
 var r=await post('agent-upload',{code:code});
 if(r.ok&&r.d.ok){m.className='msg ok';m.textContent=T('ag_saved_pre')+r.d.version+' · '+r.d.sha256;window._agCode=null;refreshAgent()}
 else{m.className='msg err';m.textContent=terr(r.d.error)||T('failed')}}
async function agFetchGit(){var m=el('ag_git_msg'),btn=el('ag_git_btn');
 m.className='msg';m.textContent=T('ag_fetching_git');if(btn)btn.disabled=true;
 var r=await post('agent-fetch-git',{});
 if(!(r.ok&&r.d.ok)){m.className='msg err';m.textContent=terr(r.d.error)||T('failed');if(btn)btn.disabled=false;return}
 m.className='msg ok';m.innerHTML=T('ag_fetched_pre')+r.d.version+' · <span class="mono">'+esc(r.d.sha256)+'</span>'+T('ag_fetched_post')+CK;
 if(btn)btn.disabled=false;
 await refreshAgent()}
async function agPush(target){if(!AGMETA||AGMETA.none){toast(T('ag_pick_first'),'err');return}
 var ids;
 if(target=='all'){var r=await j('node-names');ids=(r.nodes||[]).filter(function(n){return n.online}).map(function(n){return n.id});
  if(!ids.length){toast(T('ag_no_online'),'err');return}
  if(!await confirmBox(T('ag_confirm_all')+ids.length+T('ag_confirm_all2'),T('yes_all')))return}
 else{ids=[target];var mm=el('agres_'+target);if(mm){mm.className='msg agres';mm.textContent=T('sending')}}
 var res=await post('agent-push',{ids:ids});var rs=(res.d&&res.d.results)||[];var ok=0;
 rs.forEach(function(x){var m=el('agres_'+x.id);
  if(x.ok&&x.already){ok++;if(m){m.className='msg agres ok';m.innerHTML=T('ag_already')+CK}}
  else if(x.ok){ok++;if(m){m.className='msg agres ok';m.innerHTML=T('ag_updated')+CK+T('ag_restarting')}}
  else if(x.offline){if(m){m.className='msg agres';m.textContent=T('ag_skipped_off')}}
  else{if(m){m.className='msg agres err';m.textContent=T('ag_fail')+terr(x.error||'')}}});
 if(target=='all')toast(ok+'/'+rs.length+T('ag_nodes_updated'),ok?'ok':'err');
 setTimeout(function(){if(cur=='agent'||cur=='settings')refreshAgent()},4500)}
function refresh(){var p;if(cur=='overview')p=refreshOverview();else if(cur=='nodes')p=refreshNodes();else if(cur=='tunnels')p=refreshTunnels();else if(cur=='core')p=refreshCore();else if(cur=='portfw')p=refreshPortfw();else if(cur=='agent')p=refreshAgent();else if(cur=='logs')p=refreshLogs();else if(cur=='settings'&&el('agList'))p=refreshAgent();return Promise.resolve(p)}
// ===== system event log (auto events only; operator actions are excluded server-side) =====
function fmtEvTime(ts){var d=new Date(ts*1000);try{return d.toLocaleString(LANG=='fa'?'fa-IR':'en-US',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}catch(e){return d.toISOString().slice(0,16).replace('T',' ')}}
function logsSkel(){el('view').innerHTML='<h1>'+ic('activity','var(--acc)')+' '+esc(T('logs_title'))+'</h1><p class="sub">'+esc(T('logs_sub'))+'</p>'+
 '<div class="tbtnrow" style="margin-bottom:10px"><button class="chkall" onclick="refreshLogs()">'+ic('redo')+esc(T('logs_refresh'))+'</button><button class="chkall" onclick="logsClear()">'+ic('trash')+esc(T('logs_clear'))+'</button></div>'+
 '<div id="logChips"></div>'+
 '<div id="logList">'+skLog()+skLog()+skLog()+skLog()+skLog()+'</div>';markLogsSeen();refreshLogs();}
// One skeleton log card — same geometry as the real logcard (stripe + icon chip + two text bars + time),
// so the loading state is pixel-identical to the loaded list (matches every other page's skeleton).
function skLog(){return '<div class="card logcard" style="display:flex;margin-bottom:9px;padding:0;box-shadow:var(--sh-sm)">'+
 '<span class="sk" style="width:5px;flex:0 0 auto;border-radius:0"></span>'+
 '<div style="display:flex;gap:11px;align-items:flex-start;padding:12px 13px;flex:1;min-width:0">'+
   '<span class="sk" style="width:30px;height:30px;border-radius:9px;flex:0 0 auto"></span>'+
   '<div style="flex:1;min-width:0;display:flex;flex-direction:column;gap:8px"><span class="sk" style="width:62%;height:13px"></span><span class="sk" style="width:40%;height:11px"></span></div>'+
   '<span class="sk" style="width:38px;height:11px;flex:0 0 auto"></span>'+
 '</div></div>';}
// Map an event to a filter CATEGORY: tunnel (link up/down), rot (rotation/pin/burn/heal = the pool),
// ech, node, else sys. Kept in one place so the chips and the per-card badge always agree.
function logCat(e){var k=e.kind;
 if(k=='link')return 'tunnel';
 if(k=='rot'||k=='edge')return 'rot';
 if(k=='ech')return 'ech';
 if(k=='node')return 'node';
 return 'sys';}
var LOGEVS=[],LOGFILTER='all';
// The horizontal, sideways-scrolling category filter row. Counts are live; empty categories are hidden
// (but the active one always stays visible). "errors only" spans every category.
function logChipsHTML(){
 var c={all:LOGEVS.length,tunnel:0,rot:0,ech:0,node:0,sys:0,err:0};
 LOGEVS.forEach(function(e){c[logCat(e)]++;if(e.level=='bad')c.err++;});
 var order=[['all','logc_all'],['tunnel','logc_tunnel'],['rot','logc_rot'],['ech','logc_ech'],['node','logc_node'],['sys','logc_sys'],['err','logc_err']];
 return '<div class="logchips">'+order.filter(function(o){return o[0]=='all'||o[0]=='err'||c[o[0]]>0||LOGFILTER==o[0]}).map(function(o){var k=o[0];
   return '<div class="fchip'+(LOGFILTER==k?' on':'')+'" data-f="'+k+'" onclick="logFilter(\\''+k+'\\')">'+esc(T(o[1]))+'<span class="ct">'+(c[k]||0)+'</span></div>';}).join('')+'</div>';}
// The filtered list. Each card carries a colored category badge before the title.
function logListHTML(){
 var evs=LOGEVS.filter(function(e){return LOGFILTER=='all'?true:LOGFILTER=='err'?e.level=='bad':logCat(e)==LOGFILTER;});
 if(!evs.length)return '<div class="card muted">'+esc(T('logc_none'))+'</div>';
 return evs.map(function(e){
   var lv=e.level=='bad'?'xc':(e.level=='warn'?'warn':'okc');
   var col=e.level=='bad'?'var(--bad)':(e.level=='warn'?'var(--gold)':'var(--ok)');
   var p=evParts(e),cat=logCat(e);
   return '<div class="card logcard" style="display:flex;margin-bottom:9px;padding:0;box-shadow:var(--sh-sm)">'+
     '<span style="width:5px;flex:0 0 auto;background:'+col+'"></span>'+
     '<div style="display:flex;gap:11px;align-items:flex-start;padding:12px 13px;flex:1;min-width:0">'+
       '<span style="width:30px;height:30px;border-radius:9px;display:grid;place-items:center;flex:0 0 auto;color:'+col+';background:color-mix(in srgb,'+col+' 14%,transparent)">'+ic(lv)+'</span>'+
       '<div style="flex:1;min-width:0"><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span class="lcat lcat-'+cat+'">'+esc(T('logc_'+cat))+'</span><span dir="auto" style="font-size:13px;font-weight:700;line-height:1.55;overflow-wrap:anywhere">'+esc(p.title)+'</span></div>'+((e.kind=='edge'&&p.lines.length>=2)?evEdgeBox(p.lines):p.lines.map(evLine).join(''))+'</div>'+
       '<span class="mono" style="flex:0 0 auto;color:var(--sub);font-size:10.5px;white-space:nowrap;padding-top:2px">'+esc(fmtEvTime(e.ts))+'</span>'+
     '</div></div>';}).join('');}
// Only toggle the active class on the existing chips (do NOT rebuild the row) — rebuilding resets the
// horizontal scrollLeft, which snapped the row back to the start when picking a scrolled-to tab. Counts
// don't change on a filter pick, so an in-place highlight is enough; a full refreshLogs still rebuilds.
function logFilter(k){LOGFILTER=k;var ch=el('logChips');
 if(ch){var cs=ch.querySelectorAll('.fchip');for(var i=0;i<cs.length;i++)cs[i].classList.toggle('on',cs[i].getAttribute('data-f')===k);}
 var box=el('logList');if(box)setHTML(box,logListHTML());}
// Split an event into a clean title + detail lines. New events carry dfa/den (detail, possibly
// multi-line). OLD events only have the combined string, so parse the legacy "…: A ⟵ B" (edge
// switch) and "… — reason" forms too, so both render readably.
function evParts(e){
 var title=(LANG=='en'?e.en:e.fa)||e.fa||e.en||'';
 var det=(LANG=='en'?e.den:e.dfa)||'';
 if(det)return{title:title,lines:det.split('\\n')};
 var arrow=title.indexOf(' ⟵ ')>=0?' ⟵ ':(title.indexOf(' → ')>=0?' → ':'');
 var ci=title.indexOf(': ');
 if(arrow&&ci>0){var ab=title.slice(ci+2).split(arrow);
   return{title:title.slice(0,ci),lines:[(LANG=='en'?'from: ':'از: ')+(ab[0]||'').trim(),(LANG=='en'?'to: ':'به: ')+(ab[1]||'').trim()]};}
 var dash=title.indexOf(' — ');
 if(dash>0)return{title:title.slice(0,dash),lines:[title.slice(dash+3)]};
 return{title:title,lines:[]};
}
// One detail line. "label: value" -> RTL label + LTR-isolated value (IP:port · domain reads clean in
// an RTL page). A plain sentence renders with dir=auto so Persian stays RTL.
function evLine(l){var i=l.indexOf(': ');
 if(i>0)return '<div style="display:flex;gap:7px;align-items:flex-start;margin-top:5px"><span style="color:var(--sub);font-size:11px;flex:0 0 auto;padding-top:5px">'+esc(l.slice(0,i))+':</span>'+
   '<span class="mono" dir="ltr" style="font-size:12px;color:var(--tx);overflow-wrap:anywhere;text-align:left;flex:1;min-width:0;unicode-bidi:isolate;background:var(--field);border:1px solid var(--bord);border-radius:7px;padding:4px 8px">'+esc(l.slice(i+2))+'</span></div>';
 return '<div dir="auto" style="font-size:11.5px;color:var(--sub);line-height:1.8;overflow-wrap:anywhere;margin-top:3px">'+esc(l)+'</div>';}
// Edge-switch detail on ONE line: «از» + old pill, «به» + accent new pill. Values are LTR-isolated
// so IP:port · domain reads cleanly in the RTL page. lines are ["از: OLD","به: NEW"] (from evParts).
var EPILL='display:inline-block;direction:ltr;unicode-bidi:isolate;font-size:11px;padding:3px 9px;border-radius:8px;background:var(--field);border:1px solid var(--bord);color:var(--tx);white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis;vertical-align:middle';
function evVal(l){var i=l.indexOf(': ');return i>0?l.slice(i+2):l;}
function evEdgeBox(lines){var frm=esc(evVal(lines[0]||'')),to=esc(evVal(lines[1]||''));
 return '<div style="margin-top:7px;line-height:2.2">'+
   '<span style="font-size:10.5px;color:var(--sub)">'+(LANG=='en'?'from':'از')+'</span> '+
   '<span style="'+EPILL+'">'+frm+'</span> '+
   '<span style="font-size:10.5px;color:var(--sub)">'+(LANG=='en'?'to':'به')+'</span> '+
   '<span style="'+EPILL+';color:var(--acc);border-color:color-mix(in srgb,var(--acc) 30%,transparent);background:var(--accw)">'+to+'</span></div>';}
async function refreshLogs(){var r=await j('events').catch(function(){return{}});var box=el('logList');if(!box)return;LOGEVS=(r&&r.events)||[];
 var ch=el('logChips');
 if(!LOGEVS.length){if(ch)ch.innerHTML='';setHTML(box,'<div class="card muted">'+esc(T('logs_empty'))+'</div>');return;}
 // Preserve the row's horizontal scroll across the rebuild — the periodic poll calls refreshLogs, and a
 // bare innerHTML swap would reset scrollLeft to 0 and snap the tabs back to the start every few seconds.
 if(ch){var old=ch.querySelector('.logchips'),sl=old?old.scrollLeft:0;ch.innerHTML=logChipsHTML();var nw=ch.querySelector('.logchips');if(nw)nw.scrollLeft=sl;}
 setHTML(box,logListHTML());}
async function logsClear(){if(!await confirmBox(T('logs_clear_confirm')))return;await post('events-clear',{});toast(T('logs_cleared'),'ok');refreshLogs();}
function render(){setnav();editingId=null;setLS('tnl_page',cur);   // remember the page so a reload stays here
 if(cur=='overview')overviewSkel();else if(cur=='nodes')nodesSkel();else if(cur=='tunnels')tunnelsSkel();else if(cur=='core')coreSkel();else if(cur=='portfw'){portfwSkel();return}else if(cur=='agent'){agentSkel();return}else if(cur=='logs'){logsSkel();return}else if(cur=='settings'){settingsSkel();refreshSettings();return}
 refresh()}
function refreshFleet(){return cur=='core'?refreshCore():refreshTunnels()}
// ===== settings (loaded once on nav; NOT re-fetched on the 6s tick so the form is never clobbered mid-edit) =====
function settingsSkel(){el('view').innerHTML='<h1>'+ic('cog','var(--acc)')+' '+esc(T('nav_settings'))+'</h1><p class="sub">'+esc(T('set_sub'))+'</p><div id="setBox"><div class="card muted">'+esc(T('loading'))+'</div></div>'}
var _setMode='alert',_modeOv=null;
function modeLabel(m){return m=='auto'?T('set_mode_auto'):T('set_mode_alert')}
async function refreshSettings(){var s=await j('settings').catch(function(){return{}});var box=el('setBox');if(!box)return;
 _setMode=(s.reconcile_mode=='auto')?'auto':'alert';
 var row=function(t,d,ctl){return '<div class="setrow"><div class="setlbl"><b>'+t+'</b><span>'+d+'</span></div><div class="setctl">'+ctl+'</div></div>'};
 var langseg='<div class="seg2" style="max-width:240px"><button type="button" class="segopt'+(LANG=='fa'?' on':'')+'" onclick="applyLang(\\'fa\\')"><b>فارسی</b></button><button type="button" class="segopt'+(LANG=='en'?' on':'')+'" onclick="applyLang(\\'en\\')"><b>English</b></button></div>';
 box.innerHTML='<div class="card">'+
  row(T('lang_label'),'فارسی / English',langseg)+
  row(T('set_on_ipchange'),T('set_on_ipchange_d'),'<button type="button" class="setfield" onclick="openModePopup()"><span class="val" id="set_mode_val">'+modeLabel(_setMode)+'</span><span class="cv">'+ic('chev')+'</span></button>')+
  row(T('set_rec_int'),T('set_rec_range'),'<input id="set_rec" class="search" type="number" min="5" max="3600" value="'+(num(s.reconcile_interval)||15)+'">')+
  row(T('set_poll_int'),T('set_poll_range'),'<input id="set_poll" class="search" type="number" step="0.1" min="0.3" max="60" value="'+(num(s.poll_interval)||2)+'">')+
  row(T('set_ui_int'),T('set_ui_range'),'<input id="set_ui" class="search" type="number" step="0.1" min="0.3" max="60" value="'+(num(s.ui_interval)||2)+'">')+
  row(T('set_ech_int'),T('set_ech_range'),'<input id="set_ech" class="search" type="number" step="1" min="0" max="1440" value="'+(s.ech_refresh_mins!=null?num(s.ech_refresh_mins):15)+'">')+
  row(T('set_upwin'),T('set_upwin_d'),ssHTML('set_upwin',[{v:'1',label:T('h1')},{v:'3',label:T('h3')},{v:'6',label:T('h6')},{v:'8',label:T('h8')},{v:'12',label:T('h12')},{v:'24',label:T('h24')}],String(num(s.uptime_window)||1),'',''))+
  '<div class="tbtnrow" style="margin:14px 0 0;align-items:center"><button class="primary" onclick="saveSettings()">'+ic('check')+esc(T('save'))+'</button><span class="msg" id="set_msg" style="align-self:center"></span></div>'+
  '</div>'+
  tuningCard(s)+
  '<div class="sec" style="margin-top:8px">'+ic('redo','var(--acc)')+' '+esc(T('set_agent_update'))+'</div>'+agentBody();
 refreshAgent()}
// Operational self-heal / pool-health timings, grouped by category. Applies to a tunnel on its next
// build/rebuild (stamped into the core config), so changing a value here + rebuilding heals with it.
var _TUNDEF={suspect_backoff:[30,60,120,300,600],dead_retest_secs:1800,pin_ttl_secs:30,data_fail_threshold:2,data_good_window_secs:120,idle_mult:4,idle_min_secs:60,session_stale_mult:3,session_stale_min_secs:10,ping_loss_threshold:3,min_liveness_secs:20,probe_timeout_secs:5,flux_rotate_default_secs:600};
function _tv(s,k){var t=(s&&s.tuning)||{};return (t[k]!=null?t[k]:_TUNDEF[k])}
function tNum(id,val,mn,mx){return '<input id="'+id+'" class="search" type="number" step="1" min="'+mn+'" max="'+mx+'" value="'+esc(String(val))+'">'}
function tuningCard(s){var row=function(t,d,ctl){return '<div class="setrow"><div class="setlbl"><b>'+t+'</b><span>'+d+'</span></div><div class="setctl">'+ctl+'</div></div>'};
 return '<div class="card" style="margin-top:8px">'+
  '<div class="sec2" style="margin:0 0 4px">'+ic('activity','var(--acc)')+' '+esc(T('set_tun_hd'))+'</div>'+
  '<div class="muted" style="font-size:11px;line-height:1.8;margin:0 2px 6px">'+esc(T('set_tun_note'))+'</div>'+
  '<div class="settcat">'+esc(T('set_tcat_pool'))+'</div>'+
  row(T('set_t_suspect'),T('set_t_suspect_d'),'<input id="set_t_suspect" class="search wtxt" type="text" inputmode="numeric" value="'+esc(_tv(s,'suspect_backoff').join(', '))+'">')+
  row(T('set_t_deadretest'),T('set_t_deadretest_d'),tNum('set_t_deadretest',_tv(s,'dead_retest_secs'),5,86400))+
  row(T('set_t_pinttl'),T('set_t_pinttl_d'),tNum('set_t_pinttl',_tv(s,'pin_ttl_secs'),1,3600))+
  row(T('set_t_datafail'),T('set_t_datafail_d'),tNum('set_t_datafail',_tv(s,'data_fail_threshold'),1,100))+
  row(T('set_t_datagood'),T('set_t_datagood_d'),tNum('set_t_datagood',_tv(s,'data_good_window_secs'),1,86400))+
  '<div class="settcat">'+esc(T('set_tcat_dead'))+'</div>'+
  row(T('set_t_idlemult'),T('set_t_idlemult_d'),tNum('set_t_idlemult',_tv(s,'idle_mult'),1,100))+
  row(T('set_t_idlemin'),T('set_t_idlemin_d'),tNum('set_t_idlemin',_tv(s,'idle_min_secs'),1,86400))+
  row(T('set_t_ssmult'),T('set_t_ssmult_d'),tNum('set_t_ssmult',_tv(s,'session_stale_mult'),1,100))+
  row(T('set_t_ssmin'),T('set_t_ssmin_d'),tNum('set_t_ssmin',_tv(s,'session_stale_min_secs'),1,86400))+
  row(T('set_t_pingloss'),T('set_t_pingloss_d'),tNum('set_t_pingloss',_tv(s,'ping_loss_threshold'),1,100))+
  row(T('set_t_minlive'),T('set_t_minlive_d'),tNum('set_t_minlive',_tv(s,'min_liveness_secs'),1,3600))+
  row(T('set_t_probeto'),T('set_t_probeto_d'),tNum('set_t_probeto',_tv(s,'probe_timeout_secs'),1,120))+
  '<div class="settcat">'+esc(T('set_tcat_rot'))+'</div>'+
  row(T('set_t_fluxrot'),T('set_t_fluxrot_d'),tNum('set_t_fluxrot',_tv(s,'flux_rotate_default_secs'),1,86400))+
  '<div class="tbtnrow" style="margin:14px 0 0;align-items:center;gap:8px"><button class="primary" onclick="saveTuning()">'+ic('check')+esc(T('save'))+'</button><button class="ghost" onclick="resetTuning()">'+ic('reset')+esc(T('set_tun_reset'))+'</button><span class="msg" id="tun_msg" style="align-self:center"></span></div>'+
  '</div>'}
function _collectTuning(){
 var sb=(v('set_t_suspect')||'').split(',').map(function(x){return parseInt(x.trim())}).filter(function(n){return n>=1&&n<=86400});
 var t={dead_retest_secs:parseInt(v('set_t_deadretest')),pin_ttl_secs:parseInt(v('set_t_pinttl')),data_fail_threshold:parseInt(v('set_t_datafail')),data_good_window_secs:parseInt(v('set_t_datagood')),idle_mult:parseInt(v('set_t_idlemult')),idle_min_secs:parseInt(v('set_t_idlemin')),session_stale_mult:parseInt(v('set_t_ssmult')),session_stale_min_secs:parseInt(v('set_t_ssmin')),ping_loss_threshold:parseInt(v('set_t_pingloss')),min_liveness_secs:parseInt(v('set_t_minlive')),probe_timeout_secs:parseInt(v('set_t_probeto')),flux_rotate_default_secs:parseInt(v('set_t_fluxrot'))};
 if(sb.length)t.suspect_backoff=sb;
 return t}
async function saveTuning(){var m=el('tun_msg');if(m){m.className='msg';m.textContent=T('saving')}
 var r=await post('settings-set',{tuning:_collectTuning()});
 if(r.ok&&r.d.ok){if(m){m.className='msg';m.textContent=''}toast(T('set_tun_saved'),'ok')}
 else{if(m){m.className='msg err';m.textContent=terr((r.d&&(r.d.error||r.d.msg))||T('failed'))}}}
async function resetTuning(){if(!await confirmBox(T('set_tun_reset_confirm')))return;
 var r=await post('settings-set',{tuning:_TUNDEF});
 if(r.ok&&r.d.ok){toast(T('set_tun_saved'),'ok');refreshSettings()}
 else{toast(terr((r.d&&(r.d.error||r.d.msg))||T('failed')),'err')}}
function openModePopup(){var opt=function(m,df){return '<div class="mopt'+(_setMode==m?' on':'')+'" onclick="pickMode(\\''+m+'\\')"><span class="mrad"></span><span class="mt">'+modeLabel(m)+'</span>'+(df?'<span class="mdf">'+esc(T('set_default'))+'</span>':'')+'</div>'};
 _modeOv=openModal('<div class="modelist">'+opt('auto',false)+opt('alert',true)+'</div>',{cls:'modesheet'})}
function pickMode(m){_setMode=m;setT('set_mode_val',modeLabel(m));if(_modeOv){closeModal(_modeOv);_modeOv=null}}
async function saveSettings(){var m=el('set_msg');if(m){m.className='msg';m.textContent=T('saving')}
 var r=await post('settings-set',{reconcile_mode:_setMode,reconcile_interval:v('set_rec'),poll_interval:v('set_poll'),ui_interval:v('set_ui'),ech_refresh_mins:v('set_ech'),uptime_window:ssVal('set_upwin')});
 if(r.ok&&r.d.ok){if(m){m.className='msg';m.textContent=''}toast(T('set_saved'),'ok')}
 else{if(m){m.className='msg err';m.textContent=terr((r.d&&(r.d.error||r.d.msg))||T('failed'))}}}
function tick(){if(document.hidden){clearTimeout(TT);TT=setTimeout(tick,Math.max(UIV,4000));return}  // hidden tab: back off, don't burn cycles
 updateSidebar();refresh().catch(function(){}).then(function(){clearTimeout(TT);TT=setTimeout(tick,UIV)})}
document.addEventListener('visibilitychange',function(){if(!document.hidden){clearTimeout(TT);tick()}});
// ===== command palette (Ctrl+K) =====
document.addEventListener('keydown',function(e){if(!((e.ctrlKey||e.metaKey)&&(e.key=='k'||e.key=='K')))return;
 if(PAL){e.preventDefault();closePal();return}
 var tn=e.target&&e.target.tagName;
 if(tn=='INPUT'||tn=='SELECT'||tn=='TEXTAREA'||document.querySelector('.modalov'))return;  // don't hijack typing or stack over an open modal
 e.preventDefault();openPal()});
function openPal(){if(PAL)return;var ov=document.createElement('div');ov.className='modalov palov';
 ov.innerHTML='<div class="pal"><div class="palin">'+ic('search')+'<input id="pal_q" placeholder="'+esc(T('pal_search'))+'" autocomplete="off"><kbd>Esc</kbd></div><div class="pallist" id="pal_list"></div><div class="palfoot"><span><kbd>↑</kbd><kbd>↓</kbd> '+esc(T('pal_move'))+'</span><span><kbd>↵</kbd> '+esc(T('pal_pick'))+'</span><span><kbd>Esc</kbd> '+esc(T('pal_close'))+'</span></div></div>';
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
 {i:'dash',label:T('nav_overview'),act:function(){palNav('overview')}},{i:'server',label:T('nav_nodes'),act:function(){palNav('nodes')}},
 {i:'link',label:T('nav_tunnels'),act:function(){palNav('tunnels')}},{i:'globe',label:T('nav_portfw'),act:function(){palNav('portfw')}},
 {i:'plus',label:T('pal_add_tun'),act:function(){cur='tunnels';closePal();render();setTimeout(openCreateModal,300)}},{i:'redo',label:T('pal_agent'),act:function(){palNav('agent')}},
 {i:'activity',label:T('pal_checkall'),act:function(){cur='tunnels';closePal();render();setTimeout(function(){if(window.checkAll)checkAll()},600)}},
 {i:document.body.classList.contains('dark')?'sun':'moon',label:T('pal_theme'),act:function(){closePal();toggleTheme()}}]}
function palRender(q){q=(q||'').trim().toLowerCase();
 var nodes=(PALDATA.nodes||[]).filter(function(n){return !q||n.name.toLowerCase().indexOf(q)>=0||(n.host||'').indexOf(q)>=0}).slice(0,6)
  .map(function(n){return {i:'server',label:esc(n.name),sub:esc(n.host),act:function(){cur='nodes';QRY.nodes=n.name;PG.nodes=0;closePal();render()}}});
 var tuns=(PALDATA.tuns||[]).filter(function(l){return !q||((l.a_name||'')+' '+(l.b_name||'')+' '+(l.name||'')+' '+(l.type||'')).toLowerCase().indexOf(q)>=0}).slice(0,6)
  .map(function(l){return {i:'link',label:esc(l.a_name)+' ↔ '+esc(l.b_name),sub:esc(l.name),act:function(){cur='tunnels';QRY.tunnels=l.name;PG.tunnels=0;closePal();render()}}});
 var acts=palActions().filter(function(a){return !q||a.label.toLowerCase().indexOf(q)>=0});
 var groups=[[T('pal_g_nodes'),nodes],[T('pal_g_tuns'),tuns],[T('pal_g_acts'),acts]];PALITEMS=[];var html='';
 groups.forEach(function(g){if(!g[1].length)return;html+='<div class="palsec">'+g[0]+'</div>';
  g[1].forEach(function(it){var idx=PALITEMS.length;PALITEMS.push(it);
   html+='<div class="palrow" onmouseenter="PALIDX='+idx+';palHi()" onclick="palGo('+idx+')"><span class="gi">'+ic(it.i)+'</span>'+it.label+(it.sub?'<span class="sub mono">'+it.sub+'</span>':'')+'</div>'})});
 if(!PALITEMS.length)html='<div class="palrow" style="cursor:default;color:var(--sub)">'+esc(T('pal_none'))+'</div>';
 var lst=el('pal_list');if(lst)lst.innerHTML=html;PALIDX=0;palHi()}
function palHi(){document.querySelectorAll('#pal_list .palrow').forEach(function(r,i){r.classList.toggle('sel',i==PALIDX)})}
function palGo(i){var it=PALITEMS[i];if(it&&it.act)it.act()}
function palKey(e){if(e.key=='ArrowDown'){e.preventDefault();PALIDX=Math.min(PALIDX+1,PALITEMS.length-1);palHi();palSc()}
 else if(e.key=='ArrowUp'){e.preventDefault();PALIDX=Math.max(PALIDX-1,0);palHi();palSc()}
 else if(e.key=='Enter'){e.preventDefault();palGo(PALIDX)}else if(e.key=='Escape'){e.preventDefault();closePal()}}
function palSc(){var r=document.querySelectorAll('#pal_list .palrow')[PALIDX];if(r)r.scrollIntoView({block:'nearest'})}
(function(){var p=getLS('tnl_page');   // restore the last page on reload (fall back to overview)
 if(['overview','nodes','tunnels','core','portfw','logs','settings','agent'].indexOf(p)>=0)cur=p;})();
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
    threading.Thread(target=events_loop, daemon=True).start()      # record system events (node/tunnel up-down, auto edge change)
    threading.Thread(target=ech_refresh_loop, daemon=True).start() # re-fetch ECH keys so a CDN key rotation self-heals
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
