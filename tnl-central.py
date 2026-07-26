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
import ssl
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
PENDING_FILE = os.path.join(CENTRAL_DIR, "pending_del.json")  # {node_id: [tunnel_name,…]} teardowns owed to a node that was unreachable at delete/wipe time; drained by the poller when the node reconnects, pruned when the node is removed
UPTIME_FILE = os.path.join(CENTRAL_DIR, "uptime.json")     # persisted per-minute up/down history so the bar survives restarts
PORTFW_ORDER_FILE = os.path.join(CENTRAL_DIR, "portfw-order.json")  # operator's manual card order for port-forwards (list of node_id+name keys)
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
CORE_RAW_PROFILES = ("bip", "ipip", "gre", "icmp", "udp", "tcp", "esp")   # raw-transport encapsulation profiles
# Core transport carriers + the capability sub-families used across validation AND the browser UI
# (injected into the page below). Single source of truth so a new carrier lands in ONE place.
CORE_TRANSPORTS       = ("udp", "tcp", "raw", "flux", "ws", "dns")  # every core carrier
DIRECT_TRANSPORTS     = ("udp", "tcp", "raw", "flux")               # direct carriers (support IP rotation)
DATAGRAM_TRANSPORTS   = ("udp", "raw", "flux")                      # handshake-less carriers (fec / ip-spoof)
DESYNC_TRANSPORTS     = ("raw", "flux", "tcp", "ws")                # carriers that support fake-desync
STATUSRING_TRANSPORTS = ("udp", "tcp", "raw", "flux", "ws")        # carriers that write a precise status ring (the direct tcp/cover client writes one too)
_reg_lock = threading.Lock()     # serialize every nodes.json / links.json read-modify-write
_pending_lock = threading.Lock()   # serialize pending_del.json read-modify-write (deferred teardowns)
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
        self._ids = sorted({str(i) for i in node_ids if i})  # sorted -> stable lock order, no deadlock
        self._held = []

    def __enter__(self):
        # Acquire the canonical per-node lock for each id. The poller can pop an IDLE lock (and another
        # thread recreate it) in the window between our setdefault and our acquire, which would leave two
        # threads holding DIFFERENT lock objects for the same node — lost mutual exclusion. Guard against
        # it: after acquiring, re-check the lock is still the one registered for this id; if it was
        # swapped, release and retry with the new canonical lock. The poller only pops a lock when it is
        # NOT held, so a lock we already hold is never popped — the two rules together are race-free.
        for i in self._ids:
            while True:
                with _node_locks_guard:
                    lk = _node_locks.setdefault(i, threading.Lock())
                lk.acquire()
                with _node_locks_guard:
                    if _node_locks.get(i) is lk:
                        break
                lk.release()  # popped + recreated under us -> retry with the current canonical lock
            self._held.append(lk)
        return self

    def __exit__(self, *a):
        for lk in reversed(self._held):
            lk.release()
        self._held = []


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


def save_bytes(path, data, mode=0o644):
    """Write a binary blob ATOMICALLY (tmp in the same dir + fsync + os.replace). A plain open(wb)
    truncates then fills, so a concurrent reader (e.g. a node push computing the sha) could read
    half-written bytes and push a corrupt-but-self-consistent binary. os.replace is atomic on POSIX,
    so a reader sees either the whole old file or the whole new one — never a partial."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())   # durable before the rename: a crash mid-write can't leave a truncated staged binary
    os.chmod(tmp, mode)
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
    "keepalive": 15,          # fleet-wide keepalive (the base clock every dead-window scales off); was per-tunnel
    "dead_after_secs": 0,     # fleet-wide fixed dead-window (seconds); 0 = auto (derive from the multipliers below)
    "idle_mult": 4,
    "idle_min_secs": 60,
    "session_stale_mult": 3,
    "session_stale_min_secs": 10,
    "ping_loss_threshold": 3,
    "min_liveness_secs": 20,
    "probe_timeout_secs": 5,
    # دستهٔ ۳ — کارایی
    # sock_buf_mb is expressed in MiB for the operator; the core's `sock_buf` field is BYTES, so
    # _apply_core_tuning converts. 4 matches the core's own default (config.go: c.SockBuf = 4<<20), so an
    # untouched knob stamps nothing and the core keeps its default. 0 means OFF -> stamped as -1, the
    # core's "leave the kernel default" sentinel. Only the datagram carriers (udp/raw/flux) use it.
    "sock_buf_mb": 4,
}
_TUNING_RANGES = {
    "dead_retest_secs": (5, 86400), "pin_ttl_secs": (1, 3600),
    "data_fail_threshold": (1, 100), "data_good_window_secs": (1, 86400),
    "idle_mult": (1, 100), "idle_min_secs": (1, 86400),
    "session_stale_mult": (1, 100), "session_stale_min_secs": (1, 86400),
    "ping_loss_threshold": (1, 100), "min_liveness_secs": (1, 3600),
    "probe_timeout_secs": (1, 120),
    "keepalive": (5, 120), "dead_after_secs": (0, 300),   # dead_after 0 = auto; a positive value is floored to 10 on build
    "sock_buf_mb": (0, 64),   # MiB; 0 = off (kernel default). The core clamps the byte value to 64 MiB.
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


# --------------------------------------------------------------------------- deferred teardown queue
# When a force-delete (tunnel) or best-effort wipe (dead node) can't reach a node to tear its tunnel(s)
# down, the panel record is removed anyway and the owed teardown is parked here as {node_id: [names]}.
# The poller drains it (_pending_drain) the moment that node answers again — sending the same idempotent
# `delete` op — so no live server keeps an orphan. Entries are pruned when the node itself is removed
# (api_node_del), so a permanently-dead node's owed teardowns live no longer than its own record.
def _pending_load():
    try:
        with open(PENDING_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _pending_add(node_id, name):
    """Park a teardown owed to node_id (dedup); return True once it is DURABLY persisted (False if the
    write failed — the caller must then keep its own record so the owed teardown isn't silently lost).
    A blank node/name is a no-op that reports success."""
    if not node_id or not name:
        return True
    with _pending_lock:
        d = _pending_load()
        lst = list(d.get(node_id) or [])
        if name not in lst:
            lst.append(name)
        d[node_id] = lst
        try:
            save_json(PENDING_FILE, d)
            return True
        except OSError:
            return False


def _pending_remove(node_id, name):
    """Drop one owed teardown (after it succeeds), removing the node key when its list empties."""
    with _pending_lock:
        d = _pending_load()
        lst = [x for x in (d.get(node_id) or []) if x != name]
        if lst:
            d[node_id] = lst
        else:
            d.pop(node_id, None)
        try:
            save_json(PENDING_FILE, d)
        except OSError:
            pass


def _pending_prune_node(node_id):
    """Drop ALL teardowns owed to a node (called when the node itself is removed)."""
    with _pending_lock:
        d = _pending_load()
        if node_id in d:
            d.pop(node_id, None)
            try:
                save_json(PENDING_FILE, d)
            except OSError:
                pass


def _pending_names(node_id):
    """The tunnel names still owed a teardown on node_id (a copy, safe to iterate)."""
    return list(_pending_load().get(node_id) or [])


def _pending_counts():
    """{node_id: count} for the UI badge."""
    return {k: len(v) for k, v in _pending_load().items() if v}


def _pending_gc(valid):
    """Drop deferred teardowns owed to node ids NOT in `valid` (the current registry). Closes the
    add-after-prune race (a force-delete's _pending_add landing just after the node was removed) and GCs
    any stale key, so pending_del.json can never grow unbounded. Called from the poller's reap sweep."""
    with _pending_lock:
        d = _pending_load()
        drop = [k for k in d if k not in valid]
        if drop:
            for k in drop:
                d.pop(k, None)
            try:
                save_json(PENDING_FILE, d)
            except OSError:
                pass


def _client_node(L):
    """The registered CLIENT-side node of a core link — the end that dials (server_side names the
    listener; the other end is the client). Returns the node dict or None; callers handle not-found."""
    server_side = L.get("server_side", "a")
    return get_node(L.get("b_node") if server_side == "a" else L.get("a_node"))


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
    (a node with no key provisioned rejects the unsigned push -> the push fails loudly, fail-closed)."""
    try:
        priv, _ = _signing_keys()
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv],
                             input=str(sha_hex).encode(), check=True, capture_output=True).stdout
        return base64.b64encode(sig).decode()
    except Exception:
        return ""


def _ensure_update_key(node):
    """Provision the panel's update-signing PUBLIC key onto a node right before a code/binary push, so the
    node always holds the key it needs to verify the signature. First-set-only + idempotent on the node,
    so calling it before every push is cheap and safe; it only actually writes on the very first contact.
    This is what makes the node's fail-closed verification non-bricking: any push path self-provisions the
    key, so a node reached for the first time (or one whose add-time provisioning blipped) still verifies."""
    try:
        _, pub = _signing_keys()
        node_call(node, "set-update-key", "POST", {"pubkey": pub}, timeout=15)
    except Exception:
        pass


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
_pc = {}                   # node_id -> {"ping":..., "list":..., "ping_ts":t, "list_ts":t}
_pc_lock = threading.Lock()
_tf = {}                   # node_id -> {prev_ts, prev_up, if:{key:{prx,ptx,rx_bps,tx_bps,crx,ctx}}, seed:{}}
_tf_lock = threading.Lock()
TF_MAX_GAP = 120.0         # a poll gap bigger than this: keep the byte delta but suppress the smeared rate
TF_BPS_CEIL = 100e9        # 100 Gbit/s sanity ceiling — a larger computed rate is a garbage read -> treat as reset
_uh = {}                   # node_id -> {"ring":[float 0..1,...], "bts":ts, "up":int, "tot":int} — rolling per-minute up-fraction history
_uh_lock = threading.Lock()
UPTIME_BUCKET = 60         # seconds per uptime sample (one minute; a bucket stores the up-FRACTION = up polls / total polls in it)
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


def _pending_drain(n):
    """Finish the teardowns owed to node n now that it has answered. Uses the idempotent `delete` op, so
    a tunnel that is already gone (or never existed on a re-imaged node) still clears cleanly. Best-effort:
    a delete that still fails stays queued for the next successful poll. Usually a no-op (queue empty).
    CRITICAL: a parked name that a CURRENTLY-REGISTERED link owns on this node is STALE — a recycled
    tunnel_id gave a brand-new live tunnel the same name (e.g. reused core42) — so drop it WITHOUT deleting;
    otherwise the drain would tear down a legitimate re-created tunnel."""
    nid = n["id"]
    names = _pending_names(nid)
    if not names:
        return
    live = {L["name"] for L in load_links() if L.get("a_node") == nid or L.get("b_node") == nid}
    for nm in names:
        if nm in live:                       # a registered tunnel now owns this name here -> stale park, drop it
            _pending_remove(nid, nm)
            continue
        r = node_call(n, "delete", "POST", {"name": nm}, timeout=8)
        if r.get("ok"):
            _pending_remove(nid, nm)
            _tf_forget(nid, [nm])   # drop stale traffic totals so a reused tunnel name starts fresh


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
    if ping.get("ok"):   # node answered -> finish any teardowns owed to it (rare; no-op when the queue is empty)
        _pending_drain(n)


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
            _pending_gc(valid)   # drop deferred teardowns owed to removed nodes (add-after-prune race / stale keys)
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
        try:
            gap = max(0.3, float(get_settings().get("poll_interval", POLL_GAP) or POLL_GAP))  # fractional/sub-second OK
        except Exception:
            gap = POLL_GAP   # a hand-edited settings.json with a non-numeric poll_interval must not kill the poller thread
        time.sleep(gap)


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
    total, n = sum(ring), len(ring)
    if total >= n:            # genuinely zero downtime in the window -> a clean 100%
        return 100.0
    # Any downtime at all (even a few seconds -> at least one red bar): FLOOR to 2 decimals instead of
    # rounding, so it reads as 99.99% and never rounds UP to 100% while the bars show red. Truncation.
    return int(total / n * 10000) / 100


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
    if not src.get("ip_rotate") or src.get("transport") not in DIRECT_TRANSPORTS:
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
    # keepalive + dead_after_secs are fleet-wide too, but the core reads them as TOP-LEVEL config fields
    # (not from the `tuning` object), so inject them there. Only when the operator moved them off the
    # core's own default, so an all-default fleet still hands the core a body it would build identically.
    if tn.get("keepalive"):
        a_body["keepalive"] = b_body["keepalive"] = max(5, min(120, int(tn["keepalive"])))
    if tn.get("dead_after_secs"):
        _da = max(10, min(300, int(tn["dead_after_secs"])))
        a_body["dead_after_secs"] = b_body["dead_after_secs"] = _da
    # sock_buf is a top-level core field too, and it is the one knob the operator sets in a different unit
    # than the core reads: MiB here, BYTES on the wire. 0 means "off", which the core spells as a negative
    # value ("leave the kernel default"); anything else is MiB -> bytes. _settings_tuning already omits the
    # knob when it equals the panel default (4), which is the core's own default, so an untouched fleet
    # stamps nothing and the core applies its 4 MiB itself.
    if "sock_buf_mb" in tn:
        _mb = max(0, min(64, int(tn["sock_buf_mb"])))
        a_body["sock_buf"] = b_body["sock_buf"] = -1 if _mb == 0 else _mb * (1 << 20)
    # everything else rides in the `tuning` object (the core clamps it); strip the top-level knobs so
    # they never appear twice on the wire.
    _tn = {k: v for k, v in tn.items() if k not in ("keepalive", "dead_after_secs", "sock_buf_mb")}
    if _tn:
        a_body["tuning"] = _tn
        b_body["tuning"] = _tn


# The packet-up upstream shape per CDN. The binding constraint is requests/sec from one address,
# not bandwidth: measured on a real ArvanCloud edge at ~120ms RTT, the Cloudflare shape (8 workers,
# ~70 POST/s) gets the source IP TCP-blocked for ~3.5 minutes, while 4x512K at ~33/s runs clean at
# 4/106 Mbit. Cloudflare never blinked at either. xh_up_rate is the portable half — workers/RTT is
# the real rate, so a worker count alone means something different on a fast path than a slow one.
# "cf" carries the core's own defaults, so it emits NOTHING and a Cloudflare tunnel is byte-identical
# to before this existed.
XH_PROFILES = {
    "cf":    {},
    "arvan": {"xh_up_workers": 4, "xh_up_batch_kb": 512, "xh_up_rate": 30},
}


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
    if src.get("obfs"):
        e["obfs"] = True
    if src.get("cover"):                 # TLS camouflage (HTTPS cover); core TCP-only
        e["cover"] = True
        if src.get("cover_sni"):
            e["cover_sni"] = src["cover_sni"]
    if src.get("raw_profile"):           # raw-IP carrier encapsulation (transport=raw only)
        e["raw_profile"] = src["raw_profile"]
    if src.get("raw_proto"):             # bip custom outer IP protocol number (whitelist evasion; bip only)
        e["raw_proto"] = src["raw_proto"]
    if src.get("dns_zone"):              # dns-tunnel carrier: delegated zone + client resolver list
        e["dns_zone"] = src["dns_zone"]
        if src.get("dns_resolvers"):
            e["dns_resolvers"] = src["dns_resolvers"]
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
        if src.get("ws_xhttp_mode") in ("packet", "grpc"):  # upstream style: packet-up | grpc
            e["ws_xhttp_mode"] = src["ws_xhttp_mode"]
        # The CDN profile is stored as a NAME and expanded here, so the numbers exist in exactly one
        # place and a stored tunnel picks up a retuned profile on its next rebuild. grpc has no POST
        # ladder, so the shape is meaningless there.
        if src.get("ws_xhttp_mode") != "grpc":
            e.update(XH_PROFILES.get(str(src.get("xh_profile") or "cf"), {}))
    if src.get("ech"):                   # ECH: hide the SNI (carries ws_ech, the base64 config)
        e["ech"] = True
        host = src.get("ws_host")
        if refetch_ech and host:
            # Re-fetch fresh on rebuild — a stored single-edge ws_ech goes stale when the CDN rotates
            # its key (~hourly), and a stale key fails the ws-upgrade (same failure the pool branch
            # guards). NO fallback: raise rather than replay a stale key (caller runs this BEFORE teardown).
            ec = _fetch_ech(host, _ech_px(src))
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
        ech_map = _fetch_ech_map(hosts, _ech_px(src)) if (pool_ech and refetch_ech) else {}   # concurrent — not host-by-host
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


def _node_view(n, pend=None):
    _uw = get_settings().get("uptime_window", 1)
    base = {"id": n["id"], "name": n["name"], "host": n["host"], "port": n["port"], "proxy": _redact_proxy(n.get("proxy")),
            "disabled": bool(n.get("disabled")),   # operator hid it from the create-tunnel/portfw pickers (still connected/polled)
            "pending_del": (pend if pend is not None else _pending_counts()).get(n["id"], 0),   # teardowns owed to this node, waiting for it to reconnect
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
    _pend = _pending_counts()   # read the deferred-teardown queue once for the whole page
    return {"nodes": [_node_view(n, _pend) for n in page], "total": total, "offset": off, "limit": lim,
            "uptime_window": get_settings().get("uptime_window", 1)}


def api_node_names(d):
    """Compact list (id/name/host/online) of ALL nodes — for the create-tunnel pickers."""
    q = str(d.get("q") or "").strip().lower()
    out = []
    for n in load_nodes():
        if n.get("disabled"):   # operator hid this node from the create-tunnel/portfw pickers
            continue
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
            # a busy tunnel is proven live by traffic-flow / the core heartbeat (alive), which the node
            # reports for every core tunnel — the ICMP probe is only a tiebreaker it may skip entirely.
            pinged = (ah.get("alive") is True) or (bh.get("alive") is True)
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
    _tun = _sset.get("tuning") if isinstance(_sset.get("tuning"), dict) else {}
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
            "uptime_avg": (int(sum(ups) / len(ups) * 10) / 10 if ups else 100), "uptime_down_nodes": downcnt, "uptime_window": win,  # FLOOR to 1 decimal so the fleet avg never rounds up to 100 when a node had downtime
            "mem_used_mb": mu, "mem_total_mb": mt, "disk_used_mb": du, "disk_total_mb": dt,
            "fleet_rx_bps": frx_bps, "fleet_tx_bps": ftx_bps,
            "fleet_rx_total": frx, "fleet_tx_total": ftx,
            "ev_seq": _ev_seq_get(), "log_count": _ev_count_get(),
            "ui_interval": _sset.get("ui_interval", 2), "poll_interval": _sset.get("poll_interval", 2),
            "suspect_backoff": _tun.get("suspect_backoff", _TUNING_DEFAULTS["suspect_backoff"]),
            "dead_retest_secs": _tun.get("dead_retest_secs", _TUNING_DEFAULTS["dead_retest_secs"])}


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

# ProxyCommand relay: OpenSSH has no built-in SOCKS client, so when a node's control proxy is set we
# tunnel the SSH TCP connection through it by pointing `-o ProxyCommand=` at this tiny relay. It does
# the SAME SOCKS5 / HTTP-CONNECT handshake as the agent-HTTP path (_socks5_socket/_http_connect_socket)
# then splices ssh's stdin/stdout to the tunneled socket. Proxy details arrive via TNL_PXY_* env vars
# (so credentials never sit in argv). Self-contained stdlib — no nc/ncat/PySocks dependency on the panel.
_PROXY_RELAY_SRC = r'''#!/usr/bin/env python3
import os, sys, socket, base64, select

def _recvn(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise OSError("proxy closed the connection")
        b += c
    return b

def _socks5(s, pu, pw, dh, dp):
    s.sendall(b"\x05\x02\x00\x02" if pu else b"\x05\x01\x00")
    method = _recvn(s, 2)[1]
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
        addr = b"\x01" + socket.inet_aton(dh)
    except OSError:
        hb = dh.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb
    s.sendall(b"\x05\x01\x00" + addr + int(dp).to_bytes(2, "big"))
    rep = _recvn(s, 4)
    if rep[1] != 0:
        raise OSError("socks5 connect failed (code %d)" % rep[1])
    atyp = rep[3]
    _recvn(s, 4 if atyp == 1 else 16 if atyp == 4 else _recvn(s, 1)[0])
    _recvn(s, 2)

def _http(s, pu, pw, dh, dp):
    req = "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n" % (dh, dp, dh, dp)
    if pu:
        req += "Proxy-Authorization: Basic " + base64.b64encode(("%s:%s" % (pu, pw or "")).encode()).decode() + "\r\n"
    s.sendall((req + "\r\n").encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            raise OSError("proxy closed the connection")
        buf += c
        if len(buf) > 65536:
            raise OSError("proxy response too large")
    line = buf.split(b"\r\n", 1)[0].decode("latin1")
    if " 200" not in line:
        raise OSError("proxy CONNECT refused: " + line[:80])
    return buf.split(b"\r\n\r\n", 1)[1]  # bytes past the header are tunnel data (e.g. the SSH banner)

def main():
    dh, dp = sys.argv[1], int(sys.argv[2])
    scheme = (os.environ.get("TNL_PXY_SCHEME") or "socks5").lower()
    ph = os.environ.get("TNL_PXY_HOST") or ""
    pp = int(os.environ.get("TNL_PXY_PORT") or 0)
    pu = os.environ.get("TNL_PXY_USER") or None
    pw = os.environ.get("TNL_PXY_PASS") or None
    if not ph or not pp:
        raise OSError("proxy host/port missing")
    s = socket.create_connection((ph, pp), 20)
    s.settimeout(20)
    if scheme.startswith("socks"):
        _socks5(s, pu, pw, dh, dp)
        leftover = b""
    else:
        leftover = _http(s, pu, pw, dh, dp)
    s.settimeout(None)
    fin = sys.stdin.buffer.fileno()
    fout = sys.stdout.buffer
    if leftover:
        fout.write(leftover)
        fout.flush()
    fds = [s, fin]
    while fds:
        r = select.select(fds, [], [])[0]
        if s in r:
            data = s.recv(65536)
            if not data:
                break
            fout.write(data)
            fout.flush()
        if fin in r:
            data = os.read(fin, 65536)
            if not data:
                fds.remove(fin)
                try:
                    s.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                s.sendall(data)
    try:
        s.close()
    except OSError:
        pass

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        sys.stderr.write("tnl-proxy: %s\n" % e)
        sys.exit(1)
'''

_proxy_relay_path = None
_proxy_relay_lock = threading.Lock()


def _ensure_proxy_relay():
    """Write the ProxyCommand relay to CENTRAL_DIR once (atomically) and return its path."""
    global _proxy_relay_path
    with _proxy_relay_lock:
        if _proxy_relay_path and os.path.exists(_proxy_relay_path):
            return _proxy_relay_path
        p = os.path.join(CENTRAL_DIR, "proxy_relay.py")
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            f.write(_PROXY_RELAY_SRC)
        os.replace(tmp, p)
        _proxy_relay_path = p
        return p


def _ssh_argv(cfg, remote_cmd):
    # TOFU: accept a host key the first time we see a node (needed for unattended
    # provisioning) but PERSIST it and reject any later change. The old
    # "StrictHostKeyChecking=no + UserKnownHostsFile=/dev/null" trusted every key
    # blindly on every connect, so an on-path attacker could MITM the install
    # session and capture the SSH password / inject a malicious agent as root.
    opts = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
            "-o", "ConnectTimeout=15", "-p", str(cfg["port"])]
    env = dict(os.environ)
    proxy = (cfg.get("proxy") or "").strip()
    if proxy:
        # route the SSH TCP connection through the SAME control proxy as the agent HTTP, so a node
        # whose IP is filtered from the panel is reachable at install time — not only after register.
        pu = urllib.parse.urlparse(proxy if "://" in proxy else "socks5://" + proxy)
        env["TNL_PXY_SCHEME"] = (pu.scheme or "socks5").lower()
        env["TNL_PXY_HOST"] = pu.hostname or ""
        env["TNL_PXY_PORT"] = str(pu.port or "")
        env["TNL_PXY_USER"] = pu.username or ""
        env["TNL_PXY_PASS"] = pu.password or ""
        opts += ["-o", f"ProxyCommand={sys.executable} {_ensure_proxy_relay()} %h %p"]
    target = f"{cfg['user']}@{cfg['host']}"
    if cfg.get("keyfile"):
        return ["ssh", "-i", cfg["keyfile"], "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"] + opts + [target, remote_cmd], env
    env["SSHPASS"] = cfg.get("password", "")
    return ["sshpass", "-e", "ssh"] + opts + [target, remote_cmd], env


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
    cfg = {"host": host, "port": ssh_port, "user": user, "password": password, "proxy": proxy}
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


def api_node_toggle(d):
    # Hide/show a node in the create-tunnel & port-forward pickers. This is ONLY a display flag — it never
    # touches the node, its tunnels or its connection (api_node_names filters on it; the node stays polled
    # and listed on the Nodes page). Clean toggle: the key is dropped entirely when re-enabled.
    _require(d, ["id"])
    want = bool(d.get("disabled"))
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if x["id"] == d["id"]), None)
        if not n:
            raise ValueError("node not found")
        if want:
            n["disabled"] = True
        else:
            n.pop("disabled", None)
        save_json(NODES_FILE, nodes)
    return {"ok": True, "disabled": want}


def api_node_del(d):
    _require(d, ["id"])
    nid = d["id"]
    wipe = bool(d.get("wipe"))
    # force = the operator asserts the node's server is DEAD/gone: wipe best-effort instead of
    # all-or-nothing — skip the (impossible) node-side wipe if unreachable, but STILL close every
    # reachable peer's half now and remove the node + its links from the panel. An unreachable peer's
    # teardown is parked (pending_del) for its own reconnect, so no live server keeps an orphan.
    force = bool(d.get("wipe_force") or d.get("force"))
    out = {"ok": True, "wiped": wipe}
    if wipe:
        n = get_node(nid)
        if not n:
            raise ValueError("نود پیدا نشد")
        if force and _cached_ping(nid).get("ok") is False:
            # The operator forced AND the poller already reports this node offline -> skip the doomed
            # ~60s node-side wipe and go straight to best-effort. No blocking call, no wait. Safe against
            # orphaning a LIVE node: best-effort runs ONLY on a node the poller currently sees as offline
            # (a reachable node reads online, so it takes the normal-wipe branch below instead).
            node_ok = False
        else:
            r = node_call(n, "wipe", "POST", {}, timeout=60)
            node_ok = bool(r.get("ok"))
            if not node_ok:
                # The poller saw this node as UP (or never polled it) yet the wipe failed — it may be a LIVE
                # node returning an error, which best-effort would ORPHAN. Keep all-or-nothing. If the node
                # is really down its status flips to offline within a poll, and a retry force-wipes instantly.
                raise ValueError("پاک‌سازیِ سمتِ نود ناتمام ماند: " + (r.get("error") or r.get("msg") or "خطا")
                                 + " — اگر نود قطع است چند لحظه صبر کن تا وضعیتش قرمز شود بعد «پاک‌سازیِ اجباری» بزن؛ وگرنه «فقط از پنل جدا کن».")
        with _reg_lock:  # snapshot this node's links; they are removed only AFTER the peer teardowns are durably parked
            links = load_links()
            mine = [L for L in links if L.get("a_node") == nid or L.get("b_node") == nid]
            mine_ids = {L["id"] for L in mine}
        _park_failed = []
        def _del_peer_half(L):  # tear the peer's half of each tunnel down too, so no live server is left an orphan
            peer_id = L["b_node"] if L["a_node"] == nid else L["a_node"]
            pn = get_node(peer_id)
            if not pn:
                return
            with _PairLock(peer_id, peer_id):  # lock ONLY the peer (nid is being wiped/removed): a shared nid lock
                rr = node_call(pn, "delete", "POST", {"name": L["name"]}, timeout=8)  # would serialize all N calls -> N*timeout. Still mutually excludes a rebuild on this pair (it holds peer_id too).
            if not rr.get("ok") and not _pending_add(peer_id, L["name"]):
                _park_failed.append(L["id"])   # unreachable peer's teardown couldn't be persisted (rare disk error)
        parallel_map(_del_peer_half, mine, workers=32)  # fan out: N offline peers must not serialize to N*timeout
        if _park_failed:  # a park write failed -> abort BEFORE removing links/node, so nothing is left an orphan; the operator retries
            raise ValueError("صفِ حذفِ معلق نوشته نشد؛ برای پرهیز از تونلِ یتیم چیزی حذف نشد — دوباره تلاش کن.")
        with _reg_lock:  # NOW drop the links — every offline peer's teardown is durably parked (crash-safe: a crash before this leaves the record retryable, never record-gone-but-unparked)
            save_json(LINKS_FILE, [L for L in load_links() if L["id"] not in mine_ids])
        out["links_removed"] = len(mine_ids)
        out["node_wiped"] = node_ok   # False when a DEAD node was force-removed (its own server wasn't cleaned)
    with _reg_lock:
        save_json(NODES_FILE, [n for n in load_nodes() if n["id"] != nid])
    _pending_prune_node(nid)   # node removed from the panel -> the poller can no longer drain its owed teardowns, so drop them
    # Set the tombstone BEFORE popping the caches. _poll_node checks _tombed() right before each cache
    # write, so a poll already mid-flight must see the tomb by the time it writes — otherwise it writes
    # _pc/_tf/_uh back AFTER we popped them and the deleted node is resurrected (phantom throughput in
    # api_summary) until the next poller sweep. Setting it first is what makes the tomb actually do what
    # its comment promises; popping after closes the window.
    with _tomb_lock:  # block an in-flight poll (submitted before this delete) from re-inserting the popped cache
        _tomb[nid] = time.time() + 20
    with _pc_lock:
        _pc.pop(nid, None)
    with _tf_lock:
        _tf.pop(nid, None)
    with _uh_lock:
        _uh.pop(nid, None)
    return out


def api_node_test(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    # Measure the REAL panel->node control-plane RTT server-side (around the ping HTTP call itself), not
    # browser-side where it would also include the browser<->panel hop and the panel's own processing.
    t0 = time.perf_counter()
    p = node_call(n, "ping", "GET")
    if p.get("ok"):
        p = {**p, "rtt_ms": int((time.perf_counter() - t0) * 1000)}  # true node ping (only when reachable)
    # OFFLINE: intentionally no rtt — the time spent waiting for the request to TIME OUT is not a latency,
    # so we don't report it as a "ping" (that was the misleading multi-second number on dead nodes).
    return {"ok": bool(p.get("ok")), "info": p}


def api_node_kernel_tune(d):
    """Host network tuning (part ب) on one node: apply / revert BBR+fq+buffer-ceilings, or read
    status. Operator-triggered from the node card; apply and revert mutate host-wide sysctls on the
    node, status is a read-only snapshot the button uses to show current state."""
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("not found")
    action = str(d.get("action") or "status")
    if action not in ("apply", "revert", "status"):
        raise ValueError("bad action")
    p = node_call(n, "kernel-tune", "POST", {"action": action}, timeout=15)
    if not p.get("ok"):
        return {"ok": False, "error": p.get("error", "unreachable")}
    return {"ok": True, "active": bool(p.get("active")), "cc": str(p.get("cc") or ""),
            "qdisc": str(p.get("qdisc") or ""), "bbr_available": bool(p.get("bbr_available"))}


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


def _store_agent_src(src, msgs, extra_meta=None):
    """Validate a node-agent source (size cap, py-compile gate, agent sentinel, version pull) and store
    it + meta as the current pushable agent. `msgs` supplies the four Persian error variants
    (too_big / bad_py-prefix / not_agent / no_ver); `extra_meta` merges into AGENT_META (e.g.
    {"source": "git"}). Shared by api_agent_upload and api_agent_fetch_git; the per-caller empty/source
    check stays at the call site. Returns {ok, version, sha256[:12]}."""
    if len(src.encode()) > 262144:
        raise ValueError(msgs["too_big"])
    try:
        compile(src, "tnl-node.py", "exec")            # same compile gate the node uses — a broken paste never gets stored
    except SyntaxError as e:
        raise ValueError(msgs["bad_py"] + str(e))
    if '"agent": "tnl-node"' not in src:               # sentinel: only the node agent can be pushed (never tnl-central.py)
        raise ValueError(msgs["not_agent"])
    m = re.search(r'"version":\s*(\d+)', src)
    if not m:
        raise ValueError(msgs["no_ver"])
    ver, sha = int(m.group(1)), hashlib.sha256(src.encode()).hexdigest()
    meta = {"version": ver, "sha256": sha, "size": len(src.encode()), "uploaded_ts": int(time.time())}
    if extra_meta:
        meta.update(extra_meta)
    with _agent_lock:
        save_text(AGENT_FILE, src)
        save_json(AGENT_META, meta)
    return {"ok": True, "version": ver, "sha256": sha[:12]}


def api_agent_upload(d):
    """Store a new node-agent source in the panel (validated) so it can be pushed to the fleet."""
    _require(d, ["code"])
    src = d["code"]
    if not isinstance(src, str) or not src.strip():
        raise ValueError("کد خالی است")
    return _store_agent_src(src, {
        "too_big": "فایل بیش از حد بزرگ است",
        "bad_py": "کد پایتون نامعتبر: ",
        "not_agent": "این فایل ایجنتِ نود نیست",
        "no_ver": "نسخهٔ ایجنت در کد پیدا نشد",
    })


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
    return _store_agent_src(src, {
        "too_big": "فایلِ دریافتی بیش از حد بزرگ است",
        "bad_py": "کدِ دریافتی نامعتبر: ",
        "not_agent": "فایلِ دریافتی ایجنتِ نود نیست",
        "no_ver": "نسخهٔ ایجنت در کدِ دریافتی پیدا نشد",
    }, {"source": "git"})


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
        _ensure_update_key(n)   # provision the verify key before the signed agent-code push (node verifies fail-closed)
        r = node_call(n, "update", "POST", {"code": src, "sha256": meta["sha256"], "sig": _sign_sha(meta["sha256"])}, timeout=30)
        return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")),
                "restarting": bool(r.get("restarting")), "already": bool(r.get("already")), "error": r.get("error") or r.get("msg") or ""}

    return {"results": parallel_map(push_one, ids)}  # poller re-reads each node's version within ~2s after it bounces


_CORE_RELEASES_API = "https://api.github.com/repos/Angize/TUNNEL-MANAGER-CORE/releases"
_core_versions_cache = {"ts": 0.0, "data": None}   # filled ONLY by api_core_check (the button)
_core_versions_lock = threading.Lock()


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


def api_core_versions(d):
    """The core versions the operator can install/downgrade to — served PURELY from cache, never
    fetching. GitHub is often slow or blocked from the deployment region, and a background refresh on
    every settings/agent page load meant the panel reached out on its own schedule for something the
    operator had not asked for. api_core_check is the one place that talks to GitHub now, and it only
    runs when the button is pressed. An empty list until then is the honest state: the panel does not
    know what releases exist."""
    vers = list(_core_versions_cache["data"] or [])
    out = list(vers)  # newest first
    if out:  # tag the newest real release "(latest)" instead of a synthetic "latest" item
        out[0] = {**out[0], "label": (out[0].get("label") or out[0]["id"]) + " (latest)", "latest": True}
    info = _core_blob_info()
    if info:                                          # offer the operator-uploaded binary as its own choice
        out.append({"id": "custom", "label": "\u0628\u0627\u06cc\u0646\u0631\u06cc\u0650 \u0622\u067e\u0644\u0648\u062f\u0634\u062f\u0647" + (" \u00b7 " + info["name"] if info.get("name") else ""),
                    "custom": True, "sha256": info.get("sha256", "")[:12], "size": info.get("size")})
    return {"versions": out, "staged": _staged_info(), "checked_ts": int(_core_versions_cache["ts"] or 0)}


def api_core_check(d):
    """Ask GitHub for the release list, NOW, because the operator pressed the button. Synchronous on
    purpose: the button reports what happened, so it has to wait for the answer. Returns how many
    versions are known and whether the newest one is different from what we had, so the UI can say
    "there is a new version" instead of just silently reordering a dropdown."""
    before = list(_core_versions_cache["data"] or [])
    prev_top = (before[0].get("id") if before else "")
    vers = _fetch_core_versions()
    if vers is None:
        # Keep the previous list rather than blanking it — a failed check must not lose what we knew.
        return {"ok": False, "error": "\u062f\u0631\u06cc\u0627\u0641\u062a \u0627\u0632 \u06af\u06cc\u062a\u200c\u0647\u0627\u0628 \u0646\u0627\u0645\u0648\u0641\u0642 \u0628\u0648\u062f"}
    with _core_versions_lock:
        _core_versions_cache["data"] = vers
        _core_versions_cache["ts"] = time.time()
    top = (vers[0].get("id") if vers else "")
    return {"ok": True, "count": len(vers), "latest": top, "newer": bool(top and top != prev_top),
            "first_check": not before}


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
        # Atomic, like every other on-disk write here. A raw open("wb") truncates first, so a crash or a
        # full disk mid-write leaves a SHORT binary on disk while CORE_BLOB_META still describes the
        # previous upload — and core-push verifies against that meta, so it would ship a truncated ELF to
        # the fleet believing it was the good one.
        save_bytes(CORE_BLOB, raw)
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
    # Cache still cold — the operator has not pressed «بررسی آپدیت» yet. This IS an explicit stage/install
    # action, not a page load, so a one-off synchronous fetch here is fine and beats recording the
    # abstract "latest" against a node.
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
            save_bytes(os.path.join(CORE_STAGE_DIR, f"tnl-core-{arch}"), raw)   # atomic: a concurrent push must not read a half-written binary
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
        save_bytes(p, raw)   # atomic on-demand persist so a racing reader/push never sees partial bytes
        return raw, sha, ver
    with open(p, "rb") as f:
        raw = f.read()
    return raw, hashlib.sha256(raw).hexdigest(), ver


def _node_arch(node):
    """The CPU architecture to push a core binary for, or "" when it cannot be established.

    nodes.json has NEVER carried an `arch` key — no write path adds one (api_node_add, the SSH
    installer and api_node_edit all build the record without it) — so reading it off the record and
    defaulting to amd64 sent the x86-64 asset to EVERY node. An arm64 node then chmod-755'd that binary
    into CORE_BIN and rebuilt its tunnels: each core died with "Exec format error", every core tunnel on
    that node stayed down, and it never self-corrected because the agent page compares the node's
    reported sha against the staged one, so it read "update available" forever and each retry pushed the
    same wrong binary.

    The node already reports its arch in the ping payload, so take it from there: an explicit record
    value first (the freshly-added-node path passes one in), then the poll cache, then one live ping for
    a node that has not been polled yet. Returning "" instead of guessing is deliberate — a wrong-arch
    push is far more damaging than a refused one, and the caller turns it into a clear operator error."""
    a = str(node.get("arch") or "").strip()
    if a in ("amd64", "arm64"):
        return a
    a = str(_cached_ping(node.get("id") or "").get("arch") or "").strip()
    if a in ("amd64", "arm64"):
        return a
    a = str((node_call(node, "ping", "GET", timeout=10) or {}).get("arch") or "").strip()
    return a if a in ("amd64", "arm64") else ""


def _push_staged(node):
    """Push the staged core to one node via core-install (no node download). Returns a result dict."""
    arch = _node_arch(node)
    if not arch:
        return {"ok": False, "error": "معماریِ نود مشخص نشد — نود باید یک‌بار پاسخ بدهد تا باینریِ درست فرستاده شود"}
    b = _staged_bytes(arch)
    if not b:
        return {"ok": False, "error": "هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن"}
    raw, sha, ver = b
    _ensure_update_key(node)   # guarantee the node holds the verify key before a signed root-binary push (fail-closed on the node side)
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


def _core_result(nid, r):
    """Normalize a node core-push/install reply into the per-node result dict the UI renders."""
    err = r.get("error") or r.get("msg") or ("; ".join(r["errors"]) if r.get("errors") else "")
    return {"id": nid, "ok": bool(r.get("ok")), "offline": bool(r.get("offline")), "version": r.get("version"),
            "restarted": r.get("restarted"), "core_sha": r.get("core_sha"), "unchanged": bool(r.get("unchanged")), "error": err}

def _core_push_result(nid):
    """Push the panel's staged core to one node and return its normalized result. Shared by
    api_core_update (stock version) and api_core_push."""
    n = get_node(nid)
    if not n:
        return {"id": nid, "ok": False, "error": "node removed"}
    return _core_result(nid, _push_staged(n))


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
            _ensure_update_key(n)   # provision the verify key before the signed push (node verifies fail-closed)
            r = node_call(n, "core-install", "POST", {"data": b64, "sha256": sha, "version": "custom", "sig": _sign_sha(sha)}, timeout=200)
            return _core_result(nid, r)

        return {"results": parallel_map(one_custom, ids)}

    _stage_core(version)   # download the chosen version onto the panel first (raises if the panel is offline)

    return {"results": parallel_map(_core_push_result, ids)}


def api_core_push(d):
    """Push the currently-staged core to the given node ids (the 'push the ready binary' per-node action).
    No download, no version pick — just deliver what the panel already has staged."""
    _require(d, ["ids"])
    if not _staged_info():
        raise ValueError("هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن")
    if not isinstance(d.get("ids"), list):
        raise ValueError("ids must be a list")
    ids = [i for i in dict.fromkeys(d["ids"]) if get_node(i)]

    return {"results": parallel_map(_core_push_result, ids)}


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
        # A point-to-point core tunnel is alive/dead as a whole, but only the CLIENT side writes the core
        # heartbeat status file. Its hb-derived verdict — live_src "beat" (fresh/stale hb) OR "nohb" (never
        # connected, dw published but no hb yet) — is authoritative for the WHOLE tunnel, because only the
        # client sees whether RETURN traffic arrives. Mirror it onto the heartbeat-less server endpoint,
        # whose one-directional flow/ping would otherwise false-green a HALF-OPEN tunnel (the server still
        # receives the client's upload → flow-"alive"). "nohb" was previously omitted here, so a
        # never-connected tunnel showed the server green while the client correctly went red. Copy first —
        # ah/bh are references into the cache.
        _beat = ah if isinstance(ah, dict) and ah.get("live_src") in ("beat", "nohb") else (
            bh if isinstance(bh, dict) and bh.get("live_src") in ("beat", "nohb") else None)
        if _beat is not None:
            _other = bh if _beat is ah else ah
            if isinstance(_other, dict) and _other.get("up") and _other.get("live_src") not in ("beat", "nohb"):
                _other = dict(_other)
                _other["alive"] = _beat.get("alive")
                _other["dead"] = bool(_beat.get("dead"))
                if _beat is ah:
                    bh = _other
                else:
                    ah = _other
        a_ips = _flat_ips(_cached_ping(L["a_node"]))
        b_ips = _flat_ips(_cached_ping(L["b_node"]))
        side = "b" if L.get("view_side") == "b" else "a"
        pub = {k: v for k, v in L.items() if k != "psk"}   # never expose the shared crypto key (IPsec / core AEAD psk) to the browser
        rec = {**pub, "a_online": bool(la.get("ok")) or la.get("configs") is not None,
               "b_online": bool(lb.get("ok")) or lb.get("configs") is not None,
               "a_health": ah, "b_health": bh, "a_ips": a_ips, "b_ips": b_ips,
               "view_side": side, "view_name": (L["b_name"] if side == "b" else L["a_name"]),
               "drift": link_drift(L["id"]), **tfl.get(L["id"], {})}
        # Live active pool IP: the CLIENT node writes .peerpool (active destination) / .srcpool (active
        # source); surface it per side so the card shows the IP the tunnel is really on right now (the
        # server's box = active destination, the client's box = active source).
        #
        # `*_ip_rot` (the rotation mark) is a property of the POOL, not of the status file. It used to be
        # set to True whenever a status file carried an active address, on the assumption written in the
        # old comment here: ">=2 in its pool -> the node wrote the file". That assumption is dead. The
        # core deliberately builds a ONE-entry source pool (main.go gates on len(SrcIPs) >= 1) to PIN a
        # client's source IP, because bind_ip only works on the TCP family — and a one-entry pool writes
        # its status file just like a real one. So a node with a single IP was marked as rotating, with a
        # tooltip that told the operator it "cycles between several IPs", while PeerPool provably never
        # moves it (TestPeerPoolSingleEndpointNoop). Read the pool itself instead.
        #
        # Set unconditionally, unlike the active IP: whether a side rotates is CONFIGURATION and is always
        # known, while the active address is live state that may not exist yet (node down, core starting).
        if L.get("type") == "core" and L.get("ip_rotate"):
            srvA = (L.get("server_side") != "b")
            cl = lb if srvA else la  # the client is the non-server node
            pd = (cl.get("pools") or {}).get(L["name"]) or {}
            dact = str(pd.get("dst") or "").split(":")[0]  # active destination (bare IP)
            sact = str(pd.get("src") or "").split(":")[0]  # active source (bare IP)
            a_act, b_act = (dact, sact) if srvA else (sact, dact)
            rec["a_ip_rot"] = len([x for x in (L.get("a_ip_pool") or []) if x]) >= 2
            rec["b_ip_rot"] = len([x for x in (L.get("b_ip_pool") or []) if x]) >= 2
            if a_act:
                rec["a_ip_active"] = a_act
            if b_act:
                rec["b_ip_active"] = b_act
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
            return []                        # raw-IP / rotating-protocol: genuinely no L4 port to portcheck
        if t == "dns":
            # dns DOES have an L4 port, and the most contended one on the box: the server core binds
            # <self_ip>:53 as an authoritative NS. Lumping it with raw/flux exempted it from the guard
            # entirely, so a second dns tunnel on the same node — or any node already running
            # systemd-resolved, dnsmasq, bind, or a stray recursor — built cleanly and then failed at
            # core start with an address-in-use the operator never sees, because the panel had already
            # reported success. Port is fixed, so `p` is ignored here.
            return [(srv, srv_ip, 53, "udp")]
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
    than 0.0.0.0). A node that can't answer (briefly unreachable / timing out) is skipped rather
    than hard-blocked."""
    for node, ip, port, proto in bindings:
        if (node["id"], ip or "", int(port), proto) in exclude:
            continue
        r = node_call(node, "portcheck", "POST", {"port": port, "proto": proto, "ip": ip or ""}, timeout=10)
        if not r.get("ok"):
            continue  # node unreachable -> can't verify, don't block the build
        if r.get("busy"):
            who = str(r.get("who") or "").strip()
            tail = f" — {who}" if who else ""
            onip = f" (روی {ip})" if ip else ""
            raise ValueError(f"پورتِ {port}/{proto.upper()} روی نودِ «{node['name']}»{onip} اشغال است{tail}؛ یک پورتِ دیگر انتخاب کن")


def _core_bind_keys(bindings):
    """Normalize _port_bindings output to a comparable key set {(node_id, ip, port, proto)}."""
    return {(n["id"], ip or "", int(p), pr) for n, ip, p, pr in bindings}


# The UDP destination ports each flux carrier rotates across. MIRRORS the core's flux.go
# (fluxDportPool / fluxStunDports); tools/tuning_consistency.py fails if they drift.
FLUX_UDP_DPORTS = (443, 3478, 19302, 5349, 8801)
FLUX_STUN_DPORTS = (3478, 19302, 5349)


def _peer_addrs(rec, side):
    """Every address a link's `side` end can present: its anchor plus, when IP rotation is on, each
    selected pool IP. The conflict guards must reason over ALL of them — a rotating peer is reachable
    from any pool member, so an anchor-only comparison silently under-reports."""
    out = []
    ip = rec.get(side + "_ip")
    if ip:
        out.append(ip)
    if rec.get("ip_rotate"):
        for x in (rec.get(side + "_ip_pool") or []):
            if x and x not in out:
                out.append(x)
    return out


def _flux_drop_points(rec):
    """[(node_id, peer_ip, udp_port)] a flux tunnel's anti-leak rules DROP inbound traffic on.

    flux receives via AF_PACKET — before the IP stack — so the kernel sees frames nobody is listening
    for and answers ICMP port-unreachable, revealing that no real STUN/QUIC service runs here. A
    raw-PREROUTING DROP silences that. The rule covers EVERY pool port at once rather than the current
    epoch's, deliberately, so an epoch rotation never has to touch iptables — and that is exactly why
    it can also swallow an UNRELATED tunnel's traffic from the same peer.
    Both ends install it: the client at dial, the server on the first authenticated frame.
    The `raw` flux carrier is exempt: it rotates IP PROTOCOL numbers, and that pool already excludes
    253 so a co-located raw/bip tunnel survives — the guard this one was missing."""
    if str(rec.get("type") or "") != "core" or str(rec.get("transport") or "").lower() != "flux":
        return []
    carrier = str(rec.get("flux_carrier") or "udp").lower()
    if carrier == "raw":
        return []
    ports = FLUX_STUN_DPORTS if carrier == "stun" else FLUX_UDP_DPORTS
    out = []
    for p in ports:
        # Every peer address, not just the anchor. Under IP rotation the peer reaches us from any IP in
        # its pool, so the node installs a DROP per pool IP — a guard that only knew the anchor missed
        # every collision on the other pool members and let the panel build a tunnel it would black-hole.
        for bip in _peer_addrs(rec, "b"):
            out.append((rec.get("a_node"), bip, p))   # on A, dropping traffic from B
        for aip in _peer_addrs(rec, "a"):
            out.append((rec.get("b_node"), aip, p))   # on B, dropping traffic from A
    return out


def _udp_recv_points(rec):
    """[(node_id, peer_ip, udp_port)] this tunnel RECEIVES UDP on — exactly what a flux DROP rule on
    the same node, from the same peer, on the same port would swallow.

    Only a LISTENING side counts: a core udp client dials from a random ephemeral source port, which
    the pool can never match. fou/l2tpv3/vxlan decap on that port at BOTH ends."""
    ttype = str(rec.get("type") or "")
    p = int(rec.get("port") or _default_tunnel_port(ttype, rec.get("tunnel_id")) or 0)
    if not p:
        return []
    # Same widening as _flux_drop_points: a rotating peer sends from any IP in its pool, so the traffic
    # a DROP rule could swallow is not limited to the anchor. Comparing anchor-to-anchor made the guard
    # blind to every collision that involved a non-anchor pool member on either side.
    if ttype in ("fou", "l2tpv3", "vxlan"):
        return ([(rec.get("a_node"), bip, p) for bip in _peer_addrs(rec, "b")] +
                [(rec.get("b_node"), aip, p) for aip in _peer_addrs(rec, "a")])
    if ttype == "core" and str(rec.get("transport") or "udp").lower() == "udp":
        if (rec.get("server_side") or "a") == "a":
            return [(rec.get("a_node"), bip, p) for bip in _peer_addrs(rec, "b")]
        return [(rec.get("b_node"), aip, p) for aip in _peer_addrs(rec, "a")]
    return []


def _flux_drop_conflict(src, exclude_id=None):
    """The stored link a flux anti-leak DROP rule would black-hole (or that would black-hole THIS
    tunnel), or None.

    The core cannot make this call: it has no idea what else runs on the node. The panel does, and it
    already owns port-conflict checking, so the collision is refused at build time with a clear error
    instead of silently killing a previously healthy tunnel — the failure mode is a tunnel that just
    stops carrying traffic, with no event, no log and a perfectly healthy network.

    Two flux tunnels between the same pair are NOT a conflict: neither receives UDP on a pool port, so
    their identical rules are harmless."""
    drop = set(_flux_drop_points(src))
    recv = set(_udp_recv_points(src))
    if not drop and not recv:
        return None
    for L in load_links():
        if exclude_id and L.get("id") == exclude_id:
            continue
        if drop and drop & set(_udp_recv_points(L)):
            return L
        if recv and recv & set(_flux_drop_points(L)):
            return L
    return None


def _core_l4_conflict(new_binds, exclude_id=None):
    """Registry-level conflict check for a core tunnel. Core is CARRIER-MULTIPLEXED on its server IP:
    only udp/tcp/ws (and dns, on the fixed :53) bind an EXCLUSIVE kernel port (returned by
    _port_bindings), so two core tunnels
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
    """Validate and return the raw-bip outer-IPv4 forgery fields to store on a core link. All three
    forge a field of the outer IPv4 header so an on-path censor sees something other than the real
    flow; they only apply to transport=raw + profile=bip + crypto on. spoof_dst is the decoy
    destination; spoof_src an optional forged source; raw_proto overrides bip's native protocol
    number (1..255, e.g. 58) to slip past a protocol-whitelist filter. The node applies these per
    role (see tnl-node _core_config). cur (the existing link) supplies edit defaults so an edit that
    omits the fields keeps the stored values (mirroring _flux_fields/_ws_fields/_fec_fields) instead
    of silently wiping the config."""
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
    try:
        proto = int((d["raw_proto"] if "raw_proto" in d else cur.get("raw_proto")) or 0)
    except (TypeError, ValueError):
        proto = 0
    if proto:
        if not 1 <= proto <= 255:
            raise ValueError("شمارهٔ پروتکلِ IP باید بینِ ۱ تا ۲۵۵ باشد")
        out["raw_proto"] = proto
    return out


def _dns_fields(d, transport, cipher, cur=None):
    """Validate and return the dns-carrier fields to store on a core link: the delegated zone (whose
    authoritative NS is the server) and the client's recursive-resolver list. The dns tunnel rides
    inside DNS queries to (typically domestic) resolvers, so the client never sends a packet to the
    server IP — the last-resort carrier under a full protocol+destination whitelist. Crypto is
    mandatory (the session handshake and every datagram are AEAD-authenticated). cur (the existing
    link) supplies edit defaults so a partial edit keeps stored values."""
    out = {}
    if transport != "dns":
        return out
    if cipher == "none":
        raise ValueError("حاملِ dns به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
    cur = cur or {}
    zone = str((d["dns_zone"] if "dns_zone" in d else cur.get("dns_zone")) or "").strip().lower()
    if not zone or len(zone) > 253 or not re.match(r"^(?!-)[a-z0-9-]{1,63}(?:\.(?!-)[a-z0-9-]{1,63})+$", zone):
        raise ValueError("نامِ دامنهٔ dns (zone) نامعتبر است — مثلاً t.example.com")
    out["dns_zone"] = zone
    raw_res = d["dns_resolvers"] if "dns_resolvers" in d else cur.get("dns_resolvers")
    resolvers = []
    for r in (raw_res or []):
        rs = str(r).strip()
        if not rs:
            continue
        if rs.count(":") == 1:                       # ip:port — validate BOTH halves, not just the host
            host, _, port = rs.partition(":")
            if not (port.isdigit() and 1 <= int(port) <= 65535):
                raise ValueError("پورتِ resolverِ dns نامعتبر است — باید ۱ تا ۶۵۵۳۵ باشد: " + rs)
        else:
            host = rs
        if not is_ipv4(host):
            raise ValueError("آدرسِ resolverِ dns باید IPv4 باشد (به‌صورتِ ip یا ip:port): " + rs)
        resolvers.append(rs)
    if not resolvers:
        raise ValueError("حاملِ dns حداقل به یک resolverِ معتبر (IPv4) نیاز دارد")
    out["dns_resolvers"] = resolvers
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
    if transport not in DATAGRAM_TRANSPORTS:
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


def _desync_fields(d, transport, cur=None, xhttp=False):
    """Fake-packet desync (anti-DPI): the client emits decoy packets that reach an on-path DPI but
    not the server, mis-syncing a stateful DPI while the real session is untouched. raw/flux forge
    whole IPv4 decoys; tcp/ws inject decoy TCP segments on the kernel connection's 4-tuple. Not on
    plain udp (no injection hook), and NOT on the ws carrier's xhttp mode — its conn is synthetic, so
    the injector's *net.TCPAddr assertion fails and no decoy is ever emitted. cur (the existing link)
    supplies edit defaults so a partial edit
    keeps the stored config. Returns {} when off / not applicable — so switching to udp cleanly
    drops the fields."""
    out = {}
    if transport not in DESYNC_TRANSPORTS:
        return out
    if transport == "ws" and xhttp:
        return out   # xhttp has no real TCP 4-tuple for the injector to mirror; the core rejects it
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


def _ech_from_doh_answers(data):
    """Return the first ECH key found in a DoH JSON reply's HTTPS (type-65) answers, else ''."""
    for ans in data.get("Answer", []):
        if ans.get("type") in (65, "65", "HTTPS"):
            v = _ech_from_text(str(ans.get("data", "")))
            if v:
                return v
    return ""


def _fetch_ech(host, proxy=""):
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
            return _ech_from_doh_answers(data)
        except Exception:
            pass
        return ""

    def via_doh_proxy(dhost, dpath):   # DoH through a SOCKS5/HTTP proxy — a clean egress for a FILTERED domain
        sock = None
        try:
            pu = urllib.parse.urlparse(proxy if "://" in proxy else "socks5://" + proxy)
            scheme = (pu.scheme or "socks5").lower()
            if not pu.hostname or not pu.port:
                return ""
            if scheme.startswith("socks"):
                sock = _socks5_socket(pu.hostname, pu.port, pu.username, pu.password, dhost, 443, 7)
            elif scheme in ("http", "https", "connect"):
                sock = _http_connect_socket(pu.hostname, pu.port, pu.username, pu.password, dhost, 443, 7)
            else:
                return ""
            tls = ssl.create_default_context().wrap_socket(sock, server_hostname=dhost)  # verify the DoH resolver's cert
            sock = None   # the TLS socket owns the fd now (closed via conn.close())
            conn = http.client.HTTPConnection(dhost, 443, timeout=7)
            conn.sock = tls   # write HTTP over the proxy-tunneled TLS socket (skips conn.connect())
            conn.request("GET", "%s?name=%s&type=HTTPS" % (dpath, host),
                         headers={"accept": "application/dns-json", "user-agent": "tnl-central"})
            data = json.loads(conn.getresponse().read().decode("utf-8", "replace"))
            conn.close()
            return _ech_from_doh_answers(data)
        except Exception:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return ""

    doh = ["https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query",
           "https://dns.google/resolve", "https://8.8.8.8/resolve"]
    tasks = [via_dig] + [(lambda b=b: via_doh(b)) for b in doh]
    if proxy:   # per-tunnel proxy set -> add DoH-over-proxy racers; for a filtered domain these win the race
        tasks += [lambda: via_doh_proxy("cloudflare-dns.com", "/dns-query"),
                  lambda: via_doh_proxy("dns.google", "/resolve")]
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


def _fetch_ech_map(hosts, proxy=""):
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
        futs = {ex.submit(_fetch_ech, h, proxy): h for h in uniq}
        for f in concurrent.futures.as_completed(futs):
            try:
                out[futs[f]] = f.result() or ""
            except Exception:
                out[futs[f]] = ""
    return out


def _ech_px(src):
    """The stored per-tunnel ECH-fetch proxy (socks5/http) when its toggle is on, else '' (direct)."""
    return str(src.get("ech_proxy_url") or "").strip() if src.get("ech_proxy") else ""


def _ech_proxy_fields(d, cur, out):
    """Per-tunnel proxy for the ECH-key fetch (reaches a FILTERED domain via a clean egress). Validate +
    store ech_proxy/ech_proxy_url into `out` (only when the toggle is on), and return the proxy URL to
    fetch through, else '' (direct fetch). valid_proxy raises on a malformed URL -> the save fails loudly."""
    on = bool(d.get("ech_proxy") if "ech_proxy" in d else cur.get("ech_proxy"))
    url = valid_proxy((d.get("ech_proxy_url") if "ech_proxy_url" in d else cur.get("ech_proxy_url")) or "")
    if on:
        out["ech_proxy"] = True
        if url:
            out["ech_proxy_url"] = url
    return url if on else ""


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


# The ports a CDN proxies, split by scheme. An edge port from the wrong side is the mistake that
# broke every fronted tunnel until node #118: with wss on, a client aimed at :80 hands a TLS
# ClientHello to a plaintext edge and the handshake dies before anything else is tried — which reads
# as "this CDN doesn't support the carrier" and is nothing of the sort.
#
# This is a WHITELIST: with wss the port must be one a CDN serves TLS on, without it one served in
# the clear. Nothing else is accepted. (A blacklist of the obviously-wrong ports was tried first and
# was not enough in practice — an edge port outside these lists does not front anything, it just
# fails later and looks like a broken carrier.)
_EDGE_PLAIN_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)
_EDGE_TLS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)


def _edge_port_ok(port, tls):
    """Raise unless an explicit edge port matches the scheme wss selects. Runs on create AND edit:
    both go through _core_extra -> _ws_fields, the create form with cur={} and the edit with the
    stored link."""
    allowed = _EDGE_TLS_PORTS if tls else _EDGE_PLAIN_PORTS
    if port in allowed:
        return
    lst = "، ".join(str(x) for x in allowed)
    if tls:
        raise ValueError(
            "wss (TLS به CDN) روشن است، پس پورتِ لبه باید یکی از پورت‌های HTTPS باشد: %s — "
            "پورتِ %d قبول نیست. (یا wss را خاموش کن و پورتِ HTTP بگذار.)" % (lst, port))
    raise ValueError(
        "wss خاموش است، پس پورتِ لبه باید یکی از پورت‌های HTTP باشد: %s — "
        "پورتِ %d قبول نیست. (یا wss را روشن کن و ۴۴۳ بگذار.)" % (lst, port))


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
        ep = edge.rpartition(":")[2] if ":" in edge else ""
        if ep.isdigit():
            _edge_port_ok(int(ep), bool(out.get("ws_tls")))
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
        cfg = _fetch_ech(host, _ech_proxy_fields(d, cur, out))
        if not cfg:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد)" % host)
        out["ech"] = True
        out["ws_ech"] = cfg
    # xhttp: carry the stream over a GET(down)+POST(up) HTTP request pair instead of a
    # WebSocket upgrade, so it passes a CDN/account that blocks WebSocket. Independent of
    # wss (works over plain http too, though wss is the usual fronting choice). Single-edge
    # path only — the pool branch above returns first and builds its OWN xhttp fields, so a
    # pool's xhttp is handled there (the pool supports xhttp too, via _ws_pool_fields).
    xh = d.get("ws_xhttp") if ("ws_xhttp" in d) else cur.get("ws_xhttp")
    if bool(xh):
        out["ws_xhttp"] = True
        # Upstream style: packet-up (default, many short POSTs — most CDN-compatible) or grpc (a
        # single full-duplex request as a real gRPC call, so a CDN streams it over h2c instead of
        # buffering; needs wss).
        mode = str((d.get("ws_xhttp_mode") if "ws_xhttp_mode" in d else cur.get("ws_xhttp_mode")) or "").strip().lower()
        if mode == "grpc":
            out["ws_xhttp_mode"] = "grpc"
        else:
            # Which CDN this tunnel fronts through, for the upstream shape. Only on packet-up: the
            # ladder is what a WAF counts, and grpc does not have one. Stored as a name; _tunnel_extra
            # turns it into numbers.
            prof = str((d.get("xh_profile") if "xh_profile" in d else cur.get("xh_profile")) or "cf").strip().lower()
            if prof not in XH_PROFILES:
                raise ValueError("پروفایلِ CDN نامعتبر است")
            if prof != "cf":
                out["xh_profile"] = prof
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
            if not x:
                continue
            # The core dials each edge as a literal ip:port with no DNS step (config.go
            # validatePoolEndpoint, needPort=true): the host MUST be an IPv4 and a port is REQUIRED.
            # Reject domains/IPv6 and default a port-less IPv4 to :443 so the ip:port we store always
            # loads in the core (a domain or a bare IP passes here but fails the core config load).
            h = x.rpartition(":")[0] if ":" in x else x
            p = x.rpartition(":")[2] if ":" in x else "443"
            if not re.match(_IP4_RE, h) or not (p.isdigit() and 1 <= int(p) <= 65535):
                raise ValueError("آی‌پیِ لبهٔ نامعتبر (باید IPv4:port باشد؛ دامنه مجاز نیست — استخر مستقیم به آی‌پی وصل می‌شود): %s" % x)
            _edge_port_ok(int(p), True)   # a pool is always wss
            v = "%s:%s" % (h, p)
            if v in seen:
                continue
            seen.add(v)
            res.append(v)
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
    if len(clean_ips) < 2:
        raise ValueError("استخرِ لبه به حداقل ۲ آی‌پیِ فعال (تمیز) نیاز دارد تا بچرخد — سوخته‌ها حساب نمی‌شوند")
    if not clean_hosts:
        raise ValueError("استخر به حداقل یک دامنهٔ (SNI) تمیز نیاز دارد (سوخته‌ها کافی نیستند)")
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
    _epx_store = {}
    _epx = _ech_proxy_fields(d, cur, _epx_store) if ech_on else ""   # per-tunnel proxy for a filtered domain
    ech_map = _fetch_ech_map(clean_hosts, _epx) if ech_on else {}   # concurrent — never serialize the pool host-by-host
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
        if mode == "grpc":
            res["ws_xhttp_mode"] = "grpc"
    res.update(_sni_split_fields(d, cur))  # SNI fragmentation (the pool is always wss)
    res.update(_epx_store)                 # ech_proxy / ech_proxy_url (only present when the toggle is on)
    return res


def api_create_tunnel(d):
    d = d or {}
    with _PairLock(d.get("a_node"), d.get("b_node")):  # lock only the two nodes involved; unrelated pairs build concurrently
        return _create_tunnel_impl(d)


def _core_extra(d, cur, a_ip, b_ip, a_ips, b_ips):
    """Build the core-carrier fields for a tunnel record from request `d`, falling back to the stored
    link `cur` for any field `d` omits (so a partial edit — e.g. flux "rotate now" — never strips obfs /
    cover / gso / rotation). Pass cur={} on CREATE: every cur.get(...) is then None, so this reduces
    EXACTLY to the old create block (the sub-helpers all normalize cur to {} too, so cur=None and cur={}
    are equivalent). Returns (ce, server_side): ce is merged into `extra`; server_side is the local the
    caller uses afterwards. Raises ValueError on any invalid field (same messages as before)."""
    ce = {}
    cipher = str(d.get("cipher") or cur.get("cipher") or "auto").strip().lower()
    if cipher not in CORE_CIPHERS:
        raise ValueError("روشِ رمزنگاری نامعتبر است")
    ce["cipher"] = cipher
    if cipher != "none":   # keep the existing key when crypto stays on; make one when turning it on
        ce["psk"] = cur.get("psk") or secrets.token_hex(32)
    transport = str(d.get("transport") or cur.get("transport") or "udp").strip().lower()
    if transport not in CORE_TRANSPORTS:
        raise ValueError("حاملِ اتصال نامعتبر است")
    ce["transport"] = transport
    if transport == "raw":                     # raw-IP carrier: which protocol wraps the sealed frame
        if cipher == "none":
            raise ValueError("حاملِ raw به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        profile = str(d.get("raw_profile") or cur.get("raw_profile") or "bip").strip().lower()
        if profile not in CORE_RAW_PROFILES:
            raise ValueError("پروفایلِ raw نامعتبر است")
        ce["raw_profile"] = profile
        ce.update(_spoof_fields(d, transport, profile, cipher, cur))   # decoy / source spoofing (bip only); cur preserves omitted fields
    if transport == "dns":                     # DNS-tunnel carrier (last resort), crypto required
        ce.update(_dns_fields(d, transport, cipher, cur))
    if transport == "flux":                    # polymorphic moving-target carrier (udp|raw), crypto required
        ce.update(_flux_fields(d, transport, cipher, cur))
    if transport == "ws":                      # WebSocket carrier (CDN-frontable)
        ce.update(_ws_fields(d, transport, cur))
    ce.update(_fec_fields(d, transport, cur))    # FEC (datagram carriers only); {} elsewhere
    ce.update(_desync_fields(d, transport, cur, bool(ce.get("ws_xhttp"))))  # fake-packet desync; {} when off / not applicable
    # obfs/cover/gso fall back to the stored value when the request omits the key, so a PARTIAL edit
    # doesn't strip the anti-DPI layer, TLS cover, or throughput offload. On create cur={} makes each
    # fallback None/False — identical to reading only d.
    if (bool(d.get("obfs")) if "obfs" in d else bool(cur.get("obfs"))):   # anti-DPI needs the AEAD key
        if cipher == "none":
            raise ValueError("استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        ce["obfs"] = True
    cover = (bool(d.get("cover")) if "cover" in d else bool(cur.get("cover"))) and transport == "tcp"   # TLS cover is TCP-only
    if cover and cipher == "none":   # the REALITY-style cover carries a PSK-authenticated token — it needs the AEAD key
        raise ValueError("پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
    cover_sni = str((d["cover_sni"] if "cover_sni" in d else cur.get("cover_sni")) or "").strip()
    if cover_sni and not re.match(r"^[A-Za-z0-9.-]{1,253}$", cover_sni):
        raise ValueError("دامنهٔ نمایشی (SNI) نامعتبر است")
    if cover and not cover_sni:   # required: no imposed default SNI
        raise ValueError("برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی")
    if cover:
        ce["cover"] = True
        ce["cover_sni"] = cover_sni
    if (bool(d.get("gso")) if "gso" in d else bool(cur.get("gso"))):   # TUN segmentation offload (throughput); any transport
        ce["gso"] = True
    # IP rotation (direct transports): a full form edit sends ip_rotate + pools; a partial edit omits them,
    # so preserve the stored config. On create cur={} => the elif is dead and "ip_rotate" in d gates it
    # exactly as the old create block (which added nothing when ip_rotate was absent/false).
    if "ip_rotate" in d:
        if transport in DIRECT_TRANSPORTS and bool(d.get("ip_rotate")):
            ap = [s for s in (str(ip).strip() for ip in (d.get("a_ip_pool") or [])) if s in a_ips]
            bp = [s for s in (str(ip).strip() for ip in (d.get("b_ip_pool") or [])) if s in b_ips]
            if a_ip not in ap:
                ap = [a_ip] + ap   # the tunnel's primary IP anchors each side's pool
            if b_ip not in bp:
                bp = [b_ip] + bp
            if len(ap) >= 2 or len(bp) >= 2:   # at least one side actually has enough to rotate
                ce["ip_rotate"] = True
                ce["a_ip_pool"], ce["b_ip_pool"] = ap, bp
                ce["rotate_secs"] = max(0, min(86400, int(d.get("rotate_secs") or 0)))
                ce["auto_burn"] = bool(d.get("auto_burn"))
    elif cur.get("ip_rotate"):   # partial edit — carry the stored rotation config forward unchanged
        for _k in _ROTATION_KEYS:
            if cur.get(_k) is not None:
                ce[_k] = cur[_k]
    server_side = d.get("server_side") if d.get("server_side") in ("a", "b") else (cur.get("server_side") or "a")
    return ce, server_side


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
    pa, pb = _ping_both(A, B)
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
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
    _guard_dup_pair(A, B, a_ip, b_ip, ttype)  # reject a TRUE duplicate (same non-core type / any ipip-fou on this ip-pair)
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
        ce, server_side = _core_extra(d, {}, a_ip, b_ip, a_ips, b_ips)  # cur={} => the create form; server_side used below
        extra.update(ce)
    # Precise same-server-IP conflict: another core tunnel that binds the SAME (server ip, port, L4
    # proto). Different carrier, different port, or a raw/flux carrier (shared sockets) is allowed.
    if ttype == "core":
        _clash = _core_l4_conflict(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")))
        if _clash:
            raise ValueError(f"تونلِ core «{_clash.get('name')}» از قبل روی همین آی‌پی و پورتِ سرور هست؛ پورت یا حاملِ متفاوت انتخاب کن (حامل‌های دیگر/پورت‌های دیگر روی همین آی‌پی مجازند)")
    # A flux udp/stun tunnel DROPs inbound UDP from its peer on every rotation port, so it would
    # silently black-hole an unrelated tunnel that receives UDP from that same peer on one of them.
    # Checked for BOTH tunnel types (core and the kernel UDP carriers), in both directions.
    _fx = _flux_drop_conflict({**extra, "type": ttype, "a_node": A["id"], "b_node": B["id"],
                               "a_ip": a_ip, "b_ip": b_ip, "tunnel_id": tid, "server_side": server_side})
    if _fx:
        raise ValueError(f"با تونلِ «{_fx.get('name')}» تداخل دارد: حاملِ flux روی پورت‌های چرخشی‌اش "
                         f"({', '.join(str(x) for x in FLUX_UDP_DPORTS)}) ترافیکِ UDPِ ورودی از همان نود را "
                         f"می‌اندازد و آن تونل بی‌صدا می‌میرد؛ پورتِ دیگری برای یکی از این دو انتخاب کن")
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
        # This create OWNS `name` now (tunnel_ids recycle, so a freed name can be reused): supersede any
        # teardown still parked for it on either node so the poller's drain can never reap this live tunnel.
        _pending_remove(A["id"], name)
        _pending_remove(B["id"], name)
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
        # force = the operator accepts removing the record even if a node can't be reached now: the
        # reachable end is torn down at once, and each unreachable end's teardown is PARKED (pending_del)
        # for the poller to finish on reconnect — so no live server is left an orphan and the operator
        # is never stuck. Without force we keep the record (the original no-orphan guard).
        force = bool(d.get("force"))
        ends = [(L["a_node"], L["a_name"]), (L["b_node"], L["b_name"])]
        # NON-FORCE must be truthful: if we're going to KEEP the record (a node is unreachable) we must not
        # have already torn down the OTHER end. So pre-check reachability from the poll cache — if any end
        # is offline, keep BOTH halves untouched and offer force, instead of deleting the reachable half and
        # then reporting "link kept".
        if not force:
            off = [nm for nid, nm in ends if not _cached_ping(nid).get("ok")]
            if off:
                _refresh_cache([L["a_node"], L["b_node"]])
                return {"ok": False, "msg": "نودِ «" + "»، «".join(off) + "» در دسترس نیست — لینک دست‌نخورده نگه داشته شد؛ وقتی نود برگشت دوباره حذف کن، یا «حذفِ اجباری» را بزن"}
        errs, deferred = [], []
        for nid, nm in ends:
            n = get_node(nid)
            if not n:
                continue   # node no longer registered -> nothing to tear down on it
            if force and _cached_ping(nid).get("ok") is False:
                # the poller already knows this end is offline -> don't block on a doomed delete; park it now
                if _pending_add(nid, L["name"]):
                    deferred.append(nm)
                else:
                    errs.append(f"{nm}: صفِ حذفِ معلق نوشته نشد")
                continue
            r = node_call(n, "delete", "POST", {"name": L["name"]})
            if not r.get("ok"):
                if not force:
                    errs.append(f"{nm}: {r.get('error')}")   # cache said online but it failed (raced offline)
                elif _pending_add(nid, L["name"]):            # force: park this end's teardown for reconnect
                    deferred.append(nm)
                else:
                    errs.append(f"{nm}: صفِ حذفِ معلق نوشته نشد")   # park write failed -> keep the record, retry later
        if errs:  # non-force + a node failed/offline — KEEP the record so a later delete can finish teardown (no orphans)
            _refresh_cache([L["a_node"], L["b_node"]])
            return {"ok": False, "msg": "; ".join(errs) + " — لینک نگه داشته شد؛ وقتی نود در دسترس شد دوباره حذف کن، یا «حذفِ اجباری» را بزن"}
        with _reg_lock:  # atomic RMW; re-read so a concurrent create isn't clobbered
            save_json(LINKS_FILE, [x for x in load_links() if x["id"] != d["id"]])
        _tf_forget(L["a_node"], [L["name"]])   # drop stale traffic totals so a reused tunnel name starts fresh
        _tf_forget(L["b_node"], [L["name"]])
        _refresh_cache([L["a_node"], L["b_node"]])
        if deferred:
            return {"ok": True, "deferred": deferred,
                    "msg": "لینک حذف شد؛ پاک‌سازیِ سمتِ «" + "»، «".join(deferred) + "» وقتی نود برگشت خودکار انجام می‌شود"}
        return {"ok": True}


def api_reorder(d):
    # Manual card ordering. For nodes/core/tunnels we swap the two items' positions in the persisted
    # array (api_fleet/api_nodes iterate it in-order and paginate, so a raw swap moves the cards in every
    # browser, permanently — no extra "ord" field, no migration). Port-forwards have no central array, so
    # they use a key-order overlay instead (see _reorder_portfw). The client sends a card id and its visible
    # neighbour (up/down), which are adjacent in the shown list, so the swap is exact.
    _require(d, ["kind", "id", "target"])
    kind = d["kind"]
    aid, bid = str(d["id"]), str(d["target"])
    if aid == bid:
        return {"ok": True}
    if kind == "portfw":                   # no central array -> reorder via the key overlay (see _reorder_portfw)
        return _reorder_portfw(aid, bid)
    if kind == "nodes":
        path, loader = NODES_FILE, load_nodes
    elif kind in ("core", "tunnels"):
        path, loader = LINKS_FILE, load_links
    else:
        raise ValueError("bad kind")
    with _reg_lock:  # same RMW lock as every other nodes.json / links.json write
        items = loader()
        pos = {str(it.get("id")): i for i, it in enumerate(items)}
        if aid not in pos or bid not in pos:
            raise ValueError("item not found")
        i, jx = pos[aid], pos[bid]
        items[i], items[jx] = items[jx], items[i]
        save_json(path, items)
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
    _rot = L.get("ip_rotate") and L.get("transport") in DIRECT_TRANSPORTS
    _ap, _bp = list(L.get("a_ip_pool") or []), list(L.get("b_ip_pool") or [])
    _rs, _ab = max(0, min(86400, int(L.get("rotate_secs") or 0))), bool(L.get("auto_burn"))
    for N, self_ip, peer_ip, own, peer in ((A, L["a_ip"], L["b_ip"], _ap, _bp), (B, L["b_ip"], L["a_ip"], _bp, _ap)):
        if N:
            # `enabled` must be explicit. The rebuild path op_delete's both ends BEFORE it builds, and
            # op_delete os.remove()s the persisted config — so by the time a rollback runs there is no
            # stored value left for the node to carry forward, and its `d.get("enabled", old..., True)`
            # falls all the way through to True. A tunnel the operator had deliberately switched OFF
            # therefore came back ON after any failed edit or rebuild. All three real build paths pass
            # this key; only the rollback did not.
            body = {"type": L["type"], "self_ip": self_ip, "peer_ip": peer_ip,
                    "subnet": L["subnet"], "id": tid, "name": L["name"],
                    "enabled": L.get("enabled", True), **extra}
            role = _core_role(L, N["id"])
            if role:
                body["role"] = role
                if _rot:   # replay the stored IP-rotation pools for this node's role
                    _apply_core_rotation(body, role == "client", own, peer, _rs, _ab)
                # ...and the fleet-wide timing, exactly like the three real build paths. Without this a
                # rolled-back tunnel came back UP but with the core's compiled-in keepalive / dead-window
                # instead of the operator's, silently, on the very path where they are already reading an
                # error about something else. Both args are this one body; _apply_core_tuning stamps them
                # identically.
                _apply_core_tuning(body, body)
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
    node = _client_node(L)
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
    # status file's write time -> the UI can flag a stale file (dead tunnel) as offline.
    node_now = int(r.get("now") or 0)
    return {"ok": True, "pool": is_pool, "active": str(r.get("active") or ""),
            "health": health, "events": (r.get("events") or []), "now": node_now, "ts": int(r.get("ts") or 0)}


def _probe_now(d, resolve, endpoint):
    """Shared 'probe now': resolve the client node (ws-edge or direct pool), tell it to SIGHUP the core
    so it retests every suspect/dead entry at once. One place for the fallback error + response shape."""
    L, node = resolve(d or {})
    r = node_call(node, endpoint, "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "پروب ناموفق بود"}
    return {"ok": True}


def api_pool_probe_now(d):
    """Live 'probe now' for a ws edge pool: tell the client node to SIGHUP the running core so
    it retests every suspect/dead edge at once (no rebuild). Returns fresh status via the next poll."""
    return _probe_now(d, _ws_pool_client, "pool-probe-now")


def api_pool_select(d):
    """Live 'pin this edge': tell the client node to write a command file the running core polls
    so it jumps its rotation onto THIS specific IP/SNI (kind+key) and re-dials onto it — no
    rebuild, TUN stays up. Backs the per-edge select button."""
    d = d or {}
    _require(d, ["id", "kind", "key"])
    if d["kind"] not in ("ip", "sni"):
        raise ValueError("kind باید ip یا sni باشد")
    L, node = _ws_pool_client(d)
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


def _ws_pool_client(d):
    """Resolve (link, client node) for a ws EDGE-pool link, raising a clear error when the link isn't a
    pooled-ws core or its client node is gone. Mirror of _peer_pool_client for the ws-pool live-status ops."""
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ws_pool"):
        raise ValueError("این لینک استخرِ لبه ندارد")
    node = _client_node(L)
    if not node:
        raise ValueError("نودِ کلاینت پیدا نشد")
    return L, node


def _peer_pool_client(d):
    """Resolve (link, client node) for a direct-transport IP-rotation link, raising a clear error when
    the link isn't a pooled core or its client node is gone. Shared by the peer-pool live-status ops."""
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ip_rotate"):
        raise ValueError("این لینک استخرِ آی‌پی ندارد")
    node = _client_node(L)
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
            "health": health, "pin": pin if _peer_addr_ok(pin) else "", "ts": int(sec.get("ts") or 0)}


def api_peer_status(d):
    """Live status of a direct-transport IP-rotation link: ask the client node for BOTH pools —
    destination (the server IPs it dials) and source (this node's own egress IPs) — each with the
    active endpoint, the per-endpoint health FSM (suspect/dead + retest countdown), and any manual
    pin. `now` is the client node's clock (which stamped the retest times) so countdowns stay correct."""
    d = d or {}
    empty = {"active": "", "addrs": [], "health": [], "pin": "", "ts": 0}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ip_rotate"):
        return {"ok": True, "pool": False, "now": int(time.time()), "dst": dict(empty), "src": dict(empty)}
    node = _client_node(L)
    if not node:
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": "client node not found"}
    r = node_call(node, "peer-status", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": r.get("error") or r.get("msg")}
    node_now = int(r.get("now") or 0)
    return {"ok": True, "pool": True, "now": node_now, "dst": _peer_sec_norm(r.get("dst")), "src": _peer_sec_norm(r.get("src"))}


def api_peer_probe_now(d):
    """'Probe now' for a direct-transport pool: SIGHUP the client's core to retest every burned
    endpoint at once (re-admit it to rotation) with no rebuild. Fresh state arrives via the next poll."""
    return _probe_now(d, _peer_pool_client, "peer-probe-now")


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
    pa, pb = _ping_both(A, B)
    tid = int(L["tunnel_id"])
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
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
    _guard_dup_pair(A, B, a_ip, b_ip, ttype, exclude_id=L["id"])  # same as create, but never conflict with self
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
        ce, server_side = _core_extra(d, L, a_ip, b_ip, a_ips, b_ips)  # cur=L => stored fields fill in whatever a partial edit omits
        extra.update(ce)
    # api_create_link always stores an explicit port, so compare straight against the record.
    port_same = ("port" not in extra) or (extra["port"] == L.get("port"))
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
    # Same flux anti-leak check as create — an edit can introduce the collision either way round: by
    # switching this tunnel TO flux/udp, or by moving another one ONTO a rotation port.
    _fx = _flux_drop_conflict({**extra, "type": ttype, "a_node": A["id"], "b_node": B["id"],
                               "a_ip": a_ip, "b_ip": b_ip, "tunnel_id": tid, "server_side": server_side},
                              exclude_id=L.get("id"))
    if _fx:
        raise ValueError(f"با تونلِ «{_fx.get('name')}» تداخل دارد: حاملِ flux روی پورت‌های چرخشی‌اش "
                         f"({', '.join(str(x) for x in FLUX_UDP_DPORTS)}) ترافیکِ UDPِ ورودی از همان نود را "
                         f"می‌اندازد و آن تونل بی‌صدا می‌میرد؛ پورتِ دیگری برای یکی از این دو انتخاب کن")
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
                for k in ("port", "psk", "cipher", "transport", "obfs", "cover", "cover_sni", "raw_profile", "raw_proto", "dns_zone", "dns_resolvers", "flux_carrier", "flux_rotate_secs", "flux_shape", "flux_epoch_offset", "fec", "fec_data", "fec_parity", "ws_host", "ws_path", "ws_tls", "sni_split", "split_pos", "sni_mode", "split_ttl", "ws_xhttp", "ws_xhttp_mode", "xh_profile", "ech", "ws_ech", "ech_proxy", "ech_proxy_url", "edge_ip", "ws_pool", "ws_edge_ips", "ws_edge_ips_burned", "ws_edge_snis", "ws_edge_snis_burned", "ws_rotate_secs", "ws_auto_burn", "ws_warm_standby", "gso", "spoof_src", "spoof_dst", "fake_desync", "fake_ttl", "fake_count", "fake_mode", "dead_after_secs", "keepalive") + _ROTATION_KEYS:   # keep only the extras this type uses (incl. IP-rotation); drop the rest so an edit that turns rotation off actually clears the stored pools
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
    pa, pb = _ping_both(A, B)
    tid, ttype, subnet, name = int(L["tunnel_id"]), L["type"], L["subnet"], L["name"]
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
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
        a_ips = _flat_ips(pa)
        b_ips = _flat_ips(pb)
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
        try:
            gap = max(5, int(get_settings().get("reconcile_interval", RECONCILE_GAP) or RECONCILE_GAP))
        except Exception:
            gap = RECONCILE_GAP   # a hand-edited non-numeric reconcile_interval must not kill the reconcile thread
        time.sleep(gap)
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
_ech_healed_seq = {}       # G2: lid -> highest core self_heal event seq already persisted (ech_refresh_loop thread only)


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


def _ech_live_push(lid, chmap):
    """Push a freshly-rotated ECH key to the RUNNING client-side ws core so it hot-swaps it with NO
    rebuild (op ech-update -> the core's <status>.echcmd poll). Works for a ws edge-POOL (retestLoop
    reads it) and a SINGLE ws edge (dialLoop reads it into b.wsECH) — same sidecar. Best-effort: on any
    failure the core just keeps its old key until it self-heals in-band or the next rebuild. chmap is
    {host: base64_ech}. Returns a short label of the client node the key actually landed on (name +
    host) on a SUCCESSFUL push, else "" (skipped / node offline / core rejected) — the caller shows it
    in the refresh log so an operator sees which node got the live key."""
    if not chmap:
        return ""
    L = next((x for x in load_links() if x.get("id") == lid), None)
    if not L or L.get("type") != "core" or not (L.get("ws_pool") or L.get("ws_host")):
        return ""
    node = _client_node(L)   # the CLIENT is the non-server side (it dials the CDN with ECH)
    if not node:
        return ""
    try:
        r = node_call(node, "ech-update", "POST", {"name": L.get("name"), "snis": chmap}, timeout=8)
    except Exception:
        return ""
    if not isinstance(r, dict) or not r.get("ok"):
        return ""   # node offline or core rejected -> don't claim a push that didn't land
    nm = str(node.get("name") or "").strip()
    host = str(node.get("host") or "").strip()
    # «name • host», not «name (host)»: the pair reads as ONE value inside one labelled pill, and a
    # parenthesis wrapped around an LTR address inside an RTL line renders mirrored.
    return "%s \u2022 %s" % (nm, host) if nm and host else (nm or host or str(node.get("id") or ""))


def _ech_pool_state(lid):
    """Read the client core's live edge health once and classify it for the ECH auto-heal. Returns
    (reachable, down, stalled):
      reachable — the client node answered (a merely-offline node is not actionable; a rebuild can't help).
      down      — reachable but NO active edge: the 'ECH rotation broke the live tunnel' signal.
      stalled   — reachable WITH an active edge still coasting on an already-open connection, YET the pool
                  can no longer build a fresh edge because new establishes fail on TLS/ECH: at least one IP
                  edge is suspect/dead AND the event ring carries a recent tls-coded failure (the stale-ECH
                  cert-verify signature — cloudflare-ech.com). This is the stale-ECH-but-active-still-up
                  window: failover/rotation/reconnect are broken but the live edge hasn't died, so `down`
                  is False and nothing used to rebuild until the tunnel finally went fully down (minutes).
                  Requiring BOTH a dead edge AND a tls event keeps a normal single-edge blip from rebuilding."""
    try:
        st = api_edge_status({"id": lid})
    except Exception:
        return (False, False, False)
    reachable = bool(st.get("ok")) and not st.get("error")
    if not reachable:
        return (False, False, False)
    active = str(st.get("active") or "")
    ips = [h for h in (st.get("health") or []) if isinstance(h, dict) and h.get("kind") == "ip"]
    any_bad = any(str(h.get("state")) in ("suspect", "dead") for h in ips)
    now = int(st.get("now") or 0) or int(time.time())
    tls_recent = any(
        str(e.get("code")) == "tls" and str(e.get("kind")) in ("down", "burn")
        and (now - int(e.get("ts") or 0)) <= 900          # within the last 15 min (one refresh window)
        for e in (st.get("events") or []) if isinstance(e, dict)
    )
    stalled = bool(active) and any_bad and tls_recent
    return (True, not active, stalled)


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
    links = load_links()
    # Prune ECH bookkeeping for links that no longer exist. A deleted link is never iterated again, so
    # its residue in _ech_empty (keyed by (lid,host)) and _ech_down_rebuilt (lids) would otherwise stay
    # forever and grow without bound under create/delete churn. Sweep against the live id set, exactly
    # like every other churned map in this file (_reconcile_last, _tomb, _uh, _install_jobs, ...).
    live_ids = {L.get("id") for L in links}
    with _ech_empty_lock:
        for k in [k for k in _ech_empty if k[0] not in live_ids]:
            _ech_empty.pop(k, None)
    _ech_down_rebuilt.intersection_update(live_ids)   # single-threaded (ech_refresh_loop only) — no lock needed
    for L in links:
        hk = _ech_link_hosts(L)
        if not hk:
            continue
        kind, hosts = hk
        lid, nm = L.get("id"), L.get("name")
        ech_map = _fetch_ech_map(hosts, _ech_px(L))   # concurrent DNS fetch (per-tunnel proxy if set) — NO lock held here
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
                    log_event("warn", "ech", f"دلیل: حذفِ رکوردِ ECH تونلِ «{nm}»", "به wss ساده تنزل یافت و بازسازی شد")
                else:
                    log_event("bad", "ech", f"دلیل: حذفِ رکوردِ ECH تونلِ «{nm}»", "تنزل به wss ساده شد ولی بازسازی شکست خورد — تونل هنوز قطع است")
            continue
        changed, chmap = _ech_write(lid, kind, updates, degrade=False)   # freshen the stored key (keeps restarts/rebuilds valid)
        if changed and chmap:
            # LIVE-push the fresh key to the RUNNING ws core (pool OR single edge) so it hot-swaps it with
            # NO rebuild — the core then stays a step ahead of Cloudflare's key rotation and never hits a
            # stale-key rejection (the freshen alone only helped the NEXT rebuild/restart, not the live core).
            pushed = _ech_live_push(lid, chmap) if kind in ("pool", "single") else ""
            # Boxes per host (domain + fresh base64 key), then — when the push actually landed — the node.
            dfa = "\n".join("دامنه: %s\nکلیدِ ECH: %s" % (h, k) for h, k in chmap.items())
            if pushed:
                dfa += "\nنودِ مقصد: %s" % pushed
                fa = "کلیدِ ECHِ تونلِ «%s» تازه شد و زنده به هسته push شد (هر %s دقیقه)" % (nm, _mins_label)
            else:
                fa = "کلیدِ ECHِ تونلِ «%s» با تایمرِ زمان‌بندی‌شده تازه شد (هر %s دقیقه)" % (nm, _mins_label)
            log_event("ok", "ech", fa, dfa)
        # Down-detection needs a live status file, which only a pool writes; a single edge is left to
        # Layer 1 (the core's in-band retry) + the freshened stored key. For a pool, rebuild one we can
        # SEE is down — LEVEL-triggered on the down state, NOT gated on the key changing THIS cycle (that
        # gating is what let a persistently-down pool sit dark: the record is freshened once, then never
        # changes again). Rebuild once per down-episode, and again if the key rotates while still down;
        # reset the episode when the pool recovers.
        # Rebuild when the pool is DOWN (no active edge) OR STALLED: an active edge is still coasting
        # on an already-open connection while every IP edge is suspect/dead, so new establishes all fail
        # on the stale ECH key (cloudflare-ech.com cert) and failover/rotation/reconnect are broken —
        # but the live edge hasn't died yet, so the old `_link_is_down` check never fired and the tunnel
        # sat un-rotatable for minutes until it finally went fully down. Catching `stalled` heals it as
        # soon as the pool can no longer build a fresh edge, not minutes later.
        reachable, down, stalled = _ech_pool_state(lid) if kind == "pool" else (False, False, False)
        if kind == "pool" and (down or stalled):
            if lid not in _ech_down_rebuilt or changed:   # the live core didn't self-heal in-band -> rebuild with the fresh key
                _ech_down_rebuilt.add(lid)
                why_fa = "قطع بود" if down else "همهٔ لبه‌هایش سرِ ECH می‌سوختند"
                if _ech_safe_rebuild(lid):   # log the ACTUAL outcome; a failed rebuild must not read as success
                    log_event("ok", "ech", f"دلیل: چرخشِ کلیدِ ECH تونلِ «{nm}»", f"{why_fa}؛ با کلیدِ تازه بازسازی شد")
                else:
                    log_event("bad", "ech", f"دلیل: چرخشِ کلیدِ ECH تونلِ «{nm}»", f"{why_fa}؛ بازسازی با کلیدِ تازه شکست خورد — تونل هنوز قطع است")
                    _ech_down_rebuilt.discard(lid)   # let the NEXT cycle retry (don't burn the episode on a failed rebuild)
        else:
            _ech_down_rebuilt.discard(lid)   # healthy pool / single edge / not down -> clear the episode (a future drop rebuilds again)


def _ech_heal_once():
    """Fast lane: rebuild any ECH POOL that is DOWN or STALLED, on a ~1-minute cadence, so a
    stale-ECH tunnel heals in ~1 min instead of waiting up to a full ech_refresh interval (the delay
    the operator hit: the tunnel sat un-rotatable for minutes while the slow timer had not ticked).
    Only a BROKEN pool does a (targeted) DoH fetch + rebuild — healthy pools cost nothing and DoH load
    stays negligible. Shares _ech_down_rebuilt with _ech_refresh_once; both run on the SAME thread
    (ech_refresh_loop), so the episode set stays single-threaded — no lock needed."""
    for L in load_links():
        hk = _ech_link_hosts(L)
        if not hk or hk[0] != "pool":   # pools only — single-edge ECH has no failover to auto-rebuild
            continue
        kind, hosts = hk
        lid, nm = L.get("id"), L.get("name")
        _reachable, down, stalled = _ech_pool_state(lid)
        if not (down or stalled):
            _ech_down_rebuilt.discard(lid)   # healthy / recovered -> clear the episode (a future drop rebuilds again)
            continue
        if lid in _ech_down_rebuilt:
            continue   # already rebuilt this episode; the slow loop re-arms on a genuine key rotation
        updates = {h: k for h, k in _fetch_ech_map(hosts, _ech_px(L)).items() if k}   # targeted DoH (per-tunnel proxy if set) for THIS broken pool only
        _ech_write(lid, kind, updates, degrade=False)                     # freshen the stored key (no-op if DoH empty)
        _ech_down_rebuilt.add(lid)
        why_fa = "قطع بود" if down else "همهٔ لبه‌هایش سرِ ECH می‌سوختند"
        if _ech_safe_rebuild(lid):
            log_event("ok", "ech", f"دلیل: بازسازیِ سریعِ ECH تونلِ «{nm}»", f"{why_fa}")
        else:
            log_event("bad", "ech", f"دلیل: بازسازیِ سریعِ ECH تونلِ «{nm}»", f"{why_fa}؛ شکست خورد — تونل هنوز قطع است")
            _ech_down_rebuilt.discard(lid)   # let the next tick retry (don't burn the episode on a failed rebuild)


def _ech_ingest_selfheal():
    """G2 — persist the core's IN-BAND ECH self-heal (G1) back into the panel's stored config. When the
    core harvests a fresh key from a handshake reject it hot-swaps the key AND emits an
    ("ech","self_heal","<host> <base64>") event. Here we read that event ring and write the fresh key
    into the stored record, so a later rebuild/restart no longer regresses to the panel's stale key
    (the exact gap: G1 fixes the live core, but the panel's stored key stayed old and every rebuild
    re-injected it). Direction is the mirror of _ech_live_push: core -> panel, not panel -> core.

    Each self_heal is ingested exactly once, keyed by its monotonic event seq, so a heal that already
    landed can never be re-applied over a newer key sitting in the ring; the write itself is
    transition-gated by _ech_write. Runs on the ech_refresh_loop thread (~1 min), so _ech_healed_seq
    needs no lock. Applies to pools and single edges alike (both self-heal via the core's uEdgeHandshake)."""
    live_ids = set()
    for L in load_links():
        hk = _ech_link_hosts(L)
        if not hk:
            continue
        kind, hosts = hk
        lid, nm = L.get("id"), L.get("name")
        live_ids.add(lid)
        try:
            st = api_edge_status({"id": lid})
        except Exception:
            continue
        if not st.get("ok") or st.get("error"):
            continue
        hostset = set(hosts)
        seen_max = _ech_healed_seq.get(lid, 0)
        new_max = seen_max
        latest = {}   # host -> (seq, base64): newest not-yet-persisted self-heal per host (robust to ring order)
        for e in (st.get("events") or []):
            if not isinstance(e, dict) or str(e.get("kind")) != "ech" or str(e.get("code")) != "self_heal":
                continue
            try:
                seq = int(e.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if seq <= seen_max:
                continue   # already persisted this heal (or older) — never regress on a stale ring entry
            if seq > new_max:
                new_max = seq
            parts = str(e.get("detail") or "").split(" ", 1)
            if len(parts) != 2:
                continue
            host, b64 = parts[0], parts[1].strip()
            if host in hostset and b64 and len(b64) <= 4096 and re.match(r"^[A-Za-z0-9+/=]+$", b64):
                if host not in latest or seq >= latest[host][0]:
                    latest[host] = (seq, b64)
        _ech_healed_seq[lid] = new_max
        if not latest:
            continue
        changed, chmap = _ech_write(lid, kind, {h: v[1] for h, v in latest.items()}, degrade=False)
        if changed and chmap:
            dfa = "\n".join("دامنه: %s\nکلیدِ ECH: %s" % (h, k) for h, k in chmap.items())
            log_event("ok", "ech",
                      "کلیدِ ECHِ خودترمیمِ هستهٔ تونلِ «%s» در پنل ذخیره شد؛ rebuild دیگر به کلیدِ کهنه برنمی‌گردد" % nm,
                      dfa)
    for dead in [k for k in _ech_healed_seq if k not in live_ids]:
        _ech_healed_seq.pop(dead, None)   # drop bookkeeping for deleted/disabled links


def ech_refresh_loop():
    last_full = 0.0
    while True:
        time.sleep(60.0)   # wake every minute: the fast heal lane runs each tick, the DoH sweep every `mins`
        try:
            mins = float(get_settings().get("ech_refresh_mins", 15) or 0)
        except Exception:
            mins = 15.0
        # Resilience lanes run EVERY tick regardless of ech_refresh_mins — they are recovery, not the
        # proactive refresh cadence, so disabling the timer must not silently disable them (else a
        # self-heal never persists and a rebuild regresses to the stale key; a down pool never recovers).
        try:
            _ech_heal_once()   # backstop: rebuild a down/stalled pool with a fresh key (~1 min latency)
        except Exception:
            pass
        try:
            _ech_ingest_selfheal()   # G2: persist the core's in-band self-heal back to the stored config
        except Exception:
            pass
        if mins <= 0:
            continue   # only the PROACTIVE DoH refresh (below) honors the timer; 0 disables just that
        now = time.time()
        if (now - last_full) >= max(60.0, mins * 60.0):
            last_full = now
            try:
                _ech_refresh_once()   # slow: DoH-refresh every host's key on the scheduled interval
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
_ev_count = None  # lazy-loaded current (capped) event count, mirrored in memory so api_summary needn't re-parse events.json
_ev_state = {"init": False, "nodes": {}, "links": {}, "edge": {}, "evseq": {}, "rotip": {}, "links_coarse_down": set()}  # last-seen state (in-memory); rotip[lid:axis]=last source/dest IP, for from→to on a rotation


def _ev_ip(detail):
    """Pull an IPv4[:port] out of a core event's free-form detail (e.g. 'ip:1.2.3.4:443'). Empty if none —
    then the rotation event renders exactly as before (no box), so a non-IP detail can never mislabel."""
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", str(detail or ""))
    return m.group(0) if m else ""
_ev_suppress = {}  # link_id -> unix ts until which an edge auto-change is suppressed (operator pin)

# Map the CORE's stable reason codes (it saw the real error) to bilingual text for the log. This is
# the precise, core-level "why" the operator asked for — not the panel's coarse guess.
_EV_DOWN_CODE = {
    "ping_timeout": "بی‌پاسخ ماند (keepalive) — گلوگاه/بلاک‌هول یا سرِ مقابل خاموش",
    "reset": "اتصال ریست شد (RST — احتمالاً کشتنِ DPI)",
    "refused": "اتصال رد شد (connection refused)",
    "timeout": "مهلتِ اتصال تمام شد / بی‌مسیر",
    "eof": "اتصال بسته شد (EOF)",
    "tls": "دستِ TLS شکست خورد (احتمالاً SNI بلاک شده)",
    "ws_upgrade": "ارتقاءِ WebSocket رد شد (Origin/CDN)",
    "closed": "اتصال قطع شد",
    "dropped": "اتصال قطع شد",
    # datagram transports (udp/raw/flux) — connectionless self-heal reasons
    "stale": "سشن کهنه شد (سرِ مقابل خاموش/ری‌استارت؟) — در حالِ دست‌دادنِ مجدد",
}
_EV_UP_CODE = {
    "reconnect": "پس از افتِ سشن، خودکار وصل شد (self-heal)",
}
_EV_BURN_CODE = {
    "ip_blocked": "آی‌پیِ لبه بلاک است (روی SNIِ سالم هم جواب نداد)",
    "sni_blocked": "دامنه (SNI) بلاک است (روی آی‌پیِ سالم هم جواب نداد)",
    "throttle": "آی‌پیِ لبه گلوگاه/کند شد (دست داد ولی دیتا مرد)",
}
# Intentional IP MOVES on a datagram rotation pool (udp/raw/flux — tcp is connection-oriented and re-dials
# instead of emitting these). The core reports these as a
# "down" because they cause a brief re-handshake, but they are NOT faults — a proactive/failover rotation
# or an operator pin. Render them as informational (ok) events, not a red "disconnected". (level, fa)
_EV_ROT_CODE = {
    "peer-rotate": ("ok", "چرخش آی‌پیِ مقصد"),
    "src-rotate":  ("ok", "چرخش آی‌پیِ مبدأ"),
}


def _ev_core_text(kind, code, detail, nm):
    """Render a core event into (level, kind, title, detail) for log_event(*...).
    Splitting title from detail lets the UI show the reason on its own line."""
    key = str(detail or "")
    if key.startswith("ip:"):
        key = key[3:]
    elif key.startswith("sni:"):
        key = key[4:]
    if kind == "down":
        rot = _EV_ROT_CODE.get(code)
        if rot:   # an intentional rotation/pin, not a fault — informational, not a red "disconnected"
            lvl, fa = rot
            return (lvl, "rot", f"تونلِ «{nm}»: {fa}", "")
        rf = _EV_DOWN_CODE.get(code, "اتصال قطع شد")
        return ("bad", "link", f"دلیل: قطعِ تونلِ «{nm}»", rf)
    if kind == "up":
        rf = _EV_UP_CODE.get(code, "تونل وصل شد")
        return ("ok", "link", f"دلیل: وصلِ مجددِ تونلِ «{nm}»", rf)
    if kind == "burn":
        rf = _EV_BURN_CODE.get(code, "سوخته شد")
        # The reason string ("آی‌پیِ لبه بلاک است…") repeated what the title already says, so the card
        # carried two sentences for one fact. The endpoint is the useful part; keep only that.
        return ("warn", "edge", f"دلیل: سوختنِ لبه تونلِ «{nm}»", f"لبه: {key}")
    if kind == "heal":
        # A previously-sidelined member recovered and is back in the rotation pool. Three flavors:
        # peer-retest/src-retest are the DIRECT-transport pool's destination/source IP recovering on the
        # data plane; the default (ws edge pool) is a background probe recovery. Distinct from the
        # active-carrier up/reconnect above.
        if code == "peer-retest":
            return ("ok", "edge", f"دلیل: بازگشتِ آی‌پیِ مقصد تونلِ «{nm}»",
                    f"آی‌پی: {key}\nداده روی این آی‌پی دوباره برقرار شد")
        if code == "src-retest":
            return ("ok", "edge", f"دلیل: بازگشتِ آی‌پیِ مبدأ تونلِ «{nm}»",
                    f"آی‌پی: {key}\nداده روی این آی‌پی دوباره برقرار شد")
        return ("ok", "edge", f"دلیل: بازگشتِ لبه تونلِ «{nm}»",
                "بازآزماییِ پس‌زمینه موفق شد")
    if kind == "pool":
        # The edge pool crossed the "can it still rotate its IP axis?" line: rotation needs >=2 healthy
        # IPs, so when only one is left the tunnel keeps working but STOPS switching edges (which is why
        # the rotation log goes quiet). detail is "healthy/total". Surface the pause and its recovery.
        if code == "degraded":
            return ("warn", "edge", f"دلیل: توقفِ چرخش تونلِ «{nm}» — فقط یک لبهٔ سالم مانده",
                    "تا وقتی لبهٔ دیگری سالم نشود، روی همان یک لبه می‌ماند")
        if code == "pin_dropped":
            # The operator pinned an edge that turned out to be genuinely blocked. Rather than hold the
            # tunnel down for the whole pin window, the pin self-released and rotation moved to a healthy
            # edge. Explains "I pinned it, the tunnel dropped, and it jumped back to the old edge".
            return ("warn", "edge", f"دلیل: آزادشدنِ پینِ تونلِ «{nm}» — آن لبه مسدود بود",
                    "لبهٔ پین‌شده واقعاً مسدود بود؛ برای جلوگیری از قطعی، چرخش به لبهٔ سالم برگشت")
        return ("ok", "edge", f"دلیل: ازسرگیریِ چرخش تونلِ «{nm}»",
                "لبهٔ دیگری سالم شد و به استخر برگشت")
    if kind == "ech":
        # REACTIVE in-band self-heal reported by the core (Layer 1): the live handshake hit a stale ECH
        # key and healed inline. Tagged distinctly from the panel's SCHEDULED ech_refresh timer (below),
        # so the operator can tell the two apart. detail is "<host> <fresh base64 ECHConfigList>" — split
        # it so the (long) key lands in its OWN labeled box instead of being dumped inline in the message.
        host, _, k = key.partition(" ")
        dfa = ("دامنه: %s\n" % host if host else "") + ("کلیدِ تازهٔ ECH: %s" % k if k else "")
        return ("ok", "ech", f"دلیل: ترمیمِ خودکارِ کلیدِ ECH تونلِ «{nm}»", dfa)
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
    correct forever. Starts at zero when the seq file is missing (fresh install)."""
    global _ev_seq_total
    if _ev_seq_total is None:
        try:
            with open(EVENTS_SEQ_FILE) as f:
                _ev_seq_total = int(json.load(f))
        except (OSError, ValueError, TypeError):
            _ev_seq_total = 0
    return _ev_seq_total


def _ev_count_get():
    """Current (capped) number of stored events, kept in memory so the hot api_summary poll doesn't
    re-parse events.json every call. Seeded once from the file, then maintained by log_event and
    api_events_clear — the only writers, both under _events_lock."""
    global _ev_count
    if _ev_count is None:
        _ev_count = len(load_events())
    return _ev_count


def log_event(level, kind, fa, dfa=""):
    """Append one system event (newest first), capped at EVENTS_CAP. level: ok|warn|bad.
    fa is the one-line TITLE; dfa is an optional detail/reason that may contain "\\n" for
    multiple lines (e.g. an edge switch's from/to) — the UI renders each line separately."""
    global _ev_seq_total, _ev_count
    with _events_lock:
        evs = load_events()
        evs.insert(0, {"ts": int(time.time()), "level": level, "kind": kind,
                       "fa": fa, "dfa": dfa})
        if len(evs) > EVENTS_CAP:
            evs = evs[:EVENTS_CAP]
        _ev_count = len(evs)   # keep the in-memory count in step with the file (read lock-free by api_summary)
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
    if not (isinstance(ah, dict) and ah.get("up") and isinstance(bh, dict) and bh.get("up")):
        return False
    # a confirmed-dead core tunnel (frozen client heartbeat) is NOT up even though both ifaces still exist
    return not (ah.get("dead") or bh.get("dead"))


def _link_down_reason(L, nmap):
    """Best-effort classification of WHY a tunnel went down, from signals the panel already has."""
    for key in ("a_node", "b_node"):
        nid = L.get(key)
        if _cache_get(nid) and not _node_online(nid):
            nm = nmap.get(nid, nid)
            return f"نودِ «{nm}» آفلاین است"
    if link_drift(L["id"]):
        return "IP عوض شده — نیازمندِ بازسازی"
    if L.get("type") == "core" and L.get("ws_pool"):
        try:
            r = api_edge_status({"id": L["id"]})
            h = (r or {}).get("health") or []
            if r and r.get("pool") and h and not any(e.get("state") == "healthy" for e in h):
                return "همهٔ لبه‌های استخر بلاک/سوخته‌اند"
        except Exception:
            pass
    return "قابلِ دسترسی نیست (کریر/سرِ مقابل)"


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
            log_event("ok", "node", f"دلیل: آنلاین‌شدنِ نودِ «{nm}»")
        else:
            log_event("bad", "node", f"دلیل: آفلاین‌شدنِ نودِ «{nm}»")
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
        # A core that writes a status ring records its OWN precise down/up — a ws pool, a datagram
        # transport (udp/raw/flux), a direct tcp/cover client (hb + rotation/self-heal ring), or a
        # single-edge ws/xhttp. For ALL of those, don't ALSO emit a coarse event here or every
        # drop is double-counted (the datagram core's "stale"/"keepalive" down renders as a
        # red "disconnected" in the precise section too). A core with no status ring at all (e.g. a
        # client node offline so the core is dead) relies on the coarse classification below.
        precise_core = L.get("type") == "core" and (
            bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in STATUSRING_TRANSPORTS)
        if up:
            # The precise reconnect ("up") comes from the core event ring — UNLESS this link's down was
            # itself coarse (a client node was offline, so the core was dead and logged nothing); then
            # pair it coarsely too.
            if precise_core and lid not in _ev_state["links_coarse_down"]:
                pass  # the paired "up" comes from the core event ring
            else:
                log_event("ok", "link", f"دلیل: وصلِ تونلِ «{nm}»")
            _ev_state["links_coarse_down"].discard(lid)
        else:
            # The core records the PRECISE down reason itself (see the edge section) — don't also emit a
            # coarse one, unless a client node is offline (the core is dead then and can't report).
            a_off = _cache_get(L.get("a_node")) and not _node_online(L.get("a_node"))
            b_off = _cache_get(L.get("b_node")) and not _node_online(L.get("b_node"))
            if precise_core and not (a_off or b_off):
                pass  # core-sourced precise "down" (and its paired "up") come from the event ring
            else:
                rf = _link_down_reason(L, nmap)
                log_event("bad", "link", f"دلیل: قطعِ تونلِ «{nm}»", rf)
                if precise_core:
                    _ev_state["links_coarse_down"].add(lid)  # coarse (node-offline) down -> pair with a coarse up
    for lid in [k for k in _ev_state["links"] if k not in seen]:
        _ev_state["links"].pop(lid, None)
        _ev_state["links_coarse_down"].discard(lid)

    # --- core tunnels: PRECISE core-recorded events (down reason + burns for a ws pool;
    #     self-heal/reconnect reasons for a udp/raw/flux datagram client; src/peer-rotate + burn/heal for
    #     a direct tcp/cover client; in-band ECH self-heal for a single-edge ws/xhttp client) and — for a
    #     pool — the automatic edge-IP change. The core saw the real error; the panel just renders it.
    #     Any direct-transport (udp/tcp/raw/flux) client or ws pool / single-edge ws/xhttp writes one. ---
    seen = set()
    now = int(time.time())
    # Prefetch every status-ring core tunnel's edge-status IN PARALLEL first. api_edge_status is a live
    # per-node RPC (10s timeout), so doing it serially in the loop below made the whole sweep cost the SUM
    # of one call per tunnel — a handful of slow/offline clients could stall event detection for the entire
    # fleet. The per-link PROCESSING stays sequential and in `links` order below (event ordering, `now`, and
    # the _ev_state mutations must remain single-threaded); only the network fetch is fanned out here.
    todo = [L for L in links if L.get("type") == "core" and L.get("enabled", True)
            and (bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in STATUSRING_TRANSPORTS)]

    def _es(L):
        try:
            return api_edge_status({"id": L["id"]})
        except Exception:
            return None
    pre = dict(zip((L["id"] for L in todo), parallel_map(_es, todo)))
    for L in links:
        if L.get("type") != "core" or not L.get("enabled", True):
            continue
        is_pool = bool(L.get("ws_pool"))
        tr = str(L.get("transport") or "").lower()
        if not is_pool and tr not in STATUSRING_TRANSPORTS:
            continue  # no core status file -> nothing precise to read (direct udp/tcp/raw/flux + single-edge ws all write one)
        lid = L["id"]
        seen.add(lid)
        nm = L.get("name", "")
        r = pre.get(lid)   # prefetched in parallel above; per-link processing below stays sequential + ordered
        if not r:
            continue

        # core event ring (down/up/burn) — consume each exactly once by seq; seed silently on first pass.
        # A single MALFORMED event from one node (a non-dict entry, or a non-numeric seq) must never throw
        # out of this loop: that would kill _events_once and stop event logging for the WHOLE fleet (and,
        # on the first pass, prevent init from ever being set). So coerce seq defensively, and wrap the
        # whole per-link body so one bad link is isolated and skipped, not fatal for every other link.
        try:
            raw_evs = r.get("events")
            clean = []
            if isinstance(raw_evs, list):
                for e in raw_evs:
                    if not isinstance(e, dict):
                        continue
                    try:
                        sq = int(e.get("seq") or 0)
                    except (TypeError, ValueError):
                        continue  # a node that emits a non-numeric seq must not break ingestion
                    clean.append((sq, e))
            mx = max([0] + [sq for sq, _ in clean])
            if first:
                _ev_state["evseq"][lid] = mx
            else:
                last = _ev_state["evseq"].get(lid, 0)
                # The core's event seq restarts at 0 on every (re)start (rebuild / auto-reconcile / core
                # update / crash). Once mx has fallen BELOW our high-water, the core restarted: the stale
                # high-water would then skip every post-restart event forever (rotations stop logging). Re-
                # baseline from 0 so the fresh ring's events are logged again.
                if mx < last:
                    last = 0
                for sq, e in sorted(clean, key=lambda x: x[0]):
                    if sq <= last:
                        continue
                    ekind, ecode, edet = str(e.get("kind") or ""), str(e.get("code") or ""), str(e.get("detail") or "")
                    if ekind == "down" and ecode in _EV_ROT_CODE:
                        # source/dest IP rotation: show old→new IPs in boxes (like the edge switch), tracking
                        # the previous IP per link+axis. Falls back to no-detail when the core sends no IP.
                        ip = _ev_ip(edet)
                        axis = "src" if "src" in ecode else "dst"
                        rk = lid + ":" + axis
                        prev = _ev_state["rotip"].get(rk)
                        if ip:
                            _ev_state["rotip"][rk] = ip
                        lvl, fa = _EV_ROT_CODE[ecode]
                        if ip and prev and prev != ip:
                            dfa = f"از: {prev}\nبه: {ip}"
                        elif ip:
                            dfa = f"به: {ip}"
                        else:
                            dfa = ""
                        log_event(lvl, "rot", f"دلیل: {fa} تونلِ «{nm}»", dfa)
                        continue
                    txt = _ev_core_text(ekind, ecode, edet, nm)
                    if txt:
                        log_event(*txt)
                _ev_state["evseq"][lid] = max(last, mx)

            if is_pool:
                # automatic active-edge switch (suppressed briefly after an operator pin)
                active = str(r.get("active") or "")
                prev = _ev_state["edge"].get(lid)
                _ev_state["edge"][lid] = active
                if not (first or prev is None or prev == active or not active) and _ev_suppress.get(lid, 0) <= now:
                    log_event("warn", "edge", f"دلیل: چرخش لبه تونلِ «{nm}»", f"از: {prev}\nبه: {active}")
        except Exception:
            continue  # one bad link's data must not skip the WHOLE sweep (and stall init) — isolate + move on
    for lid in [k for k in _ev_state["edge"] if k not in seen]:
        _ev_state["edge"].pop(lid, None)
    for lid in [k for k in _ev_state["evseq"] if k not in seen]:
        _ev_state["evseq"].pop(lid, None)
    for rk in [k for k in _ev_state["rotip"] if k.rsplit(":", 1)[0] not in seen]:
        _ev_state["rotip"].pop(rk, None)

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
    global _ev_count
    with _events_lock:
        try:
            save_json(EVENTS_FILE, [])
        except OSError:
            pass
        _ev_count = 0
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


def _pf_push(n, endpoint, body, timeout=120, ret="name"):
    """Push a port-forward op to node n and normalize the reply: raise its Persian/error text on failure,
    refresh n's cache, and return {ok, <ret>: r[ret]}. Shared by portfw / portfw-edit / portfw-next
    (portfw-del is intentionally NOT routed here — it doesn't raise on !ok and also drops its byte
    counters)."""
    r = node_call(n, endpoint, "POST", body, timeout=timeout)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    _refresh_cache([n["id"]])
    return {"ok": True, ret: r.get(ret)}


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
    return _pf_push(n, "portfw", body)


# Port-forwards have no central array — they live in each node's core configs and are aggregated from the
# RAM cache, so their order is node-order × config-order. To let the operator reorder the cards persistently
# we keep a thin overlay: an ordered list of stable keys (node_id + name; node_id is a fixed-width token_hex
# so the concatenation is collision-free). Empty overlay = natural order = unchanged behaviour, so no migration.
def _pf_key(node_id, name):
    return str(node_id) + str(name)


def _pf_load_order():
    try:
        o = json.load(open(PORTFW_ORDER_FILE))
        return o if isinstance(o, list) else []
    except Exception:
        return []


def _pf_sorted(seq, key_of):
    # stable: overlay-ranked items first in overlay order, everything else keeps its natural order
    order = _pf_load_order()
    rank = {k: i for i, k in enumerate(order)}
    big = len(order)
    return [x for _, x in sorted(enumerate(seq), key=lambda p: (rank.get(key_of(p[1]), big), p[0]))]


def _pf_natural_keys():
    keys = []
    for n in load_nodes():
        r = _cached_list(n["id"])
        if r.get("configs") is None:
            continue
        for c in r["configs"]:
            if c.get("type") == "portfw" and c.get("name"):
                keys.append(_pf_key(n["id"], c.get("name")))
    return keys


def _reorder_portfw(a, b):
    natural = _pf_natural_keys()          # RAM-cache read; do it BEFORE taking _reg_lock (no lock nesting)
    with _reg_lock:
        cur = _pf_sorted(natural, lambda k: k)   # current full order = natural set under the existing overlay
        if a not in cur or b not in cur:
            raise ValueError("item not found")
        ia, ib = cur.index(a), cur.index(b)
        cur[ia], cur[ib] = cur[ib], cur[ia]
        save_json(PORTFW_ORDER_FILE, cur)         # persist the whole order so later swaps are always well-defined
    return {"ok": True}


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
    all_pf = _pf_sorted(all_pf, lambda it: _pf_key(it["node_id"], it["name"]))  # apply the operator's manual order
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
    return _pf_push(n, "portfw-edit", body)


def api_portfw_next(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("node not found")
    return _pf_push(n, "portfw-next", {"name": _pf_name(d["name"])}, timeout=60, ret="active")


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


def _ping_both(A, B):
    """Ping both endpoints of a link; raise the Persian "<node> offline" error for whichever is down.
    Returns (pa, pb) — the raw ping replies the caller flattens with _flat_ips. Shared by
    create/edit/rebuild."""
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"نودِ «{A['name']}» آفلاین است")
    if not pb.get("ok"):
        raise ValueError(f"نودِ «{B['name']}» آفلاین است")
    return pa, pb


def _guard_dup_pair(A, B, a_ip, b_ip, ttype, exclude_id=None):
    """Reject a TRUE duplicate tunnel: the same NON-core type on the same ip-pair, or any ipip/fou sharing
    an ip-pair. `exclude_id` skips one link so an edit never conflicts with itself. A multi-ip pair may
    legitimately host several tunnels on different ips; core is carrier-multiplexed (checked precisely by
    the per-carrier/port logic elsewhere), so it is not blocked here by ip-pair alone. Shared create/edit."""
    new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])
    for L in load_links():
        if exclude_id is not None and L.get("id") == exclude_id:
            continue
        same_pair = frozenset([(L.get("a_node"), L.get("a_ip")), (L.get("b_node"), L.get("b_ip"))]) == new_pair
        if L.get("type") == ttype and same_pair and ttype != "core":
            raise ValueError(f"یک تونلِ {ttype} با همین آی‌پی‌ها بینِ این دو نود از قبل هست")
        if ttype in IPIP_FAMILY and L.get("type") in IPIP_FAMILY and same_pair:  # ipip/fou can't share an ip-pair
            raise ValueError(f"تونلِ «{L.get('name')}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.")


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
    "node-add": api_node_add, "node-edit": api_node_edit, "node-del": api_node_del, "node-toggle": api_node_toggle,
    "node-install": api_node_install, "install-status": api_node_install_status,
    "node-test": api_node_test, "node-stats": api_node_stats, "node-kernel-tune": api_node_kernel_tune,
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
    "core-versions": api_core_versions, "core-check": api_core_check, "core-update": api_core_update,
    "core-upload": api_core_upload, "core-stage": api_core_stage, "core-push": api_core_push,
    "reorder": api_reorder,
}
MUTATIONS = {"node-add", "node-install", "node-edit", "node-del", "node-toggle", "node-kernel-tune", "create-tunnel", "edit-link", "rebuild-link",
             "delete-link", "link-toggle", "flux-rotate", "edge-status", "pool-probe-now", "pool-select",
             "peer-status", "peer-probe-now", "peer-select",
             "link-view", "traffic-reset", "events-clear", "portfw", "portfw-edit", "portfw-next", "portfw-del",
             "agent-upload", "agent-push", "agent-fetch-git", "settings-set", "core-check", "core-update", "core-upload", "core-stage", "core-push",
             "reorder"}

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
var L2={fa:{brand:"کنترل فلیت",sub:"برای ورود، نام کاربری و رمز را وارد کنید",user:"نام کاربری",pass:"رمز عبور",go:"ورود",fail:"ورود ناموفق",title:"ورود · tnl"}};
var LG='fa';
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
.card.rdrag{z-index:60;overflow:visible;cursor:grabbing;box-shadow:0 20px 44px -14px rgba(20,40,90,.5);border-color:color-mix(in srgb,var(--acc) 45%,transparent);opacity:.98;transition:none}
body.rdragging{cursor:grabbing;-webkit-user-select:none;user-select:none}
body.rdragging .card:not(.rdrag){transition:transform .12s ease}
/* explicit reorder mode: a grip appears on each card and ONLY the grip drags (touch-action:none), so
   normal tap / scroll / text-copy keep working everywhere else. Toggled from the toolbar button. */
.rgrip{display:none}
body.reord-on .rgrip{display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:27px;height:27px;border-radius:8px;color:var(--acc);background:color-mix(in srgb,var(--acc) 13%,transparent);cursor:grab;touch-action:none;-webkit-user-select:none;user-select:none;margin-inline-end:2px}
body.reord-on.rdragging .rgrip{cursor:grabbing}
body.reord-on .card[data-rid]{border-color:color-mix(in srgb,var(--acc) 32%,transparent)}
.reordbtn{flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--sub);cursor:pointer;padding:0}
.reordbtn svg{width:19px;height:19px}
body.reord-on .reordbtn{background:var(--acc);color:#fff;border-color:transparent}
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
.ctag.vxlan{color:var(--acc);background:color-mix(in srgb,var(--acc) 13%,transparent)}
.ctag.gre{color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent)}
.ctag.sit{color:var(--gold);background:color-mix(in srgb,var(--gold) 15%,transparent)}
.ctag.ipip{color:#14b8a6;background:color-mix(in srgb,#14b8a6 14%,transparent)}
.ctag.l2tpv3{color:#8b5cf6;background:color-mix(in srgb,#8b5cf6 14%,transparent)}
.ctag.fou{color:#ec4899;background:color-mix(in srgb,#ec4899 14%,transparent)}
.ctag.ipsec{color:#f43f5e;background:color-mix(in srgb,#f43f5e 13%,transparent)}
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
.k{color:var(--sub);font-size:11.5px;margin-bottom:8px;display:flex;align-items:center;gap:8px}
.v{font-size:22px;font-weight:800}.stat .v{font-size:22px}
.sec{font-size:12.5px;font-weight:700;color:var(--sub);margin:20px 4px 9px;display:flex;align-items:center;gap:7px}
.sec::after{content:'';flex:1;height:1px;background:linear-gradient(to left,var(--bord),transparent)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;vertical-align:1px}
.seg{display:flex;align-items:center;gap:14px}.donut{flex:0 0 116px}
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
.mtext{font-size:14px;line-height:1.85;white-space:pre-line}.mbtns{display:flex;gap:9px;margin-top:17px}
.mbtns .primary,.mbtns .ghost{margin:0}
.mbtns .primary{background:linear-gradient(180deg,color-mix(in srgb,var(--bad) 92%,#fff),var(--bad));color:#fff;box-shadow:0 10px 22px -12px color-mix(in srgb,var(--bad) 55%,transparent)}
@keyframes fade{from{opacity:0}to{opacity:1}}
.toast{position:fixed;left:50%;bottom:26px;transform:translate(-50%,20px);z-index:60;max-width:88%;padding:12px 18px;border-radius:14px;font-size:13px;background:var(--card);border:1px solid var(--bord);box-shadow:var(--dsh);opacity:0;transition:.3s;pointer-events:none}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:color-mix(in srgb,var(--bad) 45%,transparent);color:var(--bad)}
.toast.ok{border-color:color-mix(in srgb,var(--ok) 45%,transparent);color:var(--ok)}
.toolbar{display:flex;gap:9px;align-items:center;margin:2px 0 12px;flex-wrap:wrap}
.search{flex:1;min-width:150px;padding:10px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-size:13px;font-family:inherit}
.setrow2.tun-off{opacity:.55}
/* A settings group is its OWN accordion — hence `sacc`, not `acc`. `.card.acc` belongs to the
   node/tunnel/port-forward card, and THAT component sets `padding:0` on the card because its own
   header (.chead) and body (.cbody-in) carry the padding instead. The settings card borrowed the
   class name and inherited the zero and nothing else: the header text sat 2px from the border, the
   rows ran into the edge, and a collapsed card was 36px tall against a 15px radius — a capsule, not
   a card. Same inset as .card's own 14px, so an open group lines up with every other card on the page. */
.setgrp.sacc{padding:0}
.setgrp.sacc .grphd.acch{margin:0;padding:12px 14px;gap:8px;flex-wrap:nowrap;align-items:center;
  cursor:pointer;user-select:none}
/* nowrap on the header itself, wrap INSIDE the title box: a long title pushes the chip onto a second
   line but can never push the chevron off it, so the control stays at the card's far edge — the same
   place on every card, open or closed. */
.setgrp.sacc .grphd.acch .grphdl{display:flex;align-items:center;gap:8px;flex-wrap:wrap;flex:1;min-width:0}
/* The chevron sits at the far end of the header — in this RTL page that is the LEFT edge. */
.setgrp.sacc .grphd.acch .pchev{margin-inline-start:auto;flex:0 0 auto;line-height:1;
  color:var(--sub);font-size:12px;transition:transform .2s}
.setgrp.sacc .grphd.acch .pchev.open{transform:rotate(180deg)}
/* inset + the card's own radius: .card is overflow:hidden, so an outward ring gets clipped away. */
.setgrp.sacc .grphd.acch:focus-visible{outline:2px solid var(--acc);outline-offset:-2px;border-radius:15px}
.setgrp.sacc .setgrpb{padding:0 14px 12px}
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
/* --- system log ------------------------------------------------------------------------------ */
.logcard{display:flex;margin-bottom:9px;padding:0;overflow:hidden;box-shadow:var(--sh-sm)}
.logcard .lstripe{width:4px;flex:0 0 auto}
.logcard .lbody{display:flex;gap:10px;align-items:flex-start;padding:11px 12px;flex:1;min-width:0}
.logcard .lico{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;flex:0 0 auto;margin-top:1px}
.logcard .lico .ic{width:15px;height:15px}
.logcard .lmain{flex:1;min-width:0;display:flex;flex-direction:column;gap:6px}
/* The title carries the whole reason, on its own line. */
.logcard .ltitle{font-size:13px;font-weight:800;line-height:1.6;overflow-wrap:anywhere;color:var(--tx)}
.logcard .ltime{flex:0 0 auto;color:var(--sub);font-size:10.5px;white-space:nowrap;margin-top:2px}
/* from -> to: one row per side, the label fixed-width so the two values line up under each other. */
.lfromto{display:flex;flex-direction:column;gap:5px}
/* baseline, not center: against a value that wraps to several lines the label must sit on the
   FIRST line, not float halfway down the pill. */
.lft{display:flex;align-items:baseline;gap:6px;min-width:0}
/* No fixed label width: «از:» and «به:» are the same length anyway, so a fixed column only pushed
   the value away from the edge it should sit against. */
.lft .k{flex:0 0 auto;font-size:11px;color:var(--sub);text-align:start}
/* The pill hugs its value, so a bare IP stays a small chip. A value too long for the row — an
   «IP:port · SNI» endpoint, a base64 ECH key — WRAPS inside the pill. It used to scroll instead,
   which hid the rest of the value behind a horizontal gesture nobody would think to make on a log
   entry; showing the value whole is the entire point of the box. */
.lft .v{flex:0 1 auto;max-width:100%;min-width:0;direction:ltr;unicode-bidi:isolate;text-align:left;
  font-size:11.5px;line-height:1.8;padding:4px 9px;border-radius:8px;background:var(--field);
  border:1px solid var(--bord);color:var(--tx);overflow-wrap:anywhere;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.lft.to .v{color:var(--acc);background:var(--accw);border-color:color-mix(in srgb,var(--acc) 30%,transparent)}
.lnote{font-size:11.5px;color:var(--sub);line-height:1.85;overflow-wrap:anywhere}
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
.drop{border:1.5px dashed color-mix(in srgb,var(--acc) 45%,transparent);border-radius:13px;padding:18px;text-align:center;background:var(--accw);color:var(--sub);font-size:12.5px;cursor:pointer;margin-top:4px}.drop b{color:var(--acc)}
.banner{display:flex;align-items:center;gap:12px}.banner .v{font-size:13.5px;font-weight:800}
/* --- unified agent+core card (compact) --- */
.agx-uni{padding:13px}
.agx-uni .k{margin-bottom:10px}
.agx-uni .k .grow{flex:1}
.agx-meta{display:flex;flex-wrap:wrap;gap:5px 10px;align-items:center;font-size:11.5px;color:var(--sub);background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:8px 11px;margin-bottom:11px}
.agx-meta .sep{width:3px;height:3px;border-radius:50%;background:var(--sub);opacity:.5}
/* The release picker and its check button share a row: the button is what FILLS the picker, so
   putting it anywhere else would leave an empty dropdown with no visible way to populate it. */
.corverrow{display:flex;gap:8px;align-items:center;margin-bottom:9px}
/* Before the first check there is nothing to pick. A .setfield here looked like a dead control;
   this is a status line, so it reads as one. */
.corempty{flex:1;min-width:0;font-size:12px;color:var(--sub);line-height:1.7;padding:2px 2px}
.corverrow>#cor_ver_box{flex:1;min-width:0}
.corverrow>.corcheck{flex:0 0 auto;margin:0;padding:9px 13px;font-size:12.5px;min-height:38px;
  border-radius:10px;display:inline-flex;align-items:center;gap:6px;white-space:nowrap}
.corverrow>.corcheck .ic{width:14px;height:14px}
.agx-act{display:flex;gap:7px;flex-wrap:wrap}
.agx-act .primary,.agx-act .ghost{margin-top:0;padding:8px 13px;font-size:12px;border-radius:10px;display:inline-flex;align-items:center;gap:6px}
.agx-act .primary{flex:1;justify-content:center}
.agx-hint{font-size:10.5px;color:var(--sub);margin-top:8px;line-height:1.6}
/* --- compact node row + per-node core picker --- */
.agx-row{position:relative;display:flex;align-items:center;gap:9px;background:var(--card);border:1px solid var(--bord);border-radius:12px;padding:9px 11px;margin-bottom:8px;flex-wrap:wrap;box-shadow:var(--dsh)}
.agx-row .nm{font-weight:800;font-size:13px}
.agx-pill{font-size:10.5px;font-weight:700;padding:2px 6px;border-radius:6px;font-family:ui-monospace,monospace;direction:ltr;background:var(--field);color:var(--sub);border:1px solid var(--bord)}
.agx-pill.cor{background:color-mix(in srgb,#8b5cf6 12%,transparent);color:#8b5cf6;border-color:color-mix(in srgb,#8b5cf6 26%,transparent)}
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
.tbtnrow{display:flex;gap:8px;margin:14px 0 10px;flex-wrap:wrap}
/* Action buttons were full-bleed slabs: 13px text in a 12x14 box stretched edge to edge, which on a
   phone reads as a banner rather than a control. Size them to their label, keep a 40px tap target. */
.tbtnrow>button{flex:0 1 auto;min-width:0;display:inline-flex;align-items:center;justify-content:center;
  gap:6px;margin:0;font-size:12.5px;line-height:1.2;padding:9px 15px;min-height:38px;border-radius:10px}
.tbtnrow>button.primary{flex:0 1 auto}
.tbtnrow>button .ic{width:14px;height:14px}
/* «بازگردانی به پیش‌فرض» sat on --glass with --sub text and was nearly invisible on the card's own
   background. It needs to be readable without competing with Save — a legible outline, not a fill. */
.tbtnrow>button.ghost{background:var(--glass);border:1px solid var(--bord);color:var(--tx);font-weight:700}
.tbtnrow>button.ghost:hover{background:var(--field);border-color:var(--sub)}
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
/* node cards are accordion (chead + collapsing cbody) — no forced flex-column/equal-height (that would block the collapse) */
/* tunnel card: two node tiles (name + status pill + address) with ↔ between them, then a 2-col meta grid */
.tninfo{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:center;margin-top:2px;direction:ltr}
.tninfo>*{direction:rtl}   /* columns flow LTR so box B (b_name) sits on the RIGHT — same side as the header's a↔b; each box keeps its own RTL content */
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
.setgrp{margin-top:8px}
.sc-panel{--sc:#4f6ef7;--scbg:#4f6ef722}.sc-both{--sc:#0891b2;--scbg:#0891b222}.sc-ws{--sc:#c2410c;--scbg:#c2410c22}.sc-dgram{--sc:#8b5cf6;--scbg:#8b5cf622}
.grphd{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:2px 2px 8px;font-weight:800;font-size:14px;color:var(--tx)}
.grphd .gdot{width:9px;height:9px;border-radius:50%;flex:none;background:var(--sc)}
.grphd .schip{font-size:10.5px;font-weight:800;padding:2px 9px;border-radius:20px;background:var(--scbg);color:var(--sc)}
.grphd small{width:100%;font-weight:600;color:var(--sub);font-size:11px;margin-top:-2px;padding-inline-start:17px}
.setrow2{padding:10px 0;border-bottom:1px solid var(--bord)}
.setrow2:last-of-type{border-bottom:0}
.setrow2-top{display:flex;align-items:center;gap:10px}
.setlbl2{flex:1;font-size:13px;font-weight:700;color:var(--tx)}
.qbtn{flex:none;width:22px;height:22px;border-radius:50%;border:1.5px solid var(--bord);background:var(--field);color:var(--sub);font-weight:800;font-size:13px;cursor:pointer;font-family:inherit;line-height:1;padding:0}
.qbtn:hover{border-color:var(--acc);color:var(--acc)}
.setrow2.exp-open .qbtn{background:var(--acc);border-color:var(--acc);color:#fff}
.setexp{max-height:0;overflow:hidden;opacity:0;transition:max-height .28s ease,opacity .2s,margin .2s;background:var(--field);border-radius:11px;margin-top:0}
.setrow2.exp-open .setexp{max-height:280px;opacity:1;margin-top:9px;padding:10px 12px}
.setexp p{margin:0;font-size:12.5px;line-height:1.75;color:var(--tx)}
.setexp .setex{margin-top:5px;color:var(--sub)}
.setexp .setex b{color:var(--acc);font-weight:700}
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
.tag.obfs{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent);text-transform:none;letter-spacing:0;padding:1px 6px;border-radius:7px;font-size:10px}
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
.pempty{text-align:center;font-size:11px;color:var(--sub);padding:14px 0}
.pacc{border:1px solid var(--bord);border-radius:12px;overflow:hidden;background:var(--field);margin-top:12px}
.pacchd{display:flex;align-items:center;justify-content:space-between;padding:11px 13px;cursor:pointer;gap:10px}
.pacct{font-size:13px;font-weight:700}
.pacchd .pacctl{display:flex;align-items:center;gap:8px;flex:1;min-width:0}   /* title + badges share ONE line */
.paccs{margin-inline-start:auto;display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
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
.peerlive{margin-top:12px;display:flex;flex-direction:column}
.peerlive .pacc{margin-top:8px}                       /* each side is its own card now, not a row in one box */
.peerlive .pllabel{margin-bottom:2px}
.peerlive .pllabel{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:700}
.peerlive .rpool{border:none;background:transparent;display:flex;flex-direction:column;gap:6px;overflow:visible}
/* peer-pool row is a COLUMN: top line (icon+ip+actions) then the retest countdown UNDER it, indented */
.erow.pcol{flex-direction:column;align-items:stretch;flex-wrap:nowrap;row-gap:0}
.erow.pcol .etop{display:flex;align-items:center;gap:8px}
.erow.pcol .ecd{display:flex;align-items:center;gap:8px;margin-top:7px;margin-inline-start:24px}
.erow.pcol .ecd .pbar{flex:1 1 auto;width:auto;max-width:180px}
.eib.aim.on{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 55%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent)}
.tglbox.dis{opacity:.45;pointer-events:none}
.rl{font-size:8px;font-weight:800;border-radius:5px;padding:1px 4px;letter-spacing:.2px;flex:0 0 auto}
.rl.srv{color:var(--acc);background:color-mix(in srgb,var(--acc) 18%,transparent)}  /* stronger than the near-white --accw so the tint reads as clearly as the client's gold */
.rl.cli{color:var(--gold);background:var(--goldw)}
.enc{color:var(--bad);font-weight:700;display:inline-flex;align-items:center;gap:3px}.enc .ic{width:12px;height:12px}
/* two meta columns aligned EXACTLY under the two node boxes (same grid + hidden arrow as .tninfo) */
.enmeta{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:start;margin-top:11px;font-size:11.5px;color:var(--sub)}
.tninfo + .enmeta{direction:ltr}
.tninfo + .enmeta>*{direction:rtl}   /* meta columns follow the boxes' new LTR order (only the core/tunnel enmeta that directly follows a .tninfo; portfw's enmeta is left as-is) */
.enmeta .emcol{min-width:0;display:flex;flex-direction:column;gap:4px}
.enmeta .emcol>div{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.enmeta .emcol>div.wrap{white-space:normal;overflow:visible}
.enmeta .emcol b{color:var(--tx);font-weight:700}
.enmeta .earrow{visibility:hidden}
.enmeta .emcol>div.feat{display:flex;align-items:center;gap:4px;flex-wrap:wrap;white-space:normal;overflow:visible}
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
.cprot:empty{display:none}
.tnend{margin-inline-start:auto;display:inline-flex;align-items:center;gap:6px;flex:0 0 auto}
.tnend .stat,.tnend .cprot{margin-inline-start:0}
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
.pgrid.p3{grid-template-columns:repeat(3,1fr);gap:7px}
.pgrid.p3 .ptile{padding:9px 8px}
.ptile{position:relative;border:1.5px solid var(--bord);background:var(--field);border-radius:12px;padding:9px 10px;cursor:pointer;font-family:inherit;text-align:start;color:var(--tx)}
.ptile .pn{font-size:13px;font-weight:800;direction:ltr;letter-spacing:.3px;text-transform:uppercase}
.ptile .pmeta{margin-top:2px;font-size:10px;color:var(--sub)}
.ptile.on{border-color:color-mix(in srgb,var(--acc) 60%,transparent);background:var(--accw)}
.ptile.on .pn{color:var(--acc)}
.ptile .best{position:absolute;top:7px;inset-inline-start:7px;font-size:9px;font-weight:800;color:var(--ok);background:var(--okw);border-radius:20px;padding:1px 6px}
.ptile .pwarn{position:absolute;top:9px;inset-inline-start:9px;width:7px;height:7px;border-radius:50%;background:var(--gold)}
.seg2 .segopt.on{border-color:var(--acc);background:var(--accw)}
.seg2 .segopt.on span{color:color-mix(in srgb,var(--acc) 80%,var(--sub))}
/* trbar: the connection-carrier segment as a horizontal scrollable bar (fixed-width tiles + edge fade) */
.trwrap{position:relative;margin:2px 0 11px}
.trwrap .trbar{margin:0;flex-wrap:nowrap;overflow-x:auto;overflow-y:hidden;padding-bottom:2px;-webkit-overflow-scrolling:touch;scroll-snap-type:x proximity;scrollbar-width:none}
.trwrap .trbar::-webkit-scrollbar{display:none}
.trwrap .trbar .segopt{flex:0 0 auto;width:82px;scroll-snap-align:start}
.trwrap .trbar .segopt span{white-space:nowrap}
.trwrap::before{content:'';position:absolute;top:0;bottom:2px;inset-inline-end:0;width:34px;pointer-events:none;z-index:2;transition:opacity .2s;background:linear-gradient(to left,transparent,var(--card))}
[dir="ltr"] .trwrap::before{background:linear-gradient(to right,transparent,var(--card))}
.trwrap.atend::before{opacity:0}
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
// ===== i18n — Persian only (the English layer + language toggle were removed). =====
var _corS={},_eeS={};   // create/edit form state (folded from the old _corX/_eeX scalars)
var I18N={fa:{
 nav_overview:"نمای کلی",nav_nodes:"نودها",nav_tunnels:"تونل‌ها",nav_portfw:"پورت‌فوروارد",nav_core:"هستهٔ اختصاصی",nav_logs:"لاگ",nav_settings:"تنظیمات",nav_logout:"خروج",
 logs_title:"لاگِ سیستم",logs_sub:"رویدادهای خودکارِ سیستم — قطع/وصلِ نود و تونل و تغییرِ خودکارِ لبه (کارهای دستیِ شما اینجا نمی‌آید)",logs_empty:"هنوز رویدادی ثبت نشده",logs_clear:"پاک‌کردنِ لاگ",logs_cleared:"لاگ پاک شد",logs_clear_confirm:"همهٔ لاگ‌ها پاک شوند؟",
 logc_all:"همه",logc_tunnel:"تونل",logc_rot:"چرخش/استخر",logc_ech:"ECH",logc_node:"نود",logc_sys:"سیستم",logc_err:"فقط خطاها",logc_none:"در این دسته لاگی نیست",
 brand_sub:"کنترل فلیت",theme:"تم",
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
 tip_test:"تست",tip_details:"مشخصات",tip_edit:"ویرایش",tip_delete:"حذف",tip_tune:"تیونینگِ شبکه",
 kt_title:"تیونینگِ کرنل (BBR)",kt_sub:"شتاب‌دهیِ شبکه‌ی سرور",kt_desc:"BBR + fq + بافرهای بزرگ‌تر را روی این سرور روشن می‌کند. روی مسیرِ پرتلفات و پرتأخیرِ ایران، سرعتِ حامل‌های TCP را بالا می‌برد. اختیاری و برگشت‌پذیر.",kt_state:"وضعیت",kt_cc:"کنترلِ ازدحام",kt_qdisc:"صف‌بندی",kt_on:"روشن",kt_off:"خاموش",kt_enable:"روشن کردن",kt_disable:"خاموش کردن",kt_nobbr:"کرنلِ این سرور BBR ندارد — روشن‌کردن ممکن نیست.",kt_working:"در حال اعمال…",kt_enabled:"تیونینگ روشن شد",kt_disabled:"تیونینگ خاموش شد",kt_close:"بستن",
 nd_tunnels:"تونل",nd_portfw:"پورت‌فوروارد",nd_agent:"ایجنت",nd_core:"هسته",nd_core_missing:"نصب نیست",nd_ctrlproxy:"پروکسیِ کنترل",nd_toggle:"نمایش/پنهان در لیستِ ساختِ تونل و پورت‌فوروارد (اتصال قطع نمی‌شود)",nd_hidden:"از لیستِ ساخت پنهان شد",nd_shown:"به لیستِ ساخت برگشت",
 uptime_bar:"آپتایم",node_min2:"حداقل ۲ نودِ آنلاین لازم است",
 // tunnels
 tun_sub:"هر لینک نود‌به‌نود جداگانه است — بررسی، ویرایش و حذف مستقل دارد",add_tunnel:"افزودن تونل",check_all:"بررسی اتصال همگانی",
 tun_search:"جستجوی نام نود / نوع / شناسه…",tun_empty:"هنوز لینکی نیست — دکمهٔ «افزودن تونل» بالا.",
 st_off:"خاموش",st_disc:"قطع",reorder_err:"ذخیرهٔ ترتیب ناموفق بود",reord_t:"حالتِ جابه‌جایی کارت‌ها",tip_ping:"تستِ پینگ",tip_reset:"ریستِ حجمِ کل",tip_rebuild:"بازسازی",tip_toggle:"روشن/خاموشِ تونل",
 subnet:"سابنت",tid:"شناسه",iface:"اینترفیس",ttype:"نوع",udp_port:"پورتِ UDP",enc:"رمزنگاری",encrypted:"رمزنگاری‌شده",total:"مجموع",
 no_live_side:"دادهٔ زنده از این سر نیست",tun_off_note:"این تونل خاموش است — اینترفیس down شده. توگلِ بالا را بزن تا دوباره بالا بیاید.",
 turned_on:"روشن شد",turned_off:"خاموش شد",
 // core view
 core_sub:"تونل‌های هستهٔ اختصاصی (Go) — حالتِ packet/core با رمزنگاریِ داخلی، جدا از تونل‌های سیستمی",core_add:"تونلِ هسته",
 core_search:"جستجوی نام نود / شناسه…",core_empty:"هنوز تونلِ هسته‌ای نیست — دکمهٔ «تونلِ هسته» بالا را بزن.",
 server:"سرور",client:"کلاینت",carrier:"حامل",port:"پورت",caps:"قابلیت‌ها",no_cipher:"بدونِ رمز",cdn_edge:"لبهٔ CDN",active_edge:"لبهٔ فعالِ فعلی (زنده)",cor_tab_ips:"آی‌پی‌ها",cor_tab_set:"تنظیمات",
 // portfw
 pf_sub:"فوروارد پورت روی یک نود (با چرخشِ چند مقصد)",pf_add:"افزودن پورت‌فوروارد",pf_active:"پورت‌فورواردهای فعال",pf_search:"جستجوی نود / نام…",
 pf_empty:"پورت‌فورواردی نیست.",pf_no_online:"هیچ نودِ آنلاینی نیست",
 // settings
 set_sub:"رفتار خودکارِ پنل و بازه‌های بررسی",set_saved:"تنظیمات ذخیره شد",
 // toasts common
 t_rebuilt:"بازسازی شد",t_reset_done:"حجمِ کل صفر شد",
}};
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 ram:"رم",cores_word:"هسته",unit_mb:"م‌ب",unit_gb:"گیگ",refresh2s:"به‌روزرسانیِ زنده",
 // node details
 nd_title:"مشخصات نود",nd_status:"وضعیت نود",nd_off_last:"آفلاین — آخرین مقادیر",nd_conn_test:"تستِ اتصال",nd_traffic:"ترافیک",nd_ips:"آی‌پی‌ها",
 ip_leg:"تونل‌شده / پورت‌فوروارد / آزاد",ip_none:"آی‌پی‌ای گزارش نشد",free:"آزاد",nd_no_tp:"تونل یا پورت‌فورواردی روی این نود نیست",nd_ctrlproxy:"پروکسیِ کنترل",
 // node edit / add
 nd_edit:"ویرایشِ نود",f_name:"نام",f_host_ip:"هاست / آی‌پی",f_port:"پورت",f_token:"توکن",tok_keep:"خالی = توکن فعلی بماند",
 need_nhp:"نام، هاست و پورت لازم است",
 
 
 
 
 connecting_dots:"در حال اتصال…",
 need_all_nhpt:"لطفاً نام، هاست، پورت و توکن را پر کن",node_added:"نود اضافه شد",
 
 inst_done:"انجام شد",
 // node delete
 nd_del:"حذفِ نود",del_how:"می‌خواهی نود چطور حذف شود؟ یکی را انتخاب کن:",del_detach_t:"فقط از پنل جدا کن",
 del_detach_s:"نود و تونل‌هایش دست‌نخورده می‌مانند و کار می‌کنند؛ فقط از رجیستریِ این پنل حذف می‌شود. بعداً می‌توانی دوباره اضافه‌اش کنی.",
 del_wipe_t:"پاک‌سازیِ کاملِ نود",del_wipe_s:"روی خودِ سرورِ نود همه‌چیز پاک می‌شود: همهٔ تونل‌ها، ایجنت، سرویسِ systemd، توکن و فایل‌های JSON. سمتِ نودهای مقابل هم تونل‌ها بسته می‌شوند. برگشت‌ناپذیر است!",
 del_wipe_confirm:"مطمئنی؟ کلِ نود روی سرور — تونل‌ها، ایجنت و توکن — پاک می‌شود و برگشت ندارد.",del_wipe_yes:"بله، پاک کن",
 del_wiping:"در حال پاک‌سازیِ نود…",del_detaching:"در حال جدا کردن…",node_wiped:"نود کاملاً پاک‌سازی شد",node_detached:"نود از پنل جدا شد",
 del_force_ask:"این تونل به‌اجبار حذف شود؟ سمتِ نودِ در دسترس همین حالا بسته می‌شود، و سمتِ نودِ قطع وقتی برگشت خودکار پاک می‌شود.",del_force_yes:"حذفِ اجباری",
 del_wipe_force_ask:"سرور قطع است — «پاک‌سازیِ اجباری»؟ رکوردِ نود و لینک‌هایش از پنل پاک و سمتِ نودهای مقابلِ در دسترس بسته می‌شوند؛ خودِ این سرور اگر روزی برگشت باید دستی پاک شود.",del_wipe_force_yes:"پاک‌سازیِ اجباری",del_wipe_force_s:"سرور قطع است، پس روی خودش کاری نمی‌شود کرد: رکوردِ نود و لینک‌هایش از پنل پاک و سمتِ نودهای مقابلِ در دسترس بسته می‌شوند. برگشت‌ناپذیر است!",del_force_wiping:"در حالِ پاک‌سازیِ اجباری…",node_force_wiped:"نود از پنل پاک شد (سرور در دسترس نبود؛ سمتِ مقابل بسته شد)",
 pend_del_t:"حذفِ معلق — وقتی این نود دوباره وصل شد، خودکار پاک‌سازی می‌شود",
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
 
 
 // rebuild picker
 rb_title:"بازسازیِ تونل",rb_newip:"آی‌پیِ جدید",rb_no_ip:"آی‌پیِ قابلِ انتخابی نیست",rb_info:"آی‌پیِ قبلی دیگر روی نود نیست. آی‌پیِ جدیدِ این تونل را انتخاب کن — تگ‌ها نشان می‌دهند هر آی‌پی به کجا وصل است.",
 rb_no_link:"اطلاعاتِ لینک در دسترس نیست",rb_no_drift:"این تونل driftی ندارد",rebuilding:"در حال بازسازی…",rb_fetch_err:"خطا در دریافتِ اطلاعات",
 // core roles / meta
 core_edit_t:"ویرایشِ تونلِ هسته",not_found:"یافت نشد",no_change:"تغییری نبود",saved_rebuilt:"ذخیره و بازسازی شد",core_tun_t:"تونلِ هسته",core_tun_sub:"هستهٔ اختصاصی · packet/core",
 core_created:"تونلِ هسته ساخته شد",raw_need_enc:"حاملِ raw به رمزنگاری نیاز دارد",flux_need_enc:"حاملِ flux به رمزنگاری نیاز دارد",
 wss_need_host:"برای wss باید دامنه (Host) را وارد کنی",ech_need_wss:"ECH به wss نیاز دارد — اول wss را روشن کن",sni_need_wss:"تقسیمِ SNI به wss نیاز دارد — اول wss را روشن کن",
 xh_need_wss:"gRPC نیازمندِ wss است — اول wss (TLS به CDN) را روشن کن یا حاملِ HTTP را انتخاب کن",
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
 
 set_t_suspect:"زمان‌بندیِ تستِ مجددِ «موقت‌سوخته» (ثانیه)",set_t_suspect_d:"وقتی یک آی‌پی از کار می‌افتد، همان لحظه دورش نمی‌اندازیم — چند بار دیگر امتحانش می‌کنیم، ولی هر بار با صبرِ بیشتر. این عددها همان فاصله‌ها هستند، با کاما جدا. یعنی: بار اول ۳۰ ثانیه صبر کن و دوباره امتحان کن؛ باز نشد، ۶۰ ثانیه؛ بعد ۱۲۰… اگر تا آخرین عدد هم درست نشد، آن آی‌پی خراب علامت می‌خورد. عددهای کوچک‌تر یعنی زودتر دوباره امتحان می‌کند.",
 set_t_deadretest:"بازهٔ تستِ IPِ «مرده» (ثانیه)",set_t_deadretest_d:"آی‌پی‌ای که خراب علامت خورده دیگر استفاده نمی‌شود، ولی برای همیشه کنار گذاشته نمی‌شود: هر این‌قدر ثانیه یک بار دوباره امتحانش می‌کند و اگر جواب داد، خودش برمی‌گردد سرِ کار. اگر فیلترها زود عوض می‌شوند، این عدد را کم کن تا آی‌پی زودتر برگردد.",
 set_t_pinttl:"سقفِ پینِ دستی (ثانیه)",set_t_pinttl_d:"وقتی خودت روی یک آی‌پی دکمهٔ «این را فعال کن» را می‌زنی، تونل سعی می‌کند برود روی همان. ولی اگر آن آی‌پی خراب باشد، تا ابد منتظر نمی‌ماند — بعد از این‌قدر ثانیه بی‌خیال می‌شود و می‌رود سراغ بقیه. یعنی یک انتخابِ اشتباه، تونلت را قطع نگه نمی‌دارد.",
 set_t_datafail:"آستانهٔ سشنِ کوتاه",set_t_datafail_d:"بعضی وقت‌ها یک آی‌پیِ CDN وصل می‌شود ولی چند ثانیه بعد می‌افتد. این عدد می‌گوید چند بارِ پشتِ‌هم این اتفاق بیفتد تا آن آی‌پی را کنار بگذارد. کمترش کنی زودتر کنار می‌گذارد، ولی ممکن است آی‌پیِ سالم را هم بی‌گناه کنار بگذارد.",
 set_t_datagood:"پنجرهٔ گاردِ قطعی (ثانیه)",set_t_datagood_d:"یک محافظ، تا بی‌خود همه‌چیز را خراب علامت نزند. اگر اینترنتِ خودِ سرور قطع شود، همهٔ آی‌پی‌ها با هم می‌افتند — تقصیرِ آن‌ها نیست. برای همین یک آی‌پی فقط وقتی مقصر شناخته می‌شود که در این چند ثانیهٔ اخیر، لااقل یکی از بقیه سالم کار کرده باشد. اگر هیچ‌کدام سالم نبوده، یعنی مشکل از خودِ سرور است و هیچ آی‌پی‌ای علامت نمی‌خورد.",
 set_t_idlemult:"ضریبِ idle (×keepalive)",set_t_idlemult_d:"برای تونل‌های ws و tcp. چند برابرِ keepalive سکوت را تحمل کند تا بگوید اتصال مرده است. مثلاً اگر keepalive ۱۰ ثانیه باشد و این عدد ۴، بعد از ۴۰ ثانیه بی‌خبری اتصال را می‌بندد و از نو وصل می‌شود.",
 set_t_idlemin:"کفِ idle (ثانیه)",set_t_idlemin_d:"کفِ همان محاسبهٔ بالا. اگر ضرب‌کردن عددِ کوچکی درآورد، از این پایین‌تر نرود. جلوی این را می‌گیرد که یک کندیِ چندثانیه‌ایِ اینترنت، الکی قطعیِ تونل خوانده شود.",
 set_t_ssmult:"ضریبِ کهنگیِ سشن (×keepalive)",set_t_ssmult_d:"برای تونل‌های udp و raw و flux. این‌ها ارتباطِ دائمیِ برقرارشده ندارند، پس تنها نشانهٔ سالم‌بودنشان این است که داده می‌رسد. چند برابرِ keepalive سکوت را تحمل کند تا ارتباط را از نو برقرار کند.",
 set_t_ssmin:"کفِ کهنگیِ سشن (ثانیه)",set_t_ssmin_d:"کفِ همان محاسبه برای udp و raw و flux — از این کمتر، سکوت را به حسابِ قطعی نگذار.",
 set_t_pingloss:"آستانهٔ پینگِ ازدست‌رفته",set_t_pingloss_d:"چند تا از آن بسته‌های «زنده‌ای؟» پشتِ‌هم بی‌جواب بماند تا اتصال را ببندد و دوباره وصل شود. کم که باشد سریع‌تر واکنش نشان می‌دهد، ولی روی اینترنتِ ناپایدار ممکن است بی‌خود قطع و وصل کند.",
 set_t_minlive:"حداقلِ عمرِ سشنِ سالم (ثانیه)",set_t_minlive_d:"اتصالی که زودتر از این‌قدر ثانیه بیفتد، یک قطعیِ عادی حساب نمی‌شود — به پای خرابیِ همان آی‌پی نوشته می‌شود. این‌طوری آی‌پی‌ای که مدام وصل می‌شود و فوری می‌افتد، شناسایی و کنار گذاشته می‌شود.",
 set_t_probeto:"تایم‌اوتِ پروبِ لبه (ثانیه)",set_t_probeto_d:"برای اینکه بفهمد یک آی‌پیِ خراب دوباره سالم شده یا نه، یک اتصالِ آزمایشی می‌زند. این می‌گوید چند ثانیه منتظرِ جوابش بماند. اگر اینترنتت کند است این عدد را زیاد کن، وگرنه آی‌پیِ سالم را هم رد می‌کند.",
 set_g1:"۱) زمان‌بندیِ پنل",set_g1h:"روی مرکزی اجرا می‌شود",set_g1c:"پنل",
 set_g2:"۱) سلامتِ استخر و چرخشِ IP",set_g2h:"هستهٔ کلاینت",set_g2c:"هر دو استخر",
 set_g3:"۲) سوزاندنِ لبهٔ WS-CDN",set_g3h:"تونل‌های ws/xhttp",set_g3c:"فقط WS-CDN",
 set_g4:"۴) تشخیصِ مرگِ استریم",set_g4h:"بر پایهٔ keepalive",set_g4c:"ws / tcp",
 set_g7:"۵) آستانه‌های خرابی",set_g7h:"مستقل از مهلتِ ثابت",set_g7c:"همهٔ حامل‌ها",
 set_g5:"۵) دیتاگرام: کهنگیِ سشن و کارایی",set_g5h:"بی‌هندشیک، به‌علاوهٔ بافرِ سوکت",set_g5c:"udp / raw / flux",
 set_g6:"۷) کارایی",set_g6h:"پهنای‌باند",set_g6c:"udp / raw / flux",
 set_t_sockbuf:"بافرِ سوکت (مگابایت)",set_t_sockbuf_d:"وقتی داده یک‌دفعه سیل‌آسا می‌رسد، سیستم باید جایی نگهشان دارد تا برسد پردازششان کند. این همان جاست. بزرگ‌ترش کنی، در لحظه‌های شلوغ کمتر داده از دست می‌رود و سرعت بالاتر می‌رود (در تستِ ایران↔آلمان حدود ۲٫۷ برابر شد). <b>۰</b> یعنی دست نزن و همان تنظیمِ پیش‌فرضِ سیستم بماند. حواست باشد این مقدار حافظه از سرور می‌گیرد، پس روی سرورِ ضعیف زیادش نکن.",
 set_x_ipchange:"IPِ نودِ آلمان عوض شد → «هشدار» فقط علامت می‌زند و دستی بازسازی می‌کنی؛ «خودکار» پنل خودش با IPِ جدید می‌سازد.",
 set_x_rec:"<b>۱۵</b> = هر ۱۵ثانیه یک بررسی؛ کوچک‌تر = واکنشِ سریع‌تر، بارِ کمی بیشتر.",
 set_x_poll:"<b>۰٫۹</b> = کارت‌های نود تقریباً هر ثانیه تازه؛ کوچک‌تر = زنده‌تر ولی pollِ بیشتر روی نودها.",
 set_x_ui:"<b>۱</b> = اعداد و نمودارها هر ثانیه به‌روز می‌شوند (فقط مرورگر، نه بارِ شبکه).",
 set_x_ech:"<b>۱۵</b> = هر ۱۵ دقیقه کلید تازه؛ <b>۰</b> = خاموش (توصیه نمی‌شود).",
 set_x_upwin:"<b>۲۴ ساعت</b> = هر خانه ۲۴ دقیقه؛ <b>۱ ساعت</b> = هر خانه ۱ دقیقه (ریزتر).",
 set_x_suspect:"IP مشکوک شد → ۳۰ث بعد امتحان، باز مرد → ۶۰ث، بعد ۱۲۰… بعد از <b>۶۰۰</b> → مرده.",
 set_x_deadretest:"<b>۱۸۰۰</b> = IPِ مرده هر ۳۰ دقیقه یک شانسِ دوباره می‌گیرد.",
 set_x_pinttl:"<b>۵</b> = پین کردی؛ اگر ۵ثانیه وصل نشد، پین آزاد و چرخشِ عادی برمی‌گردد.",
 set_x_datafail:"<b>۳</b> = سه بارِ پیاپی اتصال زود قطع شد → لبه مشکوک می‌شود.",
 set_x_datagood:"<b>۱۲۰</b> = اگر در ۱۲۰ثانیهٔ اخیر هیچ لبه‌ای سالم نبوده، مشکل عمومی است نه این لبه → نمی‌سوزد.",
 set_x_idlemult:"keepalive=۱۰ث و ضریب=<b>۴</b> ← ۴۰ثانیه سکوت = اتصال مرده.",
 set_x_idlemin:"ضریب×keepalive شد ۴۰ث، ولی کف=<b>۶۰</b> ← مهلت ۶۰ثانیه می‌شود.",
 set_x_ssmult:"keepalive=۱۰ و ضریب=<b>۳</b> ← ۳۰ثانیه سکوت ← سشنِ نو ساخته می‌شود.",
 set_x_ssmin:"<b>۱۰</b> = کمتر از ۱۰ثانیه سکوت، سشن را کهنه حساب نکن.",
 set_x_pingloss:"<b>۳</b> = سه پینگِ پشتِ‌هم بی‌جواب ← بستن و reconnect.",
 set_x_minlive:"<b>۲۰</b> = اتصال بعد از ۵ثانیه مرد ← خرابیِ IP، نه یک قطعِ عادی.",
 set_x_probeto:"<b>۵</b> = لبه در ۵ثانیه هندشیک نداد ← ناموفق. (حاملِ مستقیم اصلاً prober ندارد.)",
 set_x_sockbuf:"<b>۴</b> = همان پیش‌فرضِ هسته. وقتی بسته‌ها یک‌دفعه سیل‌آسا می‌رسند، هرچه اتاقِ انتظار بزرگ‌تر باشد کمترش دور ریخته می‌شود (در تستِ IR↔DE سرعتِ TCP حدود ۲٫۷ برابر شد). <b>۰</b> = خاموش، بافرِ پیش‌فرضِ کرنل. حافظهٔ مصرفی ≈ همین عدد × چند سوکت روی هر نود، پس روی سرورِ کم‌رم بالا نبر. فقط udp / raw / flux.",
 h1:"ساعت",h3:"۳ ساعت",h6:"۶ ساعت",h8:"۸ ساعت",h12:"۱۲ ساعت",h24:"۲۴ ساعت",
 // generic states
 pending_check:"در حال بررسی…",off_word:"خاموش",on_word:"روشن",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 pf_dest:"مقصد",
 // command palette
 pal_search:"جستجوی نود، تونل یا دستور…",pal_move:"حرکت",pal_pick:"انتخاب",pal_close:"بستن",pal_none:"موردی یافت نشد",
 pal_g_nodes:"نودها",pal_g_tuns:"تونل‌ها",pal_g_acts:"دستورها",
 pal_add_tun:"افزودن تونل",pal_agent:"بروزرسانیِ ایجنت",pal_checkall:"تستِ همهٔ تونل‌های صفحه",pal_theme:"تغییرِ تمِ روشن/تیره",
 // agent/core update page (partial)
 ag_title:"ایجنت و هسته",ag_sub:"آپدیت و ری‌استارتِ ایجنت و هستهٔ نودها از پنل، بدونِ SSH",
 cor_check:"بررسی آپدیت",cor_checking:"در حال بررسی…",cor_check_new:"نسخهٔ تازه پیدا شد — از لیست انتخابش کن و «دریافت از گیت‌هاب» را بزن",cor_check_same:"تازه‌ترین نسخه همینی است که داری",cor_check_first:"{n} نسخه پیدا شد — یکی را انتخاب کن",cor_check_none:"هیچ نسخه‌ای پیدا نشد",cor_ver_empty:"هنوز بررسی نشده — «بررسی آپدیت» را بزن",
 ag_node_agent:"ایجنتِ نودها",ag_data_core:"هستهٔ داده",ag_fetch_git:"دریافت از گیت‌هاب",ag_file_btn:"فایلِ ایجنت",ag_push_all:"پوشِ ایجنت به همهٔ نودها",
 ag_binary:"باینری",ag_install_all:"نصبِ هسته روی همهٔ نودها",ag_search:"جستجوی نود…",ag_ready:"آمادهٔ پوش",ag_empty:"خالی",ag_no_item:"موردی نیست",
 ag_core_hint:"⚠️ دو سرِ هر تونلِ هسته باید نسخهٔ یکسان داشته باشند؛ اگر نسخهٔ یک نود را عوض کردی، نودِ طرفِ مقابل را هم به همان نسخه ببر وگرنه آن تونل قطع می‌شود.",
 ag_lbl_agent:"ایجنت",ag_lbl_core:"هسته",ag_up_avail:"آپدیت دارد",ag_uptodate:"به‌روز",ag_not_installed:"نصب نیست",
 ag_no_online:"نودِ آنلاینی نیست",ag_skipped_off:"آفلاین — رد شد",ag_fail:"ناموفق: ",ag_already:"از قبل به‌روز",ag_updated:"به‌روز شد",ag_restarting:" · در حال ری‌استارت…",
 ag_nodes_updated:" نود بروزرسانی شد",ag_pick_first:"اول یک ایجنت بارگذاری کن",ag_confirm_all:"ایجنت روی ",ag_confirm_all2:" نودِ آنلاین آپدیت و ری‌استارت شود؟",
 ag_pick_ver:"اول نسخه را انتخاب کن",ag_confirm_core:"هستهٔ نسخهٔ «",ag_confirm_core2:"» روی ",ag_confirm_core3:" نودِ آنلاین نصب و تونل‌های هسته ری‌استارت شوند؟",
 ag_installing_core:"در حال نصبِ هسته…",ag_core_already:"هسته از قبل به‌روز بود",ag_core_updated:"هسته به‌روز شد",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 fmt_day:"روز",fmt_hr:"ساعت",fmt_min:"دقیقه",fmt_sec:"ثانیه",fmt_and:"و",cipher_auto:"خودکار",cipher_none:"بدونِ رمز",
 edit_tun_t:"ویرایشِ تونل",ip_of:"آی‌پیِ ",multi_ip:"مولتی‌آی‌پی",ip_each_end:"آی‌پیِ هر سرِ تونل",
 link_ip_note1:"اگر نودی چند آی‌پی دارد، انتخاب کن تونل روی کدام آی‌پی بسته شود. تغییرِ نوع، سابنت یا آی‌پی، تونل را روی هر دو نود بازسازی می‌کند (شناسه ",link_ip_note2:" حفظ می‌شود).",
 le_port_4789:"پورتِ UDP (خالی = 4789)",le_port_auto:"پورتِ UDP (خالی = خودکار از شناسه)",
 ph_burned_manual:"سوخته (دستی)",ph_dead:"سوختهٔ دائمی",ph_suspect:"سوختهٔ موقت",ph_active:"سالم · لبهٔ فعال",ph_healthy:"سالم",
 pb_healthy:"سالم",pb_temp:"موقت",pb_dead:"دائمی",pb_burned:"سوخته",pool_empty:"خالی — یک مورد اضافه کن",
 peer_live_hd:"وضعیت زندهٔ استخر",peer_st_active:"فعال",peer_st_rot:"در چرخش",peer_pinned:"روی این آی‌پی پین شد",peer_rotating:"این نود بین چند آی‌پی می‌چرخد — آی‌پیِ نشان‌داده‌شده، آی‌پیِ فعالِ فعلی است",peer_live_note:"آی‌پیِ سوخته طبق زمان‌بندی دوباره تست می‌شود و اگر سالم شد خودش به چرخش برمی‌گردد؛ با پین می‌توانید دستی روی یک آی‌پی سوییچ کنید.",
 peer_live_empty:"وضعیتِ زندهٔ آی‌پی‌ها و دکمهٔ پین، وقتی تونل روی نودِ به‌روز در حال اجراست این‌جا نمایش داده می‌شود. اگر تازه به‌روزرسانی کرده‌اید: نود را آپدیت کنید و بعد «ذخیره و بازسازی» را بزنید تا با هستهٔ جدید ساخته شود.",
 pa_restore:"بازگرداندن به چرخش",pa_testnow:"الان تست کن",pa_active_ip:"آی‌پیِ فعلی",pa_activate:"این را فعال کن",pa_pinning:"در حالِ فعال‌سازی…",
 flux_rotated:"چرخش انجام شد — تونل بازسازی شد",pool_make_first:"اول تونل را بساز",pool_probe_sent:"پروبِ فوری فرستاده شد",pool_edge_active:"این لبه فعال شد",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 // ---- core create/edit form + shared section builders (Gap 1)
 // subnet ranges
 snr_192:"خودکار · 192.168.x (پیشنهادی)",snr_10:"خودکار · 10.x",snr_172:"خودکار · 172.16.x",snr_custom:"دلخواه (دستی وارد کن)",
 // raw profiles
 rawp_best:"بهینه",rawp_warn:"ممکن است از NAT رد نشود",rawp_bip_m:"proto دلخواه · پیش‌فرضِ ۵۸",rawp_icmp_m:"proto 1 · شبیهِ ping",rawp_gre_m:"proto 47 · GRE",rawp_ipip_m:"proto 4 · IP-in-IP",rawp_udp_m:"proto 17 · UDP",rawp_tcp_m:"proto 6 · TCP جعلی",rawp_esp_m:"proto 50 · IPsec ESP",
 // ws / xhttp profiles
 xh_prof_lbl:"CDNِ روبه‌رو",
 xhp_cf_n:"کلودفلر",xhp_cf_m:"POSTِ بیشتر · سریع‌تر",
 xhp_arvan_n:"ابرآروان",xhp_arvan_m:"POSTِ کمتر و بزرگ‌تر",
 xh_prof_note:"تنها فرقشان این است که کلاینت چند POST در ثانیه می‌زند — و همین فرقِ بینِ کارکردن و بلاک‌شدن است. کلودفلر تا نزدیکِ ۷۰ درخواست در ثانیه را تحمل می‌کند؛ <b>دیوارهٔ ابرآروان با همین عدد، آی‌پیِ نود را چند دقیقه می‌بندد</b> — پس آنجا POSTها کمتر و بزرگ‌تر می‌شوند. روی CDNِ دیگری از کلودفلر شروع کن؛ اگر زیرِ بار قطع شد، ابرآروان را بزن.",
 wsp_ws_m:"وب‌سوکت",wsp_grpc_m:"استریمِ دوطرفه",wsp_http_m:"GET + POST",
 // flux rotation presets + shapes
 frot_180:"هر ۳ دقیقه",frot_300:"هر ۵ دقیقه",frot_600:"هر ۱۰ دقیقه (پیش‌فرض)",frot_900:"هر ۱۵ دقیقه",frot_1800:"هر ۳۰ دقیقه",frot_3600:"هر ۱ ساعت",
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
 ech_t:"ECH — مخفی‌کردنِ SNI",ech_d:"نامِ دامنه را داخلِ ClientHello رمز می‌کند تا فیلترچیِ SNI نبیند کدام دامنه است. نیازمندِ wss؛ برای استخر برای هر دامنه خودکار گرفته می‌شود.",echpx_t:"پروکسی برای دریافتِ کلیدِ ECH",echpx_d:"برای دامنهٔ فیلترشده — پنل کلیدِ ECH را از این پروکسی (socks5/http) می‌گیرد. فقط برای گرفتنِ کلید است، نه ترافیکِ تونل.",sni_t:"تقسیمِ SNI (ضدِ DPI)",sni_d:"ClientHello را روی مرزِ دو بستهٔ TCP می‌شکند تا نامِ دامنه در یک بسته کامل نباشد و DPIِ SNI-محور نتواند تطبیق دهد. مکملِ ارزانِ ECH؛ نیازمندِ wss.",sni_pos_lbl:"نقطهٔ برش (split_pos) — ۰ = خودکار (وسطِ دامنه)",sni_ttl_lbl:"TTLِ سگمنتِ سرْ (split_ttl) — ۰ = پیش‌فرض (۴)",sni_mode_lbl:"حالتِ تقسیم SNI",m_split_s:"دو سگمنتِ ساده",m_dis_s:"سگمنتِ سرْ با TTL پایین",m_fake_s:"ClientHelloِ جعلی (ضدِ reassembly)",
 // ws section
 ws_prof_lbl:"حاملِ رویِ CDN",ws_prof_note:"هر سه با همین دامنه/wss/ECH فرانت می‌شوند؛ فقط شکلِ درخواست فرق می‌کند. <b>WS</b> = ارتقاء به وب‌سوکت؛ اگر CDN وب‌سوکت را بسته باشد کار نمی‌کند. <b>gRPC</b> = یک درخواستِ دوطرفه که CDN باید به‌جای بافر، استریمش کند — نیازمندِ <b>wss</b> و روشن‌بودنِ gRPC رویِ CDN. <b>HTTP</b> = یک GETِ باز برای دانلود + POSTهای کوتاه برای آپلود؛ نه وب‌سوکت می‌خواهد نه gRPC، پس از هر دو تاگلِ Cloudflare مستقل است.",
 ws_pool_t:"استخرِ لبه (چرخش + بلک‌لیست)",ws_pool_d:"چند IP و چند دامنه؛ هسته می‌چرخد و سوخته‌ها را کنار می‌گذارد. خاموش = یک لبهٔ ثابت.",
 ws_host_lbl:"دامنهٔ فرانت (Host / SNI)",ph_cdn_domain:"مثلاً cdn.example.com",ws_edge_lbl:"آی‌پیِ لبهٔ CDN (اختیاری) — کلاینت به‌جای مبدأ به این وصل می‌شود",ph_edge_ip:"مثلاً 104.16.0.1 یا 104.16.0.1:443",ws_path_lbl:"مسیر (path)",
 ws_note:"ترافیک شبیهِ HTTPS رویِ CDN دیده می‌شود (collateral freedom). سرور را پشتِ یک CDN (مثل Cloudflare) بگذار، SSL روی Flexible، پورتِ مبدأ ۸۰. با <b>استخر</b> چند IP/دامنه بده تا بچرخد و سوخته‌ها کنار بروند.",
 // ws pool inner
 rot_3m:"هر ۳ دقیقه",rot_5m:"هر ۵ دقیقه",rot_10m:"هر ۱۰ دقیقه",rot_15m:"هر ۱۵ دقیقه",rot_30m:"هر ۳۰ دقیقه",rot_1h:"هر ۱ ساعت",rot_4h:"هر ۴ ساعت",rot_8h:"هر ۸ ساعت",rot_off_fo:"خاموش (فقط failover)",
 pool_ip_lbl:"آی‌پی‌های لبهٔ CDN",pool_sni_lbl:"دامنه‌ها (SNI)",pool_ip_min2:"استخر باید حداقل ۲ آی‌پیِ فعال داشته باشد — کمتر از این نمی‌شود",pool_ab_t:"سوختهٔ خودکار",pool_ab_d:"لبهٔ بلاک‌شده خودکار کنار می‌رود و روی backoff دوباره تست می‌شود؛ خوب شد، خودش برمی‌گردد.",
 pool_warm_t:"لبهٔ یدکیِ گرم",pool_warm_d:"یک لبهٔ دومِ آماده در پس‌زمینه نگه می‌دارد؛ لبهٔ فعال که بمیرد، آنی و بدونِ قطعیِ محسوس سوییچ می‌شود. کمی ترافیکِ اضافهٔ ناچیز (فقط keepalive).",
 pool_bad_ip:"آی‌پیِ نامعتبر (مثلاً 104.16.0.1 یا 104.16.0.1:443)",pool_bad_dom:"دامنهٔ نامعتبر (مثلاً cdn.example.com)",pool_need_clean:"استخر به حداقل یک IP تمیز و یک دامنهٔ تمیز نیاز دارد",
 ech_need_wss_alert:"اول wss (TLS به CDN) را روشن کن — ECH داخلِ همان TLS کار می‌کند.",
 // core modal general
 roles_lbl:"نقش‌ها — کدام نود listen کند (سرور)",roles_note1:"نودِ سرور پورتِ",roles_note2:" را باز می‌کند؛ نودِ کلاینت (معمولاً پشتِ NAT) به آن وصل می‌شود.",
 srv_advice:"<b>توصیه: سرور را سمتِ خارج بگذار.</b> اگر نودِ ایران پشتِ NAT باشد یا پورتش فیلتر شود، ایران‌سرور وصل نمی‌شود. اگر آی‌پیِ عمومیِ باز داشته باشد ممکن است کار کند، ولی ورودی به ایران بیشتر فیلتر/پایش می‌شود و کم‌دوام‌تر است.",
 enc_method_lbl:"روشِ رمزنگاری",cipher_ph:"رمز",transport_lbl:"حاملِ اتصال",tr_udp_d:"دیتاگرام",tr_tcp_d:"پایدارتر",tr_raw_d:"پکتِ خام",tr_flux_d:"جهش‌پذیر",tr_dns_d:"آخرین‌پناه",
 dns_zone_lbl:"دامنهٔ واگذارشده (zone)",dns_zone_note:"زیردامنه‌ای که NSِ آن به سرورِ تو واگذار (delegate) شده — سرور همان authoritative NS است. مثلاً <b>t.example.com</b>",dns_resolvers_lbl:"resolverهای بازگشتی (کلاینت)",dns_resolvers_note:"آی‌پیِ resolverهای DNSِ داخلیِ ایران که کلاینت به آن‌ها کوئری می‌زند (با کاما جدا کن). کلاینت هرگز به IPِ سرور بسته نمی‌فرستد — همین آن را از فیلترِ مقصد پنهان می‌کند.",dns_delegation_note:"قبل از استفاده: در registrarِ دامنه، NSِ این zone را به IPِ سرور delegate کن و پورتِ ۵۳ سرور باز باشد. رمزنگاری الزامی است. سرعت کم است ولی در بدترین‌حالت دوام می‌آورد.",dns_need_enc:"حاملِ dns به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)",dns_need_zone:"دامنهٔ dns (zone) را وارد کن — مثلاً t.example.com",dns_need_resolvers:"حداقل یک resolverِ داخلی (IPv4) وارد کن",port_dns_ph:"dns پورت ندارد (۵۳)",
 raw_prof_lbl:"پروفایلِ کپسوله‌سازی (raw)",raw_note:"هر دو طرف باید یک پروفایل داشته باشند. <b>bip</b> بهینه است؛ نقطهٔ طلایی یعنی ممکن است از NAT رد نشود. حاملِ raw به <b>root</b> و رمزنگاری نیاز دارد.",
 raw_proto_lbl:"شمارهٔ پروتکلِ IP (bip)",raw_proto_native:"نیتیو",raw_proto_hint:"bip بدونِ هدرِ L4 است؛ فقط شمارهٔ پروتکلِ بیرونی عوض می‌شود تا از فیلترِ لیستِ‌سفیدِ پروتکل رد شود. پیش‌فرض ۵۸ (ICMPv6) که کرنلِ IPv4 نادیده می‌گیرد. بازهٔ ۱ تا ۲۵۵.",raw_proto_warn:"این شماره پروتکلی است که خودِ سیستم هم به‌کار می‌برد (ICMP/TCP/UDP/ESP/AH) و ممکن است تداخل کند — ۵۸ یا ۲۵۳ امن‌ترند.",raw_proto_bad:"شمارهٔ پروتکلِ IP باید بینِ ۱ تا ۲۵۵ باشد",
 obfs_t:"استتار در برابرِ DPI",obfs_d:"حذفِ امضا · پَدینگ/جیتر · مقاومت در برابرِ probe. رمزنگاری لازم است.",
 cover_t:"پوششِ TLS (شبیهِ HTTPS)",cover_d:"ترافیک شبیهِ HTTPS دیده می‌شود و در برابرِ پروبِ فعال هم مقاوم است. فقط با حاملِ TCP.",
 cover_sni_lbl:"سایتِ پوشش (SNI) — الزامی",cover_sni_ph:"مثلاً یک سایتِ HTTPSِ واقعی و محبوب",
 cover_sni_note1:"سرور برای هر اتصالِ ناشناس (پروب/فیلترچی) <b>واقعاً به این سایت وصل می‌شود</b> و ترافیک را به آن پراکسی می‌کند، پس پروب گواهیِ اصلیِ همان سایت را می‌بیند (مقاوم در برابرِ پروبِ فعال). پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد — ترجیحاً روی یک CDNِ بزرگ.",
 cover_sni_note2:"سرور پروب‌های ناشناس را <b>واقعاً به این سایت وصل و پراکسی می‌کند</b>، پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد (ترجیحاً روی CDNِ بزرگ).",
 gso_t:"شتاب‌دهیِ GSO/GRO",gso_d:"عبورِ حجیم را سریع‌تر می‌کند (پکت‌های بزرگ، syscallِ کمتر). فقط لینوکس؛ اگر پشتیبانی نشود بی‌اثر است.",
 set_gkd:"۳) تشخیصِ مرگ و آستانه‌های خرابی",set_gkdh:"keepalive، مهلتِ ثابت و آستانه‌ها — روی همهٔ تونل‌ها",set_gkdc:"همه",set_t_keepalive:"keepalive (ثانیه)",set_t_keepalive_d:"هر این‌قدر ثانیه یک بستهٔ خیلی کوچک بین دو سرِ تونل رد و بدل می‌شود، فقط برای اینکه معلوم شود هنوز زنده است. تقریباً همهٔ عددهای پایین از روی همین حساب می‌شوند. کم که باشد، قطعیِ تونل زودتر معلوم می‌شود — به قیمتِ ترافیکِ خیلی ناچیز. زیاد که باشد، دیرتر می‌فهمی.",set_x_keepalive:"keepalive=<b>۱۰</b> ← هر ۱۰ث یک پینگ؛ پنجرهٔ خودکار ~۳۰ث سکوت = مرده.",set_t_deadafter:"مهلتِ قطعیِ ثابت (ثانیه)",set_t_deadafter_d:"اگر این‌قدر ثانیه هیچ داده‌ای از آن طرف نیاید، تونل را مرده حساب می‌کند و از نو وصل می‌شود. <b>۰ بگذاری خودش حساب می‌کند</b> — همان که توصیه می‌شود. اگر عددی بگذاری، همان عدد برای همهٔ تونل‌ها استفاده می‌شود و آن‌وقت کارت‌های ۴ و ۵ بی‌اثر می‌شوند.",set_x_deadafter:"۰ ← خودکار (~۳×keepalive). ۲۰ ← همهٔ تونل‌ها پس از ۲۰ث سکوت مرده.",set_da_auto:"۰ = خودکار: پنجرهٔ مرگ از keepalive × ضریب‌های گروه‌های ۴ و ۵ حساب می‌شود.",set_da_fixed:"یک عدد برای همهٔ حامل‌ها: هر تونل پس از {n} ثانیه سکوت مرده است.",set_da_floored:"({v} را نوشتی، ولی کفِ ۲×keepalive آن را به {n} برد.)",set_auto_only:"فقط در حالتِ خودکار — وقتی مهلتِ ثابت = ۰ باشد",set_auto_off:"بی‌اثر — مهلتِ ثابت روشن است",
 core_range_lbl:"سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه)",core_port_lbl:"پورت (خالی=خودکار · می‌توانی 443 بگذاری)",core_port_lbl2:"پورت (می‌توانی 443)",core_subnet_lbl:"سابنتِ داخلی",
 core_edit_note:"ذخیره، تونل را روی هر دو نود از نو می‌سازد (لحظه‌ای قطع می‌شود).",ph_subnet:"مثلا 192.168.99.0/24",
 role_server_word:"سرور",role_client_word:"کلاینت",
 port_flux_ph:"flux پورت ثابت ندارد",port_raw_ph:"raw پورت ندارد",port_ws_ph:"۸۰ (کلادفلر Flexible)",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 pct:"٪",list_sep:"، ",unit_kb:"کیلوبایت",unit_mb_full:"مگابایت",app_title:"tnl · کنترل فلیت",
 ip_toggle_hint:"بزن تا بینِ نامِ نود و اینترفیس جابه‌جا شود",
 // ---- node-add modal
 nadd_auto:"خودکار",nadd_manual:"دستی",nadd_title:"افزودنِ نود",
 nadd_autonote:"مشخصاتِ SSHِ سرورِ نود را بده؛ پنل خودش وارد می‌شود، ایجنت را نصب می‌کند، توکن می‌سازد و نود را وصل می‌کند.",
 nadd_node_name:"نامِ نود",nadd_srv_ip:"آی‌پیِ سرور",nadd_ssh_port:"پورتِ SSH",nadd_ssh_user:"کاربرِ SSH",
 nadd_agent_port:"پورتِ ایجنت",nadd_ctrl_proxy:"پروکسیِ کنترل (اختیاری)",px_type:"نوعِ پروکسی",px_ip:"آی‌پی",px_port:"پورت",px_user:"یوزرنیم",px_pass:"پسورد",px_opt:"اختیاری",px_hint:"یوزر و پسوردِ خالی = بدونِ احراز. پنل از این پروکسی هم برای SSHِ نصب و هم برای کنترلِ نود استفاده می‌کند.",px_need_ipport:"آی‌پی و پورتِ پروکسی لازم است",px_bad_port:"پورتِ پروکسی نامعتبر است (۱ تا ۶۵۵۳۵)",px_bad_cred:"یوزر/پسوردِ پروکسی نباید شاملِ @ : / یا فاصله باشد",nadd_ssh_auth:"احرازِ هویتِ SSH",
 nadd_pass:"رمز",nadd_privkey:"کلیدِ خصوصی",nadd_pass_ph:"رمزِ SSH سرور",
 nadd_pass_hint:"رمزِ SSH سرور — ذخیره نمی‌شود، فقط لحظهٔ نصب استفاده می‌شود.",
 nadd_key_hint:"کلیدِ خصوصیِ SSH — امن‌تر از رمز؛ به sshpass هم نیازی نیست.",
 nadd_manual_name:"نام",nadd_manual_host:"هاست / آی‌پی",nadd_agent_port2:"پورت agent",nadd_node_tok:"توکن نود",
 
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
}});
function T(k){return (k in I18N.fa)?I18N.fa[k]:k}
// ---- backend error translator (Gap 2): backend raises Persian; translate the STATIC ones on the
// client for the EN locale. Unmatched messages (interpolated / dynamic) fall back to the original.
function terr(msg){return msg}
function perr(r){return terr((r.d&&(r.d.error||r.d.msg))||T('failed'))}   // canonical server-error message: error, then msg, then a generic fallback
function vhead(icn,navK,subK){return '<h1>'+ic(icn,'var(--acc)')+' '+esc(T(navK))+'</h1><p class="sub">'+esc(T(subK))+'</p>'}   // page header shared by every *Skel view
function paintThemeBtns(){var d=document.body.classList.contains('dark');var b1=el('thbtn');if(b1)b1.innerHTML=ic(d?'sun':'moon')+' '+esc(T('theme'));var b2=el('thbtn2');if(b2)b2.innerHTML=ic(d?'sun':'moon')}
function paintNav(){try{document.title=T('app_title')}catch(e){}var n=document.getElementById('nav');if(n)n.querySelectorAll('.navi').forEach(function(p){var s=p.querySelector('.nlbl');if(s)s.textContent=T('nav_'+p.dataset.t)});var bs=el('brandsub');if(bs)bs.textContent=T('brand_sub');var fo=el('foutbtn');if(fo){var fl=fo.querySelector('.nlbl');if(fl)fl.textContent=T('nav_logout')}paintThemeBtns()}
(function(){document.documentElement.lang='fa';document.documentElement.dir='rtl';try{document.body.dir='rtl'}catch(e){}})();
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
function fmtup(s){s=+s||0;var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),c=Math.floor(s%60);
 if(d>0)return d+' '+T('fmt_day')+' '+T('fmt_and')+' '+h+' '+T('fmt_hr');   // >=1 روز: روز و ساعت
 if(h>0)return h+' '+T('fmt_hr')+' '+T('fmt_and')+' '+m+' '+T('fmt_min');   // >=1 ساعت: ساعت و دقیقه
 if(m>0)return m+' '+T('fmt_min');                                          // >=1 دقیقه: فقط دقیقه
 return c+' '+T('fmt_sec')}                                                 // <1 دقیقه: فقط ثانیه
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
 g+='<text x="60" y="57" text-anchor="middle" font-size="21" font-weight="800" fill="'+cssv('--tx')+'" font-family="Vazirmatn,Tahoma">'+parts[0][1]+'</text><text x="60" y="76" text-anchor="middle" font-size="10" fill="'+cssv('--sub')+'" font-family="Vazirmatn,Tahoma">'+esc(T('online'))+'</text>';
 svg.innerHTML=g}
function nodeIps(id){var n=NODES.find(function(x){return x.id==id});if(!n||!n.info||!n.info.ips)return [];
 var out=[],ips=n.info.ips;Object.keys(ips).forEach(function(k){(ips[k]||[]).forEach(function(ip){if(out.indexOf(ip)<0)out.push(ip)})});return out}
function ipItems(ips){return ips.map(function(x){return {v:x,label:x}})}

var cur='overview',NODES=[],FLEET=[],FRXHIST=[],FTXHIST=[],PF=[],TT=0,editingId=null,EDID=null,selTargets={},SEL={},SSI={},SSCB={},CHK={},CHECKING=0,UPWIN=1,EVSEQ=0,UIV=2000,EDGEV={},RORD=null,RSAVE=false;   // UIV = live-refresh interval (ms); EDGEV = last active edge per link (anti-flicker); RORD = active card-drag, RSAVE = persisting a reorder
var LIM=25,PG={nodes:0,tunnels:0,portfw:0,agent:0,core:0},QRY={nodes:'',tunnels:'',portfw:'',agent:'',core:''},TOT={nodes:0,tunnels:0,portfw:0,agent:0,core:0},SEARCH_T=0,AGMETA=null,PAL=null,PALIDX=0,PALITEMS=[],PALDATA={nodes:[],tuns:[]};
var _ENUMS=__ENUMS_JSON__;   /* transport families + ciphers, injected from the Python source of truth */
function CORE_CIPHERS(){return _ENUMS.ciphers.map(function(v){return {v:v,label:(v=='auto'?T('cipher_auto'):(v=='none'?T('cipher_none'):v))}})}
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
 // Pool/peer retest-bar denominator must mirror the core's TUNED schedule, not the literals: the summary
 // surfaces the live suspect_backoff / dead_retest_secs (same path as ui_interval above); fall back to defaults.
 if(Array.isArray(s.suspect_backoff)&&s.suspect_backoff.length)_poolBackoff=s.suspect_backoff.map(Number);
 if(s.dead_retest_secs)_poolDeadStep=num(s.dead_retest_secs);
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
function toolbar(kind,ph){var rb=(kind=='core'||kind=='tunnels'||kind=='nodes'||kind=='portfw')?'<button class="reordbtn" title="'+esc(T('reord_t'))+'" onclick="toggleReord()">'+gripSvg()+'</button>':'';
 return '<div class="toolbar"><input id="q_'+kind+'" class="search" placeholder="'+ph+'" value="'+esc(QRY[kind]||'')+'" oninput="onSearch(\\''+kind+'\\')">'+rb+'</div>'}
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
function skNodeCard(){return '<div class="card node acc"><div class="chead">'+   // collapsed node accordion header
  '<span class="sk" style="width:38px;height:22px;border-radius:20px;flex:0 0 auto"></span>'+
  '<span class="grow"></span><div class="hmain" style="gap:6px;min-width:0;flex:0 0 auto">'+skb('90px',14)+skb('150px',11)+'</div>'+
  '<span class="sk" style="width:10px;height:10px;border-radius:50%;flex:0 0 auto"></span>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skAccCard(core){return '<div class="card acc"><div class="chead">'+   // exact collapsed accordion header
  '<span class="sk" style="width:38px;height:22px;border-radius:20px;flex:0 0 auto"></span>'+
  '<div class="hmain"><div class="hrow1">'+skb('96px',13)+skb('40px',15,20)+
    '<span style="margin-inline-start:auto;display:flex;align-items:center;gap:5px">'+skb('58px',11)+'<span class="sk" style="width:14px;height:8px"></span>'+skb('58px',11)+'</span></div></div>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skPfCard(){return '<div class="card acc"><div class="chead">'+     // collapsed port-forward accordion header (no on/off toggle)
  '<div class="hmain"><div class="hrow1">'+skb('90px',13)+skb('40px',15,20)+
    '<span style="margin-inline-start:auto;display:flex;align-items:center;gap:5px">'+skb('54px',12)+skb('60px',18,20)+'</span></div></div>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skAgRow(){return '<div class="agx-row">'+             // exact agent/update row
  '<div class="agx-right"><div class="agx-l1"><span class="sk" style="width:9px;height:9px;border-radius:50%"></span>'+skb('92px',13)+skb('42px',16,6)+'</div>'+
  '<div class="agx-l2">'+skb('118px',15,7)+skb('118px',15,7)+'</div></div>'+
  '<div class="agx-colb">'+skb('86px',26,9)+skb('86px',26,9)+'</div></div>'}
function skCards(kind){
 var arr=(kind=='nodes'?NODES:kind=='portfw'?PF:kind=='agent'?NODES:FLEET)||[];
 var n=Math.max(3,Math.min(8,num(arr.length)||6));
 var one=kind=='nodes'?skNodeCard:kind=='portfw'?skPfCard:kind=='agent'?skAgRow:function(){return skAccCard(kind=='core')};
 var out='';for(var i=0;i<n;i++)out+=one();return out}   // direct children of the list grid — no wrapper
function overviewSkel(){el('view').innerHTML=vhead('dash','nav_overview','ov_sub')+
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
function nodesSkel(){el('view').innerHTML=vhead('server','nav_nodes','nodes_sub')+
 '<button class="primary" onclick="openNodeAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+esc(T('add_node'))+'</button>'+
 '<div class="sec">'+ic('server','var(--acc)')+' '+esc(T('nodes_fleet'))+'</div>'+toolbar('nodes',T('nodes_search'))+'<div id="nodeList">'+skCards('nodes')+'</div>'+pagerBottom('nodes')}
var _naddMode='auto';
function openNodeAddModal(){_naddMode='auto';_authMode='pass';_installDone=null;_instStop();
 var seg='<div class="seg" id="nadd_seg"><button data-m="auto" class="on" onclick="naddSwitch(\\'auto\\')">'+ic('bolt')+esc(T('nadd_auto'))+'</button><button data-m="manual" onclick="naddSwitch(\\'manual\\')">'+ic('pen')+esc(T('nadd_manual'))+'</button></div>';
 var auto='<div id="nadd_auto">'+
   '<div class="autonote">'+ic('bolt')+'<span>'+esc(T('nadd_autonote'))+'</span></div>'+
   '<div class="grid2"><div><label class="first">'+esc(T('nadd_node_name'))+'</label><input id="a_name" placeholder="DE02"></div><div><label class="first">'+esc(T('nadd_srv_ip'))+'</label><input id="a_host" placeholder="5.75.197.55"></div></div>'+
   '<div class="grid2"><div><label>'+esc(T('nadd_ssh_port'))+'</label><input id="a_sshport" placeholder="22"></div><div><label>'+esc(T('nadd_ssh_user'))+'</label><input id="a_user" placeholder="root"></div></div>'+
   '<div class="grid2"><div><label>'+esc(T('nadd_agent_port'))+'</label><input id="a_aport" placeholder="8099"></div><div></div></div>'+
   proxyBlock('a_')+
   '<div class="authbox"><div class="authhd"><span class="t">'+esc(T('nadd_ssh_auth'))+'</span><span class="authseg" id="a_authseg"><button type="button" data-am="pass" class="on" onclick="authMode(\\'pass\\')">'+esc(T('nadd_pass'))+'</button><button type="button" data-am="key" onclick="authMode(\\'key\\')">'+esc(T('nadd_privkey'))+'</button></span></div>'+
    '<input id="a_pass" class="fld2" type="password" placeholder="'+esc(T('nadd_pass_ph'))+'" autocomplete="new-password">'+
    '<textarea id="a_key" class="fld2" rows="3" style="display:none" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>'+
    '<div class="muted" id="a_authhint" style="font-size:11px;margin-top:7px">'+esc(T('nadd_pass_hint'))+'</div></div>'+
   '<div id="nadd_prog"></div></div>';
 var manual='<div id="nadd_manual" style="display:none"><div class="grid2"><div><label class="first">'+esc(T('nadd_manual_name'))+'</label><input id="n_name" placeholder="frankfurt-1"></div><div><label class="first">'+esc(T('nadd_manual_host'))+'</label><input id="n_host" placeholder="203.0.113.10"></div></div><div class="grid2"><div><label>'+esc(T('nadd_agent_port2'))+'</label><input id="n_port" placeholder="8099"></div><div><label>'+esc(T('nadd_node_tok'))+'</label><input id="n_tok" placeholder="'+esc(T('nadd_node_tok'))+'"></div></div>'+proxyBlock('n_')+'</div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>'+esc(T('nadd_title'))+'</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+seg+auto+manual+'<div class="msg" id="n_msg"></div></div><div class="mfoot"><button class="primary" id="nadd_go" onclick="naddSubmit()">'+ic('bolt')+esc(T('nadd_install_connect'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');pxReset('a_',false,'socks5');pxReset('n_',false,'socks5')}
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
// ---- control-proxy toggle (add/manual/edit share this). Stored as a scheme://[user:pass@]host:port
// URL (so the backend parser, redaction and SSH-ProxyCommand relay stay unchanged); the fields are UI.
var _pxOn={},_pxSch={};
function proxyBlock(pfx){return '<div class="authbox" style="margin-top:14px"><div class="authhd"><span class="t">'+esc(T('nadd_ctrl_proxy'))+'</span><span class="tglsw" id="'+pfx+'pxsw" style="margin-inline-start:auto" onclick="pxTgl(\\''+pfx+'\\')"></span></div>'
 +'<div id="'+pfx+'pxbody" style="display:none">'
 +'<div class="authhd" style="margin-bottom:11px"><span class="t" style="font-size:11.5px;font-weight:700;color:var(--sub)">'+esc(T('px_type'))+'</span><span class="authseg" id="'+pfx+'pxseg"><button type="button" data-ps="socks5" class="on" onclick="pxSch(\\''+pfx+'\\',\\'socks5\\')">SOCKS5</button><button type="button" data-ps="http" onclick="pxSch(\\''+pfx+'\\',\\'http\\')">HTTP</button></span></div>'
 +'<div class="grid2"><div><label>'+esc(T('px_ip'))+'</label><input id="'+pfx+'pxip" dir="ltr" placeholder="10.202.10.202"></div><div><label>'+esc(T('px_port'))+'</label><input id="'+pfx+'pxport" dir="ltr" placeholder="1080"></div></div>'
 +'<div class="grid2" style="margin-top:11px"><div><label>'+esc(T('px_user'))+'</label><input id="'+pfx+'pxuser" dir="ltr" placeholder="'+esc(T('px_opt'))+'" autocomplete="off"></div><div><label>'+esc(T('px_pass'))+'</label><input id="'+pfx+'pxpass" dir="ltr" type="password" placeholder="'+esc(T('px_opt'))+'" autocomplete="new-password"></div></div>'
 +'<div class="muted" style="font-size:11px;margin-top:8px">'+esc(T('px_hint'))+'</div></div></div>';}
function pxTgl(pfx){var on=!_pxOn[pfx];_pxOn[pfx]=on;var s=el(pfx+'pxsw');if(s)s.classList.toggle('on',on);var b=el(pfx+'pxbody');if(b)b.style.display=on?'':'none';}
function pxSch(pfx,val){_pxSch[pfx]=val;var seg=el(pfx+'pxseg');if(seg)Array.prototype.forEach.call(seg.querySelectorAll('button'),function(x){x.classList.toggle('on',x.getAttribute('data-ps')==val);});}
function pxReset(pfx,on,scheme){_pxOn[pfx]=!!on;var s=el(pfx+'pxsw');if(s)s.classList.toggle('on',!!on);var b=el(pfx+'pxbody');if(b)b.style.display=on?'':'none';pxSch(pfx,scheme||'socks5');}
// returns '' (off), a scheme://[user:pass@]ip:port URL, or {err} on bad input
function pxCollect(pfx){if(!_pxOn[pfx])return '';var ip=(v(pfx+'pxip')||'').trim(),port=(v(pfx+'pxport')||'').trim();
 if(!ip||!port)return {err:T('px_need_ipport')};
 if(!/^[0-9]{1,5}$/.test(port)||+port<1||+port>65535)return {err:T('px_bad_port')};
 var u=(v(pfx+'pxuser')||'').trim(),w=(v(pfx+'pxpass')||'');
 if(/[@:\\/\\s]/.test(u)||/[@\\/\\s]/.test(w))return {err:T('px_bad_cred')};
 var auth=u?(u+(w?':'+w:'')+'@'):'';var h=ip.indexOf(':')>=0?('['+ip.replace(/^\\[|\\]$/g,'')+']'):ip;return (_pxSch[pfx]||'socks5')+'://'+auth+h+':'+port;}
// prefill fields from a stored (possibly credential-redacted) URL
function pxPrefill(pfx,url){url=(url||'').trim();if(!url){pxReset(pfx,false,'socks5');return;}
 var m=url.match(/^(socks5h?|http|https|connect):\\/\\/(?:([^:@\\/]*)(?::([^@\\/]*))?@)?(\\[[^\\]]+\\]|[^:\\/]+):([0-9]+)/i);
 if(!m){pxReset(pfx,true,'socks5');if(el(pfx+'pxip'))el(pfx+'pxip').value=url;return;}
 pxReset(pfx,true,/^socks/i.test(m[1])?'socks5':'http');
 if(el(pfx+'pxip'))el(pfx+'pxip').value=(m[4]||'').replace(/^\\[|\\]$/g,'');
 if(el(pfx+'pxport'))el(pfx+'pxport').value=m[5]||'';
 if(el(pfx+'pxuser'))el(pfx+'pxuser').value=m[2]||'';
 if(el(pfx+'pxpass'))el(pfx+'pxpass').value=m[3]||'';}
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
 var _px=pxCollect('a_');if(_px&&_px.err){m.className='msg err';m.textContent=_px.err;return}
 _installDone=null;m.className='msg';m.textContent='';agBtnBusy(btn,true);
 // show the FIRST step (SSH), spinning, the instant install is clicked — no "در حالِ نصب…" placeholder gap
 var _st0=_insteps()[0];
 var pr=el('nadd_prog');if(pr){pr.innerHTML='<div class="iwrap"><div class="ibanner run"><span class="ispin"></span><span>'+esc(T('inst_installing'))+'</span></div><div class="istep run"><span class="istep-i run"><span class="ispin"></span></span><div class="istep-b"><div class="istep-t">'+esc(_st0.label)+'</div><div class="istep-s">'+esc(_st0.detail)+'</div></div></div></div>';pr.scrollIntoView({behavior:'smooth',block:'center'})}
 var r=await post('node-install',{name:name,ssh_host:host,ssh_port:v('a_sshport'),ssh_user:v('a_user'),agent_port:v('a_aport'),ssh_pass:pass,ssh_key:key,proxy:_px}).catch(function(){return{ok:false,d:{}}});
 if(!(r.ok&&r.d.ok)){m.className='msg err';m.textContent=terr((r.d&&r.d.error))||T('failed');if(pr)pr.innerHTML='';agBtnBusy(btn,false,ic('bolt')+esc(T('nadd_install_connect')));return}
 // seed step 0 as revealed+running so the reveal continues seamlessly from the skeleton (no flicker back to the banner)
 _inst={job:r.d.job,steps:_insteps().map(function(s){return{label:s.label,detail:s.detail}}),confirmed:['run','wait','wait','wait'],banner:T('inst_installing'),bDone:false,bOk:false,err:'',revealIdx:1,lastReveal:_instNow(),lastPoll:0,polling:false,failN:0,finished:false,cancelled:false,timer:null};
 _instTick()}
async function refreshNodes(){if(editingId||RORD||RSAVE)return;var r=await j('nodes?offset='+(PG.nodes*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.nodes));NODES=r.nodes||[];TOT.nodes=num(r.total);UPWIN=num(r.uptime_window)||1;var box=el('nodeList');if(!box)return;
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
 var b='<div class="grid2"><div><label class="first">'+esc(T('f_name'))+'</label><input id="e_name_'+id+'" value="'+esc(n.name)+'"></div><div><label class="first">'+esc(T('f_host_ip'))+'</label><input id="e_host_'+id+'" value="'+esc(n.host)+'"></div></div><div class="grid2"><div><label>'+esc(T('f_port'))+'</label><input id="e_port_'+id+'" value="'+esc(n.port)+'"></div><div><label>'+esc(T('f_token'))+'</label><input id="e_tok_'+id+'" placeholder="'+esc(T('tok_keep'))+'"></div></div>'+proxyBlock('ne_')+'<div class="msg" id="em_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('nd_edit'))+'</h3><div class="sb">'+esc(n.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="saveEdit(\\''+id+'\\')">'+esc(T('save'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');pxPrefill('ne_',n.proxy||'')}
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
 var key=n.id,open=!!TOPEN[key];
 var en=(n.disabled!==true);   // shown in the create-tunnel/portfw pickers unless the operator hid it
 var dotk=n.online?'on':(n.pending?'':'off');   // green / grey(pending) / red — replaces the old آنلاین text badge
 var head='<div class="chead" onclick="cardTogFromEl(this)">'+grip()+'<div class="tsw'+(en?' on':'')+'" onclick="toggleNode(\\''+n.id+'\\',event)" title="'+esc(T('nd_toggle'))+'"></div><span class="grow"></span><div class="hmain" style="direction:ltr;align-items:flex-start;gap:2px;flex:0 0 auto;min-width:0"><div class="name" style="text-align:left">'+esc(n.name)+(n.pending_del>0?' <span class="tag" style="font-size:9px;padding:1px 5px;background:color-mix(in srgb,#e0894f 18%,transparent);color:#e0894f" title="'+esc(T('pend_del_t'))+'">'+ic('trash')+num(n.pending_del)+'</span>':'')+(n.proxy?' <span class="tag" style="font-size:9.5px;padding:1px 6px">'+esc(T('proxy'))+'</span>':'')+'</div><div class="muted mono" style="font-size:12px">'+esc(n.host)+':'+esc(n.port)+'</div></div>'+'<span class="ndot '+dotk+'" title="'+esc(n.online?T('online'):(n.pending?T('pending_check'):T('offline')))+'"></span>'+CHEVI+'</div>';
 var body=n.online?'<div class="nchips"><span class="nchip">'+ic('link')+esc(T('nd_tunnels'))+' <b>'+num(i.tunnels)+'</b></span><span class="nchip">'+ic('globe')+esc(T('nd_portfw'))+' <b>'+num(i.portfw)+'</b></span>'+(i.version?'<span class="nchip">'+ic('cpu')+esc(T('nd_agent'))+' v<b>'+num(i.version)+'</b></span>':'')+((i.core_sha&&String(i.core_sha).length)?'<span class="nchip">'+ic('cpu')+esc(T('nd_core'))+' <b>'+esc(i.core_ver||'?')+'</b></span>':'<span class="nchip" style="color:var(--sub)">'+ic('cpu')+esc(T('nd_core'))+' <b>'+esc(T('nd_core_missing'))+'</b></span>')+'</div>':'<div class="noff">'+ic('plugoff')+'<b>'+esc(T('not_available'))+'</b>'+(i.error?'<span>· '+esc(i.error)+'</span>':'')+'</div>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_test'))+'" onclick="testNode(\\''+n.id+'\\')">'+ic('bolt')+'</button>'+(n.online?'<button class="act" title="'+esc(T('tip_tune'))+'" onclick="kernelTune(\\''+n.id+'\\')">'+ic('activity')+'</button>':'')+'<button class="act info" title="'+esc(T('tip_details'))+'" onclick="nodeDetails(\\''+n.id+'\\')">'+ic('info')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" onclick="openNodeEdit(\\''+n.id+'\\')">'+ic('pen')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" data-nid="'+esc(n.id)+'" data-nm="'+esc(n.name)+'" data-online="'+(n.online?'1':'0')+'" onclick="delNode(this)">'+ic('trash')+'</button></div>';
 return '<div class="card node acc'+(open?' open':'')+(en?'':' off')+'" id="c_'+esc(key)+'" data-rid="'+esc(key)+'" data-rk="nodes">'+head+'<div class="cbody"><div class="cbody-in">'+body+upBar(n)+acts+'<div class="msg" id="ntm_'+n.id+'"></div></div></div></div>'}
async function toggleNode(id,e){e.stopPropagation();var n=NODES.filter(function(x){return x.id==id})[0];if(!n)return;  // hide/show in the create pickers — never disconnects
 var dis=!(n.disabled===true);n.disabled=dis;
 var c=el('c_'+id);if(c){var sw=c.querySelector('.tsw');if(sw)sw.classList.toggle('on',!dis);c.classList.toggle('off',dis)}
 var r=await post('node-toggle',{id:id,disabled:dis});
 if(!(r.ok&&r.d.ok)){n.disabled=!dis;if(c){var s2=c.querySelector('.tsw');if(s2)s2.classList.toggle('on',dis);c.classList.toggle('off',!dis)}toast(T('failed'),'err')}
 else{toast(dis?T('nd_hidden'):T('nd_shown'),'ok')}}
function upBar(n){var r=n.uptime||[];  // 60 cells: 1=up(green), 0=down(red), null=no-data(gray)
 var pct=(n.uptime_pct!=null)?n.uptime_pct:100;  // TIME-WEIGHTED % from the server (a 5s blip != a whole red cell)
 var cells=r.map(function(v){return '<i class="'+(v==null?'g':(v?'':'d'))+'"></i>'}).join('');
 return '<div class="upwrap"><div class="uptop">'+esc(T('uptime_bar'))+'<b style="margin-inline-start:6px">'+pct+T('pct')+'</b><span class="r">'+UPWIN+' '+esc(T('ov_hours_recent'))+'</span></div><div class="upbar">'+cells+'</div></div>'}
async function saveEdit(id){var m=el('em_'+id);var name=v('e_name_'+id),host=v('e_host_'+id),port=v('e_port_'+id),tok=v('e_tok_'+id);
 if(!name||!host||!port){m.className='msg err';m.textContent=T('need_nhp');return}
 var _px=pxCollect('ne_');if(_px&&_px.err){m.className='msg err';m.textContent=_px.err;return}
 m.className='msg';m.textContent=T('saving');
 var r=await post('node-edit',{id:id,name:name,host:host,port:port,token:tok,proxy:_px});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=terr(r.d.error||T('failed'))}}
async function addNode(){var m=el('n_msg');var name=v('n_name'),host=v('n_host'),port=v('n_port'),tok=v('n_tok');
 if(!name||!host||!port||!tok){m.className='msg err';m.textContent=T('need_all_nhpt');return}
 var _px=pxCollect('n_');if(_px&&_px.err){m.className='msg err';m.textContent=_px.err;return}
 m.className='msg';m.textContent=T('connecting_dots');
 var r=await post('node-add',{name:name,host:host,port:port,token:tok,proxy:_px});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('node_added')+(r.d.online?T('node_added_online'):T('node_added_offline')+terr(r.d.error||'')),r.d.online?'ok':'err')}
 else{m.className='msg err';m.textContent=terr(r.d.error||T('failed'))}}
async function testNode(id){var m=el('ntm_'+id);if(m){m.className='msg';m.textContent=T('test_testing')}
 var r=await post('node-test',{id:id});
 var info=(r.d&&r.d.info)||{};if(!m)return;
 // Online: show the SERVER-measured panel->node RTT (the real control-plane ping). Offline: show only the
 // reason — a timed-out request has no latency to report, so no misleading "· 8164ms" on a dead node.
 if(r.d&&r.d.ok){var ms=info.rtt_ms;m.className='msg ok';m.innerHTML=CK+esc(' '+T('online')+' — '+(info.hostname||'')+(ms!=null?' · '+ms+'ms':''))}
 else{m.className='msg err';m.textContent=T('offline')+': '+(terr(info.error)||T('not_available'))}}
function kernelTune(id){post('node-kernel-tune',{id:id,action:'status'}).then(function(r){
 if(!(r.ok&&r.d.ok)){toast(terr((r.d&&r.d.error)||T('failed')),'err');return}
 ktShow(id,r.d)})}
function ktRows(s){var active=!!s.active,cc=esc(s.cc||'?'),qd=esc(s.qdisc||'?');
 var chip=active?'<span class="tag" style="background:color-mix(in srgb,#3fb984 20%,transparent);color:#3fb984">'+esc(T('kt_on'))+'</span>':'<span class="tag" style="color:var(--sub)">'+esc(T('kt_off'))+'</span>';
 var row=function(lbl,val){return '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px"><span class="muted" style="font-size:12.5px">'+esc(lbl)+'</span>'+val+'</div>'};
 return '<div style="display:flex;flex-direction:column;gap:9px;padding:11px 13px;border:1px solid rgba(255,255,255,.08);border-radius:11px">'+row(T('kt_state'),chip)+row(T('kt_cc'),'<b class="mono">'+cc+'</b>')+row(T('kt_qdisc'),'<b class="mono">'+qd+'</b>')+'</div>'}
function ktShow(id,s){var ex=document.querySelector('.modal.ktmodal');if(ex)closeModal(ex.closest('.modalov'));  // never stack two kt modals (double-click / re-render)
 var bbr=!!s.bbr_available,active=!!s.active;
 var note=bbr?'':'<div class="msg err" style="margin-top:9px">'+esc(T('kt_nobbr'))+'</div>';
 var btn=active?'<button class="ghost" onclick="ktDo(this,\\''+id+'\\',\\'revert\\')">'+ic('reset')+esc(T('kt_disable'))+'</button>'
  :'<button class="primary"'+(bbr?'':' disabled')+' onclick="ktDo(this,\\''+id+'\\',\\'apply\\')">'+ic('activity')+esc(T('kt_enable'))+'</button>';
 openModal('<div class="msticky"><span class="medi">'+ic('activity')+'</span><div class="ttl"><h3>'+esc(T('kt_title'))+'</h3><div class="sb">'+esc(T('kt_sub'))+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody"><div class="muted" style="font-size:12.5px;line-height:1.75;margin-bottom:12px">'+esc(T('kt_desc'))+'</div>'+ktRows(s)+note+'<div class="msg kt_msg"></div></div><div class="mfoot"><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('kt_close'))+'</button>'+btn+'</div>',{cls:'ktmodal'})}
async function ktDo(btn,id,action){var ov=btn.closest('.modalov'),m=ov?ov.querySelector('.kt_msg'):null;  // resolve controls from THIS modal, not a global id (two kt modals could share it)
 btn.disabled=true;if(m){m.className='msg kt_msg';m.textContent=T('kt_working')}
 var r=await post('node-kernel-tune',{id:id,action:action});
 if(r.ok&&r.d.ok){toast(action=='apply'?T('kt_enabled'):T('kt_disabled'),'ok');
  if(ov&&document.body.contains(ov))ktShow(id,r.d)}  // re-render fresh state (ktShow closes this one first); skip if the operator dismissed it mid-request
 else{if(m){m.className='msg err kt_msg';m.textContent=terr((r.d&&r.d.error)||T('failed'))}btn.disabled=false}}
function doForceWipe(id){return confirmBox(T('del_wipe_force_ask'),T('del_wipe_force_yes')).then(function(ok){if(ok)return doDelNode(id,true,true)})}
function delNode(btn){var id=btn.getAttribute('data-nid');var nm=btn.getAttribute('data-nm');var offline=btn.getAttribute('data-online')==='0';
 // Node OFFLINE -> the destructive option is best-effort force-wipe DIRECTLY (one confirm, no doomed full-wipe + timeout).
 var wipeOpt=offline
  ?'<button type="button" class="delopt danger" onclick="doForceWipe(\\''+id+'\\')"><div class="do-t">'+ic('warn')+esc(T('del_wipe_force_yes'))+'</div><div class="do-s">'+esc(T('del_wipe_force_s'))+'</div></button>'
  :'<button type="button" class="delopt danger" onclick="doDelNode(\\''+id+'\\',true)"><div class="do-t">'+ic('warn')+esc(T('del_wipe_t'))+'</div><div class="do-s">'+esc(T('del_wipe_s'))+'</div></button>';
 var b='<div class="muted" style="font-size:12.5px;margin-bottom:13px">'+esc(T('del_how'))+'</div>'+
  '<button type="button" class="delopt" onclick="doDelNode(\\''+id+'\\',false)"><div class="do-t">'+ic('logout')+esc(T('del_detach_t'))+'</div><div class="do-s">'+esc(T('del_detach_s'))+'</div></button>'+
  wipeOpt+
  '<div class="msg" id="del_msg"></div>';
 openModal('<div class="msticky"><span class="medi medi-bad">'+ic('trash')+'</span><div class="ttl"><h3>'+esc(T('nd_del'))+'</h3><div class="sb">'+esc(nm)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
async function doDelNode(id,wipe,force){var m=el('del_msg');
 if(wipe&&!force&&!await confirmBox(T('del_wipe_confirm'),T('del_wipe_yes')))return;
 if(m){m.className='msg';m.textContent=(wipe?(force?T('del_force_wiping'):T('del_wiping')):T('del_detaching'))}
 document.querySelectorAll('.delopt').forEach(function(b){b.disabled=true});
 var r=await post('node-del',{id:id,wipe:wipe,wipe_force:!!force});
 if(r.ok&&r.d.ok){editingId=null;var ov=m?m.closest('.modalov'):null;
  toast(wipe?((r.d.node_wiped===false)?T('node_force_wiped'):T('node_wiped')):T('node_detached'),'ok');
  if(ov)closeModal(ov);else refreshNodes();return}
 document.querySelectorAll('.delopt').forEach(function(b){b.disabled=false});
 if(m){m.className='msg err';m.textContent=terr((r.d&&r.d.error)||T('failed'))}}

// ===== Tunnels
function tunnelsSkel(){CHK={};el('view').innerHTML=vhead('link','nav_tunnels','tun_sub')+
 '<div class="tbtnrow"><button class="primary" onclick="openCreateModal()">'+ic('plus')+esc(T('add_tunnel'))+'</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+esc(T('check_all'))+'</button></div>'+
 toolbar('tunnels',T('tun_search'))+'<div id="linkList">'+skCards('tunnels')+'</div>'+pagerBottom('tunnels')}
function fmtms(x){return (x>=10?Math.round(x):Math.round(x*10)/10)+'ms'}
function pingInfo(h){var p=[];if(h.rtt_ms!=null)p.push(T('t_ping')+' '+fmtms(h.rtt_ms));if(h.loss_pct!=null)p.push(h.loss_pct>0?(T('t_loss')+' '+(Math.round(h.loss_pct*10)/10)+T('pct')):T('t_noloss'));return p.join(' · ')}
function sideTxt(online,h){
 if(!online)return T('t_side_off');
 if(!h)return T('t_side_notun');
 if(h.up==null)return T('checking');
 if(!h.up)return T('t_side_ifdown');
 if(h.dead)return T('st_disc');   // frozen core heartbeat = the encrypted session died (peer gone)
 if(h.alive===true){var e2=pingInfo(h);return T('t_side_conn')+(e2?' · '+e2:'')}   // alive via heartbeat/traffic-flow (ICMP maybe unrun/filtered)
 if(h.alive===false)return T('t_side_nopingr')+(h.loss_pct!=null?' ('+T('t_loss')+' '+(Math.round(h.loss_pct)||100)+T('pct')+')':'');
 return T('t_side_up_unk')}
function sideState(online,h){  // k: dot color class, w: the word to show ONLY when there's a problem
 if(!online||!h)return {k:'bad',w:T('st_disc')};
 if(h.up==null)return {k:'na',w:'…'};
 if(!h.up)return {k:'bad',w:T('st_disc')};
 if(h.dead)return {k:'bad',w:T('st_disc')};       // confirmed dead (frozen core heartbeat) -> red at once
 if(h.alive===true)return {k:'ok',w:''};          // PROVEN alive (core heartbeat / real traffic / probe answered) -> green
 if(h.alive===false)return {k:'warn',w:''};       // up but not proven live yet (connecting, or no traffic + probe failed) -> yellow
 return {k:'warn',w:''}}   // no positive proof of life (unknown / still connecting) -> yellow, never green by default
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
function cardTogFromEl(elm){var c=elm.closest&&elm.closest('.card[data-rid]');if(!c)return;var id=c.getAttribute('data-rid');TOPEN[id]=!TOPEN[id];c.classList.toggle('open',TOPEN[id])}  // portfw head: derive the key from data-rid (no fragile onclick string)
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
 var typ=isCore?'<span class="ctag core">Core</span>':'<span class="ctag '+esc(l.type||'')+'">'+esc((l.type||'').toUpperCase())+'</span>';
 var off=on?'':'<span class="offtxt" style="font-size:11px">'+esc(T('st_off'))+'</span>';
 return '<div class="chead" onclick="cardTog(\\''+l.id+'\\',event)">'+grip()+
  '<div class="tsw'+(on?' on':'')+'" onclick="toggleLink(\\''+l.id+'\\',event)" title="'+esc(T('tip_toggle'))+'"></div>'+
  '<div class="hmain"><div class="hrow1"><span class="hname">'+esc(l.name)+'</span>'+typ+off+
   '<span class="hpeers" dir="ltr">'+accDot(l,'a')+esc(l.a_name)+' ↔ '+esc(l.b_name)+accDot(l,'b')+'</span></div></div>'+CHEVI+'</div>'}
function accBodyTraf(l){if(l.enabled===false)return '<div class="offbadge">'+ic('warn','var(--bad)')+'<span>'+esc(T('tun_off_note'))+'</span></div>';
 var hasT=(l.rx_total!=null||l.rx_bps!=null);
 var tot=hasT?'<span class="iso"><b class="din">↓'+fmtBytes(l.rx_total)+'</b><b class="dout">↑'+fmtBytes(l.tx_total)+'</b></span>':'<b class="mono">—</b>';
 var rates=hasT?'<span class="din iso">↓ '+fmtRate(l.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(l.tx_bps)+'</span>':'<span class="muted" style="font-size:11px">'+esc(T('no_live_side'))+'</span>';
 return '<div class="ltraf">'+rates+'<span class="tot">'+esc(T('total'))+' '+tot+'</span></div>'}
function accShell(l,isCore,inner){var open=!!TOPEN[l.id];
 return '<div class="card acc'+(l.enabled===false?' off':'')+(open?' open':'')+'" id="c_'+l.id+'" data-rid="'+esc(l.id)+'" data-rk="'+(isCore?'core':'tunnels')+'">'+accHead(l,isCore)+
  '<div class="cbody"><div class="cbody-in">'+inner+'</div></div></div>'}
function linkFooter(l,editFn){
 var c=CHK[l.id];var msg='<div class="msg '+(c?c.cls:'')+'" id="lchk_'+l.id+'">'+(c?c.html:'')+'</div>';
 var flip='<button class="act flip" onclick="flipView(\\''+l.id+'\\')" title="'+esc(T('tip_flip'))+esc(l.view_name||'—')+'">'+ic('swap')+'</button>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_ping'))+'" onclick="checkLink(\\''+l.id+'\\')">'+ic('activity')+'</button>'+flip+'<button class="act reset" title="'+esc(T('tip_reset'))+'" onclick="resetTraffic(\\''+l.id+'\\')">'+ic('reset')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" onclick="'+editFn+'(\\''+l.id+'\\')">'+ic('pen')+'</button><button class="act" title="'+esc(T('tip_rebuild'))+'" onclick="rebuildLink(\\''+l.id+'\\')">'+ic('redo')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" onclick="delLink(\\''+l.id+'\\')">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>'+esc(T('drift_note'))+'</span></div>':'';
 return {drift:drift,acts:acts,msg:msg}}
function linkCard(l){
 var body='<div class="tninfo">'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="stat" id="lba_'+l.id+'">'+accStat(l,'a')+'</span></div><div class="tna mono">'+esc(l.a_ip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="stat" id="lbb_'+l.id+'">'+accStat(l,'b')+'</span></div><div class="tna mono">'+esc(l.b_ip)+'</div></div>'+
  '</div>'+
  metaCols(l);
 var F=linkFooter(l,'openLinkEdit');
 return accShell(l,false,F.drift+body+accBodyTraf(l)+F.acts+F.msg)}
async function refreshTunnels(){if(editingId||CHECKING||RORD||RSAVE)return;var f=await j('fleet?kind=tunnels&offset='+(PG.tunnels*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.tunnels));FLEET=f.links||[];TOT.tunnels=num(f.total);var box=el('linkList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(linkCard).join(''):'<div class="card muted">'+(QRY.tunnels?T('no_results'):T('tun_empty'))+'</div>');renderPager('tunnels')}
async function saveLinkEdit(id){var m=el('lem_'+id);var type=ssVal('lt_'+id),subnet=v('e_sub_'+id);
 if(!type){m.className='msg err';m.textContent=T('tun_type');return}
 var L=FLEET.find(function(x){return x.id==id})||{};
 var a_ip=ssVal('lipa_'+id)||L.a_ip||'',b_ip=ssVal('lipb_'+id)||L.b_ip||'';
 m.className='msg';m.textContent=T('rebuilding_both');
 var body={id:id,type:type,subnet:subnet,a_ip:a_ip,b_ip:b_ip};var pe=el('le_port_'+id);if(pe)body.port=pe.value.trim();
 var r=await post('edit-link',body);
 if(r.ok&&r.d.ok){delete CHK[id];closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=perr(r)}}
function setChk(id,cls,html){CHK[id]={cls:cls,html:html};var m=el('lchk_'+id);if(m){m.className='msg '+cls;m.innerHTML=html}}
function chkLines(hdr,a,b){return '<div class="chh">'+hdr+'</div><div class="chl">'+esc(a)+'</div><div class="chl">'+esc(b)+'</div>'}
async function checkLink(id){CHECKING++;
 try{
  setChk(id,'',esc(T('checking_conn')));
  var r=await post('check-link',{id:id});
  var L=FLEET.filter(function(x){return x.id==id})[0]||{};
  if(!(r.ok&&r.d.ok)){setChk(id,'err',esc(perr(r)));return}
  var d=r.d,ab=el('lba_'+id),bb=el('lbb_'+id);
  if(ab)ab.innerHTML=sideDot(d.a_online,d.a_health);if(bb)bb.innerHTML=sideDot(d.b_online,d.b_health);
  var aup=d.a_online&&d.a_health&&d.a_health.up,bup=d.b_online&&d.b_health&&d.b_health.up;
  var pinged=(d.a_health&&d.a_health.alive===true)||(d.b_health&&d.b_health.alive===true);
  var okAll=aup&&bup&&pinged&&!(d.a_health&&d.a_health.dead)&&!(d.b_health&&d.b_health.dead);
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
async function resetTraffic(id){if(!await confirmBox(T('reset_confirm')))return;var r=await post('traffic-reset',{id:id});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshFleet()}else{toast(perr(r),'err')}}
async function resetPfTraffic(i){var p=PF[i];if(!p)return;if(!await confirmBox(T('pf_reset_confirm')))return;var r=await post('traffic-reset',{node:p.node_id,name:p.name});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshPortfw()}else{toast(perr(r),'err')}}
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
async function delLink(id){
 var l=FLEET.filter(function(x){return x.id==id})[0]||{};
 if(l.a_online===false||l.b_online===false){          // an endpoint is KNOWN-offline -> straight to force: one dialog, no wait
  if(!await confirmBox(T('del_force_ask'),T('del_force_yes')))return;
  var rf=await post('delete-link',{id:id,force:true});
  if(rf.d&&rf.d.msg)toast(rf.d.msg,(rf.d.ok?'ok':'err'));else if(!(rf.d&&rf.d.ok))toast(perr(rf),'err');
  delete CHK[id];editingId=null;refreshFleet();return}
 if(!await confirmBox(T('del_tun_confirm')))return;   // both endpoints online -> normal delete
 var r=await post('delete-link',{id:id});
 if(r.d&&r.d.msg)toast(r.d.msg,(r.d.ok?'ok':'err'));else if(!(r.d&&r.d.ok))toast(perr(r),'err');
 delete CHK[id];editingId=null;refreshFleet()}

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
 else{m.className='msg err';m.textContent=perr(r)}}

// ===== Custom core (packet/core) — its own view, list and create form
function coreSkel(){CHK={};el('view').innerHTML=vhead('cpu','nav_core','core_sub')+
 '<div class="tbtnrow"><button class="primary" onclick="openCoreModal()">'+ic('plus')+esc(T('core_add'))+'</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+esc(T('check_all'))+'</button></div>'+
 toolbar('core',T('core_search'))+'<div id="corList">'+skCards('core')+'</div>'+pagerBottom('core')}
async function refreshCore(){if(editingId||CHECKING||RORD||RSAVE)return;var f=await j('fleet?kind=core&offset='+(PG.core*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.core));FLEET=f.links||[];TOT.core=num(f.total);var box=el('corList');if(!box)return;
 setHTML(box,FLEET.length?FLEET.map(coreCard).join(''):'<div class="card muted">'+(QRY.core?T('no_results'):T('core_empty'))+'</div>');renderPager('core');if(typeof refreshCardEdges=='function')setTimeout(refreshCardEdges,300)}
// ===== reorder cards: explicit "reorder mode" (toolbar toggle) + drag by the grip handle =====
// Long-press was dropped — it fought text-select/copy and scroll ("hold to copy" kept triggering a drag).
// Now the user taps the reorder toggle in the toolbar; each card shows a grip (touch-action:none) and
// dragging THAT live-swaps with the neighbour and persists server-side. Outside reorder mode nothing here
// fires, so tap / scroll / copy behave normally. touch-action:none on the grip = no scroll-race, reliable drag.
var REORDMODE=false,RORD_AS=0;   // RORD_AS = rAF id for edge auto-scroll during a drag
function toggleReord(){REORDMODE=!REORDMODE;document.body.classList.toggle('reord-on',REORDMODE);}
function gripSvg(){return '<svg viewBox="0 0 20 20" width="16" height="16" fill="currentColor" aria-hidden="true"><circle cx="7" cy="4.5" r="1.5"/><circle cx="13" cy="4.5" r="1.5"/><circle cx="7" cy="10" r="1.5"/><circle cx="13" cy="10" r="1.5"/><circle cx="7" cy="15.5" r="1.5"/><circle cx="13" cy="15.5" r="1.5"/></svg>'}
function grip(){return '<span class="rgrip" onclick="event.stopPropagation()" title="'+esc(T('reord_t'))+'">'+gripSvg()+'</span>'}
function reordDown(e){
 if(RORD||RSAVE||!REORDMODE)return;
 if(e.isPrimary===false)return;
 if(e.pointerType==='mouse'&&e.button!==0)return;
 var g=e.target.closest?e.target.closest('.rgrip'):null;if(!g)return;   // drag ONLY from the grip handle
 var card=g.closest('.card[data-rid]');if(!card)return;
 var box=card.parentNode;if(!box)return;
 if(e.cancelable)e.preventDefault();
 RORD={card:card,box:box,id:card.getAttribute('data-rid'),kind:card.getAttribute('data-rk'),pid:e.pointerId,grabY:e.clientY,lastY:e.clientY,swaps:[]};
 try{card.setPointerCapture(e.pointerId)}catch(_){}
 card.classList.add('rdrag');document.body.classList.add('rdragging');
 if(navigator.vibrate){try{navigator.vibrate(10)}catch(_){}}
 RORD_AS=requestAnimationFrame(reordAutoScroll);   // keep the page scrolling while a dragged card sits at an edge
}
function reordApply(){   // re-place the dragged card at RORD.lastY and swap with the neighbour it has crossed
 var c=RORD.card;
 c.style.transform='translateY('+(RORD.lastY-RORD.grabY)+'px)';
 var cr=c.getBoundingClientRect(),cy=cr.top+cr.height/2;
 var p=c.previousElementSibling;
 if(p&&p.getAttribute&&p.getAttribute('data-rid')&&p.getAttribute('data-rk')===RORD.kind&&cy<p.getBoundingClientRect().top+p.getBoundingClientRect().height/2){reordShift(p,true);return}
 var n=c.nextElementSibling;
 if(n&&n.getAttribute&&n.getAttribute('data-rid')&&n.getAttribute('data-rk')===RORD.kind&&cy>n.getBoundingClientRect().top+n.getBoundingClientRect().height/2){reordShift(n,false);return}
}
function reordMove(e){
 if(!RORD)return;
 if(e.cancelable)e.preventDefault();
 RORD.lastY=e.clientY;
 reordApply();
}
function reordAutoScroll(){   // touch-action:none means the browser won't scroll during a drag, so do it ourselves near the edges
 if(!RORD){RORD_AS=0;return}
 var y=RORD.lastY,vh=window.innerHeight||document.documentElement.clientHeight,edge=76,ds=0;
 if(y<edge)ds=-Math.min(24,((edge-y)/3|0)+3);
 else if(y>vh-edge)ds=Math.min(24,((y-(vh-edge))/3|0)+3);
 if(ds){var b=window.pageYOffset;window.scrollBy(0,ds);var a=window.pageYOffset-b;if(a){RORD.grabY-=a;reordApply();}}   // grabY-=scrolled keeps the card pinned under the finger
 RORD_AS=requestAnimationFrame(reordAutoScroll);
}
function reordShift(nb,up){
 var c=RORD.card;
 var cBefore=c.getBoundingClientRect().top,nBefore=nb.getBoundingClientRect().top;
 if(up)RORD.box.insertBefore(c,nb);else RORD.box.insertBefore(nb,c);
 RORD.grabY+=(c.getBoundingClientRect().top-cBefore);          // keep the card pinned under the finger
 c.style.transform='translateY('+(RORD.lastY-RORD.grabY)+'px)';
 var dy=nBefore-nb.getBoundingClientRect().top;                 // FLIP the neighbour so it glides, not jumps
 if(dy){nb.style.transition='none';nb.style.transform='translateY('+dy+'px)';void nb.offsetHeight;nb.style.transition='';nb.style.transform=''}
 RORD.swaps.push(nb.getAttribute('data-rid'));
}
function reordEnd(){
 if(!RORD)return;var d=RORD;RORD=null;
 if(RORD_AS){cancelAnimationFrame(RORD_AS);RORD_AS=0;}
 try{d.card.releasePointerCapture(d.pid)}catch(_){}
 d.card.classList.remove('rdrag');d.card.style.transform='';document.body.classList.remove('rdragging');
 if(d.swaps.length)reordPersist(d.kind,d.id,d.swaps);
}
async function reordPersist(kind,id,swaps){
 RSAVE=true;
 try{for(var i=0;i<swaps.length;i++){var r=await post('reorder',{kind:kind,id:id,target:swaps[i]});if(!r.ok||!r.d.ok){toast((r.d&&r.d.error)||T('reorder_err'),'err');break}}}
 catch(_){toast(T('reorder_err'),'err')}
 RSAVE=false;
 if(kind==='nodes')refreshNodes();else if(kind==='core')refreshCore();else if(kind==='portfw')refreshPortfw();else refreshTunnels();
}
document.addEventListener('pointerdown',reordDown,true);
document.addEventListener('pointermove',reordMove,true);
document.addEventListener('pointerup',reordEnd,true);
document.addEventListener('pointercancel',reordEnd,true);
document.addEventListener('touchmove',function(e){if(RORD&&e.cancelable)e.preventDefault()},{passive:false});
function coreMeta(l){   // right col under box A, left col under box B (lock at the START, green)
 var sub='<div>'+esc(T('subnet'))+': <b class="mono">'+esc(l.subnet)+'</b></div>';
 var tr=(l.transport=='tcp')?'TCP':(l.transport=='raw')?('RAW·'+esc((l.raw_profile||'bip').toUpperCase())):(l.transport=='flux')?('FLUX·'+esc((l.flux_carrier||'udp').toUpperCase())):(l.transport=='dns')?('DNS·'+esc((l.dns_zone||'').toUpperCase())):(l.transport=='ws')?(l.ws_xhttp?('xHTTP·'+((l.ws_xhttp_mode=='grpc')?'grpc':'packet')):(l.ws_tls?'WSS':'WS')):'UDP';
 var prt=(l.transport!='raw'&&l.transport!='flux'&&l.transport!='dns'&&l.port)?'<div>'+esc(T('port'))+': <b class="mono">'+esc(l.port)+'</b></div>':'';
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
 var _aA=l.a_ip_active||'',_aB=l.b_ip_active||'',ka=l.id+'_a',kb=l.id+'_b';
 if(!l.ip_rotate){   // rotation OFF: evict any stale cached rotating IP so the icon + active-IP don't linger from a prior rotation
   var ce=false;if(PEERST[ka]){delete PEERST[ka];ce=true}if(PEERST[kb]){delete PEERST[kb];ce=true}if(ce)peerStSave();
 }else if(_aA||_aB){var ch=false;
   if(_aA&&(PEERST[ka]||{}).ip!==_aA){PEERST[ka]={ip:_aA};ch=true}
   if(_aB&&(PEERST[kb]||{}).ip!==_aB){PEERST[kb]={ip:_aB};ch=true}
   if(ch)peerStSave();}
 var _pa=PEERST[ka]||{},_pb=PEERST[kb]||{};
 var _aip=_aA||_pa.ip||l.a_ip,_bip=_aB||_pb.ip||l.b_ip;
 // The rotation mark comes from the record ONLY. The cache holds the last active IP so a reload
 // paints instantly, but it must not carry `rot`: the entry is rewritten only when the IP CHANGES,
 // so a side that stops rotating (a pool trimmed to one) would keep a stale rot:true forever.
 var _arot=l.a_ip_rot?rotMark():'',_brot=l.b_ip_rot?rotMark():'';
 var body='<div class="tninfo">'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="tnend"><span class="rl '+(srvA?'srv':'cli')+'">'+(srvA?T('server'):T('client'))+'</span><span class="cprot" id="cprot_a_'+l.id+'">'+_arot+'</span><span class="stat" id="lba_'+l.id+'">'+accStat(l,'a')+'</span></span></div><div class="tna mono" id="cpip_a_'+l.id+'">'+esc(_aip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="tnend"><span class="rl '+(srvA?'cli':'srv')+'">'+(srvA?T('client'):T('server'))+'</span><span class="cprot" id="cprot_b_'+l.id+'">'+_brot+'</span><span class="stat" id="lbb_'+l.id+'">'+accStat(l,'b')+'</span></span></div><div class="tna mono" id="cpip_b_'+l.id+'">'+esc(_bip)+'</div></div>'+
  '</div>'+
  coreMeta(l);
 var F=linkFooter(l,'openCoreEdit');
 return accShell(l,true,F.drift+body+accBodyTraf(l)+F.acts+F.msg)}
_corS.Srv='a',_corS.Tr='udp',_corS.Obfs=false,_corS.Cover=false,_corS.RawProfile='bip',_corS.Gso=false,_corS.FluxCarrier='udp',_corS.FluxRotate=600,_corS.FluxShape='random',_corS.FluxOffset=0,_corS.WsTls=false,_corS.Ech=false,_corS.EchProxy=false,_corS.Xhttp=false,_corS.XhMode='packet',_corS.XhProf='cf',_corS.Fec=false,_corS.FecData=10,_corS.FecParity=3,_corS.Desync=false,_corS.DesyncTtl=4,_corS.DesyncCount=2,_corS.DesyncMode='ttl',_corS.SniSplit=false,_corS.SplitPos=0,_corS.SniMode='split',_corS.SplitTtl=0;
function COR_RAW_PROFILES(){return [{v:'bip',m:T('rawp_bip_m'),tag:T('rawp_best')},{v:'icmp',m:T('rawp_icmp_m')},{v:'gre',m:T('rawp_gre_m'),warn:1},{v:'ipip',m:T('rawp_ipip_m'),warn:1},{v:'udp',m:T('rawp_udp_m')},{v:'tcp',m:T('rawp_tcp_m')},{v:'esp',m:T('rawp_esp_m'),warn:1}]}
function rawTiles(px,sel){return COR_RAW_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==sel?' on':'')+'" data-p="'+p.v+'" onclick="'+px+'SetProfile(\\''+p.v+'\\')">'+(p.tag?'<span class="best">'+esc(p.tag)+'</span>':'')+(p.warn?'<span class="pwarn" title="'+esc(T('rawp_warn'))+'"></span>':'')+'<div class="pn">'+p.v+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
// The three ways to cross a CDN, as ONE choice. They are three separate transports everywhere
// else (xray calls them WebSocket / gRPC / XHTTP), and only looked like a family here because
// grpc happens to live in xhttp.go and share the ws_xhttp config flag — an implementation detail
// that had leaked into the UI as a second picker. The stored config is unchanged: ws_xhttp is
// (v != 'ws') and ws_xhttp_mode is 'grpc' or 'packet'.
function WS_PROFILES(){return [{v:'ws',m:T('wsp_ws_m')},{v:'grpc',m:T('wsp_grpc_m')},{v:'http',m:T('wsp_http_m')}]}
// the selector value for a stored link
function wsProfOf(S){return S.Xhttp?(S.XhMode=='grpc'?'grpc':'http'):'ws'}
// Which CDN the HTTP carrier fronts through. It changes ONE thing — how many POSTs per second the
// client makes — and that is the whole difference between running and being blocked: Cloudflare
// tolerates ~70/s, ArvanCloud's WAF blocks the source IP for minutes. Only HTTP has a POST ladder,
// so this row appears for HTTP alone.
function XH_PROFILES(){return [{v:'cf',n:T('xhp_cf_n'),m:T('xhp_cf_m')},{v:'arvan',n:T('xhp_arvan_n'),m:T('xhp_arvan_m')}]}
function xhProfTiles(px,cur){return XH_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==cur?' on':'')+'" data-xp="'+p.v+'" onclick="'+px+'SetXhProf(\\''+p.v+'\\')"><div class="pn">'+esc(p.n)+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function _setXhProf(S,px,p){S.XhProf=p;var g=el(px+'xhppg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-xp')==p)})}
function corSetXhProf(p){_setXhProf(_corS,'e_',p)}
function ceSetXhProf(p){_setXhProf(_eeS,'ee_',p)}
// the row is meaningful only on the HTTP carrier (ws has no POSTs, grpc has no ladder)
function xhProfOn(S){return S.Tr=='ws'&&S.Xhttp&&S.XhMode!='grpc'}
function corXhProfGate(){var r=el('e_xhprow');if(r)r.style.display=xhProfOn(_corS)?'':'none'}
function ceXhProfGate(){var r=el('ee_xhprow');if(r)r.style.display=xhProfOn(_eeS)?'':'none'}
function wsProfTiles(px,cur){return WS_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==cur?' on':'')+'" data-wp="'+p.v+'" onclick="'+px+'SetWsProf(\\''+p.v+'\\')"><div class="pn">'+p.v+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function _setWsProf(S,px,p){S.Xhttp=(p!='ws');S.XhMode=(p=='grpc')?'grpc':'packet';
 var g=el(px+'wspg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-wp')==p)})}
function corSetWsProf(p){_setWsProf(_corS,'e_',p);corWssGate();corDesyncGate();corXhProfGate()}
function ceSetWsProf(p){_setWsProf(_eeS,'ee_',p);ceWssGate();ceDesyncGate();ceXhProfGate()}
function corSetTr(t){_corS.Tr=t;_ENUMS.tr_all.forEach(function(x){var b=el('e_tr_'+x);if(b)b.classList.toggle('on',t==x)});var w=el('e_trword');if(w)w.textContent=(t=='tcp'?'TCP':(t=='raw'?'raw-IP':(t=='flux'?'flux':(t=='ws'?'ws/TCP':(t=='dns'?'DNS':'UDP')))));corRawVis();corDnsVis();corFluxVis();corWsVis();corPortGate();corCoverGate();corFecGate();corSpoofVis();corProtoVis();corDesyncGate();corXhProfGate();corRotVis('e_');onCorCipher()}   /* obfs is unavailable on dns -- re-gate on every transport change, not just on a cipher change */
function corFluxVis(){var w=el('e_fluxblk');if(w)w.style.display=(_corS.Tr=='flux')?'':'none';fluxTick()}
function corWsVis(){var ws=_corS.Tr=='ws';var w=el('e_wsblk');if(w)w.style.display=ws?'':'none';var t=el('e_wstlsrow'),e=el('e_wsechrow');if(t)t.style.display=ws?'':'none';if(e)e.style.display=ws?'':'none';var sr=el('e_snisplitrow');if(sr)sr.style.display=ws?'':'none';var sb=el('e_snisplitbody');if(sb)sb.style.display=(ws&&_corS.SniSplit)?'':'none';corEchPxGate();if(ws){poolVis('e_');corWssGate()}}
function corToggleWsTls(){_corS.WsTls=!_corS.WsTls;var s=el('e_wstls');if(s)s.classList.toggle('on',_corS.WsTls);if(!_corS.WsTls){if(_corS.Ech){_corS.Ech=false;var e=el('e_wsech');if(e)e.classList.remove('on')}if(_corS.SniSplit){_corS.SniSplit=false;var q=el('e_snisplit');if(q)q.classList.remove('on');var b=el('e_snisplitbody');if(b)b.style.display='none'}}corEchPxGate()}
function corToggleSni(){if(!_corS.WsTls){_corS.SniSplit=false;var q=el('e_snisplit');if(q)q.classList.remove('on');alert(T('sni_need_wss'));return}_corS.SniSplit=!_corS.SniSplit;var s=el('e_snisplit');if(s)s.classList.toggle('on',_corS.SniSplit);var b=el('e_snisplitbody');if(b)b.style.display=_corS.SniSplit?'':'none'}
function corSetSniMode(m){_corS.SniMode=m;var g=el('e_snimodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_snim_'+m)});var b=el('e_snittlbody');if(b)b.style.display=(m!='split')?'':'none'}
// wss is MANDATORY for an edge pool and for the gRPC xhttp mode (both need HTTP/2 to the
// edge). In those cases force the toggle on and grey it (pointer-events:none) so it can't be turned
// off in the UI only to be silently forced back on at save — the bug the user hit. Free otherwise.
function corWssGate(){var mand=poolGet('e_').pool||(_corS.Xhttp&&_corS.XhMode=='grpc');var row=el('e_wstlsrow'),s=el('e_wstls');if(mand){_corS.WsTls=true;if(s)s.classList.add('on');if(row)row.classList.add('dis')}else if(row)row.classList.remove('dis')}
function corToggleEch(){if(!_corS.WsTls){_corS.Ech=false;var e=el('e_wsech');if(e)e.classList.remove('on');corEchPxGate();alert(T('ech_need_wss_alert'));return}_corS.Ech=!_corS.Ech;var s=el('e_wsech');if(s)s.classList.toggle('on',_corS.Ech);corEchPxGate()}
function corToggleEchProxy(){_corS.EchProxy=!_corS.EchProxy;var s=el('e_echpx');if(s)s.classList.toggle('on',_corS.EchProxy);var b=el('e_echpxbody');if(b)b.style.display=_corS.EchProxy?'':'none'}
function corEchPxGate(){var vis=(_corS.Tr=='ws'&&_corS.Ech),row=el('e_echpxrow');if(!vis){_corS.EchProxy=false;var s=el('e_echpx');if(s)s.classList.remove('on')}if(row)row.style.display=vis?'':'none';var b=el('e_echpxbody');if(b)b.style.display=(vis&&_corS.EchProxy)?'':'none'}
var _poolData={};
function poolInit(pfx,l){_poolData[pfx]={pool:!!(l&&l.ws_pool),rotate:(l&&l.ws_rotate_secs!=null)?l.ws_rotate_secs:600,autoBurn:l?!!l.ws_auto_burn:true,warm:l?!!l.ws_warm_standby:false,
  open:{ip:false,sni:false},act:{ip:'',sni:''},lid:(l&&l.id)||'',
  ip:{clean:((l&&l.ws_edge_ips)||[]).slice(),burned:((l&&l.ws_edge_ips_burned)||[]).slice()},
  sni:{clean:((l&&l.ws_edge_snis)||[]).map(function(s){return (s&&s.host)||''}).filter(Boolean),burned:((l&&l.ws_edge_snis_burned)||[]).slice()}};}
function poolGet(pfx){if(!_poolData[pfx])poolInit(pfx,null);return _poolData[pfx];}
// An edge IP must be a real IPv4 (four 0-255 octets, optional :port) or a real domain
// (labels + an alphabetic TLD); an SNI must be a real domain. This rejects garbage like
// "876889767" (no dots) AND "543.45534.453453" (dotted but not a valid IP or domain).
var _ip4Re=/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
var _domRe=/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/;
function poolValid(kind,val){var h=val;if(kind=='ip'){var c=val.lastIndexOf(':');if(c>=0){h=val.slice(0,c);var p=val.slice(c+1);if(!(/^\d+$/.test(p)&&+p>=1&&+p<=65535))return false;}return _ip4Re.test(h);}return _domRe.test(val);}
// poolRemain: seconds left until an entry's next retest, using the server clock sampled at the
// last poll plus the client-side elapsed time since — so the countdown ticks smoothly between polls.
// _cdRemain: seconds until `next` given the server clock `now` sampled at local time `polledMs`.
// _cdTick: refresh every .pcd countdown text + .pbar fill inside host against that clock. Shared by the
// ws-edge pool view (poolRemain/poolCdTick, data in d) and the direct peer pool view (peerRemain/
// peerCdTick, data in the _peerData global) — the peer view was copied from the pool view.
function _cdRemain(now,polledMs,next){if(!next||!now)return -1;var e=now+(Date.now()-(polledMs||Date.now()))/1000;return Math.max(0,Math.round(next-e));}
function _cdTick(host,now,polledMs){if(!host)return;
  Array.prototype.forEach.call(host.querySelectorAll('.pcd'),function(sp){var r=_cdRemain(now,polledMs,+sp.getAttribute('data-next'));if(r>=0)sp.textContent=poolCdTxt(r)});
  Array.prototype.forEach.call(host.querySelectorAll('.pbar'),function(bar){var tot=+bar.getAttribute('data-tot')||1,rem=_cdRemain(now,polledMs,+bar.getAttribute('data-next'));if(rem<0)return;var i=bar.firstChild;if(i)i.style.width=Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)))+'%'})}
function poolRemain(d,next){return _cdRemain(d.srvNow,d.polledMs,next);}
function poolCdTxt(r){var m=Math.floor(r/60),s=r%60;return m+':'+(s<10?'0'+s:s);}
function poolCd(d,next){var r=poolRemain(d,next);if(r<0)return '';return '<span class="pcd" data-next="'+next+'">'+poolCdTxt(r)+'</span>';}
// Backoff schedule (must mirror the core): a suspect entry's current step length by fail count;
// a dead entry retests slowly. Used to draw the fill bar (elapsed / step) like the mockup.
var _poolBackoff=[30,60,120,300,600],_poolDeadStep=1800;
function poolStepTotal(h){return h.state=='dead'?_poolDeadStep:(_poolBackoff[Math.min(h.fails||0,_poolBackoff.length-1)]||600);}
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
function poolMove(pfx,kind,from,val){var d=poolGet(pfx),to=from=='clean'?'burned':'clean';if(kind=='ip'&&from=='clean'&&d.ip.clean.length<=2){toast(T('pool_ip_min2'),'err');return}d[kind][from]=d[kind][from].filter(function(x){return x!=val});if(d[kind][to].indexOf(val)<0)d[kind][to].push(val);poolRenderKind(pfx,kind);}
function poolDel(pfx,kind,from,val){var d=poolGet(pfx);if(kind=='ip'&&from=='clean'&&d.ip.clean.length<=2){toast(T('pool_ip_min2'),'err');return}d[kind][from]=d[kind][from].filter(function(x){return x!=val});poolRenderKind(pfx,kind);}
function poolToggleAB(pfx){var d=poolGet(pfx);d.autoBurn=!d.autoBurn;var ab=el(pfx+'poolab');if(ab)ab.classList.toggle('on',d.autoBurn);}
function poolToggleWarm(pfx){var d=poolGet(pfx);d.warm=!d.warm;var w=el(pfx+'poolwarm');if(w)w.classList.toggle('on',d.warm);}
function poolVis(pfx){var d=poolGet(pfx),s=el(pfx+'wshostblk'),p=el(pfx+'wspool'),t=el(pfx+'pooltgl');if(t)t.classList.toggle('on',d.pool);if(s)s.style.display=d.pool?'none':'';if(p)p.style.display=d.pool?'':'none';if(d.pool)poolRender(pfx);}
function poolToggle(pfx){poolGet(pfx).pool=!poolGet(pfx).pool;poolVis(pfx);}
function poolCollect(pfx,body){var d=poolGet(pfx);if(!d.pool){body.ws_pool=false;return true;}var rv=ssVal(pfx+'poolrot');if(rv!=='')d.rotate=+rv;if(d.ip.clean.length<2)return T('pool_ip_min2');if(!d.sni.clean.length)return T('pool_need_clean');body.ws_pool=true;body.ws_tls=true;body.ws_edge_ips=d.ip.clean;body.ws_edge_ips_burned=d.ip.burned;body.ws_edge_snis=d.sni.clean;body.ws_edge_snis_burned=d.sni.burned;body.ws_rotate_secs=d.rotate;body.ws_auto_burn=d.autoBurn;body.ws_warm_standby=d.warm;return true;}
function corTogglePool(){poolToggle('e_');corWssGate()}
function ceTogglePool(){poolToggle('ee_');ceWssGate()}
function corSetFluxCarrier(c){_corS.FluxCarrier=c;var g=el('e_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fc]'),function(t){t.classList.toggle('on',t.getAttribute('data-fc')==c)});fluxTick()}
function corSetFluxShape(s){_corS.FluxShape=s;var g=el('e_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fs]'),function(t){t.classList.toggle('on',t.getAttribute('data-fs')==s)})}
function corFluxRotChg(){_corS.FluxRotate=parseInt(ssVal('e_fluxrot'))||600;fluxTick()}
function corFecDatagram(){return _corS.Tr=='udp'||_corS.Tr=='raw'||_corS.Tr=='flux'}
function corToggleFec(){if(!corFecDatagram())return;_corS.Fec=!_corS.Fec;var s=el('e_fecsw');if(s)s.classList.toggle('on',_corS.Fec);var r=el('e_fecrates');if(r)r.style.display=_corS.Fec?'':'none'}
function corSetFecRate(d,p){_corS.FecData=d;_corS.FecParity=p;var g=el('e_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function corFecGate(){var dg=corFecDatagram(),row=el('e_fecrow');if(!dg){_corS.Fec=false;var s=el('e_fecsw');if(s)s.classList.remove('on');var r=el('e_fecrates');if(r)r.style.display='none'}if(row)row.style.display=dg?'':'none'}
async function doFluxRotate(id){var r=await post('flux-rotate',{id:id});if(r.ok&&r.d.ok){toast(T('flux_rotated'),'ok');fluxTick()}else{toast(perr(r),'err')}}
// Live edge-pool status: poll the active edge for the open edit link and reflect it (active
// row highlight + live bar), plus mirror any auto-burns the core reported. doPoolRotate signals
// the core to jump one dimension with no rebuild, then re-polls shortly after.
_eeS.PoolLid='';
function poolApplyStatus(pfx,st){var d=poolGet(pfx);var a=String(st.active||'').split(' · ');
  d.act={ip:(a[0]||'').trim(),sni:(a[1]||'').trim()};
  d.live={};(st.health||[]).forEach(function(h){if(h&&h.key)d.live[(h.kind=='sni'?'sni':'ip')+':'+h.key]={state:String(h.state||'healthy'),next:+h.next_retest_unix||0,fails:+h.fails||0}});
  d.srvNow=+st.now||Math.floor(Date.now()/1000);d.polledMs=Date.now();
  // release the pin lock once the chosen edge is confirmed active (or after a 12s safety timeout)
  if(d.pinPending){var pk=d.pinPending;if(d.act[pk.kind]===pk.key||(Date.now()-pk.ts>12000))d.pinPending=null;}
  poolRenderKind(pfx,'ip');poolRenderKind(pfx,'sni');}  // live health (سالم/موقت/دائمی) + active edge overlay onto the rows
async function poolTick(){if(!_eeS.PoolLid)return;if(!poolGet('ee_').pool)return;var r=await post('edge-status',{id:_eeS.PoolLid});if(r.ok&&r.d&&r.d.ok&&r.d.pool)poolApplyStatus('ee_',r.d);}
(function poolLoop(){setTimeout(function(){Promise.resolve(poolTick()).then(poolLoop,poolLoop)},UIV)})();   // live-cadence self-loop
// Tick the retest countdown spans between polls so «سوختهٔ موقت/دائمی» rows show a live timer.
function poolCdTick(){var d=_poolData['ee_'];if(!d||!d.live)return;['ip','sni'].forEach(function(k){_cdTick(el('ee_lst_'+k),d.srvNow,d.polledMs)})}
setInterval(poolCdTick,1000);
// "Probe now": SIGHUP the core (via node) to retest every suspect/dead edge at once.
async function poolProbeNow(lid){if(!lid){toast(T('pool_make_first'),'err');return}var r=await post('pool-probe-now',{id:lid});if(r.ok&&r.d&&r.d.ok){toast(T('pool_probe_sent'),'ok');[1200,3000,5500,8000].forEach(function(ms){setTimeout(poolTick,ms)})}else{toast(perr(r),'err')}}
// "select this edge": pin a specific IP/SNI as the active one (exact jump, no rebuild).
async function poolSelect(lid,kind,key){if(!lid){toast(T('pool_make_first'),'err');return}
  var d=poolGet('ee_');
  if(d.pinPending)return;                                   // a pin is already in flight — ignore spam clicks
  d.pinPending={kind:kind,key:key,ts:Date.now()};           // lock ALL pin buttons until this edge is confirmed active
  poolRenderKind('ee_','ip');poolRenderKind('ee_','sni');
  var r=await post('pool-select',{id:lid,kind:kind,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('pool_edge_active'),'ok');[1200,3000,5500,8000,11000].forEach(function(ms){setTimeout(poolTick,ms)})}
  else{d.pinPending=null;poolRenderKind('ee_','ip');poolRenderKind('ee_','sni');toast(perr(r),'err')}}
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
var _peerData={dst:null,src:null,now:0,polledMs:0,pinPending:null,open:{}};   // open: per-side accordion state, kept across peerTick's re-renders
async function peerTick(){if(!_peerLid||!el('ee_peerlive'))return;var r=await post('peer-status',{id:_peerLid});if(r.ok&&r.d&&r.d.ok&&r.d.pool)peerApply(r.d);}
(function peerLoop(){setTimeout(function(){Promise.resolve(peerTick()).then(peerLoop,peerLoop)},UIV)})();   // live-cadence self-loop
function peerApply(st){
  _peerData.now=+st.now||Math.floor(Date.now()/1000);_peerData.polledMs=Date.now();
  ['dst','src'].forEach(function(side){var sec=st[side]||{};var live={};
    (sec.health||[]).forEach(function(h){if(h&&h.key)live[h.key]={state:String(h.state||'healthy'),next:+h.next_retest_unix||0,fails:+h.fails||0}});
    _peerData[side]={active:String(sec.active||''),addrs:(sec.addrs||[]).map(String),pin:String(sec.pin||''),live:live};});
  if(_peerData.pinPending){var pk=_peerData.pinPending,sec=_peerData[pk.side]||{};if(sec.active===pk.key||(Date.now()-pk.ts>12000))_peerData.pinPending=null;}
  peerRender();}
function peerRemain(next){return _cdRemain(_peerData.now,_peerData.polledMs,next);}
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
// Above this many addresses a side collapses into an accordion. Three rows read at a glance; a fourth
// starts pushing the OTHER side (and the roles/save controls) off a phone screen, which is exactly the
// state a rotating tunnel is normally in.
var PEER_ACC_MIN=3;
function peerAccOpen(side){var d=_peerData[side];if(!d)return true;
  if(d.addrs.length<=PEER_ACC_MIN)return true;                 // short list: no chevron, never collapsed
  if(!_peerData.open)_peerData.open={};
  return _peerData.open[side]!==false;}                        // long list: open by default, remembered
function peerAcc(side){if(!_peerData.open)_peerData.open={};
  _peerData.open[side]=!peerAccOpen(side);peerRender();}
// «وضعیت زندهٔ استخر» shows POOLS. A side with one address is not one, so it gets no card.
//
// This also removes an asymmetry the operator could not have guessed at. main.go builds a destination
// pool at >=2 peers but a SOURCE pool at >=1, because a 1-entry source pool has a second job: pinning
// the client's egress IP, which bind_ip cannot do on udp/raw/flux. A pool that gets built writes a
// status file; one that does not, does not. So the single-IP side appeared as a card when it was the
// CLIENT and vanished when it was the SERVER — two tunnels of the same shape rendering differently
// depending on which end was which. Gating on the address count makes both read the same: exactly the
// sides that actually rotate.
function peerBox(side,lab){var d=_peerData[side];if(!d||d.addrs.length<2)return '';
  var live=d.live||{},ns=0,nd=0;d.addrs.forEach(function(ip){var h=live[ip];if(h&&h.state=='suspect')ns++;else if(h&&h.state=='dead')nd++;});
  var badges='<span class="pbadge ok">'+(d.addrs.length-ns-nd)+' '+T('pb_healthy')+'</span>'+(ns?'<span class="pbadge warn">'+ns+' '+T('pb_temp')+'</span>':'')+(nd?'<span class="pbadge bad">'+nd+' '+T('pb_dead')+'</span>':'');
  var acc=d.addrs.length>PEER_ACC_MIN,open=peerAccOpen(side);
  // Same .pacc card the CDN-edge / SNI sections use, so both pool views read as the same component:
  // one card per axis, title and badges on ONE line, chevron only when the list is long enough to hide.
  var chev=acc?'<div class="pchev'+(open?' open':'')+'">&#9662;</div>':'';
  var hd='<div class="pacchd"'+(acc?' data-acc role="button" tabindex="0" onclick="peerAcc(\\''+side+'\\')"':' style="cursor:default"')+'>'
    +'<div class="pacctl"><div class="pacct">'+esc(lab)+'</div><div class="paccs">'+badges+'</div></div>'
    +'<div style="display:flex;align-items:center;gap:8px">'+chev+'</div></div>';
  var body='<div class="paccbody"'+(open?'':' style="display:none"')+'><div class="rpool">'
    +d.addrs.map(function(ip){return peerRow(side,ip)}).join('')+'</div></div>';
  return '<div class="pacc">'+hd+body+'</div>';}
function peerRender(){var host=el('ee_peerlive');if(!host)return;
  var boxes=peerBox('dst',T('dst_ip'))+peerBox('src',T('src_ip'));
  // No live data yet: rather than a blank gap (which reads as "the feature is missing"), show WHY — the
  // pool status appears only once the tunnel is running on the up-to-date node/core. peerTick only calls
  // this on a pool:true response, and _peerLid is set only for a rotating tunnel, so the hint is apt.
  if(!boxes){host.innerHTML='<div class="peerlive"><div class="pllabel">'+esc(T('peer_live_hd'))+'</div><div class="muted" style="font-size:11px;line-height:1.7">'+esc(T('peer_live_empty'))+'</div></div>';return;}
  host.innerHTML='<div class="peerlive"><div class="pllabel">'+esc(T('peer_live_hd'))+'</div>'+boxes+'<div class="muted" style="font-size:10.5px;line-height:1.7;margin-top:2px">'+esc(T('peer_live_note'))+'</div></div>';}
function peerCdTick(){if(!_peerLid)return;_cdTick(el('ee_peerlive'),_peerData.now,_peerData.polledMs)}
setInterval(peerCdTick,1000);
async function peerSelect(btn){var side=btn.getAttribute('data-side'),key=btn.getAttribute('data-ip');
  if(!_peerLid||_peerData.pinPending||!key)return;
  _peerData.pinPending={side:side,key:key,ts:Date.now()};peerRender();
  var r=await post('peer-select',{id:_peerLid,side:side,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('peer_pinned'),'ok');[1200,3000,5500,8000,11000].forEach(function(ms){setTimeout(peerTick,ms)})}
  else{_peerData.pinPending=null;peerRender();toast(perr(r),'err')}}
async function peerProbeNow(){if(!_peerLid)return;var r=await post('peer-probe-now',{id:_peerLid});
  if(r.ok&&r.d&&r.d.ok){toast(T('pool_probe_sent'),'ok');[1200,3000,5500,8000].forEach(function(ms){setTimeout(peerTick,ms)})}
  else{toast(perr(r),'err')}}
// ---- IP spoofing (decoy) section — shared markup + per-form logic. Only for raw + bip.
function spoofSection(idp,fnp){return '<div class="spoofsec" id="'+idp+'spoofblk" style="display:none">'
 +'<div class="spoofhd">'+ic('shield')+esc(T('spoof_hd'))+'</div>'
 +'<div class="tglbox" id="'+idp+'decoyrow"><div class="tglsw" id="'+idp+'decoysw" onclick="'+fnp+'ToggleDecoy()"></div><div class="tt"><b>'+esc(T('spoof_decoy_t'))+'</b><small>'+esc(T('spoof_decoy_d'))+'</small></div></div>'
 +'<div id="'+idp+'decoyiprow" style="display:none;margin:8px 0 2px"><input id="'+idp+'decoyip" class="mono" placeholder="'+esc(T('spoof_decoy_ph'))+'" inputmode="numeric"></div>'
 +'<div class="tglbox" id="'+idp+'srcrow"><div class="tglsw" id="'+idp+'srcsw" onclick="'+fnp+'ToggleSrc()"></div><div class="tt"><b>'+esc(T('spoof_src_t'))+'</b><small>'+esc(T('spoof_src_d'))+'</small></div></div>'
 +'<div id="'+idp+'srciprow" style="display:none;margin:8px 0 2px"><input id="'+idp+'srcip" class="mono" placeholder="'+esc(T('spoof_src_ph'))+'" inputmode="numeric"></div>'
 +'<div class="spoofcap wait" id="'+idp+'cap">…</div></div>'}
// protoSection: the bip-only outer-IP protocol-number picker. bip carries no L4 header, so only the
// outer protocol number changes — set it to slip past a protocol-whitelist filter. Default 58 (ICMPv6,
// which the IPv4 kernel ignores); 253 keeps bip's native number. Revealed by {cor,ce}ProtoVis on raw+bip.
function protoSection(idp,fnp){return '<div id="'+idp+'protorow" style="display:none;margin-top:11px">'
 +'<label class="first">'+esc(T('raw_proto_lbl'))+'</label>'
 +'<div class="seg2" id="'+idp+'ppg" style="margin-bottom:8px"><button type="button" class="segopt on" id="'+idp+'pp_58" onclick="'+fnp+'SetProto(58)"><b>58</b><span>ICMPv6</span></button><button type="button" class="segopt" id="'+idp+'pp_253" onclick="'+fnp+'SetProto(253)"><b>253</b><span>'+esc(T('raw_proto_native'))+'</span></button></div>'
 +'<input id="'+idp+'rawproto" class="mono" inputmode="numeric" maxlength="3" placeholder="58" oninput="'+fnp+'ProtoWarn()" style="text-align:center;direction:ltr">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+T('raw_proto_hint')+'</div>'
 +'<div class="spoofcap no" id="'+idp+'protowarn" style="display:none;margin-top:8px"></div></div>'}
// RAW_PROTO_WARN: numbers the local IPv4 stack itself uses (ICMP/TCP/UDP/ESP/AH) — a bip carrier on one
// of these can contend with real host traffic, so warn. 58 / 253 are safe.
var RAW_PROTO_WARN=[1,6,17,50,51];
function protoWarnUpd(idp,val){var n=parseInt(val,10);var g=el(idp+'ppg');
 if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id==idp+'pp_'+n)});
 var w=el(idp+'protowarn');if(w){var h=(RAW_PROTO_WARN.indexOf(n)>=0)?(ic('warn')+'<span>'+esc(T('raw_proto_warn'))+'</span>'):'';w.innerHTML=h;w.style.display=h?'':'none'}}
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
function FLUX_ROTS(){return [{v:'180',label:T('frot_180')},{v:'300',label:T('frot_300')},{v:'600',label:T('frot_600')},{v:'900',label:T('frot_900')},{v:'1800',label:T('frot_1800')},{v:'3600',label:T('frot_3600')}]}
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
// fake-packet desync (anti-DPI) — a gated feature box shown on the raw/flux/tcp/ws carriers (raw/flux are the ones
// the core builds the IPv4 header for). Shared create/edit markup; toggle reveals mode + ttl/count.
function DS_MODES(){return [{v:'ttl',t:T('ds_m_ttl_t'),s:T('ds_m_ttl_s')},{v:'badsum',t:T('ds_m_bad_t'),s:T('ds_m_bad_s')},{v:'both',t:T('ds_m_both_t'),s:T('ds_m_both_s')}]}
function desyncSection(idp,fnp,on,ttl,count,mode,show){return '<div id="'+idp+'dsrow" class="tglbox" style="margin-top:11px'+(show?'':';display:none')+'"><div class="tglsw'+(on&&show?' on':'')+'" id="'+idp+'dssw" onclick="'+fnp+'ToggleDesync()"></div><div class="tt"><b>'+esc(T('ds_t'))+'</b><small>'+esc(T('ds_d'))+'</small></div></div>'
 +'<div id="'+idp+'dsbody" style="'+(on&&show?'':'display:none')+'"><label>'+esc(T('ds_mode_lbl'))+'</label><div class="seg2" id="'+idp+'dsmodeseg">'+DS_MODES().map(function(m){return '<button type="button" class="segopt'+(m.v==(mode||'ttl')?' on':'')+'" id="'+idp+'dsm_'+m.v+'" onclick="'+fnp+'SetDesyncMode(\\''+m.v+'\\')"><b>'+esc(m.t)+'</b><span>'+esc(m.s)+'</span></button>'}).join('')+'</div>'
 +'<div class="grid2"><div><label>'+esc(T('ds_ttl_lbl'))+'</label><input id="'+idp+'dsttl" dir="ltr" inputmode="numeric" value="'+(ttl||4)+'"></div><div><label>'+esc(T('ds_count_lbl'))+'</label><input id="'+idp+'dscount" dir="ltr" inputmode="numeric" value="'+(count||2)+'"></div></div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+esc(T('ds_note'))+'</div></div>'}
function corToggleDesync(){_corS.Desync=!_corS.Desync;var s=el('e_dssw');if(s)s.classList.toggle('on',_corS.Desync);var b=el('e_dsbody');if(b)b.style.display=_corS.Desync?'':'none'}
function corSetDesyncMode(m){_corS.DesyncMode=m;var g=el('e_dsmodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_dsm_'+m)})}
// xhttp is excluded: its conn is synthetic, so the AF_PACKET injector has no real 4-tuple to mirror
// and not one decoy is ever emitted. The core rejects the combination outright, so leaving the
// toggle visible would only let the operator build a tunnel that fails validation.
// ONE definition of "can this carrier really inject decoy segments?". There were four hand-written
// copies of it — the two gates, the edit form's initial render, and the submit-body collector — and only
// the gates had learned that xhttp cannot. So switching the CDN profile to XHTTP hid the toggle, but
// OPENING a tunnel already stored as xhttp rendered it visible (and ON), which is exactly what the
// operator was looking at. raw/flux forge the whole IPv4 header; tcp/cover/ws inject on the kernel
// connection's real 4-tuple; an xhttp conn is synthetic and has no 4-tuple to mirror.
function desyncOk(S){return S.Tr=='raw'||S.Tr=='flux'||S.Tr=='tcp'||(S.Tr=='ws'&&!S.Xhttp)}
function corDesyncGate(){var dg=desyncOk(_corS),row=el('e_dsrow');if(!dg){_corS.Desync=false;var s=el('e_dssw');if(s)s.classList.remove('on');var b=el('e_dsbody');if(b)b.style.display='none'}if(row)row.style.display=dg?'':'none'}
function ceToggleDesync(){_eeS.Desync=!_eeS.Desync;var s=el('ee_dssw');if(s)s.classList.toggle('on',_eeS.Desync);var b=el('ee_dsbody');if(b)b.style.display=_eeS.Desync?'':'none'}
function ceSetDesyncMode(m){_eeS.DesyncMode=m;var g=el('ee_dsmodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_dsm_'+m)})}
function ceDesyncGate(){var dg=desyncOk(_eeS),row=el('ee_dsrow');if(!dg){_eeS.Desync=false;var s=el('ee_dssw');if(s)s.classList.remove('on');var b=el('ee_dsbody');if(b)b.style.display='none'}if(row)row.style.display=dg?'':'none'}
// ---- wss + ECH toggles live down in the general feature-toggle area (next to obfs / cover /
// gso), not inside the ws block, so they stay put in single AND pool mode. They are shown only
// when the carrier is WS/CDN (corWsVis/ceWsVis) and hidden otherwise, like the tcp-only cover.
function wsToggleRows(idp,fnp,tls,ech,echproxy,echproxyurl,sni,pos,mode,ttl,show){var hide=show?'':';display:none';var pxhide=(ech&&show)?'':';display:none';var pxfhide=(echproxy&&ech&&show)?'':';display:none';
 return '<div class="tglbox" id="'+idp+'wstlsrow" style="margin-top:10px'+hide+'"><div class="tglsw'+(tls?' on':'')+'" id="'+idp+'wstls" onclick="'+fnp+'ToggleWsTls()"></div><div class="tt"><b>'+esc(T('wstls_t'))+'</b><small>'+esc(T('wstls_d'))+'</small></div></div>'
  +'<div class="tglbox" id="'+idp+'wsechrow" style="margin-top:9px'+hide+'"><div class="tglsw'+(ech?' on':'')+'" id="'+idp+'wsech" onclick="'+fnp+'ToggleEch()"></div><div class="tt"><b>'+esc(T('ech_t'))+'</b><small>'+esc(T('ech_d'))+'</small></div></div>'
  +'<div class="tglbox" id="'+idp+'echpxrow" style="margin-top:9px'+pxhide+'"><div class="tglsw'+(echproxy?' on':'')+'" id="'+idp+'echpx" onclick="'+fnp+'ToggleEchProxy()"></div><div class="tt"><b>'+esc(T('echpx_t'))+'</b><small>'+esc(T('echpx_d'))+'</small></div></div>'
  +'<div id="'+idp+'echpxbody" style="margin-top:6px'+pxfhide+'"><input id="'+idp+'echproxyurl" dir="ltr" placeholder="socks5://host:1080  |  http://user:pass@host:8080" value="'+esc(echproxyurl||'')+'"></div>'
  +'<div class="tglbox" id="'+idp+'snisplitrow" style="margin-top:9px'+hide+'"><div class="tglsw'+(sni?' on':'')+'" id="'+idp+'snisplit" onclick="'+fnp+'ToggleSni()"></div><div class="tt"><b>'+esc(T('sni_t'))+'</b><small>'+esc(T('sni_d'))+'</small></div></div>'
  +'<div id="'+idp+'snisplitbody" style="margin-top:6px'+((sni&&show)?'':';display:none')+'"><label>'+esc(T('sni_pos_lbl'))+'</label><input id="'+idp+'snisplitpos" type="number" min="0" max="1400" value="'+(pos||0)+'">'
  +'<label style="margin-top:10px;display:block">'+esc(T('sni_mode_lbl'))+'</label><div class="seg2" id="'+idp+'snimodeseg">'+SNI_MODES().map(function(m){return '<button type="button" class="segopt'+(m.v==(mode||'split')?' on':'')+'" id="'+idp+'snim_'+m.v+'" onclick="'+fnp+'SetSniMode(\\''+m.v+'\\')"><b>'+esc(m.v)+'</b><span>'+esc(m.s)+'</span></button>'}).join('')+'</div>'
  +'<div id="'+idp+'snittlbody" style="margin-top:6px'+((mode&&mode!='split')?'':';display:none')+'"><label>'+esc(T('sni_ttl_lbl'))+'</label><input id="'+idp+'splitttl" type="number" min="0" max="255" value="'+(ttl||0)+'"></div></div>';}
function SNI_MODES(){return [{v:'split',s:T('m_split_s')},{v:'disorder',s:T('m_dis_s')},{v:'fake',s:T('m_fake_s')}]}
// ---- ws (WebSocket / CDN) — shared markup.
function wsSection(idp,fnp,host,path,tls,edge,ech,xhttp,mode,lid,prof){return '<div id="'+idp+'wsblk" style="display:none">'
 +'<label>'+esc(T('ws_prof_lbl'))+'</label><div class="pgrid p3" id="'+idp+'wspg">'+wsProfTiles(fnp,wsProfOf({Xhttp:xhttp,XhMode:mode}))+'</div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin:2px 2px 8px">'+T('ws_prof_note')+'</div>'
 +'<div id="'+idp+'xhprow" style="display:none;margin-bottom:8px"><label style="margin-top:2px">'+esc(T('xh_prof_lbl'))+'</label>'
 +'<div class="pgrid" id="'+idp+'xhppg">'+xhProfTiles(fnp,prof=='arvan'?'arvan':'cf')+'</div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin:2px 2px 0">'+T('xh_prof_note')+'</div></div>'
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
   return '<div class="pacc"><div class="pacchd" data-acc role="button" tabindex="0" onclick="poolAcc(\\''+idp+'\\',\\''+kind+'\\')">'
     +'<div class="pacctl"><div class="pacct">'+label+'</div><div class="paccs" id="'+idp+'hd_'+kind+'"></div></div>'
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
// The epoch NUMBER mirrors the core exactly: epochNow() = floor(unixtime/rotate) + flux_epoch_offset
// (flux_linux.go). Leaving the offset out made «چرخش الان» look like it did nothing — the operator
// pressed it, the core moved to the next shape, and this box kept showing the old number. The
// countdown is unaffected: the offset is added AFTER the division, so it shifts the epoch's name,
// not its boundaries.
function fluxStatText(fc,rot,off){var now=Math.floor(Date.now()/1000);rot=rot||600;var ep=Math.floor(now/rot)+(+off||0),nx=rot-(now%rot),mm=Math.floor(nx/60),ss=nx%60;
 return '<b style="color:var(--ok)">'+esc(T('flux_live'))+'</b> · epoch <span class="mono">#'+ep+'</span> · '+esc(T('flux_carrier_word'))+' <span class="mono">'+fc+'</span> · '+esc(T('flux_next_pre'))+' <b>'+mm+':'+(ss<10?'0':'')+ss+'</b> '+esc(T('flux_next_post'));}
function fluxTick(){[['e_',_corS.Tr,_corS.FluxCarrier,_corS.FluxRotate,_corS.FluxOffset],['ee_',_eeS.Tr,_eeS.FluxCarrier,_eeS.FluxRotate,_eeS.FluxOffset]].forEach(function(a){
 var w=el(a[0]+'fluxstat');if(w&&a[1]=='flux')w.innerHTML=fluxStatText(a[2],a[3],a[4]);});}
setInterval(fluxTick,1000);
_corS.Decoy=false,_corS.Src=false,_corS.SpoofOk=false;
function corSpoofVis(){var w=el('e_spoofblk');if(!w)return;var show=(_corS.Tr=='raw'&&_corS.RawProfile=='bip');w.style.display=show?'':'none';if(show)corSpoofProbe()}
async function corSpoofProbe(){var cap=el('e_cap');if(!cap)return;cap.className='spoofcap wait';cap.innerHTML=esc(T('spoof_checking'));
 var res=await spoofProbePair(ssVal('e_a'),ssVal('e_b'));_corS.SpoofOk=res.ok;
 spoofApplyCap('e_',res.ok,res.html,function(){_corS.Decoy=false;_corS.Src=false;
  var d=el('e_decoysw'),s=el('e_srcsw');if(d)d.classList.remove('on');if(s)s.classList.remove('on');
  var di=el('e_decoyiprow'),si=el('e_srciprow');if(di)di.style.display='none';if(si)si.style.display='none'})}
function corToggleDecoy(){if(!_corS.SpoofOk)return;_corS.Decoy=!_corS.Decoy;el('e_decoysw').classList.toggle('on',_corS.Decoy);el('e_decoyiprow').style.display=_corS.Decoy?'':'none'}
function corToggleSrc(){if(!_corS.SpoofOk)return;_corS.Src=!_corS.Src;el('e_srcsw').classList.toggle('on',_corS.Src);el('e_srciprow').style.display=_corS.Src?'':'none'}
function corRawVis(){var w=el('e_rawblk');if(w)w.style.display=(_corS.Tr=='raw')?'':'none'}
function corDnsVis(){var w=el('e_dnsblk');if(w)w.style.display=(_corS.Tr=='dns')?'':'none'}
// trFade: hide the carrier-bar edge fade once scrolled to the overflow end (Math.abs handles RTL's
// negative scrollLeft as well as LTR; a non-overflowing bar reads as already at-end -> no fade).
function trFade(bar){if(!bar)return;var w=bar.parentNode;if(!w)return;w.classList.toggle('atend',Math.abs(bar.scrollLeft)+bar.clientWidth>=bar.scrollWidth-4)}
function corPortGate(){var p=el('e_port');if(!p)return;if(_corS.Tr=='ws'){p.disabled=false;if(!p.value)p.value='80';p.placeholder=T('port_ws_ph');return}var np=(_corS.Tr=='raw'||_corS.Tr=='flux'||_corS.Tr=='dns');p.disabled=np;if(np||p.value=='80')p.value='';p.placeholder=(_corS.Tr=='flux')?T('port_flux_ph'):(_corS.Tr=='dns')?T('port_dns_ph'):(np?T('port_raw_ph'):'20050')}
// dnsSection: the transport=dns config block (delegated zone + client resolver list + delegation
// guide). Revealed by {cor,ce}DnsVis. The server is the zone's authoritative NS on :53; the client
// queries the listed DOMESTIC resolvers, so it never sends a packet to the server IP.
function dnsSection(idp,fnp){return '<div id="'+idp+'dnsblk" style="display:none">'
 +'<label class="first">'+esc(T('dns_zone_lbl'))+'</label>'
 +'<input id="'+idp+'dnszone" class="mono" placeholder="t.example.com" style="direction:ltr">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:5px">'+T('dns_zone_note')+'</div>'
 +'<label>'+esc(T('dns_resolvers_lbl'))+'</label>'
 +'<input id="'+idp+'dnsresolvers" class="mono" placeholder="10.202.10.202, 10.202.10.102" style="direction:ltr">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:5px">'+T('dns_resolvers_note')+'</div>'
 +'<div class="autonote" style="margin-top:11px">'+ic('warn')+'<span>'+T('dns_delegation_note')+'</span></div></div>'}
function corSetProfile(p){_corS.RawProfile=p;var g=el('e_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});corSpoofVis();corProtoVis()}
function corSetProto(val){var i=el('e_rawproto');if(i)i.value=val;protoWarnUpd('e_',val)}
function corProtoWarn(){var i=el('e_rawproto');if(i)protoWarnUpd('e_',i.value)}
function corProtoVis(){var w=el('e_protorow');if(!w)return;var show=(_corS.Tr=='raw'&&_corS.RawProfile=='bip');w.style.display=show?'':'none';if(show){var i=el('e_rawproto');if(i&&!i.value)i.value='58';corProtoWarn()}}
function corToggleGso(){_corS.Gso=!_corS.Gso;var s=el('e_gso');if(s)s.classList.toggle('on',_corS.Gso)}
function corToggleObfs(){if(ssVal('e_cipher')=='none')return;_corS.Obfs=!_corS.Obfs;var s=el('e_obfs');if(s)s.classList.toggle('on',_corS.Obfs)}
function corToggleCover(){if(_corS.Tr!='tcp')return;_corS.Cover=!_corS.Cover;var s=el('e_cover');if(s)s.classList.toggle('on',_corS.Cover);corSniVis()}
function corSniVis(){var w=el('e_snirow');if(w)w.style.display=(_corS.Cover&&_corS.Tr=='tcp')?'':'none'}
function corCoverGate(){var tcp=_corS.Tr=='tcp',row=el('e_coverrow'),s=el('e_cover');if(!tcp){_corS.Cover=false;if(s)s.classList.remove('on')}if(row)row.style.display=tcp?'':'none';corSniVis()}
// obfs is unavailable in two cases: cipher=none (there is nothing to frame) and the dns carrier, which
// has NO obfs framing at all — main.go hands cfg.Obfs to every other carrier, but ListenDNS/DialDNS take
// no such flag. The core now rejects that combination outright, so leaving the toggle visible would only
// let the operator build a tunnel that fails validation; before the core check it was worse, since obfs
// showed as enabled everywhere and quietly did nothing on the most sensitive carrier there is.
function _obfsGate(px,S){var off=ssVal(px+'cipher')=='none'||S.Tr=='dns',row=el(px+'obfsrow'),s=el(px+'obfs');
 if(off){S.Obfs=false;if(s)s.classList.remove('on')}if(row)row.style.display=off?'none':''}
function onCorCipher(){_obfsGate('e_',_corS)}
async function openCoreModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(on.length<2){toast(T('node_min2'),'err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});_corS.Srv='a';_corS.Tr='udp';_corS.Obfs=false;_corS.Cover=false;_corS.RawProfile='bip';_corS.Gso=false;_corS.Decoy=false;_corS.Src=false;_corS.SpoofOk=false;_corS.FluxCarrier='udp';_corS.FluxRotate=600;_corS.FluxShape='random';_corS.FluxOffset=0;_corS.WsTls=false;_corS.Ech=false;_corS.EchProxy=false;_corS.SniSplit=false;_corS.SplitPos=0;_corS.SniMode='split';_corS.SplitTtl=0;_corS.Xhttp=false;_corS.XhMode='packet';_corS.XhProf='cf';_corS.Fec=false;_corS.FecData=10;_corS.FecParity=3;_corS.Desync=false;_corS.DesyncTtl=4;_corS.DesyncCount=2;_corS.DesyncMode='ttl';_eeS.PoolLid='';_peerLid='';_rotS['e_']={on:false,secs:600,aIps:[],bIps:[],aSel:{},bSel:{}};poolInit('e_',null);
 var _t1='<div class="ctabp on" data-cp="ip"><div class="grid2"><div><label class="first">'+esc(T('src_node'))+'</label>'+ssHTML('e_a',items,items[0].v,T('src_node'),'onCorNode')+'</div>'+
  '<div><label class="first">'+esc(T('dst_node'))+'</label>'+ssHTML('e_b',items,items[1].v,T('dst_node'),'onCorNode')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="e_aip"></div><div id="e_bip"></div></div>'+
  '<div id="e_rotrow"></div>'+rotSetHTML('e_')+
  '<label>'+esc(T('roles_lbl'))+'</label><div class="seg2" id="e_roles"><button type="button" class="segopt on" id="e_srv_a" onclick="corSetSrv(\\'a\\')"></button><button type="button" class="segopt" id="e_srv_b" onclick="corSetSrv(\\'b\\')"></button></div>'+
  '<div class="muted" style="font-size:11px;margin:-5px 2px 11px">'+esc(T('roles_note1'))+' <span id="e_trword">UDP</span>'+esc(T('roles_note2'))+'</div>'+
  '<div class="autonote">'+ic('warn')+'<span>'+T('srv_advice')+'</span></div></div>';
 var _t2='<div class="ctabp" data-cp="set"><label>'+esc(T('enc_method_lbl'))+'</label>'+ssHTML('e_cipher',CORE_CIPHERS(),'auto',T('cipher_ph'),'onCorCipher')+
  '<label>'+esc(T('transport_lbl'))+'</label><div class="trwrap" id="e_trwrap"><div class="seg2 trbar" id="e_trbar" onscroll="trFade(this)"><button type="button" class="segopt on" id="e_tr_udp" onclick="corSetTr(\\'udp\\')"><b>UDP</b><span>'+esc(T('tr_udp_d'))+'</span></button><button type="button" class="segopt" id="e_tr_tcp" onclick="corSetTr(\\'tcp\\')"><b>TCP</b><span>'+esc(T('tr_tcp_d'))+'</span></button><button type="button" class="segopt" id="e_tr_raw" onclick="corSetTr(\\'raw\\')"><b>RAW</b><span>'+esc(T('tr_raw_d'))+'</span></button><button type="button" class="segopt" id="e_tr_flux" onclick="corSetTr(\\'flux\\')"><b>FLUX</b><span>'+esc(T('tr_flux_d'))+'</span></button><button type="button" class="segopt" id="e_tr_ws" onclick="corSetTr(\\'ws\\')"><b>WS</b><span>CDN</span></button><button type="button" class="segopt" id="e_tr_dns" onclick="corSetTr(\\'dns\\')"><b>DNS</b><span>'+esc(T('tr_dns_d'))+'</span></button></div></div>'+
  '<div id="e_rawblk" style="display:none"><label>'+esc(T('raw_prof_lbl'))+'</label><div class="pgrid" id="e_pg">'+rawTiles('cor','bip')+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">'+T('raw_note')+'</div>'+protoSection('e_','cor')+'</div>'+
  fluxSection('e_','cor','udp',600,'random',null)+
  wsSection('e_','cor','','',false,'',false,false,'packet','','cf')+
  dnsSection('e_','cor')+
  spoofSection('e_','cor')+
  '<div class="tglbox" id="e_obfsrow"><div class="tglsw" id="e_obfs" onclick="corToggleObfs()"></div><div class="tt"><b>'+esc(T('obfs_t'))+'</b><small>'+esc(T('obfs_d'))+'</small></div></div>'+
  '<div class="tglbox" id="e_coverrow" style="display:none"><div class="tglsw" id="e_cover" onclick="corToggleCover()"></div><div class="tt"><b>'+esc(T('cover_t'))+'</b><small>'+esc(T('cover_d'))+'</small></div></div>'+
  wsToggleRows('e_','cor',false,false,false,'',false,0,'split',0,false)+
  '<div id="e_snirow" style="display:none"><label>'+esc(T('cover_sni_lbl'))+'</label><input id="e_sni" placeholder="'+esc(T('cover_sni_ph'))+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+T('cover_sni_note1')+'</div></div>'+
  '<div class="tglbox" id="e_gsorow"><div class="tglsw" id="e_gso" onclick="corToggleGso()"></div><div class="tt"><b>'+esc(T('gso_t'))+'</b><small>'+esc(T('gso_d'))+'</small></div></div>'+
  fecSection('e_','cor',false,10,3,true)+
  desyncSection('e_','cor',false,4,2,'ttl',false)+
  '<label>'+esc(T('core_range_lbl'))+'</label>'+ssHTML('e_snr',SUBNETRANGES(),'192.168',T('range'),'onCorSubRange')+'<div id="e_snc"></div>'+
  '<label>'+esc(T('core_port_lbl'))+'</label><input id="e_port" inputmode="numeric" placeholder="20050"></div>';
 var b=corTabsHTML()+_t1+_t2+'<div class="msg" id="e_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('cpu')+'</span><div class="ttl"><h3>'+esc(T('core_tun_t'))+'</h3><div class="sb">'+esc(T('core_tun_sub'))+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreateCore()">'+esc(T('create_tun_btn'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 corRoleLbls();renderCorIps();corRotVis();corCoverGate();corPortGate();corDesyncGate();corXhProfGate();trFade(el('e_trbar'))}
function onCorNode(){corRotVis('e_');corRoleLbls();if(el('e_spoofblk')&&_corS.Tr=='raw'&&_corS.RawProfile=='bip')corSpoofProbe()}
function renderCorIps(){renderRotIps('e_')}
// ===== shared IP-rotation UI (create prefix 'e_', edit prefix 'ee_') =====
var _rotS={};
function rotSt(px){if(!_rotS[px])_rotS[px]={on:false,aIps:[],bIps:[],aSel:{},bSel:{}};return _rotS[px]}
function corTabsHTML(){return '<div class="ctabs"><button type="button" class="ctab on" data-ct="ip" onclick="corTab(this,\\'ip\\')">'+ic('pin')+esc(T('cor_tab_ips'))+'</button><button type="button" class="ctab" data-ct="set" onclick="corTab(this,\\'set\\')">'+ic('cpu')+esc(T('cor_tab_set'))+'</button></div>'}
function corTab(btn,which){var box=btn.closest('.mbody');if(!box)return;Array.prototype.forEach.call(box.querySelectorAll('.ctab'),function(t){t.classList.toggle('on',t.getAttribute('data-ct')==which)});Array.prototype.forEach.call(box.querySelectorAll('.ctabp'),function(p){p.classList.toggle('on',p.getAttribute('data-cp')==which)});box.scrollTop=0;var _tb=box.querySelector('.trbar');if(_tb)trFade(_tb)}
// Rotation-interval presets — the same minute-scale set the flux epoch and the ws edge pool already
// offer, so every rotation control in the panel reads identically. The old sub-minute choice is gone:
// each destination hop costs a full re-handshake (the session is dropped and rebuilt), so a 1-minute
// interval bought a traffic gap every minute for no real anti-detection gain. 0 = failover-only (rotate
// only when an endpoint actually dies) and stays LAST, exactly like the ws pool's «خاموش» entry.
var ROT_PRESETS=[180,300,600,900,1800,3600];
var ROT_LABELS={180:'rot_3m',300:'rot_5m',600:'rot_10m',900:'rot_15m',1800:'rot_30m',3600:'rot_1h'};
// Styled list (ssHTML) rather than a native <select>, matching the IP/node pickers and the ws pool's
// own interval list — the native control renders as an OS sheet that looks nothing like the rest.
// The stored value is passed through RAW: no snapping, no normalising. A value that is not a preset
// (a retired option, or anything hand-set through the API) simply shows the placeholder and is kept
// verbatim until the operator picks something. With no stored value at all — the create form — ssHTML
// falls back to the first item, so a freshly enabled rotation starts at 3 minutes.
function rotSetHTML(px){var st=rotSt(px);
 var items=ROT_PRESETS.map(function(v){return {v:v,label:T(ROT_LABELS[v])}});
 items.push({v:0,label:T('rot_onfail')});
 return '<div id="'+px+'rotset" style="display:none;margin-top:2px"><label class="first">'+esc(T('rot_interval'))+'</label>'+
 ssHTML(px+'rotsecs',items,st.secs,T('rot_interval'))+'</div>'}
function rotTr(px){return px=='e_'?_corS.Tr:_eeS.Tr}
function rotIsDirect(px){return _ENUMS.tr_direct.indexOf(rotTr(px))>=0}
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
function renderRotIps(px){var srv=(px=='e_')?_corS.Srv:_eeS.Srv;['a','b'].forEach(function(side){var w=el(px+side+'ip');if(!w)return;
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
 // Styled list, not a native <select>, so read through ssVal. The `||0` is load-bearing: ssVal is
 // SEL[key]||'' and the failover-only entry's value is the NUMBER 0, which is falsy, so an untouched
 // failover selection reads back as '' and must fall through to 0 (same shape the ws pool relies on).
 var secs=parseInt(ssVal(px+'rotsecs'))||0;
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
function corSetSrv(s){_corS.Srv=s;var a=el('e_srv_a'),b=el('e_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b');renderRotIps('e_')}
// Shared per-transport submit-body builder for the create AND edit core-tunnel forms (raw/flux/dns/
// fec/desync/ws branches — identical in both modulo the _corS/_eeS state + e_/ee_ DOM prefix).
// Mutates `body`; on a validation error it sets `m` and returns true so the caller bails out.
function _collectCoreBody(S,px,m,body){
 if(S.Tr=='raw'){if(ssVal(px+'cipher')=='none'){m.className='msg err';m.textContent=T('raw_need_enc');return true}body.raw_profile=S.RawProfile;if(S.RawProfile=='bip'){var _rp=parseInt(v(px+'rawproto')||'58',10);if(!(_rp>=1&&_rp<=255)){m.className='msg err';m.textContent=T('raw_proto_bad');return true}body.raw_proto=_rp}}
 if(S.Tr=='flux'){if(ssVal(px+'cipher')=='none'){m.className='msg err';m.textContent=T('flux_need_enc');return true}body.flux_carrier=S.FluxCarrier;body.flux_rotate_secs=S.FluxRotate;body.flux_shape=S.FluxShape}
 if(S.Tr=='dns'){if(ssVal(px+'cipher')=='none'){m.className='msg err';m.textContent=T('dns_need_enc');return true}var _dz=(v(px+'dnszone')||'').trim().toLowerCase();if(!_dz){m.className='msg err';m.textContent=T('dns_need_zone');return true}var _dr=(v(px+'dnsresolvers')||'').split(/[\\s,]+/).filter(Boolean);if(!_dr.length){m.className='msg err';m.textContent=T('dns_need_resolvers');return true}body.dns_zone=_dz;body.dns_resolvers=_dr}
 if((S.Tr=='udp'||S.Tr=='raw'||S.Tr=='flux')){body.fec=S.Fec;if(S.Fec){body.fec_data=S.FecData;body.fec_parity=S.FecParity}}
 if(desyncOk(S)){body.fake_desync=S.Desync;if(S.Desync){body.fake_ttl=parseInt(v(px+'dsttl'))||4;body.fake_count=parseInt(v(px+'dscount'))||2;body.fake_mode=S.DesyncMode}}
 if(S.Tr=='ws'){body.ws_path=(v(px+'wspath')||'').trim();body.ws_tls=S.WsTls;body.ech=S.Ech;body.ech_proxy=(S.Ech&&S.EchProxy);if(S.Ech&&S.EchProxy)body.ech_proxy_url=(v(px+'echproxyurl')||'').trim();body.sni_split=S.SniSplit;if(S.SniSplit){body.split_pos=parseInt(v(px+'snisplitpos'))||0;body.sni_mode=S.SniMode;if(S.SniMode!='split')body.split_ttl=parseInt(v(px+'splitttl'))||0;}body.ws_xhttp=S.Xhttp;if(S.Xhttp){body.ws_xhttp_mode=S.XhMode;if(S.XhMode!='grpc')body.xh_profile=S.XhProf}if(poolGet(px+'').pool){var pe=poolCollect(px+'',body);if(pe!==true){m.className='msg err';m.textContent=pe;return true}}else{body.ws_pool=false;body.ws_host=(v(px+'wshost')||'').trim();body.edge_ip=(v(px+'wsedge')||'').trim();if(S.WsTls&&!body.ws_host){m.className='msg err';m.textContent=T('wss_need_host');return true}if(S.Ech&&!S.WsTls){m.className='msg err';m.textContent=T('ech_need_wss');return true}if(S.Xhttp&&S.XhMode=='grpc'&&!S.WsTls){m.className='msg err';m.textContent=T('xh_need_wss');return true}}}
 return false}
async function doCreateCore(){var m=el('e_msg');m.className='msg';var a=ssVal('e_a'),bb=ssVal('e_b');
 if(a==bb){m.className='msg err';m.textContent=T('two_diff_nodes');return}
 var body={a_node:a,b_node:bb,type:'core',server_side:_corS.Srv,cipher:ssVal('e_cipher'),transport:_corS.Tr,obfs:_corS.Obfs,cover:(_corS.Cover&&_corS.Tr=='tcp'),gso:_corS.Gso};
 if(_collectCoreBody(_corS,'e_',m,body))return;
 if(_corS.Tr=='raw'&&_corS.RawProfile=='bip'&&_corS.SpoofOk){
  if(_corS.Decoy){var dip=(v('e_decoyip')||'').trim();if(!dip){m.className='msg err';m.textContent=T('decoy_need_ip');return}body.spoof_dst=dip}
  if(_corS.Src){var sip=(v('e_srcip')||'').trim();if(sip)body.spoof_src=sip}}
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
 else{m.className='msg err';m.textContent=perr(r)}}
// ===== core edit (cipher / role / port / subnet / ips -> rebuild both ends)
_eeS.Srv='a',_eeS.Tr='udp',_eeS.Obfs=false,_eeS.Cover=false,_eeS.RawProfile='bip',_eeS.Gso=false,_eeS.FluxCarrier='udp',_eeS.FluxRotate=600,_eeS.FluxShape='random',_eeS.WsTls=false,_eeS.Ech=false,_eeS.EchProxy=false,_eeS.Xhttp=false,_eeS.XhMode='packet',_eeS.XhProf='cf',_eeS.Fec=false,_eeS.FecData=10,_eeS.FecParity=3,_eeS.Desync=false,_eeS.DesyncTtl=4,_eeS.DesyncCount=2,_eeS.DesyncMode='ttl',_eeS.SniSplit=false,_eeS.SplitPos=0,_eeS.SniMode='split',_eeS.SplitTtl=0;
function ceSetTr(t){_eeS.Tr=t;_ENUMS.tr_all.forEach(function(x){var b=el('ee_tr_'+x);if(b)b.classList.toggle('on',t==x)});ceRawVis();ceDnsVis();ceFluxVis();ceWsVis();cePortGate();ceCoverGate();ceFecGate();ceSpoofVis();ceProtoVis();ceDesyncGate();ceXhProfGate();corRotVis('ee_');onEeCipher()}   /* same obfs/dns re-gate for the edit form */
function ceFluxVis(){var w=el('ee_fluxblk');if(w)w.style.display=(_eeS.Tr=='flux')?'':'none';fluxTick()}
function ceWsVis(){var ws=_eeS.Tr=='ws';var w=el('ee_wsblk');if(w)w.style.display=ws?'':'none';var t=el('ee_wstlsrow'),e=el('ee_wsechrow');if(t)t.style.display=ws?'':'none';if(e)e.style.display=ws?'':'none';var sr=el('ee_snisplitrow');if(sr)sr.style.display=ws?'':'none';var sb=el('ee_snisplitbody');if(sb)sb.style.display=(ws&&_eeS.SniSplit)?'':'none';ceEchPxGate();if(ws){poolVis('ee_');ceWssGate()}}
function ceToggleWsTls(){_eeS.WsTls=!_eeS.WsTls;var s=el('ee_wstls');if(s)s.classList.toggle('on',_eeS.WsTls);if(!_eeS.WsTls){if(_eeS.Ech){_eeS.Ech=false;var e=el('ee_wsech');if(e)e.classList.remove('on')}if(_eeS.SniSplit){_eeS.SniSplit=false;var q=el('ee_snisplit');if(q)q.classList.remove('on');var b=el('ee_snisplitbody');if(b)b.style.display='none'}}ceEchPxGate()}
function ceToggleSni(){if(!_eeS.WsTls){_eeS.SniSplit=false;var q=el('ee_snisplit');if(q)q.classList.remove('on');alert(T('sni_need_wss'));return}_eeS.SniSplit=!_eeS.SniSplit;var s=el('ee_snisplit');if(s)s.classList.toggle('on',_eeS.SniSplit);var b=el('ee_snisplitbody');if(b)b.style.display=_eeS.SniSplit?'':'none'}
function ceSetSniMode(m){_eeS.SniMode=m;var g=el('ee_snimodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_snim_'+m)});var b=el('ee_snittlbody');if(b)b.style.display=(m!='split')?'':'none'}
function ceWssGate(){var mand=poolGet('ee_').pool||(_eeS.Xhttp&&_eeS.XhMode=='grpc');var row=el('ee_wstlsrow'),s=el('ee_wstls');if(mand){_eeS.WsTls=true;if(s)s.classList.add('on');if(row)row.classList.add('dis')}else if(row)row.classList.remove('dis')}
function ceToggleEch(){if(!_eeS.WsTls){_eeS.Ech=false;var e=el('ee_wsech');if(e)e.classList.remove('on');ceEchPxGate();alert(T('ech_need_wss_alert'));return}_eeS.Ech=!_eeS.Ech;var s=el('ee_wsech');if(s)s.classList.toggle('on',_eeS.Ech);ceEchPxGate()}
function ceToggleEchProxy(){_eeS.EchProxy=!_eeS.EchProxy;var s=el('ee_echpx');if(s)s.classList.toggle('on',_eeS.EchProxy);var b=el('ee_echpxbody');if(b)b.style.display=_eeS.EchProxy?'':'none'}
function ceEchPxGate(){var vis=(_eeS.Tr=='ws'&&_eeS.Ech),row=el('ee_echpxrow');if(!vis){_eeS.EchProxy=false;var s=el('ee_echpx');if(s)s.classList.remove('on')}if(row)row.style.display=vis?'':'none';var b=el('ee_echpxbody');if(b)b.style.display=(vis&&_eeS.EchProxy)?'':'none'}
function ceSetFluxCarrier(c){_eeS.FluxCarrier=c;var g=el('ee_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fc]'),function(t){t.classList.toggle('on',t.getAttribute('data-fc')==c)});fluxTick()}
function ceSetFluxShape(s){_eeS.FluxShape=s;var g=el('ee_fluxblk');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fs]'),function(t){t.classList.toggle('on',t.getAttribute('data-fs')==s)})}
function ceFluxRotChg(){_eeS.FluxRotate=parseInt(ssVal('ee_fluxrot'))||600;fluxTick()}
function ceFecDatagram(){return _eeS.Tr=='udp'||_eeS.Tr=='raw'||_eeS.Tr=='flux'}
function ceToggleFec(){if(!ceFecDatagram())return;_eeS.Fec=!_eeS.Fec;var s=el('ee_fecsw');if(s)s.classList.toggle('on',_eeS.Fec);var r=el('ee_fecrates');if(r)r.style.display=_eeS.Fec?'':'none'}
function ceSetFecRate(d,p){_eeS.FecData=d;_eeS.FecParity=p;var g=el('ee_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function ceFecGate(){var dg=ceFecDatagram(),row=el('ee_fecrow');if(!dg){_eeS.Fec=false;var s=el('ee_fecsw');if(s)s.classList.remove('on');var r=el('ee_fecrates');if(r)r.style.display='none'}if(row)row.style.display=dg?'':'none'}
_eeS.Decoy=false,_eeS.Src=false,_eeS.SpoofOk=false,_eeS.NodesArr=['',''];
function ceSpoofVis(){var w=el('ee_spoofblk');if(!w)return;var show=(_eeS.Tr=='raw'&&_eeS.RawProfile=='bip');w.style.display=show?'':'none';if(show)ceSpoofProbe()}
async function ceSpoofProbe(){var cap=el('ee_cap');if(!cap)return;cap.className='spoofcap wait';cap.innerHTML=esc(T('spoof_checking'));
 var res=await spoofProbePair(_eeS.NodesArr[0],_eeS.NodesArr[1]);_eeS.SpoofOk=res.ok;
 spoofApplyCap('ee_',res.ok,res.html,function(){_eeS.Decoy=false;_eeS.Src=false;
  var d=el('ee_decoysw'),s=el('ee_srcsw');if(d)d.classList.remove('on');if(s)s.classList.remove('on');
  var di=el('ee_decoyiprow'),si=el('ee_srciprow');if(di)di.style.display='none';if(si)si.style.display='none'})}
function ceToggleDecoy(){if(!_eeS.SpoofOk)return;_eeS.Decoy=!_eeS.Decoy;el('ee_decoysw').classList.toggle('on',_eeS.Decoy);el('ee_decoyiprow').style.display=_eeS.Decoy?'':'none'}
function ceToggleSrc(){if(!_eeS.SpoofOk)return;_eeS.Src=!_eeS.Src;el('ee_srcsw').classList.toggle('on',_eeS.Src);el('ee_srciprow').style.display=_eeS.Src?'':'none'}
function ceSpoofPrefill(l){var di=el('ee_decoyip'),si=el('ee_srcip');if(di&&l.spoof_dst)di.value=l.spoof_dst;if(si&&l.spoof_src)si.value=l.spoof_src;
 _eeS.Decoy=!!l.spoof_dst;_eeS.Src=!!l.spoof_src;
 var d=el('ee_decoysw'),s=el('ee_srcsw');if(d)d.classList.toggle('on',_eeS.Decoy);if(s)s.classList.toggle('on',_eeS.Src);
 var dr=el('ee_decoyiprow'),sr=el('ee_srciprow');if(dr)dr.style.display=_eeS.Decoy?'':'none';if(sr)sr.style.display=_eeS.Src?'':'none'}
function ceRawVis(){var w=el('ee_rawblk');if(w)w.style.display=(_eeS.Tr=='raw')?'':'none'}
function ceDnsVis(){var w=el('ee_dnsblk');if(w)w.style.display=(_eeS.Tr=='dns')?'':'none'}
function cePortGate(){var p=el('ee_port');if(!p)return;if(_eeS.Tr=='ws'){p.disabled=false;if(!p.value)p.value='80';p.placeholder=T('port_ws_ph');return}var np=(_eeS.Tr=='raw'||_eeS.Tr=='flux'||_eeS.Tr=='dns');p.disabled=np;if(np||p.value=='80')p.value='';p.placeholder=(_eeS.Tr=='flux')?T('port_flux_ph'):(_eeS.Tr=='dns')?T('port_dns_ph'):(np?T('port_raw_ph'):'20050')}
function ceSetProfile(p){_eeS.RawProfile=p;var g=el('ee_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});ceSpoofVis();ceProtoVis()}
function ceSetProto(val){var i=el('ee_rawproto');if(i)i.value=val;protoWarnUpd('ee_',val)}
function ceProtoWarn(){var i=el('ee_rawproto');if(i)protoWarnUpd('ee_',i.value)}
function ceProtoVis(){var w=el('ee_protorow');if(!w)return;var show=(_eeS.Tr=='raw'&&_eeS.RawProfile=='bip');w.style.display=show?'':'none';if(show){var i=el('ee_rawproto');if(i&&!i.value)i.value='58';ceProtoWarn()}}
function ceToggleGso(){_eeS.Gso=!_eeS.Gso;var s=el('ee_gso');if(s)s.classList.toggle('on',_eeS.Gso)}
function ceToggleObfs(){if(ssVal('ee_cipher')=='none')return;_eeS.Obfs=!_eeS.Obfs;var s=el('ee_obfs');if(s)s.classList.toggle('on',_eeS.Obfs)}
function ceToggleCover(){if(_eeS.Tr!='tcp')return;_eeS.Cover=!_eeS.Cover;var s=el('ee_cover');if(s)s.classList.toggle('on',_eeS.Cover);ceSniVis()}
function ceSniVis(){var w=el('ee_snirow');if(w)w.style.display=(_eeS.Cover&&_eeS.Tr=='tcp')?'':'none'}
function ceCoverGate(){var tcp=_eeS.Tr=='tcp',row=el('ee_coverrow'),s=el('ee_cover');if(!tcp){_eeS.Cover=false;if(s)s.classList.remove('on')}if(row)row.style.display=tcp?'':'none';ceSniVis()}
function onEeCipher(){_obfsGate('ee_',_eeS)}
function openCoreEdit(id){var l=FLEET.filter(function(x){return x.id==id})[0];if(!l){toast(T('not_found'),'err');return}
 editingId=id;_eeS.Srv=(l.server_side=='b')?'b':'a';_eeS.Tr=(['tcp','raw','flux','ws','dns'].indexOf(l.transport)>=0)?l.transport:'udp';_eeS.Obfs=!!l.obfs;_eeS.Cover=!!l.cover&&_eeS.Tr=='tcp';_eeS.RawProfile=l.raw_profile||'bip';_eeS.Gso=!!l.gso;_eeS.Decoy=!!l.spoof_dst;_eeS.Src=!!l.spoof_src;_eeS.SpoofOk=false;_eeS.NodesArr=[l.a_node,l.b_node];_eeS.FluxCarrier=l.flux_carrier||'udp';_eeS.FluxRotate=l.flux_rotate_secs||600;_eeS.FluxShape=l.flux_shape||'random';_eeS.WsTls=!!l.ws_tls;_eeS.Ech=!!l.ech;_eeS.EchProxy=!!l.ech_proxy;_eeS.SniSplit=!!l.sni_split;_eeS.SplitPos=l.split_pos||0;_eeS.SniMode=(l.sni_mode=='disorder'||l.sni_mode=='fake')?l.sni_mode:'split';_eeS.SplitTtl=l.split_ttl||0;_eeS.Xhttp=!!l.ws_xhttp;_eeS.XhMode=(l.ws_xhttp_mode=='grpc')?'grpc':'packet';_eeS.XhProf=(l.xh_profile=='arvan')?'arvan':'cf';_eeS.Fec=!!l.fec;_eeS.FecData=l.fec_data||10;_eeS.FecParity=l.fec_parity||3;_eeS.Desync=!!l.fake_desync;_eeS.DesyncTtl=l.fake_ttl||4;_eeS.DesyncCount=l.fake_count||2;_eeS.DesyncMode=l.fake_mode||'ttl';_eeS.PoolLid=(l.ws_pool?l.id:'');poolInit('ee_',l);_peerLid=(l.ip_rotate?l.id:'');_peerData={dst:null,src:null,now:0,polledMs:0,pinPending:null,open:{}};   // open: per-side accordion state, kept across peerTick's re-renders
 var aips=l.a_ips||[],bips=l.b_ips||[];
 // rotate_secs=0 is «فقط هنگامِ قطع», a real stored value the backend clamps to (0..86400) — not an
 // absent field. `||600` treated it as absent because 0 is falsy in JS, so opening the edit form on a
 // failover-only tunnel showed 10 minutes and SAVING wrote 10 minutes: the operator's setting was
 // silently replaced by simply looking at the form. Same !=null test the ws pool already uses.
 _rotS['ee_']={on:!!l.ip_rotate,secs:(l.rotate_secs!=null?l.rotate_secs:600),aIps:aips,bIps:bips,aSel:{},bSel:{}};
 (l.a_ip_pool||[]).forEach(function(ip){_rotS['ee_'].aSel[ip]=true});(l.b_ip_pool||[]).forEach(function(ip){_rotS['ee_'].bSel[ip]=true});
 if(l.a_ip)_rotS['ee_'].aSel[l.a_ip]=true;if(l.b_ip)_rotS['ee_'].bSel[l.b_ip]=true;
 var _t1='<div class="ctabp on" data-cp="ip"><div class="muted" style="font-size:12px;margin-bottom:10px">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+' · <span class="mono">'+esc(l.name)+'</span></div>'+
  '<div class="grid2"><div id="ee_aip"></div><div id="ee_bip"></div></div>'+
  '<div id="ee_rotrow"></div>'+rotSetHTML('ee_')+'<div id="ee_peerlive"></div>'+
  '<label>'+esc(T('roles_lbl'))+'</label><div class="seg2"><button type="button" class="segopt'+(_eeS.Srv=='a'?' on':'')+'" id="ee_srv_a" onclick="ceSetSrv(\\'a\\')"></button><button type="button" class="segopt'+(_eeS.Srv=='b'?' on':'')+'" id="ee_srv_b" onclick="ceSetSrv(\\'b\\')"></button></div>'+
  '<div class="autonote">'+ic('warn')+'<span>'+T('srv_advice')+'</span></div></div>';
 var _t2='<div class="ctabp" data-cp="set"><label>'+esc(T('enc_method_lbl'))+'</label>'+ssHTML('ee_cipher',CORE_CIPHERS(),(l.cipher||'auto'),T('cipher_ph'),'onEeCipher')+
  '<label>'+esc(T('transport_lbl'))+'</label><div class="trwrap" id="ee_trwrap"><div class="seg2 trbar" id="ee_trbar" onscroll="trFade(this)"><button type="button" class="segopt'+(_eeS.Tr=='udp'?' on':'')+'" id="ee_tr_udp" onclick="ceSetTr(\\'udp\\')"><b>UDP</b><span>'+esc(T('tr_udp_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='tcp'?' on':'')+'" id="ee_tr_tcp" onclick="ceSetTr(\\'tcp\\')"><b>TCP</b><span>'+esc(T('tr_tcp_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='raw'?' on':'')+'" id="ee_tr_raw" onclick="ceSetTr(\\'raw\\')"><b>RAW</b><span>'+esc(T('tr_raw_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='flux'?' on':'')+'" id="ee_tr_flux" onclick="ceSetTr(\\'flux\\')"><b>FLUX</b><span>'+esc(T('tr_flux_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='ws'?' on':'')+'" id="ee_tr_ws" onclick="ceSetTr(\\'ws\\')"><b>WS</b><span>CDN</span></button><button type="button" class="segopt'+(_eeS.Tr=='dns'?' on':'')+'" id="ee_tr_dns" onclick="ceSetTr(\\'dns\\')"><b>DNS</b><span>'+esc(T('tr_dns_d'))+'</span></button></div></div>'+
  '<div id="ee_rawblk" style="display:'+((_eeS.Tr=='raw')?'':'none')+'"><label>'+esc(T('raw_prof_lbl'))+'</label><div class="pgrid" id="ee_pg">'+rawTiles('ce',_eeS.RawProfile)+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:7px">'+T('raw_note')+'</div>'+protoSection('ee_','ce')+'</div>'+
  fluxSection('ee_','ce',_eeS.FluxCarrier,_eeS.FluxRotate,_eeS.FluxShape,id)+
  wsSection('ee_','ce',l.ws_host,l.ws_path,_eeS.WsTls,l.edge_ip,_eeS.Ech,_eeS.Xhttp,_eeS.XhMode,l.id,_eeS.XhProf)+
  dnsSection('ee_','ce')+
  spoofSection('ee_','ce')+
  '<div class="tglbox" id="ee_obfsrow"'+((l.cipher=='none')?' style="display:none"':'')+'><div class="tglsw'+(_eeS.Obfs?' on':'')+'" id="ee_obfs" onclick="ceToggleObfs()"></div><div class="tt"><b>'+esc(T('obfs_t'))+'</b><small>'+esc(T('obfs_d'))+'</small></div></div>'+
  '<div class="tglbox" id="ee_coverrow"'+((_eeS.Tr!='tcp')?' style="display:none"':'')+'><div class="tglsw'+(_eeS.Cover?' on':'')+'" id="ee_cover" onclick="ceToggleCover()"></div><div class="tt"><b>'+esc(T('cover_t'))+'</b><small>'+esc(T('cover_d'))+'</small></div></div>'+
  wsToggleRows('ee_','ce',_eeS.WsTls,_eeS.Ech,_eeS.EchProxy,(l.ech_proxy_url||''),_eeS.SniSplit,_eeS.SplitPos,_eeS.SniMode,_eeS.SplitTtl,_eeS.Tr=='ws')+
  '<div id="ee_snirow" style="display:'+((_eeS.Cover&&_eeS.Tr=='tcp')?'':'none')+'"><label>'+esc(T('cover_sni_lbl'))+'</label><input id="ee_sni" placeholder="'+esc(T('cover_sni_ph'))+'" value="'+esc(l.cover_sni||'')+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+T('cover_sni_note2')+'</div></div>'+
  '<div class="tglbox" id="ee_gsorow"><div class="tglsw'+(_eeS.Gso?' on':'')+'" id="ee_gso" onclick="ceToggleGso()"></div><div class="tt"><b>'+esc(T('gso_t'))+'</b><small>'+esc(T('gso_d'))+'</small></div></div>'+
  fecSection('ee_','ce',_eeS.Fec,_eeS.FecData,_eeS.FecParity,(_eeS.Tr=='udp'||_eeS.Tr=='raw'||_eeS.Tr=='flux'))+
  desyncSection('ee_','ce',_eeS.Desync,_eeS.DesyncTtl,_eeS.DesyncCount,_eeS.DesyncMode,desyncOk(_eeS))+
  '<div class="grid2"><div><label>'+esc(T('core_port_lbl2'))+'</label><input id="ee_port" inputmode="numeric" value="'+esc(l.port||'')+'" placeholder="20050"></div><div><label>'+esc(T('core_subnet_lbl'))+'</label><input id="ee_subnet" class="mono" value="'+esc(l.subnet||'')+'"></div></div>'+
  '<div class="muted" style="font-size:11px;margin:2px 2px 0">'+esc(T('core_edit_note'))+'</div></div>';
 var b=corTabsHTML()+_t1+_t2+'<div class="msg" id="ee_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('core_edit_t'))+'</h3><div class="sb">'+esc(l.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCoreEdit(\\''+id+'\\')">'+esc(T('save_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 ceRoleLbls(l);renderRotIps('ee_');corRotVis('ee_');cePortGate();ceSpoofPrefill(l);ceSpoofVis();if(el('ee_rawproto')&&l.raw_proto)el('ee_rawproto').value=l.raw_proto;ceProtoVis();if(el('ee_dnszone')&&l.dns_zone)el('ee_dnszone').value=l.dns_zone;if(el('ee_dnsresolvers')&&l.dns_resolvers)el('ee_dnsresolvers').value=(l.dns_resolvers||[]).join(', ');ceDnsVis();ceFluxVis();ceWsVis();ceDesyncGate();ceXhProfGate();trFade(el('ee_trbar'));if(_eeS.PoolLid)setTimeout(poolTick,200);if(_peerLid)setTimeout(peerTick,200)}
function ceRoleLbls(l){var a=el('ee_srv_a'),b=el('ee_srv_b');
 if(a)a.innerHTML='<b>'+esc(l.a_name)+' '+esc(T('role_server_word'))+'</b><span>'+esc(l.b_name)+' '+esc(T('role_client_word'))+'</span>';
 if(b)b.innerHTML='<b>'+esc(l.b_name)+' '+esc(T('role_server_word'))+'</b><span>'+esc(l.a_name)+' '+esc(T('role_client_word'))+'</span>'}
function ceSetSrv(s){_eeS.Srv=s;var a=el('ee_srv_a'),b=el('ee_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b');renderRotIps('ee_')}
async function doCoreEdit(id){var m=el('ee_msg');m.className='msg';m.textContent=T('saving_rebuild_both');
 var l=FLEET.filter(function(x){return x.id==id})[0]||{};
 var body={id:id,type:'core',server_side:_eeS.Srv,cipher:ssVal('ee_cipher'),transport:_eeS.Tr,obfs:_eeS.Obfs,cover:(_eeS.Cover&&_eeS.Tr=='tcp'),gso:_eeS.Gso};
 if(_collectCoreBody(_eeS,'ee_',m,body))return;
 if(_eeS.Tr=='raw'&&_eeS.RawProfile=='bip'&&_eeS.SpoofOk){
  // Send an explicit value for both spoof fields ONLY when the capability probe resolved OK —
  // then the toggles reflect real user intent, so an empty value legitimately CLEARS a decoy/source
  // (backend keys on presence). When the probe is pending or NOT-ok we OMIT these fields entirely,
  // so the backend PRESERVES the stored decoy: a flaky local CAP_NET_RAW probe (which even
  // force-toggles the switches off in the UI) must never silently strip a working decoy config.
  var dip=_eeS.Decoy?(v('ee_decoyip')||'').trim():'';
  var sip=_eeS.Src?(v('ee_srcip')||'').trim():'';
  if(_eeS.Decoy&&!dip){m.className='msg err';m.textContent=T('decoy_need_ip');return}
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
 else{m.className='msg err';m.textContent=perr(r)}}

// ===== Port-forward
function portfwSkel(){el('view').innerHTML=vhead('globe','nav_portfw','pf_sub')+
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
async function refreshPortfw(){if(editingId||RORD||RSAVE)return;var box=el('pfList');if(!box)return;var r=await j('portfw-list?offset='+(PG.portfw*LIM)+'&limit='+LIM+'&q='+encodeURIComponent(QRY.portfw));PF=(r.portfw||[]).filter(function(x){return x.name});TOT.portfw=num(r.total);
 setHTML(box,PF.length?PF.map(pfCard).join(''):'<div class="card muted">'+(QRY.portfw?T('no_results'):T('pf_empty'))+'</div>');renderPager('portfw')}
function pfCard(p,i){var h=p.health||{};
 var st=h.rule?(h.reachable?'<span class="badge ok">'+esc(T('pf_active_badge'))+CK+'</span>':'<span class="badge bad">'+esc(T('pf_rule'))+CK+' · '+esc(T('pf_dest'))+XK+'</span>'):'<span class="badge bad">'+esc(T('pf_disabled'))+'</span>';
 var rotOn=p.switch_interval>0,multi=(p.dst_ips||[]).length>1;
 var lip=p.listen_ip||p.node_ip||'';   // effective listen IP: the pin (multi-IP) or the node's sole IP (single-IP)
 var rotchip=rotOn?'<span class="tag" style="display:inline-flex;align-items:center;gap:4px;color:var(--gold);border-color:color-mix(in srgb,var(--gold) 34%,transparent);background:var(--goldw);direction:ltr">'+ic('redo')+(p.switch_interval/60)+'m</span>':'';
 var key=p.node_id+p.name,open=!!TOPEN[key];
 var route='<b class="mono" dir="ltr" style="color:var(--sub);font-size:12px">'+esc(p.listen_port)+' ↔ '+esc(p.dst_port)+'</b>';   // ports, right after the portfw tag (distinguishes several forwards on one node)
 var head='<div class="chead" onclick="cardTogFromEl(this)">'+grip()+'<div class="hmain"><div class="hrow1"><span class="hname">'+esc(p.node)+'</span><span class="ctag" style="color:#fb923c;background:color-mix(in srgb,#fb923c 15%,transparent)">portfw</span>'+route+'<span class="hpeers">'+rotchip+st+'</span></div></div>'+CHEVI+'</div>';   // no dir=ltr: margin-inline-start:auto then resolves to the RIGHT (RTL) and pushes the status badge fully LEFT
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
 return '<div class="card acc'+(open?' open':'')+'" id="c_'+esc(key)+'" data-rid="'+esc(key)+'" data-rk="portfw">'+head+'<div class="cbody"><div class="cbody-in">'+body+traf+acts+'</div></div></div>'}
function pfTgl(i){var sw=el('pe_tgl_'+i),on=!sw.classList.contains('on');sw.classList.toggle('on',on);
 setT('pe_tgllbl_'+i,on?T('on_word'):T('off_word'));var w=el('pe_intwrap_'+i);if(w)w.style.display=on?'block':'none'}
async function savePfEdit(i){var p=PF[i];if(!p)return;var m=el('pem_'+i);var lp=v('pe_lp_'+i),dp=v('pe_dp_'+i),ips=v('pe_ips_'+i);
 if(!lp||!dp||!ips){m.className='msg err';m.textContent=T('pf_need_ports');return}
 var rot=el('pe_tgl_'+i).classList.contains('on'),intv=v('pe_int_'+i);
 m.className='msg';m.textContent=T('saving');
 var lip=el('ssb_pe_lip')?ssVal('pe_lip'):'';   // only multi-IP nodes expose the picker; empty ⇒ node keeps old pin
 var r=await post('portfw-edit',{node:p.node_id,name:p.name,listen_port:lp,dst_port:dp,dst_ips:ips,rotate:rot,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{m.className='msg err';m.textContent=perr(r)}}
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
  '<div class="corverrow"><div id="cor_ver_box"></div>'+
    '<button type="button" class="ghost corcheck" onclick="corCheck()">'+ic('redo')+esc(T('cor_check'))+'</button></div>'+
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
function agentSkel(){el('view').innerHTML=vhead('cpu','ag_title','ag_sub')+agentBody();refreshAgent()}
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
 // Nothing cached yet means the operator has not checked. Say so in the picker instead of showing an
 // empty control that looks broken.
 box.innerHTML=items.length?ssHTML('corver',items,sel,T('ag_pick_version'),'')
   :'<div class="corempty">'+esc(T('cor_ver_empty'))+'</div>'}
// The panel no longer polls GitHub on its own. This is the ONLY thing that fetches the release list,
// and it runs when the operator asks. It reports what it found rather than silently reordering the
// dropdown, because "is there a new version" is the actual question being asked.
async function corCheck(){var m=el('cor_msg');if(m){m.className='msg';m.textContent=T('cor_checking')}
 var res=await post('core-check',{});var d=(res&&res.d)||{};
 if(!(res.ok&&d.ok)){if(m){m.className='msg err';m.textContent=terr(d.error||T('err_github'))}return}
 await loadCoreVersions();
 if(m){m.className='msg ok';
  m.textContent=!d.count?T('cor_check_none')
    :d.first_check?T('cor_check_first').replace('{n}',d.count)
    :d.newer?T('cor_check_new'):T('cor_check_same')}}
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
function fmtEvTime(ts){var d=new Date(ts*1000);try{return d.toLocaleString('fa-IR',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}catch(e){return d.toISOString().slice(0,16).replace('T',' ')}}
function logsSkel(){el('view').innerHTML=vhead('activity','logs_title','logs_sub')+
 '<div class="tbtnrow" style="margin-bottom:10px"><button class="chkall" onclick="logsClear()">'+ic('trash')+esc(T('logs_clear'))+'</button></div>'+
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
 if(LOGFILTER!='all'&&!(c[LOGFILTER]>0))LOGFILTER='all';   // an emptied category (e.g. «فقط خطاها» at 0) can't stay active — fall back to «همه»
 var order=[['all','logc_all'],['tunnel','logc_tunnel'],['rot','logc_rot'],['ech','logc_ech'],['node','logc_node'],['sys','logc_sys'],['err','logc_err']];
 return '<div class="logchips">'+order.filter(function(o){return o[0]=='all'||c[o[0]]>0}).map(function(o){var k=o[0];   // «فقط خطاها» now hides at 0 just like every other category
   return '<div class="fchip'+(LOGFILTER==k?' on':'')+'" data-f="'+k+'" onclick="logFilter(\\''+k+'\\')">'+esc(T(o[1]))+'<span class="ct">'+(c[k]||0)+'</span></div>';}).join('')+'</div>';}
// The filtered list. Each card carries a colored category badge before the title.
function logListHTML(){
 var evs=LOGEVS.filter(function(e){return LOGFILTER=='all'?true:LOGFILTER=='err'?e.level=='bad':logCat(e)==LOGFILTER;});
 if(!evs.length)return '<div class="card muted">'+esc(T('logc_none'))+'</div>';
 return evs.map(function(e){
   var lv=e.level=='bad'?'xc':(e.level=='warn'?'warn':'okc');
   var col=e.level=='bad'?'var(--bad)':(e.level=='warn'?'var(--gold)':'var(--ok)');
   var p=evParts(e);
   return '<div class="card logcard">'+
     '<span class="lstripe" style="background:'+col+'"></span>'+
     '<div class="lbody">'+
       '<span class="lico" style="color:'+col+';background:color-mix(in srgb,'+col+' 14%,transparent)">'+ic(lv)+'</span>'+
       '<div class="lmain">'+
         '<span dir="auto" class="ltitle">'+esc(p.title)+'</span>'+
         evDetail(p.lines)+'</div>'+
       '<span class="mono ltime">'+esc(fmtEvTime(e.ts))+'</span>'+
     '</div></div>';}).join('');}
// Only toggle the active class on the existing chips (do NOT rebuild the row) — rebuilding resets the
// horizontal scrollLeft, which snapped the row back to the start when picking a scrolled-to tab. Counts
// don't change on a filter pick, so an in-place highlight is enough; a full refreshLogs still rebuilds.
function logFilter(k){LOGFILTER=k;var ch=el('logChips');
 if(ch){var cs=ch.querySelectorAll('.fchip');for(var i=0;i<cs.length;i++)cs[i].classList.toggle('on',cs[i].getAttribute('data-f')===k);}
 var box=el('logList');if(box)setHTML(box,logListHTML());}
// Split an event into a clean title + detail lines. Every event carries its structure in dfa
// (detail, possibly multi-line); an event with no detail is title-only.
function evParts(e){
 var det=e.dfa||'';
 return{title:e.fa||'',lines:det?det.split('\\n'):[]};
}
// Every detail line is either «از: X» / «به: Y» — a move — or a plain sentence. Render the move as two
// labelled rows one under the other, so the eye compares the two values vertically instead of hunting
// along a wrapped line. Values are LTR-isolated: an IP:port · domain must not be reordered by the RTL
// page. This replaces evLine/evEdgeBox/evVal, which rendered the same data three different ways
// depending on the event kind — a move looked different on a rot event than on an edge event.
// A detail line is one of two things:
//   «key: value» -> a labelled pill (از / به / لبه / دامنه / کلیدِ ECH / نودِ مقصد …); «به» is accented
//   anything else -> a plain sentence
// A label is SHORT and free of sentence punctuation — that is the whole test. The older one also
// demanded no space, which quietly demoted every multi-word label the backend emits («کلیدِ ECH»,
// «نودِ مقصد», «کلیدِ تازهٔ ECH») to a grey sentence — so a 300-char base64 key was dumped
// inline instead of boxed. tools/log_labels_check.py pins this gate against the labels the Python
// side really emits, so the two can no longer drift apart in silence.
function evDetail(lines){if(!lines||!lines.length)return '';
 var rows=[],notes=[];
 for(var i=0;i<lines.length;i++){var l=lines[i],c=l.indexOf(': ');
  var k=c>0?l.slice(0,c):'';
  if(k&&k.length<=16&&!/[\u060C\u061B\u061F.!?()\u00AB\u00BB\u2014]/.test(k))rows.push({k:k,v:l.slice(c+2)});
  else notes.push(l);}
 var out='';
 if(rows.length)out+='<div class="lfromto">'+rows.map(function(m){
   return '<div class="lft'+(m.k=='\u0628\u0647'?' to':'')+'"><span class="k">'+esc(m.k)+':</span>'+
          '<span class="v">'+esc(m.v)+'</span></div>'}).join('')+'</div>';
 for(var j=0;j<notes.length;j++)out+='<div class="lnote" dir="auto">'+esc(notes[j])+'</div>';
 return out}

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
function settingsSkel(){el('view').innerHTML=vhead('cog','nav_settings','set_sub')+'<div id="setBox"><div class="card muted">'+esc(T('loading'))+'</div></div>'}
var _setMode='alert',_modeOv=null;
function modeLabel(m){return m=='auto'?T('set_mode_auto'):T('set_mode_alert')}
async function refreshSettings(){var s=await j('settings').catch(function(){return{}});var box=el('setBox');if(!box)return;
 _setMode=(s.reconcile_mode=='auto')?'auto':'alert';
 var row=function(t,d,ctl){return '<div class="setrow"><div class="setlbl"><b>'+t+'</b><span>'+d+'</span></div><div class="setctl">'+ctl+'</div></div>'};
 box.innerHTML=grp('set_g1','set_g1h','set_g1c','sc-panel',
  qr(T('set_on_ipchange'),'set_on_ipchange_d','set_x_ipchange','<button type="button" class="setfield" onclick="openModePopup()"><span class="val" id="set_mode_val">'+modeLabel(_setMode)+'</span><span class="cv">'+ic('chev')+'</span></button>')+
  qr(T('set_rec_int'),'set_rec_range','set_x_rec','<input id="set_rec" class="search" type="number" min="5" max="3600" value="'+(num(s.reconcile_interval)||15)+'">')+
  qr(T('set_poll_int'),'set_poll_range','set_x_poll','<input id="set_poll" class="search" type="number" step="0.1" min="0.3" max="60" value="'+(num(s.poll_interval)||2)+'">')+
  qr(T('set_ui_int'),'set_ui_range','set_x_ui','<input id="set_ui" class="search" type="number" step="0.1" min="0.3" max="60" value="'+(num(s.ui_interval)||2)+'">')+
  qr(T('set_ech_int'),'set_ech_range','set_x_ech','<input id="set_ech" class="search" type="number" step="1" min="0" max="1440" value="'+(s.ech_refresh_mins!=null?num(s.ech_refresh_mins):15)+'">')+
  qr(T('set_upwin'),'set_upwin_d','set_x_upwin',ssHTML('set_upwin',[{v:'1',label:T('h1')},{v:'3',label:T('h3')},{v:'6',label:T('h6')},{v:'8',label:T('h8')},{v:'12',label:T('h12')},{v:'24',label:T('h24')}],String(num(s.uptime_window)||1),'',''))+
  '<div class="tbtnrow" style="margin:14px 0 0;align-items:center"><button class="primary" onclick="saveSettings()">'+ic('check')+esc(T('save'))+'</button><span class="msg" id="set_msg" style="align-self:center"></span></div>')+
  tuningCard(s)+
  '<div class="sec" style="margin-top:8px">'+ic('redo','var(--acc)')+' '+esc(T('set_agent_update'))+'</div>'+agentBody();
 tunDaBind();refreshAgent()}
// A settings row with a "?" that expands a concept + example; grp() wraps a scope-tagged group card.
function tgExp(b){var r=b.closest('.setrow2');var o=r.classList.toggle('exp-open');b.setAttribute('aria-expanded',o?'true':'false');b.textContent=o?'×':'؟'}
function qr(lbl,ck,xk,ctl,rc){return '<div class="setrow2'+(rc?' '+rc:'')+'"><div class="setrow2-top"><b class="setlbl2">'+lbl+'</b><button type="button" class="qbtn" onclick="tgExp(this)" aria-expanded="false">؟</button><div class="setctl">'+ctl+'</div></div><div class="setexp"><p>'+T(ck)+'</p><p class="setex">'+T(xk)+'</p></div></div>'}
// A settings group is a COLLAPSIBLE card. These blocks are long — seven of them stacked made the page
// a scroll marathon on a phone — so each collapses to its header. Open state is per-group and kept in
// _setOpen, because refreshSettings() rebuilds this HTML wholesale and would otherwise reset it.
// gk is a stable key; pass gk='' for a card that must never collapse (the panel-wide group).
var _setOpen={};
function setAcc(k){_setOpen[k]=!_setOpen[k];var b=el('sgb_'+k),c=el('sgc_'+k),h=el('sgh_'+k);
 if(b)b.style.display=_setOpen[k]?'':'none';if(c)c.classList.toggle('open',!!_setOpen[k]);
 // aria was written once at render time and never touched again, so the FIRST interaction made it
 // say the opposite of the truth for the rest of the session.
 if(h)h.setAttribute('aria-expanded',_setOpen[k]?'true':'false')}
function grp(tk,hk,ck,cls,rows,gk){
 // The <small> sub-header is gone: it restated the scope chip next to it («تونل‌های ws/xhttp» beside
 // «فقط WS-CDN»), so it cost a line of height per card and told the operator nothing new.
 var hd='<div class="grphd"><span class="gdot"></span><b>'+T(tk)+'</b><span class="schip">'+T(ck)+'</span></div>';
 if(!gk)return '<div class="card setgrp '+cls+'">'+hd+rows+'</div>';
 var op=!!_setOpen[gk];
 return '<div class="card setgrp sacc '+cls+'">'
  +'<div class="grphd acch" id="sgh_'+gk+'" data-acc onclick="setAcc(\\''+gk+'\\')" role="button" tabindex="0" aria-expanded="'+(op?'true':'false')+'">'
  +'<span class="grphdl"><span class="gdot"></span><b>'+T(tk)+'</b><span class="schip">'+T(ck)+'</span></span>'
  +'<span class="pchev'+(op?' open':'')+'" id="sgc_'+gk+'">&#9662;</span></div>'
  +'<div class="setgrpb" id="sgb_'+gk+'"'+(op?'':' style="display:none"')+'>'+rows+'</div></div>'}
// Operational self-heal / pool-health timings, grouped by category. Applies to a tunnel on its next
// build/rebuild (stamped into the core config), so changing a value here + rebuilding heals with it.
var _TUNDEF=__TUNDEF_JSON__;   /* injected at import from the panel's _TUNING_DEFAULTS — single source of truth */
function _tv(s,k){var t=(s&&s.tuning)||{};return (t[k]!=null?t[k]:_TUNDEF[k])}
function tNum(id,val,mn,mx){return '<input id="'+id+'" class="search" type="number" step="1" min="'+mn+'" max="'+mx+'" value="'+esc(String(val))+'">'}
function tuningCard(s){
 return '<div class="sec2" style="margin:14px 2px 2px">'+ic('activity','var(--acc)')+' '+esc(T('set_tun_hd'))+'</div>'+
  '<div class="muted" style="font-size:11px;line-height:1.8;margin:0 2px 4px">'+esc(T('set_tun_note'))+'</div>'+
  grp('set_g2','set_g2h','set_g2c','sc-both',
    qr(T('set_t_suspect'),'set_t_suspect_d','set_x_suspect','<input id="set_t_suspect" class="search wtxt" type="text" inputmode="numeric" value="'+esc(_tv(s,'suspect_backoff').join(', '))+'">')+
    qr(T('set_t_deadretest'),'set_t_deadretest_d','set_x_deadretest',tNum('set_t_deadretest',_tv(s,'dead_retest_secs'),5,86400))+
    qr(T('set_t_pinttl'),'set_t_pinttl_d','set_x_pinttl',tNum('set_t_pinttl',_tv(s,'pin_ttl_secs'),1,3600)),'g2')+
  grp('set_g3','set_g3h','set_g3c','sc-ws',
    qr(T('set_t_datafail'),'set_t_datafail_d','set_x_datafail',tNum('set_t_datafail',_tv(s,'data_fail_threshold'),1,100))+
    qr(T('set_t_datagood'),'set_t_datagood_d','set_x_datagood',tNum('set_t_datagood',_tv(s,'data_good_window_secs'),1,86400))+
    qr(T('set_t_probeto'),'set_t_probeto_d','set_x_probeto',tNum('set_t_probeto',_tv(s,'probe_timeout_secs'),1,120)),'g3')+
  /* MERGED: the fixed deadline and the failure thresholds are one subject — both are global, both apply
     to every carrier, and neither is affected by the auto/fixed switch. They were two cards only because
     they were written at different times. ping_loss and min_liveness stay NON-auto (ApplyTuning applies
     them unconditionally, on paths that never consult the dead window) — see #254. */
  grp('set_gkd','set_gkdh','set_gkdc','sc-both',
    qr(T('set_t_keepalive'),'set_t_keepalive_d','set_x_keepalive',tNum('set_t_keepalive',_tv(s,'keepalive'),5,120))+
    qr(T('set_t_deadafter'),'set_t_deadafter_d','set_x_deadafter',tNum('set_t_deadafter',_tv(s,'dead_after_secs'),0,300))+
    '<div class="muted" id="tun_dahint" style="font-size:11.5px;line-height:1.8;margin:8px 4px 6px"></div>'+
    qr(T('set_t_pingloss'),'set_t_pingloss_d','set_x_pingloss',tNum('set_t_pingloss',_tv(s,'ping_loss_threshold'),1,100))+
    qr(T('set_t_minlive'),'set_t_minlive_d','set_x_minlive',tNum('set_t_minlive',_tv(s,'min_liveness_secs'),1,3600)),'gkd')+
  grp('set_g4','set_g4h','set_g4c','sc-both',
    qr(T('set_t_idlemult'),'set_t_idlemult_d','set_x_idlemult',tNum('set_t_idlemult',_tv(s,'idle_mult'),1,100),'tun-auto')+
    qr(T('set_t_idlemin'),'set_t_idlemin_d','set_x_idlemin',tNum('set_t_idlemin',_tv(s,'idle_min_secs'),1,86400),'tun-auto'),'g4')+
  /* MERGED: datagram staleness and the socket buffer are the same audience (udp/raw/flux). The merge is
     only safe because tun-auto moved to the ROW: the two staleness knobs are greyed by a positive fixed
     deadline, the socket buffer never is (it is a throughput knob, unrelated to the dead-window formula).
     Marking the whole CARD auto here would grey out sock_buf and label it inert — exactly the #254 bug. */
  grp('set_g5','set_g5h','set_g5c','sc-dgram',
    qr(T('set_t_ssmult'),'set_t_ssmult_d','set_x_ssmult',tNum('set_t_ssmult',_tv(s,'session_stale_mult'),1,100),'tun-auto')+
    qr(T('set_t_ssmin'),'set_t_ssmin_d','set_x_ssmin',tNum('set_t_ssmin',_tv(s,'session_stale_min_secs'),1,86400),'tun-auto')+
    qr(T('set_t_sockbuf'),'set_t_sockbuf_d','set_x_sockbuf',tNum('set_t_sockbuf',_tv(s,'sock_buf_mb'),0,64)),'g5')+
  '<div class="tbtnrow" style="margin:12px 2px 0;align-items:center;gap:8px"><button class="primary" onclick="saveTuning()">'+ic('check')+esc(T('save'))+'</button><button class="ghost" onclick="resetTuning()">'+ic('reset')+esc(T('set_tun_reset'))+'</button><span class="msg" id="tun_msg" style="align-self:center"></span></div>'}
function _collectTuning(){
 var sb=(v('set_t_suspect')||'').split(',').map(function(x){return parseInt(x.trim())}).filter(function(n){return n>=1&&n<=86400});
 var t={keepalive:parseInt(v('set_t_keepalive')),dead_after_secs:parseInt(v('set_t_deadafter')),dead_retest_secs:parseInt(v('set_t_deadretest')),pin_ttl_secs:parseInt(v('set_t_pinttl')),data_fail_threshold:parseInt(v('set_t_datafail')),data_good_window_secs:parseInt(v('set_t_datagood')),idle_mult:parseInt(v('set_t_idlemult')),idle_min_secs:parseInt(v('set_t_idlemin')),session_stale_mult:parseInt(v('set_t_ssmult')),session_stale_min_secs:parseInt(v('set_t_ssmin')),ping_loss_threshold:parseInt(v('set_t_pingloss')),min_liveness_secs:parseInt(v('set_t_minlive')),probe_timeout_secs:parseInt(v('set_t_probeto')),sock_buf_mb:parseInt(v('set_t_sockbuf'))};
 if(sb.length)t.suspect_backoff=sb;
 return t}
// The stream/datagram multiplier groups only decide the dead window while the fixed deadline is 0: a
// positive dead_after_secs overrides BOTH families (core deadWindow()), so grey them out and say so
// instead of leaving the operator tuning knobs that currently have no effect. Disabled inputs keep
// their .value, so _collectTuning still round-trips them untouched.
function tunDaSync(){var d=el('set_t_deadafter');if(!d)return;
 var v=Math.max(0,parseInt(d.value)||0),k=el('set_t_keepalive'),ka=Math.max(5,parseInt(k&&k.value)||15);
 var on=v>0,eff=Math.max(v,2*ka),h=el('tun_dahint');
 if(h)h.textContent=on?(T('set_da_fixed').replace('{n}',eff)+(eff>v?' '+T('set_da_floored').replace('{v}',v).replace('{n}',eff):'')):T('set_da_auto');
 // Grey out the AUTO-only knobs by ROW, not by card. They used to be marked on the whole group, which
 // worked only while every row in a group was auto. Now that datagram staleness shares a card with the
 // socket buffer, a card-level sweep would disable sock_buf too and label it inert — the exact defect
 // #254 fixed for ping_loss/min_liveness. One note per card that CONTAINS auto rows, placed under the
 // header so a collapsed card still reads correctly when opened.
 var rows=document.querySelectorAll('.setrow2.tun-auto'),seen=[];
 for(var i=0;i<rows.length;i++){var r=rows[i];
  var ins=r.querySelectorAll('input');for(var q=0;q<ins.length;q++)ins[q].disabled=on;
  r.classList.toggle('tun-off',on);
  var g=r.closest('.setgrp');if(g&&seen.indexOf(g)<0)seen.push(g)}
 for(var j=0;j<seen.length;j++){var g2=seen[j],n=g2.querySelector('.tun-state');
  if(!n){n=document.createElement('div');n.className='tun-state';n.style.cssText='font-size:11px;line-height:1.7;margin:-2px 4px 8px';
   var host=g2.querySelector('.setgrpb')||g2;host.insertBefore(n,host.firstChild)}
  n.textContent=on?T('set_auto_off'):T('set_auto_only');
  n.style.color=on?'var(--gold)':'var(--sub)'}}
function tunDaBind(){var ids=['set_t_deadafter','set_t_keepalive'];
 for(var i=0;i<ids.length;i++){var e=el(ids[i]);if(e)e.addEventListener('input',tunDaSync)}
 tunDaSync()}
async function saveTuning(){var m=el('tun_msg');if(m){m.className='msg';m.textContent=T('saving')}
 var r=await post('settings-set',{tuning:_collectTuning()});
 if(r.ok&&r.d.ok){if(m){m.className='msg';m.textContent=''}toast(T('set_tun_saved'),'ok')}
 else{if(m){m.className='msg err';m.textContent=perr(r)}}}
async function resetTuning(){if(!await confirmBox(T('set_tun_reset_confirm')))return;
 var r=await post('settings-set',{tuning:_TUNDEF});
 if(r.ok&&r.d.ok){toast(T('set_tun_saved'),'ok');refreshSettings()}
 else{toast(perr(r),'err')}}
function openModePopup(){var opt=function(m,df){return '<div class="mopt'+(_setMode==m?' on':'')+'" onclick="pickMode(\\''+m+'\\')"><span class="mrad"></span><span class="mt">'+modeLabel(m)+'</span>'+(df?'<span class="mdf">'+esc(T('set_default'))+'</span>':'')+'</div>'};
 _modeOv=openModal('<div class="modelist">'+opt('auto',false)+opt('alert',true)+'</div>',{cls:'modesheet'})}
function pickMode(m){_setMode=m;setT('set_mode_val',modeLabel(m));if(_modeOv){closeModal(_modeOv);_modeOv=null}}
async function saveSettings(){var m=el('set_msg');if(m){m.className='msg';m.textContent=T('saving')}
 var r=await post('settings-set',{reconcile_mode:_setMode,reconcile_interval:v('set_rec'),poll_interval:v('set_poll'),ui_interval:v('set_ui'),ech_refresh_mins:v('set_ech'),uptime_window:ssVal('set_upwin')});
 if(r.ok&&r.d.ok){if(m){m.className='msg';m.textContent=''}toast(T('set_saved'),'ok')}
 else{if(m){m.className='msg err';m.textContent=perr(r)}}}
function tick(){if(document.hidden){clearTimeout(TT);TT=setTimeout(tick,Math.max(UIV,4000));return}  // hidden tab: back off, don't burn cycles
 updateSidebar();refresh().catch(function(){}).then(function(){clearTimeout(TT);TT=setTimeout(tick,UIV)})}
document.addEventListener('visibilitychange',function(){if(!document.hidden){clearTimeout(TT);tick()}});
// Every accordion header is role="button" + tabindex="0", so it has to answer Enter and Space like
// one; none of them did. Delegated, so a header only has to carry data-acc and its own onclick.
document.addEventListener('keydown',function(e){if(e.key!='Enter'&&e.key!=' ')return;
 var h=e.target&&e.target.closest&&e.target.closest('[data-acc]');if(!h)return;
 e.preventDefault();h.click()});
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

# Keep the browser's tuning defaults in lock-step with the Python source of truth: inject _TUNING_DEFAULTS
# as JSON at import time, so there is NO hand-copied JS literal to drift (consolidation Track B). The
# tools/tuning_consistency.py guard enforces the remaining panel<->core<->node agreement.
INDEX_HTML = INDEX_HTML.replace("__TUNDEF_JSON__", json.dumps(_TUNING_DEFAULTS, separators=(",", ":")))
# transport families + ciphers -> browser, so the enum lives only in the Python consts above (Track B).
INDEX_HTML = INDEX_HTML.replace("__ENUMS_JSON__", json.dumps(
    {"ciphers": list(CORE_CIPHERS), "tr_all": list(CORE_TRANSPORTS), "tr_direct": list(DIRECT_TRANSPORTS)},
    separators=(",", ":")))

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
