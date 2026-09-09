#!/usr/bin/env python3

import base64
import getpass
import gzip
import hashlib
import hmac
import http.client
import ipaddress
import ssl
import json
import os
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CENTRAL_DIR = "/opt/tnl-central"
WEB_CONF = os.path.join(CENTRAL_DIR, "web.conf")
NODES_FILE = os.path.join(CENTRAL_DIR, "nodes.json")
PROXIES_FILE = os.path.join(CENTRAL_DIR, "proxies.json")
LINKS_FILE = os.path.join(CENTRAL_DIR, "links.json")
TRAFFIC_FILE = os.path.join(CENTRAL_DIR, "traffic.json")
SETTINGS_FILE = os.path.join(CENTRAL_DIR, "settings.json")
PENDING_FILE = os.path.join(CENTRAL_DIR, "pending_del.json")
UPTIME_FILE = os.path.join(CENTRAL_DIR, "uptime.json")
PORTFW_ORDER_FILE = os.path.join(CENTRAL_DIR, "portfw-order.json")
MOVED_FILE = os.path.join(CENTRAL_DIR, "moved.json")
AGENT_FILE = os.path.join(CENTRAL_DIR, "agent.py")
AGENT_META = os.path.join(CENTRAL_DIR, "agent.meta.json")
CORE_BLOB = os.path.join(CENTRAL_DIR, "core.bin")
CORE_BLOB_META = os.path.join(CENTRAL_DIR, "core.meta.json")
SERVICE_FILE = "/etc/systemd/system/tnl-central.service"
SELF_PATH = os.path.realpath(__file__)
INSTALLED = os.path.join(CENTRAL_DIR, "tnl-central.py")

SESSION_TTL = 8 * 3600
PBKDF2_ITERS = 150_000
TYPES = ("vxlan", "gre", "sit", "ipip", "l2tpv3", "fou", "ipsec", "core")
IPIP_FAMILY = ("ipip", "fou")
CORE_CIPHERS = ("auto", "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "xchacha20-poly1305", "none")
CORE_RAW_PROFILE_PROTOS = {"bare": 253, "ipip": 4, "gre": 47, "icmp": 1, "udp": 17, "tcp": 6, "esp": 50,
                           "ah": 51, "etherip": 97, "ipcomp": 108, "l2tpv3": 115}
CORE_RAW_PROFILES = tuple(sorted(CORE_RAW_PROFILE_PROTOS))
CORE_TRANSPORTS       = ("udp", "tcp", "raw", "ws", "dns")
DIRECT_TRANSPORTS     = ("udp", "tcp", "raw")
DATAGRAM_TRANSPORTS   = ("udp", "raw")
DESYNC_TRANSPORTS     = ("raw", "tcp", "ws")
DESYNC_INJECT_TRANSPORTS = ("tcp", "ws")
DESYNC_INJECT_TTL_MAX = 8
SPLIT_TTL_MAX = DESYNC_INJECT_TTL_MAX
CORE_MAX_WORKERS = 8
QUEUEING_TRANSPORTS = ("raw", "udp")
STATUSRING_TRANSPORTS = ("udp", "tcp", "raw", "ws", "dns")
_reg_lock = threading.Lock()
_pending_lock = threading.Lock()
_agent_lock = threading.Lock()
_core_blob_lock = threading.Lock()
_node_locks = {}
_node_locks_guard = threading.Lock()
_settings = {}
_settings_lock = threading.RLock()
_drift = {}
_drift_lock = threading.Lock()
_CENTRAL_PORT = 0
_CENTRAL_TLS = False
_CENTRAL_HOST = {"ip": "", "ts": 0.0}
_central_host_lock = threading.Lock()
CENTRAL_HOST_TTL = 300


def central_host():
    with _central_host_lock:
        now = time.time()
        if _CENTRAL_HOST["ip"] and now - _CENTRAL_HOST["ts"] < CENTRAL_HOST_TTL:
            return _CENTRAL_HOST["ip"]
        ip = central_ip()
        _CENTRAL_HOST["ip"] = ip if is_ipv4(ip) else ""
        _CENTRAL_HOST["ts"] = now
        return _CENTRAL_HOST["ip"]


def _central_headers():
    if not _CENTRAL_PORT:
        return {}
    h = {"X-Central-Port": str(_CENTRAL_PORT), "X-Central-TLS": "1" if _CENTRAL_TLS else "0"}
    ip = central_host()
    if ip:
        h["X-Central-Host"] = ip
    return h


class _PairLock:
    def __init__(self, *node_ids):
        self._ids = sorted({str(i) for i in node_ids if i})
        self._held = []

    def __enter__(self):
        for i in self._ids:
            while True:
                with _node_locks_guard:
                    lk = _node_locks.setdefault(i, threading.Lock())
                lk.acquire()
                with _node_locks_guard:
                    if _node_locks.get(i) is lk:
                        break
                lk.release()
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
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


_TUNING_DEFAULTS = {
    "suspect_backoff": [600, 1800, 3600],
    "dead_retest_secs": 21600,
    "min_liveness_secs": 20,
    "probe_min_pct": 15,
    "ladder_revive": [45, 180, 600],
    "sock_buf_mb": 4,
}
REVIVE_STEP_MIN, REVIVE_STEP_MAX = 10, 3600
BACKOFF_STEP_MIN, BACKOFF_STEP_MAX = 1, 86400
_TUNING_LIST_KEYS = ("suspect_backoff", "ladder_revive")
_TUNING_LIST_RANGES = {"suspect_backoff": (BACKOFF_STEP_MIN, BACKOFF_STEP_MAX),
                       "ladder_revive": (REVIVE_STEP_MIN, REVIVE_STEP_MAX)}
_PROBE_SAMPLES = 20
_TUNING_STEPS = {"probe_min_pct": (5, "حداقلِ بسته‌های برگشتی")}
_TUNING_LIST_LABELS = {"suspect_backoff": "زمان‌بندیِ تستِ مجددِ موقت‌سوخته",
                       "ladder_revive": "صبر پیش از تلاشِ دوبارهٔ نردبان"}
_TUNING_NUM_LABELS = {"dead_retest_secs": "تستِ مجددِ آی‌پیِ سوخته",
                      "min_liveness_secs": "حداقلِ عمرِ سشنِ سالم",
                      "probe_min_pct": "حداقلِ بسته‌های برگشتی",
                      "sock_buf_mb": "بافرِ سوکت"}
_TUNING_RANGES = {
    "dead_retest_secs": (5, 86400),
    "min_liveness_secs": (1, 3600),
    "probe_min_pct": (5, 100),
    "sock_buf_mb": (0, 64),
}


def _raw_proto_owner(proto):
    for name, num in CORE_RAW_PROFILE_PROTOS.items():
        if num == int(proto) and name != "bare":
            return name
    return ""


def _check_raw_proto(proto):
    if not 1 <= int(proto) <= 255:
        raise ValueError("شمارهٔ پروتکلِ IP باید بینِ 1 تا 255 باشد")
    owner = _raw_proto_owner(proto)
    if owner:
        raise ValueError(
            f"پروتکلِ {int(proto)} مالِ پروفایلِ «{owner}» است. این حامل هیچ هدری نمی‌سازد، پس پاکت با "
            f"شمارهٔ {int(proto)} بیرون می‌رود ولی جای هدرِ {owner} دادهٔ رمزشده دارد — دستگاه‌های میانِ راه "
            f"آن را بدشکل می‌بینند و می‌اندازند. پروفایلِ «{owner}» را انتخاب کن که هدرش را هم می‌سازد.")


def _validate_tuning(raw, base=None):
    out = dict(_TUNING_DEFAULTS)
    if isinstance(base, dict):
        out.update({k: base[k] for k in _TUNING_DEFAULTS if k in base})
    if not isinstance(raw, dict):
        return out
    for k, (lo, hi) in _TUNING_RANGES.items():
        if k in raw and raw[k] in (None, ""):
            raise ValueError("«%s» را خالی نگذار — عددی بینِ %d تا %d بگذار"
                             % (_TUNING_NUM_LABELS.get(k, k), lo, hi))
        if k in raw and raw[k] not in (None, ""):
            try:
                v = int(raw[k])
            except (TypeError, ValueError):
                continue
            step, label = _TUNING_STEPS.get(k, (0, ""))
            if step and v % step:
                raise ValueError("«%s» باید مضربی از %d باشد — %d پذیرفته نیست" % (label, step, v))
            out[k] = max(lo, min(hi, v))
    for k, (lo, hi) in _TUNING_LIST_RANGES.items():
        if k not in raw or not isinstance(raw[k], (list, tuple)):
            continue
        steps = []
        for x in raw[k]:
            try:
                iv = int(x)
            except (TypeError, ValueError):
                continue
            if not lo <= iv <= hi:
                raise ValueError("«%s» باید بینِ %d تا %d ثانیه باشد — %d پذیرفته نیست"
                                 % (_TUNING_LIST_LABELS[k], lo, hi, iv))
            steps.append(iv)
        if steps:
            out[k] = steps
    return out


def _settings_tuning():
    s = get_settings().get("tuning")
    if not isinstance(s, dict):
        s = {}
    out = {}
    for k, dv in _TUNING_DEFAULTS.items():
        v = s.get(k, dv)
        if k in _TUNING_LIST_KEYS:
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
        "reconcile_mode": "alert",
        "reconcile_interval": 15,
        "poll_interval": 2,
        "ui_interval": 2,
        "uptime_window": 1,
        "ech_refresh_mins": 15,
        "agent_delivery": "push",
        "core_delivery": "push",
        "dl_proxy_on": False,
        "dl_proxy_id": "",
        "tuning": dict(_TUNING_DEFAULTS),
    }


DELIVERY_MODES = ("push", "github", "panel")


def load_settings():
    d = settings_defaults()
    try:
        with open(SETTINGS_FILE) as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            d.update(stored)
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
    out = get_settings()
    if "reconcile_mode" in d:
        m = str(d["reconcile_mode"]).strip().lower()
        if m not in ("auto", "alert"):
            raise ValueError("حالت باید auto یا alert باشد")
        out["reconcile_mode"] = m
    if "reconcile_interval" in d and d["reconcile_interval"] not in (None, ""):
        out["reconcile_interval"] = max(5, min(3600, int(d["reconcile_interval"])))
    if "poll_interval" in d and d["poll_interval"] not in (None, ""):
        out["poll_interval"] = max(0.3, min(60.0, round(float(d["poll_interval"]), 2)))
    if "ui_interval" in d and d["ui_interval"] not in (None, ""):
        out["ui_interval"] = max(0.3, min(60.0, round(float(d["ui_interval"]), 2)))
    if "uptime_window" in d and d["uptime_window"] not in (None, ""):
        w = int(d["uptime_window"])
        out["uptime_window"] = w if w in (1, 3, 6, 8, 12, 24) else 1
    if "ech_refresh_mins" in d and d["ech_refresh_mins"] not in (None, ""):
        m = round(float(d["ech_refresh_mins"]), 2)
        out["ech_refresh_mins"] = 0.0 if m <= 0 else max(1.0, min(1440.0, m))
    for k in ("agent_delivery", "core_delivery"):
        if k in d:
            m = str(d[k]).strip().lower()
            if m not in DELIVERY_MODES:
                raise ValueError("حالتِ تحویل باید یکی از push / github / panel باشد")
            out[k] = m
    if "dl_proxy_on" in d or "dl_proxy_id" in d:
        on = bool(d.get("dl_proxy_on", out.get("dl_proxy_on")))
        pid = str(d.get("dl_proxy_id", out.get("dl_proxy_id")) or "").strip()
        if on:
            if not pid:
                raise ValueError("یک پروکسی از فهرست انتخاب کن")
            if not get_proxy(pid):
                raise ValueError("پروکسی پیدا نشد — شاید حذف شده باشد")
        out["dl_proxy_on"], out["dl_proxy_id"] = on, pid if on else ""
    if "tuning" in d:
        out["tuning"] = _validate_tuning(d["tuning"], out.get("tuning"))
    return out


_moved_lock = threading.Lock()


def _moved_load():
    try:
        with open(MOVED_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


_moved = _moved_load()


def _moved_save():
    save_json(MOVED_FILE, _moved)


def _moved_note(nid, name, old, new, new_port):
    with _moved_lock:
        prev = _moved.get(nid)
        _moved[nid] = {"name": name, "from": old, "to": new, "to_port": new_port}
        fresh = not prev or (prev.get("to"), prev.get("to_port")) != (new, new_port)
        if fresh:
            _moved_save()
        return fresh


def _moved_clear(nid):
    with _moved_lock:
        if _moved.pop(nid, None) is not None:
            _moved_save()


def moved_to(nid):
    with _moved_lock:
        v = _moved.get(nid)
        return v["to"] if v else ""


def moved_port(nid):
    with _moved_lock:
        v = _moved.get(nid)
        return int(v.get("to_port") or 0) if v else 0


def moved_addr(nid):
    with _moved_lock:
        v = _moved.get(nid)
        return ("%s:%d" % (v["to"], int(v.get("to_port") or 0))) if v else ""


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


_sess_lock = threading.Lock()


def sess_epoch(conf):
    try:
        return int(conf.get("sess_epoch") or 0)
    except (TypeError, ValueError):
        return 0


def bump_sess_epoch(conf):
    with _sess_lock:
        nxt = sess_epoch(conf) + 1
        try:
            stored = load_conf()
        except Exception:
            stored = dict(conf)
        stored["sess_epoch"] = nxt
        save_json(WEB_CONF, stored)
        conf["sess_epoch"] = nxt
        return nxt


def make_token(conf, user):
    body = f"{user}|{int(time.time()) + SESSION_TTL}|{sess_epoch(conf)}"
    sig = hmac.new(bytes.fromhex(conf["secret"]), body.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}|{sig}".encode()).decode()


def check_token(conf, token):
    try:
        user, exp, epoch, sig = base64.urlsafe_b64decode(token.encode()).decode().rsplit("|", 3)
    except Exception:
        return None
    body = f"{user}|{exp}|{epoch}"
    good = hmac.new(bytes.fromhex(conf["secret"]), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, sig):
        return None
    try:
        if int(exp) < int(time.time()) or int(epoch) != sess_epoch(conf):
            return None
    except (TypeError, ValueError):
        return None
    return user if user == conf.get("user") else None


FAIL_WINDOW = 300
FAIL_LIMIT = 8
FAIL_MAX_KEYS = 4096
LOGIN_GATE = 4

_fails = {}
_fails_lock = threading.Lock()
_login_gate = threading.BoundedSemaphore(LOGIN_GATE)
_blk_logged = {}


def _fails_trim(now):
    while _fails:
        oldest = next(iter(_fails))
        if now - _fails[oldest][1] <= FAIL_WINDOW:
            break
        del _fails[oldest]
    while len(_fails) >= FAIL_MAX_KEYS:
        del _fails[next(iter(_fails))]


def rate_limited(ip):
    with _fails_lock:
        rec = _fails.get(ip)
        if not rec:
            return False
        if time.time() - rec[1] > FAIL_WINDOW:
            del _fails[ip]
            return False
        return rec[0] >= FAIL_LIMIT


def note_fail(ip):
    with _fails_lock:
        now = time.time()
        _fails_trim(now)
        rec = _fails.get(ip)
        if rec and now - rec[1] <= FAIL_WINDOW:
            rec[0] += 1
        else:
            _fails.pop(ip, None)
            _fails[ip] = [1, now]


def is_ipv4(s):
    try:
        return isinstance(ipaddress.ip_address(s), ipaddress.IPv4Address)
    except Exception:
        return False


def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


UA_MAX = 140
UA_BROWSERS = (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
               ("Chrome/", "Chrome"), ("Version/", "Safari"))
UA_SYSTEMS = (("Windows NT 10.0", "Windows 10/11"), ("Windows NT", "Windows"),
              ("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
              ("CrOS", "ChromeOS"), ("Mac OS X", "macOS"), ("X11", "Linux"), ("Linux", "Linux"))


def ua_clean(ua):
    out = "".join(c for c in str(ua) if c.isprintable())
    return out.replace("\u2190", "-").strip()


def ua_browser(ua):
    for tag, name in UA_BROWSERS:
        i = ua.find(tag)
        if i < 0:
            continue
        ver = ua[i + len(tag):].split(".")[0].split(" ")[0]
        return "%s %s" % (name, ver) if ver.isdigit() else name
    return ""


def ua_system(ua):
    for tag, name in UA_SYSTEMS:
        if tag in ua:
            return name
    return ""


def fail_count(ip):
    with _fails_lock:
        rec = _fails.get(ip)
        return rec[0] if rec else 0


def note_blocked(ip):
    now = time.time()
    with _fails_lock:
        if now - _blk_logged.get(ip, 0) < FAIL_WINDOW:
            return False
        _blk_logged.pop(ip, None)
        _blk_logged[ip] = now
        while len(_blk_logged) > FAIL_MAX_KEYS:
            del _blk_logged[next(iter(_blk_logged))]
        return True


def log_internal(where):
    sys.stderr.write("tnl-central: %s failed\n%s" % (where, traceback.format_exc()))
    sys.stderr.flush()


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


def load_proxies():
    try:
        with open(PROXIES_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def get_proxy(pid):
    return next((p for p in load_proxies() if p["id"] == pid), None)


def node_proxy(node):
    if not (node or {}).get("proxy_on"):
        return ""
    p = get_proxy(str(node.get("proxy_id") or ""))
    return proxy_url(p) if p else ""


def _pending_load():
    try:
        with open(PENDING_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _pending_add(node_id, name):
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
    with _pending_lock:
        d = _pending_load()
        if node_id in d:
            d.pop(node_id, None)
            try:
                save_json(PENDING_FILE, d)
            except OSError:
                pass


def _pending_names(node_id):
    return list(_pending_load().get(node_id) or [])


def _pending_counts():
    return {k: len(v) for k, v in _pending_load().items() if v}


def _pending_gc(valid):
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
    s = socket.create_connection((ph, pp), timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x02\x00\x02" if pu else b"\x05\x01\x00")
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
            addr = b"\x01" + socket.inet_aton(dh)
        except OSError:
            hb = dh.encode()
            addr = b"\x03" + bytes([len(hb)]) + hb
        s.sendall(b"\x05\x01\x00" + addr + int(dp).to_bytes(2, "big"))
        rep = _recvn(s, 4)
        if rep[1] != 0:
            raise OSError(f"socks5 connect failed (code {rep[1]})")
        atyp = rep[3]
        _recvn(s, 4 if atyp == 1 else 16 if atyp == 4 else _recvn(s, 1)[0])
        _recvn(s, 2)
        return s
    except Exception:
        s.close()
        raise


def _http_connect_socket(ph, pp, pu, pw, dh, dp, timeout):
    s = socket.create_connection((ph, pp), timeout)
    try:
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


NODE_WIRE = {
    "ping": "pg", "list": "ls", "check": "ck", "tunnel": "mk", "delete": "dl", "apply": "ap",
    "update": "up", "wipe": "wz", "portfw": "pf", "portfw-edit": "pe", "portfw-next": "pn",
    "portcheck": "pc", "speedtest": "sd", "edge-status": "es", "peer-status": "ps", "peer-select": "pl",
    "pool-select": "qs", "retest-now": "rt", "ech-update": "eu",
    "core-put": "cp", "core-apply": "ca", "set-update-key": "sk", "kernel-tune": "kt", "link-enable": "le",
    "core-restart": "cr",
}


NODE_OP_TIMEOUT = 30
NODE_UPLOAD_TIMEOUT = 200


def wire(endpoint):
    try:
        return NODE_WIRE[endpoint]
    except KeyError:
        raise ValueError("مسیرِ ناشناخته روی نود: %r" % endpoint)


def _proxy_socket(proxy, dh, dp, timeout):
    pu = urllib.parse.urlparse(proxy if "://" in proxy else "socks5://" + proxy)
    scheme = (pu.scheme or "socks5").lower()
    if not pu.hostname or not pu.port:
        raise OSError("bad proxy address")
    uq = lambda v: urllib.parse.unquote(v) if v else v
    user, pw = uq(pu.username), uq(pu.password)
    if scheme.startswith("socks"):
        return _socks5_socket(pu.hostname, pu.port, user, pw, dh, dp, timeout)
    if scheme in ("http", "https", "connect"):
        return _http_connect_socket(pu.hostname, pu.port, user, pw, dh, dp, timeout)
    raise OSError(f"bad proxy scheme '{scheme}'")


def _node_call_proxied(node, proxy, endpoint, method, body, timeout, _retry=True):
    dh, dp = node["host"], int(node["port"])
    sock = None
    try:
        sock = _proxy_socket(proxy, dh, dp, timeout)
        conn = http.client.HTTPConnection(dh, dp, timeout=timeout)
        conn.sock = sock
        data = json.dumps(body or {}).encode() if method == "POST" else None
        path = f"/api/{wire(endpoint)}"
        headers = dict(_auth_headers(node, method, path, data))
        ctr = headers["X-Ctr"]
        headers.update(_central_headers())
        if data is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        status, sig = r.status, r.getheader("X-Resp-Sig", "")
        conn.close()
        sock = None
        if not _resp_verified(node, ctr, status, raw, sig):
            return _unsigned_reply()
        try:
            out = json.loads(raw.decode())
        except Exception:
            return {"ok": False, "error": f"پاسخِ HTTP {status} از نود"}
        if _retry and _stale_ctr(node, out):
            return _node_call_proxied(node, proxy, endpoint, method, body, timeout, _retry=False)
        return out
    except Exception as e:
        return {"ok": False, "offline": True, "error": ("proxy: " + str(e).split("] ")[-1])[:90]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


_SIGN_KEY = None


def _signing_keys():
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
    try:
        priv, _ = _signing_keys()
        sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", priv],
                             input=str(sha_hex).encode(), check=True, capture_output=True).stdout
        return base64.b64encode(sig).decode()
    except Exception:
        return ""


def _ensure_update_key(node):
    try:
        _, pub = _signing_keys()
        node_call(node, "set-update-key", "POST", {"pubkey": pub}, timeout=15)
    except Exception:
        pass


_ctr_lock = threading.Lock()
_ctr_next = {}


def _take_ctr(nid):
    with _ctr_lock:
        c = max(_ctr_next.get(nid, 0), int(time.time() * 1000))
        _ctr_next[nid] = c + 1
        return c


def _bump_ctr(nid, at_least):
    with _ctr_lock:
        if at_least > _ctr_next.get(nid, 0):
            _ctr_next[nid] = at_least


def _sig_msg(method, path, ctr, body_sha):
    return "%s\n%s\n%s\n%s" % (method, path, ctr, body_sha)


def _auth_headers(node, method, path, data):
    tok = node.get("token", "")
    ctr = _take_ctr(node.get("id") or node.get("host") or "")
    bs = hashlib.sha256(data).hexdigest() if data else ""
    mac = hmac.new(tok.encode("utf-8"), _sig_msg(method, path, ctr, bs).encode("utf-8"),
                   hashlib.sha256).digest()
    return {"X-Ctr": str(ctr), "X-Body": bs, "X-Sig": base64.b64encode(mac).decode()}


def _resp_sig_msg(ctr, status, body_sha):
    return "resp\n%s\n%s\n%s" % (ctr, status, body_sha)


def _resp_verified(node, ctr, status, raw, sig_b64):
    tok = str(node.get("token") or "")
    if not tok or not sig_b64:
        return False
    try:
        got = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return False
    want = hmac.new(tok.encode("utf-8"),
                    _resp_sig_msg(ctr, status, hashlib.sha256(raw).hexdigest()).encode("utf-8"),
                    hashlib.sha256).digest()
    return hmac.compare_digest(want, got)


def _unsigned_reply():
    return {"ok": False, "offline": True, "error": "پاسخِ نود امضای معتبر ندارد"}


def _stale_ctr(node, res):
    if not isinstance(res, dict) or "stale counter" not in str(res.get("error") or ""):
        return False
    try:
        _bump_ctr(node.get("id") or node.get("host") or "", int(res["ctr"]) + 1)
    except (KeyError, TypeError, ValueError):
        return False
    return True


def node_call(node, endpoint, method="POST", body=None, timeout=8, _retry=True):
    proxy = node_proxy(node)
    if proxy:
        return _node_call_proxied(node, proxy, endpoint, method, body, timeout)
    path = f"/api/{wire(endpoint)}"
    url = f"http://{node['host']}:{int(node['port'])}{path}"
    data = json.dumps(body or {}).encode() if method == "POST" else None
    req = urllib.request.Request(url, data=data, method=method)
    hdrs = _auth_headers(node, method, path, data)
    ctr = hdrs["X-Ctr"]
    for k, v in hdrs.items():
        req.add_header(k, v)
    for k, v in _central_headers().items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            if not _resp_verified(node, ctr, r.status, raw, r.headers.get("X-Resp-Sig", "")):
                return _unsigned_reply()
            out = json.loads(raw.decode())
            return out if isinstance(out, dict) else {"ok": False, "error": "پاسخِ نود قابلِ خواندن نبود"}
    except urllib.error.HTTPError as e:
        raw = e.read()
        if not _resp_verified(node, ctr, e.code, raw, e.headers.get("X-Resp-Sig", "")):
            return _unsigned_reply()
        try:
            out = json.loads(raw.decode())
        except Exception:
            return {"ok": False, "error": f"پاسخِ HTTP {e.code} از نود"}
        if not isinstance(out, dict):
            return {"ok": False, "error": f"پاسخِ HTTP {e.code} از نود"}
        if _retry and _stale_ctr(node, out):
            return node_call(node, endpoint, method, body, timeout, _retry=False)
        return out
    except Exception as e:
        return {"ok": False, "offline": True, "error": str(e).split("] ")[-1][:80]}


def node_push(node, endpoint, body, on_progress=None, timeout=NODE_UPLOAD_TIMEOUT, chunk=64 * 1024,
              should_abort=None, _retry=True):
    dh, dp = node["host"], int(node["port"])
    data = bytes(body) if isinstance(body, (bytes, bytearray)) else json.dumps(body or {}).encode()
    total = len(data)
    proxy = node_proxy(node)
    sock = None
    try:
        sock = _proxy_socket(proxy, dh, dp, timeout) if proxy \
            else socket.create_connection((dh, dp), timeout)
        sock.settimeout(timeout)
        path = "/api/%s" % wire(endpoint)
        head = ["POST %s HTTP/1.1" % path, "Host: %s:%d" % (dh, dp),
                "Content-Type: application/json", "Content-Length: %d" % total,
                "Connection: close"]
        hdrs = _auth_headers(node, "POST", path, data)
        ctr = hdrs["X-Ctr"]
        head += ["%s: %s" % kv for kv in hdrs.items()]
        head += ["%s: %s" % kv for kv in _central_headers().items()]
        sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode())
        sent, pre = 0, b""
        deadline = time.monotonic() + timeout
        if on_progress:
            on_progress(0, total)
        while sent < total:
            if should_abort and should_abort():
                return {"ok": False, "cancelled": True, "delivered": False}
            if select.select([sock], [], [], 0)[0]:
                pre = sock.recv(65536)
                if not pre:
                    raise OSError("connection closed while sending")
                break
            n = sock.send(data[sent:sent + chunk])
            if not n:
                raise OSError("connection closed while sending")
            sent += n
            if on_progress:
                on_progress(sent, total)
        raw, head_blob, rest, clen = pre, b"", b"", None
        sock.settimeout(min(0.25, timeout))
        while True:
            head_blob, sep, rest = raw.partition(b"\r\n\r\n")
            if sep:
                clen = next((int(l.split(b":", 1)[1]) for l in head_blob.split(b"\r\n")
                             if l.lower().startswith(b"content-length:")), None)
                if clen is not None and len(rest) >= clen:
                    break
            if should_abort and should_abort():
                return {"ok": False, "cancelled": True, "delivered": True}
            if time.monotonic() > deadline:
                raise OSError("timed out waiting for the node")
            try:
                b = sock.recv(65536)
            except socket.timeout:
                continue
            if not b:
                break
            raw += b
            if len(raw) > 1048576:
                raise OSError("response too large")
        st = head_blob.split(b" ")
        status = st[1].decode() if len(st) > 1 else "?"
        sig = next((l.split(b":", 1)[1].strip().decode() for l in head_blob.split(b"\r\n")
                    if l.lower().startswith(b"x-resp-sig:")), "")
        payload = rest[:clen] if clen is not None else rest
        if not _resp_verified(node, ctr, status, payload, sig):
            return _unsigned_reply()
        try:
            out = json.loads(payload.decode())
        except Exception:
            return {"ok": False, "error": "HTTP %s از نود" % status}
        if not isinstance(out, dict):
            return {"ok": False, "error": "پاسخِ نود قابلِ خواندن نبود"}
        if _retry and _stale_ctr(node, out):
            return node_push(node, endpoint, body, on_progress, timeout, chunk, should_abort,
                             _retry=False)
        return out
    except Exception as e:
        return {"ok": False, "offline": True, "error": str(e).split("] ")[-1][:90]}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def parallel_map(fn, items, workers=32):
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))


POLL_WORKERS = 64
POLL_GAP = 2
_pc = {}
_pc_lock = threading.Lock()
_tf = {}
_tf_lock = threading.Lock()
TF_MAX_GAP = 120.0
TF_BPS_CEIL = 100e9
_uh = {}
_uh_lock = threading.Lock()
UPTIME_BUCKET = 60
UPTIME_KEEP = 1440
_tomb = {}
_tomb_lock = threading.Lock()


def _cache_get(nid):
    with _pc_lock:
        e = _pc.get(nid)
        return dict(e) if e else None


def _tombed(nid, ts):
    with _tomb_lock:
        exp = _tomb.get(nid)
        return bool(exp and ts < exp)


def _pending_drain(n):
    nid = n["id"]
    names = _pending_names(nid)
    if not names:
        return
    live = {L["name"] for L in load_links() if L.get("a_node") == nid or L.get("b_node") == nid}
    for nm in names:
        if nm in live:
            _pending_remove(nid, nm)
            continue
        r = node_call(n, "delete", "POST", {"name": nm}, timeout=8)
        if r.get("ok"):
            _pending_remove(nid, nm)
            _tf_forget(nid, [nm])


def _poll_node(n):
    _t0 = time.perf_counter()
    ping = node_call(n, "ping", "GET", timeout=6)
    if ping.get("ok"):
        ping = {**ping, "rtt_ms": int((time.perf_counter() - _t0) * 1000)}
    t_ping = time.time()
    if not _tombed(n["id"], t_ping):
        if ping.get("ok"):
            s = ping.get("stats") or {}
            _tf_ingest(n["id"], s.get("net"), s.get("uptime"), t_ping)
        else:
            _tf_zero_rates(n["id"])
        _uh_sample(n["id"], bool(ping.get("ok")), t_ping)
    lst = node_call(n, "list", "GET", timeout=12)
    now = time.time()
    if _tombed(n["id"], now):
        return
    with _pc_lock:
        _pc[n["id"]] = {"ping": ping, "list": lst, "ping_ts": t_ping, "list_ts": now}
    if ping.get("ok"):
        _pending_drain(n)


def _refresh_cache(nids):
    nodes = {n["id"]: n for n in load_nodes()}
    parallel_map(_poll_node, [nodes[i] for i in dict.fromkeys(nids) if i in nodes])


_warm_inflight = set()
_warm_lock = threading.Lock()


def _ensure_cached(nodes):
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


NODE_STATE = ("_pc", "_tf", "_uh", "_moved")


def _prune_node_state(valid):
    g = globals()
    for name in NODE_STATE:
        with g[name + "_lock"]:
            store = g[name]
            for nid in [k for k in store if k not in valid]:
                store.pop(nid, None)
    with _tomb_lock:
        for nid in [k for k, exp in _tomb.items() if time.time() > exp]:
            _tomb.pop(nid, None)
    with _node_locks_guard:
        for nid in [k for k in _node_locks if k not in valid]:
            lk = _node_locks.get(nid)
            if lk is not None and not lk.locked():
                _node_locks.pop(nid, None)
    _pending_gc(valid)


def poller_loop():
    ex = ThreadPoolExecutor(max_workers=POLL_WORKERS)
    inflight = set()
    inflight_lock = threading.Lock()

    def _run(n):
        try:
            _poll_node(n)
        finally:
            with inflight_lock:
                inflight.discard(n["id"])

    def _run_px(p):
        try:
            _px_sweep(p)
        finally:
            with inflight_lock:
                inflight.discard("px:" + p["id"])

    while True:
        try:
            nodes = load_nodes()
            valid = {n["id"] for n in nodes}
            _prune_node_state(valid)
            if nodes:
                with inflight_lock:
                    todo = [n for n in nodes if n["id"] not in inflight]
                    inflight.update(n["id"] for n in todo)
                for n in todo:
                    ex.submit(_run, n)
            pxs = load_proxies()
            live_px = {p["id"] for p in pxs}
            with _px_lock:
                for pid in [k for k in _px if k not in live_px]:
                    _px.pop(pid, None)
                for pid in [k for k in _px_relay if k not in live_px]:
                    _px_relay.pop(pid, None)
            for p in pxs:
                with inflight_lock:
                    if ("px:" + p["id"]) in inflight:
                        continue
                    inflight.add("px:" + p["id"])
                ex.submit(_run_px, p)
        except Exception:
            pass
        try:
            gap = max(0.3, float(get_settings().get("poll_interval", POLL_GAP) or POLL_GAP))
        except Exception:
            gap = POLL_GAP
        time.sleep(gap)


_px_lock = threading.Lock()
_px = {}


def _proxy_probe(p, timeout=6):
    t0 = time.monotonic()
    host, port = p["host"], int(p["port"])
    user, pw = p.get("user") or "", p.get("pass") or ""
    s = None
    try:
        s = socket.create_connection((host, port), timeout)
        s.settimeout(timeout)
        if p["scheme"] == "socks5":
            s.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
            head = b""
            while len(head) < 2:
                c = s.recv(2 - len(head))
                if not c:
                    raise OSError("پروکسی اتصال را بست")
                head += c
            if head[0:1] != b"\x05":
                raise OSError("پاسخِ پروکسی SOCKS5 نیست")
            method = head[1]
            if method == 0xFF:
                raise OSError("پروکسی روشِ احرازِ ما را نپذیرفت")
            if method == 2:
                if not user:
                    raise OSError("پروکسی یوزر/پسورد می‌خواهد")
                u, w = user.encode(), pw.encode()
                s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
                ares = b""
                while len(ares) < 2:
                    c = s.recv(2 - len(ares))
                    if not c:
                        raise OSError("پروکسی هنگامِ احراز اتصال را بست")
                    ares += c
                if ares[1] != 0:
                    raise OSError("یوزر/پسوردِ پروکسی پذیرفته نشد")
        else:
            s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)).encode()
                      + ((b"Proxy-Authorization: Basic "
                          + base64.b64encode(("%s:%s" % (user, pw)).encode()) + b"\r\n") if user else b"")
                      + b"\r\n")
            line = b""
            while b"\r\n" not in line:
                c = s.recv(256)
                if not c:
                    raise OSError("پروکسی بدونِ پاسخ اتصال را بست")
                line += c
                if len(line) > 8192:
                    break
            if not line.startswith(b"HTTP/"):
                raise OSError("پاسخِ پروکسی HTTP نیست")
            code = line.split(b" ")[1].decode(errors="replace") if b" " in line else "?"
            if code == "407":
                raise OSError("یوزر/پسوردِ پروکسی پذیرفته نشد (407)")
    except Exception as e:
        return {"ok": False, "ms": None, "error": str(e).split("] ")[-1][:90], "ts": time.time()}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return {"ok": True, "ms": int((time.monotonic() - t0) * 1000), "error": "", "ts": time.time()}


PX_RELAY_GAP = 15
PX_ECHO_TTL = 120
_px_relay = {}
_px_echo = {"ts": 0.0, "addr": None}
_px_echo_lock = threading.Lock()


def _echo_over(sock, host, port, timeout):
    end = time.monotonic() + timeout
    sock.settimeout(timeout)
    sock.sendall(("GET /px-echo HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
                  % (host, port)).encode())
    line = b""
    while b"\r\n" not in line:
        sock.settimeout(max(0.05, end - time.monotonic()))
        c = sock.recv(128)
        if not c:
            raise OSError("چیزی برنگشت")
        line += c
        if len(line) > 4096:
            break
    if not line.startswith(b"HTTP/"):
        raise OSError("پاسخِ عبوری HTTP نیست")


def _panel_echo_addr():
    with _px_echo_lock:
        now = time.time()
        if now - _px_echo["ts"] < PX_ECHO_TTL:
            return _px_echo["addr"]
        return _panel_echo_probe(now)


def _panel_echo_probe(now):
    addr, ip, port = None, central_ip(), _CENTRAL_PORT
    if is_ipv4(ip) and port:
        s = None
        try:
            s = socket.create_connection((ip, int(port)), 3)
            _echo_over(s, ip, int(port), 3)
            addr = (ip, int(port))
        except Exception:
            addr = None
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
    _px_echo.update(ts=now, addr=addr)
    return addr


def _proxy_relay(p, timeout=6):
    addr = _panel_echo_addr()
    if not addr:
        return {"ok": True, "skipped": True, "error": "", "ts": time.time()}
    s = None
    try:
        s = _proxy_socket(proxy_url(p), addr[0], addr[1], timeout)
        _echo_over(s, addr[0], addr[1], timeout)
    except Exception as e:
        return {"ok": False, "skipped": False, "ts": time.time(),
                "error": "پروکسی عبور نمی‌دهد — " + str(e).split("] ")[-1][:60]}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return {"ok": True, "skipped": False, "error": "", "ts": time.time()}


def _px_deep(p, st):
    if not st.get("ok"):
        return st
    with _px_lock:
        prev = _px_relay.get(p["id"])
    if not prev or time.time() - prev["ts"] >= PX_RELAY_GAP:
        prev = _proxy_relay(p)
        with _px_lock:
            _px_relay[p["id"]] = prev
    if prev.get("skipped") or prev.get("ok"):
        return st
    return {**st, "ok": False, "error": prev["error"]}


def _px_sweep(p):
    _px_publish(p["id"], _px_deep(p, _proxy_probe(p)))


def _px_publish(pid, st):
    with _px_lock:
        _px[pid] = st


def _px_get(pid):
    with _px_lock:
        return dict(_px.get(pid) or {})


def _cached_ping(nid):
    return (_cache_get(nid) or {}).get("ping") or {}


def _known_offline(n):
    p = _cached_ping(n["id"])
    if "ok" in p:
        return not p["ok"]
    return not bool(node_call(n, "ping", "GET").get("ok"))


def _cached_list(nid):
    return (_cache_get(nid) or {}).get("list") or {}


TF_IF_MAX = 512
TF_IF_KEY_MAX = 32
TF_CTR_CEIL = 1 << 64
TF_IF_PRUNE_MISSES = 15


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
        if e["prev_ts"] and now < e["prev_ts"]:
            return
        dt = (now - e["prev_ts"]) if e["prev_ts"] else 0
        reboot = e["prev_up"] is not None and up is not None and up < e["prev_up"]
        emit = (0 < dt <= TF_MAX_GAP) and not reboot
        gap = dt > TF_MAX_GAP and not reboot
        ifs = e["if"]
        for key, v in net.items():
            if not _tf_valid_key(key):
                continue
            if not (isinstance(v, list) and len(v) == 2):
                continue
            try:
                rx, tx = int(v[0]), int(v[1])
            except (TypeError, ValueError):
                continue
            if not (0 <= rx < TF_CTR_CEIL and 0 <= tx < TF_CTR_CEIL):
                continue
            s = ifs.get(key)
            if s is None:
                if len(ifs) >= TF_IF_MAX:
                    continue
                sd = e["seed"].get(key)
                ifs[key] = {"prx": rx, "ptx": tx, "rx_bps": 0.0, "tx_bps": 0.0,
                            "crx": sd[0] if sd else 0, "ctx": sd[1] if sd else 0, "miss": 0}
                continue
            s["miss"] = 0
            for raw, pk, ck, bk in ((rx, "prx", "crx", "rx_bps"), (tx, "ptx", "ctx", "tx_bps")):
                draw = raw - s[pk]
                if draw < 0 or reboot:
                    s[bk] = 0.0
                elif emit:
                    bps = draw * 8.0 / dt
                    if bps > TF_BPS_CEIL:
                        s[bk] = 0.0
                    else:
                        s[bk] = bps
                        s[ck] += draw
                elif gap:
                    s[bk] = 0.0
                    if draw <= TF_BPS_CEIL / 8.0 * dt:
                        s[ck] += draw
                s[pk] = raw
        stale = []
        for key, s in e["if"].items():
            if key not in net:
                s["rx_bps"] = 0.0
                s["tx_bps"] = 0.0
                s["miss"] = s.get("miss", 0) + 1
                if s["miss"] > TF_IF_PRUNE_MISSES:
                    stale.append(key)
        for key in stale:
            e["if"].pop(key, None)
        e["prev_ts"] = now
        e["prev_up"] = up


def _tf_forget(nid, keys):
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
    with _tf_lock:
        e = _tf.get(nid)
        return {k: dict(v) for k, v in e["if"].items()} if e else {}


def _tf_node_view(nid):
    s = _tf_read(nid).get("_node")
    if not s:
        return None
    return {"rx_bps": s["rx_bps"], "tx_bps": s["tx_bps"], "rx_total": s["crx"], "tx_total": s["ctx"]}


def _tf_zero_rates(nid):
    with _tf_lock:
        e = _tf.get(nid)
        if e:
            for s in e["if"].values():
                s["rx_bps"] = 0.0
                s["tx_bps"] = 0.0


def _uh_sample(nid, up, now):
    with _uh_lock:
        e = _uh.get(nid)
        if e is None:
            _uh[nid] = {"ring": [], "bts": now, "up": 1 if up else 0, "tot": 1}
            return
        e["up"] = e.get("up", 0) + (1 if up else 0)
        e["tot"] = e.get("tot", 0) + 1
        if now - e["bts"] >= UPTIME_BUCKET:
            frac = e["up"] / e["tot"] if e["tot"] else 1.0
            missed = min(int((now - e["bts"]) / UPTIME_BUCKET), UPTIME_KEEP)
            e["ring"].extend([frac] * missed)
            if len(e["ring"]) > UPTIME_KEEP:
                e["ring"] = e["ring"][-UPTIME_KEEP:]
            e["bts"] = now
            e["up"], e["tot"] = 0, 0


def _uh_cells(nid, window_hours, cells=60):
    try:
        wh = int(window_hours)
    except Exception:
        wh = 1
    if wh not in (1, 3, 6, 8, 12, 24):
        wh = 1
    per = wh
    total = cells * per
    with _uh_lock:
        e = _uh.get(nid)
        ring = list(e["ring"]) if e else []
    ring = ring[-total:]
    slots = [None] * (total - len(ring)) + ring
    out = []
    for i in range(cells):
        chunk = [x for x in slots[i * per:(i + 1) * per] if x is not None]
        out.append(None if not chunk else (0 if min(chunk) < 1.0 else 1))
    return out


def _uh_pct(nid, window_hours):
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
    if total >= n:
        return 100.0
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
            if isinstance(ring, list):
                _uh[nid] = {"ring": [max(0.0, min(1.0, float(x))) for x in ring][-UPTIME_KEEP:], "bts": now, "up": 0, "tot": 0}


def _tf_snapshot():
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
            save_json(UPTIME_FILE, {k: v for k, v in _uh_snapshot().items() if k in valid})
        except Exception:
            pass


def query_dict(path):
    return {k: v[-1] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(path).query).items()}


def _list_query(d):
    return str(d.get("q") or "").strip().lower()


SUBNET_BASES = {"192.168": ("192.168.0.0", 16), "172.16": ("172.16.0.0", 12), "10": ("10.0.0.0", 8)}
SUBNET_BASE_DEFAULT = "192.168"


def subnet_cap(base=None):
    _, prefix = SUBNET_BASES.get(str(base or SUBNET_BASE_DEFAULT), SUBNET_BASES[SUBNET_BASE_DEFAULT])
    return (1 << (24 - prefix)) - 1


TID_MIN = 1
TID_MAX = max(subnet_cap(b) for b in SUBNET_BASES)


def tunnel_name(ttype, tid):
    return f"core{tid}" if ttype == "core" else f"native{tid}"


def overlay_host(ttype, server_side, is_a):
    if ttype == "core":
        return 1 if (server_side == "a") == bool(is_a) else 2
    return 1 if is_a else 2


def subnet_default(ttype, tid, base=None):
    if ttype == "sit":
        return "fd00:%x:%x::/64" % (tid >> 16, tid & 0xFFFF)
    if not base:
        base = next((b for b in ("192.168", "172.16", "10") if tid <= subnet_cap(b)), "10")
    net, prefix = SUBNET_BASES.get(str(base), SUBNET_BASES[SUBNET_BASE_DEFAULT])
    cap = subnet_cap(base)
    if not TID_MIN <= tid <= cap:
        raise ValueError(f"شناسهٔ {tid} در بازهٔ «{net}/{prefix}» جا نمی‌شود "
                         f"(این بازه {cap} تونل می‌گیرد)؛ بازهٔ بزرگ‌تری انتخاب کن")
    return "%s/24" % (ipaddress.IPv4Address(int(ipaddress.IPv4Address(net)) + tid * 256))


PORT_BAND_LO = 20000
PORT_BAND_HI = 29999


def rand_port(taken=()):
    free = [p for p in range(PORT_BAND_LO, PORT_BAND_HI + 1) if p not in taken]
    if not free:
        raise ValueError("پورتِ آزادی در بازهٔ %d تا %d نمانده است" % (PORT_BAND_LO, PORT_BAND_HI))
    return free[secrets.randbelow(len(free))]


def free_tunnel_port(A, B, exclude_id=None):
    used = set()
    for L in load_links():
        if exclude_id is not None and L.get("id") == exclude_id:
            continue
        try:
            used.add(int(L.get("port") or 0))
        except (TypeError, ValueError):
            pass
    return rand_port(used)


def _subnet_fits(ttype, sub):
    try:
        return ipaddress.ip_network(sub, strict=False).version == (6 if ttype == "sit" else 4)
    except Exception:
        return False


def carry_subnet(ttype, tid, stored, base=None):
    return stored if stored and _subnet_fits(ttype, stored) else subnet_default(ttype, tid, base)


def norm_subnet(ttype, tid, provided, base=None):
    want6 = (ttype == "sit")
    if not provided:
        return subnet_default(ttype, tid, base)
    if _subnet_fits(ttype, provided):
        return provided
    raise ValueError("سابنتِ «%s» خوانده نمی‌شود — این تونل به یک شبکهٔ %s نیاز دارد، مثلاً %s"
                     % (provided, "IPv6" if want6 else "IPv4", subnet_default(ttype, tid, base)))


_ROTATION_KEYS = ("ip_rotate", "a_ip_pool", "b_ip_pool", "rotate_secs")

_WORKERS_KEYS = ("a_workers", "b_workers")

_LINK_EXTRA_KEYS = ("port", "psk", "cipher", "transport", "obfs", "cover", "cover_sni", "raw_profile",
                    "raw_proto", "raw_port", "raw_sport", "raw_sport_random", "raw_sport_rotate", "raw_dports",
                    "raw_sport_lo", "raw_sport_hi", "conntrack_bypass", "port_tries", "a_workers", "b_workers", "dns_zone", "dns_resolvers",
                    "fec", "fec_data", "fec_parity", "ws_host", "ws_path", "ws_tls",
                    "sni_split", "split_pos", "sni_mode", "split_ttl", "cdn_carrier",
                    "http_up_workers", "http_up_batch_kb", "http_streams",
                    "ech", "ws_ech", "ech_proxy", "ech_proxy_url", "edge_ip", "ws_pool",
                    "ws_edge_ips", "ws_edge_snis",
                    "ws_rotate_secs", "gso",
                    "fake_desync", "fake_ttl", "fake_count", "fake_mode") + _ROTATION_KEYS


def _node_extra(extra):
    e = dict(extra)
    skip = _ROTATION_KEYS + _WORKERS_KEYS
    return {k: v for k, v in e.items() if k not in skip}


def _apply_core_rotation(body, is_client, own_pool, peer_pool, rotate_secs):
    if is_client:
        if peer_pool:
            body["peer_ips"] = list(peer_pool)
        if own_pool:
            body["src_ips"] = list(own_pool)
        body["peer_rotate_secs"] = rotate_secs
    else:
        body["pool_listen"] = True
        if own_pool and body.get("transport") in ("udp", "tcp"):
            body["listen_ips"] = list(own_pool)
        if peer_pool:
            body["peer_src_ips"] = list(peer_pool)


def _core_rotation_bodies(src, a_body, b_body):
    if not src.get("ip_rotate") or src.get("transport") not in DIRECT_TRANSPORTS:
        return
    ap, bp = list(src.get("a_ip_pool") or []), list(src.get("b_ip_pool") or [])
    rs = max(0, min(86400, int(src.get("rotate_secs") or 0)))
    _apply_core_rotation(a_body, a_body.get("role") == "client", ap, bp, rs)
    _apply_core_rotation(b_body, b_body.get("role") == "client", bp, ap, rs)


def _core_workers_bodies(src, a_body, b_body):
    for body, key in ((a_body, "a_workers"), (b_body, "b_workers")):
        n = _link_workers(src, key)
        if n > 1:
            body["workers"] = n


def _apply_core_tuning(a_body, b_body):
    tn = _settings_tuning()
    if "sock_buf_mb" in tn:
        _mb = max(0, min(64, int(tn["sock_buf_mb"])))
        a_body["sock_buf"] = b_body["sock_buf"] = -1 if _mb == 0 else _mb * (1 << 20)
    _tn = {k: v for k, v in tn.items()
           if k not in ("sock_buf_mb", "probe_min_pct")}
    if _tn:
        a_body["tuning"] = _tn
        b_body["tuning"] = _tn


def _apply_probe_tuning(*bodies):
    tn = _settings_tuning()
    if "probe_min_pct" not in tn:
        return
    lo, hi = _TUNING_RANGES["probe_min_pct"]
    v = max(lo, min(hi, int(tn["probe_min_pct"])))
    for b in bodies:
        b["probe_min_pct"] = v


HTTP_SHAPE = {"http_up_workers": (1, 16, 8), "http_up_batch_kb": (8, 512, 512),
              "http_streams": (1, 16, 1)}
HTTP_SHAPE_GRPC = ("http_streams",)


def _tunnel_extra(src, refetch_ech=True):
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
    if src.get("cover"):
        e["cover"] = True
        if src.get("cover_sni"):
            e["cover_sni"] = src["cover_sni"]
    if src.get("raw_profile"):
        e["raw_profile"] = src["raw_profile"]
    if src.get("raw_proto"):
        e["raw_proto"] = src["raw_proto"]
    if src.get("raw_port"):
        e["raw_port"] = src["raw_port"]
    if src.get("port_tries"):
        e["port_tries"] = src["port_tries"]
    if src.get("raw_sport_random"):
        e["raw_sport_random"] = True
    elif src.get("raw_sport"):
        e["raw_sport"] = src["raw_sport"]
    if src.get("raw_sport_rotate"):
        e["raw_sport_rotate"] = src["raw_sport_rotate"]
    if src.get("raw_dports"):
        e["raw_dports"] = src["raw_dports"]
    if src.get("raw_sport_lo") and src.get("raw_sport_hi"):
        e["raw_sport_lo"] = src["raw_sport_lo"]
        e["raw_sport_hi"] = src["raw_sport_hi"]
    if src.get("conntrack_bypass"):
        e["conntrack_bypass"] = True
    if src.get("dns_zone"):
        e["dns_zone"] = src["dns_zone"]
        if src.get("dns_resolvers"):
            e["dns_resolvers"] = src["dns_resolvers"]
    if src.get("fec"):
        e["fec"] = True
        e["fec_data"] = src.get("fec_data") or 16
        e["fec_parity"] = src.get("fec_parity") or 4
    if src.get("fake_desync"):
        e["fake_desync"] = True
        e["fake_ttl"] = src.get("fake_ttl") or 4
        e["fake_count"] = src.get("fake_count") or 2
        e["fake_mode"] = src.get("fake_mode") or "ttl"
    if src.get("ws_host"):
        e["ws_host"] = src["ws_host"]
    if src.get("ws_path"):
        e["ws_path"] = src["ws_path"]
    if src.get("ws_tls"):
        e["ws_tls"] = True
    if src.get("sni_split"):
        e["sni_split"] = True
        if src.get("split_pos"):
            e["split_pos"] = int(src["split_pos"])
        if src.get("sni_mode") in ("disorder", "fake"):
            e["sni_mode"] = src["sni_mode"]
            if src.get("split_ttl"):
                e["split_ttl"] = int(src["split_ttl"])
    if src.get("cdn_carrier"):
        e["cdn_carrier"] = src["cdn_carrier"]
        if src.get("cdn_carrier") in ("http", "grpc"):
            for k in HTTP_SHAPE:
                if src.get("cdn_carrier") == "grpc" and k not in HTTP_SHAPE_GRPC:
                    continue
                if src.get(k):
                    e[k] = int(src[k])
    if src.get("ech"):
        e["ech"] = True
        host = src.get("ws_host")
        if refetch_ech and host:
            ec = _fetch_ech(host, _ech_px(src))
            if not ec:
                raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — بازسازی متوقف شد (ECH روشن است ولی رکوردِ HTTPS/ech= در دسترس نیست)." % host)
            e["ws_ech"] = ec
        elif src.get("ws_ech"):
            e["ws_ech"] = src["ws_ech"]
    if src.get("edge_ip"):
        e["edge_ip"] = src["edge_ip"]
    if src.get("ws_pool") and src.get("ws_edge_ips") and src.get("ws_edge_snis"):
        e["ws_pool"] = True
        e["ws_tls"] = True
        e["ws_edge_ips"] = src["ws_edge_ips"]
        pool_ech = bool(src.get("ech"))
        hosts = [s.get("host") for s in src["ws_edge_snis"] if isinstance(s, dict) and s.get("host")]
        ech_map = _fetch_ech_map(hosts, _ech_px(src)) if (pool_ech and refetch_ech) else {}
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
                ec = s.get("ech", "") if pool_ech else ""
            psnis.append({"host": h, "ech": ec, "path": s.get("path") or src.get("ws_path") or "/"})
        e["ws_edge_snis"] = psnis
        _rs = src.get("ws_rotate_secs")
        e["ws_rotate_secs"] = int(_rs) if _rs is not None else 600
    if src.get("gso"):
        e["gso"] = True
    return _node_extra(e)


def _core_role(L, node_id):
    if L.get("type") != "core":
        return None
    server_node = L.get("b_node") if L.get("server_side") == "b" else L.get("a_node")
    return "server" if node_id == server_node else "client"


def _require(d, keys):
    for k in keys:
        if k not in d or d[k] in (None, ""):
            raise ValueError(f"فیلدِ «{k}» فرستاده نشد")


def valid_proxy_ref(d):
    on = bool(d.get("proxy_on"))
    pid = str(d.get("proxy_id") or "").strip()
    if not on:
        return False, ""
    if not pid or not get_proxy(pid):
        raise ValueError("پروکسی انتخاب نشده — از بخشِ «پروکسی‌ها» یکی بساز و انتخابش کن")
    return True, pid


def valid_proxy(p):
    p = str(p or "").strip()
    if not p:
        return ""
    u = urllib.parse.urlparse(p if "://" in p else "socks5://" + p)
    if u.scheme.lower() not in ("socks5", "socks5h", "http", "https", "connect") or not u.hostname or not u.port:
        raise ValueError("پروکسی نامعتبر — نمونه: socks5://host:1080 یا http://user:pass@host:8080")
    return p if "://" in p else "socks5://" + p


def _proxy_names():
    return {p["id"]: p["name"] for p in load_proxies()}


def _node_view(n, pend=None, pxn=None):
    _uw = get_settings().get("uptime_window", 1)
    _pon = bool(n.get("proxy_on"))
    _pid = str(n.get("proxy_id") or "")
    base = {"id": n["id"], "name": n["name"], "host": n["host"], "port": n["port"],
            "proxy_on": _pon, "proxy_id": _pid,
            "proxy_name": (pxn if pxn is not None else _proxy_names()).get(_pid, "") if _pon else "",
            "disabled": bool(n.get("disabled")),
            "pending_del": (pend if pend is not None else _pending_counts()).get(n["id"], 0),
            "moved_to": moved_addr(n["id"]),
            "central_want": _panel_origin_for(n),
            "uptime": _uh_cells(n["id"], _uw), "uptime_pct": _uh_pct(n["id"], _uw),
            "traffic": _tf_node_view(n["id"])}
    c = _cache_get(n["id"])
    if not c or c.get("ping") is None:
        return {**base, "online": False, "pending": True, "info": {"error": "در حال بررسی…"}}
    p = c["ping"]
    return {**base, "online": bool(p.get("ok")),
            "info": p if p.get("ok") else {"error": p.get("error", "unreachable")}}


def api_nodes(d):
    q = str((d or {}).get("q") or "").strip().lower()
    nodes = load_nodes()
    if q:
        nodes = [n for n in nodes if q in n["name"].lower() or q in n["host"].lower()]
    _ensure_cached(nodes)
    _pend = _pending_counts()
    _pxn = _proxy_names()
    return {"nodes": [_node_view(n, _pend, _pxn) for n in nodes], "total": len(nodes),
            "uptime_window": get_settings().get("uptime_window", 1)}


def api_node_names(d):
    q = str(d.get("q") or "").strip().lower()
    out = []
    for n in load_nodes():
        if n.get("disabled"):
            continue
        if q and q not in n["name"].lower() and q not in n["host"].lower():
            continue
        p = _cached_ping(n["id"])
        out.append({"id": n["id"], "name": n["name"], "host": n["host"],
                    "online": bool(p.get("ok")), "cpus": (p.get("stats") or {}).get("cpus"),
                    "info": {"ips": p.get("ips") or {}}})
    return {"nodes": out, "total": len(out)}


def _link_side_health(L, node_key):
    lst = _cached_list(L[node_key])
    if lst.get("configs") is None:
        return None, False
    return (lst.get("health") or {}).get(L["name"]), True


def _cpu_snap():
    with open("/proc/stat") as f:
        v = [int(x) for x in f.readline().split()[1:]]
    idle = v[3] + (v[4] if len(v) > 4 else 0)
    return sum(v), idle


def central_stats():
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


UP_CRIT = 85
PING_BAD = 150


def subnet_free_counts(links):
    used = {int(L["tunnel_id"]) for L in links if str(L.get("tunnel_id", "")).isdigit()}
    return {b: max(0, subnet_cap(b) - sum(1 for t in used if 1 <= t <= subnet_cap(b)))
            for b in SUBNET_BASES}


def api_next_port(d):
    used = set()
    for L in load_links():
        try:
            used.add(int(L.get("port") or 0))
        except (TypeError, ValueError):
            pass
    return {"ok": True, "port": rand_port(used), "lo": PORT_BAND_LO, "hi": PORT_BAND_HI}


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
            if _cache_get(nid):
                alerts.append({"level": "bad", "kind": "node", "id": nid, "msg": f"نودِ «{nm}» آفلاین است"})
            mv = moved_to(nid)
            if mv:
                alerts.append({"level": "warn", "kind": "node", "id": nid,
                               "msg": f"نودِ «{nm}» از {mv} جواب می‌دهد — هوستش را عوض کن"})
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
    up = noping = down = drift_n = off_n = 0
    types = {"vxlan": 0, "gre": 0, "sit": 0}
    worst_tun = None
    rtts = []
    for L in links:
        if not L.get("enabled", True):
            types[L.get("type", "")] = types.get(L.get("type", ""), 0) + 1
            off_n += 1
            continue
        ah, _a = _link_side_health(L, "a_node")
        bh, _b = _link_side_health(L, "b_node")
        if (isinstance(ah, dict) and ah.get("up") is None) or (isinstance(bh, dict) and bh.get("up") is None):
            types[L.get("type", "")] = types.get(L.get("type", ""), 0) + 1
            continue
        if L.get("type") == "core":
            types["core"] = types.get("core", 0) + 1
            if link_drift(L["id"]):
                drift_n += 1
            elif not _link_up(L):
                down += 1
            elif (isinstance(ah, dict) and ah.get("alive") is True) or (isinstance(bh, dict) and bh.get("alive") is True):
                up += 1
            else:
                noping += 1
            continue
        types[L.get("type", "")] = types.get(L.get("type", ""), 0) + 1
        both_up = isinstance(ah, dict) and ah.get("up") and isinstance(bh, dict) and bh.get("up")
        if both_up:
            pinged = (ah.get("alive") is True) or (bh.get("alive") is True)
            if pinged:
                up += 1
            else:
                noping += 1
            sides = [h for h in (ah, bh) if isinstance(h, dict)]
            lrtt = max([_sflt(h.get("rtt_ms")) for h in sides if h.get("rtt_ms") is not None] or [0])
            lbad = any(h.get("alive") is False for h in sides)
            lloss = max([_sflt(h.get("loss_pct")) for h in sides] or [0])
            if lrtt > 0:
                rtts.append(lrtt)
            if lbad or lrtt > PING_BAD:
                cand = {"name": L.get("name"),
                        "a": nmap.get(L.get("a_node"), L.get("a_name", "")),
                        "b": nmap.get(L.get("b_node"), L.get("b_name", "")),
                        "rtt": lrtt if lrtt > 0 else None, "loss": lloss}
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
            ups.append(_uh_pct(n["id"], win))
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
            "proxies": len(load_proxies()),
            "links": len(links) - n_core, "core": n_core, "link_total": len(links),
            "links_healthy": up, "tunnels": tun, "portfw": pf,
            "health_score": score,
            "central": central_stats(),
            "heat": heat, "worst": worst,
            "crit": len(crit), "outdated": outdated,
            "alerts": alerts[:10],
            "link_up": up, "link_noping": noping, "link_down": down, "link_drift": drift_n,
            "link_off": off_n,
            "link_types": types, "worst_tunnel": worst_tun,
            "subnet_free": subnet_free_counts(links),
            "fleet_avg_ping": round(sum(rtts) / len(rtts)) if rtts else None,
            "uptime_avg": (int(sum(ups) / len(ups) * 10) / 10 if ups else 100), "uptime_down_nodes": downcnt, "uptime_window": win,
            "mem_used_mb": mu, "mem_total_mb": mt, "disk_used_mb": du, "disk_total_mb": dt,
            "fleet_rx_bps": frx_bps, "fleet_tx_bps": ftx_bps,
            "fleet_rx_total": frx, "fleet_tx_total": ftx,
            "ev_seq": _ev_seq_get(), "log_count": _ev_count_get(),
            "ui_interval": _sset.get("ui_interval", 2), "poll_interval": _sset.get("poll_interval", 2),
            "suspect_backoff": _tun.get("suspect_backoff", _TUNING_DEFAULTS["suspect_backoff"]),
            "dead_retest_secs": _tun.get("dead_retest_secs", _TUNING_DEFAULTS["dead_retest_secs"])}


def _name_taken(nodes, name, exclude_id=None):
    key = str(name).strip().lower()
    return any(n.get("id") != exclude_id and str(n.get("name", "")).strip().lower() == key for n in nodes)


def _host_taken(nodes, host, exclude_id=None):
    key = str(host).strip().lower()
    return any(n.get("id") != exclude_id and str(n.get("host", "")).strip().lower() == key for n in nodes)


def _node_first_contact(node):
    p = node_call(node, "ping", "GET")
    _refresh_cache([node["id"]])
    if not p.get("ok"):
        return
    try:
        _, _pub = _signing_keys()
        node_call(get_node(node["id"]) or node, "set-update-key", "POST", {"pubkey": _pub}, timeout=15)
    except Exception:
        pass
    _push_staged_on_add(get_node(node["id"]) or {**node, "arch": p.get("arch")})


def _refresh_bg(nids):
    threading.Thread(target=_refresh_cache, args=(list(nids),), daemon=True).start()


def api_node_add(d):
    _require(d, ["name", "host", "port", "token"])
    name = str(d["name"]).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise ValueError("نامِ نود نامعتبر است")
    host = str(d["host"]).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("آی‌پی یا هاستِ نود نامعتبر است")
    port = int(d["port"])
    if not 1 <= port <= 65535:
        raise ValueError("پورت نامعتبر است")
    token = str(d["token"]).strip()
    if not token:
        raise ValueError("توکن لازم است")
    if len(token) < 16:
        raise ValueError("توکن کوتاه است — حداقل ۱۶ کاراکتر بگذار")
    pon, pid = valid_proxy_ref(d)
    node = {"id": secrets.token_hex(5), "name": name, "host": host, "port": port, "token": token,
            "proxy_on": pon, "proxy_id": pid}
    with _reg_lock:
        nodes = load_nodes()
        if _name_taken(nodes, name):
            raise ValueError(f"نودی با نامِ «{name}» از قبل وجود دارد — یک نامِ یکتا انتخاب کن")
        if _host_taken(nodes, host):
            raise ValueError(f"نودی با آی‌پیِ «{host}» از قبل وجود دارد")
        nodes.append(node)
        save_json(NODES_FILE, nodes)
    threading.Thread(target=_node_first_contact, args=(node,), daemon=True).start()
    return {"ok": True, "id": node["id"], "checking": True}


NODE_RAW_URL = "https://raw.githubusercontent.com/Angize/TUNNEL-MANAGER-NODE/main/tnl-node.py"
_INSTALL_STEPS = [("ssh", "اتصالِ SSH"), ("agent", "رساندنِ ایجنت به نود"),
                  ("install", "نصب و راه‌اندازیِ سرویس"), ("register", "ثبت و اتصال در پنل")]
_INSTALL_LABELS = dict(_INSTALL_STEPS)
_install_jobs = {}
_install_lock = threading.Lock()


def _scrub(s):
    return re.sub(r"TNL_NODE_TOKEN=\S+", "TNL_NODE_TOKEN=***", s or "")[-1400:]


def _install_get(jid):
    with _install_lock:
        j = _install_jobs.get(jid)
        return json.loads(json.dumps(j)) if j else None


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


def _install_running(jid):
    with _install_lock:
        j = _install_jobs.get(jid)
        if not j:
            return _INSTALL_STEPS[0][0]
        for s in j["steps"]:
            if s["state"] == "run":
                return s["key"]
        for s in reversed(j["steps"]):
            if s["state"] != "wait":
                return s["key"]
    return _INSTALL_STEPS[0][0]


def _install_finish(jid, ok, banner):
    with _install_lock:
        j = _install_jobs.get(jid)
        if j:
            j["done"], j["ok"], j["banner"] = True, ok, banner


SSH_KNOWN_HOSTS = os.path.join(CENTRAL_DIR, "known_hosts")

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
    opts = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
            "-o", "ConnectTimeout=15", "-p", str(cfg["port"])]
    env = dict(os.environ)
    proxy = (cfg.get("proxy") or "").strip()
    if proxy:
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


def _ssh_run(cfg, remote_cmd, timeout, stdin_text=None):
    argv, env = _ssh_argv(cfg, remote_cmd)
    try:
        p = subprocess.run(argv, env=env, input=stdin_text, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", "SSH timeout"


def _install_worker(jid, cfg, name, agent_port, pon, pid):
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

        _install_step(jid, "agent", "run")
        try:
            src, ameta = _staged_agent()
        except OSError:
            return fail("agent", "ایجنتی روی پنل آماده نیست",
                        "در «تنظیمات» ایجنت را از گیت‌هاب بگیر یا فایلش را بارگذاری کن، بعد دوباره امتحان کن.")
        verify = f"echo '{ameta['sha256']}  /tmp/tnl-node.py' | sha256sum -c - >/dev/null; echo TNL_RECV_OK"
        if _delivery_mode("agent") == "github":
            recv = (f"set -e; umask 077; (curl -fsSL {NODE_RAW_URL} -o /tmp/tnl-node.py"
                    f" || wget -qO /tmp/tnl-node.py {NODE_RAW_URL}); echo TNL_DL_OK; {verify}")
            stdin, how = None, "از گیت‌هاب"
        else:
            recv, stdin, how = (f"set -e; umask 077; base64 -d > /tmp/tnl-node.py; echo TNL_DL_OK; {verify}",
                                base64.b64encode(src.encode()).decode(), "از پنل")
        rc, out, err = _ssh_run(cfg, recv, 120, stdin_text=stdin)
        if "TNL_DL_OK" not in out:
            return fail("agent", "دریافتِ ایجنت روی نود ناموفق (curl/wget؟ دسترسیِ اینترنت؟)", (err or out).strip())
        if rc != 0 or "TNL_RECV_OK" not in out:
            return fail("agent", "فایلِ رسیده با ایجنتِ آمادهٔ پنل یکی نیست", (err or out).strip())
        _install_step(jid, "agent", "ok", f"tnl-node.py نسخهٔ {ameta['version']} {how} رسید")

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
                "port": agent_port, "token": token, "proxy_on": pon, "proxy_id": pid}
        with _reg_lock:
            nodes = load_nodes()
            if _name_taken(nodes, name):
                return fail("register", f"نودی با نامِ «{name}» در این فاصله اضافه شد — نام باید یکتا باشد")
            if _host_taken(nodes, cfg["host"]):
                return fail("register", f"نودی با آی‌پیِ «{cfg['host']}» در این فاصله اضافه شد")
            nodes.append(node)
            save_json(NODES_FILE, nodes)
        _refresh_cache([node["id"]])
        online = False
        for _ in range(6):
            if node_call(node, "ping", "GET").get("ok"):
                online = True
                break
            time.sleep(2)
        with _install_lock:
            _install_jobs[jid]["node_id"] = node["id"]
        if online:
            _push_staged_on_add(get_node(node["id"]) or node)
        _install_step(jid, "register", "ok" if online else "warn",
                      "نود وصل شد و آنلاین است" if online else "ثبت شد ولی هنوز پاسخ نمی‌دهد (پورتِ ایجنت را به سرورِ مرکزی باز کن)")
        _install_finish(jid, True, f"«{name}» نصب و وصل شد" if online else f"«{name}» ثبت شد؛ در انتظارِ آنلاین‌شدن")
    except Exception as e:
        fail(_install_running(jid), "خطای غیرمنتظره", str(e))
    finally:
        kf = cfg.get("keyfile")
        if kf:
            try:
                os.remove(kf)
            except Exception:
                pass


def api_node_install(d):
    _gate_ready(True)
    _require(d, ["name", "ssh_host"])
    name = str(d["name"]).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise ValueError("نامِ نود نامعتبر است")
    host = str(d["ssh_host"]).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("آی‌پی یا هاستِ نود نامعتبر است")
    _exist = load_nodes()
    if _name_taken(_exist, name):
        raise ValueError(f"نودی با نامِ «{name}» از قبل وجود دارد — یک نامِ یکتا انتخاب کن")
    if _host_taken(_exist, host):
        raise ValueError(f"نودی با آی‌پیِ «{host}» از قبل وجود دارد")
    ssh_port = int(d.get("ssh_port") or 22)
    if not 1 <= ssh_port <= 65535:
        raise ValueError("پورتِ SSH نامعتبر است")
    user = str(d.get("ssh_user") or "root").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", user):
        raise ValueError("کاربرِ SSH نامعتبر است")
    agent_port = int(d.get("agent_port") or 8099)
    if not 1 <= agent_port <= 65535:
        raise ValueError("پورتِ ایجنت نامعتبر است")
    pon, pid = valid_proxy_ref(d)
    password = str(d.get("ssh_pass") or "")
    key = str(d.get("ssh_key") or "").strip()
    if not password and not key:
        raise ValueError("رمزِ SSH یا کلیدِ خصوصی لازم است")
    cfg = {"host": host, "port": ssh_port, "user": user, "password": password,
           "proxy": node_proxy({"proxy_on": pon, "proxy_id": pid})}
    if key:
        fd, kp = tempfile.mkstemp(prefix="tnlkey_")
        with os.fdopen(fd, "w") as f:
            f.write(key if key.endswith("\n") else key + "\n")
        os.chmod(kp, 0o600)
        cfg["keyfile"], cfg["password"] = kp, ""
    now = int(time.time())
    jid = secrets.token_hex(6)
    with _install_lock:
        for k in [k for k, v in _install_jobs.items() if now - v.get("ts", now) > 3600]:
            _install_jobs.pop(k, None)
        _install_jobs[jid] = {"steps": [{"key": k, "label": l, "state": "wait", "detail": "", "log": ""}
                                        for k, l in _INSTALL_STEPS],
                              "done": False, "ok": False, "banner": "", "node_id": None, "ts": now}
    threading.Thread(target=_install_worker, args=(jid, cfg, name, agent_port, pon, pid), daemon=True).start()
    return {"ok": True, "job": jid}


def api_node_install_status(d):
    _require(d, ["job"])
    j = _install_get(d["job"])
    if not j:
        raise ValueError("این کار دیگر در جریان نیست")
    return {**j, "ok": True, "success": bool(j.get("ok"))}


def api_node_edit(d):
    _require(d, ["id", "name", "host", "port"])
    name = str(d["name"]).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise ValueError("نامِ نود نامعتبر است")
    host = str(d["host"]).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("آی‌پی یا هاستِ نود نامعتبر است")
    port = int(d["port"])
    if not 1 <= port <= 65535:
        raise ValueError("پورت نامعتبر است")
    token = str(d.get("token") or "").strip()
    pon, pid = valid_proxy_ref(d)
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if x["id"] == d["id"]), None)
        if not n:
            raise ValueError("نود پیدا نشد")
        if _name_taken(nodes, name, exclude_id=d["id"]):
            raise ValueError(f"نودِ دیگری با نامِ «{name}» وجود دارد — نام باید یکتا باشد")
        if _host_taken(nodes, host, exclude_id=d["id"]):
            raise ValueError(f"نودِ دیگری با آی‌پیِ «{host}» وجود دارد")
        n["name"], n["host"], n["port"] = name, host, port
        n["proxy_on"], n["proxy_id"] = pon, pid
        if token:
            n["token"] = token
        save_json(NODES_FILE, nodes)
        links = load_links()
        chg = False
        for L in links:
            if L.get("a_node") == d["id"] and L.get("a_name") != name:
                L["a_name"], chg = name, True
            if L.get("b_node") == d["id"] and L.get("b_name") != name:
                L["b_name"], chg = name, True
        if chg:
            save_json(LINKS_FILE, links)
    _refresh_bg([d["id"]])
    return {"ok": True, "checking": True}


def api_node_toggle(d):
    _require(d, ["id"])
    want = bool(d.get("disabled"))
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if x["id"] == d["id"]), None)
        if not n:
            raise ValueError("نود پیدا نشد")
        if want:
            n["disabled"] = True
        else:
            n.pop("disabled", None)
        save_json(NODES_FILE, nodes)
    return {"ok": True, "disabled": want}


def api_node_del(d):
    _require(d, ["id"])
    nid = d["id"]
    force = bool(d.get("wipe_force") or d.get("force"))
    n = get_node(nid)
    if not n:
        raise ValueError("نود پیدا نشد")
    if force and _known_offline(n):
        node_ok = False
    else:
        r = node_call(n, "wipe", "POST", {}, timeout=NODE_OP_TIMEOUT)
        node_ok = bool(r.get("ok"))
        if not node_ok:
            raise ValueError("پاک‌سازیِ سمتِ نود ناتمام ماند: " + (r.get("error") or r.get("msg") or "خطا")
                             + " — اگر نود قطع است چند لحظه صبر کن تا وضعیتش قرمز شود بعد «پاک‌سازیِ اجباری» بزن.")
    with _reg_lock:
        links = load_links()
        mine = [L for L in links if L.get("a_node") == nid or L.get("b_node") == nid]
        mine_ids = {L["id"] for L in mine}
    _park_failed = []
    def _del_peer_half(L):
        peer_id = L["b_node"] if L["a_node"] == nid else L["a_node"]
        pn = get_node(peer_id)
        if not pn:
            return
        with _PairLock(peer_id, peer_id):
            rr = node_call(pn, "delete", "POST", {"name": L["name"]}, timeout=8)
        if not rr.get("ok") and not _pending_add(peer_id, L["name"]):
            _park_failed.append(L["id"])
    parallel_map(_del_peer_half, mine, workers=32)
    if _park_failed:
        raise ValueError("صفِ حذفِ معلق نوشته نشد؛ برای پرهیز از تونلِ یتیم چیزی حذف نشد — دوباره تلاش کن.")
    with _reg_lock:
        save_json(LINKS_FILE, [L for L in load_links() if L["id"] not in mine_ids])
    out = {"ok": True, "links_removed": len(mine_ids), "node_wiped": node_ok}
    with _reg_lock:
        save_json(NODES_FILE, [n for n in load_nodes() if n["id"] != nid])
    _pending_prune_node(nid)
    with _tomb_lock:
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
        raise ValueError("پیدا نشد")
    t0 = time.perf_counter()
    p = node_call(n, "ping", "GET")
    if p.get("ok"):
        p = {**p, "rtt_ms": int((time.perf_counter() - t0) * 1000)}
    return {"ok": bool(p.get("ok")), "info": p}


def api_node_adopt_ip(d):
    _require(d, ["id"])
    n = get_node(str(d["id"]))
    if not n:
        raise ValueError("نود پیدا نشد")
    new, newp = moved_to(n["id"]), moved_port(n["id"]) or int(n.get("port") or 0)
    if not new:
        raise ValueError("آدرسِ تازه‌ای برای این نود ثبت نشده")
    probe = dict(n)
    probe["host"], probe["port"] = new, newp
    if not node_call(probe, "ping", "GET", timeout=8).get("ok"):
        pid = str(n.get("proxy_id") or "") if n.get("proxy_on") else ""
        px = _px_get(pid) if pid else {}
        if px and not px.get("ok"):
            raise ValueError("پروکسیِ این نود قطع است، پس هیچ آدرسی از آن رد نمی‌شود — اول پروکسی را درست کن")
        raise ValueError(f"نشانیِ {new}:{newp} همین حالا جواب نمی‌دهد — چیزی عوض نشد")
    with _reg_lock:
        nodes = load_nodes()
        t = next((x for x in nodes if x["id"] == n["id"]), None)
        if not t:
            raise ValueError("نود پیدا نشد")
        old, oldp = t["host"], int(t.get("port") or 0)
        t["host"], t["port"] = new, newp
        save_json(NODES_FILE, nodes)
    _moved_clear(n["id"])
    log_event("ok", "node", f"نودِ «{n['name']}»: تنظیمِ نشانیِ تازه",
              f"نشانی از {old}:{oldp} به {new}:{newp} عوض شد — تونل‌هایش را بازسازی کن")
    _refresh_cache([n["id"]])
    return {"ok": True, "host": new, "port": newp}


def api_node_kernel_tune(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("پیدا نشد")
    action = str(d.get("action") or "status")
    if action not in ("apply", "revert", "status"):
        raise ValueError("عملیاتِ نامعتبر")
    p = node_call(n, "kernel-tune", "POST", {"action": action}, timeout=15)
    if not p.get("ok"):
        return {"ok": False, "error": p.get("error", "unreachable")}
    return {"ok": True, "active": bool(p.get("active")), "cc": str(p.get("cc") or ""),
            "qdisc": str(p.get("qdisc") or ""), "bbr_available": bool(p.get("bbr_available"))}


def api_node_stats(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("پیدا نشد")
    p = node_call(n, "ping", "GET", timeout=8)
    if not p.get("ok"):
        return {"online": False, "error": p.get("error", "unreachable")}
    return {"online": True, "stats": p.get("stats") or {},
            "tunnels": p.get("tunnels"), "portfw": p.get("portfw"), "hostname": p.get("hostname")}


def api_node_traffic(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise ValueError("پیدا نشد")
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
    if len(src.encode()) > 262144:
        raise ValueError(msgs["too_big"])
    try:
        compile(src, "tnl-node.py", "exec")
    except SyntaxError as e:
        raise ValueError(msgs["bad_py"] + str(e))
    if '"agent": "tnl-node"' not in src:
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
    try:
        src = _gh_get(NODE_RAW_URL, 30)[:300000].decode("utf-8", "replace")
    except Exception as e:
        raise ValueError("دریافت از گیت‌هاب ناموفق: " + _gh_why(e))
    if not src.strip():
        raise ValueError("فایلِ دریافتی خالی است")
    return _store_agent_src(src, {
        "too_big": "فایلِ دریافتی بیش از حد بزرگ است",
        "bad_py": "کدِ دریافتی نامعتبر: ",
        "not_agent": "فایلِ دریافتی ایجنتِ نود نیست",
        "no_ver": "نسخهٔ ایجنت در کدِ دریافتی پیدا نشد",
    }, {"source": "git"})


def api_agent_info(d):
    try:
        with open(AGENT_META) as f:
            meta = json.load(f)
    except Exception:
        meta = {"none": True}
    return {**meta, "delivery": _delivery_mode("agent")}


def _staged_agent():
    with _agent_lock:
        with open(AGENT_FILE) as f:
            src = f.read()
        with open(AGENT_META) as f:
            meta = json.load(f)
    return src, meta


def _delivery_mode(kind):
    m = str(get_settings().get(kind + "_delivery") or "push")
    return m if m in DELIVERY_MODES else "push"


_route_src_cache = {}
ROUTE_SRC_TTL = 60


def _route_src(host):
    now = time.time()
    hit = _route_src_cache.get(host)
    if hit and now - hit[0] < ROUTE_SRC_TTL:
        return hit[1]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip = s.getsockname()[0] if s.connect((host, 9)) is None else ""
    except OSError:
        ip = ""
    finally:
        s.close()
    _route_src_cache[host] = (now, ip)
    return ip


def _panel_origin_for(node):
    if not _CENTRAL_PORT:
        return ""
    ip = central_host() if node_proxy(node) else _route_src(str(node.get("host") or ""))
    return f"{'https' if _CENTRAL_TLS else 'http'}://{ip}:{_CENTRAL_PORT}" if is_ipv4(ip) else ""


DL_TICKET_TTL = 3600


def _range_start(hdr, size):
    h = str(hdr or "").strip().lower()
    if not h:
        return 0
    m = re.fullmatch(r"bytes=(\d+)-(\d*)", h)
    if not m:
        return None
    start = int(m.group(1))
    if start >= size:
        return None
    if m.group(2) and int(m.group(2)) < start:
        return None
    return start


def _dl_ticket_msg(q):
    return "&".join("%s=%s" % (k, q[k]) for k in sorted(q) if k != "sig")


def _panel_dl_url(node, kind, arch=""):
    origin = _panel_origin_for(node)
    if not origin:
        return ""
    tok = str(node.get("token") or "")
    q = {"fp": hashlib.sha256(tok.encode()).hexdigest(), "k": kind,
         "exp": str(int(time.time()) + DL_TICKET_TTL)}
    if arch:
        q["arch"] = arch
    q["sig"] = base64.urlsafe_b64encode(
        hmac.new(tok.encode(), _dl_ticket_msg(q).encode(), hashlib.sha256).digest()).decode()
    return origin + "/api/dl?" + urllib.parse.urlencode(q)


def _dl_ticket_node(q):
    fp, sig = str(q.get("fp") or ""), str(q.get("sig") or "")
    if len(fp) != 64 or not sig:
        return None
    try:
        if int(q.get("exp") or 0) < time.time():
            return None
        got = base64.urlsafe_b64decode(sig)
    except Exception:
        return None
    msg = _dl_ticket_msg(q).encode()
    for n in load_nodes():
        tok = str(n.get("token") or "")
        if not tok or not hmac.compare_digest(hashlib.sha256(tok.encode()).hexdigest(), fp):
            continue
        return n if hmac.compare_digest(hmac.new(tok.encode(), msg, hashlib.sha256).digest(), got) else None
    return None


_NO_ORIGIN = ("پنل هنوز آدرسِ خودش را نمی‌داند، پس نمی‌تواند نشانیِ دانلود بدهد — "
              "حالتِ تحویل را روی «پنل آپلود کند» یا «از گیت‌هاب» بگذار")


def _agent_meta_or_empty():
    try:
        return _staged_agent()[1]
    except Exception:
        return {}


def _agent_delivery_check(meta, mode):
    if mode == "github" and meta.get("source") != "git":
        raise ValueError("این ایجنت از فایل بارگذاری شده و روی گیت‌هاب نیست — یا «دریافت از گیت‌هاب» را بزن، "
                         "یا حالتِ تحویلِ ایجنت را عوض کن")


def _agent_update_body(node, src, meta, sig):
    mode = _delivery_mode("agent")
    _agent_delivery_check(meta, mode)
    body = {"sha256": meta["sha256"], "sig": sig}
    if mode == "push":
        return {"code": src, **body}
    if mode == "github":
        return {"url": NODE_RAW_URL, **body}
    url = _panel_dl_url(node, "ag")
    if not url:
        raise ValueError(_NO_ORIGIN)
    return {"url": url, **body}


def _core_delivery_check(mode, custom):
    if mode == "github" and custom:
        raise ValueError("این باینری روی پنل بارگذاری شده و روی گیت‌هاب نیست — "
                         "حالتِ تحویلِ هسته را روی «پنل آپلود کند» یا «نود از پنل بگیرد» بگذار")


def _github_grant(ver, arch):
    url = _release_asset_url(ver, arch)
    return {"url": url, "version": ver, "sig": _sign_sha(url)}


def _core_install_body(node, b64, sha, ver, sig, arch="", custom=False):
    mode = _delivery_mode("core")
    _core_delivery_check(mode, custom)
    if mode == "github":
        return _github_grant(ver, arch)
    body = {"sha256": sha, "version": ver, "sig": sig}
    if mode == "push":
        return {"data": b64, **body}
    url = _panel_dl_url(node, "cb" if custom else "co", "" if custom else arch)
    if not url:
        raise ValueError(_NO_ORIGIN)
    return {"url": url, **body}


def _readiness():
    if _delivery_mode("agent") == "github":
        agent = True
    else:
        try:
            _staged_agent()
            agent = True
        except Exception:
            agent = False
    info = _staged_info()
    if _delivery_mode("core") == "github":
        missing = []
    else:
        missing = [a for a in CORE_ARCHES
                   if not os.path.isfile(os.path.join(CORE_STAGE_DIR, "tnl-core-" + a))]
    core = bool(info) and not missing
    return {"agent": agent, "core": core, "core_missing": missing,
            "core_version": (info or {}).get("version", ""), "ok": agent and core}


def api_readiness(d):
    return _readiness()


def _gate_ready(need_agent):
    r = _readiness()
    miss = []
    if need_agent and not r["agent"]:
        miss.append("ایجنتِ نود")
    if not r["core"]:
        miss.append("هستهٔ داده" + (" برای معماریِ " + "، ".join(r["core_missing"]) if r["core_version"] else ""))
    if miss:
        raise ValueError("این کار به چیزی نیاز دارد که هنوز روی پنل آماده نیست: " + " و ".join(miss)
                         + " — در «تنظیمات» آن را بگیر و دوباره امتحان کن")


def _dl_artifact(kind, arch):
    if kind == "ag":
        return _staged_agent()[0].encode()
    if kind == "co":
        b = _staged_bytes(arch)
        return b[0] if b else None
    if kind == "cb":
        with _core_blob_lock:
            with open(CORE_BLOB, "rb") as f:
                return f.read()
    return None


def _body_cache(build):
    cache = {}

    def enc(node, _ctx=None):
        body = build(node)
        key = body.get("url") or body["sha256"]
        if key not in cache:
            cache[key] = json.dumps(body).encode()
        return cache[key]

    return enc


_push_lock = threading.Lock()
_push_jobs = {}
_push_batch = set()
_push_final = None
PUSH_STATES = ("wait", "run", "ok", "same", "err", "skip")
PUSH_CAP = 256


PUSH_BUSY_STATES = ("wait", "run")


def _busy_nodes(kind):
    return {nid for v in _push_jobs.values() if not v["done"] and v["kind"] == kind
            for nid, s in v["nodes"].items() if s["state"] in PUSH_BUSY_STATES}


def _push_job_new(kind, nodes):
    jid = secrets.token_hex(6)
    now = int(time.time())
    with _push_lock:
        for k in [k for k, v in _push_jobs.items() if now - v.get("ts", now) > 3600]:
            _push_jobs.pop(k, None)
        busy = _busy_nodes(kind)
        nodes = [x for x in nodes if x["id"] not in busy]
        if not nodes:
            raise ValueError("همین به‌روزرسانی روی این نود در جریان است — تا تمام‌شدنش صبر کن")
        global _push_final
        if not _push_live():
            _push_batch.clear()
            _push_final = None
        _push_batch.add(jid)
        _push_jobs[jid] = {"kind": kind, "order": [n["id"] for n in nodes], "done": False, "ts": now,
                           "cancel": False, "paused": False,
                           "nodes": {n["id"]: {"name": n["name"], "state": "wait", "pct": 0,
                                               "step": "", "si": 0, "sn": 0,
                                               "err": "", "detail": ""} for n in nodes}}
    return jid


def _push_start(kind, nodes, plan):
    if not nodes:
        return None
    jid = _push_job_new(kind, nodes)
    threading.Thread(target=_push_worker, args=(jid, kind, nodes, plan), daemon=True).start()
    return jid


PUSH_ALL = "*"


def _push_live():
    return [jid for jid, j in sorted(_push_jobs.items(), key=lambda kv: kv[1].get("ts", 0))
            if not j["done"]]


def _push_merge_locked(jids):
    order, nodes, kinds = [], {}, set()
    cancel = paused = True
    for jid in jids:
        j = _push_jobs[jid]
        kinds.add(j["kind"])
        cancel = cancel and bool(j.get("cancel"))
        paused = paused and bool(j.get("paused"))
        for nid in j["order"]:
            if nid not in nodes:
                order.append(nid)
                nodes[nid] = dict(j["nodes"][nid])
    return {"ok": True, "job": PUSH_ALL, "kind": kinds.pop() if len(kinds) == 1 else "mixed",
            "done": all(_push_jobs[jid]["done"] for jid in jids),
            "cancel": cancel, "paused": paused, "order": order, "nodes": nodes}


def _push_seal_locked():
    global _push_final
    _push_final = _push_merge_locked(sorted(_push_batch, key=lambda k: _push_jobs[k].get("ts", 0)))


def _push_merged():
    with _push_lock:
        live = _push_live()
        if live:
            return _push_merge_locked(live)
        return dict(_push_final) if _push_final else None


def _push_set(jid, nid, **kw):
    if "state" in kw and kw["state"] not in PUSH_STATES:
        raise ValueError("وضعیتِ ناشناختهٔ آپلود: %r" % kw["state"])
    with _push_lock:
        j = _push_jobs.get(jid)
        if j and nid in j["nodes"]:
            j["nodes"][nid].update(kw)


def _skip_waiting(j):
    for nid in j["order"]:
        if j["nodes"][nid]["state"] == "wait":
            j["nodes"][nid].update(state="skip", pct=0)


def _push_cancelled(jid):
    with _push_lock:
        j = _push_jobs.get(jid)
        return bool(j and j.get("cancel"))


class _BuildCtx:
    def __init__(self, jid, nid, at, i):
        self.jid, self.nid, self._at, self._i = jid, nid, at, i

    def step(self, name):
        _push_set(self.jid, self.nid, step=name)

    def progress(self, sent, total):
        _push_set(self.jid, self.nid,
                  pct=self._at(self._i, (sent / total) * 0.95 if total and sent < total else 0.96))

    def cancelled(self):
        return _push_cancelled(self.jid)


def _push_one(jid, nid, plan):
    n = len(plan)

    def at(i, frac):
        return int(max(0.0, min(1.0, (i + frac) / n)) * 100)

    try:
        keyed = False
        for i, (code, endpoint, build, timeout, gate) in enumerate(plan):
            if _push_cancelled(jid):
                _push_set(jid, nid, state="skip", step=code)
                return
            fresh = get_node(nid)
            if not fresh:
                _push_set(jid, nid, state="err", err="node_gone")
                return
            if i and _push_paused(jid):
                _push_set(jid, nid, state="run", step="paused", si=i + 1, sn=n, pct=at(i, 0))
                while _push_paused(jid):
                    if _push_cancelled(jid):
                        _push_set(jid, nid, state="skip", step=code)
                        return
                    time.sleep(0.2)
            _push_set(jid, nid, state="run", step=code, si=i + 1, sn=n, pct=at(i, 0))
            if not keyed:
                _ensure_update_key(fresh)
                keyed = True
            try:
                body = build(fresh, _BuildCtx(jid, nid, at, i))
            except _Cancelled:
                _push_set(jid, nid, state="skip", step=code, pct=0)
                return
            except ValueError as e:
                _push_set(jid, nid, state="err", err="unbuildable", detail=str(e))
                return
            _push_set(jid, nid, step=code, pct=at(i, 0))
            if body is None:
                _push_set(jid, nid, state="skip", step=code)
                return

            def prog(sent, total, _nid=nid, _i=i):
                _push_set(jid, _nid, pct=at(_i, (sent / total) * 0.95 if total and sent < total else 0.96))

            r = node_push(fresh, endpoint, body, on_progress=prog, timeout=timeout,
                          should_abort=lambda: _push_cancelled(jid))
            if r.get("cancelled"):
                _push_set(jid, nid, state="skip", step=code,
                          detail="درخواست کامل به نود رسیده بود — ممکن است همین مرحله را انجام داده باشد"
                                 if r.get("delivered") else "")
                return
            if not r.get("ok"):
                _push_set(jid, nid, state="err", step=code,
                          err=str(r.get("code") or ("offline" if r.get("offline") else "failed")),
                          detail=str(r.get("error") or r.get("msg") or ""))
                return
            if gate and gate(r):
                _push_set(jid, nid, state="same", step=code, pct=100)
                return
            _push_set(jid, nid, pct=at(i + 1, 0), restarted=r.get("restarted"))
        _push_set(jid, nid, state="ok", pct=100)
    except Exception as e:
        _push_set(jid, nid, state="err", err="panel", detail=str(e)[:120])


def _push_paused(jid):
    with _push_lock:
        j = _push_jobs.get(jid)
        return bool(j and j.get("paused") and not j.get("cancel"))


def _push_next(jid, first):
    with _push_lock:
        j = _push_jobs.get(jid)
        if not j:
            return None
        if j.get("cancel"):
            return None
        if j.get("paused"):
            return "wait" if any(v["state"] == "wait" for v in j["nodes"].values()) else None
        for nid in j["order"]:
            if j["nodes"][nid]["state"] == "wait":
                j["nodes"][nid].update(state="run", step=first[0], si=1, sn=first[1], pct=0)
                return nid
    return None


def _push_worker(jid, kind, nodes, payload):
    def loop():
        while True:
            nid = _push_next(jid, (payload[0][0], len(payload)))
            if nid is None:
                return
            if nid != "wait":
                _push_one(jid, nid, payload)
                continue
            time.sleep(0.3)

    try:
        n = min(PUSH_CAP, max(1, len(nodes)))
        workers = [threading.Thread(target=loop, daemon=True) for _ in range(n)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
    finally:
        with _push_lock:
            j = _push_jobs.get(jid)
            if j:
                j["done"] = True
            if not _push_live() and _push_batch:
                _push_seal_locked()


def api_push_status(d):
    jid = str((d or {}).get("job") or "")
    if not jid or jid == PUSH_ALL:
        return _push_merged() or {"ok": True, "job": "", "idle": True, "done": True}
    with _push_lock:
        j = _push_jobs.get(jid)
        if not j:
            raise ValueError("این کار دیگر در جریان نیست")
        return {"ok": True, "job": jid, "kind": j["kind"], "done": j["done"],
                "cancel": bool(j.get("cancel")), "paused": bool(j.get("paused")), "order": list(j["order"]),
                "nodes": {k: dict(v) for k, v in j["nodes"].items()}}


def api_push_cancel(d):
    jid = str((d or {}).get("job") or "") or PUSH_ALL
    with _push_lock:
        targets = _push_live() if jid == PUSH_ALL else [jid]
        js = [_push_jobs[k] for k in targets if k in _push_jobs]
        if not js:
            raise ValueError("این کار دیگر در جریان نیست")
        live = [j for j in js if not j["done"]]
        if not live:
            return {"ok": True, "already_done": True}
        for j in live:
            j["cancel"] = True
            _skip_waiting(j)
    log_event("warn", "node", "لغوِ آپلود به فلیت توسطِ اپراتور")
    return {"ok": True, "job": jid}


def api_push_pause(d):
    jid = str((d or {}).get("job") or "") or PUSH_ALL
    want = bool((d or {}).get("paused", True))
    with _push_lock:
        targets = _push_live() if jid == PUSH_ALL else [jid]
        js = [_push_jobs[k] for k in targets if k in _push_jobs]
        if not js:
            raise ValueError("این کار دیگر در جریان نیست")
        live = [j for j in js if not j["done"] and not j.get("cancel")]
        if not live:
            return {"ok": True, "done": True}
        for j in live:
            j["paused"] = want
    return {"ok": True, "job": jid, "paused": want}


def _update_targets(d):
    _require(d, ["ids"])
    if not isinstance(d.get("ids"), list):
        raise ValueError("فهرستِ شناسه‌ها نامعتبر است")
    nodes = [n for n in (get_node(i) for i in dict.fromkeys(d["ids"])) if n]
    if not nodes:
        raise ValueError("نودی انتخاب نشده")
    return nodes


def _core_current(ping, sha):
    got = str(ping.get("core_sha") or "")
    return bool(got) and sha.startswith(got)


def _update_start(kind, nodes, plan):
    jid = _push_start(kind, nodes, plan)
    return {"ok": True, "job": jid} if jid else {"ok": True, "none": True}


def api_update_agent(d):
    nodes = _update_targets(d)
    mode = _delivery_mode("agent")
    have = _agent_meta_or_empty()
    if mode == "github" and (not have or have.get("source") == "git"):
        try:
            api_agent_fetch_git({})
        except Exception:
            if not have:
                raise
    try:
        src, meta = _staged_agent()
    except OSError:
        raise ValueError("ابتدا یک ایجنت بارگذاری کنید")
    _agent_delivery_check(meta, mode)
    sig = _sign_sha(meta["sha256"])
    enc = _body_cache(lambda n: _agent_update_body(n, src, meta, sig))
    plan = [("check", "ping", lambda _n, _c=None: {}, 15,
             lambda r, _w=meta["sha256"]: str(r.get("sha256") or "") == _w),
            ("deliver", "update", enc, 60, None)]
    return _update_start("agent", nodes, plan)


def api_update_core(d):
    nodes = _update_targets(d)
    version = str((d or {}).get("version") or "").strip()
    if version == "custom":
        info = _core_blob_info()
        if not info:
            raise ValueError("هیچ باینریِ سفارشی‌ای بارگذاری نشده")
        _core_delivery_check(_delivery_mode("core"), True)
        with _core_blob_lock:
            with open(CORE_BLOB, "rb") as f:
                raw = f.read()
        b64, sha = base64.b64encode(raw).decode(), info["sha256"]
        sig = _sign_sha(sha)
        put = _body_cache(lambda n: _core_install_body(n, b64, sha, "custom", sig, custom=True))
        plan = [("check", "ping", lambda _n, _c=None: {}, 15, lambda r, _s=sha: _core_current(r, _s)),
                ("deliver", "core-put", put, 300, None),
                ("install", "core-apply",
                 lambda _n, _c=None, _s=sha, _g=sig: {"sha256": _s, "version": "custom", "sig": _g},
                 300, None)]
        return _update_start("core", nodes, plan)

    gh = _delivery_mode("core") == "github"
    if not version and not _staged_info():
        raise ValueError("هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه انتخاب کن")

    parts = {}
    staged = {"done": not version or _staged_holds(version, not gh), "err": ""}
    staging = threading.Lock()

    def ensure(ctx=None):
        if staged["done"]:
            return
        mine = staging.acquire(blocking=False)
        if not mine:
            if ctx:
                ctx.step("stagewait")
            staging.acquire()
        try:
            if staged["err"]:
                raise ValueError(staged["err"])
            if staged["done"]:
                return
            if ctx and not gh:
                ctx.step("stage")
            try:
                if gh:
                    _stage_core_meta(version)
                else:
                    _stage_core(version, on_progress=(ctx.progress if ctx else None),
                                should_abort=(ctx.cancelled if ctx else None))
            except _Cancelled:
                raise
            except Exception as e:
                staged["err"] = f"نسخهٔ «{version}» از گیت‌هاب گرفته نشد: " + _gh_why(e)
                raise ValueError(staged["err"])
            staged["done"] = True
        finally:
            staging.release()

    def check_body(_n, ctx=None):
        ensure(ctx)
        return {}

    def prep(n):
        arch = _node_arch(n)
        if not arch:
            raise ValueError("معماریِ نود مشخص نشد — نود باید یک‌بار پاسخ بدهد تا باینریِ درست فرستاده شود")
        if arch not in parts:
            if gh:
                ver = str((_staged_info() or {}).get("version") or "")
                if not ver:
                    raise ValueError("هیچ نسخه‌ای انتخاب نشده — اول یک نسخه انتخاب کن")
                parts[arch] = ("", "", ver, "", arch)
            else:
                b = _staged_bytes(arch)
                if not b:
                    raise ValueError("هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن")
                raw, sha, ver = b
                parts[arch] = (base64.b64encode(raw).decode(), sha, ver, _sign_sha(sha), arch)
        return parts[arch]

    def put_body(n):
        b64, sha, ver, sig, arch = prep(n)
        return _core_install_body(n, b64, sha, ver, sig, arch=arch)

    put = _body_cache(put_body)

    def apply_body(n, _ctx=None):
        _b64, sha, ver, sig, arch = prep(n)
        return _github_grant(ver, arch) if gh else {"sha256": sha, "version": ver, "sig": sig}

    def current(r):
        arch = str(r.get("arch") or "")
        if arch not in CORE_ARCHES:
            return False
        if gh:
            ensure()
            ver = str((_staged_info() or {}).get("version") or "")
            return bool(ver) and str(r.get("core_ver") or "") == ver
        want = str(((_staged_info() or {}).get("sha") or {}).get(arch) or "")
        return bool(want) and _core_current(r, want)

    plan = [("check", "ping", check_body, 15, current),
            ("deliver", "core-put", put, 300, None),
            ("install", "core-apply", apply_body, 300, None)]
    return _update_start("core", nodes, plan)


_CORE_RELEASES_API = "https://api.github.com/repos/Angize/TUNNEL-MANAGER-CORE/releases"
_core_versions_cache = {"ts": 0.0, "data": None}
_core_versions_lock = threading.Lock()


def _fetch_core_versions():
    raw = _gh_get(_CORE_RELEASES_API, 30, {"Accept": "application/vnd.github+json"})
    vers = []
    for rel in json.loads(raw.decode()):
        tag = rel.get("tag_name")
        if not tag or rel.get("draft"):
            continue
        vers.append({"id": tag, "label": rel.get("name") or tag, "prerelease": bool(rel.get("prerelease"))})
    return vers


def api_core_versions(d):
    vers = list(_core_versions_cache["data"] or [])
    out = list(vers)
    if out:
        out[0] = {**out[0], "label": (out[0].get("label") or out[0]["id"]) + " (latest)", "latest": True}
    info = _core_blob_info()
    if info:
        out.append({"id": "custom", "label": "\u0628\u0627\u06cc\u0646\u0631\u06cc\u0650 \u0622\u067e\u0644\u0648\u062f\u0634\u062f\u0647" + (" \u00b7 " + info["name"] if info.get("name") else ""),
                    "custom": True, "sha256": info.get("sha256", "")[:12], "size": info.get("size")})
    return {"versions": out, "staged": _staged_info(), "checked_ts": int(_core_versions_cache["ts"] or 0),
            "delivery": _delivery_mode("core")}


def api_core_delete_blob(d):
    with _core_blob_lock:
        gone = False
        for path in (CORE_BLOB, CORE_BLOB_META):
            try:
                os.remove(path)
                gone = True
            except FileNotFoundError:
                pass
    if not gone:
        raise ValueError("هیچ باینریِ سفارشی‌ای بارگذاری نشده")
    log_event("ok", "core", "باینریِ سفارشیِ هسته حذف شد")
    return {"ok": True}


def api_core_check(d):
    before = list(_core_versions_cache["data"] or [])
    prev_top = (before[0].get("id") if before else "")
    try:
        vers = _fetch_core_versions()
    except Exception as e:
        return {"ok": False, "error": "\u062f\u0631\u06cc\u0627\u0641\u062a \u0627\u0632 \u06af\u06cc\u062a\u200c\u0647\u0627\u0628 \u0646\u0627\u0645\u0648\u0641\u0642: " + _gh_why(e)}
    with _core_versions_lock:
        _core_versions_cache["data"] = vers
        _core_versions_cache["ts"] = time.time()
    top = (vers[0].get("id") if vers else "")
    return {"ok": True, "count": len(vers), "latest": top, "newer": bool(top and top != prev_top),
            "first_check": not before}


def _core_blob_info():
    try:
        with open(CORE_BLOB_META) as f:
            m = json.load(f)
        if os.path.isfile(CORE_BLOB):
            return m
    except Exception:
        pass
    return None


def api_core_upload(d):
    _require(d, ["data"])
    try:
        raw = base64.b64decode(d["data"], validate=True)
    except Exception:
        raise ValueError("فایل base64 نامعتبر است")
    if len(raw) < 100000:
        raise ValueError("فایل خیلی کوچک است — این باینریِ هسته نیست")
    if len(raw) > 15 * 1024 * 1024:
        raise ValueError("فایل بیش از حد بزرگ است")
    if raw[:4] != b"\x7fELF":
        raise ValueError("این یک باینریِ ELF لینوکسی نیست")
    sha = hashlib.sha256(raw).hexdigest()
    name = str(d.get("name") or "core.bin")[:80]
    with _core_blob_lock:
        save_bytes(CORE_BLOB, raw)
        save_json(CORE_BLOB_META, {"sha256": sha, "size": len(raw), "name": name, "uploaded_ts": int(time.time())})
    return {"ok": True, "sha256": sha[:12], "size": len(raw), "name": name}


_CORE_REL_DL = "https://github.com/Angize/TUNNEL-MANAGER-CORE/releases"
_CORE_TAG_RE = re.compile(r"^[A-Za-z0-9._+-]{1,64}$")
CORE_ARCHES = ("amd64", "arm64")
CORE_STAGE_DIR = os.path.join(CENTRAL_DIR, "core-stage")
CORE_STAGE_META = os.path.join(CENTRAL_DIR, "core-stage.meta.json")
_core_stage_lock = threading.Lock()


def _resolve_core_version(version):
    version = (version or "latest").strip() or "latest"
    if version != "latest":
        if version in (".", "..") or not _CORE_TAG_RE.match(version):
            raise ValueError("نسخهٔ هسته نامعتبر است — فقط حروف/عدد و کاراکترهای «._+-» مجاز است")
        return version
    for v in (api_core_versions({}).get("versions") or []):
        if v.get("id") and v["id"] != "custom":
            return v["id"]
    try:
        fetched = _fetch_core_versions()
    except Exception:
        fetched = []
    if fetched:
        with _core_versions_lock:
            _core_versions_cache["data"] = fetched
            _core_versions_cache["ts"] = time.time()
        for v in fetched:
            if v.get("id"):
                return v["id"]
    return "latest"


class _Cancelled(Exception):
    pass


def _read_body(r, clen, on_progress, should_abort):
    try:
        total = int(clen or 0)
    except (TypeError, ValueError):
        total = 0
    out, got = [], 0
    while True:
        if should_abort and should_abort():
            raise _Cancelled()
        chunk = r.read(262144)
        if not chunk:
            break
        out.append(chunk)
        got += len(chunk)
        if on_progress:
            on_progress(got, total)
    return b"".join(out)


def _dl_proxy():
    st = get_settings()
    if not st.get("dl_proxy_on"):
        return ""
    p = get_proxy(str(st.get("dl_proxy_id") or ""))
    return proxy_url(p) if p else ""


def _proxy_get(proxy, url, timeout, headers, hops=6, on_progress=None, should_abort=None):
    for _ in range(hops):
        u = urllib.parse.urlparse(url)
        if u.scheme != "https":
            raise OSError("through a proxy the panel fetches https only")
        host, port = u.hostname, u.port or 443
        sock, conn = _proxy_socket(proxy, host, port, timeout), None
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
            conn.sock, sock = sock, None
            conn.request("GET", (u.path or "/") + (("?" + u.query) if u.query else ""),
                         headers={**headers, "Connection": "close"})
            r = conn.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                loc = r.getheader("Location") or ""
                r.read()
                if not loc:
                    raise OSError("redirect without a location")
                url = urllib.parse.urljoin(url, loc)
                continue
            if r.status != 200:
                raise OSError(("HTTP %d %s" % (r.status, r.reason or "")).strip())
            return _read_body(r, r.getheader("Content-Length"), on_progress, should_abort)
        finally:
            for c in (sock, conn):
                if c is not None:
                    try:
                        c.close()
                    except Exception:
                        pass
    raise OSError("too many redirects")


def _gh_why(e):
    return (str(e).strip() or type(e).__name__)[:120]


def _gh_get(url, timeout, headers=None, on_progress=None, should_abort=None):
    hdrs = {"User-Agent": "tnl-central", **(headers or {})}
    proxy = _dl_proxy()
    if proxy:
        return _proxy_get(proxy, url, timeout, hdrs, on_progress=on_progress, should_abort=should_abort)
    req = urllib.request.Request(url, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return _read_body(r, r.headers.get("Content-Length"), on_progress, should_abort)


def _dl(url, timeout, on_progress=None, should_abort=None):
    return _gh_get(url, timeout, on_progress=on_progress, should_abort=should_abort)


def _release_asset_url(version, arch):
    if arch not in CORE_ARCHES:
        raise ValueError("معماریِ نامعتبر — فقط amd64 یا arm64 مجاز است")
    asset = f"tnl-core-linux-{arch}"
    return (f"{_CORE_REL_DL}/latest/download/{asset}" if version in ("latest", "")
            else f"{_CORE_REL_DL}/download/{version}/{asset}")


def _release_sha(version, arch, should_abort=None):
    sha = _dl(_release_asset_url(version, arch) + ".sha256", 30,
              should_abort=should_abort).decode().split()[0].strip().lower()
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise RuntimeError("checksum unavailable from the release")
    return sha


def _fetch_release(version, arch, on_progress=None, should_abort=None):
    base = _release_asset_url(version, arch)
    sha = _release_sha(version, arch, should_abort=should_abort)
    raw = _dl(base, 180, on_progress=on_progress, should_abort=should_abort)
    if hashlib.sha256(raw).hexdigest() != sha:
        raise RuntimeError("release checksum mismatch")
    return raw, sha


def _staged_holds(version, need_bytes):
    info = _staged_info()
    if not info:
        return False
    try:
        want = _resolve_core_version(version)
    except ValueError:
        return False
    if str(info.get("version") or "") != want:
        return False
    arches = [a for a in (info.get("arches") or []) if a in CORE_ARCHES]
    if not arches:
        return False
    if not need_bytes:
        return True
    if info.get("meta_only"):
        return False
    return all(os.path.isfile(os.path.join(CORE_STAGE_DIR, "tnl-core-%s" % a)) for a in arches)


def _staged_info():
    try:
        with open(CORE_STAGE_META) as f:
            info = json.load(f)
        return info if info.get("version") else None
    except Exception:
        return None


STAGE_SCALE = 1000000


def _stage_core(version, on_progress=None, should_abort=None):
    rel = _resolve_core_version(version)
    os.makedirs(CORE_STAGE_DIR, exist_ok=True)
    got, shas, sizes = [], {}, {}
    whole = len(CORE_ARCHES) * STAGE_SCALE
    with _core_stage_lock:
        for k, arch in enumerate(CORE_ARCHES):
            def part(sent, total, _k=k):
                if on_progress:
                    on_progress(_k * STAGE_SCALE + (int(STAGE_SCALE * sent / total) if total else 0), whole)
            try:
                raw, sha = _fetch_release(rel, arch, on_progress=part, should_abort=should_abort)
            except _Cancelled:
                raise
            except Exception:
                if arch == "amd64":
                    raise
                continue
            save_bytes(os.path.join(CORE_STAGE_DIR, f"tnl-core-{arch}"), raw)
            got.append(arch)
            shas[arch] = sha
            sizes[arch] = len(raw)
        save_json(CORE_STAGE_META, {"version": rel, "arches": got, "sha": shas, "size": sizes, "ts": int(time.time())})
    return {"version": rel, "arches": got, "missing": [a for a in CORE_ARCHES if a not in got]}


def _stage_core_meta(version):
    rel = _resolve_core_version(version)
    got = list(CORE_ARCHES)
    with _core_stage_lock:
        save_json(CORE_STAGE_META, {"version": rel, "arches": got, "sha": {}, "size": {},
                                    "ts": int(time.time()), "meta_only": True})
    return {"version": rel, "arches": got, "missing": []}


def _staged_sha(arch):
    sha = str(((_staged_info() or {}).get("sha") or {}).get(arch) or "").lower()
    return sha if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha) else ""


def _staged_bytes(arch):
    if arch not in CORE_ARCHES:
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
        save_bytes(p, raw)
        return raw, sha, ver
    with open(p, "rb") as f:
        raw = f.read()
    return raw, hashlib.sha256(raw).hexdigest(), ver


def _node_arch(node):
    a = str(node.get("arch") or "").strip()
    if a in CORE_ARCHES:
        return a
    a = str(_cached_ping(node.get("id") or "").get("arch") or "").strip()
    if a in CORE_ARCHES:
        return a
    a = str((node_call(node, "ping", "GET", timeout=10) or {}).get("arch") or "").strip()
    return a if a in CORE_ARCHES else ""


def _push_staged(node):
    arch = _node_arch(node)
    if not arch:
        return {"ok": False, "error": "معماریِ نود مشخص نشد — نود باید یک‌بار پاسخ بدهد تا باینریِ درست فرستاده شود"}
    if _delivery_mode("core") == "github":
        sha, ver, b64 = "", str((_staged_info() or {}).get("version") or ""), ""
        if not ver:
            return {"ok": False, "error": "هیچ نسخه‌ای انتخاب نشده — اول یک نسخه انتخاب کن"}
    else:
        b = _staged_bytes(arch)
        if not b:
            return {"ok": False, "error": "هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن"}
        raw, sha, ver = b
        b64 = base64.b64encode(raw).decode()
    sig = _sign_sha(sha) if sha else ""
    try:
        body = _core_install_body(node, b64, sha, ver, sig, arch)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    _ensure_update_key(node)
    r = node_call(node, "core-put", "POST", body, timeout=NODE_UPLOAD_TIMEOUT)
    if not r.get("ok") or r.get("code") == "same":
        return r
    ap = (_github_grant(ver, arch) if _delivery_mode("core") == "github"
          else {"sha256": sha, "version": ver, "sig": sig})
    return node_call(node, "core-apply", "POST", ap, timeout=NODE_UPLOAD_TIMEOUT)


def _push_staged_on_add(node):
    try:
        if _staged_info():
            _push_staged(node)
    except Exception:
        pass


def _node_tunnel(node, body):
    r = node_call(node, "tunnel", "POST", body, timeout=NODE_OP_TIMEOUT)
    err = str(r.get("error") or r.get("msg") or "")
    if not r.get("ok") and "core not installed" in err:
        pr = _push_staged(node)
        if not pr.get("ok"):
            r["error"] = f"هسته روی نودِ «{node.get('name', '?')}» نصب نیست و پنل هم چیزی برای پوش ندارد — اول یک نسخه دانلود کن"
            return r
        r = node_call(node, "tunnel", "POST", body, timeout=NODE_OP_TIMEOUT)
    return r


_stage_job = {"id": "", "version": "", "sent": 0, "total": 0, "done": True, "cancel": False,
              "err": "", "arches": [], "missing": []}
_stage_job_lock = threading.Lock()


def _stage_job_view():
    with _stage_job_lock:
        j = dict(_stage_job)
    pct = int(100 * j["sent"] / j["total"]) if j["total"] else 0
    return {"ok": True, "job": j["id"], "version": j["version"], "done": j["done"],
            "cancel": j["cancel"], "err": j["err"], "arches": j["arches"], "missing": j["missing"],
            "pct": max(0, min(100, pct))}


def _stage_run(version):
    def note(sent, total):
        with _stage_job_lock:
            _stage_job["sent"], _stage_job["total"] = sent, total

    def stop():
        with _stage_job_lock:
            return _stage_job["cancel"]

    try:
        info = _stage_core(version, on_progress=note, should_abort=stop)
        with _stage_job_lock:
            _stage_job.update(version=info["version"], arches=info["arches"],
                              missing=info["missing"], sent=1, total=1)
    except _Cancelled:
        with _stage_job_lock:
            _stage_job["err"] = "لغو شد"
    except Exception as e:
        with _stage_job_lock:
            _stage_job["err"] = _gh_why(e)
    finally:
        with _stage_job_lock:
            _stage_job["done"] = True


def api_core_stage(d):
    version = str((d or {}).get("version") or "latest").strip()
    if _delivery_mode("core") == "github":
        info = _stage_core_meta(version)
        return {"ok": True, "meta_only": True, "done": True, **info}
    with _stage_job_lock:
        if not _stage_job["done"]:
            raise ValueError("یک دانلود همین حالا در جریان است — صبر کن یا لغوش کن")
        _stage_job.update(id=secrets.token_hex(6), version=version, sent=0, total=0, done=False,
                          cancel=False, err="", arches=[], missing=[])
        jid = _stage_job["id"]
    threading.Thread(target=_stage_run, args=(version,), daemon=True).start()
    return {"ok": True, "meta_only": False, "done": False, "job": jid}


def api_core_stage_status(d):
    return _stage_job_view()


def api_core_stage_cancel(d):
    with _stage_job_lock:
        if _stage_job["done"]:
            return {"ok": True, "done": True}
        _stage_job["cancel"] = True
    return {"ok": True, "done": False}


def api_fleet(d):
    q = _list_query(d)
    nodes = {n["id"]: n for n in load_nodes()}
    kind = (d or {}).get("kind")
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
                 or q in str(L.get("name", "")).lower()
                 or q in L.get("type", "").lower() or q in str(L.get("tunnel_id", "")).lower()]
    total = len(links)
    page = links
    need = {L[k] for L in page for k in ("a_node", "b_node")}
    _ensure_cached([nodes[i] for i in need if i in nodes])
    with _tf_lock:
        tfl = {}
        for L in page:
            side = "b" if L.get("view_side") == "b" else "a"
            nid = L["b_node"] if side == "b" else L["a_node"]
            s = (_tf.get(nid) or {}).get("if", {}).get(L["name"])
            if s:
                tfl[L["id"]] = {"rx_bps": s["rx_bps"], "tx_bps": s["tx_bps"],
                                "rx_total": s["crx"], "tx_total": s["ctx"]}
    out = []
    for L in page:
        la, lb = _cached_list(L["a_node"]), _cached_list(L["b_node"])
        ah = (la.get("health") or {}).get(L["name"]) if la.get("configs") is not None else None
        bh = (lb.get("health") or {}).get(L["name"]) if lb.get("configs") is not None else None
        pa, pb = _cached_ping(L["a_node"]), _cached_ping(L["b_node"])
        a_ips, b_ips = _flat_ips(pa), _flat_ips(pb)
        side = "b" if L.get("view_side") == "b" else "a"
        pub = {k: v for k, v in L.items() if k != "psk"}
        rec = {**pub, "a_online": bool(la.get("ok")) or la.get("configs") is not None,
               "b_online": bool(lb.get("ok")) or lb.get("configs") is not None,
               "a_health": ah, "b_health": bh, "a_ips": a_ips, "b_ips": b_ips,
               "view_side": side, "view_name": (L["b_name"] if side == "b" else L["a_name"]),
               "drift": link_drift(L["id"]), "rb": rb_last(L["id"]), "tag": int(L.get("tag") or 0),
               **tfl.get(L["id"], {})}
        if L.get("type") == "core":
            _ct = [t for t in ((L["a_name"], la.get("ct") or {}), (L["b_name"], lb.get("ct") or {}))
                   if t[1].get("max")]
            if _ct:
                _nm, _w = max(_ct, key=lambda t: t[1]["count"] / float(t[1]["max"]))
                rec["ct"] = {"count": int(_w["count"]), "max": int(_w["max"]),
                             "pct": int(round(100.0 * _w["count"] / _w["max"])), "node": _nm}
            _cl = lb if (L.get("server_side") != "b") else la
            _sp = (_cl.get("sports") or {}).get(L["name"])
            if _sp:
                rec["sport_live"] = int(_sp)
            _srv = la if (L.get("server_side") != "b") else lb
            _rc = (_cl.get("rots") or {}).get(L["name"]) or {}
            _rs = (_srv.get("rots") or {}).get(L["name"]) or {}
            if _rc or _rs:
                rec["rot_live"] = {"cli": int((_rc.get("sport") or 0)), "srv": int((_rs.get("sport") or 0)),
                                   "dport": int(_rc.get("dport") or 0),
                                   "dports": int(_rc.get("dports") or 0),
                                   "every": int((_rc or _rs).get("every") or 0),
                                   "lo": int((_rc or _rs).get("lo") or 0),
                                   "hi": int((_rc or _rs).get("hi") or 0),
                                   "drawn": int((_rc or _rs).get("drawn") or 0)}
        if L.get("type") == "core" and L.get("ip_rotate"):
            srvA = (L.get("server_side") != "b")
            cl = lb if srvA else la
            pd = (cl.get("pools") or {}).get(L["name"]) or {}
            dact = str(pd.get("dst") or "").split(":")[0]
            sact = str(pd.get("src") or "").split(":")[0]
            a_act, b_act = (dact, sact) if srvA else (sact, dact)
            rec["a_ip_rot"] = len([x for x in (L.get("a_ip_pool") or []) if x]) >= 2
            rec["b_ip_rot"] = len([x for x in (L.get("b_ip_pool") or []) if x]) >= 2
            if a_act:
                rec["a_ip_active"] = a_act
            if b_act:
                rec["b_ip_active"] = b_act
        out.append(rec)
    return {"links": out, "total": total}


def api_link_view(d):
    _require(d, ["id"])
    with _reg_lock:
        links = load_links()
        side = None
        for x in links:
            if x["id"] == d["id"]:
                side = "a" if x.get("view_side") == "b" else "b"
                x["view_side"] = side
                break
        if side is None:
            raise ValueError("تونل پیدا نشد")
        save_json(LINKS_FILE, links)
    return {"ok": True, "view_side": side}


def api_traffic_reset(d):
    d = d or {}
    if d.get("id"):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)
        if not L:
            raise ValueError("تونل پیدا نشد")
        _tf_reset(L["a_node"], [L["name"]])
        _tf_reset(L["b_node"], [L["name"]])
        return {"ok": True}
    if d.get("node"):
        n = get_node(d["node"])
        if not n:
            raise ValueError("نود پیدا نشد")
        _tf_reset(n["id"], ["pf:" + _pf_name(d["name"])] if d.get("name") else ["_node"])
        return {"ok": True}
    raise ValueError("شناسهٔ تونل یا نود فرستاده نشد")


def _link_nodes(d):
    L = next((x for x in load_links() if x.get("id") == (d or {}).get("id")), None)
    return (L["a_node"], L["b_node"]) if L else (None, None)


def _default_tunnel_port(ttype, tid):
    if ttype == "vxlan":
        return 4789
    return None


def _port_bindings(ttype, port, transport, server_side, tid, A, B, a_ip=None, b_ip=None, a_pool=None, b_pool=None):
    p = int(port or _default_tunnel_port(ttype, tid) or 0)
    if not p:
        return []
    if ttype == "core":
        server_a = (server_side or "a") == "a"
        srv = A if server_a else B
        srv_ip = a_ip if server_a else b_ip
        srv_pool = (a_pool if server_a else b_pool) or []
        t = (transport or "udp").lower()
        if t == "raw":
            return []
        if t == "dns":
            return [(srv, srv_ip, 53, "udp")]
        proto = "tcp" if t in ("tcp", "ws") else "udp"
        pool_ips = [ip for ip in srv_pool if ip] if t in ("udp", "tcp") else []
        if pool_ips:
            return [(srv, ip, p, proto) for ip in pool_ips]
        return [(srv, srv_ip, p, proto)]
    if ttype in ("fou", "l2tpv3", "vxlan"):
        return [(A, None, p, "udp"), (B, None, p, "udp")]
    return []


def _guard_port_conflicts(bindings, exclude=frozenset()):
    for node, ip, port, proto in bindings:
        if (node["id"], ip or "", int(port), proto) in exclude:
            continue
        r = node_call(node, "portcheck", "POST", {"port": port, "proto": proto, "ip": ip or ""}, timeout=10)
        if not r.get("ok"):
            continue
        if r.get("busy"):
            who = str(r.get("who") or "").strip()
            tail = f" — {who}" if who else ""
            onip = f" (روی {ip})" if ip else ""
            raise ValueError(f"پورتِ {port}/{proto.upper()} روی نودِ «{node['name']}»{onip} اشغال است{tail}؛ یک پورتِ دیگر انتخاب کن")


def _core_bind_keys(bindings):
    return {(n["id"], ip or "", int(p), pr) for n, ip, p, pr in bindings}




def _peer_addrs(rec, side):
    out = []
    ip = rec.get(side + "_ip")
    if ip:
        out.append(ip)
    if rec.get("ip_rotate"):
        for x in (rec.get(side + "_ip_pool") or []):
            if x and x not in out:
                out.append(x)
    return out



def _core_l4_conflict(new_binds, exclude_id=None):
    keys = _core_bind_keys(new_binds)
    if not keys:
        return None
    for L in load_links():
        if L.get("type") != "core" or L.get("id") == exclude_id:
            continue
        LA, LB = get_node(L.get("a_node")), get_node(L.get("b_node"))
        if not LA or not LB:
            continue
        eb = _port_bindings("core", L.get("port"), L.get("transport"), L.get("server_side"),
                            L.get("tunnel_id"), LA, LB, L.get("a_ip"), L.get("b_ip"),
                            L.get("a_ip_pool"), L.get("b_ip_pool"))
        if keys & _core_bind_keys(eb):
            return L
    return None


def _dns_fields(d, transport, cipher, cur=None):
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
        if rs.count(":") == 1:
            host, _, port = rs.partition(":")
            if not (port.isdigit() and 1 <= int(port) <= 65535):
                raise ValueError("پورتِ resolverِ dns نامعتبر است — باید 1 تا 65535 باشد: " + rs)
        else:
            host = rs
        if not is_ipv4(host):
            raise ValueError("آدرسِ resolverِ dns باید IPv4 باشد (به‌صورتِ ip یا ip:port): " + rs)
        resolvers.append(rs)
    if not resolvers:
        raise ValueError("حاملِ dns حداقل به یک resolverِ معتبر (IPv4) نیاز دارد")
    out["dns_resolvers"] = resolvers
    return out



def _workers_field(d, transport, fec_on, cur=None):
    cur = cur or {}
    out, asked_any = {}, False
    for key in ("a_workers", "b_workers"):
        asked = key in d
        asked_any = asked_any or asked
        if asked:
            try:
                n = int(d[key] or 1)
            except (TypeError, ValueError):
                raise ValueError("تعدادِ صفِ موازی نامعتبر است")
            if not 1 <= n <= CORE_MAX_WORKERS:
                raise ValueError(f"تعدادِ صفِ موازی باید بینِ 1 تا {CORE_MAX_WORKERS} باشد")
        else:
            n = int(cur.get(key) or 1)
        if n > 1:
            out[key] = n
    if not out:
        return {}
    if transport not in QUEUEING_TRANSPORTS or fec_on:
        if asked_any:
            raise ValueError("«صف‌های موازی» فقط برای حاملِ raw یا udp و بدونِ FEC است؛ "
                             "جای دیگر هستهٔ اختصاصی همان یک صف را برمی‌دارد")
        return {}
    return out


def _link_workers(L, key):
    return max(1, min(CORE_MAX_WORKERS, int(L.get(key) or 1)))


def _fec_fields(d, transport, cur=None):
    out = {}
    if transport not in DATAGRAM_TRANSPORTS:
        return out
    cur = cur or {}
    fec = bool(d.get("fec")) if ("fec" in d) else bool(cur.get("fec"))
    if not fec:
        return out
    out["fec"] = True
    fd = int(d.get("fec_data") or cur.get("fec_data") or 16)
    fp = int(d.get("fec_parity") or cur.get("fec_parity") or 4)
    if fd < 1 or fp < 1 or fd + fp > 255:
        raise ValueError("مقادیرِ FEC نامعتبر است (داده و پریتی هر کدام ≥1، مجموع ≤255)")
    if fd > 64:
        raise ValueError("دادهٔ FEC حداکثر 64 است — بالاتر از آن فریمِ بازسازی‌شده بیرونِ پنجرهٔ ضدِ تکرارِ گیرنده می‌افتد و دور ریخته می‌شود (یعنی پهنای‌باندِ FEC مصرف می‌شود و هیچ ترمیمی نمی‌کند)")
    out["fec_data"] = fd
    out["fec_parity"] = fp
    return out


def _desync_fields(d, transport, cur=None, is_http=False):
    out = {}
    if transport not in DESYNC_TRANSPORTS:
        return out
    if transport == "ws" and is_http:
        return out
    cur = cur or {}
    on = bool(d.get("fake_desync")) if ("fake_desync" in d) else bool(cur.get("fake_desync"))
    if not on:
        return out
    out["fake_desync"] = True
    ttl = int(d.get("fake_ttl") or cur.get("fake_ttl") or 4)
    if ttl < 1 or ttl > 255:
        raise ValueError("TTLِ طعمه باید بین 1 تا 255 باشد")
    if transport in DESYNC_INJECT_TRANSPORTS:
        ttl = min(ttl, DESYNC_INJECT_TTL_MAX)
    out["fake_ttl"] = ttl
    cnt = int(d.get("fake_count") or cur.get("fake_count") or 2)
    if cnt < 1 or cnt > 64:
        raise ValueError("تعدادِ طعمه باید بین 1 تا 64 باشد")
    out["fake_count"] = cnt
    mode = str(d.get("fake_mode") or cur.get("fake_mode") or "ttl").strip().lower()
    if mode not in ("ttl", "badsum", "both"):
        raise ValueError("حالتِ طعمه نامعتبر است")
    if mode == "both" and cnt == 1:
        raise ValueError("حالتِ «هر دو» به حداقل 2 طعمه نیاز دارد (یک طعمه نمی‌تواند هم‌زمان TTL‌پایین و چک‌سام‌خراب باشد)")
    out["fake_mode"] = mode
    return out


_ECH_RE = re.compile(r'ech="?([A-Za-z0-9+/=]+)"?')
_GENERIC_RE = re.compile(r'\\#\s+\d+\s+([0-9A-Fa-f][0-9A-Fa-f\s]+)')


def _ech_from_svcb(raw):
    try:
        i = 2
        while i < len(raw) and raw[i] != 0:
            i += 1 + raw[i]
        i += 1
        while i + 4 <= len(raw):
            key = int.from_bytes(raw[i:i + 2], "big"); i += 2
            ln = int.from_bytes(raw[i:i + 2], "big"); i += 2
            val = raw[i:i + ln]; i += ln
            if key == 5:
                return base64.b64encode(val).decode()
    except Exception:
        pass
    return ""


def _ech_from_text(s):
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
    for ans in data.get("Answer", []):
        if ans.get("type") in (65, "65", "HTTPS"):
            v = _ech_from_text(str(ans.get("data", "")))
            if v:
                return v
    return ""


def _fetch_ech(host, proxy=""):
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

    def via_doh_proxy(dhost, dpath):
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
            tls = ssl.create_default_context().wrap_socket(sock, server_hostname=dhost)
            sock = None
            conn = http.client.HTTPConnection(dhost, 443, timeout=7)
            conn.sock = tls
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
    if proxy:
        tasks = [lambda: via_doh_proxy("cloudflare-dns.com", "/dns-query"),
                 lambda: via_doh_proxy("dns.google", "/resolve")]
    else:
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
        ex.shutdown(wait=False)
        if found:
            return found
        if attempt < 2:
            time.sleep(0.8)
    return ""


def _fetch_ech_map(hosts, proxy=""):
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
    return str(src.get("ech_proxy_url") or "").strip() if src.get("ech_proxy") else ""


def _ech_proxy_fields(d, cur, out):
    on = bool(d.get("ech_proxy") if "ech_proxy" in d else cur.get("ech_proxy"))
    url = valid_proxy((d.get("ech_proxy_url") if "ech_proxy_url" in d else cur.get("ech_proxy_url")) or "")
    if on:
        out["ech_proxy"] = True
        if url:
            out["ech_proxy_url"] = url
    return url if on else ""


def _sni_split_fields(d, cur):
    on = d.get("sni_split") if ("sni_split" in d) else cur.get("sni_split")
    if not on:
        return {}
    sp = int((d.get("split_pos") if "split_pos" in d else cur.get("split_pos")) or 0)
    if sp < 0 or sp > 1400:
        raise ValueError("split_pos باید بین 0 تا 1400 باشد (0 = خودکار، وسطِ دامنه)")
    out = {"sni_split": True}
    if sp:
        out["split_pos"] = sp
    mode = str((d.get("sni_mode") if "sni_mode" in d else cur.get("sni_mode")) or "split").strip().lower()
    if mode not in ("split", "disorder", "fake"):
        raise ValueError("حالتِ SNI نامعتبر است (split / disorder / fake)")
    if mode != "split":
        out["sni_mode"] = mode
    if mode == "disorder":
        st = int((d.get("split_ttl") if "split_ttl" in d else cur.get("split_ttl")) or 0)
        if st < 0 or st > SPLIT_TTL_MAX:
            raise ValueError("split_ttl باید بین 0 تا " + str(SPLIT_TTL_MAX)
                             + " باشد (0 = پیش‌فرض)؛ بالاتر از آن سگمنتِ سرْ به سرور می‌رسد و disorder بی‌اثر می‌شود")
        if st:
            out["split_ttl"] = st
    return out


_EDGE_PLAIN_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)
_EDGE_TLS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)


def _edge_port_ok(port, tls):
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
        "پورتِ %d قبول نیست. (یا wss را روشن کن و 443 بگذار.)" % (lst, port))


def _cdn_shape_fields(d, cur, cdn):
    if cdn not in ("http", "grpc"):
        return {}
    cur = cur or {}
    out = {}
    for k, (lo, hi, dflt) in HTTP_SHAPE.items():
        if cdn == "grpc" and k not in HTTP_SHAPE_GRPC:
            continue
        raw = d.get(k) if k in d else cur.get(k)
        if raw in (None, ""):
            out[k] = dflt
            continue
        try:
            v = int(raw)
        except (TypeError, ValueError):
            raise ValueError("مقدارِ «%s» باید عدد باشد" % k)
        if v < lo or v > hi:
            raise ValueError("«%s» باید بین %d و %d باشد" % (k, lo, hi))
        out[k] = v
    return out


def _ws_fields(d, transport, cur=None):
    out = {}
    if transport != "ws":
        return out
    cur = cur or {}
    if (d.get("ws_pool") if "ws_pool" in d else cur.get("ws_pool")):
        return _ws_pool_fields(d, cur)
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
    edge = str((d["edge_ip"] if "edge_ip" in d else cur.get("edge_ip")) or "").strip()
    if edge:
        eh = edge.rpartition(":")[0] or edge
        if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", eh):
            raise ValueError("آدرسِ لبهٔ CDN (edge_ip) نامعتبر است")
        ep = edge.rpartition(":")[2] if ":" in edge else ""
        if ep.isdigit():
            _edge_port_ok(int(ep), bool(out.get("ws_tls")))
        out["edge_ip"] = edge
    ech = d.get("ech") if ("ech" in d) else cur.get("ech")
    if ech:
        if not out.get("ws_tls"):
            raise ValueError("ECH به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن")
        cfg = _fetch_ech(host, _ech_proxy_fields(d, cur, out))
        if not cfg:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد)" % host)
        out["ech"] = True
        out["ws_ech"] = cfg
    cdn = str((d.get("cdn_carrier") if "cdn_carrier" in d else cur.get("cdn_carrier")) or "ws").strip().lower()
    if cdn not in ("ws", "http", "grpc"):
        raise ValueError("حاملِ CDN نامعتبر است")
    xh = cdn != "ws"
    if bool(xh):
        if cdn == "grpc" and not out.get("ws_tls"):
            raise ValueError("حاملِ grpc به wss نیاز دارد (برای HTTP/2 به لبه) — اول wss را روشن کن")
        out["cdn_carrier"] = cdn
        out.update(_cdn_shape_fields(d, cur, cdn))
    ss = _sni_split_fields(d, cur)
    if ss:
        if not out.get("ws_tls"):
            raise ValueError("تقسیمِ SNI به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن")
        out.update(ss)
    return out


_IP4_RE = r"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$"
_DOMAIN_RE = r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"


def _ws_rotate_default(d, cur):
    if "ws_rotate_secs" in d and d.get("ws_rotate_secs") is not None:
        return d["ws_rotate_secs"]
    v = cur.get("ws_rotate_secs")
    return 600 if v is None else v


def _ws_pool_fields(d, cur=None):
    cur = cur or {}

    def _list(key):
        return (d[key] if key in d else cur.get(key)) or []

    def _ips(key):
        seen, res = set(), []
        for x in _list(key):
            x = str(x).strip()
            if not x:
                continue
            h = x.rpartition(":")[0] if ":" in x else x
            p = x.rpartition(":")[2] if ":" in x else "443"
            if not re.match(_IP4_RE, h) or not (p.isdigit() and 1 <= int(p) <= 65535):
                raise ValueError("آی‌پیِ لبهٔ نامعتبر (باید IPv4:port باشد؛ دامنه مجاز نیست — استخر مستقیم به آی‌پی وصل می‌شود): %s" % x)
            _edge_port_ok(int(p), True)
            v = "%s:%s" % (h, p)
            if v in seen:
                continue
            seen.add(v)
            res.append(v)
        return res

    def _hosts(key):
        seen, res = set(), []
        for x in _list(key):
            if isinstance(x, dict):
                x = x.get("host", "")
            x = str(x).strip().lower()
            if not x or x in seen:
                continue
            if not re.match(_DOMAIN_RE, x):
                raise ValueError("دامنهٔ (SNI) نامعتبر (باید یک دامنهٔ معتبر باشد): %s" % x)
            seen.add(x)
            res.append(x)
        return res

    clean_ips, clean_hosts = _ips("ws_edge_ips"), _hosts("ws_edge_snis")
    if len(clean_ips) < 2:
        raise ValueError("استخرِ لبه به حداقل 2 آی‌پی نیاز دارد تا بچرخد")
    if not clean_hosts:
        raise ValueError("استخر به حداقل یک دامنهٔ (SNI) نیاز دارد")
    if len(clean_ips) > 64 or len(clean_hosts) > 64:
        raise ValueError("استخر خیلی بزرگ است (حداکثر 64)")
    path = str((d["ws_path"] if "ws_path" in d else cur.get("ws_path")) or "").strip() or "/"
    if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", path):
        raise ValueError("مسیر (path) نامعتبر است")
    ech_on = bool(d.get("ech") if "ech" in d else cur.get("ech"))
    _epx_store = {}
    _epx = _ech_proxy_fields(d, cur, _epx_store) if ech_on else ""
    ech_map = _fetch_ech_map(clean_hosts, _epx) if ech_on else {}
    snis = []
    for h in clean_hosts:
        ec = ech_map.get(h, "") if ech_on else ""
        if ech_on and not ec:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد). استخر با ECH روشن ساخته نمی‌شود." % h)
        snis.append({"host": h, "ech": ec, "path": path})
    res = {
        "ws_pool": True,
        "ws_tls": True,
        "ech": ech_on,
        "cdn_carrier": str((d.get("cdn_carrier") if "cdn_carrier" in d else cur.get("cdn_carrier")) or "ws"),
        "ws_edge_ips": clean_ips,
        "ws_edge_snis": snis,
        "ws_rotate_secs": max(0, min(28800, int(_ws_rotate_default(d, cur)))),
        "ws_path": path,
    }
    res.update(_cdn_shape_fields(d, cur, res["cdn_carrier"]))
    res.update(_sni_split_fields(d, cur))
    res.update(_epx_store)
    return res


def api_create_tunnel(d):
    d = d or {}
    A, B = get_node(d.get("a_node")), get_node(d.get("b_node"))
    ttype = str(d.get("type") or "")

    def build(h):
        with _PairLock(d.get("a_node"), d.get("b_node")):
            return _create_tunnel_impl(d, h)

    return act_start("new:" + secrets.token_hex(4), build,
                     target="%s ↔ %s" % ((A or {}).get("name", "?"), (B or {}).get("name", "?")),
                     page="core" if ttype == "core" else "tunnels",
                     ttype=str(d.get("transport") or ttype))


RAW_DPORTS_MAX = 16
RAW_BAND_MIN_LO = 1024
RAW_BAND_MIN_SPAN = 100
RAW_SPROT_MAX = 60
PORT_TRIES_MAX = 60


def _core_extra(d, cur, a_ip, b_ip, a_ips, b_ips):
    ce = {}
    cipher = str(d.get("cipher") or cur.get("cipher") or "auto").strip().lower()
    if cipher not in CORE_CIPHERS:
        raise ValueError("روشِ رمزنگاری نامعتبر است")
    ce["cipher"] = cipher
    if cipher != "none":
        ce["psk"] = cur.get("psk") or secrets.token_hex(32)
    transport = str(d.get("transport") or cur.get("transport") or "udp").strip().lower()
    if transport not in CORE_TRANSPORTS:
        raise ValueError("حاملِ اتصال نامعتبر است")
    ce["transport"] = transport
    if transport == "raw":
        if cipher == "none":
            raise ValueError("حاملِ raw به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        profile = str(d.get("raw_profile") or cur.get("raw_profile") or "bare").strip().lower()
        if profile not in CORE_RAW_PROFILES:
            raise ValueError("پروفایلِ raw نامعتبر است")
        ce["raw_profile"] = profile
        try:
            _rp = int((d["raw_proto"] if "raw_proto" in d else cur.get("raw_proto")) or 0)
        except (TypeError, ValueError):
            _rp = 0
        if profile == "bare" and _rp:
            _check_raw_proto(_rp)
            ce["raw_proto"] = _rp
        try:
            _rport = int((d["raw_port"] if "raw_port" in d else cur.get("raw_port")) or 0)
        except (TypeError, ValueError):
            _rport = 0
        if _rport and profile in ("udp", "tcp"):
            if not 1 <= _rport <= 65535:
                raise ValueError("پورتِ حامل باید بینِ 1 تا 65535 باشد")
            ce["raw_port"] = _rport
        elif _rport and "raw_port" in d:
            raise ValueError(f"«پورتِ حامل» فقط برای پروفایلِ udp و tcp است؛ «{profile}» هیچ پورتی جعل نمی‌کند")
        _srand = bool(d["raw_sport_random"] if "raw_sport_random" in d else cur.get("raw_sport_random"))
        try:
            _rsport = int((d["raw_sport"] if "raw_sport" in d else cur.get("raw_sport")) or 0)
        except (TypeError, ValueError):
            _rsport = 0
        if _srand and _rsport and "raw_sport" in d and "raw_sport_random" in d:
            raise ValueError("«پورتِ مبدأ» یا ثابت است یا چرخان — هر دو با هم نمی‌شود")
        if profile in ("udp", "tcp"):
            if _srand:
                ce["raw_sport_random"] = True
            elif _rsport:
                if not 1 <= _rsport <= 65535:
                    raise ValueError("پورتِ مبدأ باید بینِ 1 تا 65535 باشد")
                ce["raw_sport"] = _rsport
        else:
            if _srand and "raw_sport_random" in d:
                raise ValueError(f"«پورتِ مبدأِ چرخان» فقط برای پروفایلِ udp و tcp است؛ «{profile}» هیچ پورتی جعل نمی‌کند")
            if _rsport and "raw_sport" in d:
                raise ValueError(f"«پورتِ مبدأ» فقط برای پروفایلِ udp و tcp است؛ «{profile}» هیچ پورتی جعل نمی‌کند")
        try:
            _rrot = int((d["raw_sport_rotate"] if "raw_sport_rotate" in d else cur.get("raw_sport_rotate")) or 0)
        except (TypeError, ValueError):
            _rrot = 0
        if profile in ("udp", "tcp"):
            if _rrot:
                if not 1 <= _rrot <= RAW_SPROT_MAX:
                    raise ValueError(f"«چرخشِ پورتِ مبدأ» باید بینِ 1 تا {RAW_SPROT_MAX} باشد (هر چند پکت یک پورتِ تازه؛ زیرِ سقفِ per-tuple میدل‌باکس)")
                if _srand or _rsport:
                    raise ValueError("«چرخشِ پورتِ مبدأ» پورت را مدام عوض می‌کند، پس با «پورتِ مبدأِ ثابت» یا «رندومِ واکنشی» جمع نمی‌شود")
                ce["raw_sport_rotate"] = _rrot
                try:
                    _rdp = int((d["raw_dports"] if "raw_dports" in d else cur.get("raw_dports")) or 0)
                except (TypeError, ValueError):
                    _rdp = 0
                if _rdp:
                    if not 1 <= _rdp <= RAW_DPORTS_MAX:
                        raise ValueError(f"«چند پورتِ مقصد» باید بینِ 1 تا {RAW_DPORTS_MAX} باشد")
                    ce["raw_dports"] = _rdp
            elif int((d.get("raw_dports") or 0)) and "raw_dports" in d:
                raise ValueError("«چند پورتِ مقصد» بدونِ «چرخشِ پورتِ مبدأ» بی‌اثر است — با مبدأِ ثابت هر پکت باز هم در همان سطلِ میدل‌باکس می‌افتد. اول چرخش را روشن کن")
            if _rrot or _srand:
                try:
                    _blo = int((d["raw_sport_lo"] if "raw_sport_lo" in d else cur.get("raw_sport_lo")) or 0)
                    _bhi = int((d["raw_sport_hi"] if "raw_sport_hi" in d else cur.get("raw_sport_hi")) or 0)
                except (TypeError, ValueError):
                    _blo = _bhi = 0
                if _blo or _bhi:
                    if not (RAW_BAND_MIN_LO <= _blo <= _bhi <= 65535):
                        raise ValueError(f"«بازهٔ چرخش» باید دو پورتِ بینِ {RAW_BAND_MIN_LO} تا 65535 باشد و ابتدایش از انتهایش کوچک‌تر — زیرِ {RAW_BAND_MIN_LO} پورتِ ممتاز است و حاملِ جعلی دلیلی برای ادعای آن ندارد")
                    if _bhi - _blo + 1 < RAW_BAND_MIN_SPAN:
                        raise ValueError(f"«بازهٔ چرخش» دستِ‌کم باید {RAW_BAND_MIN_SPAN} پورت پهنا داشته باشد؛ باریک‌تر از آن یعنی پورتِ ثابت با چند قدمِ اضافه — برای آن «پورتِ مبدأِ ثابت» هست")
                    ce["raw_sport_lo"], ce["raw_sport_hi"] = _blo, _bhi
            elif (d.get("raw_sport_lo") or d.get("raw_sport_hi")) and ("raw_sport_lo" in d or "raw_sport_hi" in d):
                raise ValueError("«بازهٔ چرخش» فقط وقتی معنا دارد که پورتِ مبدأ در حرکت باشد — «چرخشِ پورتِ مبدأ» یا «رندومِ واکنشی» را روشن کن")
        elif _rrot and "raw_sport_rotate" in d:
            raise ValueError(f"«چرخشِ پورتِ مبدأ» فقط برای پروفایلِ udp و tcp است؛ «{profile}» هیچ پورتی جعل نمی‌کند")
        _ctb = bool(d["conntrack_bypass"]) if "conntrack_bypass" in d else bool(cur.get("conntrack_bypass"))
        if _ctb:
            if profile not in ("udp", "tcp"):
                raise ValueError(f"«رد شدن از conntrack» فقط برای پروفایلِ udp و tcp معنا دارد؛ «{profile}» به‌ازای هر پکت جریانِ تازه نمی‌سازد")
            ce["conntrack_bypass"] = True
    if transport == "dns":
        ce.update(_dns_fields(d, transport, cipher, cur))
    if transport == "ws":
        ce.update(_ws_fields(d, transport, cur))
    ce.update(_fec_fields(d, transport, cur))
    ce.update(_workers_field(d, transport, bool(ce.get("fec")), cur))
    ce.update(_desync_fields(d, transport, cur, ce.get("cdn_carrier", "ws") != "ws"))
    if (bool(d.get("obfs")) if "obfs" in d else bool(cur.get("obfs"))):
        if cipher == "none":
            raise ValueError("استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
        if transport == "dns":
            raise ValueError("استتار روی حاملِ dns پشتیبانی نمی‌شود (کریرِ DNS اصلاً فریمِ obfs ندارد) — استتار را خاموش کن")
        ce["obfs"] = True
    cover = (bool(d.get("cover")) if "cover" in d else bool(cur.get("cover"))) and transport == "tcp"
    if cover and cipher == "none":
        raise ValueError("پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
    cover_sni = str((d["cover_sni"] if "cover_sni" in d else cur.get("cover_sni")) or "").strip()
    if cover_sni and not re.match(r"^[A-Za-z0-9.-]{1,253}$", cover_sni):
        raise ValueError("دامنهٔ نمایشی (SNI) نامعتبر است")
    if cover and not cover_sni:
        raise ValueError("برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی")
    if cover:
        ce["cover"] = True
        ce["cover_sni"] = cover_sni
    try:
        _ptries = int((d["port_tries"] if "port_tries" in d else cur.get("port_tries")) or 0)
    except (TypeError, ValueError):
        _ptries = 0
    if _ptries:
        if not 1 <= _ptries <= PORT_TRIES_MAX:
            raise ValueError(f"تعدادِ قرعهٔ پورتِ مبدأ باید بینِ 1 تا {PORT_TRIES_MAX} باشد")
        ce["port_tries"] = _ptries
    if (bool(d.get("gso")) if "gso" in d else bool(cur.get("gso"))):
        ce["gso"] = True
    if "ip_rotate" in d:
        if transport in DIRECT_TRANSPORTS and bool(d.get("ip_rotate")):
            ap = [s for s in (str(ip).strip() for ip in (d.get("a_ip_pool") or [])) if s in a_ips]
            bp = [s for s in (str(ip).strip() for ip in (d.get("b_ip_pool") or [])) if s in b_ips]
            if a_ip not in ap:
                ap = [a_ip] + ap
            if b_ip not in bp:
                bp = [b_ip] + bp
            if len(ap) >= 2 or len(bp) >= 2:
                ce["ip_rotate"] = True
                ce["a_ip_pool"], ce["b_ip_pool"] = ap, bp
                ce["rotate_secs"] = max(0, min(86400, int(d.get("rotate_secs") or 0)))
    elif cur.get("ip_rotate"):
        for _k in _ROTATION_KEYS:
            if cur.get(_k) is not None:
                ce[_k] = cur[_k]
    server_side = d.get("server_side") if d.get("server_side") in ("a", "b") else (cur.get("server_side") or "a")
    return ce, server_side


CREATE_STEPS = 4


def _create_tunnel_impl(d, h=None):
    act_step(h, "خواندنِ وضعیتِ دو نود", 0, CREATE_STEPS)
    _require(d, ["a_node", "b_node", "type"])
    A, B = get_node(d["a_node"]), get_node(d["b_node"])
    if not A or not B:
        raise ValueError("نود پیدا نشد")
    if A["id"] == B["id"]:
        raise ValueError("دو سرِ تونل باید دو نودِ متفاوت باشند")
    ttype = d["type"]
    if ttype not in TYPES:
        raise ValueError("نوعِ تونل نامعتبر است")
    if ttype == "core":
        _gate_ready(False)
    pa, pb = _ping_both(A, B)
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()
    if want_a and want_a not in a_ips:
        raise ValueError(f"آی‌پیِ «{want_a}» روی نودِ «{A['name']}» نیست")
    if want_b and want_b not in b_ips:
        raise ValueError(f"آی‌پیِ «{want_b}» روی نودِ «{B['name']}» نیست")
    a_ip = want_a or (a_ips[0] if a_ips else None)
    b_ip = want_b or (b_ips[0] if b_ips else None)
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("آی‌پیِ نودها خوانده نشد")
    if a_ip == b_ip:
        raise ValueError("آی‌پیِ دو سرِ تونل یکی است؛ برای هر طرف یک آی‌پیِ متفاوت انتخاب کن")
    _guard_dup_pair(A, B, a_ip, b_ip, ttype)
    la = node_call(A, "list", "GET", timeout=30)
    lb = node_call(B, "list", "GET", timeout=30)
    if la.get("configs") is None or lb.get("configs") is None:
        raise ValueError("فهرستِ تونل‌های یک نود خوانده نشد (مشغول یا قطع) — برای جلوگیری از تداخلِ شناسه متوقف شد")
    used = {int(x["tunnel_id"]) for x in load_links() if str(x.get("tunnel_id", "")).isdigit()}
    for L in (la, lb):
        for c in L.get("configs", []):
            try:
                used.add(int(c.get("id")))
            except Exception:
                pass
    _cap = (TID_MAX if ttype == "sit" or str(d.get("subnet") or "").strip()
            else subnet_cap(d.get("subnet_base")))
    explicit = int(d.get("id") or 0)
    if explicit and not TID_MIN <= explicit <= _cap:
        raise ValueError(f"شناسهٔ تونل خارج از محدوده است ({TID_MIN} تا {_cap})")
    if explicit and explicit in used:
        raise ValueError(f"شناسهٔ {explicit} از قبل روی این فلیت استفاده شده است")
    tid = explicit or next((i for i in range(TID_MIN, _cap + 1) if i not in used), 0)
    if not tid:
        raise ValueError(f"شناسهٔ آزادی در این بازه نمانده است ({_cap} تونل می‌گیرد)؛ "
                         f"بازهٔ بزرگ‌تری انتخاب کن یا سابنت را دستی بده")
    _cs = str(d.get("subnet") or "").strip()
    if _cs and "/" not in _cs:
        raise ValueError("سابنت باید پیشوند داشته باشد — مثلاً 192.168.9.0/24")
    subnet = norm_subnet(ttype, tid, d.get("subnet"), d.get("subnet_base"))
    name = tunnel_name(ttype, tid)
    _guard_subnet_overlap(A, B, subnet)
    _guard_addr_on_another_iface(pa, pb, A, B, subnet, {name})
    extra = {}
    if ttype in ("l2tpv3", "fou", "core"):
        port = int(d.get("port") or 0) or free_tunnel_port(A, B)
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (1 تا 65535)")
        extra["port"] = port
    if ttype == "vxlan":
        port = int(d.get("port") or 4789)
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (1 تا 65535)")
        extra["port"] = port
    if ttype == "ipsec":
        extra["psk"] = secrets.token_hex(32)
    server_side = None
    if ttype == "core":
        ce, server_side = _core_extra(d, {}, a_ip, b_ip, a_ips, b_ips)
        extra.update(ce)
    if ttype == "core":
        _clash = _core_l4_conflict(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")))
        if _clash:
            raise ValueError(f"همین آی‌پی و پورتِ سرور از قبل مالِ تونلِ «{_clash.get('name')}» است. پورتِ دیگری بگذار یا حاملِ دیگری انتخاب کن — روی یک آی‌پی، حاملِ متفاوت یا پورتِ متفاوت مجاز است.")
    _guard_port_conflicts(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")))
    node_extra = _node_extra(extra)
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name,
              "host": overlay_host(ttype, server_side, True), **node_extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name,
              "host": overlay_host(ttype, server_side, False), **node_extra}
    if ttype == "core":
        a_body["role"] = "server" if server_side == "a" else "client"
        b_body["role"] = "server" if server_side == "b" else "client"
        _core_rotation_bodies(extra, a_body, b_body)
        _core_workers_bodies(extra, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
    _apply_probe_tuning(a_body, b_body)
    act_step(h, "ساخت روی نودِ «%s»" % A["name"], 1, CREATE_STEPS)
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')}")
    try:
        act_step(h, "ساخت روی نودِ «%s»" % B["name"], 2, CREATE_STEPS, more=False)
    except ActCancelled:
        node_call(A, "delete", "POST", {"name": name})
        raise
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        rr = node_call(A, "delete", "POST", {"name": name})
        warn = "" if rr.get("ok") else f" — هشدار: '{name}' روی {A['name']} پاک نشد، دستی تمیزش کن"
        raise ValueError(f"نودِ «{B['name']}»: {rb.get('error') or rb.get('msg')} (تغییرات روی {A['name']} برگردانده شد){warn}")
    act_step(h, "ثبتِ تونل", 3, CREATE_STEPS, stop=False)
    try:
        with _reg_lock:
            links = load_links()
            links.append({"id": secrets.token_hex(6), "name": name, "type": ttype, "subnet": subnet,
                          "tunnel_id": tid, "a_node": A["id"], "a_name": A["name"], "a_ip": a_ip,
                          "b_node": B["id"], "b_name": B["name"], "b_ip": b_ip, "created": int(time.time()),
                          **extra, **({"server_side": server_side} if ttype == "core" else {})})
            save_json(LINKS_FILE, links)
        _pending_remove(A["id"], name)
        _pending_remove(B["id"], name)
    except Exception as e:
        da = node_call(A, "delete", "POST", {"name": name})
        db = node_call(B, "delete", "POST", {"name": name})
        stuck = "، ".join(N["name"] for N, r in ((A, da), (B, db)) if not r.get("ok"))
        warn = f" — هشدار: '{name}' روی {stuck} پاک نشد، دستی تمیزش کن" if stuck else ""
        raise ValueError(f"ذخیرهٔ رکوردِ لینک شکست خورد؛ تونل‌ها برچیده شدند{warn} ({str(e)[:80]})")
    _refresh_cache([A["id"], B["id"]])
    return {"ok": True, "name": name, "a_tunnel_ip": ra.get("tunnel_ip"), "b_tunnel_ip": rb.get("tunnel_ip")}


def api_delete_link(d):
    return act_link(d, lambda h: _delete_link_impl(d, h))


DELETE_STEPS = 3


def _delete_link_impl(d, h=None):
    act_step(h, "بررسیِ دو سر", 0, DELETE_STEPS)
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")
    with _PairLock(L["a_node"], L["b_node"]):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)
        if not L:
            return {"ok": True}
        force = bool(d.get("force"))
        ends = [(L["a_node"], L["a_name"]), (L["b_node"], L["b_name"])]
        if not force:
            off = [nm for nid, nm in ends if not _cached_ping(nid).get("ok")]
            if off:
                _refresh_cache([L["a_node"], L["b_node"]])
                return {"ok": False, "msg": "نودِ «" + "»، «".join(off) + "» در دسترس نیست — لینک دست‌نخورده نگه داشته شد؛ وقتی نود برگشت دوباره حذف کن، یا «حذفِ اجباری» را بزن"}
        errs, deferred = [], []
        act_step(h, "برچیدنِ تونل روی دو نود", 1, DELETE_STEPS, more=False)
        for nid, nm in ends:
            n = get_node(nid)
            if not n:
                continue
            if force and _known_offline(n):
                if _pending_add(nid, L["name"]):
                    deferred.append(nm)
                else:
                    errs.append(f"{nm}: صفِ حذفِ معلق نوشته نشد")
                continue
            r = node_call(n, "delete", "POST", {"name": L["name"]})
            if not r.get("ok"):
                if not force:
                    errs.append(f"{nm}: {r.get('error')}")
                elif _pending_add(nid, L["name"]):
                    deferred.append(nm)
                else:
                    errs.append(f"{nm}: صفِ حذفِ معلق نوشته نشد")
        if errs:
            _refresh_cache([L["a_node"], L["b_node"]])
            return {"ok": False, "msg": "; ".join(errs) + " — لینک نگه داشته شد؛ وقتی نود در دسترس شد دوباره حذف کن، یا «حذفِ اجباری» را بزن"}
        act_step(h, "برداشتنِ رکورد", 2, DELETE_STEPS, stop=False)
        with _reg_lock:
            save_json(LINKS_FILE, [x for x in load_links() if x["id"] != d["id"]])
        _tf_forget(L["a_node"], [L["name"]])
        _tf_forget(L["b_node"], [L["name"]])
        _refresh_cache([L["a_node"], L["b_node"]])
        if deferred:
            return {"ok": True, "deferred": deferred,
                    "msg": "لینک حذف شد؛ پاک‌سازیِ سمتِ «" + "»، «".join(deferred) + "» وقتی نود برگشت خودکار انجام می‌شود"}
        return {"ok": True}


REORDER_MAX = 256


def api_reorder(d):
    _require(d, ["kind", "id", "targets"])
    kind = d["kind"]
    aid = str(d["id"])
    targets = d["targets"]
    if not isinstance(targets, list) or len(targets) > REORDER_MAX:
        raise ValueError("فهرستِ ترتیب نامعتبر است (حداکثر %d مورد)" % REORDER_MAX)
    targets = [str(t) for t in targets if str(t) != aid]
    if not targets:
        return {"ok": True}
    if kind == "portfw":
        return _reorder_portfw(aid, targets)
    if kind == "nodes":
        path, loader = NODES_FILE, load_nodes
    elif kind in ("core", "tunnels"):
        path, loader = LINKS_FILE, load_links
    else:
        raise ValueError("نوعِ نامعتبر")
    with _reg_lock:
        items = loader()
        pos = {str(it.get("id")): i for i, it in enumerate(items)}
        if aid not in pos or any(t not in pos for t in targets):
            raise ValueError("مورد پیدا نشد")
        for bid in targets:
            i, jx = pos[aid], pos[bid]
            items[i], items[jx] = items[jx], items[i]
            pos[aid], pos[bid] = jx, i
        save_json(path, items)
    return {"ok": True}


def _restore_link(A, B, L, extra=None):
    tid = int(L["tunnel_id"])
    if extra is None:
        try:
            extra = _tunnel_extra(L)
        except Exception:
            extra = _tunnel_extra(L, refetch_ech=False)
    ttype = L["type"]
    a_body = {"type": ttype, "self_ip": L["a_ip"], "peer_ip": L["b_ip"], "subnet": L["subnet"],
              "id": tid, "name": L["name"], "host": overlay_host(ttype, L.get("server_side"), True),
              "enabled": L.get("enabled", True), **extra}
    b_body = {"type": ttype, "self_ip": L["b_ip"], "peer_ip": L["a_ip"], "subnet": L["subnet"],
              "id": tid, "name": L["name"], "host": overlay_host(ttype, L.get("server_side"), False),
              "enabled": L.get("enabled", True), **extra}
    if ttype == "core":
        a_body["role"] = _core_role(L, A["id"]) if A else ""
        b_body["role"] = _core_role(L, B["id"]) if B else ""
        _core_rotation_bodies(L, a_body, b_body)
        _core_workers_bodies(L, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
    _apply_probe_tuning(a_body, b_body)
    for N, body in ((A, a_body), (B, b_body)):
        if not N:
            continue
        try:
            node_call(N, "tunnel", "POST", body, timeout=NODE_OP_TIMEOUT)
        except Exception:
            pass


def api_edit_link(d):
    def edit(h):
        a, b = _link_nodes(d)
        with _PairLock(a, b, (d or {}).get("a_node"), (d or {}).get("b_node")):
            return _edit_link_impl(d, h)

    return act_link(d, edit)


def api_edge_status(d):
    d = d or {}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core":
        return {"ok": True, "pool": False, "active": "", "health": [], "events": []}
    is_pool = bool(L.get("ws_pool"))
    node = _client_node(L)
    if not node:
        return {"ok": True, "pool": is_pool, "active": "", "health": [], "events": [], "error": "نودِ کلاینتِ این تونل پیدا نشد"}
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
    node_now = int(r.get("now") or 0)
    pair = r.get("pair") if isinstance(r.get("pair"), dict) else {}
    return {"ok": True, "pool": is_pool, "active": str(r.get("active") or ""),
            "ready": bool(r.get("ready")),
            "pair": {"low": str(pair.get("low") or ""), "high": str(pair.get("high") or ""),
                     "low_kind": str(pair.get("low_kind") or ""),
                     "high_kind": str(pair.get("high_kind") or "")},
            "health": health, "events": (r.get("events") or []), "now": node_now, "ts": int(r.get("ts") or 0)}


def _retest_now(d, resolve):
    d = d or {}
    _require(d, ["id", "kind", "key"])
    if d["kind"] not in ("ip", "sni", "dst", "src"):
        raise ValueError("kind باید ip / sni / dst / src باشد")
    L, node = resolve(d)
    r = node_call(node, "retest-now", "POST",
                  {"name": L.get("name"), "kind": d["kind"], "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "ناموفق بود"}
    return {"ok": True}


def api_pool_retest_now(d):
    return _retest_now(d, _ws_pool_client)


def api_pool_select(d):
    d = d or {}
    _require(d, ["id", "kind", "key"])
    if d["kind"] not in ("ip", "sni"):
        raise ValueError("kind باید ip یا sni باشد")
    L, node = _ws_pool_client(d)
    r = node_call(node, "pool-select", "POST", {"name": L.get("name"), "kind": d["kind"], "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "انتخاب ناموفق بود"}
    now = int(time.time())
    _ev_suppress[d["id"]] = now + 45
    try:
        for k, ts in list(_ev_suppress.items()):
            if ts < now:
                _ev_suppress.pop(k, None)
    except RuntimeError:
        pass
    return {"ok": True}


def _ws_pool_client(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ws_pool"):
        raise ValueError("این لینک استخرِ لبه ندارد")
    node = _client_node(L)
    if not node:
        raise ValueError("نودِ کلاینت پیدا نشد")
    return L, node


def _peer_pool_client(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ip_rotate"):
        raise ValueError("این لینک استخرِ آی‌پی ندارد")
    node = _client_node(L)
    if not node:
        raise ValueError("نودِ کلاینت پیدا نشد")
    return L, node


_PEER_ADDR_RE = re.compile(r"^[0-9A-Fa-f:.]{1,64}$")


def _peer_addr_ok(s):
    return bool(s) and bool(_PEER_ADDR_RE.match(s))


def _peer_sec_norm(sec):
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
    return {"active": active if _peer_addr_ok(active) else "",
            "addrs": [x for x in (str(v) for v in (sec.get("addrs") or [])) if _peer_addr_ok(x)][:64],
            "health": health, "ts": int(sec.get("ts") or 0)}


def api_peer_status(d):
    d = d or {}
    empty = {"active": "", "addrs": [], "health": [], "ts": 0}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get("ip_rotate"):
        return {"ok": True, "pool": False, "now": int(time.time()), "dst": dict(empty), "src": dict(empty)}
    node = _client_node(L)
    if not node:
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": "نودِ کلاینتِ این تونل پیدا نشد"}
    r = node_call(node, "peer-status", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": r.get("error") or r.get("msg")}
    node_now = int(r.get("now") or 0)
    return {"ok": True, "pool": True, "now": node_now, "dst": _peer_sec_norm(r.get("dst")), "src": _peer_sec_norm(r.get("src"))}


def api_peer_retest_now(d):
    return _retest_now(d, _peer_pool_client)


def api_peer_select(d):
    d = d or {}
    _require(d, ["id", "key"])
    side = "src" if str(d.get("side")) == "src" else "dst"
    L, node = _peer_pool_client(d)
    r = node_call(node, "peer-select", "POST", {"name": L.get("name"), "side": side, "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error") or r.get("msg") or "انتخاب ناموفق بود"}
    return {"ok": True}



EDIT_STEPS = 4


def _node_set(*nodes):
    out, seen = [], set()
    for n in nodes:
        if n and n["id"] not in seen:
            seen.add(n["id"])
            out.append(n)
    return out


def _guard_arrival_free(was_a, was_b, A, B, tid, names):
    stay = {n["id"] for n in (was_a, was_b) if n}
    for N in _node_set(A, B):
        if N["id"] in stay:
            continue
        lst = node_call(N, "list", "GET", timeout=30)
        if lst.get("configs") is None:
            raise ValueError(f"فهرستِ تونل‌های نودِ «{N['name']}» خوانده نشد (مشغول یا قطع) — "
                             f"برای اینکه تونلِ دیگری روی آن پاک نشود متوقف شد")
        for c in (lst.get("configs") or []):
            if str(c.get("name") or "") in names or _sint(c.get("id")) == tid:
                raise ValueError(f"نودِ «{N['name']}» از قبل تونلی با همین شناسه ({tid}) دارد. "
                                 f"اگر مالِ همین تونل و از جابه‌جاییِ قبلی مانده، اول از روی آن نود "
                                 f"پاکش کن؛ وگرنه شناسه‌ها تداخل دارند")


def _undo_move(was_a, was_b, A, B, name):
    stay = {n["id"] for n in (was_a, was_b) if n}
    for N in _node_set(A, B):
        if N["id"] not in stay:
            node_call(N, "delete", "POST", {"name": name})


def _edit_link_impl(d, h=None):
    act_step(h, "خواندنِ وضعیتِ دو نود", 0, EDIT_STEPS)
    _require(d, ["id", "type"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")
    ttype = d["type"]
    if ttype not in TYPES:
        raise ValueError("نوعِ تونل نامعتبر است")
    was_a, was_b = get_node(L["a_node"]), get_node(L["b_node"])
    A = get_node(d["a_node"]) if str(d.get("a_node") or "").strip() else was_a
    B = get_node(d["b_node"]) if str(d.get("b_node") or "").strip() else was_b
    if not A or not B:
        raise ValueError("نودِ این تونل در پنل ثبت نیست — یکی از نودهای موجود را انتخاب کن")
    if A["id"] == B["id"]:
        raise ValueError("دو سرِ تونل باید دو نودِ متفاوت باشند")
    moved = A["id"] != L["a_node"] or B["id"] != L["b_node"]
    pa, pb = _ping_both(A, B)
    tid = int(L["tunnel_id"])
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()
    if want_a and want_a not in a_ips:
        raise ValueError(f"آی‌پیِ «{want_a}» روی نودِ «{A['name']}» نیست")
    if want_b and want_b not in b_ips:
        raise ValueError(f"آی‌پیِ «{want_b}» روی نودِ «{B['name']}» نیست")
    a_ip = (want_a if want_a in a_ips else
            (L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)))
    b_ip = (want_b if want_b in b_ips else
            (L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)))
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("آی‌پیِ نودها خوانده نشد")
    if a_ip == b_ip:
        raise ValueError("آی‌پیِ دو سرِ تونل یکی است؛ برای هر طرف یک آی‌پیِ متفاوت انتخاب کن")
    _guard_dup_pair(A, B, a_ip, b_ip, ttype, exclude_id=L["id"])
    _cs = str(d.get("subnet") or "").strip()
    if _cs and "/" not in _cs:
        raise ValueError("سابنت باید پیشوند داشته باشد — مثلاً 192.168.9.0/24")
    subnet = (norm_subnet(ttype, tid, d["subnet"]) if str(d.get("subnet") or "").strip()
              else carry_subnet(ttype, tid, L.get("subnet")))
    _guard_subnet_overlap(A, B, subnet, exclude_id=L["id"])
    old_name = L["name"]
    new_name = tunnel_name(ttype, tid)
    _guard_addr_on_another_iface(pa, pb, A, B, subnet, {old_name, new_name})
    name_changed = new_name != old_name
    type_changed = ttype != L["type"]
    extra = {}
    if ttype in ("l2tpv3", "fou", "core"):
        _asked = "port" in d and not str(d.get("port") or "").strip()
        port = int(d.get("port") or 0) or (0 if _asked else (L.get("port") if L.get("type") in ("l2tpv3", "fou", "core") else 0)) or free_tunnel_port(A, B, exclude_id=L["id"])
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (1 تا 65535)")
        extra["port"] = port
    if ttype == "vxlan":
        _asked = "port" in d and not str(d.get("port") or "").strip()
        port = int(d.get("port") or 0) or (0 if _asked else (L.get("port") if L.get("type") == "vxlan" else 0)) or 4789
        if not 1 <= port <= 65535:
            raise ValueError("پورتِ UDP خارج از محدوده است (1 تا 65535)")
        extra["port"] = port
    if ttype == "ipsec":
        extra["psk"] = L.get("psk") if (L.get("type") == "ipsec" and L.get("psk")) else secrets.token_hex(32)
    server_side = None
    if ttype == "core":
        ce, server_side = _core_extra(d, L, a_ip, b_ip, a_ips, b_ips)
        extra.update(ce)
    port_same = ("port" not in extra) or (extra["port"] == L.get("port"))
    if not moved and ttype != "core" and ttype == L["type"] and subnet == L["subnet"] and a_ip == L["a_ip"] and b_ip == L["b_ip"] and port_same:
        return {"ok": True, "unchanged": True, "name": old_name, "msg": "چیزی برای تغییر نبود"}
    _own = frozenset((N["id"], ip or "", p, pr) for N, ip, p, pr in
                     _port_bindings(L.get("type"), L.get("port"), L.get("transport"), L.get("server_side"), tid, was_a or A, was_b or B, L.get("a_ip"), L.get("b_ip"), L.get("a_ip_pool"), L.get("b_ip_pool")))
    if ttype == "core":
        _clash = _core_l4_conflict(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")), exclude_id=L.get("id"))
        if _clash:
            raise ValueError(f"همین آی‌پی و پورتِ سرور از قبل مالِ تونلِ «{_clash.get('name')}» است. پورتِ دیگری بگذار یا حاملِ دیگری انتخاب کن.")
    _guard_port_conflicts(_port_bindings(ttype, extra.get("port"), extra.get("transport"), server_side, tid, A, B, a_ip, b_ip, extra.get("a_ip_pool"), extra.get("b_ip_pool")), exclude=_own)
    if moved:
        _guard_arrival_free(was_a, was_b, A, B, tid, {old_name, new_name})
    if name_changed or type_changed or moved or ttype == "core":
        act_step(h, "برچیدنِ پیکربندیِ قبلی", 1, EDIT_STEPS)
        for N in _node_set(was_a, was_b, A, B):
            node_call(N, "delete", "POST", {"name": old_name})
    node_extra = _node_extra(extra)
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": new_name,
              "host": overlay_host(ttype, server_side, True), "enabled": L.get("enabled", True), **node_extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": new_name,
              "host": overlay_host(ttype, server_side, False), "enabled": L.get("enabled", True), **node_extra}
    if ttype == "core":
        a_body["role"] = "server" if server_side == "a" else "client"
        b_body["role"] = "server" if server_side == "b" else "client"
        _core_rotation_bodies(extra, a_body, b_body)
        _core_workers_bodies(extra, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
    _apply_probe_tuning(a_body, b_body)
    act_step(h, "اعمال روی نودِ «%s»" % A["name"], 2, EDIT_STEPS)
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        _undo_move(was_a, was_b, A, B, new_name)
        _restore_link(was_a, was_b, L)
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')} (تونلِ قبلی بازگردانده شد)")
    try:
        act_step(h, "اعمال روی نودِ «%s»" % B["name"], 3, EDIT_STEPS, more=False)
    except ActCancelled:
        _undo_move(was_a, was_b, A, B, new_name)
        _restore_link(was_a, was_b, L)
        raise
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        if name_changed:
            for N in _node_set(A, B):
                node_call(N, "delete", "POST", {"name": new_name})
        _undo_move(was_a, was_b, A, B, new_name)
        _restore_link(was_a, was_b, L)
        raise ValueError(f"نودِ «{B['name']}»: {rb.get('error') or rb.get('msg')} (تونلِ قبلی بازگردانده شد)")
    act_step(h, "ثبتِ تغییر", 3, EDIT_STEPS, stop=False)
    with _reg_lock:
        links = load_links()
        for x in links:
            if x["id"] == L["id"]:
                x.update({"name": new_name, "type": ttype, "subnet": subnet, "a_ip": a_ip, "b_ip": b_ip,
                          "a_node": A["id"], "a_name": A["name"],
                          "b_node": B["id"], "b_name": B["name"]})
                for k in _LINK_EXTRA_KEYS:
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
    _refresh_cache([L["a_node"], L["b_node"], A["id"], B["id"]])
    return {"ok": True, "name": new_name, "a_tunnel_ip": ra.get("tunnel_ip"), "b_tunnel_ip": rb.get("tunnel_ip")}


SPEED_SECS = 8
SPEED_STREAMS = 8


def api_link_speed(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")
    if L.get("enabled") is False:
        raise ValueError("این تونل خاموش است — اول روشنش کن")
    srv_is_a = L.get("server_side") != "b"
    srv = get_node(L["a_node"] if srv_is_a else L["b_node"])
    cli = get_node(L["b_node"] if srv_is_a else L["a_node"])
    if not srv or not cli:
        raise ValueError("نود پیدا نشد")
    secs, streams = SPEED_SECS, SPEED_STREAMS
    r = node_call(srv, "speedtest", "POST", {"name": L["name"], "mode": "serve", "secs": secs},
                  timeout=NODE_OP_TIMEOUT)
    if not r.get("ok"):
        raise ValueError("نودِ «%s» گیرندهٔ تست را بالا نیاورد: %s"
                         % (srv["name"], r.get("error") or r.get("msg") or "?"))
    q = node_call(cli, "speedtest", "POST",
                  {"name": L["name"], "mode": "run", "peer_ip": r.get("ip"), "port": r.get("port"),
                   "secs": secs, "streams": streams}, timeout=secs * 2 + 60)
    if not q.get("ok"):
        raise ValueError("نودِ «%s» تست را اجرا نکرد: %s"
                         % (cli["name"], q.get("error") or q.get("msg") or "?"))
    return {"ok": True, "from": cli["name"], "to": srv["name"], "secs": secs, "streams": streams,
            "up_mbit": q.get("up_mbit"), "down_mbit": q.get("down_mbit")}


def api_check_link(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")

    def chk(nid):
        n = get_node(nid)
        if not n:
            return {"online": False, "health": None}
        r = node_call(n, "check", "POST", {"name": L["name"]}, timeout=30)
        if r.get("ok"):
            return {"online": True, "health": r.get("health")}
        if r.get("offline"):
            return {"online": False, "health": None}
        return {"online": True, "health": None}

    a, b = parallel_map(chk, [L["a_node"], L["b_node"]])
    ah, bh = a["health"], b["health"]
    return {"ok": True, "name": L["name"], "a_online": a["online"], "b_online": b["online"],
            "a_health": ah, "b_health": bh}


def api_restart_link(d):
    def restart(h):
        a, b = _link_nodes(d)
        with _PairLock(a, b):
            return _restart_link_impl(d, h)

    return act_link(d, restart)


def _restart_link_impl(d, h=None):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")
    if L["type"] != "core":
        raise ValueError("فقط تونلِ هسته پروسه‌ای دارد که ری‌استارت شود")
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise ValueError("یکی از نودهای این تونل دیگر در پنل ثبت نیست")
    ends, errs = [], []
    for i, (side, N) in enumerate((("a", A), ("b", B))):
        act_step(h, "ری‌استارتِ هسته روی نودِ «%s»" % N["name"], i, 2, stop=(i == 0), more=False)
        r = node_call(N, "core-restart", "POST", {"name": L["name"]}, timeout=30)
        ok = bool(r.get("ok"))
        ends.append({"side": side, "node": N["name"], "ok": ok})
        if not ok:
            errs.append(f"{N['name']}: {r.get('error') or r.get('msg') or '?'}")
    if errs:
        log_event("bad", "link", f"تونلِ «{L['name']}»: ری‌استارتِ ناموفقِ هسته", "؛ ".join(errs))
        raise ValueError("؛ ".join(errs))
    log_event("ok", "link", f"تونلِ «{L['name']}»: ری‌استارتِ هسته",
              "پروسه روی هر دو نود تازه شد؛ کانفیگ دست‌نخورده")
    return {"ok": True, "ends": ends}


_rb_lock = threading.Lock()
_rb_last = {}
RB_KEEP = 900


def _rb_note(lid, ok, error=""):
    with _rb_lock:
        for k in [k for k, v in _rb_last.items() if time.time() - v["ts"] > RB_KEEP]:
            _rb_last.pop(k, None)
        _rb_last[lid] = {"ok": ok, "error": str(error)[:200], "ts": int(time.time())}


def rb_last(lid):
    with _rb_lock:
        v = _rb_last.get(lid)
        return dict(v) if v and time.time() - v["ts"] <= RB_KEEP else None


def api_rebuild_link(d):
    def rebuild(h):
        a, b = _link_nodes(d)
        with _PairLock(a, b):
            try:
                r = _rebuild_link_impl(d, h)
            except Exception as e:
                _rb_note(str(d.get("id") or ""), False, e)
                raise
            _rb_note(str(d.get("id") or ""), bool(r.get("ok")))
            return r

    return act_link(d, rebuild)


REBUILD_STEPS = 4


def _rebuild_link_impl(d, h=None):
    act_step(h, "خواندنِ وضعیتِ دو نود", 0, REBUILD_STEPS)
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise ValueError("یکی از نودهای این تونل دیگر در پنل ثبت نیست")
    pa, pb = _ping_both(A, B)
    tid, ttype, subnet, name = int(L["tunnel_id"]), L["type"], L["subnet"], L["name"]
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()
    a_ip = (want_a if want_a in a_ips else
            (L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)))
    b_ip = (want_b if want_b in b_ips else
            (L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)))
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise ValueError("آی‌پیِ نودها خوانده نشد")
    if ttype in IPIP_FAMILY:
        new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])
        for x in load_links():
            if (x.get("id") != L["id"] and x.get("type") in IPIP_FAMILY
                    and frozenset([(x.get("a_node"), x.get("a_ip")), (x.get("b_node"), x.get("b_ip"))]) == new_pair):
                raise ValueError(f"بازسازی ممکن نیست: تونلِ «{x.get('name')}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.")
    _guard_addr_on_another_iface(pa, pb, A, B, subnet, {name})
    extra = _tunnel_extra(L)
    act_step(h, "برچیدنِ هر دو سر", 1, REBUILD_STEPS)
    node_call(A, "delete", "POST", {"name": name})
    node_call(B, "delete", "POST", {"name": name})
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name,
              "host": overlay_host(ttype, L.get("server_side"), True), "enabled": L.get("enabled", True), **extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name,
              "host": overlay_host(ttype, L.get("server_side"), False), "enabled": L.get("enabled", True), **extra}
    if ttype == "core":
        a_body["role"], b_body["role"] = _core_role(L, A["id"]), _core_role(L, B["id"])
        _core_rotation_bodies(L, a_body, b_body)
        _core_workers_bodies(L, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
    _apply_probe_tuning(a_body, b_body)
    act_step(h, "ساخت روی نودِ «%s»" % A["name"], 2, REBUILD_STEPS)
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        _restore_link(A, B, L, extra)
        raise ValueError(f"نودِ «{A['name']}»: {ra.get('error') or ra.get('msg')} (تلاش برای بازگردانی)")
    try:
        act_step(h, "ساخت روی نودِ «%s»" % B["name"], 3, REBUILD_STEPS, more=False)
    except ActCancelled:
        _restore_link(A, B, L, extra)
        raise
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
    _set_drift(L["id"], False)
    _refresh_cache([L["a_node"], L["b_node"]])
    return {"ok": True, "name": name}


CARD_TAGS = 6


def api_link_tag(d):
    _require(d, ["id"])
    tag = int(d.get("tag") or 0)
    if not 0 <= tag <= CARD_TAGS:
        raise ValueError("رنگِ نشانه‌گذاری نامعتبر است")
    with _reg_lock:
        items = load_links()
        L = next((x for x in items if x["id"] == d["id"]), None)
        if L is None:
            items = load_nodes()
            L = next((x for x in items if x["id"] == d["id"]), None)
            path = NODES_FILE
        else:
            path = LINKS_FILE
        if L is None:
            raise ValueError("مورد پیدا نشد")
        if tag:
            L["tag"] = tag
        else:
            L.pop("tag", None)
        save_json(path, items)
    return {"ok": True, "tag": tag}


def api_link_toggle(d):
    _require(d, ["id"])
    enabled = bool(d.get("enabled"))
    a, b = _link_nodes(d)
    if not a or not b:
        raise ValueError("تونل پیدا نشد")
    with _PairLock(a, b):
        with _reg_lock:
            links = load_links()
            L = next((x for x in links if x["id"] == d["id"]), None)
            if not L:
                raise ValueError("تونل پیدا نشد")
            L["enabled"] = enabled
            save_json(LINKS_FILE, links)
        sides = {}
        for tag, nid in (("a", L["a_node"]), ("b", L["b_node"])):
            N = get_node(nid)
            if N:
                sides[tag] = node_call(N, "link-enable", "POST", {"name": L["name"], "enabled": enabled},
                                          timeout=NODE_OP_TIMEOUT)
        _refresh_cache([L["a_node"], L["b_node"]])
    both = len(sides) == 2 and all((sides.get(t) or {}).get("ok") for t in ("a", "b"))
    bad = [t for t in ("a", "b") if not (sides.get(t) or {}).get("ok")]
    names = {"a": L.get("a_name") or "A", "b": L.get("b_name") or "B"}
    return {"ok": True, "enabled": enabled, "both": both, "sides": sides,
            "failed": [names[t] for t in bad],
            "msg": "" if both else ("سمتِ %s جواب نداد — تونل روی آن سر عوض نشد"
                                    % "، ".join(names[t] for t in bad))}


RECONCILE_GAP = 15
RECONCILE_RETRY = 60
_reconcile_last = {}


def _reconcile_once():
    mode = get_settings().get("reconcile_mode", "alert")
    now = time.time()
    links = load_links()
    valid_ids = {L["id"] for L in links}
    for k in [k for k in _reconcile_last if k not in valid_ids]:
        _reconcile_last.pop(k, None)
    with _drift_lock:
        for k in [k for k in _drift if k not in valid_ids]:
            _drift.pop(k, None)
    for L in links:
        pa, pb = _cached_ping(L["a_node"]), _cached_ping(L["b_node"])
        if not pa.get("ok") or not pb.get("ok"):
            continue
        a_ips = _flat_ips(pa)
        b_ips = _flat_ips(pb)
        if not a_ips or not b_ips:
            continue
        a_ok, b_ok = L.get("a_ip") in a_ips, L.get("b_ip") in b_ips
        if a_ok and b_ok:
            _set_drift(L["id"], False)
            continue
        _set_drift(L["id"], True)
        if mode != "auto":
            continue
        ambiguous = (not a_ok and len(a_ips) != 1) or (not b_ok and len(b_ips) != 1)
        if ambiguous:
            continue
        if now - _reconcile_last.get(L["id"], 0) < RECONCILE_RETRY:
            continue
        try:
            r = api_rebuild_link({"id": L["id"]})
            if r.get("ok"):
                _set_drift(L["id"], False)
            else:
                _reconcile_last[L["id"]] = now
        except Exception:
            _reconcile_last[L["id"]] = now


def reconcile_loop():
    while True:
        try:
            gap = max(5, int(get_settings().get("reconcile_interval", RECONCILE_GAP) or RECONCILE_GAP))
        except Exception:
            gap = RECONCILE_GAP
        time.sleep(gap)
        try:
            _reconcile_once()
        except Exception:
            pass


_ECH_EMPTY_CYCLES = 3
_ech_empty = {}
_ech_empty_lock = threading.Lock()
_ech_down_rebuilt = set()
_ech_healed_seq = {}


def _ech_link_hosts(L):
    if L.get("type") != "core" or not L.get("ech") or not L.get("enabled", True):
        return None
    if L.get("ws_pool") and L.get("ws_edge_snis"):
        hosts = [s.get("host") for s in L["ws_edge_snis"] if isinstance(s, dict) and s.get("host")]
        return ("pool", hosts) if hosts else None
    if L.get("ws_host"):
        return ("single", [L.get("ws_host")])
    return None


def _ech_live_push(lid, chmap):
    if not chmap:
        return (False, "")
    L = next((x for x in load_links() if x.get("id") == lid), None)
    if not L or L.get("type") != "core" or not (L.get("ws_pool") or L.get("ws_host")):
        return (False, "")
    node = _client_node(L)
    if not node:
        return (False, "")
    try:
        r = node_call(node, "ech-update", "POST", {"name": L.get("name"), "snis": chmap}, timeout=8)
    except Exception:
        return (True, "")
    if not isinstance(r, dict) or not r.get("ok"):
        return (True, "")
    nm = str(node.get("name") or "").strip()
    host = str(node.get("host") or "").strip()
    return (True, "%s \u2022 %s" % (nm, host) if nm and host else (nm or host or str(node.get("id") or "")))


def _ech_pool_state(lid):
    try:
        st = api_edge_status({"id": lid})
    except Exception:
        return (False, False, False)
    reachable = bool(st.get("ok")) and not st.get("error")
    if not reachable:
        return (False, False, False)
    ready = bool(st.get("ready"))
    ips = [h for h in (st.get("health") or []) if isinstance(h, dict) and h.get("kind") == "ip"]
    any_bad = any(str(h.get("state")) in ("suspect", "dead") for h in ips)
    now = int(st.get("now") or 0) or int(time.time())
    tls_recent = any(
        str(e.get("code")) == "tls" and str(e.get("kind")) in ("down", "burn")
        and (now - int(e.get("ts") or 0)) <= 900
        for e in (st.get("events") or []) if isinstance(e, dict)
    )
    stalled = ready and any_bad and tls_recent
    return (True, not ready, stalled)


def _ech_write(lid, kind, updates, degrade):
    changed = False
    chmap = {}
    with _reg_lock:
        links = load_links()
        for x in links:
            if x.get("id") != lid:
                continue
            if degrade:
                if x.get("ws_ech"):
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


def _ech_blank(lid, hosts):
    want = set(hosts)
    changed = False
    with _reg_lock:
        links = load_links()
        for x in links:
            if x.get("id") != lid:
                continue
            for s in (x.get("ws_edge_snis") or []):
                if isinstance(s, dict) and s.get("host") in want and s.get("ech"):
                    s["ech"] = ""
                    changed = True
            break
        if changed:
            save_json(LINKS_FILE, links)
    return changed


def _ech_keys_blank(L, kind, hosts):
    if kind == "single":
        return not str(L.get("ws_ech") or "").strip()
    return all(not str(s.get("ech") or "").strip()
               for s in (L.get("ws_edge_snis") or [])
               if isinstance(s, dict) and s.get("host") in hosts)


def _ech_safe_rebuild(lid):
    try:
        api_rebuild_link({"id": lid})
        return True
    except Exception:
        return False


def _ech_refresh_once():
    try:
        _mins_label = "%g" % float(get_settings().get("ech_refresh_mins", 15) or 15)
    except Exception:
        _mins_label = "15"
    links = load_links()
    live_ids = {L.get("id") for L in links}
    with _ech_empty_lock:
        for k in [k for k in _ech_empty if k[0] not in live_ids]:
            _ech_empty.pop(k, None)
    _ech_down_rebuilt.intersection_update(live_ids)
    for L in links:
        hk = _ech_link_hosts(L)
        if not hk:
            continue
        kind, hosts = hk
        lid, nm = L.get("id"), L.get("name")
        ech_map = _fetch_ech_map(hosts, _ech_px(L))
        updates, gone = {}, []
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
                    if _ech_empty[key] >= _ECH_EMPTY_CYCLES:
                        gone.append(h)
        removed = bool(hosts) and len(gone) == len(hosts)
        blank_before = _ech_keys_blank(L, kind, set(hosts))
        if removed:
            if _ech_write(lid, kind, {}, degrade=True)[0]:
                if _ech_safe_rebuild(lid):
                    log_event("warn", "ech", f"تونلِ «{nm}»: حذفِ رکوردِ ECH",
                              f"کلید از DNS ناپدید شد؛ تونل فعلاً بدون ECH بازسازی شد. تنظیمِ ECH همچنان روشن است و "
                              f"پنل هر {_mins_label} دقیقه دوباره امتحان می‌کند — به‌محضِ برگشتنِ رکورد خودش برمی‌گردد")
                else:
                    log_event("bad", "ech", f"تونلِ «{nm}»: حذفِ رکوردِ ECH", "تنزل به wss ساده شد ولی بازسازی شکست خورد — تونل هنوز قطع است")
            continue
        if gone and _ech_blank(lid, gone):
            names = "، ".join(gone)
            if _ech_safe_rebuild(lid):
                log_event("warn", "ech", f"تونلِ «{nm}»: حذفِ رکوردِ ECH روی بخشی از استخر",
                          f"رکوردِ ECHِ {names} از DNS ناپدید شده؛ همان دامنه‌ها بدون ECH بازسازی شدند و "
                          f"بقیهٔ استخر دست‌نخورده ماند. پنل هر {_mins_label} دقیقه دوباره امتحان می‌کند")
            else:
                log_event("bad", "ech", f"تونلِ «{nm}»: حذفِ رکوردِ ECH روی بخشی از استخر",
                          f"کلیدِ کهنهٔ {names} پاک شد ولی بازسازی شکست خورد — رفتن روی آن دامنه‌ها هنوز می‌میرد")
        changed, chmap = _ech_write(lid, kind, updates, degrade=False)
        if changed and chmap and blank_before:
            if _ech_safe_rebuild(lid):
                log_event("ok", "ech", f"تونلِ «{nm}»: بازگشتِ ECH",
                          "رکوردِ ECH دوباره منتشر شد؛ تونل با کلیدِ تازه بازسازی شد")
            else:
                log_event("bad", "ech", f"تونلِ «{nm}»: بازگشتِ ECH",
                          "رکوردِ ECH برگشت ولی بازسازی شکست خورد — تونل هنوز بدون ECH است")
        if changed and chmap:
            tried, pushed = _ech_live_push(lid, chmap)
            dfa = "\n".join("دامنه: %s\nکلیدِ ECH: %s" % (h, k) for h, k in chmap.items())
            if pushed:
                dfa += "\nنودِ مقصد: %s" % pushed
                log_event("ok", "ech", "کلیدِ ECHِ تونلِ «%s» تازه شد و زنده به هسته push شد (هر %s دقیقه)" % (nm, _mins_label), dfa)
            elif tried:
                if _ech_safe_rebuild(lid):
                    log_event("warn", "ech", "کلیدِ ECHِ تونلِ «%s» تازه شد ولی pushِ زنده نرسید" % nm, dfa + "\nنود جواب نداد؛ تونل با کلیدِ تازه بازسازی شد")
                else:
                    log_event("bad", "ech", "کلیدِ ECHِ تونلِ «%s» تازه شد ولی به هسته نرسید" % nm, dfa + "\nنه pushِ زنده جواب داد نه بازسازی — هسته هنوز کلیدِ کهنه دارد")
            else:
                log_event("ok", "ech", "کلیدِ ECHِ تونلِ «%s» با تایمرِ زمان‌بندی‌شده تازه شد (هر %s دقیقه)" % (nm, _mins_label), dfa)
        reachable, down, stalled = _ech_pool_state(lid) if kind == "pool" else (False, False, False)
        if kind == "pool" and (down or stalled):
            if lid not in _ech_down_rebuilt or changed:
                _ech_down_rebuilt.add(lid)
                why_fa = "قطع بود" if down else "همهٔ لبه‌هایش سرِ ECH می‌سوختند"
                if _ech_safe_rebuild(lid):
                    log_event("ok", "ech", f"تونلِ «{nm}»: چرخشِ کلیدِ ECH", f"{why_fa}؛ با کلیدِ تازه بازسازی شد")
                else:
                    log_event("bad", "ech", f"تونلِ «{nm}»: چرخشِ کلیدِ ECH", f"{why_fa}؛ بازسازی با کلیدِ تازه شکست خورد — تونل هنوز قطع است")
                    _ech_down_rebuilt.discard(lid)
        else:
            _ech_down_rebuilt.discard(lid)


def _ech_heal_once():
    for L in load_links():
        hk = _ech_link_hosts(L)
        if not hk or hk[0] != "pool":
            continue
        kind, hosts = hk
        lid, nm = L.get("id"), L.get("name")
        _reachable, down, stalled = _ech_pool_state(lid)
        if not (down or stalled):
            _ech_down_rebuilt.discard(lid)
            continue
        if lid in _ech_down_rebuilt:
            continue
        updates = {h: k for h, k in _fetch_ech_map(hosts, _ech_px(L)).items() if k}
        _ech_write(lid, kind, updates, degrade=False)
        _ech_down_rebuilt.add(lid)
        why_fa = "قطع بود" if down else "همهٔ لبه‌هایش سرِ ECH می‌سوختند"
        if _ech_safe_rebuild(lid):
            log_event("ok", "ech", f"تونلِ «{nm}»: بازسازیِ سریعِ ECH", f"{why_fa}")
        else:
            log_event("bad", "ech", f"تونلِ «{nm}»: بازسازیِ سریعِ ECH", f"{why_fa}؛ شکست خورد — تونل هنوز قطع است")
            _ech_down_rebuilt.discard(lid)


def _ech_ingest_selfheal():
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
        events = st.get("events") or []
        seen_max = _ech_healed_seq.get(lid, 0)
        ring_max = 0
        for e in events:
            if isinstance(e, dict):
                try:
                    ring_max = max(ring_max, int(e.get("seq") or 0))
                except (TypeError, ValueError):
                    pass
        if ring_max < seen_max:
            log_event("ok", "ech",
                      "شمارندهٔ رویدادِ هستهٔ تونلِ «%s» صفر شده (ری‌استارتِ هسته)؛ ثبتِ خودترمیمِ ECH از نو باز شد" % nm)
            seen_max = 0
        new_max = seen_max
        latest = {}
        for e in events:
            if not isinstance(e, dict) or str(e.get("kind")) != "ech" or str(e.get("code")) != "self_heal":
                continue
            try:
                seq = int(e.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            if seq <= seen_max:
                continue
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
        _ech_healed_seq.pop(dead, None)


def ech_refresh_loop():
    last_full = 0.0
    while True:
        time.sleep(60.0)
        try:
            mins = float(get_settings().get("ech_refresh_mins", 15) or 0)
        except Exception:
            mins = 15.0
        try:
            _ech_heal_once()
        except Exception:
            pass
        try:
            _ech_ingest_selfheal()
        except Exception:
            pass
        if mins <= 0:
            continue
        now = time.time()
        if (now - last_full) >= max(60.0, mins * 60.0):
            last_full = now
            try:
                _ech_refresh_once()
            except Exception:
                pass


EVENTS_FILE = os.path.join(CENTRAL_DIR, "events.json")
EVENTS_SEQ_FILE = os.path.join(CENTRAL_DIR, "events.seq")
EVENTS_TTL = 24 * 3600
EVENTS_MAX = 5000
_events_lock = threading.Lock()
_ev_seq_total = None
_ev_count = None
_ev_list = None
_ev_dirty = False
_ev_state = {"init": False, "nodes": {}, "links": {}, "edge": {}, "evseq": {}, "rotip": {}, "links_coarse_down": set()}


def _ev_ip(detail):
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", str(detail or ""))
    return m.group(0) if m else ""
def _ev_value(detail):
    tag, _, rest = str(detail or "").partition(":")
    return rest.strip() if tag in ("ip", "sni") and rest.strip() else ""


_ev_suppress = {}

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
    "session-dead": "سشنِ DNS تمام شد — مسیرِ ریزالور دیگر آن را حمل نمی‌کند",
    "peer-dead": "آی‌پیِ مقصدی که چرخش روی آن رفت جواب نداد — سوزانده شد و رفت روی آی‌پیِ بعدی",
}
_HEAL_AXIS = {"dst": "آی‌پیِ مقصد", "src": "آی‌پیِ مبدأ",
              "ip": "آی‌پیِ لبه", "sni": "دامنه (SNI)"}

_EV_UP_CODE = {
    "reconnect": "پس از افتِ سشن، خودکار وصل شد (self-heal)",
}
_EV_ROT_AXIS = {
    "peer-rotate": ("dst", "چرخش آی‌پیِ مقصد"),
    "src-rotate":  ("src", "چرخش آی‌پیِ مبدأ"),
    "edge-rotate": ("ip",  "چرخش لبهٔ CDN"),
    "sni-rotate":  ("sni", "چرخش دامنه"),
}
_EV_ROT_CODE = {
    "rehandshake": ("warn", "دست‌دادنِ دوباره، پیش از سوزاندنِ هر آدرسی"),
    "port-roll": ("ok", "با چرخشِ پورتِ مبدأ برگشت"),
    "edge-walk": ("warn", "گشتنِ لبه‌ها — اتصال زودتر از آن می‌میرد که پروب بتواند قضاوت کند"),
    "ladder-revive": ("warn", "ازسرگیریِ نردبان پس از بن‌بست"),
}


def _ev_rot(kind, code):
    if kind not in ("down", "rot"):
        return None
    ax = _EV_ROT_AXIS.get(code)
    if ax is None:
        lvl_fa = _EV_ROT_CODE.get(code) if kind == "down" else None
        return (lvl_fa[0], lvl_fa[1], "") if lvl_fa else None
    axis, fa = ax
    if kind == "rot":
        return ("ok", fa + " — طبقِ زمان‌بندی", axis)
    return ("warn", fa + " — اجباری: مسیر جواب نداد", axis)


def _rot_pair(axis, prev, cur, other):
    if not cur:
        return ""
    pair = (lambda one: f"{other} ← {one}" if other else one) if axis == "src" \
        else (lambda one: f"{one} ← {other}" if other else one)
    if prev and prev != cur:
        return f"از: {pair(prev)}\nبه: {pair(cur)}"
    return f"به: {pair(cur)}"


def _mib(b):
    try:
        n = int(b)
    except (TypeError, ValueError):
        return str(b)
    if n >= 1 << 20:
        return "%.1f مگابایت" % (n / float(1 << 20))
    if n >= 1 << 10:
        return "%.0f کیلوبایت" % (n / float(1 << 10))
    return "%d بایت" % n


def _ev_core_text(kind, code, detail, nm):
    raw = str(detail or "")
    axis, sep, rest = raw.partition(":")
    key = rest if sep and axis in ("dst", "src", "ip", "sni") else raw
    if kind == "down":
        rf = _EV_DOWN_CODE.get(code, "اتصال قطع شد")
        return ("bad", "link", f"تونلِ «{nm}»: قطع شد", rf)
    if kind == "up":
        rf = _EV_UP_CODE.get(code, "تونل وصل شد")
        return ("ok", "link", f"تونلِ «{nm}»: وصلِ مجدد", rf)
    if kind == "burn":
        what = _HEAL_AXIS.get(str(detail or "").split(":", 1)[0], "آی‌پی")
        return ("warn", "burn", f"تونلِ «{nm}»: سوختنِ {what}", f"{what}: {key}")
    if kind == "cfg":
        if code == "sockbuf-clamped":
            parts = key.split()
            title = f"تونلِ «{nm}»: بافرِ سوکت به‌اندازه‌ای که خواستی اعمال نشد"
            if len(parts) == 3 and parts[0] == "send":
                return ("warn", "cfg", title,
                        f"بافرِ ارسال: {_mib(parts[1])} خواسته شد، {_mib(parts[2])} اعمال شد\n"
                        f"چاره: net.core.wmem_max را روی آن نود بالا ببر، یا CAP_NET_ADMIN به سرویس بده")
            if len(parts) == 3:
                return ("warn", "cfg", title,
                        f"بافرِ دریافت: {_mib(parts[1])} خواسته شد، {_mib(parts[2])} اعمال شد\n"
                        f"چاره: net.core.rmem_max را روی آن نود بالا ببر، یا CAP_NET_ADMIN به سرویس بده")
        return ("warn", "cfg", f"تونلِ «{nm}»: یک تنظیم آن‌طور که خواسته شد اعمال نشد", f"جزئیات: {key}")
    if kind == "heal":
        if code == "tun-probe":
            what = _HEAL_AXIS.get(str(detail or "").split(":", 1)[0], "آی‌پی")
            return ("ok", "heal", f"تونلِ «{nm}»: بازگشتِ {what}",
                    f"{key}\nپروبِ نود دید ترافیک واقعاً از این مسیر رد می‌شود")
    if kind == "pool":
        what = _HEAL_AXIS.get(axis, "آی‌پی")
        left = key if sep and axis in _HEAL_AXIS else ""
        if code == "degraded":
            return ("warn", "edge",
                    f"تونلِ «{nm}»: توقفِ چرخشِ {what} — فقط یکی در دسترس مانده",
                    (f"در دسترس: {left}\n" if left else "")
                    + "بقیه سوخته‌اند و نوبتِ آزمایشِ دوباره‌شان نرسیده؛ تا آن موقع روی همان یک می‌ماند")
        return ("ok", "edge", f"تونلِ «{nm}»: ازسرگیریِ چرخشِ {what}",
                (f"در دسترس: {left}\n" if left else "")
                + "دوباره بیش از یک مورد در دسترسِ چرخش است")
    if kind == "ech":
        host, _, k = key.partition(" ")
        dfa = ("دامنه: %s\n" % host if host else "") + ("کلیدِ تازهٔ ECH: %s" % k if k else "")
        return ("ok", "ech", f"تونلِ «{nm}»: ترمیمِ خودکارِ کلیدِ ECH", dfa)
    return None


def _ev_all():
    global _ev_list, _ev_dirty
    if _ev_list is None:
        try:
            with open(EVENTS_FILE) as f:
                raw = json.load(f)
        except (OSError, ValueError):
            raw = []
        raw = raw if isinstance(raw, list) else []
        _ev_list = _ev_prune(raw)
        if len(_ev_list) != len(raw):
            _ev_dirty = True
    return _ev_list


def load_events():
    with _events_lock:
        return list(_ev_all())


def _ev_flush():
    global _ev_dirty
    if not _ev_dirty:
        return
    try:
        save_json(EVENTS_FILE, _ev_list)
        save_json(EVENTS_SEQ_FILE, _ev_seq_get())
        _ev_dirty = False
    except OSError:
        pass


def _ev_seq_get():
    global _ev_seq_total
    if _ev_seq_total is None:
        try:
            with open(EVENTS_SEQ_FILE) as f:
                _ev_seq_total = int(json.load(f))
        except (OSError, ValueError, TypeError):
            _ev_seq_total = 0
    return _ev_seq_total


def _ev_count_get():
    global _ev_count
    if _ev_count is None:
        with _events_lock:
            _ev_count = len(_ev_all())
    return _ev_count


def _ev_cat(kind):
    if kind == "auth":
        return "auth"
    if kind == "link":
        return "tunnel"
    if kind in ("rot", "edge", "burn", "heal"):
        return "rot"
    if kind in ("ech", "node"):
        return kind
    return "sys"


def _ev_prune(evs, now=None):
    cut = (time.time() if now is None else now) - EVENTS_TTL
    return [e for e in evs if isinstance(e, dict) and _sint(e.get("ts")) >= cut][:EVENTS_MAX]


def ev_sweep():
    global _ev_list, _ev_count, _ev_dirty
    with _events_lock:
        before = len(_ev_all())
        _ev_list = _ev_prune(_ev_list)
        _ev_count = len(_ev_list)
        if len(_ev_list) != before:
            _ev_dirty = True
        _ev_flush()
        return before - len(_ev_list)


def log_event(level, kind, fa, dfa=""):
    global _ev_seq_total, _ev_count, _ev_dirty
    with _events_lock:
        evs = _ev_all()
        evs.insert(0, {"ts": int(time.time()), "level": level, "kind": kind,
                       "fa": fa, "dfa": dfa})
        if len(evs) > EVENTS_MAX:
            del evs[EVENTS_MAX:]
        _ev_count = len(evs)
        _ev_seq_total = _ev_seq_get() + 1
        _ev_dirty = True


def _node_online(nid):
    return bool(_cached_ping(nid).get("ok"))


def _link_up(L):
    ah, _a = _link_side_health(L, "a_node")
    bh, _b = _link_side_health(L, "b_node")
    if not (isinstance(ah, dict) and ah.get("up") and isinstance(bh, dict) and bh.get("up")):
        return False
    return not (ah.get("dead") or bh.get("dead"))


def _link_down_reason(L, nmap):
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
    rotated = set()

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
            log_event("ok", "node", f"نودِ «{nm}»: آنلاین شد")
        else:
            log_event("bad", "node", f"نودِ «{nm}»: آفلاین شد")
    for nid in [k for k in _ev_state["nodes"] if k not in seen]:
        _ev_state["nodes"].pop(nid, None)

    seen = set()
    for L in links:
        lid = L["id"]
        seen.add(lid)
        if not L.get("enabled", True):
            _ev_state["links"].pop(lid, None)
            _ev_state["links_coarse_down"].discard(lid)
            continue
        a_probed = _cache_get(L.get("a_node")) is not None
        b_probed = _cache_get(L.get("b_node")) is not None
        if not (a_probed and b_probed):
            continue
        _ah, _ = _link_side_health(L, "a_node")
        _bh, _ = _link_side_health(L, "b_node")
        if (isinstance(_ah, dict) and _ah.get("up") is None) or (isinstance(_bh, dict) and _bh.get("up") is None):
            continue
        up = bool(_link_up(L))
        prev = _ev_state["links"].get(lid)
        _ev_state["links"][lid] = up
        if first or prev is None or prev == up:
            continue
        nm = L.get("name", "")
        precise_core = L.get("type") == "core" and (
            bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in STATUSRING_TRANSPORTS)
        if up:
            if precise_core and lid not in _ev_state["links_coarse_down"]:
                pass
            else:
                log_event("ok", "link", f"تونلِ «{nm}»: وصل شد")
            _ev_state["links_coarse_down"].discard(lid)
        else:
            a_off = _cache_get(L.get("a_node")) and not _node_online(L.get("a_node"))
            b_off = _cache_get(L.get("b_node")) and not _node_online(L.get("b_node"))
            if precise_core and not (a_off or b_off):
                pass
            else:
                rf = _link_down_reason(L, nmap)
                log_event("bad", "link", f"تونلِ «{nm}»: قطع شد", rf)
                if precise_core:
                    _ev_state["links_coarse_down"].add(lid)
    for lid in [k for k in _ev_state["links"] if k not in seen]:
        _ev_state["links"].pop(lid, None)
        _ev_state["links_coarse_down"].discard(lid)

    seen = set()
    now = int(time.time())
    todo = [L for L in links if L.get("type") == "core" and L.get("enabled", True)
            and (bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in STATUSRING_TRANSPORTS)]

    srcneed = [L for L in links if L.get("type") == "core" and L.get("enabled", True) and L.get("ip_rotate")
               and not _ev_state["rotip"].get(L["id"] + ":src")]

    def _ps(L):
        try:
            return api_peer_status({"id": L["id"]})
        except Exception:
            return None
    for L, ps in zip(srcneed, parallel_map(_ps, srcneed)):
        for ax in ("src", "dst"):
            a = str(((ps or {}).get(ax) or {}).get("active") or "")
            if a and not _ev_state["rotip"].get(L["id"] + ":" + ax):
                _ev_state["rotip"][L["id"] + ":" + ax] = a

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
            continue
        lid = L["id"]
        seen.add(lid)
        nm = L.get("name", "")
        r = pre.get(lid)
        if not r or "error" in r:
            continue

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
                        continue
                    clean.append((sq, e))
            mx = max([0] + [sq for sq, _ in clean])
            if first:
                _ev_state["evseq"][lid] = mx
            else:
                last = _ev_state["evseq"].get(lid, 0)
                if clean and mx < last:
                    last = 0
                for sq, e in sorted(clean, key=lambda x: x[0]):
                    if sq <= last:
                        continue
                    ekind, ecode, edet = str(e.get("kind") or ""), str(e.get("code") or ""), str(e.get("detail") or "")
                    rot = _ev_rot(ekind, ecode)
                    if rot and rot[2] in ("ip", "sni"):
                        lvl, fa = rot[0], rot[1]
                        rotated.add(lid)
                        log_event(lvl, "rot", f"تونلِ «{nm}»: {fa}",
                                  f"به: {_ev_value(edet)}" if _ev_value(edet) else "")
                        continue
                    if rot and ecode == "port-roll":
                        kv = dict(w.split(":", 1) for w in edet.split() if ":" in w)
                        lvl = rot[0]
                        rotated.add(lid)
                        tries, sport = kv.get("tries"), kv.get("sport")
                        say = f"تونلِ «{nm}»: با چرخشِ پورتِ مبدأ"
                        if tries:
                            say += f" پس از {tries} تلاش"
                        if sport:
                            say += f"، با پورتِ {sport}"
                        say += " برگشت"
                        log_event(lvl, "rot", say, "")
                        continue
                    if rot and rot[2]:
                        ip = _ev_ip(edet)
                        axis = rot[2]
                        rk = lid + ":" + axis
                        prev = _ev_state["rotip"].get(rk)
                        if ip:
                            _ev_state["rotip"][rk] = ip
                        other_k = lid + ":" + ("dst" if axis == "src" else "src")
                        other = _ev_state["rotip"].get(other_k) or ""
                        if axis == "src" and not other:
                            other = _ev_ip(str(r.get("active") or ""))
                            if other:
                                _ev_state["rotip"][other_k] = other
                        lvl, fa = rot[0], rot[1]
                        dfa = _rot_pair(axis, prev, ip, other)
                        log_event(lvl, "rot", f"تونلِ «{nm}»: {fa}", dfa)
                        continue
                    if rot:
                        log_event(rot[0], "rot", f"تونلِ «{nm}»: {rot[1]}", "")
                        continue
                    txt = _ev_core_text(ekind, ecode, edet, nm)
                    if txt:
                        log_event(*txt)
                _ev_state["evseq"][lid] = max(last, mx)

            if is_pool:
                active = str(r.get("active") or "")
                prev = _ev_state["edge"].get(lid)
                if active:
                    _ev_state["edge"][lid] = active
                if lid in rotated:
                    pass
                elif not (first or prev is None or prev == active or not active) and _ev_suppress.get(lid, 0) <= now:
                    log_event("ok", "edge", f"تونلِ «{nm}»: چرخش لبه", f"از: {prev}\nبه: {active}")
        except Exception:
            continue
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
            ev_sweep()
        except Exception:
            pass


def api_events(d):
    d = d or {}
    lim = max(1, min(EVENTS_MAX, _sint(d.get("limit")) or EVENTS_MAX))
    cut = time.time() - EVENTS_TTL
    evs = [dict(e, cat=_ev_cat(e.get("kind")))
           for e in load_events()[:lim] if _sint(e.get("ts")) >= cut]
    return {"ok": True, "events": evs}


def api_events_clear(d):
    global _ev_count, _ev_dirty
    with _events_lock:
        _ev_all()[:] = []
        _ev_count = 0
        _ev_dirty = True
        _ev_flush()
    return {"ok": True}


def _pf_field(k, v):
    if k in ("listen_port", "dst_port"):
        p = _sint(v)
        if not 1 <= p <= 65535:
            raise ValueError(f"«{k}» باید بینِ ۱ تا ۶۵۵۳۵ باشد")
        return p
    if k == "dst_ips":
        raw = v if isinstance(v, list) else re.split(r"[\s,]+", str(v))
        ips = [str(x).strip() for x in raw if str(x).strip()]
        if not ips or not all(is_ipv4(x) for x in ips):
            raise ValueError("فهرستِ آی‌پیِ مقصد باید حداقل یک آدرسِ IPv4 داشته باشد")
        return ips
    if k == "listen_ip":
        s = str(v).strip()
        if not is_ipv4(s):
            raise ValueError("آی‌پیِ شنود نامعتبر است")
        return s
    if k == "iface":
        s = str(v).strip()
        if not re.match(r"^[A-Za-z0-9._-]{1,15}$", s):
            raise ValueError("نامِ کارتِ شبکه نامعتبر است")
        return s
    if k == "interval_min":
        m = _sint(v)
        if not 1 <= m <= 1440:
            raise ValueError("بازهٔ چرخش باید بینِ ۱ تا ۱۴۴۰ دقیقه باشد")
        return m
    return v


def _pf_name(v):
    s = str(v).strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,40}$", s):
        raise ValueError("نامِ پورت‌فوروارد نامعتبر است — فقط حروف/عدد و «._-» (1 تا 40 کاراکتر) مجاز است")
    return s


def _pf_push(n, endpoint, body, timeout=NODE_OP_TIMEOUT, ret="name"):
    r = node_call(n, endpoint, "POST", body, timeout=timeout)
    if not r.get("ok"):
        raise ValueError(r.get("error") or r.get("msg") or "failed")
    _refresh_cache([n["id"]])
    return {"ok": True, ret: r.get(ret)}


def api_portfw(d):
    _require(d, ["node", "listen_port", "dst_port", "dst_ips"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("نود پیدا نشد")
    body = {"listen_port": _pf_field("listen_port", d["listen_port"]),
            "dst_port": _pf_field("dst_port", d["dst_port"]),
            "dst_ips": _pf_field("dst_ips", d["dst_ips"]),
            "interval_min": _pf_field("interval_min", d.get("interval_min", 5))}
    if d.get("iface"):
        body["iface"] = _pf_field("iface", d["iface"])
    if d.get("listen_ip"):
        body["listen_ip"] = _pf_field("listen_ip", d["listen_ip"])
    return _pf_push(n, "portfw", body)


def _pf_key(node_id, name):
    return str(node_id) + str(name)


def _pf_load_order():
    try:
        o = json.load(open(PORTFW_ORDER_FILE))
        return o if isinstance(o, list) else []
    except Exception:
        return []


def _pf_sorted(seq, key_of):
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


def _reorder_portfw(a, targets):
    natural = _pf_natural_keys()
    with _reg_lock:
        cur = _pf_sorted(natural, lambda k: k)
        if a not in cur or any(b not in cur for b in targets):
            raise ValueError("مورد پیدا نشد")
        for b in targets:
            ia, ib = cur.index(a), cur.index(b)
            cur[ia], cur[ib] = cur[ib], cur[ia]
        save_json(PORTFW_ORDER_FILE, cur)
    return {"ok": True}


def api_portfw_list(d):
    q = _list_query(d)
    all_pf = []
    for n in load_nodes():
        r = _cached_list(n["id"])
        if r.get("configs") is None:
            continue
        h = r.get("health") or {}
        node_ips = _flat_ips(_cached_ping(n["id"]))
        node_ip = node_ips[0] if len(node_ips) == 1 else ""
        tf = _tf_read(n["id"])
        for c in r["configs"]:
            if c.get("type") != "portfw":
                continue
            if q and q not in n["name"].lower() and q not in str(c.get("name", "")).lower():
                continue
            t = tf.get("pf:" + str(c.get("name") or ""))
            bw = ({"rx_bps": t["rx_bps"], "tx_bps": t["tx_bps"], "rx_total": t["crx"], "tx_total": t["ctx"]}
                  if t else {"rx_bps": 0.0, "tx_bps": 0.0, "rx_total": 0, "tx_total": 0})
            all_pf.append({"node": n["name"], "node_id": n["id"], "name": c.get("name"),
                           "iface": c.get("iface"), "listen_port": c.get("listen_port"),
                           "listen_ip": c.get("listen_ip") or "", "node_ip": node_ip,
                           "dst_port": c.get("dst_port"), "dst_ips": c.get("dst_ips", []),
                           "switch_interval": c.get("switch_interval", 0), "health": h.get(c.get("name")),
                           **bw})
    all_pf = _pf_sorted(all_pf, lambda it: _pf_key(it["node_id"], it["name"]))
    return {"portfw": all_pf, "total": len(all_pf)}


def api_portfw_edit(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("نود پیدا نشد")
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
        raise ValueError("نود پیدا نشد")
    return _pf_push(n, "portfw-next", {"name": _pf_name(d["name"])}, timeout=NODE_OP_TIMEOUT, ret="active")


def api_portfw_del(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise ValueError("نود پیدا نشد")
    name = _pf_name(d["name"])
    r = node_call(n, "delete", "POST", {"name": name})
    if r.get("ok"):
        _tf_forget(n["id"], ["pf:" + name])
    _refresh_cache([n["id"]])
    return {"ok": bool(r.get("ok")), "msg": r.get("error", "")}


def _flat_ips(ping):
    return [ip for ips in (ping.get("ips") or {}).values() for ip in ips]


def _ping_both(A, B):
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    if not pa.get("ok"):
        raise ValueError(f"نودِ «{A['name']}» آفلاین است")
    if not pb.get("ok"):
        raise ValueError(f"نودِ «{B['name']}» آفلاین است")
    return pa, pb


def _guard_addr_on_another_iface(pa, pb, A, B, subnet, skip_ifaces):
    try:
        want = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return
    for node, ping in ((A, pa), (B, pb)):
        for iface, ips in ((ping.get("ips") or {})).items():
            if iface in skip_ifaces:
                continue
            for ip in ips:
                try:
                    addr = ipaddress.ip_address(str(ip).split("/")[0])
                except ValueError:
                    continue
                if addr.version == want.version and addr in want:
                    raise ValueError(
                        f"نودِ «{node['name']}» همین حالا {addr} را روی کارتِ «{iface}» دارد و با سابنتِ "
                        f"«{subnet}» هم‌پوشانی می‌کند. لینوکس این را رد نمی‌کند، ولی مسیرِ آن بازه دوتا "
                        f"می‌شود و ترافیک می‌تواند از همان کارت برود در حالی که تونل سبز نشان داده "
                        f"می‌شود. بازهٔ دیگری انتخاب کن یا آن آدرس را از «{iface}» بردار.")


def _guard_subnet_overlap(A, B, subnet, exclude_id=None):
    try:
        want = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return
    nodes = {A["id"], B["id"]}
    for L in load_links():
        if exclude_id is not None and L.get("id") == exclude_id:
            continue
        if not nodes & {L.get("a_node"), L.get("b_node")}:
            continue
        try:
            other = ipaddress.ip_network(str(L.get("subnet") or ""), strict=False)
        except ValueError:
            continue
        if want.version == other.version and want.overlaps(other):
            its = "" if other == want else f" ({other})"
            raise ValueError(f"سابنتِ «{subnet}» با تونلِ «{L.get('name')}»{its} روی یک نودِ مشترک "
                             f"هم‌پوشانی دارد؛ بازهٔ دیگری انتخاب کن")


def _guard_dup_pair(A, B, a_ip, b_ip, ttype, exclude_id=None):
    new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])
    for L in load_links():
        if exclude_id is not None and L.get("id") == exclude_id:
            continue
        same_pair = frozenset([(L.get("a_node"), L.get("a_ip")), (L.get("b_node"), L.get("b_ip"))]) == new_pair
        if L.get("type") == ttype and same_pair and ttype != "core":
            raise ValueError(f"یک تونلِ {ttype} با همین آی‌پی‌ها بینِ این دو نود از قبل هست")
        if ttype in IPIP_FAMILY and L.get("type") in IPIP_FAMILY and same_pair:
            raise ValueError(f"تونلِ «{L.get('name')}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.")


def _node_ip_tags(nid):
    n = get_node(nid)
    if not n:
        return []
    live = []
    for ip in _flat_ips(_cached_ping(nid)):
        if ip not in live:
            live.append(ip)
    peers = {}
    for L in load_links():
        for mine, theirs, pool in (("a_node", "b_name", "a_ip_pool"), ("b_node", "a_name", "b_ip_pool")):
            if L.get(mine) != nid:
                continue
            ent = {"node": L.get(theirs) or "", "type": L.get("type") or "", "name": L.get("name") or ""}
            side = "a_ip" if mine == "a_node" else "b_ip"
            for ip in ([L.get(side)] + (list(L.get(pool) or []) if L.get("ip_rotate") else [])):
                if ip and not any(e["name"] == ent["name"] for e in peers.setdefault(ip, [])):
                    peers[ip].append(ent)
    pf = {}
    only_ip = live[0] if len(live) == 1 else ""
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
        raise ValueError("پیدا نشد")
    return {"online": bool(_cached_ping(n["id"]).get("ok")), "ips": _node_ip_tags(n["id"])}


def api_link_rebuild_info(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise ValueError("تونل پیدا نشد")

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


def _proxy_nodes(nodes=None):
    out = {}
    for n in (load_nodes() if nodes is None else nodes):
        if n.get("proxy_on"):
            out.setdefault(str(n.get("proxy_id") or ""), []).append(n)
    return out


def _proxy_users(nodes=None):
    out = {pid: [n["name"] for n in ns] for pid, ns in _proxy_nodes(nodes).items()}
    own = str((get_settings() or {}).get("dl_proxy_id") or "").strip()
    if own:
        out.setdefault(own, []).append("پنل (دانلودِ خودش)")
    return out


def proxy_url(p):
    auth = ""
    if p.get("user"):
        q = lambda v: urllib.parse.quote(str(v or ""), safe="")
        auth = "%s:%s@" % (q(p["user"]), q(p.get("pass")))
    return "%s://%s%s:%d" % (p["scheme"], auth, p["host"], int(p["port"]))


def _proxy_row(p, users=None):
    st = _px_get(p["id"])
    return {"id": p["id"], "name": p["name"], "scheme": p["scheme"], "host": p["host"],
            "port": int(p["port"]), "user": p.get("user") or "", "has_pass": bool(p.get("pass")),
            "addr": "%s://%s:%d" % (p["scheme"], p["host"], int(p["port"])),
            "nodes": (users if users is not None else _proxy_users()).get(p["id"], []),
            "online": bool(st.get("ok")), "pending": not st, "status": st}


def api_proxies(d):
    users = _proxy_users()
    return {"proxies": [_proxy_row(p, users) for p in load_proxies()]}


def _proxy_name(d, taken):
    name = str(d.get("name") or "").strip()
    if not 1 <= len(name) <= 40:
        raise ValueError("نامِ پروکسی لازم است (حداکثر ۴۰ نویسه)")
    if name.lower() in taken:
        raise ValueError("پروکسیِ دیگری با همین نام هست")
    return name


def _proxy_fields(d):
    scheme = str(d.get("scheme") or "socks5").strip().lower()
    if scheme not in ("socks5", "http"):
        raise ValueError("نوعِ پروکسی باید socks5 یا http باشد")
    host = str(d.get("host") or "").strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise ValueError("آی‌پی یا هاستِ پروکسی نامعتبر است")
    try:
        port = int(str(d.get("port") or "").strip())
    except ValueError:
        raise ValueError("پورتِ پروکسی نامعتبر است (1 تا 65535)")
    if not 1 <= port <= 65535:
        raise ValueError("پورتِ پروکسی نامعتبر است (1 تا 65535)")
    user = str(d.get("user") or "").strip()
    pw = d.get("pass")
    pw = None if pw is None else str(pw)
    return scheme, host, port, user, pw


def api_proxy_add(d):
    scheme, host, port, user, pw = _proxy_fields(d)
    with _reg_lock:
        ps = load_proxies()
        p = {"id": secrets.token_hex(5), "name": _proxy_name(d, {x["name"].lower() for x in ps}),
             "scheme": scheme, "host": host, "port": port, "user": user, "pass": pw or ""}
        ps.append(p)
        save_json(PROXIES_FILE, ps)
    log_event("ok", "node", f"پروکسیِ «{p['name']}»: افزوده شد", f"{scheme}://{host}:{port}")
    return {"ok": True, "proxy": _proxy_row(p)}


def api_proxy_edit(d):
    _require(d, ["id"])
    scheme, host, port, user, pw = _proxy_fields(d)
    with _reg_lock:
        ps = load_proxies()
        p = next((x for x in ps if x["id"] == d["id"]), None)
        if not p:
            raise ValueError("پروکسی پیدا نشد")
        p["name"] = _proxy_name(d, {x["name"].lower() for x in ps if x["id"] != p["id"]})
        p["scheme"], p["host"], p["port"], p["user"] = scheme, host, port, user
        if pw:
            p["pass"] = pw
        elif not user:
            p["pass"] = ""
        save_json(PROXIES_FILE, ps)
    log_event("ok", "node", f"پروکسیِ «{p['name']}»: ویرایش شد", f"{scheme}://{host}:{port}")
    return {"ok": True, "proxy": _proxy_row(p)}


def api_proxy_test(d):
    _require(d, ["id"])
    p = get_proxy(str(d["id"]))
    if not p:
        raise ValueError("پروکسی پیدا نشد")
    out = _px_deep(p, _proxy_probe(p, timeout=8))
    _px_publish(p["id"], out)
    return out


def api_proxy_del(d):
    _require(d, ["id"])
    with _reg_lock:
        ps = load_proxies()
        p = next((x for x in ps if x["id"] == d["id"]), None)
        if not p:
            raise ValueError("پروکسی پیدا نشد")
        used = _proxy_users().get(p["id"], [])
        if used:
            raise ValueError("این پروکسی روی این نودها فعال است: " + "، ".join(used))
        save_json(PROXIES_FILE, [x for x in ps if x["id"] != p["id"]])
    log_event("ok", "node", f"پروکسیِ «{p['name']}»: حذف شد")
    return {"ok": True}


def api_settings(d):
    return get_settings()


def api_settings_set(d):
    with _settings_lock:
        obj = validate_settings(d or {})
        _settings.clear()
        _settings.update(obj)
        save_json(SETTINGS_FILE, obj)
    return {"ok": True, "settings": obj}


CHECKIN_CTR_FILE = os.path.join(CENTRAL_DIR, "checkin_ctr.json")
CHECKIN_CTR_PERSIST_MS = 60000

_checkin_ctr = {}
_checkin_ctr_saved = {}
_checkin_ctr_lock = threading.Lock()


def checkin_ctr_load():
    try:
        with open(CHECKIN_CTR_FILE) as f:
            stored = json.load(f)
    except Exception:
        return
    if not isinstance(stored, dict):
        return
    with _checkin_ctr_lock:
        for k, v in stored.items():
            try:
                _checkin_ctr[k] = _checkin_ctr_saved[k] = int(v)
            except (TypeError, ValueError):
                continue


def checkin_ctr_accept(nid, ctr):
    with _checkin_ctr_lock:
        if ctr <= _checkin_ctr.get(nid, 0):
            return False
        _checkin_ctr[nid] = ctr
        if ctr - _checkin_ctr_saved.get(nid, 0) < CHECKIN_CTR_PERSIST_MS:
            return True
        _checkin_ctr_saved[nid] = ctr
        snap = dict(_checkin_ctr_saved)
    save_json(CHECKIN_CTR_FILE, snap)
    return True


def _checkin_claimant(d):
    fp = str(d.get("fp") or "")
    sig = str(d.get("sig") or "")
    if len(fp) != 64 or not sig:
        return None
    signed = {k: v for k, v in d.items() if k != "sig"}
    msg = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    try:
        got = base64.b64decode(sig, validate=True)
    except Exception:
        return None
    for node in load_nodes():
        tok = str(node.get("token") or "")
        if not tok or not hmac.compare_digest(hashlib.sha256(tok.encode()).hexdigest(), fp):
            continue
        if not hmac.compare_digest(hmac.new(tok.encode(), msg, hashlib.sha256).digest(), got):
            return None
        try:
            ctr = int(d.get("ctr") or 0)
        except (TypeError, ValueError):
            return None
        return node if checkin_ctr_accept(node["id"], ctr) else None
    return None


def api_checkin_impl(source_ip, d):
    n = _checkin_claimant(d or {})
    if not n:
        return {"ok": False, "error": "درخواستِ نود امضا ندارد یا نود ناشناخته است"}
    tok = str(n.get("token", ""))
    with _reg_lock:
        n = next((x for x in load_nodes() if x["id"] == n["id"]), None)
        if not n:
            return {"ok": False, "error": "نودِ ناشناخته"}
        n_snap, host, port = dict(n), n.get("host"), int(n.get("port") or 0)
    want_host = source_ip if (source_ip and is_ipv4(source_ip)) else host
    try:
        want_port = int((d or {}).get("port") or 0)
    except (TypeError, ValueError):
        want_port = 0
    if not 1 <= want_port <= 65535:
        want_port = port
    if (want_host, want_port) == (host, port):
        _moved_clear(n_snap["id"])
        return {"ok": True, "updated": False, "host": host, "port": port}
    if node_call(n_snap, "ping", "GET", timeout=5).get("ok"):
        _moved_clear(n_snap["id"])
        return {"ok": True, "updated": False, "host": host, "port": port}
    probe = dict(n_snap)
    probe["host"], probe["port"] = want_host, want_port
    if not node_call(probe, "ping", "GET", timeout=5).get("ok"):
        return {"ok": False, "unconfirmed": True, "host": host, "port": port}
    if get_settings().get("reconcile_mode") != "auto":
        if _moved_note(n_snap["id"], n_snap.get("name") or "", host, want_host, want_port):
            log_event("warn", "node", f"نودِ «{n_snap.get('name')}»: جابه‌جاییِ نشانی",
                      f"از {host}:{port} به {want_host}:{want_port} رفته و از نشانیِ تازه جواب می‌دهد — روی"
                      " کارتِ نود نشانِ هشدار را بزن و «تنظیم به‌عنوانِ آی‌پیِ نود»، بعد تونل‌هایش را بازسازی کن."
                      " (برای انجامِ خودکار، حالتِ آشتی را «خودکار» بگذار.)")
        return {"ok": True, "updated": False, "host": host, "port": port, "moved_to": want_host}
    _moved_clear(n_snap["id"])
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if hmac.compare_digest(str(x.get("token", "")), tok)), None)
        if not n:
            return {"ok": False, "error": "نودِ ناشناخته"}
        n["host"], n["port"] = want_host, want_port
        host, port, nid = want_host, want_port, n["id"]
        save_json(NODES_FILE, nodes)
    _refresh_cache([nid])
    return {"ok": True, "updated": True, "host": host, "port": port}


ACT_KEEP = 20
ACT_KEEP_FAIL = 600

_acts = {}
_act_lock = threading.RLock()


class ActCancelled(Exception):
    pass


def act_step(h, step, i=0, n=0, stop=True, more=None):
    if h is None:
        return
    with _act_lock:
        if stop and h.get("cancel"):
            raise ActCancelled()
        h.update(step=step, si=i, sn=n, pct=int(i * 100 / n) if n else 0,
                 can=bool(stop if more is None else more))


def _act_prune():
    now = time.time()
    for k in [k for k, v in _acts.items() if v["state"] != "run"
              and now - v["ended"] > (ACT_KEEP_FAIL if v["state"] == "fail" else ACT_KEEP)]:
        _acts.pop(k, None)


def act_start(key, fn, target="", page="", ttype=""):
    with _act_lock:
        _act_prune()
        cur = _acts.get(key)
        if cur and cur["state"] == "run":
            raise ValueError("همین کار روی این مورد در جریان است — تا تمام‌شدنش صبر کن")
        h = {"key": key, "target": target, "page": page, "ttype": ttype,
             "state": "run", "step": "", "si": 0, "sn": 0, "pct": 0, "err": "", "note": "",
             "cancel": False, "can": True, "started": int(time.time()), "ended": 0}
        _acts[key] = h

    def run():
        try:
            res = fn(h)
            res = res if isinstance(res, dict) else {}
            bad = (res.get("msg") or res.get("error") or "") if res.get("ok") is False else ""
            with _act_lock:
                if bad:
                    h.update(state="fail", step="", err=str(bad)[:300], ended=int(time.time()))
                else:
                    h.update(state="done", step="", pct=100, si=h["sn"], can=False,
                             note=str(res.get("msg") or "")[:300], ended=int(time.time()))
        except ActCancelled:
            with _act_lock:
                h.update(state="cancel", step="", ended=int(time.time()))
        except Exception as e:
            with _act_lock:
                h.update(state="fail", step="", err=str(e)[:300], ended=int(time.time()))

    threading.Thread(target=run, daemon=True).start()
    return {"ok": True, "act": key}


def act_link(d, fn):
    lid = (d or {}).get("id")
    L = next((x for x in load_links() if x["id"] == lid), None)
    if not L:
        raise ValueError("تونل پیدا نشد")
    return act_start("link:" + str(lid), fn, target=L.get("name") or "")


def api_acts(_d):
    with _act_lock:
        _act_prune()
        out = {k: {x: y for x, y in v.items() if x != "cancel"} for k, v in _acts.items()}
    return {"ok": True, "acts": out, "now": int(time.time())}


def api_act_cancel(d):
    key = str((d or {}).get("act") or "")
    with _act_lock:
        h = _acts.get(key)
        if not h or h["state"] != "run":
            raise ValueError("این کار دیگر در جریان نیست")
        if not h.get("can"):
            raise ValueError("این کار از مرحله‌ای گذشته که بشود جلویش را گرفت — تا تمام‌شدنش صبر کن")
        h["cancel"] = True
        h["step"] = "در حالِ لغو…"
    return {"ok": True, "act": key}


def _dispatch(cmd, d):
    return API[cmd](d)


API = {
    "nodes": api_nodes, "node-names": api_node_names, "summary": api_summary, "next-port": api_next_port,
    "settings": api_settings, "settings-set": api_settings_set, "readiness": api_readiness,
    "node-add": api_node_add, "node-edit": api_node_edit, "node-del": api_node_del, "node-toggle": api_node_toggle,
    "node-install": api_node_install, "install-status": api_node_install_status,
    "node-test": api_node_test, "node-stats": api_node_stats, "node-kernel-tune": api_node_kernel_tune,
    "node-adopt-ip": api_node_adopt_ip, "node-ips": api_node_ips, "link-rebuild-info": api_link_rebuild_info,
    "traffic": api_node_traffic, "fleet": api_fleet,
    "create-tunnel": api_create_tunnel, "edit-link": api_edit_link, "check-link": api_check_link,
    "link-speed": api_link_speed,
    "proxies": api_proxies, "proxy-add": api_proxy_add, "proxy-edit": api_proxy_edit,
    "proxy-del": api_proxy_del, "proxy-test": api_proxy_test,
    "rebuild-link": api_rebuild_link, "restart-link": api_restart_link, "delete-link": api_delete_link, "link-toggle": api_link_toggle,
    "edge-status": api_edge_status,
    "pool-retest-now": api_pool_retest_now, "pool-select": api_pool_select,
    "peer-status": api_peer_status, "peer-retest-now": api_peer_retest_now, "peer-select": api_peer_select,
    "link-view": api_link_view, "traffic-reset": api_traffic_reset,
    "events": api_events, "events-clear": api_events_clear,
    "acts": api_acts, "act-cancel": api_act_cancel,
    "portfw": api_portfw, "portfw-list": api_portfw_list, "portfw-edit": api_portfw_edit,
    "portfw-next": api_portfw_next, "portfw-del": api_portfw_del,
    "agent-upload": api_agent_upload, "agent-info": api_agent_info,
    "update-agent": api_update_agent, "update-core": api_update_core,
    "agent-fetch-git": api_agent_fetch_git,
    "core-versions": api_core_versions, "core-check": api_core_check,
    "core-upload": api_core_upload, "core-delete-blob": api_core_delete_blob, "core-stage": api_core_stage, "core-stage-status": api_core_stage_status,
    "core-stage-cancel": api_core_stage_cancel, "push-status": api_push_status, "push-cancel": api_push_cancel, "push-pause": api_push_pause,
    "reorder": api_reorder, "link-tag": api_link_tag,
}
MUTATIONS = {"proxy-add", "proxy-edit", "proxy-del", "proxy-test", "push-cancel", "push-pause", "node-add", "node-install", "node-edit", "node-del", "node-toggle", "node-kernel-tune", "node-adopt-ip", "create-tunnel", "edit-link", "rebuild-link", "restart-link",
             "link-speed", "check-link", "node-test", "node-ips", "link-rebuild-info",
             "delete-link", "link-toggle", "edge-status", "pool-retest-now", "pool-select",
             "peer-status", "peer-retest-now", "peer-select",
             "link-view", "traffic-reset", "events-clear", "portfw", "portfw-edit", "portfw-next", "portfw-del",
             "agent-upload", "agent-fetch-git", "settings-set", "core-check", "core-upload", "core-stage",
             "core-delete-blob", "core-stage-cancel",
             "update-agent", "update-core",
             "reorder", "link-tag",
             "act-cancel"}


class HeaderDeadline:
    def __init__(self, raw, sock, idle):
        self.raw, self.sock, self.idle, self.until = raw, sock, idle, None

    def arm(self, budget):
        self.until = time.monotonic() + budget

    def disarm(self):
        self.until = None
        try:
            self.sock.settimeout(self.idle)
        except OSError:
            pass

    def _tick(self):
        if self.until is None:
            return
        left = self.until - time.monotonic()
        if left <= 0:
            raise TimeoutError("header deadline")
        try:
            self.sock.settimeout(left)
        except OSError:
            pass

    def readline(self, *a):
        self._tick()
        return self.raw.readline(*a)

    def read(self, *a):
        self._tick()
        return self.raw.read(*a)

    def __getattr__(self, name):
        return getattr(self.raw, name)


class Handler(BaseHTTPRequestHandler):
    server_version = "tnl-central"
    timeout = 60
    header_budget = 15

    def log_message(self, *a):
        pass

    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        self.rfile = HeaderDeadline(self.rfile, self.connection, self.timeout)

    def handle_one_request(self):
        self.rfile.arm(self.header_budget)
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        finally:
            self.rfile.disarm()

    def parse_request(self):
        got = BaseHTTPRequestHandler.parse_request(self)
        self.rfile.disarm()
        return got

    def _conf(self):
        return self.server.conf

    def _user(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return check_token(self._conf(), c["tnl_session"].value) if "tnl_session" in c else None

    SEND_CHUNK = 64 * 1024
    BIG_SEND_TIMEOUT = 120

    GZIP_MIN = 4096

    def _send(self, code, body, ctype="application/json", extra=None, big=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        data = body.encode() if isinstance(body, str) else body
        enc = ""
        if not big and len(data) >= self.GZIP_MIN and "gzip" in self.headers.get("Accept-Encoding", ""):
            data, enc = gzip.compress(data, 6), "gzip"
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if enc:
            self.send_header("Content-Encoding", enc)
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                         "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if not big:
            self.wfile.write(data)
            return
        sock = getattr(self, "connection", None)
        prev = sock.gettimeout() if sock else None
        if sock:
            sock.settimeout(self.BIG_SEND_TIMEOUT)
        try:
            mv = memoryview(data)
            for i in range(0, len(mv), self.SEND_CHUNK):
                self.wfile.write(mv[i:i + self.SEND_CHUNK])
        finally:
            if sock:
                sock.settimeout(prev)

    def _body(self, cap=1048576):
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            n = 0
        n = min(max(n, 0), cap)
        raw = self.rfile.read(n) if n > 0 else b""
        try:
            obj = json.loads(raw.decode()) if raw else {}
        except Exception:
            return {}
        return obj if isinstance(obj, dict) else {}

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML if self._user() else LOGIN_HTML, "text/html; charset=utf-8")
        elif path == "/api/dl":
            self._dl()
        elif path.startswith("/api/"):
            self._api(path[5:], "GET")
        else:
            self._send(404, {"error": "پیدا نشد"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/login":
            self._login()
        elif path == "/api/checkin":
            self._checkin()
        elif path == "/api/logout":
            self._body()
            conf = self._conf()
            if self._user():
                bump_sess_epoch(conf)
                self._auth_log("ok", "خروج از پنل انجام شد و همهٔ نشست‌های باز باطل شدند.")
            secure = "; Secure" if conf.get("tls") else ""
            self._send(200, {"ok": True}, extra={"Set-Cookie": "tnl_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" + secure})
        elif path.startswith("/api/"):
            self._api(path[5:], "POST")
        else:
            self._send(404, {"error": "پیدا نشد"})

    def _client_ip(self):
        peer = self.client_address[0]
        conf = self._conf()
        if not conf.get("tls"):
            return peer
        trusted = conf.get("trusted_proxies")
        if isinstance(trusted, list) and trusted:
            if peer not in trusted:
                return peer
            hops = set(trusted)
        else:
            try:
                if not ipaddress.ip_address(peer).is_loopback:
                    return peer
            except ValueError:
                return peer
            hops = set()
        chain = [h.strip() for h in (self.headers.get("X-Forwarded-For", "") or "").split(",") if h.strip()]
        while chain and chain[-1] in hops:
            chain.pop()
        return chain[-1] if chain and is_ip(chain[-1]) else peer

    def _auth_log(self, level, title, extra=None):
        ua = ua_clean(self.headers.get("User-Agent", "") or "")
        rows = ["از: %s" % self._client_ip()] + list(extra or [])
        b = ua_browser(ua)
        if b:
            rows.append("مرورگر: %s" % b)
        sysname = ua_system(ua)
        if sysname:
            rows.append("دستگاه: %s" % sysname)
        if ua:
            rows.append("نشانه: %s" % ua[:UA_MAX])
        log_event(level, "auth", title, "\n".join(rows))

    def _login(self):
        d = self._body()
        ip = self._client_ip()
        if rate_limited(ip):
            if note_blocked(ip):
                self._auth_log("bad", "تلاش برای ورود در حالی که این نشانی قفل است همچنان ادامه دارد.")
            self._send(429, {"error": "تلاشِ زیاد — چند دقیقه صبر کن"})
            return
        if not _login_gate.acquire(blocking=False):
            self._send(429, {"error": "تلاشِ زیاد — چند لحظه صبر کن"})
            return
        try:
            conf = self._conf()
            time.sleep(0.3)
            user_ok = hmac.compare_digest(str(d.get("user", "")), str(conf.get("user") or ""))
            pass_ok = verify_password(conf, str(d.get("pass", "")))
        finally:
            _login_gate.release()
        if user_ok and pass_ok:
            secure = "; Secure" if conf.get("tls") else ""
            cookie = f"tnl_session={make_token(conf, conf['user'])}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict{secure}"
            self._auth_log("ok", "ورود موفق به پنل انجام شد.")
            self._send(200, {"ok": True}, extra={"Set-Cookie": cookie})
        else:
            note_fail(ip)
            tries = fail_count(ip)
            who = "درست" if user_ok else "ناشناخته"
            if tries >= FAIL_LIMIT:
                self._auth_log("bad", "پس از %d تلاشِ ناموفق در %d دقیقه، ورود از این نشانی قفل شد."
                               % (tries, FAIL_WINDOW // 60),
                               ["نام کاربری: %s" % who])
            else:
                self._auth_log("warn", "یک تلاشِ ناموفق برای ورود ثبت شد؛ تلاشِ %d از %d مجاز."
                               % (tries, FAIL_LIMIT), ["نام کاربری: %s" % who])
            self._send(401, {"error": "نام کاربری یا رمز اشتباه است"})

    def _dl(self):
        ip = self._client_ip()
        if rate_limited(ip):
            self._send(429, {"error": "تلاشِ زیاد — چند دقیقه صبر کن"})
            return
        q = {k: v[0] for k, v in
             urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "").items()}
        if not _dl_ticket_node(q):
            note_fail(ip)
            self._send(401, {"error": "نشستِ شما منقضی شده — دوباره وارد شو"})
            return
        try:
            raw = _dl_artifact(q.get("k", ""), q.get("arch", ""))
        except Exception:
            raw = None
        if not raw:
            self._send(404, {"error": "چیزی روی پنل آماده نیست"})
            return
        start = _range_start(self.headers.get("Range", ""), len(raw))
        if start is None:
            self._send(416, {"error": "بازهٔ درخواستی نامعتبر است"}, extra={"Content-Range": "bytes */%d" % len(raw)})
            return
        if start:
            self._send(206, raw[start:], "application/octet-stream", big=True,
                       extra={"Accept-Ranges": "bytes",
                              "Content-Range": "bytes %d-%d/%d" % (start, len(raw) - 1, len(raw))})
            return
        self._send(200, raw, "application/octet-stream", big=True,
                   extra={"Accept-Ranges": "bytes"})

    def _checkin(self):
        ip = self._client_ip()
        if rate_limited(ip):
            self._send(429, {"error": "تلاشِ زیاد — چند دقیقه صبر کن"})
            return
        try:
            res = api_checkin_impl(self.client_address[0], self._body())
        except ValueError as e:
            self._send(400, {"error": str(e)})
            return
        except Exception:
            log_internal("checkin")
            self._send(500, {"error": "خطای داخلی"})
            return
        if not res.get("ok"):
            note_fail(ip)
        self._send(200 if res.get("ok") else 401, res)

    def _api(self, cmd, method):
        if not self._user():
            self._send(401, {"error": "وارد نشده‌اید"})
            return
        if cmd not in API:
            self._send(404, {"error": "مسیرِ ناشناخته"})
            return
        if cmd in MUTATIONS:
            if method != "POST":
                self._send(405, {"error": "این درخواست باید POST باشد"})
                return
            if self.headers.get("X-Requested-With") != "tnl-central":
                self._send(403, {"error": "درخواستِ نامعتبر"})
                return
        d = self._body(cap=20971520 if cmd == "core-upload" else 1048576) if method == "POST" else query_dict(self.path)
        try:
            self._send(200, _dispatch(cmd, d))
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception:
            log_internal("api %s" % cmd)
            self._send(500, {"error": "خطای داخلی"})


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
.navi .ctwrap{margin-inline-end:auto;display:flex;gap:4px;align-items:center;direction:ltr}  
.navi .ctwrap .ct{margin-inline-start:0}
.navi .ct.ctun{color:#fff;background:var(--acc);border-color:transparent;min-width:20px}  
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
.rgrip{display:none}
body.reord-on .rgrip{display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:27px;height:27px;border-radius:8px;color:var(--acc);background:color-mix(in srgb,var(--acc) 13%,transparent);cursor:grab;touch-action:none;-webkit-user-select:none;user-select:none;margin-inline-end:2px}
body.reord-on.rdragging .rgrip{cursor:grabbing}
body.reord-on .card[data-rid]{border-color:color-mix(in srgb,var(--acc) 32%,transparent)}
.reordbtn{flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;width:42px;height:42px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--sub);cursor:pointer;padding:0}
.reordbtn svg{width:19px;height:19px}
body.reord-on .reordbtn{background:var(--acc);color:#fff;border-color:transparent}
.grid .card{margin-bottom:0}
.card.acc{padding:0}
.card.acc.off{opacity:.72}
.chead{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;user-select:none}
.chead:hover{background:color-mix(in srgb,var(--acc) 4%,transparent)}
.hmain{display:flex;flex-direction:column;gap:4px;min-width:0;flex:1}
.hrow1{display:flex;align-items:center;gap:8px;min-width:0}
.hname{font-size:13.5px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:40%}
.ctag{font-size:10px;font-weight:800;padding:2px 8px;border-radius:20px;background:var(--field);color:var(--sub);flex:0 0 auto}
.ctag.core{background:var(--accw);color:var(--acc)}.ctag.c-udp{color:var(--acc);background:color-mix(in srgb,var(--acc) 13%,transparent)}.ctag.c-tcp{color:var(--ok);background:color-mix(in srgb,var(--ok) 14%,transparent)}.ctag.c-raw{color:var(--gold);background:color-mix(in srgb,var(--gold) 15%,transparent)}.ctag.c-ws{color:#0ea5e9;background:color-mix(in srgb,#0ea5e9 14%,transparent)}.ctag.c-http{color:#14b8a6;background:color-mix(in srgb,#14b8a6 14%,transparent)}.ctag.c-grpc{color:#ec4899;background:color-mix(in srgb,#ec4899 14%,transparent)}.ctag.c-dns{color:#f97316;background:color-mix(in srgb,#f97316 14%,transparent)}
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
body.reord-on .cbody{transition:none}   
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
.tag{font-size:10.5px;line-height:1.5;text-transform:uppercase;letter-spacing:.4px;border:1px solid color-mix(in srgb,var(--acc) 40%,transparent);color:var(--acc);border-radius:7px;padding:0 6px;font-weight:700}
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
.mssub{margin-right:auto;color:var(--sub);font-size:12px;direction:ltr;unicode-bidi:isolate}
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
.search:focus{outline:none;border-color:color-mix(in srgb,var(--acc) 55%,transparent);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}
@media(prefers-reduced-motion:no-preference){#view>*{animation:rise .45s cubic-bezier(.22,.61,.36,1) both}}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
@media(min-width:900px){
 #nodeList,#linkList,#pfList{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:start}
 #nodeList>.card,#linkList>.card,#pfList>.card{margin-bottom:0}
 #nodeList>.card.muted,#linkList>.card.muted,#pfList>.card.muted{grid-column:1/-1}
}
.sk{display:block;background:linear-gradient(90deg,var(--sk-base) 0%,var(--sk-base) 38%,var(--sk-hi) 50%,var(--sk-base) 62%,var(--sk-base) 100%);background-color:var(--sk-base);background-size:220% 100%;border-radius:7px;animation:shim 1.25s ease-in-out infinite}
@keyframes shim{from{background-position:200% 0}to{background-position:-200% 0}}
@media (prefers-reduced-motion:reduce){.sk{animation:none}}
@media(prefers-reduced-motion:reduce){.sk{animation:none}}
.logmore{cursor:pointer;text-align:center;font-weight:700}
.logmore:active{opacity:.6}
.logchips{display:flex;gap:8px;flex-wrap:nowrap;overflow-x:auto;overflow-y:hidden;margin:0 0 12px;padding:2px 1px 8px;-webkit-overflow-scrolling:touch;scrollbar-width:thin}
.logchips::-webkit-scrollbar{height:7px}
.logchips::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--sub) 40%,transparent);border-radius:99px}
.logchips::-webkit-scrollbar-track{background:transparent}
.fchip{flex:0 0 auto;font-size:12.5px;font-weight:600;color:var(--sub);background:var(--card);border:1px solid var(--bord);border-radius:999px;padding:6px 13px;cursor:pointer;display:flex;align-items:center;gap:7px;user-select:none;white-space:nowrap;transition:background .12s,color .12s,border-color .12s}
.fchip:hover{border-color:color-mix(in srgb,var(--acc) 45%,var(--bord))}
.fchip.on{color:#fff;background:var(--acc);border-color:var(--acc)}
.fchip .ct{font-size:10.5px;font-weight:800;background:color-mix(in srgb,var(--sub) 18%,transparent);border-radius:999px;padding:0 6px;min-width:17px;text-align:center}
.fchip.on .ct{background:rgba(255,255,255,.25);color:#fff}
.sodlog{
 --sod-ink:var(--tx);--sod-dim:var(--sub);--sod-line:var(--bord);--sod-face:var(--field);
 --sod-amber:#a4670f;--sod-amberw:rgba(198,132,26,.11);--sod-amberb:rgba(198,132,26,.28);
 --sod-bad:#c9443c;--sod-warn:#a4670f;--sod-ok:#22815b;
 background:var(--card);
 border:1px solid var(--sod-line);border-radius:14px;padding:4px 11px 8px;margin-top:2px;position:relative;overflow:hidden}
body.dark .sodlog{
 --sod-ink:#e2e9f2;--sod-dim:#6c7c92;--sod-line:#1b2534;--sod-face:#0e1520;
 --sod-amber:#f5a623;--sod-amberw:rgba(245,166,35,.12);--sod-amberb:rgba(245,166,35,.3);
 --sod-bad:#ff5f56;--sod-warn:#f5a623;--sod-ok:#3fd6a0;
 background:radial-gradient(150% 60% at 50% -14%,rgba(245,166,35,.10),transparent 62%),linear-gradient(#0b1017,#111926);
 border-color:#1b2534}
.sodlog .sodsweep{position:absolute;inset:0;pointer-events:none;overflow:hidden;display:none}
body.dark .sodlog .sodsweep{display:block}
.sodlog .sodsweep::after{content:'';position:absolute;left:0;right:0;height:140px;
 background:linear-gradient(180deg,transparent,rgba(245,166,35,.04),transparent);animation:sodsweep 8s linear infinite}
@keyframes sodsweep{from{top:-150px}to{top:100%}}
.sodlog h1{font-size:17px;font-weight:800;color:var(--sod-ink);margin:10px 2px 6px;display:flex;align-items:center;gap:9px}
.sodlog h1 .ic{width:19px;height:19px;stroke:var(--sod-amber)}
.sodlog p.sub{color:var(--sod-dim);font-size:12px;line-height:1.95;margin:0 2px 14px;max-width:60ch}
.sodlog .tbtnrow{margin:0 0 11px}
body .sodlog .chkall,body.dark .sodlog .chkall{background:transparent;color:var(--sod-dim);
 border:1px solid var(--sod-line);box-shadow:none;font-size:12px;font-weight:700;padding:8px 14px;border-radius:9px}
.sodlog .chkall:hover{color:var(--sod-bad);border-color:color-mix(in srgb,var(--sod-bad) 42%,var(--sod-line))}
.sodlog .chkall .ic{width:14px;height:14px}
.sodlog .toolbar{margin:0 0 11px}
.sodlog .search{background:var(--sod-face);border:1px solid var(--sod-line);color:var(--sod-ink);
 border-radius:9px;font-size:12.5px;padding:9px 12px}
.sodlog .search::placeholder{color:var(--sod-dim)}
.sodlog .search:focus{outline:none;border-color:var(--sod-amberb);box-shadow:0 0 0 3px var(--sod-amberw)}
.sodlog .logchips{margin:0 0 4px;padding-bottom:9px}
.sodlog .fchip{background:transparent;border:1px solid var(--sod-line);color:var(--sod-dim);
 font-size:12px;font-weight:600;border-radius:8px}
.sodlog .fchip:hover{border-color:var(--sod-amberb);color:var(--sod-ink)}
.sodlog .fchip.on{background:var(--sod-amberw);border-color:var(--sod-amberb);color:var(--sod-amber)}
.sodlog .fchip .ct{background:var(--sod-line);color:var(--sod-dim);font-size:10px}
.sodlog .fchip.on .ct{background:var(--sod-amberb);color:var(--sod-amber)}
.sodlog .logchips::-webkit-scrollbar-thumb{background:var(--sod-line)}
.sodlog #logList{border-top:1px solid var(--sod-line);padding-top:2px}
.sodlog .card.muted{background:transparent;border:1px dashed var(--sod-line);color:var(--sod-dim);
 box-shadow:none;font-size:12.5px;text-align:center;padding:14px}
.sodlog .sk{background:var(--sod-line)}
.sodev{display:grid;grid-template-columns:3px minmax(0,1fr);gap:12px;align-items:stretch;
 padding:13px 4px 14px;border-bottom:1px solid var(--sod-line);position:relative;background:transparent}
.sodev>div{min-width:0}
.sodev:last-of-type{border-bottom:0}
.sodev .sbar{border-radius:2px;background:var(--sev)}
body.dark .sodev .sbar{box-shadow:0 0 10px -1px var(--sev)}
.sodev .shead{display:flex;align-items:baseline;gap:9px;margin-bottom:6px}
.sodev .slv{font-size:9px;font-weight:800;letter-spacing:.07em;color:var(--sev)}
.sodev .stime{margin-inline-start:auto;font-size:10px;color:var(--sod-dim);font-variant-numeric:tabular-nums;
 direction:rtl;unicode-bidi:plaintext;font-family:inherit;white-space:nowrap}
.sodev .ssen{font-size:13px;line-height:2.05;font-weight:400;color:var(--sod-ink);overflow-wrap:anywhere}
.sodev.bad .ssen{font-weight:500}
.sodev .svals{display:flex;flex-wrap:wrap;gap:5px 9px;margin-top:8px;align-items:baseline}
.sodev .svals .sp{display:inline-flex;align-items:baseline;gap:5px;min-width:0;max-width:100%}
.sodev .sval{font-family:ui-monospace,Consolas,monospace;font-size:11px;direction:ltr;unicode-bidi:isolate;
 color:var(--sod-amber);background:var(--sod-amberw);border-radius:3px;padding:1px 6px;
 border:1px solid var(--sod-amberb);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
 min-width:0;flex:0 1 auto}
.sodev .sk2{color:var(--sod-dim);font-size:10.5px;flex:0 0 auto}
.sodev.bad{--sev:var(--sod-bad)}.sodev.warn{--sev:var(--sod-warn)}.sodev.ok{--sev:var(--sod-ok)}
.sodev.sodtap{cursor:pointer;border-radius:8px}
.sodev.sodtap:hover{background:var(--sod-amberw)}
.sodev.sodtap:focus-visible{outline:2px solid var(--sod-amber);outline-offset:-2px}
.sodev .sfold{display:none;margin-top:9px;padding-top:9px;border-top:1px dashed var(--sod-line);
 flex-direction:column;gap:5px}
.sodev.open .sfold{display:flex}
.sodev .sfold .sr{display:flex;gap:8px;align-items:baseline;font-size:11px;color:var(--sod-dim)}
.sodev .sfold .sr b{font-weight:600;flex:0 0 auto}
.sodev .sfold .sr span{font-family:ui-monospace,Consolas,monospace;font-size:10.5px;direction:ltr;
 unicode-bidi:isolate;color:var(--sod-ink);overflow-wrap:anywhere;min-width:0;flex:1 1 auto}
.sodev .smore{font-size:10.5px;color:var(--sod-amber);font-weight:700;margin-top:7px;display:inline-block}
.sodev .smore .less,.sodev.open .smore .more{display:none}
.sodev.open .smore .less{display:inline}
.sodlog .logmore{background:transparent;border:1px dashed var(--sod-line);color:var(--sod-dim);margin-top:9px}
.logcard{display:flex;margin-bottom:9px;padding:0;overflow:hidden;box-shadow:var(--sh-sm)}
.logcard .lstripe{width:4px;flex:0 0 auto}
.logcard .lbody{display:flex;gap:10px;align-items:flex-start;padding:11px 12px;flex:1;min-width:0}
.logcard .lico{width:26px;height:26px;border-radius:8px;display:grid;place-items:center;flex:0 0 auto;margin-top:1px}
.logcard .lico .ic{width:15px;height:15px}
.logcard .lmain{flex:1;min-width:0;display:flex;flex-direction:column;gap:6px}
.logcard .ltitle{font-size:13px;font-weight:800;line-height:1.6;overflow-wrap:anywhere;color:var(--tx)}
.logcard .lhead{display:flex;gap:8px;align-items:flex-start;justify-content:space-between}
.logcard .ltime{flex:0 0 auto;color:var(--sub);font-size:10.5px;white-space:nowrap;margin-top:2px}
.lfromto{display:flex;flex-direction:column;gap:5px}
.lft{display:flex;align-items:baseline;gap:6px;min-width:0}
.lft .k{flex:0 0 auto;font-size:11px;color:var(--sub);text-align:start}
.lft .v{flex:0 1 auto;max-width:100%;min-width:0;direction:ltr;unicode-bidi:isolate;text-align:left;
  font-size:11.5px;line-height:1.8;padding:4px 9px;border-radius:8px;background:var(--field);
  border:1px solid var(--bord);color:var(--tx);overflow-wrap:anywhere;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
.lft.to .v{color:var(--acc);background:var(--accw);border-color:color-mix(in srgb,var(--acc) 30%,transparent)}
.ep{white-space:nowrap}
.ep-a{padding:0 5px;opacity:.65}
.lnote{font-size:11.5px;color:var(--sub);line-height:1.85;overflow-wrap:anywhere}
.lfold .lfbody{display:none;margin-top:7px}
.lfold.open .lfbody{display:block}
.logcard.logtap{cursor:pointer}
.logcard.logtap:hover{border-color:color-mix(in srgb,var(--acc) 38%,transparent)}
.logcard.logtap:focus-visible{outline:2px solid var(--acc);outline-offset:2px}
.lcat{font-size:10px;font-weight:700;border-radius:999px;padding:1px 8px;flex:0 0 auto;white-space:nowrap;line-height:1.7}
.lcat-tunnel{color:#4d80f0;background:color-mix(in srgb,#4d80f0 15%,transparent)}
.lcat-rot{color:#12a5b8;background:color-mix(in srgb,#12a5b8 16%,transparent)}
.lcat-ech{color:#8a63f0;background:color-mix(in srgb,#8a63f0 16%,transparent)}
.lcat-node{color:var(--gold);background:color-mix(in srgb,var(--gold) 16%,transparent)}
.lcat-sys{color:var(--sub);background:color-mix(in srgb,var(--sub) 15%,transparent)}
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
.mfoot.hug .primary,.mfoot.hug .ghost{flex:0 0 auto}
.lpill{display:inline-flex;align-items:center;gap:5px;font-size:10.5px;font-weight:700;color:var(--ok);background:var(--okw);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent);border-radius:20px;padding:2px 8px}
.lpill .pd{width:6px;height:6px;border-radius:50%;background:var(--ok);animation:lpulse 1.4s infinite}
.pushbar{height:6px;border-radius:4px;background:var(--field);border:1px solid var(--bord);overflow:hidden;margin-top:6px}
.pushbar>i{display:block;height:100%;width:0;background:var(--acc);transition:width .42s linear}
.pushbar.ok>i{background:var(--ok)}.pushbar.err>i{background:var(--bad)}
.mvwarn{flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;width:27px;height:27px;padding:0;margin-inline-start:7px;border-radius:9px;cursor:pointer;background:color-mix(in srgb,#e0894f 16%,transparent);border:1px solid color-mix(in srgb,#e0894f 45%,transparent);animation:mvpulse 1.7s ease-in-out infinite}
.mvwarn svg{width:15px;height:15px;stroke:#e0894f;fill:none;stroke-width:2.1}
.mvwarn:active{transform:scale(.94)}
@keyframes mvpulse{0%,100%{box-shadow:0 0 0 0 color-mix(in srgb,#e0894f 42%,transparent)}50%{box-shadow:0 0 0 5px transparent}}
.medi.warn{background:color-mix(in srgb,#e0894f 16%,transparent);border-color:color-mix(in srgb,#e0894f 38%,transparent)}
.medi.warn svg{stroke:#e0894f}
.plbl{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:11px;color:var(--sub);margin-top:5px}
.plbl b{font-variant-numeric:tabular-nums;font-weight:700;margin-inline-start:auto}
.lpill.off{color:var(--sub);background:transparent;border-color:var(--bord)}
.lpill.off .pd{background:var(--sub);animation:none}
@keyframes lpulse{0%,100%{opacity:1}50%{opacity:.25}}
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
.kt-desc{font-size:12.5px;line-height:1.85;color:var(--sub);margin-bottom:13px}
.nd-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.nd-tile{display:flex;flex-direction:column;gap:2px;background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:9px 10px;min-width:0}
.nd-tile.nd-wide{grid-column:1/-1}
.nd-tile .medi{color:var(--acc)}.nd-tile .medi .ic{width:15px;height:15px}
.nd-tile>span{font-size:11px;color:var(--sub)}
.nd-tile b{font-size:12.5px;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-variant-numeric:tabular-nums}
.nd-tile b.ltr{direction:ltr;text-align:right}
.nd-off{display:flex;flex-direction:column;align-items:center;gap:6px;text-align:center;padding:26px 10px;background:var(--badw);border:1px solid var(--bord);border-radius:12px}
.nd-off .ic{width:30px;height:30px;color:var(--bad)}.nd-off b{font-size:14px;color:var(--tx)}.nd-off span{font-size:12px;color:var(--sub)}
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
#view .gauges{margin-bottom:0}#view .ttiles{margin-bottom:0}   
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
.ltraf{margin-top:10px;padding-top:9px;border-top:1px dashed var(--bord);display:flex;align-items:center;gap:13px;font-size:12px;font-variant-numeric:tabular-nums}
.ndtraf{margin:0 14px;padding:9px 0 12px}.ltraf .tot{color:var(--sub);margin-inline-start:auto;display:flex;align-items:center;gap:6px}
.iso{direction:ltr;unicode-bidi:isolate}   
.tot .iso{display:inline-flex;gap:8px}
.act.flip{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 40%,transparent)}
.act.reset{color:var(--gold);border-color:color-mix(in srgb,var(--gold) 40%,transparent)}
.nchips{display:grid;grid-template-columns:auto auto;justify-content:start;gap:7px 16px;margin-top:9px}
.nchip{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;color:var(--sub)}
.nchip b{color:var(--tx);font-weight:700}.nchip .ic{width:13px;height:13px;color:var(--sub)}
.upwrap{margin-top:11px}
.uptop{display:flex;align-items:center;font-size:11.5px;color:var(--sub);margin-bottom:6px}.uptop b{color:var(--tx)}.uptop .r{margin-inline-start:auto}
.upbar{display:flex;gap:2px;height:22px;direction:ltr}
.upbar i{flex:1;border-radius:2px;background:var(--ok);min-width:1px}.upbar i.d{background:var(--bad)}.upbar i.g{background:color-mix(in srgb,var(--sub) 28%,transparent)}
.drop{border:1.5px dashed color-mix(in srgb,var(--acc) 45%,transparent);border-radius:13px;padding:18px;text-align:center;background:var(--accw);color:var(--sub);font-size:12.5px;cursor:pointer;margin-top:4px}.drop b{color:var(--acc)}
.banner{display:flex;align-items:center;gap:12px}.banner .v{font-size:13.5px;font-weight:800}
.stpage{--sc-h:38px;--sc-w:186px;--sc-g:12px}
.stgrid>.card{margin-bottom:var(--sc-g)}
@media(min-width:900px){.stgrid{column-count:2;column-gap:var(--sc-g)}
 .stgrid>.card{break-inside:avoid}}
.opgrid{display:grid;grid-template-columns:1fr;gap:var(--sc-g);align-items:stretch}
@media(min-width:900px){.opgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
.sg{padding:0;overflow:hidden}
.sghd{display:flex;align-items:center;gap:9px;padding:13px 14px;border-bottom:1px solid var(--bord)}
.sghd .sgt{width:30px;height:30px;border-radius:9px;display:inline-flex;align-items:center;justify-content:center;
  flex:none;background:var(--scbg);color:var(--sc)}
.sghd .sgt .ic{width:15px;height:15px}
.sghd b{font-size:13.5px;font-weight:800}
.sghd .schip{margin-inline-start:auto;font-size:10.5px;font-weight:800;padding:2px 9px;border-radius:20px;
  background:var(--scbg);color:var(--sc);white-space:nowrap}
.sc-panel{--sc:var(--acc);--scbg:var(--accw)}
.sc-conn{--sc:var(--acc2);--scbg:color-mix(in srgb,var(--acc2) 13%,transparent)}
.sc-pool{--sc:var(--gold);--scbg:var(--warnw)}
.sc-perf{--sc:#8b5cf6;--scbg:color-mix(in srgb,#8b5cf6 13%,transparent)}
.sgb{padding:2px 14px 12px}
.sr{padding:8px 0;border-bottom:1px dashed var(--bord)}
.sr:last-child{border-bottom:0}
.srtop{display:flex;align-items:center;gap:10px;min-height:var(--sc-h)}
.srlbl{flex:1;min-width:0;font-size:13px;font-weight:700}
.srlbl u{text-decoration:none;color:var(--sub);font-weight:600}
.srq{flex:none;width:22px;height:22px;border-radius:50%;border:1.5px solid var(--bord);background:var(--field);
  color:var(--sub);font-size:11px;line-height:1;cursor:pointer;padding:0;font-family:inherit}
.srq:hover{border-color:var(--acc);color:var(--acc)}
.sr.exp-open .srq{background:var(--acc);border-color:var(--acc);color:#fff}
.srctl{flex:none;width:var(--sc-w);max-width:52%}
.srctl>*{width:100%;height:var(--sc-h);margin:0}
.srctl input.search{min-width:0;padding:0 12px;border-radius:10px;font-variant-numeric:tabular-nums}
.srctl .setfield{padding:0 12px;border-radius:10px}
.srctl .msbtn{padding:0 12px;border-radius:10px}
.srctl .seg2{gap:4px;padding:3px;background:var(--field);border:1px solid var(--bord);border-radius:10px}
.srctl .seg2 .segopt{padding:0;border:0;background:transparent;border-radius:7px;display:flex;
  align-items:center;justify-content:center}
.srctl .seg2 .segopt.on{background:var(--card);color:var(--acc);box-shadow:var(--sh-sm)}
.srctl input.wtxt{max-width:none;text-align:left;direction:ltr;font-family:ui-monospace,Consolas,monospace;font-size:12px}
.srexp{max-height:0;overflow:hidden;opacity:0;transition:max-height .28s ease,opacity .2s,margin .2s;
  background:var(--field);border-radius:11px;padding:0 12px}
.sr.exp-open .srexp{max-height:300px;opacity:1;margin-top:9px;padding:10px 12px}
.srexp p{margin:0;font-size:12.5px;line-height:1.75}
.srexp .srex{margin-top:5px;color:var(--sub)}
.srexp .srex b{color:var(--acc);font-weight:700}
.srnote{margin:8px 2px 0;font-size:11px;line-height:1.85;color:var(--sub)}
.stsave{position:sticky;bottom:10px;z-index:5;display:flex;align-items:center;justify-content:flex-end;gap:9px;flex-wrap:wrap;margin-top:var(--sc-g);
  padding:9px 13px;border-radius:14px;background:var(--card);border:1px solid var(--bord);box-shadow:var(--dsh)}
.stnote{margin:2px 2px 10px;font-size:11px;line-height:1.85;color:var(--sub)}
.stsave button{margin:0;flex:none;height:var(--sc-h);padding:0 15px;border-radius:10px;font-size:12.5px;
  display:inline-flex;align-items:center;gap:6px}
.stsave .msg{flex:none;margin:0}
.opc{padding:14px;display:flex;flex-direction:column;gap:10px}
.opc .ophd{display:flex;align-items:center;gap:9px}
.opc .ophd .sgt{width:30px;height:30px;border-radius:9px;display:inline-flex;align-items:center;
  justify-content:center;flex:none;background:var(--scbg);color:var(--sc)}
.opc .ophd .sgt .ic{width:15px;height:15px}
.opc .ophd b{font-size:13.5px;font-weight:800}
.opc .ophd .grow{flex:1}
.opmeta{display:flex;flex-wrap:wrap;gap:4px 9px;align-items:center;font-size:11.5px;color:var(--sub);
  background:var(--field);border:1px solid var(--bord);border-radius:11px;padding:8px 11px;min-height:var(--sc-h)}
.opmeta .sep{width:3px;height:3px;border-radius:50%;background:var(--sub);opacity:.5}
.oprow{display:flex;gap:8px;align-items:center}
.oprow>.primary,.oprow>.ghost,.oprow>.corcheck{margin:0;height:var(--sc-h);border-radius:10px;font-size:12.5px;
  display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:0 13px}
.oprow>.primary,.oprow>.ghost{flex:1;min-width:0}
.oprow>.corcheck,.oprow>.opdel{flex:0 0 auto;white-space:nowrap}
.oprow>.opdel{width:var(--sc-h);padding:0;color:var(--bad);border-color:color-mix(in srgb,var(--bad) 32%,transparent)}
.oprow>#cor_ver_box{flex:1;min-width:0}
.oprow>#cor_ver_box .msbtn{height:var(--sc-h);border-radius:10px;padding:0 12px;margin:0;width:100%}
.oprow .ic{width:14px;height:14px}
.corempty{flex:1;min-width:0;font-size:12px;color:var(--sub);line-height:1.7}
.opdlv label{display:block;margin:0 2px 6px;font-size:11.5px;color:var(--sub)}
.opdlv .seg2{margin:0;gap:6px}
.opdlv .seg2 .segopt{padding:8px 6px;border-radius:10px}
.opgo{width:100%;margin:auto 0 0;height:var(--sc-h);border-radius:10px;font-size:13px;display:inline-flex;
  align-items:center;justify-content:center;gap:7px}
.opgo .ic{width:15px;height:15px}
.ophint{font-size:10.5px;color:var(--sub);line-height:1.7;margin:0}
#agList{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:var(--sc-g);align-items:stretch}
.nx{display:flex;flex-direction:column;gap:9px;background:var(--card);border:1px solid var(--bord);
  border-radius:14px;padding:11px 13px;box-shadow:var(--dsh)}
.nxh{display:flex;align-items:flex-start;gap:8px;min-height:22px}
.nxh .ndot{margin-top:5px}
.nxh .nmwrap{min-width:0;display:flex;flex-direction:column;gap:1px}
.nxh .nm{font-weight:800;font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nxh .nxhost{font-size:11px;color:var(--sub);font-family:ui-monospace,Consolas,monospace;direction:ltr;
  text-align:right;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nxv{display:flex;gap:6px;flex-wrap:wrap;direction:ltr;justify-content:flex-end}
.nxv .vp{display:inline-flex;align-items:center;gap:4px;height:25px;padding:0 8px;border-radius:8px;
  background:var(--field);border:1px solid var(--bord);font-size:11px;font-weight:700;
  font-family:ui-monospace,Consolas,monospace}
.nxv .vp .ic{width:12px;height:12px}
.nxv .vp.ok{background:var(--okw);border-color:transparent;color:var(--ok)}
.nxv .vp.up{background:var(--warnw);border-color:transparent;color:var(--gold)}
.nxv .vp.na{background:var(--badw);border-color:transparent;color:var(--bad)}
.nxv .vp.offl{color:var(--sub)}
.nxa{display:flex;gap:7px;margin-top:auto}
.nxa .ib{width:34px;height:34px;border-radius:10px}
.nx .agres{margin:0;min-height:0;font-size:11.5px}
.nx .agres:empty{display:none}   
.nx .pushbar{margin-top:0}
.rdbar{display:flex;align-items:center;gap:10px;margin:0 0 12px;padding:11px 13px;border-radius:13px;
  background:color-mix(in srgb,var(--gold) 12%,var(--card));border:1px solid color-mix(in srgb,var(--gold) 38%,transparent)}
.rdbar .ic{width:17px;height:17px;flex:0 0 auto;stroke:var(--gold)}
.rdbar .rdtx{display:flex;flex-direction:column;gap:2px;min-width:0;flex:1}
.rdbar b{font-size:12.5px;font-weight:800}
.rdbar span{font-size:11px;color:var(--sub);line-height:1.6}
.rdbar button{margin:0;flex:0 0 auto;padding:8px 12px;font-size:11.5px;border-radius:10px}
.cn-stale{color:var(--gold)}
.ib{width:32px;height:32px;border-radius:10px;border:1px solid var(--bord);background:var(--glass);color:var(--tx);display:inline-flex;align-items:center;justify-content:center;padding:0;margin:0;cursor:pointer}
.ib .ic{width:15px;height:15px}
.ib.up{background:color-mix(in srgb,var(--gold) 15%,transparent);color:var(--gold);border-color:color-mix(in srgb,var(--gold) 34%,transparent)}
.ib:disabled{opacity:.42;cursor:not-allowed}
.pfab{position:fixed;bottom:16px;left:50%;transform:translateX(-50%);z-index:40;display:flex;align-items:center;gap:7px;padding:6px 8px;border-radius:999px;background:var(--card);border:1px solid color-mix(in srgb,var(--acc) 55%,transparent);box-shadow:var(--dsh)}
.pfab .pfn{font-size:11.5px;font-weight:800;font-variant-numeric:tabular-nums;white-space:nowrap;padding-inline-start:4px}
.pfab .pfn s{text-decoration:none;color:var(--sub);font-weight:700}
.pfb{width:30px;height:30px;border-radius:50%;border:1px solid var(--bord);background:var(--glass);color:var(--tx);display:inline-flex;align-items:center;justify-content:center;padding:0;margin:0;flex:0 0 auto;cursor:pointer}
.pfb .ic{width:14px;height:14px}
.pfb.stop{border-color:color-mix(in srgb,var(--bad) 50%,transparent);color:var(--bad)}
.pfb:disabled{opacity:.35;cursor:not-allowed}
body.pushing .toast{bottom:74px}
.nact.iconly{gap:6px;display:grid;grid-auto-flow:column;grid-auto-columns:minmax(0,1fr)}
.nact.iconly .act{padding:8px 0;justify-content:center}
.nact.iconly .act .ic{width:15px;height:15px}
.chkall{display:inline-flex;align-items:center;gap:6px;background:#2f9e6f;color:#fff;border:0;font-weight:800;font-size:13px;padding:12px 18px;border-radius:12px;cursor:pointer;font-family:inherit;box-shadow:0 9px 20px -11px color-mix(in srgb,var(--ok) 70%,transparent)}
body.dark .chkall{background:#1f7a56}   
.chkall .ic{width:15px;height:15px}
.chkall:active{transform:scale(.97)}
.tbtnrow{display:flex;gap:8px;margin:14px 0 10px;flex-wrap:wrap}
.tbtnrow>button{flex:0 1 auto;min-width:0;display:inline-flex;align-items:center;justify-content:center;
  gap:6px;margin:0;font-size:12.5px;line-height:1.2;padding:9px 15px;min-height:38px;border-radius:10px}
.tbtnrow>button.primary{flex:0 1 auto}
.tbtnrow>button .ic{width:14px;height:14px}
.tbtnrow>button.ghost{background:var(--glass);border:1px solid var(--bord);color:var(--tx);font-weight:700}
.tbtnrow>button.ghost:hover{background:var(--field);border-color:var(--sub)}
.tbtnrow>button .ic{width:15px;height:15px}
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
.tninfo{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:center;margin-top:2px;direction:ltr}
.tninfo>*{direction:rtl}   
.tnnode{background:var(--field);border:1px solid var(--bord);border-radius:12px;padding:10px 12px;min-width:0}
.tnnode.st-ok{border-color:var(--ok)}
.tnnode.st-warn{border-color:var(--gold)}
.tnnode.st-bad{border-color:var(--bad)}
.tnnode.st-na{border-color:var(--bord)}
.tnend .stat:empty,.tnhead .stat:empty{display:none}
.tnhead{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:5px}
.tnnode .tnn{font-size:13px;font-weight:800;color:var(--tx);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.tnnode .tna{font-size:13px;font-weight:700;color:var(--sub);overflow-wrap:anywhere}
.arow{margin-top:11px;padding-top:10px;border-top:1px dashed var(--bord);display:flex;align-items:center;gap:9px;font-size:11.5px;color:var(--sub);flex-wrap:wrap}
.ast{font-size:10px;font-weight:800;padding:3px 9px;border-radius:20px;flex:0 0 auto;display:inline-flex;align-items:center;gap:5px}
.ast.run{color:var(--acc);background:var(--accw)}
.ast.cancel{color:var(--gold);background:var(--goldw)}
.ast.fail{color:var(--bad);background:var(--badw)}
.ast.done{color:var(--ok);background:var(--okw)}
.astep{flex:1 1 auto;min-width:0;line-height:1.7;color:var(--tx);font-weight:600;overflow-wrap:anywhere}
.astep.sw{animation:astepin .34s cubic-bezier(.22,.7,.3,1)}
@keyframes astepin{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:none}}
.aclock{font-family:ui-monospace,Consolas,monospace;font-variant-numeric:tabular-nums;font-size:11px;color:var(--sub);flex:0 0 auto}
.abar{flex:1 1 100%;height:5px;border-radius:3px;background:var(--bord);overflow:hidden}
.abar>i{display:block;height:100%;width:0;background:var(--acc);border-radius:3px;transition:width .6s cubic-bezier(.4,0,.2,1)}
.abar.cancel>i{background:var(--gold)}.abar.fail>i{background:var(--bad)}.abar.done>i{background:var(--ok)}
.abar.spin>i{width:38%;background:linear-gradient(90deg,transparent,var(--acc),transparent);transition:none;animation:asweep 1.25s ease-in-out infinite}
@keyframes asweep{from{transform:translateX(-100%)}to{transform:translateX(263%)}}
.abtn{flex:0 0 auto;font:inherit;font-size:11px;font-weight:700;cursor:pointer;padding:5px 11px;border-radius:9px;border:1px solid var(--bord);background:var(--field);color:var(--sub);transition:.15s}
.abtn:hover{color:var(--tx);border-color:var(--sub)}
.abtn.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 35%,transparent)}
.abtn.danger:hover{background:var(--badw)}
.apulse{width:7px;height:7px;border-radius:50%;background:var(--acc);flex:0 0 auto;animation:jp 1.5s ease-in-out infinite}
@keyframes jp{0%,100%{opacity:.35;transform:scale(.8)}50%{opacity:1;transform:scale(1.15)}}
.card.acting::after{content:'';position:absolute;top:0;left:0;height:2px;width:34%;border-radius:2px;pointer-events:none;
 background:linear-gradient(90deg,transparent,var(--acc),transparent);animation:acardsweep 1.9s ease-in-out infinite}
@keyframes acardsweep{from{transform:translateX(-100%)}to{transform:translateX(194%)}}
.card.acting .tninfo,.card.acting .enmeta{opacity:.72}
@media (prefers-reduced-motion:reduce){.apulse{animation:none;opacity:.9}.abar>i{transition:none}
 .abar.spin>i,.card.acting::after,.astep.sw{animation:none}}
.cpv{cursor:pointer;-webkit-tap-highlight-color:transparent;text-decoration:underline dotted color-mix(in srgb,currentColor 45%,transparent);text-underline-offset:3px}
.cpv:active{opacity:.5}
@keyframes jcardin{from{opacity:0;transform:translateY(-8px) scale(.985)}to{opacity:1;transform:none}}
.card.jin{animation:jcardin .34s cubic-bezier(.22,.7,.3,1)}
@keyframes jbreathe{0%,100%{opacity:.72}50%{opacity:1}}
.card.apend .hname{animation:jbreathe 2.1s ease-in-out infinite}
@media (prefers-reduced-motion:reduce){.card.jin{animation:none}.card.apend .hname{animation:none}}
.tnarrow{color:var(--acc);font-weight:800;font-size:19px;text-align:center}
.card.node .noff{flex:1 1 auto;display:flex;align-items:center;justify-content:center;gap:6px;flex-wrap:wrap;text-align:center;padding:9px 10px;margin:9px 0 1px;background:var(--badw);border:1px dashed var(--bord);border-radius:10px}
.card.node .noff .ic{width:15px;height:15px;color:var(--bad)}
.card.node .noff b{font-size:12px;color:var(--bad)}.card.node .noff span{font-size:11px;color:var(--sub)}
button.act.ok{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 42%,transparent)}
button.act.info{color:var(--acc);border-color:color-mix(in srgb,var(--acc) 38%,transparent)}
button.act.warn{color:#fb923c;border-color:color-mix(in srgb,#fb923c 46%,transparent)}
button.act.danger{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 40%,transparent)}
@media(prefers-reduced-motion:reduce){.modal.wide{animation:none}.gfill{transition:none}.lpill .pd{animation:none}}
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
.ippeer{display:inline-flex;align-items:center;gap:4px;font-size:11px;font-weight:700;padding:4px 10px;border-radius:8px;background:var(--accw);color:var(--acc);cursor:pointer;user-select:none;transition:transform .12s,background .15s,color .15s}
.ippeer:active{transform:scale(.95)}
.ippeer .ipn{display:inline-flex;align-items:center;gap:4px}
.ippeer .ipi{display:none}
.ippeer.show .ipn{display:none}
.ippeer.show .ipi{display:inline}
.ippeer.show{background:var(--acc);color:#fff}
.seg{display:flex;background:var(--field);border:1px solid var(--bord);border-radius:12px;padding:4px;gap:4px;margin-bottom:14px}
.seg button{flex:1;border:0;background:transparent;color:var(--sub);font-family:inherit;font-weight:800;font-size:13px;padding:9px;border-radius:9px;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:6px}
.seg button.on{background:var(--card);color:var(--acc);box-shadow:0 1px 3px rgba(20,30,50,.12)}
.seg button .ic{width:15px;height:15px}
.autonote{display:flex;gap:8px;align-items:flex-start;font-size:11.5px;color:var(--sub);background:var(--warnw);border:1px solid color-mix(in srgb,var(--gold) 30%,transparent);border-radius:11px;padding:10px 12px;margin-bottom:13px}
.autonote .ic{color:var(--gold);flex:0 0 auto;margin-top:1px}
.warncap{display:flex;gap:8px;align-items:flex-start;font-size:11px;line-height:1.65;border-radius:10px;padding:9px 11px;margin-top:10px}
.warncap .ic{flex:0 0 auto;margin-top:1px}
.warncap.ok{background:var(--okw);color:var(--ok);border:1px solid color-mix(in srgb,var(--ok) 30%,transparent)}
.warncap.no{background:var(--badw);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad) 30%,transparent)}
.warncap.wait{background:var(--field);color:var(--sub);border:1px solid var(--bord)}
.warncap b{font-weight:800}
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
.setfield{width:100%;display:flex;align-items:center;padding:11px 13px;border:1px solid var(--bord);border-radius:12px;background:var(--field);color:var(--tx);font-family:inherit;font-weight:800;font-size:14px;cursor:pointer}
.pxhd{display:flex;align-items:center;justify-content:space-between;gap:10px}
.pxurl{font-size:12.5px;color:var(--sub);margin-top:6px;word-break:break-all}
.pxused{font-size:11.5px;color:var(--sub);margin-top:6px}
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
.modal.sssheet{max-width:360px;padding:8px}
.sspop{display:flex;flex-direction:column;min-height:0}
.sspop .sspopq{margin-bottom:8px;flex:0 0 auto}
.sspoplist{overflow:auto;max-height:min(58vh,420px);min-height:0}
.toast .ic{width:15px;height:15px;display:inline-block;vertical-align:-3px;margin-inline-end:4px}
.tag.core{color:#8b5cf6;border-color:color-mix(in srgb,#8b5cf6 40%,transparent);background:color-mix(in srgb,#8b5cf6 12%,transparent)}
body.dark .tag.core{color:#a78bfa}
.tag.obfs{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent);text-transform:none;letter-spacing:0;padding:0 5px;border-radius:6px;font-size:10px;line-height:1.5}
.tglbox{display:flex;align-items:center;gap:10px;margin-top:10px;padding:11px 12px;border:1px solid var(--bord);border-radius:12px;background:var(--field)}
.tglbox .tt{flex:1}.tglbox .tt b{font-size:12.5px;font-weight:700;display:block}
.tglbox .tt small{font-size:10.5px;color:var(--sub);display:block;margin-top:1px;line-height:1.5}
.ctabs{display:flex;gap:8px;margin:2px 0 6px}
.ctab{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;height:42px;border-radius:12px;background:var(--field);color:var(--sub);border:1px solid transparent;font-weight:700;font-size:13.5px;cursor:pointer;font-family:inherit;transition:.15s}
.ctab svg{width:16px;height:16px}
.ctab.on{background:var(--accw);color:var(--acc);border-color:color-mix(in srgb,var(--acc) 30%,transparent)}
.ctabp{display:none}.ctabp.on{display:block}
.rpool{border:1px solid var(--bord);border-radius:11px;overflow:hidden;background:var(--field)}
.rrow{display:flex;align-items:center;gap:7px;padding:0 9px;min-height:40px;border-bottom:1px solid var(--bord);cursor:pointer;user-select:none}
.rrow:last-child{border-bottom:none}
.rrow .sic{width:18px;height:18px;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;color:var(--sub);opacity:.4}
.rrow .sic svg{width:18px;height:18px}
.rrow.on{box-shadow:inset -3px 0 0 var(--ok)}
.rrow.on .sic{color:var(--ok);opacity:1}
.rrow .rip{flex:1;text-align:center;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;direction:ltr;letter-spacing:-.02em}
.pempty{text-align:center;font-size:11px;color:var(--sub);padding:14px 0}
.pacc{border:1px solid var(--bord);border-radius:12px;overflow:hidden;background:var(--field);margin-top:12px}
.pacchd{display:flex;align-items:center;justify-content:space-between;padding:11px 13px;cursor:pointer;gap:10px}
.pacct{font-size:13px;font-weight:700}
.pacchd .pacctl{display:flex;align-items:center;gap:8px;flex:1;min-width:0}   
.paccs{margin-inline-start:auto;display:flex;gap:5px;flex-wrap:wrap;justify-content:flex-end}
.pbadge{font-size:10px;font-weight:700;border-radius:99px;padding:1px 8px}
.pbadge.ok{background:rgba(78,201,154,.16);color:var(--ok)}
.pbadge.bad{background:rgba(240,115,106,.16);color:var(--bad)}
.pbadge.warn{background:var(--warnw);color:var(--gold)}
.pchev{color:var(--sub);transition:transform .2s;font-size:12px;flex:0 0 auto}
.pchev.open{transform:rotate(180deg)}
.paccbody{padding:0 11px 11px}
.erow{display:flex;align-items:center;gap:8px;padding:8px 10px;border:1px solid var(--bord);border-radius:10px;border-inline-start-width:3px;border-inline-start-color:var(--bord);flex-wrap:wrap;row-gap:7px}
.erow.ok{border-inline-start-color:var(--ok)}
.erow.warn{border-inline-start-color:var(--gold)}
.erow.bad{border-inline-start-color:var(--bad)}
.erow.dead .eip{text-decoration:line-through;color:var(--sub)}
.estat{flex:0 0 auto;display:grid;place-items:center}
.estat .ic{width:16px;height:16px}
.estat.ok{color:var(--ok)}.estat.warn{color:var(--gold)}.estat.bad{color:var(--bad)}.estat.mut{color:var(--sub)}
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
.pbar>i{display:block;height:100%;background:var(--gold);transition:width .5s linear}
.pbar.bad>i{background:var(--bad)}
.peerlive{margin-top:12px;display:flex;flex-direction:column}
.peerlive .pacc{margin-top:8px}                       
.peerlive .pllabel{margin-bottom:2px}
.peerlive .pllabel{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:700}
.peerlive .rpool{border:none;background:transparent;display:flex;flex-direction:column;gap:6px;overflow:visible}
.erow.pcol{flex-direction:column;align-items:stretch;flex-wrap:nowrap;row-gap:0}
.erow.pcol .etop{display:flex;align-items:center;gap:8px}
.erow.pcol .ecd{display:flex;align-items:center;gap:8px;margin-top:7px;margin-inline-start:24px}
.erow.pcol .ecd .pbar{flex:1 1 auto;width:auto;max-width:180px}
.eib.aim.on{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 55%,transparent);background:color-mix(in srgb,var(--ok) 12%,transparent)}
.tglbox.dis{opacity:.45;pointer-events:none}
.portlock{opacity:.42;pointer-events:none}
.card.tagd{position:relative}
.card.tagd::before{content:'';position:absolute;inset:0;border-radius:inherit;padding:1px;
 background:linear-gradient(140deg,var(--tga),var(--tgb));pointer-events:none;
 -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
 -webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);
 mask-composite:exclude}
.card.tagpick{transform:scale(.985)}
.card.tagpick,.card.tagpick *{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
.tagov,.tagov *{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
.tagov{position:fixed;inset:0;z-index:70;background:rgba(8,11,18,.34);display:flex;align-items:center;justify-content:center;padding:20px}
.tagbox{background:var(--card);border:1px solid var(--bord);border-radius:18px;padding:16px 18px;box-shadow:0 18px 50px rgba(8,11,18,.28);max-width:340px;width:100%}
.tagbox .tgt{font-size:12.5px;font-weight:700;margin-bottom:12px;text-align:center}
.tagpal{display:flex;gap:10px;justify-content:center}
.tagdot{width:40px;height:40px;border-radius:50%;border:2px solid transparent;cursor:pointer;flex:0 0 auto;padding:0}
.tagdot.on{border-color:var(--tx);box-shadow:0 0 0 3px var(--field)}
.tagnone{margin-top:14px;width:100%;border-radius:12px;padding:9px;border:1px solid var(--bord);background:var(--field);color:var(--sub);font:inherit;font-size:12px;cursor:pointer}
.rl{font-size:8px;font-weight:800;border-radius:5px;padding:1px 4px;letter-spacing:.2px;flex:0 0 auto}
.rl.srv{color:var(--acc);background:color-mix(in srgb,var(--acc) 18%,transparent)}  
.rl.cli{color:var(--gold);background:var(--goldw)}
.enc{color:var(--bad);font-weight:700;display:inline-flex;align-items:center;gap:3px}.enc .ic{width:12px;height:12px}
.enmeta{display:grid;grid-template-columns:1fr auto 1fr;gap:8px;align-items:start;margin-top:11px;font-size:11.5px;color:var(--sub)}
.tninfo + .enmeta{direction:ltr}
.tninfo + .enmeta>*{direction:rtl}   
.enmeta .emcol{min-width:0;display:flex;flex-direction:column;gap:4px}
.enmeta .emcol>div{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.enmeta .emcol>div.wrap{white-space:normal;overflow:visible}
.enmeta .emcol b{color:var(--tx);font-weight:700}
.enmeta .earrow{visibility:hidden}
.enmeta .emwarn{display:block;grid-column:1/-1;text-align:center;margin-top:2px}
.enmeta .emwarn .ic{display:inline-block;vertical-align:-3px;margin-top:0;margin-left:5px}
.enmeta .emcol>div.feat{display:flex;align-items:center;gap:3px;flex-wrap:wrap;white-space:normal;overflow:visible}
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
.cedge .echip.ip{flex:0 0 auto}      
.cedge .echip.dom{flex:0 1 auto;font-weight:600;color:var(--sub)}   
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
.seg2 .segopt.on{border-color:var(--acc);background:var(--accw)}
.seg2 .segopt.on span{color:color-mix(in srgb,var(--acc) 80%,var(--sub))}
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
   <a class="navi" data-t="proxies"><span class="ic" data-ic="globe"></span> <span class="nlbl">پروکسی‌ها</span><span class="ct" id="ct_proxies"></span></a>
   <a class="navi" data-t="tunnels"><span class="ic" data-ic="link"></span> <span class="nlbl">تانل‌های سیستمی</span><span class="ct" id="ct_tunnels"></span></a>
   <a class="navi" data-t="portfw"><span class="ic" data-ic="fwd"></span> <span class="nlbl">پورت‌فوروارد</span><span class="ct" id="ct_portfw"></span></a>
   <a class="navi" data-t="core"><span class="ic" data-ic="cpu"></span> <span class="nlbl">هستهٔ اختصاصی</span><span class="ct" id="ct_core"></span></a>
   <a class="navi" data-t="logs"><span class="ic" data-ic="list"></span> <span class="nlbl">لاگ</span><span class="ctwrap"><span class="ct" id="ct_logs"></span><span class="ct ctun" id="ct_logs_un" style="display:none"></span></span></a>
   <a class="navi" data-t="settings"><span class="ic" data-ic="cog"></span> <span class="nlbl">تنظیمات</span></a>
   <a class="navi" data-t="logout"><span class="ic" data-ic="logout"></span> <span class="nlbl">خروج</span></a>
  </nav>
 </aside>
 <main class="main">
  <div class="mtop"><button class="hb" onclick="drawer(true)"><span class="ic" data-ic="menu"></span></button><div class="sbrand"><span class="logo" style="width:28px;height:28px;font-size:14px"><span class="ic" data-ic="shield"></span></span><span>TUNNEL-MANAGER</span></div><button class="hb" id="thbtn2" onclick="toggleTheme()"><span class="ic" data-ic="moon"></span></button></div>
  <div id="rdbar"></div>
  <div id="view"></div>
 </main>
</div>
<div id="pushFab"></div>
<script>
var _corS={},_eeS={};   
var I18N={fa:{
 nav_overview:"نمای کلی",nav_nodes:"نودها",nav_proxies:"پروکسی‌ها",
 a_pending:"در حالِ ساخت",a_working:"در حالِ انجام…",a_cancel:"لغو",a_dismiss:"بستن",
 a_st_run:"در حالِ انجام",a_st_done:"انجام شد",a_st_fail:"ناموفق",a_st_cancel:"لغو شد",
 a_took:"در {t} تمام شد",a_stopped:"پیش از تمام‌شدن لغو شد",
 px_sub:"پروکسی‌هایی که نودها می‌توانند ترافیکشان را از آن‌ها رد کنند",px_add:"افزودنِ پروکسی",
 px_edit_t:"ویرایشِ پروکسی",px_add_t:"پروکسیِ تازه",px_name:"نام",
 px_type:"نوعِ پروکسی",px_ip:"آی‌پی",px_port:"پورت",px_user:"یوزرنیم",px_pass:"پسورد",px_opt:"اختیاری",
 px_pass_keep:"خالی = پسوردِ فعلی بماند",
 px_hint:"یوزر و پسوردِ خالی = بدونِ احراز. پسورد روی مرکزی می‌ماند و هیچ‌وقت به مرورگر فرستاده نمی‌شود.",
 px_empty:"هنوز پروکسی‌ای نساخته‌ای",px_used_by:"در حالِ استفاده روی: ",px_used_none:"روی هیچ نودی فعال نیست",
 px_del_confirm:"این پروکسی حذف شود؟",px_saved:"پروکسی ذخیره شد",px_deleted:"پروکسی حذف شد",
 ag_p_wait:"در نوبت",
 ups_of:"گامِ {i} از {n}",ups_check:"در حالِ بررسی",ups_deliver:"در حالِ فرستادن",ups_install:"در حالِ نصب",
 ups_stage:"دانلودِ هسته روی پنل",ups_paused:"متوقف شده — منتظرِ ادامه",ups_stagewait:"منتظرِ دانلودِ هسته روی پنل",ups_start:"در حالِ شروع",ups_restarted:"{n} تونل دوباره بالا آمد",
 upe_offline:"نود آفلاین است",upe_node_gone:"نود حذف شد",upe_failed:"ناموفق",upe_panel:"خطای پنل",
 upe_unbuildable:"چیزی برای فرستادن به این نود نبود",upe_sha_mismatch:"بایت‌ها با چک‌سام نخواندند",
 upe_bad_signature:"امضای پنل تأیید نشد",upe_too_small:"فایل برای یک هسته خیلی کوچک است",
 upe_download_failed:"نود نتوانست دانلود کند",upe_nothing_staged:"چیزی روی نود آماده نبود",
 ag_p_ok:"انجام شد",ag_p_same:"همین نسخه بود",ag_p_err:"ناموفق",

 ag_p_lost:"ردیابی قطع شد — آپلود روی پنل ادامه دارد؛ صفحه را باز کن تا دوباره وصل شود",
 ag_p_skip:"لغو شد",ag_p_cancel:"لغوِ آپلود",ag_p_cancel_q:"آپلود لغو شود؟ نودهای در نوبت اصلاً نمی‌روند و نودی که همین حالا وسطِ فرستادنِ بایت‌هاست نیمه‌کاره بریده می‌شود — نسخهٔ فعلی‌اش دست‌نخورده می‌ماند، چون نود چیزی را که کامل نرسیده نصب نمی‌کند. ولی نودی که بایت‌هایش کامل رسیده و دارد اعمال می‌کند برگشت‌پذیر نیست: آن کارش را تمام می‌کند. برای اینکه فقط نودهای بعدی نروند، «توقف» را بزن.",
 ag_p_cancel_none:"چیزی برای لغو نمانده — بایت‌ها رسیده‌اند و نودها دارند اعمال می‌کنند؛ این مرحله برگشت‌پذیر نیست",
 ag_p_pause:"توقفِ آپلود — آپلودهای جاری تمام می‌شوند، نودهای بعدی نمی‌روند",ag_p_resume:"ازسرگیریِ آپلود",
 ag_p_none:"همهٔ نودها همین نسخه را دارند — چیزی فرستاده نشد",
 px_test:"تستِ اتصال",px_testing:"در حالِ تست…",px_up:"وصل شد",
 nd_proxy_on:"ترافیکِ این نود از پروکسی برود",nd_proxy_pick:"پروکسی",
 nd_proxy_none:"پروکسی‌ای نساخته‌ای — اول از بخشِ «پروکسی‌ها» یکی بساز",
 nd_proxy_all:"هر درخواستی به این نود — کنترلِ ایجنت و SSHِ نصب — از این پروکسی رد می‌شود.",nav_tunnels:"تانل‌های سیستمی",nav_portfw:"پورت‌فوروارد",nav_core:"هستهٔ اختصاصی",nav_logs:"لاگ",nav_settings:"تنظیمات",nav_logout:"خروج",
 logs_title:"لاگِ سیستم",logs_sub:"رویدادهای خودکارِ __LOGKEEPH__ ساعتِ گذشته، حداکثر __LOGMAX__ تا — قطع/وصلِ نود و تونل و تغییرِ خودکارِ لبه، به‌علاوهٔ چند کارِ دستی که روی کلِ فلیت اثر دارند (لغوِ آپلود و افزودن/ویرایش/حذفِ پروکسی). قدیمی‌تر از آن (یا فراتر از این تعداد، روی فلیتِ شلوغ) خودکار پاک می‌شود",logs_empty:"هنوز رویدادی ثبت نشده",logs_clear:"پاک‌کردنِ لاگ",logs_cleared:"لاگ پاک شد",logs_clear_confirm:"همهٔ لاگ‌ها پاک شوند؟",
 logs_search:"جست‌وجو در متنِ لاگ و جزئیاتش…",logs_more:"{n} موردِ قدیمی‌ترِ دیگر — برای دیدنشان بزن",logs_no_match:"چیزی با این عبارت پیدا نشد",
 logc_all:"همه",logc_tunnel:"تونل",logc_rot:"چرخش/استخر",logc_ech:"ECH",logc_node:"نود",logc_auth:"ورود",logc_sys:"سیستم",sod_bad:"بحرانی",sod_warn:"هشدار",sod_ok:"عادی",sod_more:"جزئیاتِ بیشتر",sod_less:"بستن",logc_err:"فقط خطاها",
 brand_sub:"کنترل فلیت",theme:"تم",
 save:"ذخیره",save_rebuild:"ذخیره و بازسازی",cancel:"انصراف",add:"افزودن",close:"بستن",confirm_del:"تأیید و حذف",yes_all:"بله، همه",
 online:"آنلاین",offline:"آفلاین",failed:"ناموفق",saving:"در حال ذخیره…",checking:"در حال بررسی…",loading:"در حال بارگذاری…",
 no_results:"موردی یافت نشد.",live:"زنده",select:"انتخاب کنید",ip:"آی‌پی",err_check:"خطا در بررسی",not_available:"در دسترس نیست",
search:"جستجو…",
 disk:"دیسک",cpu_cores:"تعداد هسته",os:"سیستم‌عامل",uptime:"آپ‌تایم",host:"میزبان",proxy:"پروکسی",
 ov_sub:"آمارِ دقیقِ فلیت — بدونِ میانگینِ گمراه‌کننده",ov_health:"سلامتِ فلیت",ov_attention:"نیازمندِ توجه",ov_allnodes:"همهٔ نودها یک‌نگاه",
 st_healthy:"سالم",st_warn:"هشدار (>60٪)",st_crit:"بحرانی (>85٪)",ov_central:"سرورِ مرکزی (این پنل)",ov_worst:"پرمصرف‌ترین نودها",
 ov_tunbreak:"وضعیتِ تفکیکیِ تونل‌ها",ov_traffic:"ترافیکِ فلیت",ov_uptime:"آپ‌تایم",ov_rxtot:"↓ ورودیِ کل",ov_txtot:"↑ خروجیِ کل",
 ov_uptime_avg:"میانگینِ آپ‌تایم",ov_down_nodes:"نود قطعی داشته",ov_chip_node:"نود",ov_chip_uplink:"لینکِ سالم",ov_chip_tunnel:"تونل",ov_chip_alert:"هشدار",ov_chip_noalert:"بدونِ هشدار",
 ov_noalert:"همه‌چیز مرتب است — هشداری نیست",ov_no_nodes:"نودی نیست",ov_no_online:"نودِ آنلاینی نیست",ov_no_tunnel:"تونلی نیست",
 ov_heat_note:"نود · هر میله = بدترین متریکِ آن نود (دیسک/رم/CPU) · خاکستری = آفلاین",
 tst_connected:"متصل",tst_noping:"بدونِ پینگ",tst_down:"قطع",tst_rebuild:"نیازمندِ بازسازی",
 tst_dead:"هیچ‌کدام از بسته‌های آزمایشی برنگشت — چیزی از این تونل رد نمی‌شود",
 ov_worst_q:"بدترین کیفیت: تونلِ",ov_loss:"اتلاف",ov_ping:"پینگ",ov_all_good:"کیفیتِ همهٔ تونل‌ها خوب است",ov_fleet_ping:"میانگینِ پینگِ فلیت",
 ov_uptime_lbl:"میانگینِ آپ‌تایمِ",ov_hours_recent:"ساعتِ اخیر",load:"لود",
 nodes_sub:"افزودن و وضعیت زنده‌ی نودها",add_node:"افزودن نود",nodes_fleet:"نودهای فلیت",nodes_search:"جستجوی نام یا آی‌پی…",
 nodes_empty:"هنوز نودی اضافه نشده — دکمهٔ «افزودن نود» بالا.",
 tip_test:"تست",tip_details:"مشخصات",tip_edit:"ویرایش",tip_delete:"حذف",tip_tune:"تیونینگِ شبکه",tip_nreset:"صفر کردنِ ترافیکِ نود",nreset_confirm:"مجموعِ ترافیکِ این نود صفر شود؟ فقط شمارشِ پنل پاک می‌شود — خودِ نود و تونل‌هایش دست نمی‌خورند.",
 kt_title:"تیونینگِ کرنل (BBR)",kt_sub:"شتاب‌دهیِ شبکه‌ی سرور",kt_desc:"BBR + fq + بافرهای بزرگ‌تر را روی این سرور روشن می‌کند. روی مسیرِ پرتلفات و پرتأخیرِ ایران، سرعتِ حامل‌های TCP را بالا می‌برد. اختیاری و برگشت‌پذیر.",kt_state:"وضعیت",kt_cc:"کنترلِ ازدحام",kt_qdisc:"صف‌بندی",kt_on:"روشن",kt_off:"خاموش",kt_enable:"روشن کردن",kt_disable:"خاموش کردن",kt_nobbr:"کرنلِ این سرور BBR ندارد — روشن‌کردن ممکن نیست.",kt_working:"در حال اعمال…",kt_enabled:"تیونینگ روشن شد",kt_disabled:"تیونینگ خاموش شد",
 nd_tunnels:"تونل",nd_portfw:"پورت‌فوروارد",nd_agent:"ایجنت",nd_core:"هسته",nd_core_missing:"نصب نیست",nd_ctrlproxy:"پروکسیِ کنترل",nd_toggle:"نمایش/پنهان در لیستِ ساختِ تونل و پورت‌فوروارد (اتصال قطع نمی‌شود)",nd_hidden:"از لیستِ ساخت پنهان شد",nd_shown:"به لیستِ ساخت برگشت",
 uptime_bar:"آپتایم",node_min2:"حداقل 2 نودِ آنلاین لازم است",
 tun_sub:"هر لینک نود‌به‌نود جداگانه است — بررسی، ویرایش و حذف مستقل دارد",add_tunnel:"افزودن تونل",check_all:"بررسی اتصال همگانی",
 tun_search:"جستجوی نام نود / نوع / شناسه…",tun_empty:"هنوز لینکی نیست — دکمهٔ «افزودن تونل» بالا.",
 st_off:"خاموش",st_disc:"قطع",reorder_err:"ذخیرهٔ ترتیب ناموفق بود",tag_title:"رنگِ نشانه‌گذاری",tag_clear:"بدونِ رنگ",tag_err:"ذخیرهٔ رنگ ناموفق بود",reord_t:"حالتِ جابه‌جایی کارت‌ها",tip_ping:"تستِ پینگ",tip_speed:"تستِ سرعتِ خودِ تونل",speed_run:"در حال اندازه‌گیریِ سرعت روی خودِ تونل…",speed_done:"سرعتِ تونل",speed_how:"{s} ثانیه در هر جهت · {n} جریان",speed_up:"آپلود",speed_down:"دانلود",speed_note:"روی آی‌پیِ داخلیِ تونل اندازه گرفته شد، پس عددْ ظرفیتِ خودِ تونل است نه خطِ اینترنت. عددِ گزارش‌شده چیزی است که سرِ دیگر <b>تحویل گرفته</b>، نه چیزی که فرستنده در سوکت ریخته.",tip_reset:"ریستِ حجمِ کل",tip_rebuild:"بازسازی",tip_restart:"ری‌استارتِ هسته",restart_confirm:"هستهٔ این تونل روی هر دو نود ری‌استارت شود؟ کانفیگ و استخرِ آی‌پی دست نمی‌خورد.",restart_yes:"ری‌استارت",restarted:"هسته ری‌استارت شد",restart_failed:"ری‌استارت ناموفق بود",tip_toggle:"روشن/خاموشِ تونل",
 subnet:"سابنت",tid:"شناسه",iface:"اینترفیس",ttype:"نوع",udp_port:"پورتِ UDP",enc:"رمزنگاری",encrypted:"رمزنگاری‌شده",total:"مجموع",
 no_live_side:"دادهٔ زنده از این سر نیست",tun_off_note:"این تونل خاموش است — اینترفیس down شده. توگلِ بالا را بزن تا دوباره بالا بیاید.",
 turned_on:"روشن شد",turned_off:"خاموش شد",
 core_sub:"تونل‌های هستهٔ اختصاصی (Go) — حالتِ packet/core با رمزنگاریِ داخلی، جدا از تونل‌های سیستمی",core_add:"تونلِ هسته",
 core_search:"جستجوی نام نود / شناسه…",core_empty:"هنوز تونلِ هسته‌ای نیست — دکمهٔ «تونلِ هسته» بالا را بزن.",
 server:"سرور",client:"کلاینت",profile:"پروفایل",port:"پورت",port_dst:"پورتِ مقصد",port_src:"پورتِ مبدأ",port_src_rand:"رندوم",caps:"قابلیت‌ها",no_cipher:"بدونِ رمز",cdn_edge:"لبهٔ CDN",active_edge:"لبهٔ فعالِ فعلی (زنده)",cor_tab_ips:"آی‌پی‌ها",cor_tab_set:"تنظیمات",
 err_rt_nomod:"کرنلِ این نود این نوع تونل را ندارد — ماژولش لود نیست",
 err_rt_exists:"این اینترفیس یا آدرس از قبل روی نود هست",
 err_rt_unsupported:"کرنلِ این نود این کار را پشتیبانی نمی‌کند",
 err_rt_notperm:"کرنل اجازه نداد",err_rt_noroute:"از این نود مسیری به آن آدرس نیست",
 err_rt_addrused:"این آدرس از قبل روی نود گرفته شده",err_rt_nodev:"چنین اینترفیسی روی نود نیست",
 err_rt_badarg:"کرنل ورودی را نپذیرفت",err_rt_other:"کرنل رد کرد",
 err_kernel:"کرنل درخواست را رد کرد",err_refused:"اتصال رد شد",err_noroute:"مسیری به میزبان نیست",
 err_dns:"نامِ میزبان پیدا نشد",err_reset:"اتصال از آن سر قطع شد",err_timeout:"وقت تمام شد",
 err_unreach:"در دسترس نبود",err_denied:"اجازه داده نشد",err_nocmd:"این دستور روی نود نیست",
 err_nofile:"چنین فایل یا مسیری نیست",err_afam:"این نوع آدرس پشتیبانی نمی‌شود",
 err_pipe:"اتصال وسطِ کار قطع شد",err_cert_unknown:"گواهیِ TLSِ این سرور شناخته نشد",err_cert_expired:"گواهیِ TLSِ این سرور منقضی شده",err_eof:"اتصال بی‌جواب بسته شد",err_cert:"مشکلِ گواهیِ TLS",
 copied:"کپی شد",copy_fail:"کپی نشد",tip_copy:"بزن تا کپی شود",port_src_fixed:"ثابت",
 pf_sub:"فوروارد پورت روی یک نود (با چرخشِ چند مقصد)",pf_add:"افزودن پورت‌فوروارد",pf_active:"پورت‌فورواردهای فعال",pf_search:"جستجوی نود / نام…",
 pf_empty:"پورت‌فورواردی نیست.",pf_no_online:"هیچ نودِ آنلاینی نیست",
 set_sub:"رفتار خودکارِ پنل و بازه‌های بررسی",set_saved:"تنظیمات ذخیره شد",
 t_reset_done:"حجمِ کل صفر شد",
}};
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 ram:"رم",cores_word:"هسته",unit_mb:"م‌ب",unit_gb:"گیگ",refresh2s:"به‌روزرسانیِ زنده",
 nd_title:"مشخصات نود",nd_status:"وضعیت نود",nd_off_last:"آفلاین — آخرین مقادیر",nd_conn_test:"تستِ اتصال",nd_traffic:"ترافیک",nd_ips:"آی‌پی‌ها",
 ip_leg:"تونل‌شده / پورت‌فوروارد / آزاد",ip_none:"آی‌پی‌ای گزارش نشد",free:"آزاد",nd_no_tp:"تونل یا پورت‌فورواردی روی این نود نیست",nd_ctrlproxy:"پروکسیِ کنترل",
 nd_edit:"ویرایشِ نود",f_name:"نام",f_host_ip:"هاست / آی‌پی",f_port:"پورت",f_token:"توکن",tok_keep:"خالی = توکن فعلی بماند",
 node_name_ascii:"نامِ نود فقط با حروفِ انگلیسی، عدد، فاصله و «_ . -» و حداکثر ۴۰ کاراکتر — نامِ فارسی روی نود قابلِ استفاده نیست",need_nhp:"نام، هاست و پورت لازم است",
 
 
 
 connecting_dots:"در حال اتصال…",
 need_all_nhpt:"لطفاً نام، هاست، پورت و توکن را پر کن",node_added_checking:"نود اضافه شد — وضعیتش تا چند لحظهٔ دیگر روی کارتش می‌آید",
 inst_done:"انجام شد",
 nd_del:"حذفِ نود",del_how:"حذفِ نود تونل‌هایش را هم می‌بندد — سمتِ خودش و سمتِ نودهای مقابل:",
 del_wipe_t:"پاک‌سازیِ کاملِ نود",del_wipe_s:"روی خودِ سرورِ نود همه‌چیز پاک می‌شود: همهٔ تونل‌ها، ایجنت، سرویسِ systemd، توکن و فایل‌های JSON. سمتِ نودهای مقابل هم تونل‌ها بسته می‌شوند. برگشت‌ناپذیر است!",
 del_wipe_confirm:"مطمئنی؟ کلِ نود روی سرور — تونل‌ها، ایجنت و توکن — پاک می‌شود و برگشت ندارد.",del_wipe_yes:"بله، پاک کن",
 del_wiping:"در حال پاک‌سازیِ نود…",node_wiped:"نود کاملاً پاک‌سازی شد",
 del_force_ask:"این تونل به‌اجبار حذف شود؟ سمتِ نودِ در دسترس همین حالا بسته می‌شود، و سمتِ نودِ قطع وقتی برگشت خودکار پاک می‌شود.",del_force_yes:"حذفِ اجباری",
 del_wipe_force_ask:"سرور قطع است — «پاک‌سازیِ اجباری»؟ رکوردِ نود و لینک‌هایش از پنل پاک و سمتِ نودهای مقابلِ در دسترس بسته می‌شوند؛ خودِ این سرور اگر روزی برگشت باید دستی پاک شود.",del_wipe_force_yes:"پاک‌سازیِ اجباری",del_wipe_force_s:"سرور قطع است، پس روی خودش کاری نمی‌شود کرد: رکوردِ نود و لینک‌هایش از پنل پاک و سمتِ نودهای مقابلِ در دسترس بسته می‌شوند. برگشت‌ناپذیر است!",del_force_wiping:"در حالِ پاک‌سازیِ اجباری…",node_force_wiped:"نود از پنل پاک شد (سرور در دسترس نبود؛ سمتِ مقابل بسته شد)",
 pend_del_t:"حذفِ معلق — وقتی این نود دوباره وصل شد، خودکار پاک‌سازی می‌شود",
 test_testing:"در حال تست…",
 t_side_off:"نود آفلاین (به agent وصل نشد — شاید پورت/توکن عوض شده)",t_side_notun:"قطع (تونل روی نود نیست)",t_side_ifdown:"قطع (اینترفیس پایین)",
 t_side_conn:"متصل",t_side_nopingr:"پینگ جواب نداد",t_side_up_unk:"بالا (پینگ نامشخص)",t_ping:"پینگ",t_loss:"اتلاف",
 no_tunnel_check:"تونلی برای بررسی نیست",checkall_done:"بررسیِ همهٔ تونل‌ها تمام شد",
 rebuild_confirm:"این تونل روی هر دو نود از نو ساخته شود؟ (حذف و ساختِ مجدد با همان تنظیمات)",rebuilding_both:"در حال بازسازیِ تونل روی دو نود…",
 rebuild_failed:"بازسازی ناموفق",rb_last_fail:"بازسازیِ قبلی ناموفق بود — ",nd_moved_t:"این نود آی‌پیِ جدیدی گرفته — بزن ببین",mv_title:"آی‌پیِ تازهٔ نود",mv_desc:"این نود آی‌پیِ جدیدی دریافت کرده است و از همان آدرس جواب می‌دهد. با «تنظیم» هوستِ نود روی آن عوض می‌شود؛ بعدش تونل‌هایش را بازسازی کن.",mv_new:"آی‌پیِ تازه",mv_old:"هوستِ فعلی",mv_set:"تنظیم به‌عنوانِ آی‌پیِ نود",mv_setting:"در حالِ تنظیم…",mv_done:"هوستِ نود عوض شد: ",net_timeout:"پاسخی از پنل نرسید (زمان تمام شد). کار ممکن است روی پنل ادامه داشته باشد؛ کمی بعد صفحه را تازه کن.",net_drop:"ارتباط با پنل قطع شد و پاسخ نرسید. کار روی پنل ادامه دارد؛ کمی بعد صفحه را تازه کن.",checking_conn:"در حال بررسی اتصال (پینگِ زنده روی دو سر)…",
 conn_off:"این تونل خاموش است — پینگ نمی‌دهد چون شما خاموشش کرده‌اید، نه چون قطع است",conn_ok:"اتصال برقرار",conn_bad:"مشکل در اتصال",reset_confirm:"حجمِ کلِ این تونل صفر شود؟ (نرخِ زنده دست‌نخورده می‌ماند)",
 pf_reset_confirm:"حجمِ کلِ این پورت‌فوروارد صفر شود؟",del_tun_confirm:"این تونل روی هر دو نود حذف شود؟",
 view_switched:"دیدِ مصرف به نودِ «",view_switched2:"» تغییر یافت.",drift_note:"آی‌پیِ یکی از نودها عوض شده — این تونل نیاز به بازسازی دارد. دکمهٔ «بازسازی» را بزن.",
 tip_flip:"تعویضِ دیدِ مصرف — فعلاً: ",
 add_tunnel_t:"افزودنِ تونل",create_sub:"سیستمی · یک مبدأ ↔ یک مقصد",src_node:"نودِ مبدأ",dst_node:"نودِ مقصد",
 srv_node:"نودِ سرور",cli_node:"نودِ کلاینت",
 tun_type:"نوع تونل",local_range:"سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه، بدون تداخل)",custom_subnet:"سابنتِ دلخواه",range:"رنج",
 create_tun_btn:"ساخت تونل",two_diff_nodes:"دو نودِ متفاوت انتخاب کن",creating_tun:"در حال ساختِ تونل…",
 src_ip:"آی‌پیِ نودِ مبدأ",dst_ip:"آی‌پیِ نودِ مقصد",
 rot_t:"چرخشِ آی‌پی",rot_d:"بینِ آی‌پی‌های هر نود می‌چرخد و آی‌پیِ بلاک‌شده را کنار می‌گذارد (مسیرِ مستقیم، بدونِ CDN)",
 rot_interval:"بازهٔ چرخش",rot_onfail:"فقط هنگامِ قطع",rot_5m:"هر 5 دقیقه",rot_10m:"هر 10 دقیقه",
 rot_min2:"برای چرخش باید حداقل 2 آی‌پی در هر استخر انتخاب شود",
 
 
 rb_title:"بازسازیِ تونل",rb_newip:"آی‌پیِ جدید",rb_no_ip:"آی‌پیِ قابلِ انتخابی نیست",rb_info:"آی‌پیِ قبلی دیگر روی نود نیست. آی‌پیِ جدیدِ این تونل را انتخاب کن — تگ‌ها نشان می‌دهند هر آی‌پی به کجا وصل است.",
 rb_no_link:"اطلاعاتِ لینک در دسترس نیست",rb_no_drift:"این تونل driftی ندارد",rebuilding:"در حال بازسازی…",rb_fetch_err:"خطا در دریافتِ اطلاعات",
 core_edit_t:"ویرایشِ تونلِ هسته",not_found:"یافت نشد",core_tun_t:"تونلِ هسته",core_tun_sub:"هستهٔ اختصاصی · packet/core",
 raw_need_enc:"حاملِ raw به رمزنگاری نیاز دارد",
 wss_need_host:"برای wss باید دامنه (Host) را وارد کنی",ech_need_wss:"ECH به wss نیاز دارد — اول wss را روشن کن",sni_need_wss:"تقسیمِ SNI به wss نیاز دارد — اول wss را روشن کن",
 cdn_need_wss:"gRPC نیازمندِ wss است — اول wss (TLS به CDN) را روشن کن یا حاملِ HTTP را انتخاب کن",
 cover_need_sni:"برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی",
 creating_core:"در حال ساختِ تونلِ هسته روی دو نود…",saving_rebuild_both:"در حال ذخیره و بازسازیِ دو سر…",
 pf_add_t:"افزودنِ پورت‌فوروارد",pf_edit_t:"ویرایشِ پورت‌فوروارد",pf_node:"نود",pf_listen_port:"پورتِ ورودی",pf_dst_port:"پورتِ مقصد",
 pf_dst_ips:"آی‌پی(های) مقصد — با کاما جدا کن",pf_rot_min:"چرخش هر (دقیقه) — اگر چند آی‌پی دادی",pf_rot_between:"چرخش بینِ مقصدها",
 pf_rot_interval:"بازهٔ چرخش (دقیقه)",pf_lip:"آی‌پیِ ورودی (شنود)",pf_lip_note:"پورت فقط روی این آی‌پی فوروارد می‌شود",
 pf_lip_full:"آی‌پیِ ورودی (شنود) — پورت فقط روی این آی‌پی فوروارد می‌شود",pf_rot_note:"چرخش فقط با 2 آی‌پیِ مقصد یا بیشتر فعال می‌شود.",
 pf_need_ports:"پورت‌ها و آی‌پیِ مقصد لازم است",pf_need_all:"نود، پورتِ ورودی/مقصد و آی‌پی لازم است",creating_dots:"در حال ساخت…",
 pf_created:"پورت‌فوروارد ساخته شد: ",pf_del_confirm:"این پورت‌فوروارد حذف شود؟",pf_active_now:"هم‌اکنون روی: ",pf_targets:"مقصدها: ",
 pf_iface:"اینترفیس: ",pf_lip_lbl:"آی‌پیِ ورودی: ",pf_lp_lbl:"پورتِ ورودی: ",pf_dp_lbl:"پورتِ مقصد: ",pf_active_badge:"فعال · مقصد",
 pf_disabled:"غیرفعال",pf_rule:"قانون",pf_rotate_now:"چرخش الان",pf_rotate_done:"چرخش انجام شد ← ",pf_rotate_failed:"چرخش ناموفق",
 set_on_ipchange:"وقتی آی‌پیِ نود عوض شد",set_on_ipchange_d:"«خودکار»: هوستِ نود و بازسازیِ تونل، هر دو خودکار. «هشدار»: پنل فقط می‌گوید نود کجا رفته و خودت انجام می‌دهی",set_rec_int:"بازهٔ بررسیِ ترمیم (ثانیه)",
 set_rec_range:"5 تا 3600",set_poll_int:"بازهٔ پایشِ فلیت (ثانیه)",set_poll_range:"0٫3 تا 60 — زیرِ 1 هم مجاز (بارِ شبکه بالا)",set_ui_int:"بازهٔ رفرشِ نمایش (ثانیه)",set_ui_range:"0٫3 تا 60 — نرخ/گیج‌ها با این بازه تازه می‌شوند",set_ech_int:"بازهٔ تازه‌سازیِ کلیدِ ECH (دقیقه)",set_ech_range:"0 = خاموش، وگرنه 1 تا 1440 — چرخشِ کلیدِ CDN خودکار ترمیم می‌شود",set_upwin:"پنجرهٔ نوارِ آپ‌تایم",
 set_upwin_d:"60 خانه؛ هر خانه = پنجره ÷ 60",set_mode_auto:"خودکار",set_mode_alert:"هشدار",set_default:"پیش‌فرض",set_agent_update:"بروزرسانیِ ایجنت",
 set_apply_note:"گروهِ «پنل» همان لحظه اعمال می‌شود. سه گروهِ دیگر روی هر تونل هنگامِ ساخت/بازسازیِ بعدی اثر می‌کنند — برای اعمالِ فوری، تونل را «بازسازی» کن. مقدارهای خارج از بازه در هسته کلَمپ می‌شوند.",set_reset:"بازگردانی همه به پیش‌فرض",set_reset_confirm:"همهٔ تنظیماتِ پنل به پیش‌فرض برگردند؟ این شاملِ مودهای تحویلِ ایجنت/هسته و پروکسیِ دانلود هم می‌شود، نه فقط این کارت.",set_reset_yes:"بازگردان",
 set_t_suspect:"زمان‌بندیِ تستِ مجددِ «موقت‌سوخته» (دقیقه)",set_t_suspect_d:"وقتی یک آی‌پی از کار می‌افتد، همان لحظه دورش نمی‌اندازیم — چند بار دیگر امتحانش می‌کنیم، ولی هر بار با صبرِ بیشتر. این عددها همان فاصله‌ها هستند، به دقیقه و با کاما جدا. یعنی: بار اول 10 دقیقه صبر کن و دوباره امتحان کن؛ باز نشد، 30 دقیقه؛ بعد 60… اگر تا آخرین عدد هم درست نشد، آن آی‌پی خراب علامت می‌خورد. عددهای کوچک‌تر یعنی زودتر دوباره امتحان می‌کند.",
 set_x_revive:"مثال: <b>45, 180, 600</b> — بارِ اول ۴۵ ثانیه صبر می‌کند، باز نشد ۱۸۰، بعد ۶۰۰، و از آن به بعد همان ۶۰۰ تکرار می‌شود. بازهٔ مجاز ۱۰ تا ۳۶۰۰ ثانیه.",set_t_revive:"صبر پیش از تلاشِ دوبارهٔ نردبان (ثانیه)",set_t_revive_d:"وقتی تونل می‌افتد، هسته پله‌پله چیزها را عوض می‌کند تا برش گرداند: اول پورتِ مبدأ را دوباره می‌کشد، بعد یک‌بار دستِ دوباره می‌دهد، و آخرش می‌رود روی آی‌پی/لبهٔ بعدی. اگر همهٔ این پله‌ها خرج شود و جای دیگری هم برای رفتن نمانَد، کار همان‌جا تمام می‌شود و تونل دیگر <b>هیچ چیزی را عوض نمی‌کند</b> — تا وقتی یا ترافیک خودش دوباره رد شود یا هسته ری‌استارت شود. این عددها می‌گویند چقدر صبر کند و بعد همان پله‌ها را از نو به خودش بدهد. به ثانیه و با کاما جدا: بارِ اول ۴۵ ثانیه، باز نشد ۱۸۰، بعد ۶۰۰ — و آخرین عدد از آن به بعد تکرار می‌شود. به‌محضِ اینکه ترافیک رد شود همه‌چیز صفر می‌شود و دفعهٔ بعد باز از عددِ اول شروع می‌کند. کوچک‌تر یعنی زودتر دوباره تلاش می‌کند؛ خیلی کوچک یعنی روی مسیری که واقعاً مرده بی‌خود می‌چرخد. بازهٔ مجاز ۱۰ تا ۳۶۰۰ ثانیه است: نود وقتی تونل قطع است حدودِ هر یک ثانیه یک‌بار قضاوت می‌کند، پس صبرِ کوتاه‌تر از چند قضاوت یعنی نردبان زودتر از آنکه نتیجه‌اش دیده شود دوباره پر می‌شود؛ و صبرِ بیشتر از یک ساعت عملاً یعنی «هرگز».",
 set_t_deadretest:"بازهٔ تستِ IPِ «مرده» (دقیقه)",set_t_deadretest_d:"آی‌پی‌ای که خراب علامت خورده دیگر استفاده نمی‌شود، ولی برای همیشه کنار گذاشته نمی‌شود: هر این‌قدر دقیقه یک بار دوباره امتحانش می‌کند و اگر جواب داد، خودش برمی‌گردد سرِ کار. اگر فیلترها زود عوض می‌شوند، این عدد را کم کن تا آی‌پی زودتر برگردد.",




 set_step_bad:"«{f}» باید مضربی از {s} باشد — {v} پذیرفته نیست",
 porttries_lbl:"چند بار پورتِ مبدأ عوض شود",porttries_bad:"عدد باید بینِ 1 تا 60 باشد", set_t_minlive:"حداقلِ عمرِ سشنِ سالم (ثانیه)",set_t_minlive_d:"اتصالی که زودتر از این‌قدر ثانیه بیفتد، یک <b>سشنِ واقعی</b> حساب نمی‌شود — مثل تماسی که ۵ ثانیه بعد قطع شد و اصلاً یک مکالمه نبود. روی استخرِ CDN باعث می‌شود کریر از همان لبه کنار برود، وگرنه «وصل شد و افتاد» بی‌وقفه تکرار می‌شود چون دیالِ موفق هیچ مکثی سرِ راه نمی‌گذارد. <b>هیچ آی‌پی‌ای را متهم نمی‌کند</b> — قضاوت دربارهٔ اینکه یک لبه سالم است یا نه فقط با پروبِ TUN است.",
 set_g1:"1) پنل",set_g1c:"فقط مرکزی",
 set_g2:"3) آی‌پی و چرخش",set_g2c:"استخرِ IP و لبهٔ CDN",
 set_g5:"4) کارایی",set_g5c:"udp / raw",
 set_t_sockbuf:"بافرِ سوکت (مگابایت)",set_t_sockbuf_d:"وقتی داده یک‌دفعه سیل‌آسا می‌رسد، سیستم باید جایی نگهشان دارد تا برسد پردازششان کند. این همان جاست. بزرگ‌ترش کنی، در لحظه‌های شلوغ کمتر داده از دست می‌رود و سرعت بالاتر می‌رود (در تستِ ایران↔آلمان حدود 2٫7 برابر شد). <b>0</b> یعنی دست نزن و همان تنظیمِ پیش‌فرضِ سیستم بماند. حواست باشد این مقدار حافظه از سرور می‌گیرد، پس روی سرورِ ضعیف زیادش نکن.",
 set_x_ipchange:"IPِ نودِ آلمان عوض شد → «هشدار» فقط علامت می‌زند و دستی بازسازی می‌کنی؛ «خودکار» پنل خودش با IPِ جدید می‌سازد.",
 set_x_rec:"<b>15</b> = هر 15ثانیه یک بررسی؛ کوچک‌تر = واکنشِ سریع‌تر، بارِ کمی بیشتر.",
 set_x_poll:"<b>0٫9</b> = کارت‌های نود تقریباً هر ثانیه تازه؛ کوچک‌تر = زنده‌تر ولی pollِ بیشتر روی نودها.",
 set_x_ui:"<b>1</b> = اعداد و نمودارها هر ثانیه به‌روز می‌شوند (فقط مرورگر، نه بارِ شبکه).",
 set_x_ech:"<b>15</b> = هر 15 دقیقه کلید تازه؛ <b>0</b> = خاموش (توصیه نمی‌شود).",
 set_x_upwin:"<b>24 ساعت</b> = هر خانه 24 دقیقه؛ <b>1 ساعت</b> = هر خانه 1 دقیقه (ریزتر).",
 set_x_suspect:"IP مشکوک شد → 10 دقیقه بعد امتحان، باز مرد → 30 دقیقه، بعد <b>60</b> → مرده.",
 set_x_deadretest:"<b>360</b> = IPِ مرده هر 6 ساعت یک شانسِ دوباره می‌گیرد.",




 set_x_minlive:"<b>20</b> = اتصالی که بعد از 5ثانیه افتاد سشنِ واقعی نبود ← از آن لبه کنار برو، ولی متهمش نکن.",
 set_x_probemin:"<b>15</b> = از 20 بسته حداقل 3 تا باید برگردد. <b>5</b> = یک جواب هم بس است (رفتارِ قبلی). <b>100</b> = هر 20 تا باید برگردند.",
 set_pm_hint:"= حداقل {n} بسته از {c} باید جواب بدهد",
 set_x_sockbuf:"<b>4</b> = همان پیش‌فرضِ هسته. وقتی بسته‌ها یک‌دفعه سیل‌آسا می‌رسند، هرچه اتاقِ انتظار بزرگ‌تر باشد کمترش دور ریخته می‌شود (در تستِ IR↔DE سرعتِ TCP حدود 2٫7 برابر شد). <b>0</b> = خاموش، بافرِ پیش‌فرضِ کرنل. حافظهٔ مصرفی ≈ همین عدد × چند سوکت روی هر نود، پس روی سرورِ کم‌رم بالا نبر. فقط udp / raw.",
 h1:"ساعت",h3:"3 ساعت",h6:"6 ساعت",h8:"8 ساعت",h12:"12 ساعت",h24:"24 ساعت",
 pending_check:"در حال بررسی…",off_word:"خاموش",on_word:"روشن",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 pf_dest:"مقصد",
 pal_search:"جستجوی نود، تونل یا دستور…",pal_move:"حرکت",pal_pick:"انتخاب",pal_close:"بستن",pal_none:"موردی یافت نشد",
 pal_g_nodes:"نودها",pal_g_tuns:"تونل‌ها",pal_g_acts:"دستورها",
 pal_add_tun:"افزودن تونل",pal_agent:"بروزرسانیِ ایجنت",pal_checkall:"تستِ همهٔ تونل‌های صفحه",pal_theme:"تغییرِ تمِ روشن/تیره",
 ag_title:"ایجنت و هسته",ag_sub:"آپدیت و ری‌استارتِ ایجنت و هستهٔ نودها از پنل، بدونِ SSH",
 cor_del_blob:"حذفِ باینریِ آپلودشده",cor_del_blob_q:"باینریِ سفارشی از پنل حذف شود؟ نودهایی که همین حالا رویش هستند دست‌نخورده می‌مانند.",cor_del_blob_ok:"باینریِ سفارشی حذف شد",cor_deleting:"در حالِ حذف…",
 cor_check:"بررسی آپدیت",cor_checking:"در حال بررسی…",cor_check_new:"نسخهٔ تازه پیدا شد — از لیست انتخابش کن و «دریافت از گیت‌هاب» را بزن",cor_check_same:"تازه‌ترین نسخه همینی است که داری",cor_check_first:"{n} نسخه پیدا شد — یکی را انتخاب کن",cor_check_none:"هیچ نسخه‌ای پیدا نشد",cor_ver_empty:"هنوز بررسی نشده — «بررسی آپدیت» را بزن",
 ag_node_agent:"ایجنتِ نودها",ag_data_core:"هستهٔ داده",ag_fetch_git:"دریافت از گیت‌هاب",ag_file_btn:"فایلِ ایجنت",ag_push_all:"پوشِ ایجنت به همهٔ نودها",
 ag_binary:"باینری",ag_install_all:"نصبِ هسته روی همهٔ نودها",ag_search:"جستجوی نود…",ag_ready:"آمادهٔ پوش",ag_empty:"خالی",ag_no_item:"موردی نیست",

 ag_lbl_agent:"ایجنت",ag_lbl_core:"هسته",ag_up_avail:"آپدیت دارد",ag_uptodate:"به‌روز",ag_not_installed:"نصب نیست",ag_ver_pick:"نصبِ {v} روی این نود",ag_send:"ارسالِ",
 ag_no_online:"نودِ آنلاینی نیست",
 ag_pick_first:"اول یک ایجنت بارگذاری کن",ag_confirm_all:"ایجنت روی ",ag_confirm_all2:" نودِ آنلاین آپدیت و ری‌استارت شود؟",
 ag_pick_ver:"اول نسخه را انتخاب کن",ag_confirm_core:"هستهٔ نسخهٔ «",ag_confirm_core2:"» روی ",ag_confirm_core3:" نودِ آنلاین نصب و تونل‌های هسته ری‌استارت شوند؟",
 nd_central:"پنل را کجا می‌داند",nd_central_none:"هنوز نمی‌داند",
 cn_stale_one:"۱ نود هنوز پنل را در نشانیِ قدیمی می‌داند",
 cn_stale_n:"{n} نود هنوز پنل را در نشانیِ قدیمی می‌دانند",
 cn_stale_sub:"تا وقتی پنل به آن‌ها برسد خودشان به‌روز می‌شوند. اگر نشانیِ قدیمی را دارید برمی‌دارید، صبر کنید تا این پیام برود.",
 rdy_title:"پنل هنوز چیزی برای دادن به نودها ندارد",
 rdy_agent:"ایجنتِ نود روی پنل نیست",rdy_core:"هستهٔ داده روی پنل نیست",
 rdy_core_arch:"هستهٔ داده برای معماریِ {a} روی پنل نیست",
 rdy_why:"تا اینها آماده نشوند، «افزودن نود» و ساختِ تونلِ هسته رد می‌شوند.",
 rdy_go:"برو به تنظیمات",cor_arch_missing:" — معماریِ {a} نیامد؛ دوباره «دریافت از گیت‌هاب» را بزن",
 dlv_lbl:"فایل چطور به نود برسد",
 dlv_push_t:"پنل آپلود کند",dlv_git_t:"نود از گیت‌هاب",dlv_pan_t:"نود از پنل",

}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 fmt_day:"روز",fmt_hr:"ساعت",fmt_min:"دقیقه",fmt_sec:"ثانیه",fmt_and:"و",cipher_auto:"خودکار",cipher_none:"بدونِ رمز",
 edit_tun_t:"ویرایشِ تونل",ip_of:"آی‌پیِ ",multi_ip:"مولتی‌آی‌پی",ip_each_end:"آی‌پیِ هر سرِ تونل",
 link_ip_note1:"اگر نودی چند آی‌پی دارد، انتخاب کن تونل روی کدام آی‌پی بسته شود. تغییرِ نوع، سابنت یا آی‌پی، تونل را روی هر دو نود بازسازی می‌کند (شناسه ",link_ip_note2:" حفظ می‌شود).",
 le_port_4789:"پورتِ UDP — خالی = 4789",le_port_auto:"پورتِ UDP — خالی = یک پورتِ تصادفی از باند",
 ph_dead:"سوختهٔ دائمی",ph_suspect:"سوختهٔ موقت",ph_active:"سالم · لبهٔ فعال",ph_active_retry:"لبهٔ فعال · در حالِ آزمایشِ دوباره",ph_healthy:"سالم",
 pb_healthy:"سالم",pb_temp:"موقت",pb_dead:"دائمی",pool_empty:"خالی — یک مورد اضافه کن",
 peer_live_hd:"وضعیت زندهٔ استخر",peer_st_active:"فعال",peer_st_active_retry:"فعال · در حالِ آزمایشِ دوباره",peer_st_rot:"در چرخش",peer_moved:"چرخش از این آی‌پی ادامه پیدا می‌کند",peer_rotating:"این نود بین چند آی‌پی می‌چرخد — آی‌پیِ نشان‌داده‌شده، آی‌پیِ فعالِ فعلی است",
 peer_live_empty:"وضعیتِ زندهٔ آی‌پی‌ها و دکمهٔ جابه‌جایی، وقتی تونل روی نودِ به‌روز در حال اجراست این‌جا نمایش داده می‌شود. اگر تازه به‌روزرسانی کرده‌اید: نود را آپدیت کنید و بعد «ذخیره و بازسازی» را بزنید تا با هستهٔ جدید ساخته شود.",
 pa_testnow:"صبرش را صفر کن — در چرخشِ بعدی امتحان می‌شود",pa_active_ip:"آی‌پیِ فعلی",pa_activate:"این را فعال کن",pa_selecting:"در حالِ فعال‌سازی…",
 pool_stale:"وضعیتِ لبه‌ها تازه نشد — نود جواب نداد؛ رنگ‌های زیر مالِ آخرین باری است که جواب داد",pool_make_first:"اول تونل را بساز",peer_probe_pulled:"صبرِ همین یکی صفر شد — در اولین چرخشِ بعدی امتحان می‌شود و پروبِ tun قضاوتش می‌کند",pool_edge_active:"این لبه فعال شد",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 snr_192:"خودکار · 192.168.x (پیشنهادی)",snr_10:"خودکار · 10.x",snr_172:"خودکار · 172.16.x",snr_custom:"دلخواه (دستی وارد کن)",
 rawp_bare_m:"proto دلخواه · بدونِ هدر",rawp_icmp_m:"proto 1 · شبیهِ ping",rawp_gre_m:"proto 47 · GRE",rawp_ipip_m:"proto 4 · IP-in-IP",rawp_udp_m:"proto 17 · UDP",rawp_tcp_m:"proto 6 · TCP جعلی",rawp_esp_m:"proto 50 · IPsec ESP",rawp_l2tpv3_m:"proto 115 · تونلِ L2TPv3",rawp_ah_m:"proto 51 · IPsec AH",rawp_ipcomp_m:"proto 108 · IPComp",rawp_etherip_m:"proto 97 · EtherIP",
 cdn_shape_lbl:"شکلِ حاملِ http",
 cdn_upw_lbl:"کارگرِ آپلود",cdn_upkb_lbl:"اندازهٔ هر آپلود (KB)",cdn_strm_lbl:"جریانِ حامل",
 wsp_ws_m:"وب‌سوکت",wsp_grpc_m:"استریمِ دوطرفه",wsp_http_m:"GET + POST",
 grpc_zone_warn:"این حامل باید روی خودِ زونِ CDN فعال باشد، وگرنه لبه درخواست را با 403 رد می‌کند و تونل اصلاً بالا نمی‌آید.",
 
 
 fec_light:"سبک",fec_balanced:"متعادل",fec_strong:"قوی",fec_ov10:"10٪ سربار",fec_ov25:"25٪ سربار",fec_ov50:"50٪ سربار",
 
 rot_int_lbl:"بازهٔ چرخش",
 
 
 fec_t:"تصحیحِ خطا (FEC)",fec_d:"بسته‌های گم‌شده را خودش بازمی‌سازد بدون اینکه دوباره بفرستد — برای خطِ پُرافت. کمی پهنای‌باند بیشتر می‌خورد. فقط روی حامل‌های دیتاگرامی.",fec_rate_lbl:"نرخِ افزونگیِ FEC",
 fec_note:"«16+4» یعنی هر 16 پکتِ داده، 4 پکتِ پریتی؛ گیرنده تا 4 تا از هر 20 تا را گم کند بازسازی می‌کند. هزینهٔ پردازش فقط به عددِ دوم بستگی دارد، نه به اولی؛ پس بلوکِ بزرگ‌تر با همان پریتی هم ارزان‌تر است هم قوی‌تر. هر دو سرِ تونل یک تنظیم می‌گیرند. درصدِ روی کاشی برای بلوکِ پُر است: روی تونلِ کم‌ترافیک بلوک با پکتِ کمتری بسته می‌شود و همیشه دستِ‌کم یک پکتِ پریتی می‌رود، پس سربارِ لحظه‌ای بالاتر می‌رود (برای بلوکِ تک‌پکتی تا 100٪). نسبتِ محافظت هرگز از عددِ انتخابی کمتر نمی‌شود.",
 ds_t:"desync — بسته‌های طعمه (ضدِ DPI)",ds_d:"چند بستهٔ قلابی می‌فرستد تا فیلترچی ردِ اتصالِ واقعی را گم کند؛ خودِ تونل دست‌نخورده می‌ماند. روی حاملِ UDP و HTTP در دسترس نیست.",ds_mode_lbl:"حالتِ طعمه",ds_ttl_lbl:"TTL طعمه",ds_count_lbl:"تعدادِ طعمه",
 ds_note:"TTL کم = طعمه چند هاپ دوام می‌آورد و پیش از سرور می‌میرد (1 برای رله‌ٔ کوتاه، 3 تا 5 برای مسیرِ اینترنتی تا DPI). چک‌سامِ خراب = سرور دورش می‌ریزد. تعداد = چند طعمه سرِ هر دست‌دهی.",
 ds_both_needs2:"حالتِ «هر دو» یعنی هم طعمهٔ TTL و هم طعمهٔ چک‌سام — پس دستِ‌کم به ۲ طعمه نیاز دارد؛ عدد را بالا ببر یا یکی از دو حالت را انتخاب کن",ds_ttl_cap:"طعمه روی همان اتصالِ واقعی تزریق می‌شود، پس TTL سقفِ 8 دارد (طعمه‌ای که به سرور برسد RST می‌گیرد) و عددِ بزرگ‌تر به 8 کم می‌شود. روی raw کلِ 1 تا 255 اعمال می‌شود.",
 ds_m_ttl_t:"TTL کم",ds_m_ttl_s:"می‌میرد سرِ راه",ds_m_bad_t:"چک‌سامِ خراب",ds_m_bad_s:"سرور دور می‌ریزد",ds_m_both_t:"هردو",ds_m_both_s:"ترکیبی",
 wstls_t:"wss (TLS به CDN)",wstls_d:"اتصال به CDN رمز می‌شود تا از بیرون شبیهِ بازکردنِ یک سایتِ عادی باشد. برای پنهان‌شدن پشتِ CDN لازم است.",
 ech_t:"ECH — مخفی‌کردنِ SNI",ech_d:"نامِ دامنه را هم رمز می‌کند تا فیلترچی نفهمد به کدام سایت وصل شده‌ای. نیازمندِ wss؛ برای استخر خودکار گرفته می‌شود.",echpx_t:"پروکسی برای دریافتِ کلیدِ ECH",echpx_d:"برای دامنهٔ فیلترشده — پنل کلیدِ ECH را از این پروکسی (socks5/http) می‌گیرد. فقط برای گرفتنِ کلید است، نه ترافیکِ تونل.",sni_t:"تقسیمِ SNI (ضدِ DPI)",sni_d:"نامِ دامنه را بینِ دو بسته می‌شکند تا فیلترچی نتواند یکجا بخواندش. جایگزینِ ECH وقتی ECH در دسترس نیست — با ECHِ روشن کاری نمی‌کند. نیازمندِ wss.",sni_pos_lbl:"نقطهٔ برش (split_pos) — 0 = خودکار (وسطِ دامنه)",sni_ttl_lbl:"TTLِ سگمنتِ سرْ در حالتِ disorder (split_ttl) — 0 = پیش‌فرض (4)، بیشترین 8",sni_mode_lbl:"حالتِ تقسیم SNI",m_split_s:"دو سگمنتِ ساده",m_dis_s:"سگمنتِ سرْ با TTL پایین",m_fake_s:"ClientHelloِ جعلی (ضدِ reassembly)",
 ws_prof_lbl:"نوعِ اتصال روی CDN",
 ws_pool_t:"استخرِ لبه (چرخش + بلک‌لیست)",ws_pool_d:"چند IP و چند دامنه؛ هسته می‌چرخد و سوخته‌ها را کنار می‌گذارد. خاموش = یک لبهٔ ثابت.",
 ws_host_lbl:"دامنهٔ فرانت (Host / SNI)",ph_cdn_domain:"مثلاً cdn.example.com",ws_edge_lbl:"آی‌پیِ لبهٔ CDN (اختیاری) — کلاینت به‌جای مبدأ به این وصل می‌شود",ph_edge_ip:"مثلاً 104.16.0.1 یا 104.16.0.1:443",ws_path_lbl:"مسیر (path)",
 ws_note:"ترافیک شبیهِ HTTPS رویِ CDN دیده می‌شود (collateral freedom). سرور را پشتِ یک CDN (مثل Cloudflare) بگذار، SSL روی Flexible، پورتِ مبدأ 80. با <b>استخر</b> چند IP/دامنه بده تا بچرخد و سوخته‌ها کنار بروند.",
 rot_3m:"هر 3 دقیقه",rot_5m:"هر 5 دقیقه",rot_10m:"هر 10 دقیقه",rot_15m:"هر 15 دقیقه",rot_30m:"هر 30 دقیقه",rot_1h:"هر 1 ساعت",rot_4h:"هر 4 ساعت",rot_8h:"هر 8 ساعت",rot_off_fo:"خاموش (فقط failover)",
 pool_ip_lbl:"آی‌پی‌های لبهٔ CDN",pool_sni_lbl:"دامنه‌ها (SNI)",pool_ip_min2:"استخر باید حداقل 2 آی‌پیِ فعال داشته باشد — کمتر از این نمی‌شود",
 pool_bad_ip:"آی‌پیِ نامعتبر (مثلاً 104.16.0.1 یا 104.16.0.1:443)",pool_bad_dom:"دامنهٔ نامعتبر (مثلاً cdn.example.com)",pool_need_clean:"استخر به حداقل یک IP تمیز و یک دامنهٔ تمیز نیاز دارد",
 ech_need_wss_alert:"اول wss (TLS به CDN) را روشن کن — ECH داخلِ همان TLS کار می‌کند.",
 roles_lbl:"نقش‌ها — کدام نود listen کند (سرور)",
 enc_method_lbl:"روشِ رمزنگاری",cipher_ph:"رمز",transport_lbl:"نوعِ اتصال",tr_udp_d:"دیتاگرام",tr_ws_d:"پشتِ ابر",tr_tcp_d:"پایدارتر",tr_raw_d:"پکتِ خام",tr_dns_d:"آخرین‌پناه",
 dns_zone_lbl:"دامنهٔ واگذارشده (zone)",dns_zone_note:"زیردامنه‌ای که NSِ آن به سرورِ تو واگذار (delegate) شده — سرور همان authoritative NS است. مثلاً <b>t.example.com</b>",dns_resolvers_lbl:"resolverهای بازگشتی (کلاینت)",dns_resolvers_note:"آی‌پیِ resolverهای DNSِ داخلیِ ایران که کلاینت به آن‌ها کوئری می‌زند (با کاما جدا کن). کلاینت هرگز به IPِ سرور بسته نمی‌فرستد — همین آن را از فیلترِ مقصد پنهان می‌کند.",dns_delegation_note:"قبل از استفاده: در registrarِ دامنه، NSِ این zone را به IPِ سرور delegate کن و پورتِ 53 سرور باز باشد. رمزنگاری الزامی است. سرعت کم است ولی در بدترین‌حالت دوام می‌آورد.",dns_need_enc:"حاملِ dns به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)",dns_need_zone:"دامنهٔ dns (zone) را وارد کن — مثلاً t.example.com",dns_need_resolvers:"حداقل یک resolverِ داخلی (IPv4) وارد کن",
 raw_prof_lbl:"پروفایلِ کپسوله‌سازی (raw)",
got_it:"باشه", raw_sport_lbl:"پورتِ سمتِ کلاینت (مبدأ)",raw_sport_fixed_n:"ثابت",raw_sport_fixed_m:"پیش‌فرض 51820 · قابلِ تغییر",raw_sport_ike:"IKE",raw_sport_bad:"پورتِ مبدأ باید بینِ 1 تا 65535 باشد",raw_sport_rand_n:"رندومِ واکنشی",raw_sport_rand_m:"روی خرابی و روی سکوت",raw_sprot_t:"چرخشِ پورتِ مبدأ",ctb_t:"رد شدن از conntrack",ctb_d:"جریانِ حامل در جدولِ conntrackِ نود ثبت نمی‌شود · یک ACCEPT هم کنارش گذاشته می‌شود تا فایروالِ deny نشکند",ctb_warn:"جدولِ conntrackِ نودِ «{n}» {p}٪ پر است ({c} از {m}). چرخشِ پورت به‌ازای هر پورتِ تازه یک جریانِ تازه می‌سازد؛ جدول که پر شود کرنل پکت می‌اندازد — هم برای این تونل هم برای بقیهٔ سرویس‌هایِ همان نود. «رد شدن از conntrack» را در ویرایشِ همین تونل روشن کن.",raw_sprot_d:"هر چند پکت یک پورتِ تازه · پروفایلِ udp یا tcp",raw_sprot_lbl:"هر چند پکت",raw_sprot_bad:"عدد باید بینِ 1 تا 60 باشد",raw_dports_lbl:"چند پورتِ مقصد",raw_dports_bad:"عدد باید بینِ 1 تا {n} باشد",band_lbl:"بازهٔ چرخش (پورتِ مبدأ)",band_lo:"از",band_hi:"تا",band_bad:"بازه باید دو پورتِ بینِ {n} تا 65535 باشد و ابتدایش کوچک‌تر",band_narrow:"بازه دستِ‌کم {n} پورت پهنا می‌خواهد",band_hint:"پیش‌فرض {lo}-{hi} · اگر مسیری پورتِ بالا را می‌اندازد، بازه را زیرِ آن بیاور",port_dst_rot:"چرخان",port_dst_rot_n:"{n} پورت",port_src_rot:"چرخان",port_src_rot_up:"پورتِ مبدأِ کلاینت",port_src_rot_down:"پورتِ مبدأِ سرور",port_src_rot_every:"هر {n} پکت",port_src_rot_fail:"روی هر خرابی",port_src_rot_drawn:"{n} پورت",raw_port_lbl:"پورتِ سمتِ سرور (مقصد)",raw_port_quic:"QUIC",raw_port_bad:"پورت باید بینِ 1 تا 65535 باشد",raw_proto_lbl:"شمارهٔ پروتکلِ IP (bare)",raw_proto_native:"نیتیو",raw_proto_hint:"bare هیچ هدرِ L4 نمی‌سازد؛ فقط شمارهٔ پروتکلِ بیرونی عوض می‌شود تا از فیلترِ شمارهٔ پروتکل رد شود. شماره‌های تخصیص‌نیافته امن‌ترین‌اند (143 تا 254)، چون هیچ دستگاهی پارسرشان را ندارد. بازهٔ مجاز 1 تا 255.",raw_proto_free:"آزاد",raw_proto_owned:"پروتکلِ {n} مالِ پروفایلِ «{p}» است. این حامل هدر نمی‌سازد، پس پاکت با همین شماره بیرون می‌رود ولی جای هدرِ {p} دادهٔ رمزشده دارد — میانِ راه بدشکل دیده و انداخته می‌شود. پروفایلِ «{p}» را بزن که هدرش را هم می‌سازد.",raw_proto_bad:"شمارهٔ پروتکلِ IP باید بینِ 1 تا 255 باشد",
 workers_lbl:"صف‌های موازیِ تونل",workers_lbl_node:"روی {n}",workers_lbl_cores:"دارای {c} هسته",workers_1:"پیش‌فرض",workers_2:"سبک",workers_3:"نیمه‌سبک",workers_4:"متوسط",workers_5:"نیمه‌سنگین",workers_6:"سنگین",workers_7:"خیلی سنگین",workers_8:"بیشینه",
 obfs_t:"استتار در برابرِ DPI",obfs_d:"اندازه و زمان‌بندیِ بسته‌ها را به‌هم می‌ریزد تا الگویِ ثابتی برای شناسایی نماند. رمزنگاری باید روشن باشد.",
 cover_t:"پوششِ TLS (شبیهِ HTTPS)",cover_d:"تونل از بیرون عینِ یک سایتِ HTTPS دیده می‌شود؛ اگر کسی سرور را وارسی کند هم چیزی لو نمی‌رود. فقط روی حاملِ TCP.",
 cover_sni_lbl:"سایتِ پوشش (SNI) — الزامی",cover_sni_ph:"مثلاً یک سایتِ HTTPSِ واقعی و محبوب",
 cover_sni_note1:"سرور برای هر اتصالِ ناشناس (پروب/فیلترچی) <b>واقعاً به این سایت وصل می‌شود</b> و ترافیک را به آن پراکسی می‌کند، پس پروب گواهیِ اصلیِ همان سایت را می‌بیند (مقاوم در برابرِ پروبِ فعال). پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد — ترجیحاً روی یک CDNِ بزرگ.",
 cover_sni_note2:"سرور پروب‌های ناشناس را <b>واقعاً به این سایت وصل و پراکسی می‌کند</b>، پس باید یک سایتِ <b>HTTPSِ واقعی، در دسترس، فیلترنشده و محبوب</b> باشد (ترجیحاً روی CDNِ بزرگ).",
 gso_t:"شتاب‌دهیِ GSO",gso_d:"سرعتِ ترافیکِ سنگین را بالا می‌برد. فقط روی لینوکس؛ اگر کرنل پشتیبانی نکند خودش خاموش می‌ماند.",
 set_gkd:"2) اتصال و تشخیصِ مرگ",set_gkdc:"هسته + پروبِ همهٔ تونل‌ها",set_t_probemin:"حداقلِ بسته‌های برگشتی (٪)",set_t_probemin_d:"نودِ خودت هر چند ثانیه ۲۰ بستهٔ کوچک از <b>داخلِ</b> تونل به آن‌سر می‌فرستد و می‌شمارد چندتا برگشت. این عدد می‌گوید چند درصدشان باید برگردد تا تونل «کارکن» حساب شود. هم رنگِ نقطه را همین تعیین می‌کند، هم اینکه آی‌پیِ مقصد سوزانده شود یا سوختگی‌اش پاک شود. پایین بگذاری سخت‌گیریِ کمتر: تونلی که ۹۵٪ بسته می‌اندازد هم سبز می‌ماند. بالا بگذاری زودتر می‌فهمی مسیر خراب شده و زودتر روی آی‌پیِ بعدی می‌چرخد. روی همهٔ تونل‌ها اثر دارد، نه فقط core.",
 core_range_lbl:"سابنتِ لوکال (رنجِ خصوصی — خودکار بر اساس شناسه)",core_port_lbl:"پورت — خالی = خودکار، می‌توانی 443 بگذاری",core_port_lbl2:"پورت (می‌توانی 443)",core_subnet_lbl:"سابنتِ داخلی",
 core_edit_note:"ذخیره، تونل را روی هر دو نود از نو می‌سازد (لحظه‌ای قطع می‌شود).",ph_subnet:"مثلا 192.168.99.0/24",
 role_server_word:"سرور",role_client_word:"کلاینت",
 port_band_ph:"خالی = یک پورتِ تصادفی از باند",port_ws_ph:"80 (کلادفلر Flexible)",
}});
(function(x){for(var k in x.fa)I18N.fa[k]=x.fa[k]})({fa:{
 pct:"٪",list_sep:"، ",unit_kb:"کیلوبایت",unit_mb_full:"مگابایت",app_title:"tnl · کنترل فلیت",
 ip_toggle_hint:"بزن تا بینِ نامِ نود و اینترفیس جابه‌جا شود",
 nadd_auto:"خودکار",nadd_manual:"دستی",nadd_title:"افزودنِ نود",
 nadd_autonote:"مشخصاتِ SSHِ سرورِ نود را بده؛ پنل خودش وارد می‌شود، ایجنت را نصب می‌کند، توکن می‌سازد و نود را وصل می‌کند.",
 nadd_node_name:"نامِ نود",nadd_srv_ip:"آی‌پیِ سرور",nadd_ssh_port:"پورتِ SSH",nadd_ssh_user:"کاربرِ SSH",
 nadd_agent_port:"پورتِ ایجنت",nadd_ssh_auth:"احرازِ هویتِ SSH",
 nadd_pass:"رمز",nadd_privkey:"کلیدِ خصوصی",nadd_pass_ph:"رمزِ SSH سرور",
 nadd_pass_hint:"رمزِ SSH سرور — ذخیره نمی‌شود، فقط لحظهٔ نصب استفاده می‌شود.",
 nadd_key_hint:"کلیدِ خصوصیِ SSH — امن‌تر از رمز؛ به sshpass هم نیازی نیست.",
 nadd_manual_name:"نام",nadd_manual_host:"هاست / آی‌پی",nadd_agent_port2:"پورتِ ایجنت",nadd_node_tok:"توکن نود",
 nadd_install_connect:"نصب و اتصالِ خودکار",nadd_add_connect:"افزودن و اتصال",
 nadd_pass_word:"رمزِ SSH",nadd_is_required:" لازم است",nadd_need_name_ip:"نام و آی‌پیِ سرور لازم است",
 inst_ssh:"اتصالِ SSH",inst_agent:"رساندنِ ایجنت به نود",inst_service:"نصب و راه‌اندازیِ سرویس",inst_register:"ثبت و اتصال در پنل",
 inst_connecting:"در حالِ اتصال…",inst_waiting:"در انتظار…",inst_installing:"در حالِ نصب…",inst_done:"انجام شد",
 inst_status_notfound:"وضعیتِ نصب یافت نشد",inst_panel_lost:"ارتباط با پنل قطع شد",inst_node_installed:"نود نصب شد",inst_retry:"تلاشِ مجدد",
 custom_subnet_ph:"مثلا 192.168.99.0/24 یا fd00:99::/64",ttype_port_ph:"مثلا 51820",
 ttype_port_auto_lbl:"پورتِ UDP، اختیاری — خالی = یک پورتِ تصادفی از باند",
 ttype_l2_note:"روی UDP سوار می‌شود؛ برای دورزدنِ فیلتر می‌توانی پورتِ دلخواه بگذاری.",
 ttype_vxlan_lbl:"پورتِ UDP (خالی = 4789)",
 ttype_vxlan_note:"پورتِ استانداردِ VXLAN؛ برای دورزدنِ فیلتر می‌توانی عوضش کنی (مثلاً 443).",
 ttype_ipsec_note:"رمزنگاری‌شده (ESP). کلید خودکار ساخته و امن به هر دو سر داده می‌شود — بدونِ دیمنِ خارجی.",
 ag_word_agent:"ایجنت",ag_word_core:"هسته",ag_pick_version:"انتخاب نسخه",err_github:"ناموفق — پنل به گیت‌هاب دسترسی دارد؟",
 ag_no_agent_loaded:"هنوز ایجنتی بارگذاری نشده — «دریافت از گیت‌هاب» یا «فایلِ ایجنت».",
 ag_no_core_staged:"هنوز هسته‌ای روی پنل دانلود نشده — «دریافت از گیت‌هاب» را بزن تا آماده‌ی پوش شود.",
 cor_downloading:"در حال دانلودِ هسته روی پنل…",cor_staged_pre:"هستهٔ «",cor_staged_post:"» روی پنل آماده شد",
 cor_picking:"در حال گرفتنِ نشانیِ نسخه…",cor_picked_post:"» انتخاب شد — نودها خودشان از گیت‌هاب می‌گیرند",
 cor_pick_git:"انتخابِ نسخه",cor_dl_cancel:"لغوِ دانلود",
 dlpx_title:"پروکسیِ دانلودِ پنل",
 dlpx_sub:"وقتی خودِ پنل از گیت‌هاب چیزی می‌گیرد — باینریِ هسته، ایجنت، فهرستِ نسخه‌ها — از این پروکسی برود. نودها از این تنظیم اثر نمی‌گیرند؛ پروکسیِ آن‌ها روی خودِ نود است.",
 dlpx_on:"دانلودهای پنل از پروکسی بروند",
 dlpx_via:"هر درخواستی که خودِ پنل به گیت‌هاب می‌زند از این پروکسی رد می‌شود.",
 dlpx_none:"هنوز پروکسی‌ای ثبت نشده — در «پروکسی‌ها» یکی اضافه کن",
 cor_reading_upload:"در حال خواندن و آپلودِ باینری…",cor_read_fail:"خواندنِ فایل ناموفق",
 cor_bin_saved_pre:"باینری ذخیره شد: ",cor_bin_saved_post:" — «نصبِ همه» را بزن یا از منوی هر نود",
 ag_pick_file_first:"اول فایلِ ایجنت را انتخاب کن",ag_checking_saving:"در حال بررسی و ذخیره…",ag_saved_pre:"ذخیره شد: v",
 ag_fetching_git:"در حال دریافت از گیت‌هاب…",ag_fetched_pre:"دریافت شد: v",ag_fetched_post:" — حالا «پوشِ همه» را بزن",
}});
function T(k){return (k in I18N.fa)?I18N.fa[k]:k}
var ERRNOISE=[/^(dial|read|write) (tcp|udp)\\s*/i,/connect:\\s*/i,
 /context deadline exceeded:?\\s*/i,/^bash: line \\d+:\\s*/i,/^sh: \\d+:\\s*/i,/^ssh:\\s*/i,
 /^connect:\\s*/i,/^Error:\\s*/i,/^error:\\s*/i];
var ERRWHOLE=[[/x509:[^,]*signed by unknown authority/i,'err_cert_unknown'],
 [/x509:[^,]*certificate has expired[^,]*/i,'err_cert_expired'],
 [/i\\/o timeout/i,'err_timeout'],
 [/EOF$/,'err_eof']];
var ERRFA=[
 [/RTNETLINK answers:\\s*No such file or directory/ig,'err_rt_nomod'],
 [/RTNETLINK answers:\\s*File exists/ig,'err_rt_exists'],
 [/RTNETLINK answers:\\s*Operation not supported/ig,'err_rt_unsupported'],
 [/RTNETLINK answers:\\s*Operation not permitted/ig,'err_rt_notperm'],
 [/RTNETLINK answers:\\s*Network is unreachable/ig,'err_rt_noroute'],
 [/RTNETLINK answers:\\s*Address already in use/ig,'err_rt_addrused'],
 [/RTNETLINK answers:\\s*Cannot find device/ig,'err_rt_nodev'],
 [/RTNETLINK answers:\\s*Invalid argument/ig,'err_rt_badarg'],
 [/RTNETLINK answers:\\s*([A-Za-z][A-Za-z ]+)/ig,'err_rt_other'],
 [/Error talking to the kernel/ig,'err_kernel'],
 [/Cannot find device/ig,'err_rt_nodev'],
 [/Connection refused/ig,'err_refused'],
 [/No route to host/ig,'err_noroute'],
 [/Name or service not known/ig,'err_dns'],
 [/Connection reset by peer/ig,'err_reset'],
 [/timed out|timeout/ig,'err_timeout'],
 [/unreachable/ig,'err_unreach'],
 [/Permission denied/ig,'err_denied'],
 [/command not found/ig,'err_nocmd'],
 [/No such file or directory/ig,'err_nofile'],
 [/Address family not supported/ig,'err_afam'],
 [/broken pipe/ig,'err_pipe'],
 [/certificate/ig,'err_cert']];
function terr(msg){msg=String(msg==null?'':msg);
 for(var i=0;i<ERRNOISE.length;i++)msg=msg.replace(ERRNOISE[i],'');
 for(var i=0;i<ERRWHOLE.length;i++)msg=msg.replace(ERRWHOLE[i][0],T(ERRWHOLE[i][1]));
 for(var i=0;i<ERRFA.length;i++)msg=msg.replace(ERRFA[i][0],T(ERRFA[i][1]));
 return msg.trim()}
function perr(r,fbk){return r&&r.net?T(r.net=='timeout'?'net_timeout':'net_drop')
 :terr((r.d&&(r.d.error||r.d.msg))||T(fbk||'failed'))}   
function vhead(icn,navK,subK){return '<h1>'+ic(icn,'var(--acc)')+' '+esc(T(navK))+'</h1><p class="sub">'+esc(T(subK))+'</p>'}   
function paintThemeBtns(){var d=document.body.classList.contains('dark');var b1=el('thbtn');if(b1)b1.innerHTML=ic(d?'sun':'moon')+' '+esc(T('theme'));var b2=el('thbtn2');if(b2)b2.innerHTML=ic(d?'sun':'moon')}
function paintNav(){try{document.title=T('app_title')}catch(e){}var n=document.getElementById('nav');if(n)n.querySelectorAll('.navi').forEach(function(p){var s=p.querySelector('.nlbl');if(s)s.textContent=T('nav_'+p.dataset.t)});var bs=el('brandsub');if(bs)bs.textContent=T('brand_sub');var fo=el('foutbtn');if(fo){var fl=fo.querySelector('.nlbl');if(fl)fl.textContent=T('nav_logout')}paintThemeBtns()}
(function(){document.documentElement.lang='fa';document.documentElement.dir='rtl';try{document.body.dir='rtl'}catch(e){}})();
var H={'Content-Type':'application/json','X-Requested-With':'tnl-central'};
var NET_TIMEOUT=20000,NET_POST_TIMEOUT=300000;
function _abo(ms){var ac=window.AbortController?new AbortController():null;
 return{s:ac?ac.signal:undefined,t:ac?setTimeout(function(){ac.abort()},ms||NET_TIMEOUT):0}}
function j(u){var g=_abo();return fetch('/api/'+u,{signal:g.s}).then(function(r){return r.json()})
 .then(function(v){clearTimeout(g.t);return v},function(e){clearTimeout(g.t);throw e})}
function post(u,b,ms){var g=_abo(ms||NET_POST_TIMEOUT);
 return fetch('/api/'+u,{method:'POST',headers:H,body:JSON.stringify(b||{}),signal:g.s})
  .then(async function(r){return{ok:r.ok,d:await r.json().catch(function(){return{}})}})
  .catch(function(e){return{ok:false,d:{},net:(e&&e.name=='AbortError')?'timeout':'drop'}})
  .then(function(v){clearTimeout(g.t);return v})}
function logout(){post('logout').then(function(){location.href='/'})}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function hA(e){return e.getAttribute('data-ha')}
function hB(e){return e.getAttribute('data-hb')}
function hC(e){return e.getAttribute('data-hc')}
function el(id){return document.getElementById(id)}
function v(id){var e=el(id);return e?e.value.trim():''}
function setT(id,t){var e=el(id);if(e&&e.textContent!==String(t))e.textContent=t}
function setHTML(box,html){if(!box)return;if(box._sig===html)return;box._sig=html;box.innerHTML=html}  
var _rowBox=null;
function rowNode(k,h){if(!_rowBox)_rowBox=document.createElement('div');_rowBox.innerHTML=h;
 var n=_rowBox.firstElementChild||document.createElement('div');
 n.setAttribute('data-k',k);n._h=h;return n}
function morphNode(a,b){
 if(a.nodeType!==b.nodeType||a.nodeName!==b.nodeName)return false;
 if(a.nodeType!==1){if(a.nodeValue!==b.nodeValue)a.nodeValue=b.nodeValue;return true}
 var i,at,bt=b.attributes;
 for(i=bt.length-1;i>=0;i--)if(a.getAttribute(bt[i].name)!==bt[i].value)a.setAttribute(bt[i].name,bt[i].value);
 at=a.attributes;
 for(i=at.length-1;i>=0;i--)if(!b.hasAttribute(at[i].name))a.removeAttribute(at[i].name);
 var an=a.firstChild,bn=b.firstChild;
 while(bn){var bx=bn.nextSibling;
  if(!an){a.appendChild(bn);bn=bx;continue}
  var ax=an.nextSibling;
  if(!morphNode(an,bn))a.replaceChild(bn,an);
  an=ax;bn=bx}
 while(an){var dead=an;an=an.nextSibling;a.removeChild(dead)}
 return true}
function setList(box,rows){if(!box)return;
 if(!rows.length){box._sig='';box.textContent='';return}
 var i,j='';for(i=0;i<rows.length;i++)j+=rows[i].k.length+':'+rows[i].k+rows[i].h;
 if(j===box._sig)return;
 box._sig=j;
 var have=Object.create(null),c=box.children,k,keyed=false;
 for(i=0;i<c.length;i++){k=c[i].getAttribute('data-k');if(k!==null){have[k]=c[i];keyed=true}}
 if(!keyed){box.innerHTML=rows.map(function(r){return r.h}).join('');
  if(box.children.length===rows.length){
   for(i=0;i<rows.length;i++){box.children[i].setAttribute('data-k',rows[i].k);box.children[i]._h=rows[i].h}
   return}
  box.textContent=''}
 var prev=null;
 for(i=0;i<rows.length;i++){var r=rows[i],old=have[r.k],node;
  if(old&&old._h===r.h)node=old;
  else{var fresh=rowNode(r.k,r.h);
   if(old&&morphNode(old,fresh)){old._h=r.h;node=old}
   else{if(old)old.remove();node=fresh;if(keyed&&!old)fresh.classList.add('jin')}}
  delete have[r.k];
  var want=prev?prev.nextSibling:box.firstChild;
  if(node!==want)box.insertBefore(node,want);
  prev=node}
 for(k in have)have[k].remove();
 while(prev.nextSibling)box.removeChild(prev.nextSibling)}
var RMSG={};
function rmsgCls(cls){return cls?'msg '+cls:'msg'}
function rmsgHTML(id){var c=RMSG[id];return '<div class="'+rmsgCls(c&&c.cls)+'" id="'+id+'">'+(c?c.html:'')+'</div>'}
function rmsgSet(id,cls,html){RMSG[id]={cls:cls,html:html};var m=el(id);if(m){m.className=rmsgCls(cls);m.innerHTML=html}}
function rmsgClear(id){delete RMSG[id];var m=el(id);if(m){m.className=rmsgCls('');m.innerHTML=''}}
function num(x){x=+x;return isFinite(x)?x:0}
function fmtup(s){s=+s||0;var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60),c=Math.floor(s%60);
 if(d>0)return d+' '+T('fmt_day')+' '+T('fmt_and')+' '+h+' '+T('fmt_hr');
 if(h>0)return h+' '+T('fmt_hr')+' '+T('fmt_and')+' '+m+' '+T('fmt_min');
 if(m>0)return m+' '+T('fmt_min');
 return c+' '+T('fmt_sec')}
function fmtBytes(n){n=num(n);var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?(n<10?n.toFixed(2):n<100?n.toFixed(1):Math.round(n)):Math.round(n))+' '+u[i]}
function fmtRate(b){b=num(b);var u=['bps','Kbps','Mbps','Gbps'],i=0;while(b>=1000&&i<3){b/=1000;i++}return (i?(b<10?b.toFixed(1):Math.round(b)):Math.round(b))+' '+u[i]}
function tfRow(t){return '<div class="tf-row"><div class="tf-nm"><span class="mono">'+esc(t.name)+'</span><span class="tag '+esc(t.type)+'">'+esc(t.type)+'</span></div><div class="tf-fig"><span class="din iso">↓'+fmtRate(t.rx_bps)+'</span><span class="dout iso">↑'+fmtRate(t.tx_bps)+'</span><span class="tot iso"><b class="din">↓'+fmtBytes(t.rx_total)+'</b> <b class="dout">↑'+fmtBytes(t.tx_total)+'</b></span></div></div>'}
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
 gauge:'<svg viewBox="0 0 24 24" '+_S+'><path d="M3.5 18a9 9 0 1 1 17 0"/><path d="M12 18l4.2-5.2"/><circle cx="12" cy="18" r="1.5"/></svg>',
 fwd:'<svg viewBox="0 0 24 24" '+_S+'><path d="M3 12h11"/><path d="M10 8l4 4-4 4"/><path d="M19 5v14"/></svg>',
 list:'<svg viewBox="0 0 24 24" '+_S+'><path d="M9 6h11M9 12h11M9 18h8"/><path d="M4.5 6h.01M4.5 12h.01M4.5 18h.01"/></svg>',
 plus:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 5v14M5 12h14"/></svg>',
 pen:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M14 6l4 4"/></svg>',
 trash:'<svg viewBox="0 0 24 24" '+_S+'><path d="M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13"/></svg>',
 redo:'<svg viewBox="0 0 24 24" '+_S+'><path d="M21 12a9 9 0 11-2.64-6.36M21 4v4h-4"/></svg>',
 swap:'<svg viewBox="0 0 24 24" '+_S+'><path d="M8 3 4 7l4 4M4 7h16M16 21l4-4-4-4M20 17H4"/></svg>',
 reset:'<svg viewBox="0 0 24 24" '+_S+'><path d="M3 12a9 9 0 1 0 3-6.7L3 8M3 3v5h5"/><path d="M10 16v-4M14 16v-7"/></svg>',
 restart:'<svg viewBox="0 0 24 24" '+_S+'><path d="M12 3v8"/><path d="M7.5 5.8a8 8 0 1 0 9 0"/></svg>',
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
 search:'<svg viewBox="0 0 24 24" '+_S+'><circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/></svg>',
 chev:'<svg viewBox="0 0 24 24" '+_S+'><path d="M6 9l6 6 6-6"/></svg>',
 pause:'<svg viewBox="0 0 24 24" '+_S+'><path d="M9 5v14M15 5v14"/></svg>',
 play:'<svg viewBox="0 0 24 24" '+_S+'><path d="M7 4l13 8-13 8z"/></svg>'
};
function ic(n,c){return '<span class="ic"'+(c?' style="color:'+c+'"':'')+'>'+(IC[n]||'')+'</span>'}
function paintIcons(root){(root||document).querySelectorAll('[data-ic]').forEach(function(e){e.innerHTML=IC[e.dataset.ic]||''})}
function toggleTheme(){var d=document.body.classList.toggle('dark');try{localStorage.setItem('tnl_dark',d?'1':'')}catch(e){}paintThemeBtns();refresh()}
try{if(localStorage.getItem('tnl_dark'))document.body.classList.add('dark')}catch(e){}
paintIcons();paintNav();

function nodeIps(id){var n=NODES.find(function(x){return x.id==id});if(!n||!n.info||!n.info.ips)return [];
 var out=[],ips=n.info.ips;Object.keys(ips).forEach(function(k){(ips[k]||[]).forEach(function(ip){if(out.indexOf(ip)<0)out.push(ip)})});return out}
function ipItems(ips){return ips.map(function(x){return {v:x,label:x}})}

var cur='overview',NODES=[],FLEET=[],FRXHIST=[],FTXHIST=[],PF=[],TT=0,EDID=null,selTargets={},SEL={},SSI={},SSCB={},UPWIN=1,EVSEQ=0,LOGN=0,UIV=2000,EDGEV={},RORD=null,RSAVE=false;   
var QRY={nodes:'',tunnels:'',portfw:'',agent:'',core:'',logs:''},SEARCH_T=0,AGMETA=null,PAL=null,PALIDX=0,PALITEMS=[],PALDATA={nodes:[],tuns:[]};
var _ENUMS=__ENUMS_JSON__;   
var _WKMAX=[],_WKN=__WORKERSMAX__;for(var _i=1;_i<=_WKN;_i++)_WKMAX.push(_i);
function wkClamp(n){n=parseInt(n,10);return (n>=1&&n<=_WKN)?n:1}
function wkCarrier(S){return (S.Tr=='raw'||S.Tr=='udp')&&!S.Fec}
var _TUNDEF=__TUNDEF_JSON__;var _TUNSTEP=__TUNSTEP_JSON__;   
var _SETDEF=__SETDEF_JSON__;   
var _PROBESAMP=__PROBE_SAMPLES__;   
function CORE_CIPHERS(){return _ENUMS.ciphers.map(function(v){return {v:v,label:(v=='auto'?T('cipher_auto'):(v=='none'?T('cipher_none'):v))}})}
var TYPEITEMS=[{v:'vxlan',label:'VXLAN'},{v:'gre',label:'GRE'},{v:'sit',label:'SIT (IPv6)'},{v:'ipip',label:'IPIP'},{v:'l2tpv3',label:'L2TPv3'},{v:'fou',label:'IPIP-over-FOU'},{v:'ipsec',label:'IPsec'}];
function SUBNETRANGES(){function it(b,k){return {v:b,label:T(k),sub:'('+subnetFree(b)+')'}}
 return [it('192.168','snr_192'),it('10','snr_10'),it('172.16','snr_172'),{v:'custom',label:T('snr_custom')}]}
document.querySelectorAll('#nav .navi').forEach(function(p){p.onclick=function(){if(p.dataset.t=='logout'){logout();return}cur=p.dataset.t;drawer(false);render()}});
function setnav(){document.querySelectorAll('#nav .navi').forEach(function(p){p.classList.toggle('on',p.dataset.t==cur)})}
function drawer(open){document.body.classList.toggle('navopen',!!open)}
async function updateSidebar(){var s=await j('summary').catch(function(){return{}});
 setT('ct_nodes',num(s.nodes_total));setT('ct_proxies',num(s.proxies));setT('ct_tunnels',num(s.links));setT('ct_portfw',num(s.portfw));setT('ct_core',num(s.core));
 setT('ct_logs',num(s.log_count));LOGN=num(s.log_count);   
 if(s.ui_interval)UIV=Math.max(300,Math.round(num(s.ui_interval)*1000));   
 if(Array.isArray(s.suspect_backoff)&&s.suspect_backoff.length)_poolBackoff=s.suspect_backoff.map(Number);
 if(s.dead_retest_secs)_poolDeadStep=num(s.dead_retest_secs);
 if(s.subnet_free)SUBNET_FREE=s.subnet_free;
 EVSEQ=num(s.ev_seq);var raw=getLS('tnl_logs_seen'),seen;
 if(raw===''){seen=EVSEQ;setLS('tnl_logs_seen',EVSEQ)}else{seen=num(raw)}
 if(cur=='logs'){seen=EVSEQ;setLS('tnl_logs_seen',EVSEQ)}
 var un=Math.max(0,EVSEQ-seen);setUnread(un);
}
function setUnread(un){var e=el('ct_logs_un');if(!e)return;e.textContent=un>0?(un>99?'99+':String(un)):'';e.style.display=un>0?'':'none'}
function getLS(k){try{return localStorage.getItem(k)||''}catch(e){return ''}}
function setLS(k,v){try{localStorage.setItem(k,v)}catch(e){}}
function markLogsSeen(){setLS('tnl_logs_seen',EVSEQ);setUnread(0)}  

function ssHTML(key,items,sel,ph,cb){SSI[key]=items;SSCB[key]=cb||'';
 if(sel==null&&items.length)sel=items[0].v;SEL[key]=sel;
 var cur=items.filter(function(x){return String(x.v)==String(sel)})[0];
 return '<button type="button" class="msbtn'+(cur?'':' ph')+'" id="ssb_'+key+'" data-ha="'+esc(key)+'" onclick="ssToggle(hA(this))"><span id="sst_'+key+'">'+(cur?esc(cur.label):esc(_ssph(ph)))+'</span><span class="cv">'+ic('chev')+'</span></button>'}
function _ssph(ph){return ph||T('select')}
function ssRow(key,it){return '<div class="msrow'+(String(it.v)==String(SEL[key])?' sel':'')+'" data-v="'+esc(it.v)+'" data-ha="'+esc(key)+'" onclick="ssPick(hA(this),this)"><span class="mscheck"></span><span>'+esc(it.label)+'</span>'+(it.sub?'<span class="mssub">'+esc(it.sub)+'</span>':'')+'</div>'}
var SS_OV={};
function ssToggle(key){var items=SSI[key]||[];if(!items.length)return;  
 var search=items.length>10?'<input class="search sspopq" placeholder="'+esc(T('search'))+'" oninput="msFilter(this)" autocomplete="off">':'';
 SS_OV[key]=openModal('<div class="sspop">'+search+'<div class="sspoplist">'+items.map(function(it){return ssRow(key,it)}).join('')+'</div></div>',{cls:'sssheet'})}
function ssPick(key,row){var val=row.getAttribute('data-v');SEL[key]=val;
 var items=SSI[key]||[],cur=items.filter(function(x){return String(x.v)==String(val)})[0];
 setT('sst_'+key,cur?cur.label:val);var b=el('ssb_'+key);if(b)b.classList.remove('ph');
 if(SS_OV[key]){closeModal(SS_OV[key]);SS_OV[key]=null}
 if(SSCB[key]&&window[SSCB[key]])window[SSCB[key]]()}
function ssVal(key){return SEL[key]||''}
document.addEventListener('click',function(e){document.querySelectorAll('.mslist').forEach(function(l){
 if(l.style.display=='none')return;var b=l.previousElementSibling;
 if(l.contains(e.target)||(b&&b.contains(e.target)))return;
 l.style.display='none';if(b&&b.classList)b.classList.remove('open')})});

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
function formErr(m,txt){if(m){m.className='msg';m.textContent=''}   
 var ov=document.createElement('div');ov.className='modalov';
 ov.innerHTML='<div class="modal"><div class="mtext"></div><div class="mbtns"><button class="primary mok"></button></div></div>';
 ov.querySelector('.mtext').textContent=txt;
 ov.querySelector('.mok').textContent=T('got_it');
 document.body.appendChild(ov);
 function done(){ov.remove();document.removeEventListener('keydown',onk)}
 function onk(e){if(e.key!='Escape')return;var a=document.querySelectorAll('.modalov');if(a[a.length-1]!==ov)return;e.stopImmediatePropagation();done()}
 document.addEventListener('keydown',onk);
 ov.querySelector('.mok').onclick=done;
 ov.onclick=function(e){if(e.target==ov)done()};
 try{ov.querySelector('.mok').focus()}catch(e){}
 return true}
function toast(msg,kind){var t=document.createElement('div');t.className='toast '+(kind||'');
 t.innerHTML=(kind=='ok'?ic('okc'):kind=='err'?ic('xc'):'')+'<span>'+esc(msg)+'</span>';
 document.body.appendChild(t);setTimeout(function(){t.classList.add('show')},10);
 setTimeout(function(){t.classList.remove('show');setTimeout(function(){t.remove()},320)},3400)}

function copyFallback(t){try{var ta=document.createElement('textarea');ta.value=t;ta.setAttribute('readonly','');
 ta.style.cssText='position:fixed;top:0;left:-9999px;opacity:0';document.body.appendChild(ta);
 ta.select();ta.setSelectionRange(0,t.length);var ok=document.execCommand('copy');ta.remove();return !!ok}catch(_){return false}}
function copyTxt(t,e){if(e)e.stopPropagation();t=String(t||'').trim();if(!t)return;
 function done(ok){toast(ok?T('copied'):T('copy_fail'),ok?'ok':'err')}
 if(window.isSecureContext&&navigator.clipboard&&navigator.clipboard.writeText){
  navigator.clipboard.writeText(t).then(function(){done(true)},function(){done(copyFallback(t))});return}
 done(copyFallback(t))}
function cpv(t,cls){t=String(t||'');if(!t)return '<b class="mono">—</b>';
 return '<b class="mono cpv'+(cls?' '+cls:'')+'" title="'+esc(T('tip_copy'))+'" onclick="copyTxt(this.textContent,event)">'+esc(t)+'</b>'}

var ACTS={},ACTNOW=0,ADISM={},_ASTEP={},_ABUILDS=-1;
function actSeen(a){return a.key+':'+a.ended}                 
function actLive(a){return !!a&&!ADISM[actSeen(a)]}
function actOf(l){var a=ACTS['link:'+l.id];return actLive(a)?a:null}
async function refreshActs(){var r=await j('acts').catch(function(){return null});if(!r)return;
 ACTS=r.acts||{};ACTNOW=num(r.now);
 var n=0;for(var k in ACTS)if(k.indexOf('new:')===0&&ACTS[k].state=='run')n++;
 if(n!==_ABUILDS){_ABUILDS=n;if(cur=='core'||cur=='tunnels')refreshFleet()}}
function actAge(a){var t=(a.state=='run')?(ACTNOW-num(a.started)):(num(a.ended||ACTNOW)-num(a.started));
 t=Math.max(0,num(t));var m=Math.floor(t/60),s=t%60;return (m<10?'0':'')+m+':'+(s<10?'0':'')+s}
function actPill(a){return '<span class="ast '+esc(a.state)+'">'+(a.state=='run'?'<span class="apulse"></span>':'')+esc(T('a_st_'+a.state))+'</span>'}
function actWords(a){
 if(a.state=='fail')return esc(terr(a.err)||T('a_st_fail'));
 if(a.state=='cancel')return esc(T('a_stopped'));
 if(a.state=='done')return esc(a.note?terr(a.note):T('a_took').replace('{t}',actAge(a)));
 return esc(a.step||T('a_working'))}
function actBar(a){
 if(a.state=='run'&&!num(a.sn))return '<div class="abar spin"><i></i></div>';
 var pct=a.state=='done'?100:Math.max(5,num(a.pct));
 return '<div class="abar'+(a.state=='run'?'':' '+esc(a.state))+'"><i style="width:'+pct+'%"></i></div>'}
function actRow(a){if(!actLive(a))return '';
 var sw=(_ASTEP[a.key]!==a.step);_ASTEP[a.key]=a.step;
 var btn=(a.state=='run')
  ?(a.can?'<button class="abtn danger" type="button" data-ha="'+esc(a.key)+'" onclick="actCancel(hA(this))">'+esc(T('a_cancel'))+'</button>':'')
  :'<button class="abtn" type="button" title="'+esc(T('a_dismiss'))+'" data-ha="'+esc(actSeen(a))+'" onclick="actDismiss(hA(this))">✕</button>';
 return '<div class="arow">'+actPill(a)+
  '<span class="astep'+(sw?' sw':'')+'">'+actWords(a)+'</span>'+
  (a.state=='run'?'<span class="aclock">'+esc(actAge(a))+'</span>':'')+btn+actBar(a)+'</div>'}
function linkActRow(l){return actRow(actOf(l))}
function cardActCls(l){var a=actOf(l);return (a&&a.state=='run')?' acting':''}
function pendActs(page){var out=[],k;
 for(k in ACTS)if(k.indexOf('new:')===0&&ACTS[k].page==page&&ACTS[k].state!='done'&&actLive(ACTS[k]))out.push(ACTS[k]);
 return out.sort(function(x,y){return num(x.started)-num(y.started)})}
function apendCard(a){var fam=String(a.ttype||'').toLowerCase();
 return '<div class="card acc open apend'+(a.state=='run'?' acting':'')+'">'+
  '<div class="chead" style="cursor:default"><div class="hmain"><div class="hrow1">'+
   '<span class="hname">'+esc(T('a_pending'))+'</span>'+
   (fam?'<span class="ctag c-'+esc(fam)+'">'+esc(fam.toUpperCase())+'</span>':'')+
   '<span class="hpeers" dir="ltr">'+esc(a.target||'')+'</span>'+
  '</div></div></div>'+
  '<div class="cbody"><div class="cbody-in">'+actRow(a)+'</div></div></div>'}
function withPending(page,rows){
 return rows.concat(pendActs(page).map(function(a){return {k:'pend_'+a.key,h:apendCard(a)}}))}
async function actStarted(){await refreshActs();return refreshFleet()}
async function actCancel(key){var r=await post('act-cancel',{act:key});
 if(!(r.ok&&r.d.ok))toast(perr(r),'err');
 actStarted()}
function actDismiss(seen){ADISM[seen]=true;refresh().catch(function(){})}
async function actAccepted(key,box){var end=Date.now()+45000;
 while(Date.now()<end){
  if(box&&!box.isConnected)return {gone:true};   
  var r=await j('acts').catch(function(){return null});
  if(r&&r.acts){ACTS=r.acts;ACTNOW=num(r.now);
   var a=r.acts[key];
   if(!a)return {ok:true};                                    
   if(a.state=='fail')return {err:terr(a.err)||T('failed')};
   if(a.state=='cancel')return {err:T('a_stopped')};
   if(a.state=='done'||num(a.si)>=1)return {ok:true}}
  await new Promise(function(f){setTimeout(f,280)})}
 return {ok:true}}

function toolbar(kind,ph){var rb=(kind=='core'||kind=='tunnels'||kind=='nodes'||kind=='portfw')?'<button class="reordbtn" title="'+esc(T('reord_t'))+'" onclick="toggleReord()">'+gripSvg()+'</button>':'';
 return '<div class="toolbar"><input id="q_'+kind+'" class="search" placeholder="'+ph+'" value="'+esc(QRY[kind]||'')+'" data-ha="'+esc(kind)+'" oninput="onSearch(hA(this))">'+rb+'</div>'}
function onSearch(kind){clearTimeout(SEARCH_T);SEARCH_T=setTimeout(function(){QRY[kind]=v('q_'+kind);refresh()},280)}
function msFilter(inp){var q=inp.value.trim().toLowerCase(),list=inp.parentNode;
 list.querySelectorAll('.msrow').forEach(function(r){r.style.display=(!q||r.textContent.toLowerCase().indexOf(q)>=0)?'':'none'})}
var SUBNET_BASE_NETS={'192.168':[3232235520,16],'172.16':[2886729728,12],'10':[167772160,8]};
function subnetCap(base){var b=SUBNET_BASE_NETS[base]||SUBNET_BASE_NETS['192.168'];return (1<<(24-b[1]))-1}
function subnetForBase(type,tid,base){tid=num(tid)||0;
 if(type=='sit')return 'fd00:'+(tid>>16).toString(16)+':'+(tid&0xFFFF).toString(16)+'::/64';
 if(tid>subnetCap(base))base=['192.168','172.16','10'].filter(function(x){return tid<=subnetCap(x)})[0];
 if(!base||tid<1||tid>subnetCap(base))return '';
 var b=SUBNET_BASE_NETS[base];
 var n=(b[0]+tid*256)>>>0;
 return ((n>>>24)&255)+'.'+((n>>>16)&255)+'.'+((n>>>8)&255)+'.'+(n&255)+'/24'}
var SUBNET_FREE=null;
function subnetFree(base){if(SUBNET_FREE&&SUBNET_FREE[base]!=null)return num(SUBNET_FREE[base]);
 return subnetCap(base)}
function subnetBaseOf(l){var tid=num(l.tunnel_id);
 return ['192.168','172.16','10'].filter(function(x){return tid<=subnetCap(x)&&subnetForBase(l.type,tid,x)==l.subnet})[0]||'custom'}
function recalcEditSubnet(){if(!EDID)return;var L=FLEET.filter(function(x){return x.id==EDID})[0];if(!L)return;
 var b=ssVal('lsr_'+EDID),f=el('e_sub_'+EDID);
 if(f&&b&&b!='custom')f.value=subnetForBase(ssVal('lt_'+EDID),L.tunnel_id,b);
 renderEditPort(EDID)}
var LEDTYPE='',LEDPORT='';
function renderEditPort(id){var w=el('lpx_'+id);if(!w)return;var t=ssVal('lt_'+id);
 var pre=(t==LEDTYPE&&LEDPORT!=null)?String(LEDPORT):'';
 if(t=='vxlan')w.innerHTML='<label>'+esc(rng(T('le_port_4789'),1,PORT_MAX))+'</label><input id="le_port_'+id+'" inputmode="numeric" placeholder="4789" value="'+esc(pre)+'">';
 else if(t=='l2tpv3'||t=='fou')w.innerHTML='<label>'+esc(rng(T('le_port_auto'),1,PORT_MAX))+'</label><input id="le_port_'+id+'" inputmode="numeric" placeholder="'+esc(T('ttype_port_ph'))+'" value="'+esc(pre)+'">';
 else w.innerHTML=''}

function go(t){cur=t;drawer(false);render()}
function ocol(p){return p>85?cssv('--bad'):p>60?cssv('--gold'):cssv('--ok')}
function heatTip(ev,bar){ev.stopPropagation();var box=bar.parentNode;var tip=box.querySelector('.htip');
 if(!tip){tip=document.createElement('div');tip.className='htip';box.appendChild(tip)}
 tip.innerHTML='<span>'+esc(bar.dataset.nm)+'</span> '+bar.dataset.info;
 tip.style.left=(bar.offsetLeft+bar.offsetWidth/2)+'px';tip.style.display='block';
 clearTimeout(box._tt);box._tt=setTimeout(function(){if(tip)tip.style.display='none'},2400)}
function skb(w,h,r){return '<span class="sk" style="width:'+w+';height:'+(h||12)+'px'+(r!=null?';border-radius:'+r+'px':'')+'"></span>'}
function skNodeCard(){return '<div class="card node acc"><div class="chead">'+   
  '<span class="sk" style="width:38px;height:22px;border-radius:20px;flex:0 0 auto"></span>'+
  '<span class="grow"></span><div class="hmain" style="gap:6px;min-width:0;flex:0 0 auto">'+skb('90px',14)+skb('150px',11)+'</div>'+
  '<span class="sk" style="width:10px;height:10px;border-radius:50%;flex:0 0 auto"></span>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skAccCard(core){return '<div class="card acc"><div class="chead">'+   
  '<span class="sk" style="width:38px;height:22px;border-radius:20px;flex:0 0 auto"></span>'+
  '<div class="hmain"><div class="hrow1">'+skb('96px',13)+skb('40px',15,20)+
    '<span style="margin-inline-start:auto;display:flex;align-items:center;gap:5px">'+skb('58px',11)+'<span class="sk" style="width:14px;height:8px"></span>'+skb('58px',11)+'</span></div></div>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skPfCard(){return '<div class="card acc"><div class="chead">'+     
  '<div class="hmain"><div class="hrow1">'+skb('90px',13)+skb('40px',15,20)+
    '<span style="margin-inline-start:auto;display:flex;align-items:center;gap:5px">'+skb('54px',12)+skb('60px',18,20)+'</span></div></div>'+
  '<span class="sk" style="width:14px;height:14px;border-radius:4px;flex:0 0 auto"></span></div></div>'}
function skAgRow(){return '<div class="nx">'+             
  '<div class="nxh"><span class="sk" style="width:9px;height:9px;border-radius:50%"></span>'+
  '<span class="nmwrap">'+skb('92px',13)+skb('70px',11)+'</span></div>'+
  '<div class="nxv">'+skb('62px',25,8)+skb('62px',25,8)+'</div>'+
  '<div class="nxa">'+skb('34px',34,10)+skb('34px',34,10)+'</div></div>'}
function skCards(kind){
 var arr=(kind=='nodes'?NODES:kind=='portfw'?PF:kind=='agent'?NODES:FLEET)||[];
 var n=Math.max(3,Math.min(8,num(arr.length)||6));
 var one=kind=='nodes'?skNodeCard:kind=='portfw'?skPfCard:kind=='agent'?skAgRow:function(){return skAccCard(kind=='core')};
 var out='';for(var i=0;i<n;i++)out+=one();return out}   
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
 var sc=num(s.health_score),scol=sc>=85?cssv('--ok'):sc>=60?cssv('--gold'):cssv('--bad');
 var se=el('o_score');se.textContent=sc;se.style.color=scol;
 el('o_chips').innerHTML='<span class="ochip a">'+esc(T('ov_chip_node'))+' <b dir="ltr">'+on+'/'+tot+'</b></span>'+
  '<span class="ochip o">'+esc(T('ov_chip_uplink'))+' <b dir="ltr">'+num(s.link_up)+'/'+((num(s.link_total)-num(s.link_off))||links)+'</b></span>'+   
  '<span class="ochip a">'+esc(T('ov_chip_tunnel'))+' <b>'+num(s.tunnels)+'</b></span>'+
  (alerts.length?'<span class="ochip b">'+esc(T('ov_chip_alert'))+' <b>'+alerts.length+'</b></span>':'<span class="ochip o">'+esc(T('ov_chip_noalert'))+'</span>');
 var goMap={node:'nodes',link:'tunnels',drift:'tunnels',disk:'nodes',ram:'nodes',cpu:'nodes',agent:'settings'};
 var goLbl={nodes:T('nav_nodes'),tunnels:T('nav_tunnels'),settings:T('nav_settings')};
 el('o_alerts').innerHTML=alerts.length?alerts.map(function(a){var c=a.level=='bad'?cssv('--bad'):cssv('--gold');var g=goMap[a.kind]||'nodes';return '<div class="oalert"><span class="dot" style="background:'+c+'"></span><span class="msg">'+esc(a.msg)+'</span><span class="go" data-ha="'+esc(g)+'" onclick="go(hA(this))">'+goLbl[g]+' →</span></div>'}).join(''):'<div style="text-align:center;padding:10px 0;font-size:12.5px;color:var(--ok);display:flex;align-items:center;justify-content:center;gap:7px">'+ic('okc','var(--ok)')+' '+esc(T('ov_noalert'))+'</div>';
 var heat=s.heat||[];
 setHTML(el('o_heat'),heat.length?heat.map(function(h){var nm=esc(h.name);if(!h.online)return '<div class="hbar" onclick="heatTip(event,this)" data-nm="'+nm+'" data-info="'+esc(T('offline'))+'" title="'+nm+' — '+esc(T('offline'))+'" style="height:10px;background:color-mix(in srgb,var(--sub) 35%,transparent)"></div>';var p=num(h.pct);return '<div class="hbar" onclick="heatTip(event,this)" data-nm="'+nm+'" data-info="'+p+T('pct')+'" title="'+nm+' — '+p+T('pct')+'" style="height:'+(12+p*0.54)+'px;background:'+ocol(p)+'"></div>'}).join(''):'<div class="muted" style="font-size:12px">'+esc(T('ov_no_nodes'))+'</div>');
 setT('o_heat_c',(heat.length||0)+' '+T('ov_heat_note'));
 var c=s.central||{},cl=(c.load||[])[0];
 setGauge('scpu',c.cpu_pct,T('load')+' '+(cl!=null?cl:'—')+' · '+(num(c.cpus)||'?')+' '+T('cores_word'));
 setGauge('sram',c.ram_pct,c.mem_used_mb!=null?(num(c.mem_used_mb)+' / '+num(c.mem_total_mb)+' '+T('unit_mb')):'—');
 setGauge('sdisk',c.disk_pct,c.disk_used_mb!=null?(Math.round(num(c.disk_used_mb)/1024)+' / '+Math.round(num(c.disk_total_mb)/1024)+' '+T('unit_gb')):'—');
 var w=s.worst||{},wr=function(k,o){if(!o)return '';var p=num(o.pct),cc=ocol(p);return '<div class="wrow"><span class="wk">'+k+'</span><span class="wnm">'+esc(o.name)+'</span><span class="wbar"><i style="width:'+p+'%;background:'+cc+'"></i></span><span class="wpc" style="color:'+cc+'">'+p+T('pct')+'</span></div>'};
 var wh=wr(T('disk'),w.disk)+wr(T('ram'),w.ram)+wr('CPU',w.cpu);
 el('o_worst').innerHTML=wh||'<div class="muted" style="text-align:center;padding:8px 0;font-size:12.5px">'+esc(T('ov_no_online'))+'</div>';
 var lu=num(s.link_up),ln=num(s.link_noping),ld=num(s.link_down),ldr=num(s.link_drift),lo=num(s.link_off);
 el('o_tst').innerHTML='<div class="tb"><div class="n" style="color:var(--ok)">'+lu+'</div><div class="l">'+esc(T('tst_connected'))+'</div></div>'+
  '<div class="tb"><div class="n" style="color:var(--gold)">'+ln+'</div><div class="l">'+esc(T('tst_noping'))+'</div></div>'+
  '<div class="tb"><div class="n" style="color:'+(ld?'var(--bad)':'var(--tx)')+'">'+ld+'</div><div class="l">'+esc(T('tst_down'))+'</div></div>'+
  '<div class="tb"><div class="n" style="color:'+(ldr?'var(--gold)':'var(--tx)')+'">'+ldr+'</div><div class="l">'+esc(T('tst_rebuild'))+'</div></div>'+
  (lo?'<div class="tb"><div class="n" style="color:var(--sub)">'+lo+'</div><div class="l">'+esc(T('st_off'))+'</div></div>':'');
 var ty=s.link_types||{};
 var TYD=[['core','#6366f1'],['vxlan','var(--acc)'],['gre','var(--ok)'],['sit','#a855f7'],['ipip','#14b8a6'],['l2tpv3','#8b5cf6'],['fou','#ec4899'],['ipsec','#f43f5e']];
 var tt=0;TYD.forEach(function(x){tt+=num(ty[x[0]])});tt=tt||1;
 el('o_typebar').innerHTML=TYD.map(function(x){return '<i style="width:'+(num(ty[x[0]])/tt*100)+'%;background:'+x[1]+'"></i>'}).join('');
 el('o_typleg').innerHTML=TYD.filter(function(x){return num(ty[x[0]])>0}).map(function(x){return '<span><i class="otrack" style="background:'+x[1]+'"></i>'+x[0]+' <b>'+num(ty[x[0]])+'</b></span>'}).join('')||'<span class="muted">'+esc(T('ov_no_tunnel'))+'</span>';
 var wt=s.worst_tunnel;
 if(wt){var pr=(wt.a&&wt.b)?' <span dir="ltr" style="color:var(--tx);font-weight:800">'+esc(wt.a)+' ↔ '+esc(wt.b)+'</span>':'';
  setHTML(el('o_wtun'),'<div class="onote">📡 '+esc(T('ov_worst_q'))+' <b>'+esc(wt.name)+'</b>'+pr+(num(wt.loss)>0?' · '+esc(T('ov_loss'))+' <b style="color:var(--bad)">'+Math.round(num(wt.loss))+T('pct')+'</b>':'')+(wt.rtt!=null?' · '+esc(T('ov_ping'))+' <b>'+Math.round(num(wt.rtt))+'ms</b>':'')+'</div>');}
 else{setHTML(el('o_wtun'),'<div class="onote">'+ic('okc','var(--ok)')+' '+esc(T('ov_all_good'))+(s.fleet_avg_ping!=null?' · '+esc(T('ov_fleet_ping'))+' <b style="color:var(--tx)">'+num(s.fleet_avg_ping)+'ms</b>':'')+'</div>');}
 var frx=num(s.fleet_rx_bps),ftx=num(s.fleet_tx_bps);
 setT('o_frx',fmtRate(frx));setT('o_ftx',fmtRate(ftx));
 setT('o_ftin',fmtBytes(s.fleet_rx_total));setT('o_ftout',fmtBytes(s.fleet_tx_total));
 FRXHIST.push(frx);FTXHIST.push(ftx);if(FRXHIST.length>26){FRXHIST.shift();FTXHIST.shift()}dualSpark('o_traf',FRXHIST,FTXHIST);
 var uw=num(s.uptime_window)||1;
 setT('o_uptime',num(s.uptime_avg)+T('pct'));setT('o_uptime_l',T('ov_uptime_lbl')+' '+uw+' '+T('ov_hours_recent'));
 setT('o_updown',num(s.uptime_down_nodes))}

function nodesSkel(){el('view').innerHTML=vhead('server','nav_nodes','nodes_sub')+
 '<button class="primary" onclick="openNodeAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+esc(T('add_node'))+'</button>'+
 '<div class="sec">'+ic('server','var(--acc)')+' '+esc(T('nodes_fleet'))+'</div>'+toolbar('nodes',T('nodes_search'))+'<div id="nodeList">'+skCards('nodes')+'</div>'}
var _naddMode='auto';
async function openNodeAddModal(){await pxLoad();   
 _naddMode='auto';_authMode='pass';_installDone=null;_instStop();
 var seg='<div class="seg" id="nadd_seg"><button data-m="auto" class="on" onclick="naddSwitch(\\'auto\\')">'+ic('bolt')+esc(T('nadd_auto'))+'</button><button data-m="manual" onclick="naddSwitch(\\'manual\\')">'+ic('pen')+esc(T('nadd_manual'))+'</button></div>';
 var auto='<div id="nadd_auto">'+
   '<div class="autonote">'+ic('bolt')+'<span>'+esc(T('nadd_autonote'))+'</span></div>'+
   '<div class="grid2"><div><label class="first">'+esc(T('nadd_node_name'))+'</label><input id="a_name" placeholder="DE02"></div><div><label class="first">'+esc(T('nadd_srv_ip'))+'</label><input id="a_host" placeholder="5.75.197.55"></div></div>'+
   '<div class="grid2"><div><label>'+esc(rng(T('nadd_ssh_port'),1,PORT_MAX))+'</label><input id="a_sshport" placeholder="22"></div><div><label>'+esc(T('nadd_ssh_user'))+'</label><input id="a_user" placeholder="root"></div></div>'+
   '<div class="grid2"><div><label>'+esc(rng(T('nadd_agent_port'),1,PORT_MAX))+'</label><input id="a_aport" placeholder="8099"></div><div></div></div>'+
   '<div class="authbox"><div class="authhd"><span class="t">'+esc(T('nadd_ssh_auth'))+'</span><span class="authseg" id="a_authseg"><button type="button" data-am="pass" class="on" onclick="authMode(\\'pass\\')">'+esc(T('nadd_pass'))+'</button><button type="button" data-am="key" onclick="authMode(\\'key\\')">'+esc(T('nadd_privkey'))+'</button></span></div>'+
    '<input id="a_pass" class="fld2" type="password" placeholder="'+esc(T('nadd_pass_ph'))+'" autocomplete="new-password">'+
    '<textarea id="a_key" class="fld2" rows="3" style="display:none" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>'+
    '<div class="muted" id="a_authhint" style="font-size:11px;margin-top:7px">'+esc(T('nadd_pass_hint'))+'</div></div>'+
   proxyBlock('a_')+
   '<div id="nadd_prog"></div></div>';
 var manual='<div id="nadd_manual" style="display:none"><div class="grid2"><div><label class="first">'+esc(T('nadd_manual_name'))+'</label><input id="n_name" placeholder="frankfurt-1"></div><div><label class="first">'+esc(T('nadd_manual_host'))+'</label><input id="n_host" placeholder="203.0.113.10"></div></div><div class="grid2"><div><label>'+esc(rng(T('nadd_agent_port2'),1,PORT_MAX))+'</label><input id="n_port" placeholder="8099"></div><div><label>'+esc(T('nadd_node_tok'))+'</label><input id="n_tok" placeholder="'+esc(T('nadd_node_tok'))+'"></div></div>'+proxyBlock('n_')+'</div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>'+esc(T('nadd_title'))+'</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+seg+auto+manual+'<div class="msg" id="n_msg"></div></div><div class="mfoot"><button class="primary" id="nadd_go" onclick="naddSubmit()">'+ic('bolt')+esc(T('nadd_install_connect'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
function naddSwitch(m){_naddMode=m;_installDone=null;_instStop();
 var a=el('nadd_auto'),mn=el('nadd_manual');if(a)a.style.display=m=='auto'?'':'none';if(mn)mn.style.display=m=='manual'?'':'none';
 document.querySelectorAll('#nadd_seg button').forEach(function(b){b.classList.toggle('on',b.dataset.m==m)});
 var btn=el('nadd_go');if(btn){btn.disabled=false;btn.className='primary';btn.innerHTML=(m=='auto'?ic('bolt')+esc(T('nadd_install_connect')):ic('plus')+esc(T('nadd_add_connect')))}
 var pr=el('nadd_prog');if(pr&&m=='manual')pr.innerHTML='';
 var msg=el('n_msg');if(msg){msg.className='msg';msg.textContent=''}}
var _installDone=null;  
function naddSubmit(){if(_naddMode=='auto'){if(_installDone=='ok'){var ov=el('nadd_go').closest('.modalov');if(ov)closeModal(ov);return}return doAutoInstall()}return addNode()}
function instIcon(st){return st=='ok'?'<span class="istep-i ok">'+CK+'</span>':st=='err'?'<span class="istep-i err">'+XK+'</span>':st=='warn'?'<span class="istep-i warn">'+ic('warn')+'</span>':st=='run'?'<span class="istep-i run"><span class="ispin"></span></span>':'<span class="istep-i wait"></span>'}
var _inst=null,_MINSPIN=600;
function _insteps(){return [{label:T('inst_ssh'),detail:T('inst_connecting')},{label:T('inst_agent'),detail:T('inst_waiting')},{label:T('inst_service'),detail:T('inst_waiting')},{label:T('inst_register'),detail:T('inst_waiting')}]}
function _instStop(){if(_inst){_inst.cancelled=true;if(_inst.timer)clearTimeout(_inst.timer);_inst=null}}
function _instPoll(c){j('install-status?job='+encodeURIComponent(c.job)+'&_='+Date.now())
 .then(function(d){c.polling=false;
   if(d&&d.ok){c.failN=0;c.steps=d.steps||[];c.confirmed=c.steps.map(function(s){return s.state});if(d.banner)c.banner=d.banner;c.bDone=!!d.done;c.bOk=!!d.success}
   else if(d&&/not found/.test(d.error||'')){c.err=T('inst_status_notfound');c.bDone=true;c.bOk=false}
   else{c.failN++;if(c.failN>=45){c.err=T('inst_panel_lost');c.bDone=true;c.bOk=false}}})
 .catch(function(){c.polling=false;c.failN++;if(c.failN>=45){c.err=T('inst_panel_lost');c.bDone=true;c.bOk=false}})}
function _instRender(c){var box=el('nadd_prog');if(!box)return;var anim=!c.finished;
 var bicon=anim?'<span class="ispin"></span>':(c.bOk?CK:XK);
 var btext=anim?T('inst_installing'):(c.err||c.banner||T('inst_done'));   
 var html='<div class="ibanner '+(anim?'run':(c.bOk?'ok':'err'))+'">'+bicon+'<span>'+esc(btext)+'</span></div>';
 var steps=c.steps||[],conf=c.confirmed||[];
 for(var i=0;i<c.revealIdx;i++){var s=steps[i]||{},cst=conf[i]||'',disp;
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
 if(c.cancelled||!el('nadd_prog')){_instStop();return}   
 var now=_instNow();
 if(!c.polling&&now-c.lastPoll>=380){c.polling=true;c.lastPoll=now;_instPoll(c)}
 var conf=c.confirmed||[],started=0;
 for(var i=0;i<conf.length;i++){if(conf[i]&&conf[i]!='wait')started=i+1}
 var cur=c.revealIdx-1,curTerm=cur<0||(conf[cur]&&conf[cur]!='wait'&&conf[cur]!='run');
 if(c.revealIdx<started&&now-c.lastReveal>=_MINSPIN&&curTerm){c.revealIdx++;c.lastReveal=now}  
 if(!c.finished&&c.bDone&&c.revealIdx>=started&&now-c.lastReveal>=_MINSPIN&&(started>0||c.err)){_instFinish(c);return}
 _instRender(c);c.timer=setTimeout(_instTick,150)}
function proxyBlock(pfx){return pxFields(pfx, _pxNode[pfx]||null)}
var _pxNode={};
var _authMode='pass';
function authMode(m){_authMode=m;
 var pf=el('a_pass'),kf=el('a_key'),h=el('a_authhint');
 if(pf)pf.style.display=(m=='pass')?'':'none';if(kf)kf.style.display=(m=='key')?'':'none';
 document.querySelectorAll('#a_authseg button').forEach(function(b){b.classList.toggle('on',b.dataset.am==m)});
 if(h)h.textContent=(m=='key')?T('nadd_key_hint'):T('nadd_pass_hint');
 var f=(m=='pass')?pf:kf;if(f){try{f.focus()}catch(e){}}}
function agBtnBusy(btn,on,label){if(!btn)return;btn.disabled=on;
 btn.innerHTML=on?'<span class="bspin"></span>':label}
async function doAutoInstall(){if(_inst)return;var m=el('n_msg'),btn=el('nadd_go');   
 var name=v('a_name'),host=v('a_host');
 var pass=_authMode=='pass'?v('a_pass'):'',key=_authMode=='key'&&el('a_key')?el('a_key').value.trim():'';
 if(!name||!host){formErr(m,T('nadd_need_name_ip'));return}
 if(!nodeNameOK(name)){formErr(m,T('node_name_ascii'));return}
 if(!pass&&!key){formErr(m,(_authMode=='key'?T('nadd_privkey'):T('nadd_pass_word'))+T('nadd_is_required'));return}
 _installDone=null;m.className='msg';m.textContent='';agBtnBusy(btn,true);
 var _st0=_insteps()[0];
 var pr=el('nadd_prog');if(pr){pr.innerHTML='<div class="iwrap"><div class="ibanner run"><span class="ispin"></span><span>'+esc(T('inst_installing'))+'</span></div><div class="istep run"><span class="istep-i run"><span class="ispin"></span></span><div class="istep-b"><div class="istep-t">'+esc(_st0.label)+'</div><div class="istep-s">'+esc(_st0.detail)+'</div></div></div></div>';pr.scrollIntoView({behavior:'smooth',block:'center'})}
 var r=await post('node-install',Object.assign({name:name,ssh_host:host,ssh_port:v('a_sshport'),ssh_user:v('a_user'),agent_port:v('a_aport'),ssh_pass:pass,ssh_key:key},pxBody('a_'))).catch(function(){return{ok:false,d:{}}});
 if(!(r.ok&&r.d.ok)){formErr(m,terr((r.d&&r.d.error))||T('failed'));if(pr)pr.innerHTML='';agBtnBusy(btn,false,ic('bolt')+esc(T('nadd_install_connect')));return}
 _inst={job:r.d.job,steps:_insteps().map(function(s){return{label:s.label,detail:s.detail}}),confirmed:['run','wait','wait','wait'],banner:T('inst_installing'),bDone:false,bOk:false,err:'',revealIdx:1,lastReveal:_instNow(),lastPoll:0,polling:false,failN:0,finished:false,cancelled:false,timer:null};
 _instTick()}
function listBusy(){return !!(RORD||RSAVE)}
async function refreshNodes(){if(listBusy())return;var r=await j('nodes?q='+encodeURIComponent(QRY.nodes));NODES=r.nodes||[];UPWIN=num(r.uptime_window)||1;var box=el('nodeList');if(!box||listBusy())return;   
 var rows=[],bn=cnBanner(NODES);
 if(bn)rows.push({k:'__banner',h:bn});
 NODES.forEach(function(n){rows.push({k:n.id,h:nodeCard(n)})});
 if(!NODES.length)rows.push({k:'__empty',h:'<div class="card muted">'+(QRY.nodes?T('no_results'):T('nodes_empty'))+'</div>'});
 setList(box,rows)}
function cnBanner(ns){var k=(ns||[]).filter(cnStale).length;if(!k)return '';
 return '<div class="rdbar" style="margin-bottom:12px">'+ic('warn')+'<div class="rdtx"><b>'+
  esc(k==1?T('cn_stale_one'):T('cn_stale_n').replace('{n}',k))+'</b><span>'+esc(T('cn_stale_sub'))+'</span></div></div>'}
function kv(k,val){return '<span>'+k+': <b>'+val+'</b></span>'}
function openModal(html,opts){opts=opts||{};
 var ov=document.createElement('div');ov.className='modalov';
 ov.innerHTML='<div class="modal wide'+(opts.cls?' '+opts.cls:'')+'">'+html+'</div>';
 document.body.appendChild(ov);
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
 if(!document.querySelector('.modalov')){EDID=null;try{document.body.style.overflow=''}catch(e){}}
 refresh().catch(function(){})}
function glvl(p){return p>=88?'crit':p>=70?'warn':'ok'}
function gaugeHTML(key,label){return '<div class="gauge"><div class="gwrap"><svg width="84" height="84"><circle class="gtrack" cx="42" cy="42" r="33" fill="none" stroke-width="8"/><circle id="g_'+key+'" class="gfill ok" cx="42" cy="42" r="33" fill="none" stroke-width="8" stroke-linecap="round" stroke-dasharray="207.3" stroke-dashoffset="207.3" transform="rotate(-90 42 42)"/></svg><div class="gc"><b id="gt_'+key+'">—</b></div></div><div class="gl">'+label+'</div><div class="gsub" id="gs_'+key+'">…</div></div>'}
function setGauge(key,pct,sub){var C=207.3,g=el('g_'+key),t=el('gt_'+key),s=el('gs_'+key);if(!g)return;
 pct=Math.max(0,Math.min(100,Math.round(num(pct))));
 g.setAttribute('stroke-dashoffset',(C*(1-pct/100)).toFixed(1));g.setAttribute('class','gfill '+glvl(pct));
 t.innerHTML=pct+'<i>'+T('pct')+'</i>';if(s&&sub!=null)s.textContent=sub}
function cnStale(n){var got=(n.info&&n.info.central)||'',want=n.central_want||'';return !!(got&&want&&got!==want)}
function cnCell(n){var got=(n.info&&n.info.central)||'';
 if(!got)return '<span class="muted">'+esc(T('nd_central_none'))+'</span>';
 return '<span class="mono'+(cnStale(n)?' cn-stale':'')+'">'+esc(got)+'</span>'}
function ndTile(icn,label,val,wide,ltr){return '<div class="nd-tile'+(wide?' nd-wide':'')+'"><span class="medi">'+ic(icn)+'</span><span>'+label+'</span><b'+(ltr?' class="ltr"':'')+'>'+val+'</b></div>'}
function ndApplyStats(s){var rp=s.mem_total_mb?Math.round(num(s.mem_used_mb)/num(s.mem_total_mb)*100):0;
 setGauge('cpu',s.cpu_pct,T('load')+' '+((s.load||[])[0]||'—'));
 setGauge('ram',rp,num(s.mem_used_mb)+' / '+num(s.mem_total_mb)+' '+T('unit_mb'));
 setGauge('disk',s.disk_pct,s.disk_used_mb!=null?(Math.round(num(s.disk_used_mb)/1024)+' / '+Math.round(num(s.disk_total_mb)/1024)+' '+T('unit_gb')):'—')}
function ndSetHead(ov,online){var dot=ov.querySelector('.nd-head .dot');if(dot)dot.className='dot '+(online?'ok':'bad');
 var bd=ov.querySelector('.nd-head .nd-ping');if(bd){bd.className='badge '+(online?'ok':'bad')+' nd-ping';bd.textContent=online?T('online'):T('offline')}
 var sb=ov.querySelector('.msticky .sb');if(sb)sb.innerHTML=online?'<span class="lpill"><span class="pd"></span>'+esc(T('live'))+'</span> '+esc(T('refresh2s')):esc(T('nd_off_last'))}
function nodeDetails(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;var i=n.info||{},s=i.stats||{};
 var head='<div class="nd-head"><span class="dot '+(n.online?'ok':'bad')+'"></span><div class="nd-id"><b class="nd-name">'+esc(n.name)+'</b><span class="nd-hp">'+esc(n.host)+':'+esc(n.port)+'</span></div>'+(n.proxy_on?'<span class="tag" style="margin-inline-start:6px">'+esc(T('proxy'))+'</span>':'')+'<span class="badge '+(n.online?'ok':'bad')+' nd-ping">'+(n.online?T('online'):T('offline'))+'</span></div>';
 var mb;
 if(n.online){var g='<div class="gauges">'+gaugeHTML('cpu','CPU')+gaugeHTML('ram','RAM')+gaugeHTML('disk',T('disk'))+'</div>';
  var traf='<div class="nd-sec">'+ic('traf')+' '+esc(T('nd_traffic'))+'<span class="lpill" style="margin-inline-start:auto"><span class="pd"></span>'+esc(T('live'))+'</span></div><div class="tf-chart"><div class="tf-top"><span class="din iso">↓ <b id="tf_rin">—</b></span><span class="dout iso">↑ <b id="tf_rout">—</b></span></div><svg id="tf_spark" class="tf-spk" viewBox="0 0 300 46" preserveAspectRatio="none"></svg></div><div class="ttiles"><div class="ttile"><span class="din">'+esc(T('ov_rxtot'))+'</span><b id="tf_tin">—</b></div><div class="ttile"><span class="dout">'+esc(T('ov_txtot'))+'</span><b id="tf_tout">—</b></div></div><div id="tf_tuns" class="tf-tuns"></div>';
  var tiles='<div class="nd-grid">'+ndTile('os',T('os'),esc(s.os||'?'),false,true)+ndTile('clock',T('uptime'),s.uptime?fmtup(s.uptime):'?')+ndTile('cores',T('cpu_cores'),num(s.cpus)||'?')+ndTile('link',T('nd_tunnels'),num(i.tunnels))+ndTile('globe',T('nd_portfw'),num(i.portfw))+ndTile('shield',T('nd_ctrlproxy'),n.proxy_on?esc(n.proxy_name||'?'):'—')+ndTile('server',T('host'),esc(i.hostname||'?'),true,true)+ndTile('pin',T('ip'),esc(n.host),true,true)+ndTile('globe',T('nd_central'),cnCell(n),true,true)+'</div>';
  mb=head+g+traf+'<div class="nd-divider"></div>'+tiles+'<div class="nd-divider"></div><div class="nd-sec">'+ic('pin')+' '+esc(T('nd_ips'))+'<span class="muted" style="margin-inline-start:auto;font-size:11px;font-weight:500">'+esc(T('ip_leg'))+'</span></div><div id="nd_ips" class="ndips"><div class="muted" style="font-size:11.5px;padding:6px 2px">…</div></div>'}
 else{mb=head+'<div class="nd-off">'+ic('plugoff')+'<b>'+esc(T('not_available'))+'</b>'+(i.error?'<span>'+esc(i.error)+'</span>':'')+'</div>'}
 var sub=n.online?'<span class="lpill"><span class="pd"></span>'+esc(T('live'))+'</span> '+esc(T('refresh2s')):esc(T('nd_status'));
 var html='<div class="msticky"><span class="medi">'+ic('info')+'</span><div class="ttl"><h3>'+esc(T('nd_title'))+'</h3><div class="sb">'+sub+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+mb+'</div><div class="mfoot"><button class="primary" data-ha="'+esc(id)+'" onclick="ndRetest(hA(this))">'+esc(T('nd_conn_test'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('close'))+'</button></div>';
 var ov=openModal(html,{cls:'ndsheet',onclose:function(){if(ov._iv){clearInterval(ov._iv);ov._iv=0}}});
 if(n.online){ndApplyStats(s);var tfin=[],tfout=[];
  post('node-ips',{id:id}).then(function(v){if(ov._closed)return;var r=v.d;var ib=el('nd_ips');if(ib)ib.innerHTML=ipTagsHTML(r&&r.ips)});
  var poll=function(){
   j('node-stats?id='+id).then(function(r){if(ov._closed)return;if(r&&r.online&&r.stats){ndApplyStats(r.stats);ndSetHead(ov,true)}else{ndSetHead(ov,false)}}).catch(function(){});
   j('traffic?id='+id).then(function(r){if(ov._closed||!r||!r.node)return;var nd=r.node;
    setT('tf_rin',fmtRate(nd.rx_bps));setT('tf_rout',fmtRate(nd.tx_bps));setT('tf_tin',fmtBytes(nd.rx_total));setT('tf_tout',fmtBytes(nd.tx_total));
    tfin.push(num(nd.rx_bps));tfout.push(num(nd.tx_bps));if(tfin.length>30){tfin.shift();tfout.shift()}dualSpark('tf_spark',tfin,tfout);
    var rows=(r.tunnels||[]).concat(r.portfw||[]);
    var tb=el('tf_tuns');if(tb)tb.innerHTML=rows.length?rows.map(tfRow).join(''):'<div class="muted" style="font-size:11.5px;padding:7px 2px">'+esc(T('nd_no_tp'))+'</div>'}).catch(function(){})};
  poll();ov._iv=setInterval(poll,UIV)}}   
function ndRetest(id){j('node-stats?id='+id).then(function(r){if(r&&r.online){toast(T('online'),'ok')}else{toast(T('offline')+': '+((r&&r.error)||T('not_available')),'err')}}).catch(function(){toast(T('err_check'),'err')})}
async function openNodeEdit(id){var n=NODES.find(function(x){return x.id==id});if(!n)return;
 await pxLoad();   
 _pxNode['ne_']=n;
 var b='<div class="grid2"><div><label class="first">'+esc(T('f_name'))+'</label><input id="e_name_'+id+'" value="'+esc(n.name)+'"></div><div><label class="first">'+esc(T('f_host_ip'))+'</label><input id="e_host_'+id+'" value="'+esc(n.host)+'"></div></div><div class="grid2"><div><label>'+esc(T('f_port'))+'</label><input id="e_port_'+id+'" value="'+esc(n.port)+'"></div><div><label>'+esc(T('f_token'))+'</label><input id="e_tok_'+id+'" placeholder="'+esc(T('tok_keep'))+'"></div></div>'+proxyBlock('ne_')+'<div class="msg" id="em_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('nd_edit'))+'</h3><div class="sb">'+esc(n.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" data-ha="'+esc(id)+'" onclick="saveEdit(hA(this))">'+esc(T('save'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
function liveIP(ips,cur){ips=ips||[];return (cur&&ips.indexOf(cur)>=0)?cur:''}
function ipEndField(side,id,nm,ips,cur){var lab='<label class="first">'+esc(T('ip_of'))+esc(nm)+'</label>';
 ips=(ips&&ips.length)?ips:(cur?[cur]:[]);
 if(ips.length>1)return '<div>'+lab+ssHTML('lip'+side+'_'+id,ips.map(function(x){return{v:x,label:x}}),(cur&&ips.indexOf(cur)>=0)?cur:ips[0],T('ip'),'')+'</div>';
 return '<div>'+lab+'<input class="mono" value="'+esc(ips[0]||cur||'—')+'" disabled style="opacity:.6"></div>'}
function openLinkEdit(id){var l=FLEET.find(function(x){return x.id==id});if(!l)return;EDID=id;LEDTYPE=l.type;LEDPORT=(l.port==null?'':l.port);
 var multi=((l.a_ips||[]).length>1)||((l.b_ips||[]).length>1);
 var b='<div class="grid2"><div><label class="first">'+esc(T('tun_type'))+'</label>'+ssHTML('lt_'+id,TYPEITEMS,l.type,T('ttype'),'recalcEditSubnet')+'</div><div><label class="first">'+esc(T('range'))+'</label>'+ssHTML('lsr_'+id,SUBNETRANGES(),subnetBaseOf(l),T('range'),'recalcEditSubnet')+'</div></div><label>'+esc(T('subnet'))+'</label><input id="e_sub_'+id+'" value="'+esc(l.subnet)+'"><div id="lpx_'+id+'"></div>'+
  '<div class="muted" style="font-weight:700;color:var(--tx);margin:16px 2px 9px;display:flex;align-items:center;gap:6px">'+ic('pin','var(--acc)')+esc(T('ip_each_end'))+(multi?' <span class="tag" style="font-size:9.5px;padding:1px 7px">'+esc(T('multi_ip'))+'</span>':'')+'</div>'+
  '<div class="grid2">'+ipEndField('a',id,l.a_name,l.a_ips,l.a_ip)+ipEndField('b',id,l.b_name,l.b_ips,l.b_ip)+'</div>'+
  '<div class="muted" style="font-size:11.5px;margin-top:9px">'+esc(T('link_ip_note1'))+esc(l.tunnel_id)+esc(T('link_ip_note2'))+'</div><div class="msg" id="lem_'+id+'"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('link')+'</span><div class="ttl"><h3>'+esc(T('edit_tun_t'))+'</h3><div class="sb">'+esc(l.a_name)+' ↔ '+esc(l.b_name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" data-ha="'+esc(id)+'" onclick="saveLinkEdit(hA(this))">'+esc(T('save_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{onclose:function(){EDID=null}});
 renderEditPort(id)}
async function openPfEdit(i){var p=PF[i];if(!p)return;var rotOn=p.switch_interval>0;
 var r=await j('node-names');NODES=r.nodes||[];var ips=nodeIps(p.node_id);
 var lipsec=(ips.length>1)?'<label class="first">'+esc(T('pf_lip'))+'</label>'+ssHTML('pe_lip',ipItems(ips),(p.listen_ip&&ips.indexOf(p.listen_ip)>=0?p.listen_ip:ips[0]),T('ip'),'')+'<div class="muted" style="font-size:11px;margin:-3px 2px 12px">'+esc(T('pf_lip_note'))+'</div>':'';
 var fc=lipsec?'':' class="first"';
 var b=lipsec+'<div class="grid2"><div><label'+fc+'>'+esc(rng(T('pf_listen_port'),1,PORT_MAX))+'</label><input id="pe_lp" value="'+esc(p.listen_port)+'"></div><div><label'+fc+'>'+esc(rng(T('pf_dst_port'),1,PORT_MAX))+'</label><input id="pe_dp" value="'+esc(p.dst_port)+'"></div></div><label>'+esc(T('pf_dst_ips'))+'</label><input id="pe_ips" value="'+esc((p.dst_ips||[]).join(', '))+'"><label>'+esc(T('pf_rot_between'))+'</label><div class="tgl"><span class="tglsw'+(rotOn?' on':'')+'" id="pe_tgl" onclick="pfTgl()"></span><span class="muted" id="pe_tgllbl">'+(rotOn?T('on_word'):T('off_word'))+'</span></div><div id="pe_intwrap" style="'+(rotOn?'':'display:none')+'"><label>'+esc(T('pf_rot_interval'))+'</label><input id="pe_int" value="'+esc(rotOn?(p.switch_interval/60):5)+'"></div><div class="muted" style="font-size:11.5px;margin-top:9px">'+esc(T('pf_rot_note'))+'</div><div class="msg" id="pem"></div>';
 var ov=openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('pf_edit_t'))+'</h3><div class="sb">'+esc(p.node)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="savePfEdit(this)">'+esc(T('save'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');
 ov._pf={node_id:p.node_id,name:p.name}}
function nodeCard(n){var i=n.info||{};
 var key=n.id,open=!!TOPEN[key];
 var en=(n.disabled!==true);   
 var dotk=n.online?'on':(n.pending?'':'off');   
 var head='<div class="chead" onclick="cardTogFromEl(this)">'+grip()+'<div class="tsw'+(en?' on':'')+'" data-ha="'+esc(n.id)+'" onclick="toggleNode(hA(this),event)" title="'+esc(T('nd_toggle'))+'"></div>'+(n.moved_to?'<button class="mvwarn" data-nid="'+esc(n.id)+'" onclick="openMovedIp(this,event)" title="'+esc(T('nd_moved_t'))+'">'+ic('warn')+'</button>':'')+'<span class="grow"></span><div class="hmain" style="direction:ltr;align-items:flex-start;gap:2px;flex:0 0 auto;min-width:0"><div class="name" style="text-align:left">'+esc(n.name)+(n.pending_del>0?' <span class="tag" style="font-size:9px;padding:1px 5px;background:color-mix(in srgb,#e0894f 18%,transparent);color:#e0894f" title="'+esc(T('pend_del_t'))+'">'+ic('trash')+num(n.pending_del)+'</span>':'')+(n.proxy_on?' <span class="tag" style="font-size:9.5px;padding:1px 6px">'+esc(T('proxy'))+'</span>':'')+'</div><div class="muted mono" style="font-size:12px">'+esc(n.host)+':'+esc(n.port)+'</div></div>'+'<span class="ndot '+dotk+'" title="'+esc(n.online?T('online'):(n.pending?T('pending_check'):T('offline')))+'"></span>'+CHEVI+'</div>';
 var body=n.online?'<div class="nchips"><span class="nchip">'+ic('link')+esc(T('nd_tunnels'))+' <b>'+num(i.tunnels)+'</b></span><span class="nchip">'+ic('globe')+esc(T('nd_portfw'))+' <b>'+num(i.portfw)+'</b></span>'+(i.version?'<span class="nchip">'+ic(AG_IC)+esc(T('nd_agent'))+' v<b>'+num(i.version)+'</b></span>':'')+((i.core_sha&&String(i.core_sha).length)?'<span class="nchip">'+ic(COR_IC)+esc(T('nd_core'))+' <b>'+esc(i.core_ver||'?')+'</b></span>':'<span class="nchip" style="color:var(--sub)">'+ic(COR_IC)+esc(T('nd_core'))+' <b>'+esc(T('nd_core_missing'))+'</b></span>')+'</div>':'<div class="noff">'+ic('plugoff')+'<b>'+esc(T('not_available'))+'</b>'+(i.error?'<span>· '+esc(i.error)+'</span>':'')+'</div>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_test'))+'" data-ha="'+esc(n.id)+'" onclick="testNode(hA(this))">'+ic('bolt')+'</button>'+(n.online?'<button class="act" title="'+esc(T('tip_tune'))+'" data-ha="'+esc(n.id)+'" onclick="kernelTune(hA(this))">'+ic('gauge')+'</button>':'')+'<button class="act reset" title="'+esc(T('tip_nreset'))+'" data-ha="'+esc(n.id)+'" onclick="resetNodeTraffic(hA(this))">'+ic('reset')+'</button><button class="act info" title="'+esc(T('tip_details'))+'" data-ha="'+esc(n.id)+'" onclick="nodeDetails(hA(this))">'+ic('info')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" data-ha="'+esc(n.id)+'" onclick="openNodeEdit(hA(this))">'+ic('pen')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" data-nid="'+esc(n.id)+'" data-nm="'+esc(n.name)+'" data-online="'+(n.online?'1':'0')+'" onclick="delNode(this)">'+ic('trash')+'</button></div>';
 return '<div class="card node acc'+(open?' open':'')+(en?'':' off')+'" id="c_'+esc(key)+'" data-rid="'+esc(key)+'" data-rk="nodes">'+head+ndTraf(n)+'<div class="cbody"><div class="cbody-in">'+body+upBar(n)+acts+rmsgHTML('ntm_'+n.id)+'</div></div></div>'}
async function toggleNode(id,e){e.stopPropagation();var n=NODES.filter(function(x){return x.id==id})[0];if(!n)return;  
 var dis=!(n.disabled===true);n.disabled=dis;
 var c=el('c_'+id);if(c){var sw=c.querySelector('.tsw');if(sw)sw.classList.toggle('on',!dis);c.classList.toggle('off',dis)}
 var r=await post('node-toggle',{id:id,disabled:dis});
 if(!(r.ok&&r.d.ok)){n.disabled=!dis;if(c){var s2=c.querySelector('.tsw');if(s2)s2.classList.toggle('on',dis);c.classList.toggle('off',!dis)}toast(T('failed'),'err')}
 else{toast(dis?T('nd_hidden'):T('nd_shown'),'ok')}}
function openMovedIp(el,e){if(e)e.stopPropagation();
 var id=(el&&el.getAttribute)?el.getAttribute('data-nid'):el;
 var n=NODES.filter(function(x){return x.id==id})[0]||{};
 if(!n.moved_to)return;
 openModal('<div class="msticky"><span class="medi warn">'+ic('warn')+'</span><div class="ttl"><h3>'+esc(T('mv_title'))+'</h3><div class="sb">'+esc(n.name||'')+'</div></div></div>'
  +'<div class="mbody"><div class="kt-desc">'+esc(T('mv_desc'))+'</div>'
  +'<div class="nd-grid">'+ndTile('globe',T('mv_new'),'<span class="mono" style="direction:ltr">'+esc(n.moved_to)+'</span>')
  +ndTile('server',T('mv_old'),'<span class="mono" style="direction:ltr">'+esc(n.host)+'</span>')+'</div>'
  +'<div class="msg" data-mv></div></div>'
  +'<div class="mfoot hug"><button class="primary" data-nid="'+esc(id)+'" onclick="adoptMovedIp(this)">'+ic('check')+esc(T('mv_set'))+'</button>'
  +'<button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('close'))+'</button></div>')}
async function adoptMovedIp(btn){var ov=btn.closest('.modalov'),m=ov?ov.querySelector('[data-mv]'):null;   
 btn.disabled=true;if(m){m.className='msg';m.textContent=T('mv_setting')}
 var r=await post('node-adopt-ip',{id:btn.getAttribute('data-nid')});
 if(r.ok&&r.d.ok){if(ov)closeModal(ov);toast(T('mv_done')+r.d.host,'ok');refreshNodes()}
 else{if(m)formErr(m,perr(r));btn.disabled=false}}
function upBar(n){var r=n.uptime||[];  
 var pct=(n.uptime_pct!=null)?n.uptime_pct:100;  
 var cells=r.map(function(v){return '<i class="'+(v==null?'g':(v?'':'d'))+'"></i>'}).join('');
 return '<div class="upwrap"><div class="uptop">'+esc(T('uptime_bar'))+'<b style="margin-inline-start:6px">'+pct+T('pct')+'</b><span class="r">'+UPWIN+' '+esc(T('ov_hours_recent'))+'</span></div><div class="upbar">'+cells+'</div></div>'}
async function saveEdit(id){var m=el('em_'+id);var name=v('e_name_'+id),host=v('e_host_'+id),port=v('e_port_'+id),tok=v('e_tok_'+id);
 if(!name||!host||!port){formErr(m,T('need_nhp'));return}
 if(!nodeNameOK(name)){formErr(m,T('node_name_ascii'));return}
 m.className='msg';m.textContent=T('saving');
 var r=await post('node-edit',Object.assign({id:id,name:name,host:host,port:port,token:tok},pxBody('ne_')));
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'))}else{formErr(m,terr(r.d.error||T('failed')))}}
async function addNode(){var m=el('n_msg');var name=v('n_name'),host=v('n_host'),port=v('n_port'),tok=v('n_tok');
 if(!name||!host||!port||!tok){formErr(m,T('need_all_nhpt'));return}
 if(!nodeNameOK(name)){formErr(m,T('node_name_ascii'));return}
 m.className='msg';m.textContent=T('connecting_dots');
 var r=await post('node-add',Object.assign({name:name,host:host,port:port,token:tok},pxBody('n_')));
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('node_added_checking'),'ok');refreshNodes()}
 else{formErr(m,terr(r.d.error||T('failed')))}}
async function testNode(id){var k='ntm_'+id;
 rmsgSet(k,'',esc(T('test_testing')));
 var r=await post('node-test',{id:id});
 var info=(r.d&&r.d.info)||{};
 if(r.d&&r.d.ok){var ms=info.rtt_ms;rmsgSet(k,'ok',CK+esc(' '+T('online')+' — '+(info.hostname||'')+(ms!=null?' · '+ms+'ms':'')))}
 else{rmsgClear(k);formErr(null,T('offline')+': '+(terr(info.error)||T('not_available')))}}
function kernelTune(id){post('node-kernel-tune',{id:id,action:'status'}).then(function(r){
 if(!(r.ok&&r.d.ok)){toast(terr((r.d&&r.d.error)||T('failed')),'err');return}
 ktShow(id,r.d)})}
function ktRows(s){var active=!!s.active;
 var pill='<span class="lpill'+(active?'':' off')+'"><span class="pd"></span>'+esc(T(active?'kt_on':'kt_off'))+'</span>';
 var val=function(v){return '<span class="mono">'+esc(v||'?')+'</span>'};
 return '<div class="nd-grid">'+ndTile('activity',T('kt_state'),pill,true)
  +ndTile('traf',T('kt_cc'),val(s.cc))+ndTile('swap',T('kt_qdisc'),val(s.qdisc))+'</div>'}
function ktShow(id,s){var ex=document.querySelector('.modal.ktmodal');if(ex)closeModal(ex.closest('.modalov'));  
 var bbr=!!s.bbr_available,active=!!s.active;
 var note=bbr?'':'<div class="msg err" style="margin-top:9px">'+esc(T('kt_nobbr'))+'</div>';
 var btn=active?'<button class="primary" data-ha="'+esc(id)+'" onclick="ktDo(this,hA(this),\\'revert\\')">'+esc(T('kt_disable'))+'</button>'
  :'<button class="primary"'+(bbr?'':' disabled')+' data-ha="'+esc(id)+'" onclick="ktDo(this,hA(this),\\'apply\\')">'+esc(T('kt_enable'))+'</button>';
 openModal('<div class="msticky"><span class="medi">'+ic('gauge')+'</span><div class="ttl"><h3>'+esc(T('kt_title'))+'</h3><div class="sb">'+esc(T('kt_sub'))+'</div></div></div><div class="mbody"><div class="kt-desc">'+esc(T('kt_desc'))+'</div>'+ktRows(s)+note+'<div class="msg kt_msg"></div></div><div class="mfoot hug">'+btn+'<button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'ktmodal'})}
async function ktDo(btn,id,action){var ov=btn.closest('.modalov'),m=ov?ov.querySelector('.kt_msg'):null;  
 btn.disabled=true;if(m){m.className='msg kt_msg';m.textContent=T('kt_working')}
 var r=await post('node-kernel-tune',{id:id,action:action});
 if(r.ok&&r.d.ok){toast(action=='apply'?T('kt_enabled'):T('kt_disabled'),'ok');
  if(ov&&document.body.contains(ov))ktShow(id,r.d)}  
 else{if(m){m.className='msg err kt_msg';m.textContent=terr((r.d&&r.d.error)||T('failed'))}btn.disabled=false}}
function doForceWipe(id){return confirmBox(T('del_wipe_force_ask'),T('del_wipe_force_yes')).then(function(ok){if(ok)return doDelNode(id,true)})}
function delNode(btn){var id=btn.getAttribute('data-nid');var nm=btn.getAttribute('data-nm');var offline=btn.getAttribute('data-online')==='0';
 var wipeOpt=offline
  ?'<button type="button" class="delopt danger" data-ha="'+esc(id)+'" onclick="doForceWipe(hA(this))"><div class="do-t">'+ic('warn')+esc(T('del_wipe_force_yes'))+'</div><div class="do-s">'+esc(T('del_wipe_force_s'))+'</div></button>'
  :'<button type="button" class="delopt danger" data-ha="'+esc(id)+'" onclick="doDelNode(hA(this))"><div class="do-t">'+ic('warn')+esc(T('del_wipe_t'))+'</div><div class="do-s">'+esc(T('del_wipe_s'))+'</div></button>';
 var b='<div class="muted" style="font-size:12.5px;margin-bottom:13px">'+esc(T('del_how'))+'</div>'+
  wipeOpt+
  '<div class="msg" id="del_msg"></div>';
 openModal('<div class="msticky"><span class="medi medi-bad">'+ic('trash')+'</span><div class="ttl"><h3>'+esc(T('nd_del'))+'</h3><div class="sb">'+esc(nm)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>')}
async function doDelNode(id,force){var m=el('del_msg');
 if(!force&&!await confirmBox(T('del_wipe_confirm'),T('del_wipe_yes')))return;
 if(m){m.className='msg';m.textContent=(force?T('del_force_wiping'):T('del_wiping'))}
 document.querySelectorAll('.delopt').forEach(function(b){b.disabled=true});
 var r=await post('node-del',{id:id,wipe_force:!!force});
 if(r.ok&&r.d.ok){var ov=m?m.closest('.modalov'):null;
  toast((r.d.node_wiped===false)?T('node_force_wiped'):T('node_wiped'),'ok');
  if(ov)closeModal(ov);else refreshNodes();return}
 document.querySelectorAll('.delopt').forEach(function(b){b.disabled=false});
 if(m){formErr(m,terr((r.d&&r.d.error)||T('failed')))}}

function tunnelsSkel(){CHK={};el('view').innerHTML=vhead('link','nav_tunnels','tun_sub')+
 '<div class="tbtnrow"><button class="primary" onclick="openCreateModal()">'+ic('plus')+esc(T('add_tunnel'))+'</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+esc(T('check_all'))+'</button></div>'+
 toolbar('tunnels',T('tun_search'))+'<div id="linkList">'+skCards('tunnels')+'</div>'}
function fmtms(x){return (x>=10?Math.round(x):Math.round(x*10)/10)+'ms'}
function pingInfo(h){if(!h)return '';var p=[];
 if(h.rtt_ms!=null)p.push(T('t_ping')+' '+fmtms(h.rtt_ms));
 if(h.loss_pct!=null&&h.loss_pct>0)p.push(T('t_loss')+' '+Math.round(h.loss_pct)+T('pct'));
 return p.join(' · ')}
function sideTxt(online,h,peer){
 if(!online)return T('t_side_off');
 if(!h)return T('t_side_notun');
 if(h.up==null)return T('checking');
 if(!h.up)return T('t_side_ifdown');
 if(h.alive===true){var e2=pingInfo(h);return T('t_side_conn')+(e2?' · '+e2:'')}
 if(h.alive===false)return T('t_side_nopingr')+(h.loss_pct!=null?' ('+T('t_loss')+' '+Math.round(h.loss_pct)+T('pct')+')':'');
 return T('t_side_up_unk')}
function sideState(online,h,peer){
 if(!online)return {k:'bad',w:T('st_disc'),t:T('t_side_off')};        
 if(!h)return {k:'bad',w:T('st_disc'),t:T('t_side_notun')};           
 if(h.up==null)return {k:'na',w:'…',t:T('checking')};
 if(!h.up)return {k:'bad',w:T('st_disc'),t:T('t_side_ifdown')};
 if(h.alive===true)return {k:'ok',w:'',t:T('tst_connected')};         
 if(h.alive===false)return {k:'bad',w:T('st_disc'),t:T('tst_dead')};  
 return {k:'na',w:'…',t:T('checking')}}                               
function boxCls(online,h,peer){return 'st-'+sideState(online,h,peer).k}
function paintBox(id,online,h,peer){var e=el(id);if(!e)return;
 e.className='tnnode '+boxCls(online,h,peer);e.title=boxTitle(online,h,peer)}
function boxTitle(online,h,peer){return sideState(online,h,peer).t}
function sideDot(online,h,peer){var s=sideState(online,h,peer);   
 return s.w?'<span class="stw '+s.k+'">'+esc(s.w)+'</span>':''}
function metaCols(l){   
 var sub='<div>'+esc(T('subnet'))+': '+cpv(l.subnet)+'</div>';
 var idr='<div>'+esc(T('tid'))+': <b>'+esc(l.tunnel_id)+'</b></div>';
 var ifc='<div>'+esc(T('iface'))+': <b class="mono">'+esc(l.name)+'</b></div>';
 var typ='<div class="tagrow">'+esc(T('ttype'))+': <span class="tag '+esc(l.type)+'">'+esc(l.type)+'</span></div>';
 var right,left;
 if(l.type=='ipsec'){right=sub+idr+ifc;left=typ+'<div class="wrap">'+esc(T('enc'))+': <span class="enc">'+ic('lock','var(--bad)')+esc(T('encrypted'))+'</span></div>'}
 else if((l.type=='l2tpv3'||l.type=='fou'||l.type=='vxlan')&&l.port){right=sub+idr+ifc;left=typ+'<div>'+esc(T('udp_port'))+': <b class="mono">'+esc(l.port)+'</b></div>'}
 else{right=sub+ifc;left=idr+typ}   
 return '<div class="enmeta"><div class="emcol">'+right+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+left+'</div></div>'}
var TOPEN={};   
var PEERST=(function(){try{return JSON.parse(localStorage.getItem('tnl_peerst')||'{}')||{}}catch(e){return {}}})();
function peerStSave(){try{localStorage.setItem('tnl_peerst',JSON.stringify(PEERST))}catch(e){}}
var CHEVI='<svg class="chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>';
var _NODENAME_RE=/^[A-Za-z0-9 _.-]{1,40}$/;
function nodeNameOK(s){return _NODENAME_RE.test(String(s||''))}
function cardTog(id,e){TOPEN[id]=!TOPEN[id];var c=el('c_'+id);if(c)c.classList.toggle('open',TOPEN[id])}
function cardTogFromEl(elm){var c=elm.closest&&elm.closest('.card[data-rid]');if(!c)return;var id=c.getAttribute('data-rid');TOPEN[id]=!TOPEN[id];c.classList.toggle('open',TOPEN[id])}  
async function toggleLink(id,e){e.stopPropagation();var L=FLEET.filter(function(x){return x.id==id})[0];if(!L)return;
 var next=(L.enabled===false);L.enabled=next;   
 var c=el('c_'+id);if(c){var sw=c.querySelector('.tsw');if(sw)sw.classList.toggle('on',next);c.classList.toggle('off',!next)}
 var r=await post('link-toggle',{id:id,enabled:next});
 if(!(r.ok&&r.d.ok)){L.enabled=!next;toast(T('failed'),'err')}
 else if(r.d.both===false){toast(terr(r.d.msg)||T('failed'),'err')}
 else{toast(next?T('turned_on'):T('turned_off'),'ok')}
 refreshFleet()}
function accDot(l,side){if(l.enabled===false)return '<span class="sdot na" title="'+esc(T('st_off'))+'"></span>';
 var s=sideState(side=='a'?l.a_online:l.b_online, side=='a'?l.a_health:l.b_health, side=='a'?l.b_health:l.a_health);
 return '<span class="sdot '+s.k+'" title="'+esc(s.t)+'"></span>'}   
function accStat(l,side){if(l.enabled===false)return '<span class="stw na">'+esc(T('st_off'))+'</span><span class="sdot na"></span>';
 return side=='a'?sideDot(l.a_online,l.a_health,l.b_health):sideDot(l.b_online,l.b_health,l.a_health)}
function srvIsA(l){return l.server_side!='b'}
function sideOrder(l,isCore){return (isCore&&srvIsA(l))?['b','a']:['a','b']}
function accHead(l,isCore){var on=l.enabled!==false;
 var so=sideOrder(l,isCore),sl=so[0],sr=so[1];
var typ=isCore?'<span class="ctag c-'+esc(carrierFamily(l))+'">'+esc(carrierLabel(l))+'</span>'
              :'<span class="ctag '+esc(l.type||'')+'">'+esc((l.type||'').toUpperCase())+'</span>';
 var off=on?'':'<span class="offtxt" style="font-size:11px">'+esc(T('st_off'))+'</span>';
 return '<div class="chead" data-ha="'+esc(l.id)+'" onclick="cardTog(hA(this),event)">'+grip()+
  '<div class="tsw'+(on?' on':'')+'" data-ha="'+esc(l.id)+'" onclick="toggleLink(hA(this),event)" title="'+esc(T('tip_toggle'))+'"></div>'+
  '<div class="hmain"><div class="hrow1"><span class="hname">'+esc(l.name)+'</span>'+typ+off+
   '<span class="hpeers" dir="ltr">'+accDot(l,sl)+esc(l[sl+'_name'])+' ↔ '+esc(l[sr+'_name'])+accDot(l,sr)+'</span></div></div>'+CHEVI+'</div>'}
function accBodyTraf(l){if(l.enabled===false)return '<div class="offbadge">'+ic('warn','var(--bad)')+'<span>'+esc(T('tun_off_note'))+'</span></div>';
 var hasT=(l.rx_total!=null||l.rx_bps!=null);
 var tot=hasT?'<span class="iso"><b class="din">↓'+fmtBytes(l.rx_total)+'</b><b class="dout">↑'+fmtBytes(l.tx_total)+'</b></span>':'<b class="mono">—</b>';
 var rates=hasT?'<span class="din iso">↓ '+fmtRate(l.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(l.tx_bps)+'</span>':'<span class="muted" style="font-size:11px">'+esc(T('no_live_side'))+'</span>';
 return '<div class="ltraf">'+rates+'<span class="tot">'+esc(T('total'))+' '+tot+'</span></div>'}
var CARD_TAGS=[{a:'#9DE02E',b:'#39D74C'},{a:'#21D6DF',b:'#36ABFA'},{a:'#37E9C7',b:'#45C9EF'},
 {a:'#FDB61E',b:'#F77F43'},{a:'#F68C38',b:'#F75968'},{a:'#E46DC9',b:'#A673FC'}];
var TAG_HOLD_MS=450,TAG_ARM_MS=300,TAG_STUCK_MS=10000,_tagT=null,_tagCard=null,_tagX=0,_tagY=0;
function tagCardAt(t){if(!t||!t.closest)return null;
 var h=t.closest('.chead');if(!h)return null;
 var c=h.closest('.card.acc[data-rid]');
 return (c&&!t.closest('button,input,select,a,.act,.tsw,.tglsw,.modalov'))?c:null}
function tagHoldStart(e){
 if(e.touches&&e.touches.length>1)return;
 var c=tagCardAt(e.target);if(!c)return;
 var p=e.touches?e.touches[0]:e;_tagX=p.clientX;_tagY=p.clientY;_tagCard=c;
 _tagT=setTimeout(function(){_tagT=null;c.classList.remove('tagpick');tagBuzz();openTagPicker(c)},TAG_HOLD_MS);
 c.classList.add('tagpick');
 document.addEventListener('selectstart',tagNoSelect,true)}
function tagNoSelect(e){e.preventDefault()}
function tagBuzz(){try{if(navigator.vibrate)navigator.vibrate(18)}catch(_){}
 try{var s=window.getSelection();if(s&&s.removeAllRanges)s.removeAllRanges()}catch(_){}}
function tagHoldMove(e){
 if(!_tagT)return;var p=e.touches?e.touches[0]:e;
 if(Math.abs(p.clientX-_tagX)>10||Math.abs(p.clientY-_tagY)>10)tagHoldCancel()}
function tagHoldCancel(){if(_tagT){clearTimeout(_tagT);_tagT=null}
 document.removeEventListener('selectstart',tagNoSelect,true);
 if(_tagCard){_tagCard.classList.remove('tagpick');_tagCard=null}}
function openTagPicker(card){
 var id=card.getAttribute('data-rid'),cur=num((card.getAttribute('style')||'')?0:0);
 var link=(FLEET||[]).filter(function(x){return String(x.id)==id})[0]||{};
 cur=num(link.tag);
 var ov=document.createElement('div');ov.className='tagov';
 ov.addEventListener('selectstart',tagNoSelect);
 ov.addEventListener('contextmenu',function(e){e.preventDefault()});
 ov.innerHTML='<div class="tagbox"><div class="tgt">'+esc(T('tag_title'))+'</div><div class="tagpal">'
  +CARD_TAGS.map(function(t,i){return '<button type="button" class="tagdot'+(cur==i+1?' on':'')
    +'" data-t="'+(i+1)+'" style="background:linear-gradient(140deg,'+t.a+','+t.b+')"></button>'}).join('')
  +'</div><button type="button" class="tagnone" data-t="0">'+esc(T('tag_clear'))+'</button></div>';
 var live=false,armed=false,armT=null;
 var arm=function(){if(armed)return;armed=true;armT=setTimeout(function(){live=true},TAG_ARM_MS)};
 var give=setTimeout(arm,TAG_STUCK_MS);
 document.addEventListener('touchend',arm,true);
 document.addEventListener('touchcancel',arm,true);
 document.addEventListener('mouseup',arm,true);
 var close=function(){clearTimeout(give);clearTimeout(armT);
  document.removeEventListener('touchend',arm,true);
  document.removeEventListener('touchcancel',arm,true);
  document.removeEventListener('mouseup',arm,true);
  ov.remove()};
 ov.addEventListener('click',function(e){
  if(!live)return;
  var b=e.target.closest('[data-t]');
  if(!b){if(e.target===ov)close();return}
  close();setCardTag(id,parseInt(b.getAttribute('data-t'),10))});
 document.body.appendChild(ov)}
async function setCardTag(id,tag){
 var was=TAGPEND[id];
 TAGPEND[id]=tag;
 var link=(FLEET||[]).filter(function(x){return String(x.id)==id})[0];
 var prev=link?num(link.tag):0;
 if(link)link.tag=tag;
 var c=el('c_'+id);
 if(c){c.classList.toggle('tagd',tag>=1);var t=CARD_TAGS[tag-1];
  if(t){c.style.setProperty('--tga',t.a);c.style.setProperty('--tgb',t.b)}}
 try{var r=await post('link-tag',{id:id,tag:tag},NET_TIMEOUT);
  if(r.ok&&r.d.ok)return;
  toast((r.d&&r.d.error)||T('tag_err'),'err')}
 catch(_){toast(T('tag_err'),'err')}
 if(TAGPEND[id]!==tag)return;
 if(was===undefined)delete TAGPEND[id];else TAGPEND[id]=was;
 if(link)link.tag=prev;
 var c2=el('c_'+id);
 if(c2){c2.classList.toggle('tagd',prev>=1);var t2=CARD_TAGS[prev-1];
  if(t2){c2.style.setProperty('--tga',t2.a);c2.style.setProperty('--tgb',t2.b)}}}
document.addEventListener('touchstart',tagHoldStart,{passive:true});
document.addEventListener('touchmove',tagHoldMove,{passive:true});
document.addEventListener('touchend',tagHoldCancel);
document.addEventListener('touchcancel',tagHoldCancel);
document.addEventListener('mousedown',tagHoldStart);
document.addEventListener('mousemove',tagHoldMove);
document.addEventListener('mouseup',tagHoldCancel);
document.addEventListener('contextmenu',function(e){if(tagCardAt(e.target))e.preventDefault()});
var TAGPEND={};
function tagPending(links){(links||[]).forEach(function(l){
 var p=TAGPEND[l.id];if(p===undefined)return;
 if(num(l.tag)===p){delete TAGPEND[l.id];return}
 l.tag=p});
 return links}
function tagStyle(n){var t=CARD_TAGS[n-1];return t?(' style="--tga:'+t.a+';--tgb:'+t.b+'"'):''}
function tagCls(l){return (num(l.tag)>=1&&num(l.tag)<=CARD_TAGS.length)?' tagd':''}
function accShell(l,isCore,inner){var open=!!TOPEN[l.id];
 return '<div class="card acc'+(l.enabled===false?' off':'')+(open?' open':'')+cardActCls(l)+tagCls(l)+'" id="c_'+l.id+'" data-rid="'+esc(l.id)+'" data-rk="'+(isCore?'core':'tunnels')+'"'+tagStyle(num(l.tag))+'>'+accHead(l,isCore)+
  '<div class="cbody"><div class="cbody-in">'+inner+'</div></div></div>'}
function linkFooter(l,editFn){
 var msg=rmsgHTML('lchk_'+l.id);
 var flip='<button class="act flip" data-ha="'+esc(l.id)+'" onclick="flipView(hA(this))" title="'+esc(T('tip_flip'))+esc(l.view_name||'—')+'">'+ic('swap')+'</button>';
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('tip_ping'))+'" data-ha="'+esc(l.id)+'" onclick="checkLink(hA(this))">'+ic('activity')+'</button><button class="act info" title="'+esc(T('tip_speed'))+'" data-ha="'+esc(l.id)+'" onclick="speedLink(hA(this))">'+ic('gauge')+'</button>'+flip+'<button class="act reset" title="'+esc(T('tip_reset'))+'" data-ha="'+esc(l.id)+'" onclick="resetTraffic(hA(this))">'+ic('reset')+'</button><button class="act warn" title="'+esc(T('tip_edit'))+'" data-ha="'+esc(l.id)+'" onclick="'+editFn+'(hA(this))">'+ic('pen')+'</button><button class="act" title="'+esc(T('tip_rebuild'))+'" data-ha="'+esc(l.id)+'" onclick="rebuildLink(hA(this))">'+ic('redo')+'</button>'+(l.type=='core'?'<button class="act info" title="'+esc(T('tip_restart'))+'" data-ha="'+esc(l.id)+'" onclick="restartLink(hA(this))">'+ic('restart')+'</button>':'')+'<button class="act danger" title="'+esc(T('tip_delete'))+'" data-ha="'+esc(l.id)+'" onclick="delLink(hA(this))">'+ic('trash')+'</button></div>';
 var drift=l.drift?'<div class="msg err" style="margin:0 0 9px;display:flex;align-items:center;gap:6px">'+ic('warn','#e0564f')+'<span>'+esc(T('drift_note'))+'</span></div>':'';
 if(l.rb&&!l.rb.ok)drift+='<div class="msg err" style="margin:0 0 9px">'+esc(T('rb_last_fail'))+esc(terr(l.rb.error||T('rebuild_failed')))+'</div>';
 return {drift:drift,acts:acts,msg:msg}}
function linkCard(l){
 var body='<div class="tninfo">'+
  '<div class="tnnode '+boxCls(l.a_online,l.a_health,l.b_health)+'" id="bxa_'+l.id+'" title="'+esc(boxTitle(l.a_online,l.a_health,l.b_health))+'"><div class="tnhead"><span class="tnn">'+esc(l.a_name)+'</span><span class="stat" id="lba_'+l.id+'">'+accStat(l,'a')+'</span></div><div class="tna mono cpv" title="'+esc(T('tip_copy'))+'" onclick="copyTxt(this.textContent,event)">'+esc(l.a_ip)+'</div></div>'+
  '<span class="tnarrow">↔</span>'+
  '<div class="tnnode '+boxCls(l.b_online,l.b_health,l.a_health)+'" id="bxb_'+l.id+'" title="'+esc(boxTitle(l.b_online,l.b_health,l.a_health))+'"><div class="tnhead"><span class="tnn">'+esc(l.b_name)+'</span><span class="stat" id="lbb_'+l.id+'">'+accStat(l,'b')+'</span></div><div class="tna mono cpv" title="'+esc(T('tip_copy'))+'" onclick="copyTxt(this.textContent,event)">'+esc(l.b_ip)+'</div></div>'+
  '</div>'+
  metaCols(l);
 var F=linkFooter(l,'openLinkEdit');
 return accShell(l,false,F.drift+body+accBodyTraf(l)+linkActRow(l)+F.acts+F.msg)}
async function refreshTunnels(){if(listBusy())return;var f=await j('fleet?kind=tunnels&q='+encodeURIComponent(QRY.tunnels));FLEET=tagPending(f.links||[]);var box=el('linkList');if(!box||listBusy())return;   
 var _rows=withPending('tunnels',FLEET.map(function(l){return {k:l.id,h:linkCard(l)}}));
 setList(box,_rows.length?_rows:[{k:'__empty',h:'<div class="card muted">'+(QRY.tunnels?T('no_results'):T('tun_empty'))+'</div>'}])}
async function saveLinkEdit(id){var m=el('lem_'+id);var type=ssVal('lt_'+id),subnet=v('e_sub_'+id);
 if(!type){formErr(m,T('tun_type'));return}
 var L=FLEET.find(function(x){return x.id==id})||{};
 var a_ip=ssVal('lipa_'+id)||liveIP(L.a_ips,L.a_ip),b_ip=ssVal('lipb_'+id)||liveIP(L.b_ips,L.b_ip);
 m.className='msg';m.textContent=T('rebuilding_both');
 var body={id:id,type:type,subnet:subnet,a_ip:a_ip,b_ip:b_ip};var pe=el('le_port_'+id);if(pe)body.port=pe.value.trim();
 var r=await post('edit-link',body);
 if(!(r.ok&&r.d.act)){formErr(m,perr(r));return}
 var vr=await actAccepted(r.d.act,m);
 if(vr.gone)return;
 if(vr.err){formErr(m,vr.err);return}
 rmsgClear('lchk_'+id);closeModal(m.closest('.modalov'))}
function chkLines(hdr,a,b){return '<div class="chh">'+hdr+'</div><div class="chl">'+esc(a)+'</div><div class="chl">'+esc(b)+'</div>'}
function ltr(s){return '⁦'+s+'⁩'}
async function speedLink(id){var k='lchk_'+id;
 rmsgSet(k,'',esc(T('speed_run')));
 var r=await post('link-speed',{id:id});
 if(!(r.ok&&r.d.ok)){rmsgSet(k,'err',esc(perr(r)));return}
 var d=r.d,up=num(d.up_mbit),dn=num(d.down_mbit);
 rmsgSet(k,(up>0&&dn>0)?'ok':'err',chkLines(CK+' '+esc(T('speed_done'))+' <span class="muted">'+esc(T('speed_how').replace('{s}',String(num(d.secs))).replace('{n}',String(num(d.streams))))+'</span>',
   T('speed_down')+': '+ltr(fmtRate(dn*1e6)),
   T('speed_up')+': '+ltr(fmtRate(up*1e6)))
   +'<div class="wrap muted" style="margin-top:6px">'+T('speed_note')+'</div>')}
async function checkLink(id){var k='lchk_'+id;
 rmsgSet(k,'',esc(T('checking_conn')));
 var r=await post('check-link',{id:id});
 var L=FLEET.filter(function(x){return x.id==id})[0]||{};
 if(!(r.ok&&r.d.ok)){rmsgSet(k,'err',esc(perr(r)));return}
 var d=r.d,ab=el('lba_'+id),bb=el('lbb_'+id);
 if(L.enabled===false){var off='<span class="stw na">'+esc(T('st_off'))+'</span><span class="sdot na"></span>';
  if(ab)ab.innerHTML=off;if(bb)bb.innerHTML=off;
  rmsgSet(k,'',esc(T('conn_off')));return}
 if(ab)ab.innerHTML=sideDot(d.a_online,d.a_health,d.b_health);if(bb)bb.innerHTML=sideDot(d.b_online,d.b_health,d.a_health);
 paintBox('bxa_'+id,d.a_online,d.a_health,d.b_health);paintBox('bxb_'+id,d.b_online,d.b_health,d.a_health);
 var aup=d.a_online&&d.a_health&&d.a_health.up,bup=d.b_online&&d.b_health&&d.b_health.up;
 var okAll=aup&&bup&&d.a_health.alive===true&&d.b_health.alive===true;
 rmsgSet(k,okAll?'ok':'err',chkLines(okAll?CK+' '+T('conn_ok'):XK+' '+T('conn_bad'),
   (L.a_name||'A')+': '+sideTxt(d.a_online,d.a_health,d.b_health),(L.b_name||'B')+': '+sideTxt(d.b_online,d.b_health,d.a_health)))}
async function checkAll(){var b=el('chkAllBtn');if(!FLEET.length){toast(T('no_tunnel_check'),'err');return}
 if(b){b.disabled=true;b.style.opacity='.6'}
 try{await Promise.all(FLEET.map(function(l){return checkLink(l.id)}))}
 finally{if(b){b.disabled=false;b.style.opacity=''}}
 toast(T('checkall_done'),'ok')}
async function rebuildLink(id){
 var _L=FLEET.filter(function(x){return x.id==id})[0];
 if(_L&&_L.drift){openRebuildPicker(id);return}   
 if(!await confirmBox(T('rebuild_confirm')))return;
 var r=await post('rebuild-link',{id:id});
 if(!(r.ok&&r.d.act)){toast(perr(r,'rebuild_failed'),'err');return}
 rmsgClear('lchk_'+id);
 actStarted()}
async function restartLink(id){if(!await confirmBox(T('restart_confirm'),T('restart_yes')))return;
 var r=await post('restart-link',{id:id});
 if(!(r.ok&&r.d.act)){toast(perr(r,'restart_failed'),'err');return}
 rmsgClear('lchk_'+id);actStarted()}
async function flipView(id){var r=await post('link-view',{id:id});
 if(r.ok&&r.d.ok){var L=FLEET.filter(function(x){return x.id==id})[0];var nm=L?(r.d.view_side=='b'?L.b_name:L.a_name):'';
  rmsgSet('lchk_'+id,'ok',ic('swap')+esc(T('view_switched')+nm+T('view_switched2')));
  setTimeout(function(){rmsgClear('lchk_'+id)},4000);
  refreshFleet()}
 else{toast(T('failed'),'err')}}
function ndTraf(n){var t=n.traffic;if(!t)return '';
 return '<div class="ltraf ndtraf"><span class="din iso">↓ '+fmtRate(t.rx_bps)+'</span><span class="dout iso">↑ '+fmtRate(t.tx_bps)+'</span><span class="tot">'+esc(T('total'))+' <span class="iso"><b class="din">↓'+fmtBytes(t.rx_total)+'</b><b class="dout">↑'+fmtBytes(t.tx_total)+'</b></span></span></div>'}
async function resetNodeTraffic(id){if(!await confirmBox(T('nreset_confirm')))return;var r=await post('traffic-reset',{node:id});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshNodes()}else{toast(perr(r),'err')}}
async function resetTraffic(id){if(!await confirmBox(T('reset_confirm')))return;var r=await post('traffic-reset',{id:id});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshFleet()}else{toast(perr(r),'err')}}
async function resetPfTraffic(i){var p=PF[i];if(!p)return;if(!await confirmBox(T('pf_reset_confirm')))return;var r=await post('traffic-reset',{node:p.node_id,name:p.name});if(r.ok&&r.d.ok){toast(T('t_reset_done'),'ok');refreshPortfw()}else{toast(perr(r),'err')}}
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
 post('link-rebuild-info',{id:id}).then(function(v){var r=v.d;
  if(!r||!r.id){toast(T('rb_no_link'),'err');return}
  _rbSel={};var secs='';
  [['a','a_ip'],['b','b_ip']].forEach(function(pp){var side=r[pp[0]],key=pp[1];
   if(!side||!side.drifted)return;
   var free=(side.ips||[]).filter(function(x){return x.free})[0];
   _rbSel[key]=free?free.ip:(((side.ips||[])[0]||{}).ip||'');
   secs+='<div class="nd-sec">'+esc(side.node)+' — '+esc(T('rb_newip'))+'</div><div class="rbsec">'+
     (side.ips&&side.ips.length?side.ips.map(function(x){return rbRow(key,x)}).join(''):'<div class="muted" style="font-size:12px;padding:4px 2px">'+esc(T('rb_no_ip'))+'</div>')+'</div>'});
  if(!secs){toast(T('rb_no_drift'),'ok');refreshTunnels();return}
  var body='<div style="color:var(--sub);font-size:12px;margin-bottom:12px">'+esc(T('rb_info'))+'</div>'+secs+'<div class="msg" id="rb_msg"></div>';
  _rbOv=openModal('<div class="msticky"><span class="medi">'+ic('redo')+'</span><div class="ttl"><h3>'+esc(T('rb_title'))+'</h3><div class="sb">'+esc(r.name||'')+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+body+'</div><div class="mfoot"><button class="primary" data-ha="'+esc(id)+'" onclick="doRebuildPick(hA(this))">'+ic('redo')+esc(T('tip_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');
 }).catch(function(){toast(T('rb_fetch_err'),'err')})}
function rbRow(key,x){var sel=_rbSel[key]==x.ip;
 return '<div class="rbrow'+(sel?' sel':'')+'" data-ip="'+esc(x.ip)+'" data-ha="'+esc(key)+'" onclick="rbPick(hA(this),this)"><span class="rbdot"></span><span class="mono" style="direction:ltr;font-size:13px">'+esc(x.ip)+'</span><span class="rbtags">'+ipChips(x)+'</span></div>'}
function rbPick(key,row){_rbSel[key]=row.getAttribute('data-ip');
 var sec=row.closest('.rbsec')||row.parentNode;sec.querySelectorAll('.rbrow').forEach(function(r){r.classList.remove('sel')});
 row.classList.add('sel')}
async function doRebuildPick(id){var body={id:id};if(_rbSel.a_ip)body.a_ip=_rbSel.a_ip;if(_rbSel.b_ip)body.b_ip=_rbSel.b_ip;
 var m=el('rb_msg');if(m){m.className='msg';m.textContent=T('rebuilding')}
 var r=await post('rebuild-link',body);
 if(!(r.ok&&r.d.act)){if(m)formErr(m,perr(r,'rebuild_failed'));else toast(perr(r,'rebuild_failed'),'err');return}
 var vr=await actAccepted(r.d.act,m);
 if(vr.gone)return;
 if(vr.err){if(m)formErr(m,vr.err);else toast(vr.err,'err');return}
 if(_rbOv)closeModal(_rbOv);rmsgClear('lchk_'+id);refreshFleet()}
async function delLink(id){
 var l=FLEET.filter(function(x){return x.id==id})[0]||{};
 if(l.a_online===false||l.b_online===false){          
  if(!await confirmBox(T('del_force_ask'),T('del_force_yes')))return;
  var rf=await post('delete-link',{id:id,force:true});
  if(!(rf.ok&&rf.d.act)){toast(perr(rf),'err');return}
  rmsgClear('lchk_'+id);actStarted();return}
 if(!await confirmBox(T('del_tun_confirm')))return;   
 var r=await post('delete-link',{id:id});
 if(!(r.ok&&r.d.act)){toast(perr(r),'err');return}
 rmsgClear('lchk_'+id);actStarted()}

function ipSeed(k,ips,stored){if(SEL[k]&&ips.indexOf(SEL[k])>=0)return SEL[k];
 if(stored&&ips.indexOf(stored)>=0)return stored;return ips[0]}
function ipField(k,ips,lab,stored){
 if(ips.length>1)return '<label class="first">'+lab+'</label>'+ssHTML(k,ipItems(ips),ipSeed(k,ips,stored),T('ip'),'');
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
function renderDstIp(){var w=el('c_dstip');if(!w)return;w.innerHTML=ipField('c_bare',nodeIps(ssVal('c_b')),T('dst_ip'))}
function renderSrcIp(){var w=el('c_srcip');if(!w)return;w.innerHTML=ipField('c_aip',nodeIps(ssVal('c_a')),T('src_ip'))}
function onCreateType(){var f=el('c_subnet');if(f&&f.value.trim()){var wantV6=(ssVal('c_type')=='sit');
  if((f.value.indexOf(':')>=0)!=wantV6)f.value=''}
 renderTypeExtra()}
function renderTypeExtra(){var w=el('c_typex');if(!w)return;var t=ssVal('c_type');
 if(t=='l2tpv3'||t=='fou'){w.innerHTML='<label>'+esc(rng(T('ttype_port_auto_lbl'),1,PORT_MAX))+'</label><input id="c_port" inputmode="numeric" placeholder="'+esc(T('ttype_port_ph'))+'"><div class="muted" style="font-size:11px;margin:6px 2px 11px">'+esc(T('ttype_l2_note'))+'</div>'}
 else if(t=='vxlan'){w.innerHTML='<label>'+esc(T('ttype_vxlan_lbl'))+'</label><input id="c_port" inputmode="numeric" placeholder="4789"><div class="muted" style="font-size:11px;margin:6px 2px 11px">'+esc(T('ttype_vxlan_note'))+'</div>'}
 else if(t=='ipsec'){w.innerHTML='<div class="autonote" style="margin-bottom:11px">'+ic('shield')+'<span>'+esc(T('ttype_ipsec_note'))+'</span></div>'}
 else w.innerHTML=''}
function nodeName(id){var n=NODES.find(function(x){return x.id==id});return n?n.name:id}
function nodeCpus(id){var n=NODES.find(function(x){return x.id==id});return n?num(n.cpus):0}
async function doCreate(){var m=el('c_msg');m.className='msg';var a=ssVal('c_a'),b=ssVal('c_b');
 if(a==b){formErr(m,T('two_diff_nodes'));return}
 var type=ssVal('c_type'),range=ssVal('c_snr'),custom=v('c_subnet');
 var aip=el('ssb_c_aip')?ssVal('c_aip'):'',bare=el('ssb_c_bare')?ssVal('c_bare'):'';   
 var body={a_node:a,b_node:b,type:type,a_ip:aip,b_ip:bare};
 if(range=='custom')body.subnet=custom;else body.subnet_base=range;
 if((type=='l2tpv3'||type=='fou'||type=='vxlan')&&el('c_port')&&v('c_port'))body.port=v('c_port');
 m.textContent=T('creating_tun');
 var r=await post('create-tunnel',body);
 if(!(r.ok&&r.d.act)){formErr(m,perr(r));return}
 var vr=await actAccepted(r.d.act,m);
 if(vr.gone)return;
 if(vr.err){formErr(m,vr.err);return}
 closeModal(m.closest('.modalov'));refreshTunnels()}

function coreSkel(){CHK={};el('view').innerHTML=vhead(COR_IC,'nav_core','core_sub')+
 '<div class="tbtnrow"><button class="primary" onclick="openCoreModal()">'+ic('plus')+esc(T('core_add'))+'</button><button class="chkall" id="chkAllBtn" onclick="checkAll()">'+ic('activity')+esc(T('check_all'))+'</button></div>'+
 toolbar('core',T('core_search'))+'<div id="corList">'+skCards('core')+'</div>'}
async function refreshCore(){if(listBusy())return;var f=await j('fleet?kind=core&q='+encodeURIComponent(QRY.core));FLEET=tagPending(f.links||[]);var box=el('corList');if(!box||listBusy())return;   
 var _rows=withPending('core',FLEET.map(function(l){return {k:l.id,h:coreCard(l)}}));
 setList(box,_rows.length?_rows:[{k:'__empty',h:'<div class="card muted">'+(QRY.core?T('no_results'):T('core_empty'))+'</div>'}])}   
var REORDMODE=false,RORD_AS=0;   
function toggleReord(){REORDMODE=!REORDMODE;document.body.classList.toggle('reord-on',REORDMODE);if(REORDMODE)reordCollapse();}
function reordCollapse(one){
 var cs=one?[one]:document.querySelectorAll('.card.acc.open');
 for(var i=0;i<cs.length;i++){var c=cs[i];
  if(!c.classList.contains('open'))continue;
  c.classList.remove('open');var k=c.getAttribute('data-rid');if(k)TOPEN[k]=false;}
}
function gripSvg(){return '<svg viewBox="0 0 20 20" width="16" height="16" fill="currentColor" aria-hidden="true"><circle cx="7" cy="4.5" r="1.5"/><circle cx="13" cy="4.5" r="1.5"/><circle cx="7" cy="10" r="1.5"/><circle cx="13" cy="10" r="1.5"/><circle cx="7" cy="15.5" r="1.5"/><circle cx="13" cy="15.5" r="1.5"/></svg>'}
function grip(){return '<span class="rgrip" onclick="event.stopPropagation()" title="'+esc(T('reord_t'))+'">'+gripSvg()+'</span>'}
function reordDown(e){
 if(RORD||RSAVE||!REORDMODE)return;
 if(e.isPrimary===false)return;
 if(e.pointerType==='mouse'&&e.button!==0)return;
 var g=e.target.closest?e.target.closest('.rgrip'):null;if(!g)return;   
 var card=g.closest('.card[data-rid]');if(!card)return;
 var box=card.parentNode;if(!box)return;
 if(e.cancelable)e.preventDefault();
 reordCollapse(card);
 var vh0=window.innerHeight||document.documentElement.clientHeight;
 RORD={card:card,box:box,id:card.getAttribute('data-rid'),kind:card.getAttribute('data-rk'),pid:e.pointerId,grabY:e.clientY,lastY:e.clientY,swaps:[],
       maxY:Math.max(0,(document.documentElement.scrollHeight||0)-vh0)};
 try{card.setPointerCapture(e.pointerId)}catch(_){}
 card.classList.add('rdrag');document.body.classList.add('rdragging');
 if(navigator.vibrate){try{navigator.vibrate(10)}catch(_){}}
 RORD_AS=requestAnimationFrame(reordAutoScroll);   
}
function reordApply(){   
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
function reordAutoScroll(){   
 if(!RORD){RORD_AS=0;return}
 var y=RORD.lastY,vh=window.innerHeight||document.documentElement.clientHeight,edge=76,ds=0;
 if(y<edge)ds=-Math.min(24,((edge-y)/3|0)+3);
 else if(y>vh-edge)ds=Math.min(24,((y-(vh-edge))/3|0)+3);
 var cur=window.pageYOffset;   
 if(ds>0)ds=Math.min(ds,RORD.maxY-cur);else if(ds<0)ds=Math.max(ds,-cur);
 if(ds>0||ds<0){var b=cur;window.scrollBy(0,ds);var a=window.pageYOffset-b;if(a){RORD.grabY-=a;reordApply();}}   
 RORD_AS=requestAnimationFrame(reordAutoScroll);
}
function reordShift(nb,up){
 var c=RORD.card;
 var cBefore=c.getBoundingClientRect().top,nBefore=nb.getBoundingClientRect().top;
 RORD.box.insertBefore(nb,up?c.nextSibling:c);
 RORD.grabY+=(c.getBoundingClientRect().top-cBefore);          
 c.style.transform='translateY('+(RORD.lastY-RORD.grabY)+'px)';
 var dy=nBefore-nb.getBoundingClientRect().top;                 
 if(dy){nb.style.transition='none';nb.style.transform='translateY('+dy+'px)';void nb.offsetHeight;nb.style.transition='';nb.style.transform=''}
 RORD.swaps.push(nb.getAttribute('data-rid'));
}
function reordEnd(e){
 if(!RORD)return;
 if(e&&e.pointerId!=null&&e.pointerId!==RORD.pid)return;
 var d=RORD;RORD=null;
 if(RORD_AS){cancelAnimationFrame(RORD_AS);RORD_AS=0;}
 try{d.card.releasePointerCapture(d.pid)}catch(_){}
 d.card.classList.remove('rdrag');d.card.style.transform='';document.body.classList.remove('rdragging');
 if(d.swaps.length)reordPersist(d.kind,d.id,d.swaps);
}
async function reordPersist(kind,id,targets){
 RSAVE=true;
 try{var r=await post('reorder',{kind:kind,id:id,targets:targets},NET_TIMEOUT);   
  if(!r.ok||!r.d.ok)toast((r.d&&r.d.error)||T('reorder_err'),'err');}
 catch(_){toast(T('reorder_err'),'err')}
 finally{RSAVE=false}
 if(kind==='nodes')refreshNodes();else if(kind==='core')refreshCore();else if(kind==='portfw')refreshPortfw();else refreshTunnels();
}
document.addEventListener('pointerdown',reordDown,true);
document.addEventListener('pointermove',reordMove,true);
document.addEventListener('pointerup',reordEnd,true);
document.addEventListener('pointercancel',reordEnd,true);
document.addEventListener('lostpointercapture',function(e){
 if(RORD&&e.pointerId===RORD.pid){try{RORD.card.setPointerCapture(e.pointerId)}catch(_){}}},true);
document.addEventListener('touchmove',function(e){if(RORD&&e.cancelable)e.preventDefault()},{passive:false});
function coreMeta(l){   
 var sub='<div>'+esc(T('subnet'))+': '+cpv(l.subnet)+'</div>';
 var prt=portRows(l);
 var ifc='<div>'+esc(T('iface'))+': <b class="mono">'+esc(l.name)+'</b></div>';
 var typ='<div class="tagrow">'+esc(T('ttype'))+': <span class="ctag c-'+esc(carrierFamily(l))+'">'+esc(carrierLabel(l))+'</span></div>';
 var _pf=carrierProfile(l);
 var prof=_pf?'<div>'+esc(T('profile'))+': <b class="mono">'+esc(_pf)+'</b></div>':'';
 var feats=[];
 if(l.transport=='ws'&&l.ws_pool)feats.push('<span class="tag obfs">pool</span>');
 if(l.transport=='ws'&&l.ws_tls)feats.push('<span class="tag obfs">wss</span>');if(l.sni_split)feats.push('<span class="tag obfs">SNI'+(l.sni_mode||'split')+'</span>');
 if(l.transport=='ws'&&l.ech)feats.push('<span class="tag obfs">ECH</span>');
 if(l.obfs)feats.push('<span class="tag obfs">obfs</span>');if(l.cover)feats.push('<span class="tag obfs">TLS</span>');if(l.gso)feats.push('<span class="tag obfs">GSO</span>');if(l.fec)feats.push('<span class="tag obfs">FEC '+((l.fec_data||16)+'+'+(l.fec_parity||4))+'</span>');if(l.fake_desync)feats.push('<span class="tag obfs">desync</span>');
 var cap='<div class="feat">'+esc(T('caps'))+': '+(feats.length?feats.join(' '):'<span class="nofeat">—</span>')+'</div>';
 var encv=(l.cipher&&l.cipher!='none')
   ?'<span class="encval">'+esc(l.cipher=='auto'?'aes-256-gcm':l.cipher)+'</span>'
   :'<b>'+esc(T('no_cipher'))+'</b>';
 var enc='<div class="enc-line">'+esc(T('enc'))+': '+encv+'</div>';
function edgeHost(v){v=String(v||'');var i=v.lastIndexOf(':');return (i>0&&v.indexOf(':')==i)?v.slice(0,i):v}
 var edge='';
 if(l.transport=='ws'){
   if(l.ws_pool){edge='<div class="cedge live"><div class="ct"><span class="cdot"></span>'+esc(T('active_edge'))+'</div><div class="echips" id="cardedge_'+l.id+'">'+edgeChips(EDGEV[l.id]||'')+'</div></div>';}
   else{var eip=l.edge_ip?edgeHost(l.edge_ip):'',edom=l.ws_host||'';
     if(eip||edom)edge='<div class="cedge"><div class="ct">'+esc(T('cdn_edge'))+'</div><div class="echips">'+edgeChipsOf(eip,edom)+'</div></div>';}
 }
 return '<div class="enmeta"><div class="emcol">'+sub+prt+ifc+'</div><span class="tnarrow earrow">↔</span><div class="emcol">'+typ+prof+cap+enc+'</div>'+ctbWarn(l)+'</div>'+edge}
function coreCard(l){
 var srvA=(l.server_side!='b');   
 var _aA=l.a_ip_active||'',_aB=l.b_ip_active||'',ka=l.id+'_a',kb=l.id+'_b';
 if(!l.ip_rotate){   
   var ce=false;if(PEERST[ka]){delete PEERST[ka];ce=true}if(PEERST[kb]){delete PEERST[kb];ce=true}if(ce)peerStSave();
 }else if(_aA||_aB){var ch=false;
   if(_aA&&(PEERST[ka]||{}).ip!==_aA){PEERST[ka]={ip:_aA};ch=true}
   if(_aB&&(PEERST[kb]||{}).ip!==_aB){PEERST[kb]={ip:_aB};ch=true}
   if(ch)peerStSave();}
 var _pa=PEERST[ka]||{},_pb=PEERST[kb]||{};
 var _aip=_aA||_pa.ip||l.a_ip,_bip=_aB||_pb.ip||l.b_ip;
 var _arot=l.a_ip_rot?rotMark():'',_brot=l.b_ip_rot?rotMark():'';
 var _ip={a:_aip,b:_bip},_rt={a:_arot,b:_brot};
 var nbox=function(s){var isSrv=(s=='a')==srvA;
  return '<div class="tnnode '+boxCls(l[s+'_online'],l[s+'_health'],l[(s=='a'?'b':'a')+'_health'])+'" id="bx'+s+'_'+l.id+'" title="'+esc(boxTitle(l[s+'_online'],l[s+'_health'],l[(s=='a'?'b':'a')+'_health']))+'"><div class="tnhead"><span class="tnn">'+esc(l[s+'_name'])+'</span><span class="tnend"><span class="rl '+(isSrv?'srv':'cli')+'">'+(isSrv?T('server'):T('client'))+'</span><span class="cprot" id="cprot_'+s+'_'+l.id+'">'+_rt[s]+'</span><span class="stat" id="lb'+s+'_'+l.id+'">'+accStat(l,s)+'</span></span></div><div class="tna mono cpv" id="cpip_'+s+'_'+l.id+'" title="'+esc(T('tip_copy'))+'" onclick="copyTxt(this.textContent,event)">'+esc(_ip[s])+'</div></div>'};
 var _so=sideOrder(l,true);   
 var body='<div class="tninfo">'+
  nbox(_so[0])+
  '<span class="tnarrow">↔</span>'+
  nbox(_so[1])+
  '</div>'+
  coreMeta(l);
 var F=linkFooter(l,'openCoreEdit');
 return accShell(l,true,F.drift+body+accBodyTraf(l)+linkActRow(l)+F.acts+F.msg)}
_corS.Srv='a',_corS.Tr='udp',_corS.Obfs=true,_corS.Cover=false,_corS.RawProfile='bare',_corS.Sprot=false,_corS.Gso=false,_corS.WsTls=false,_corS.Ech=false,_corS.EchProxy=false,_corS.Cdn='ws',_corS.Fec=false,_corS.FecData=16,_corS.FecParity=4,_corS.Desync=false,_corS.DesyncTtl=4,_corS.DesyncCount=2,_corS.DesyncMode='ttl',_corS.SniSplit=false,_corS.SplitPos=0,_corS.SniMode='split',_corS.SplitTtl=0;
function carrierFamily(l){var t=l.transport||'udp';
 return (t=='ws')?((l.cdn_carrier=='grpc')?'grpc':(l.cdn_carrier=='http')?'http':'ws'):t}
function carrierLabel(l){return carrierFamily(l).toUpperCase()}
function carrierProfile(l){var t=l.transport||'udp';
 if(t=='raw')return rawProfTag(l);
 if(t=='dns')return (l.dns_zone||'').toUpperCase();
 return ''}
function rawProfTag(l){var p=(l.raw_profile||'bare');
 return p.toUpperCase()+((p=='bare')?('('+(num(l.raw_proto)||253)+')'):'')}
var RAW_DPORT_DEF=443,RAW_SPORT_FIX=51820,RAW_ROT_LO=10000,RAW_ROT_HI=59999,RAW_DPORTS_MAX=16,RAW_BAND_MIN_LO=1024,RAW_BAND_MIN_SPAN=100,RAW_SPROT_MAX=60,PORT_TRIES_MAX=60;
function rotSrcRows(l,every){var R=l.rot_live||{},cli=num(R.cli),srv=num(R.srv),lo=num(R.lo)||RAW_ROT_LO,hi=num(R.hi)||RAW_ROT_HI;
 var mode=every?T('port_src_rot'):T('port_src_rand');
 var clock=every?T('port_src_rot_every').replace('{n}',every):T('port_src_rot_fail');
 var band=esc(mode)+' · '+esc(lo+'-'+hi)+' · '+esc(clock);
 var drawn=num(R.drawn);
 if(drawn)band+=' · '+esc(T('port_src_rot_drawn').replace('{n}',String(drawn)));
 if(!cli&&!srv)return '<div>'+esc(T('port_src'))+': <b class="mono">'+esc(mode)+'</b></div>'
   +'<div class="wrap muted">'+band+'</div>';
 var rows='';
 if(cli)rows+='<div>'+esc(T('port_src_rot_up'))+': <b class="mono">'+esc(cli)+'</b></div>';
 if(srv)rows+='<div>'+esc(T('port_src_rot_down'))+': <b class="mono">'+esc(srv)+'</b></div>';
 return rows+'<div class="wrap muted">'+band+'</div>'}
var CT_WARN_PCT=80;
function ctbWarn(l){
 if(l.transport!='raw'||l.conntrack_bypass)return '';
 if(l.raw_profile!='udp'&&l.raw_profile!='tcp')return '';
 if(!num(l.raw_sport_rotate)&&!l.raw_sport_random)return '';
 var c=l.ct||{},pct=num(c.pct);
 if(!pct||pct<CT_WARN_PCT)return '';
 var msg=esc(T('ctb_warn').replace('{p}',String(pct)).replace('{c}',String(num(c.count))).replace('{m}',String(num(c.max))));
 return '<div class="warncap no emwarn">'+ic('warn')+'<span>'
   +msg.replace('{n}',function(){return '<b class="mono iso">'+esc(String(c.node||''))+'</b>'})
   +'</span></div>'}
function portRows(l){var t=l.transport||'udp';
 var live=num(l.sport_live);
 if(t=='raw'){
  if(l.raw_profile!='udp'&&l.raw_profile!='tcp')return '';
  var _R=l.rot_live||{},_nd=num(_R.dports),_ld=num(_R.dport)||num(l.raw_port)||RAW_DPORT_DEF;
  var _dst='<div>'+esc(T('port_dst'))+': <b class="mono">'+esc((_nd>1)?_ld:(num(l.raw_port)||RAW_DPORT_DEF))+'</b></div>';
  if(_nd>1)_dst+='<div class="wrap muted">'+esc(T('port_dst_rot')+' · '+T('port_dst_rot_n').replace('{n}',String(_nd)))+'</div>';
  var _rot=num(l.raw_sport_rotate);
  if(_rot||l.raw_sport_random)return _dst+rotSrcRows(l,_rot);
  return _dst+'<div>'+esc(T('port_src'))+': <b class="mono">'+esc(T('port_src_fixed')+' ('+(live||num(l.raw_sport)||RAW_SPORT_FIX)+')')+'</b></div>'}
 if(t=='dns')return '';
 var rows=(l.port)?('<div>'+esc(T('port'))+': <b class="mono">'+esc(l.port)+'</b></div>'):'';
 if(live&&portTriesOn({Tr:t}))rows+='<div>'+esc(T('port_src'))+': <b class="mono">'+esc(live)+'</b></div>';
 return rows}
function COR_RAW_PROFILES(){return [{v:'bare',m:T('rawp_bare_m')},{v:'icmp',m:T('rawp_icmp_m')},{v:'gre',m:T('rawp_gre_m')},{v:'ipip',m:T('rawp_ipip_m')},{v:'udp',m:T('rawp_udp_m')},{v:'tcp',m:T('rawp_tcp_m')},{v:'esp',m:T('rawp_esp_m')},{v:'l2tpv3',m:T('rawp_l2tpv3_m')},{v:'ah',m:T('rawp_ah_m')},{v:'ipcomp',m:T('rawp_ipcomp_m')},{v:'etherip',m:T('rawp_etherip_m')}]}
function rawTiles(px,sel){return COR_RAW_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==sel?' on':'')+'" data-p="'+p.v+'" data-ha="'+esc(p.v)+'" onclick="'+px+'SetProfile(hA(this))">'+'<div class="pn">'+p.v+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function WS_PROFILES(){return [{v:'ws',m:T('wsp_ws_m')},{v:'grpc',m:T('wsp_grpc_m')},{v:'http',m:T('wsp_http_m')}]}
function wsProfOf(S){return (S.Cdn=='http'||S.Cdn=='grpc')?S.Cdn:'ws'}
var CDN_SHAPE={upw:{k:'http_up_workers',lo:1,hi:16,d:8},upkb:{k:'http_up_batch_kb',lo:8,hi:512,d:512},downw:{k:'http_streams',lo:1,hi:16,d:1}};
function cdnNum(idp,n,lbl,l){var f=CDN_SHAPE[n];var cur=(l&&l[f.k])||f.d;return '<div style="flex:1;min-width:92px"><label style="margin-top:0">'+esc(lbl)+'</label><input id="'+idp+'cdn'+n+'" type="number" min="'+f.lo+'" max="'+f.hi+'" value="'+cur+'"></div>'}
function cdnShapeInputs(idp,l){return '<div id="'+idp+'cdnup" style="display:flex;gap:8px;flex:2">'+cdnNum(idp,'upw',T('cdn_upw_lbl'),l)+cdnNum(idp,'upkb',T('cdn_upkb_lbl'),l)+'</div>'+cdnNum(idp,'downw',T('cdn_strm_lbl'),l)}
function cdnShapeBody(px,body,cdn){Object.keys(CDN_SHAPE).forEach(function(n){var f=CDN_SHAPE[n];if(cdn!='http'&&f.k!='http_streams')return;var x=parseInt(v(px+'cdn'+n));if(!(x>=f.lo&&x<=f.hi))x=f.d;body[f.k]=x})}
function cdnShapeOn(S){return S.Tr=='ws'&&(S.Cdn=='http'||S.Cdn=='grpc')}
function corCdnShapeGate(){cdnShapeRow('e_',_corS);grpcZoneGate(_corS,'e_')}
function ceCdnShapeGate(){cdnShapeRow('ee_',_eeS);grpcZoneGate(_eeS,'ee_')}
function cdnShapeRow(px,S){var r=el(px+'cdnprow');if(r)r.style.display=cdnShapeOn(S)?'':'none';var u=el(px+'cdnup');if(u)u.style.display=(S.Cdn=='http')?'flex':'none'}
function wsProfTiles(px,cur){return WS_PROFILES().map(function(p){return '<button type="button" class="ptile'+(p.v==cur?' on':'')+'" data-wp="'+p.v+'" data-ha="'+esc(p.v)+'" onclick="'+px+'SetWsProf(hA(this))"><div class="pn">'+p.v+'</div><div class="pmeta">'+esc(p.m)+'</div></button>'}).join('')}
function grpcZoneGate(S,px){var w=el(px+'grpczone');if(w)w.style.display=(S.Cdn=='grpc')?'':'none'}
function _setWsProf(S,px,p){S.Cdn=p;grpcZoneGate(S,px);
 var g=el(px+'wspg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-wp')==p)})}
function corSetWsProf(p){_setWsProf(_corS,'e_',p);corWssGate();corDesyncGate();corCdnShapeGate()}
function ceSetWsProf(p){_setWsProf(_eeS,'ee_',p);ceWssGate();ceDesyncGate();ceCdnShapeGate()}
function corSetTr(t){_corS.Tr=t;_ENUMS.tr_all.forEach(function(x){var b=el('e_tr_'+x);if(b)b.classList.toggle('on',t==x)});var w=el('e_trword');if(w)w.textContent=(t=='tcp'?'TCP':(t=='raw'?'raw-IP':(t=='ws'?'CDN':(t=='dns'?'DNS':'UDP'))));corRawVis();corDnsVis();corWsVis();corPortGate();corCoverGate();corFecGate();corProtoVis();corPortTriesVis();corDesyncGate();corCdnShapeGate();corRotVis('e_');corWorkersVis();onCorCipher()}   

function corWsVis(){var ws=_corS.Tr=='ws';var w=el('e_wsblk');if(w)w.style.display=ws?'':'none';var t=el('e_wstlsrow'),e=el('e_wsechrow');if(t)t.style.display=ws?'':'none';if(e)e.style.display=ws?'':'none';var sr=el('e_snisplitrow');if(sr)sr.style.display=ws?'':'none';var sb=el('e_snisplitbody');if(sb)sb.style.display=(ws&&_corS.SniSplit)?'':'none';corEchPxGate();if(ws){poolVis('e_');corWssGate()}}
function corToggleWsTls(){_corS.WsTls=!_corS.WsTls;var s=el('e_wstls');if(s)s.classList.toggle('on',_corS.WsTls);if(!_corS.WsTls){if(_corS.Ech){_corS.Ech=false;var e=el('e_wsech');if(e)e.classList.remove('on')}if(_corS.SniSplit){_corS.SniSplit=false;var q=el('e_snisplit');if(q)q.classList.remove('on');var b=el('e_snisplitbody');if(b)b.style.display='none'}}corEchPxGate()}
function corToggleSni(){if(!_corS.WsTls){_corS.SniSplit=false;var q=el('e_snisplit');if(q)q.classList.remove('on');alert(T('sni_need_wss'));return}_corS.SniSplit=!_corS.SniSplit;var s=el('e_snisplit');if(s)s.classList.toggle('on',_corS.SniSplit);var b=el('e_snisplitbody');if(b)b.style.display=_corS.SniSplit?'':'none'}
function corSetSniMode(m){_corS.SniMode=m;var g=el('e_snimodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_snim_'+m)});var b=el('e_snittlbody');if(b)b.style.display=(m=='disorder')?'':'none'}
function corWssGate(){var mand=poolGet('e_').pool||_corS.Cdn=='grpc';var row=el('e_wstlsrow'),s=el('e_wstls');if(mand){_corS.WsTls=true;if(s)s.classList.add('on');if(row)row.classList.add('dis')}else if(row)row.classList.remove('dis')}
function corToggleEch(){if(!_corS.WsTls){_corS.Ech=false;var e=el('e_wsech');if(e)e.classList.remove('on');corEchPxGate();alert(T('ech_need_wss_alert'));return}_corS.Ech=!_corS.Ech;var s=el('e_wsech');if(s)s.classList.toggle('on',_corS.Ech);corEchPxGate()}
function corToggleEchProxy(){_corS.EchProxy=!_corS.EchProxy;var s=el('e_echpx');if(s)s.classList.toggle('on',_corS.EchProxy);var b=el('e_echpxbody');if(b)b.style.display=_corS.EchProxy?'':'none'}
function corEchPxGate(){var vis=(_corS.Tr=='ws'&&_corS.Ech),row=el('e_echpxrow');if(!vis){_corS.EchProxy=false;var s=el('e_echpx');if(s)s.classList.remove('on')}if(row)row.style.display=vis?'':'none';var b=el('e_echpxbody');if(b)b.style.display=(vis&&_corS.EchProxy)?'':'none'}
var _poolData={};
function poolInit(pfx,l){_poolData[pfx]={pool:!!(l&&l.ws_pool),rotate:(l&&l.ws_rotate_secs!=null)?l.ws_rotate_secs:600,
  open:{ip:false,sni:false},act:{ip:'',sni:''},lid:(l&&l.id)||'',
  ip:{clean:((l&&l.ws_edge_ips)||[]).slice()},
  sni:{clean:((l&&l.ws_edge_snis)||[]).map(function(s){return (s&&s.host)||''}).filter(Boolean)}};}
function poolGet(pfx){if(!_poolData[pfx])poolInit(pfx,null);return _poolData[pfx];}
var _ip4Re=/^(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}$/;
var _domRe=/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\\.)+[A-Za-z]{2,}$/;
function edgePortsOK(){var e=_ENUMS.edge_ports||{};return (poolGet('ee_').tls?e.tls:e.plain)||[]}
function poolValid(kind,val){var h=val;if(kind=='ip'){var c=val.lastIndexOf(':');if(c>=0){h=val.slice(0,c);var p=val.slice(c+1);if(!(/^\\d+$/.test(p)&&edgePortsOK().indexOf(+p)>=0))return false;}return _ip4Re.test(h);}return _domRe.test(val);}
function _cdRemain(now,polledMs,next){if(!next||!now)return -1;var e=now+(Date.now()-(polledMs||Date.now()))/1000;return Math.max(0,Math.round(next-e));}
function _cdTick(host,now,polledMs){if(!host)return;
  Array.prototype.forEach.call(host.querySelectorAll('.pcd'),function(sp){var r=_cdRemain(now,polledMs,+sp.getAttribute('data-next'));if(r>=0)sp.textContent=poolCdTxt(r)});
  Array.prototype.forEach.call(host.querySelectorAll('.pbar'),function(bar){var tot=+bar.getAttribute('data-tot')||1,rem=_cdRemain(now,polledMs,+bar.getAttribute('data-next'));if(rem<0)return;var i=bar.firstChild;if(i)i.style.width=Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)))+'%'})}
function poolRemain(d,next){return _cdRemain(d.srvNow,d.polledMs,next);}
function poolCdTxt(r){var h=Math.floor(r/3600),m=Math.floor(r%3600/60),s=r%60;
 return (h?h+':'+(m<10?'0'+m:m):m)+':'+(s<10?'0'+s:s);}
function poolCd(d,next){var r=poolRemain(d,next);if(r<0)return '';return '<span class="pcd" data-next="'+next+'">'+poolCdTxt(r)+'</span>';}
var _poolBackoff=_TUNDEF.suspect_backoff.slice(),_poolDeadStep=_TUNDEF.dead_retest_secs;
function poolStepTotal(h){return h.state=='dead'?_poolDeadStep:(_poolBackoff[Math.min(h.fails||0,_poolBackoff.length-1)]||600);}
function poolBarPct(d,h){var tot=poolStepTotal(h),rem=poolRemain(d,h.next);if(rem<0)return -1;return Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)));}
function poolBar(d,h){var p=poolBarPct(d,h);if(p<0)return '';return '<span class="pbar'+(h.state=='dead'?' bad':'')+'" data-next="'+h.next+'" data-tot="'+poolStepTotal(h)+'"><i style="width:'+p+'%"></i></span>';}
function poolRenderKind(pfx,kind){var d=poolGet(pfx);
  var lv=d.live||{};var ns=0,nd=0;d[kind].clean.forEach(function(v){var h=lv[kind+':'+v];if(h&&h.state=='suspect')ns++;else if(h&&h.state=='dead')nd++;});
  var hd=el(pfx+'hd_'+kind);if(hd){hd.innerHTML='<span class="pbadge ok">'+(d[kind].clean.length-ns-nd)+' '+T('pb_healthy')+'</span>'+(ns?'<span class="pbadge warn">'+ns+' '+T('pb_temp')+'</span>':'')+(nd?'<span class="pbadge bad">'+nd+' '+T('pb_dead')+'</span>':'');}
  var host=el(pfx+'lst_'+kind);if(!host)return;
  function row(v){var act=d.act&&d.act[kind]===v;
    var h=lv[kind+':'+v];
    var rowc,sc,sic,stt;
    if(h&&h.state=='dead'){rowc='bad';sc='bad';sic=act?'bolt':'xc';stt=act?T('ph_active_retry'):T('ph_dead');}
    else if(h&&h.state=='suspect'){rowc='warn';sc='warn';sic=act?'bolt':'warn';stt=act?T('ph_active_retry'):T('ph_suspect');}
    else if(act){rowc='ok';sc='ok';sic='bolt';stt=T('ph_active');}
    else{rowc='ok';sc='ok';sic='okc';stt=T('ph_healthy');}
    var rt=(h&&(h.state=='suspect'||h.state=='dead'))?'<span class="ert">'+poolCd(d,h.next)+poolBar(d,h)+'</span>':'';
    var acts='';
    if(h&&(h.state=='suspect'||h.state=='dead')&&d.lid)acts+='<button type="button" class="eib" title="'+esc(T('pa_testnow'))+'" data-ha="'+esc(d.lid)+'" data-hb="'+esc(kind)+'" data-hc="'+esc(v)+'" onclick="poolRetestNow(hA(this),hB(this),hC(this))">'+ic('redo')+'</button>';
    if(d.lid){var pend=d.selPending;var isTarget=pend&&pend.kind==kind&&pend.key==v;
      if(pend)acts+='<button type="button" class="eib aim'+(act?' on':'')+'" disabled style="opacity:.45;pointer-events:none" title="'+esc(T('pa_selecting'))+'">'+(isTarget?'<span class="bspin"></span>':ic('pin'))+'</button>';
      else acts+='<button type="button" class="eib aim'+(act?' on':'')+'" title="'+(act?esc(T('pa_active_ip')):esc(T('pa_activate')))+'" data-ha="'+esc(d.lid)+'" data-hb="'+esc(kind)+'" data-hc="'+esc(v)+'" onclick="poolSelect(hA(this),hB(this),hC(this))">'+ic('pin')+'</button>';}
    acts+='<button type="button" class="eib del" title="'+esc(T('tip_delete'))+'" data-ha="'+esc(pfx)+'" data-hb="'+esc(kind)+'" data-hc="'+esc(v)+'" onclick="poolDel(hA(this),hB(this),hC(this))">'+ic('trash')+'</button>';
    return '<div class="erow '+rowc+((h&&h.state=='dead')?' dead':'')+'">'
     +'<span class="estat '+sc+'" title="'+stt+'">'+ic(sic)+'</span>'
     +'<span class="eip" title="'+esc(v)+'">'+esc(v)+'</span>'+rt
     +'<span class="eacts">'+acts+'</span></div>';}
  var html=d[kind].clean.map(row).join('');
  host.innerHTML=html||'<div class="pempty">'+esc(T('pool_empty'))+'</div>';}
function poolAccApply(pfx,kind){var d=poolGet(pfx),b=el(pfx+'body_'+kind),c=el(pfx+'chev_'+kind);if(b)b.style.display=d.open[kind]?'':'none';if(c)c.classList.toggle('open',d.open[kind]);}
function poolAcc(pfx,kind){var d=poolGet(pfx);d.open[kind]=!d.open[kind];poolAccApply(pfx,kind);}
function poolRender(pfx){['ip','sni'].forEach(function(k){poolRenderKind(pfx,k);poolAccApply(pfx,k);});}
function poolAdd(pfx,kind){var i=el(pfx+'add_'+kind);if(!i)return;var val=(i.value||'').trim();if(kind=='sni')val=val.toLowerCase();if(!val)return;if(!poolValid(kind,val)){alert(kind=='ip'?T('pool_bad_ip'):T('pool_bad_dom'));return;}var d=poolGet(pfx);if(d[kind].clean.indexOf(val)>=0){i.value='';return;}d[kind].clean.push(val);i.value='';d.open[kind]=true;poolAccApply(pfx,kind);poolRenderKind(pfx,kind);}
function poolDel(pfx,kind,val){var d=poolGet(pfx);if(kind=='ip'&&d.ip.clean.length<=2){toast(T('pool_ip_min2'),'err');return}d[kind].clean=d[kind].clean.filter(function(x){return x!=val});poolRenderKind(pfx,kind);}
function poolVis(pfx){var d=poolGet(pfx),s=el(pfx+'wshostblk'),p=el(pfx+'wspool'),t=el(pfx+'pooltgl');if(t)t.classList.toggle('on',d.pool);if(s)s.style.display=d.pool?'none':'';if(p)p.style.display=d.pool?'':'none';if(d.pool)poolRender(pfx);}
function poolToggle(pfx){poolGet(pfx).pool=!poolGet(pfx).pool;poolVis(pfx);}
function poolCollect(pfx,body){var d=poolGet(pfx);if(!d.pool){body.ws_pool=false;return true;}var rv=ssVal(pfx+'poolrot');if(rv!=='')d.rotate=+rv;if(d.ip.clean.length<2)return T('pool_ip_min2');if(!d.sni.clean.length)return T('pool_need_clean');body.ws_pool=true;body.ws_tls=true;body.ws_edge_ips=d.ip.clean;body.ws_edge_snis=d.sni.clean;body.ws_rotate_secs=d.rotate;return true;}
function corTogglePool(){poolToggle('e_');corWssGate()}
function ceTogglePool(){poolToggle('ee_');ceWssGate()}



function fecDatagram(S){return S.Tr=='udp'||S.Tr=='raw'}
function corFecDatagram(){return fecDatagram(_corS)}
function corToggleFec(){if(!corFecDatagram())return;_corS.Fec=!_corS.Fec;var s=el('e_fecsw');if(s)s.classList.toggle('on',_corS.Fec);var r=el('e_fecrates');if(r)r.style.display=_corS.Fec?'':'none';corWorkersVis()}   
function corSetFecRate(d,p){_corS.FecData=d;_corS.FecParity=p;var g=el('e_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function corFecGate(){var dg=corFecDatagram(),row=el('e_fecrow');if(!dg){_corS.Fec=false;var s=el('e_fecsw');if(s)s.classList.remove('on');var r=el('e_fecrates');if(r)r.style.display='none'}if(row)row.style.display=dg?'':'none'}

function poolApplyStatus(pfx,st){var d=poolGet(pfx);var pr=st.pair||{};
  d.act={ip:'',sni:''};
  if(pr.low_kind)d.act[pr.low_kind]=String(pr.low||'');
  if(pr.high_kind)d.act[pr.high_kind]=String(pr.high||'');
  d.live={};(st.health||[]).forEach(function(h){if(h&&h.key)d.live[(h.kind=='sni'?'sni':'ip')+':'+h.key]={state:String(h.state||'healthy'),next:+h.next_retest_unix||0,fails:+h.fails||0}});
  d.srvNow=+st.now||Math.floor(Date.now()/1000);d.polledMs=Date.now();
  if(d.selPending){var pk=d.selPending;if(d.act[pk.kind]===pk.key||(Date.now()-pk.ts>12000))d.selPending=null;}
  poolRenderKind(pfx,'ip');poolRenderKind(pfx,'sni');}  
async function poolTick(){if(!_eeS.PoolLid)return;if(!poolGet('ee_').pool)return;var r=await post('edge-status',{id:_eeS.PoolLid});
 if(r.ok&&r.d&&r.d.ok&&r.d.pool){poolStale(false);poolApplyStatus('ee_',r.d);return}
 poolStale(true,perr(r));}
function poolStale(on,why){var w=el('ee_poolstale');if(!w)return;
 w.style.display=on?'':'none';w.innerHTML=on?(ic('warn')+'<span>'+esc(T('pool_stale'))+(why?(' — '+esc(why)):'')+'</span>'):'';}
(function poolLoop(){setTimeout(function(){Promise.resolve(poolTick()).then(poolLoop,poolLoop)},UIV)})();   
function poolCdTick(){var d=_poolData['ee_'];if(!d||!d.live)return;['ip','sni'].forEach(function(k){_cdTick(el('ee_lst_'+k),d.srvNow,d.polledMs)})}
setInterval(poolCdTick,1000);
async function poolRetestNow(lid,kind,key){if(!lid){toast(T('pool_make_first'),'err');return}
  var r=await post('pool-retest-now',{id:lid,kind:kind,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('peer_probe_pulled'),'ok');[1200,3000,5500,8000].forEach(function(ms){setTimeout(poolTick,ms)})}else{toast(perr(r),'err')}}
async function poolSelect(lid,kind,key){if(!lid){toast(T('pool_make_first'),'err');return}
  var d=poolGet('ee_');
  if(d.selPending)return;                                   
  d.selPending={kind:kind,key:key,ts:Date.now()};           
  poolRenderKind('ee_','ip');poolRenderKind('ee_','sni');
  var r=await post('pool-select',{id:lid,kind:kind,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('pool_edge_active'),'ok');[1200,3000,5500,8000,11000].forEach(function(ms){setTimeout(poolTick,ms)})}
  else{d.selPending=null;poolRenderKind('ee_','ip');poolRenderKind('ee_','sni');toast(perr(r),'err')}}
function edgeChipsOf(ip,dom){
 if(!ip&&!dom)return '<span class="echip wait">…</span>';
 var h=ip?'<span class="echip ip">'+esc(ip)+'</span>':'';
 if(dom)h+='<span class="echip dom">'+esc(dom)+'</span>';
 return h}
function edgeChips(v){v=String(v||'');var p=v.split(' · ');return edgeChipsOf(p[0]||'',p.slice(1).join(' · '))}
async function refreshCardEdges(){var els=document.querySelectorAll('[id^="cardedge_"]');
 await Promise.all(Array.prototype.map.call(els,function(elm){var lid=elm.id.slice(9);   
  return post('edge-status',{id:lid}).then(function(r){if(r.ok&&r.d&&r.d.ok&&r.d.pool){var v=r.d.active||'';
    if(v&&v!==EDGEV[lid]){EDGEV[lid]=v;var e=el('cardedge_'+lid);if(e)e.innerHTML=edgeChips(v)}}},function(){})}))}   
(function edgesLoop(){var d=document.hidden?Math.max(UIV,4000):UIV;
 setTimeout(function(){if(document.hidden){edgesLoop();return}refreshCardEdges().then(edgesLoop,edgesLoop)},d)})();
function rotMark(){return '<span class="rotmark" title="'+esc(T('peer_rotating'))+'">'+ic('redo')+'</span>'}
var _peerLid='';
var _peerData={dst:null,src:null,now:0,polledMs:0,selPending:null,open:{}};   
async function peerTick(){if(!_peerLid||!el('ee_peerlive'))return;var r=await post('peer-status',{id:_peerLid});if(r.ok&&r.d&&r.d.ok&&r.d.pool)peerApply(r.d);}
(function peerLoop(){setTimeout(function(){Promise.resolve(peerTick()).then(peerLoop,peerLoop)},UIV)})();   
function peerApply(st){
  _peerData.now=+st.now||Math.floor(Date.now()/1000);_peerData.polledMs=Date.now();
  ['dst','src'].forEach(function(side){var sec=st[side]||{};var live={};
    (sec.health||[]).forEach(function(h){if(h&&h.key)live[h.key]={state:String(h.state||'healthy'),next:+h.next_retest_unix||0,fails:+h.fails||0}});
    _peerData[side]={active:String(sec.active||''),addrs:(sec.addrs||[]).map(String),live:live};});
  if(_peerData.selPending){var pk=_peerData.selPending,sec=_peerData[pk.side]||{};if(sec.active===pk.key||(Date.now()-pk.ts>12000))_peerData.selPending=null;}
  peerRender();}
function peerRemain(next){return _cdRemain(_peerData.now,_peerData.polledMs,next);}
function peerCd(next){var r=peerRemain(next);if(r<0)return '';return '<span class="pcd" data-next="'+next+'">'+poolCdTxt(r)+'</span>';}
function peerBar(h){var tot=poolStepTotal(h),rem=peerRemain(h.next);if(rem<0)return '';var p=Math.max(0,Math.min(100,Math.round((tot-rem)/tot*100)));return '<span class="pbar'+(h.state=='dead'?' bad':'')+'" data-next="'+h.next+'" data-tot="'+tot+'"><i style="width:'+p+'%"></i></span>';}
function peerRow(side,ip){var d=_peerData[side],h=d.live[ip],act=(d.active===ip);
  var rowc,sc,sic,stt;
  if(h&&h.state=='dead'){rowc='bad';sc='bad';sic=act?'bolt':'xc';stt=act?T('peer_st_active_retry'):T('ph_dead');}
  else if(h&&h.state=='suspect'){rowc='warn';sc='warn';sic=act?'bolt':'warn';stt=act?T('peer_st_active_retry'):T('ph_suspect');}
  else if(act){rowc='ok';sc='ok';sic='bolt';stt=T('peer_st_active');}
  else{rowc='ok';sc='ok';sic='okc';stt=T('peer_st_rot');}
  var burned=(h&&(h.state=='suspect'||h.state=='dead'));
  var cd=burned?'<div class="ecd">'+peerCd(h.next)+peerBar(h)+'</div>':'';
  var pend=_peerData.selPending,isTarget=pend&&pend.side==side&&pend.key==ip,acts='';
  if(burned&&_peerLid)acts+='<button type="button" class="eib" title="'+esc(T('pa_testnow'))+'" data-ha="'+esc(side)+'" data-hb="'+esc(ip)+'" onclick="peerRetestNow(hA(this),hB(this))">'+ic('redo')+'</button>';
  if(pend)acts+='<button type="button" class="eib aim'+(act?' on':'')+'" disabled style="opacity:.45;pointer-events:none" title="'+esc(T('pa_selecting'))+'">'+(isTarget?'<span class="bspin"></span>':ic('pin'))+'</button>';
  else acts+='<button type="button" class="eib aim'+(act?' on':'')+'" title="'+(act?esc(T('pa_active_ip')):esc(T('pa_activate')))+'" data-side="'+side+'" data-ip="'+esc(ip)+'" onclick="peerSelect(this)">'+ic('pin')+'</button>';
  return '<div class="erow pcol '+rowc+((h&&h.state=='dead')?' dead':'')+'"><div class="etop"><span class="estat '+sc+'" title="'+stt+'">'+ic(sic)+'</span><span class="eip" title="'+esc(ip)+'">'+esc(ip)+'</span><span class="eacts">'+acts+'</span></div>'+cd+'</div>';}
var PEER_ACC_MIN=3;
function peerAccOpen(side){var d=_peerData[side];if(!d)return true;
  if(d.addrs.length<=PEER_ACC_MIN)return true;                 
  if(!_peerData.open)_peerData.open={};
  return _peerData.open[side]!==false;}                        
function peerAcc(side){if(!_peerData.open)_peerData.open={};
  _peerData.open[side]=!peerAccOpen(side);peerRender();}
function peerBox(side,lab){var d=_peerData[side];if(!d||d.addrs.length<2)return '';
  var live=d.live||{},ns=0,nd=0;d.addrs.forEach(function(ip){var h=live[ip];if(h&&h.state=='suspect')ns++;else if(h&&h.state=='dead')nd++;});
  var badges='<span class="pbadge ok">'+(d.addrs.length-ns-nd)+' '+T('pb_healthy')+'</span>'+(ns?'<span class="pbadge warn">'+ns+' '+T('pb_temp')+'</span>':'')+(nd?'<span class="pbadge bad">'+nd+' '+T('pb_dead')+'</span>':'');
  var acc=d.addrs.length>PEER_ACC_MIN,open=peerAccOpen(side);
  var chev=acc?'<div class="pchev'+(open?' open':'')+'">&#9662;</div>':'';
  var hd='<div class="pacchd"'+(acc?' data-acc role="button" tabindex="0" data-ha="'+esc(side)+'" onclick="peerAcc(hA(this))"':' style="cursor:default"')+'>'
    +'<div class="pacctl"><div class="pacct">'+esc(lab)+'</div><div class="paccs">'+badges+'</div></div>'
    +'<div style="display:flex;align-items:center;gap:8px">'+chev+'</div></div>';
  var body='<div class="paccbody"'+(open?'':' style="display:none"')+'><div class="rpool">'
    +d.addrs.map(function(ip){return peerRow(side,ip)}).join('')+'</div></div>';
  return '<div class="pacc">'+hd+body+'</div>';}
function peerRender(){var host=el('ee_peerlive');if(!host)return;
  var boxes=peerBox('dst',T('dst_ip'))+peerBox('src',T('src_ip'));
  if(!boxes){host.innerHTML='<div class="peerlive"><div class="pllabel">'+esc(T('peer_live_hd'))+'</div><div class="muted" style="font-size:11px;line-height:1.7">'+esc(T('peer_live_empty'))+'</div></div>';return;}
  host.innerHTML='<div class="peerlive"><div class="pllabel">'+esc(T('peer_live_hd'))+'</div>'+boxes+'</div>';}
function peerCdTick(){if(!_peerLid)return;_cdTick(el('ee_peerlive'),_peerData.now,_peerData.polledMs)}
setInterval(peerCdTick,1000);
async function peerSelect(btn){var side=btn.getAttribute('data-side'),key=btn.getAttribute('data-ip');
  if(!_peerLid||_peerData.selPending||!key)return;
  _peerData.selPending={side:side,key:key,ts:Date.now()};peerRender();
  var r=await post('peer-select',{id:_peerLid,side:side,key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('peer_moved'),'ok');[1200,3000,5500,8000,11000].forEach(function(ms){setTimeout(peerTick,ms)})}
  else{_peerData.selPending=null;peerRender();toast(perr(r),'err')}}
async function peerRetestNow(side,key){if(!_peerLid)return;
  var r=await post('peer-retest-now',{id:_peerLid,kind:(side=='src'?'src':'dst'),key:key});
  if(r.ok&&r.d&&r.d.ok){toast(T('peer_probe_pulled'),'ok');[1200,3000,5500,8000].forEach(function(ms){setTimeout(peerTick,ms)})}
  else{toast(perr(r),'err')}}
function protoSection(idp,fnp){return '<div id="'+idp+'protorow" style="display:none;margin-top:11px">'
 +'<label class="first">'+esc(T('raw_proto_lbl'))+'</label>'
 +'<div class="seg2" id="'+idp+'ppg" style="margin-bottom:8px"><button type="button" class="segopt on" id="'+idp+'pp_253" onclick="'+fnp+'SetProto(253)"><b>253</b><span>'+esc(T('raw_proto_native'))+'</span></button><button type="button" class="segopt" id="'+idp+'pp_252" onclick="'+fnp+'SetProto(252)"><b>252</b><span>'+esc(T('raw_proto_free'))+'</span></button></div>'
 +'<input id="'+idp+'rawproto" class="mono" inputmode="numeric" maxlength="3" placeholder="253" oninput="'+fnp+'ProtoWarn()" style="text-align:center;direction:ltr">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+T('raw_proto_hint')+'</div>'
 +'<div class="warncap no" id="'+idp+'protowarn" style="display:none;margin-top:8px"></div></div>'}
function portSection(idp,fnp){return '<div id="'+idp+'portrow" style="display:none;margin-top:11px">'
 +'<label class="first">'+esc(rng(T('raw_port_lbl'),1,PORT_MAX))+'</label>'
 +'<div class="seg2" id="'+idp+'rpg" style="margin-bottom:8px">'
   +'<button type="button" class="segopt on" id="'+idp+'rp_443" onclick="'+fnp+'SetPort(443)"><b>443</b><span>'+esc(T('raw_port_quic'))+'</span></button>'
   +'<button type="button" class="segopt" id="'+idp+'rp_51820" onclick="'+fnp+'SetPort(51820)"><b>51820</b><span>WireGuard</span></button>'
   +'<button type="button" class="segopt" id="'+idp+'rp_4500" onclick="'+fnp+'SetPort(4500)"><b>4500</b><span>IPsec</span></button></div>'
 +'<input id="'+idp+'rawport" class="mono" inputmode="numeric" maxlength="5" placeholder="443" oninput="'+fnp+'PortWarn()" style="text-align:center;direction:ltr">'
 +'<div id="'+idp+'srcblk">'
   +'<label style="margin-top:13px">'+esc(rng(T('raw_sport_lbl'),1,PORT_MAX))+'</label>'
   +'<div class="seg2" id="'+idp+'spg">'
     +'<button type="button" class="segopt on" id="'+idp+'sp_fix" onclick="'+fnp+'SetSport(0)"><b>'+esc(T('raw_sport_fixed_n'))+'</b><span>'+esc(T('raw_sport_fixed_m'))+'</span></button>'
     +'<button type="button" class="segopt" id="'+idp+'sp_rnd" onclick="'+fnp+'SetSport(1)"><b>'+esc(T('raw_sport_rand_n'))+'</b><span>'+esc(T('raw_sport_rand_m'))+'</span></button></div>'
   +'<div id="'+idp+'spfix" style="margin-top:8px">'
     +'<div class="seg2" id="'+idp+'spg2" style="margin-bottom:8px">'
       +'<button type="button" class="segopt on" id="'+idp+'sp_51820" onclick="'+fnp+'SetSportPort(51820)"><b>51820</b><span>WireGuard</span></button>'
       +'<button type="button" class="segopt" id="'+idp+'sp_4500" onclick="'+fnp+'SetSportPort(4500)"><b>4500</b><span>IPsec</span></button>'
       +'<button type="button" class="segopt" id="'+idp+'sp_500" onclick="'+fnp+'SetSportPort(500)"><b>500</b><span>'+esc(T('raw_sport_ike'))+'</span></button></div>'
     +'<input id="'+idp+'rawsport" class="mono" inputmode="numeric" maxlength="5" placeholder="51820" oninput="'+fnp+'SportWarn()" style="text-align:center;direction:ltr"></div></div>'
 +'<div id="'+idp+'sprotrow" style="display:none">'
   +'<div class="tglbox"><div class="tglsw" id="'+idp+'sprotsw" onclick="'+fnp+'ToggleSprot()"></div>'
     +'<div class="tt"><b>'+esc(T('raw_sprot_t'))+'</b><small>'+esc(T('raw_sprot_d'))+'</small></div></div>'
   +'<div id="'+idp+'sprotbody" style="display:none">'
     +'<div class="grid2">'
       +'<div><label>'+esc(rng(T('raw_sprot_lbl'),1,RAW_SPROT_MAX))+'</label>'
         +'<input id="'+idp+'rawsprot" class="mono" inputmode="numeric" maxlength="2" placeholder="5" oninput="'+fnp+'SprotWarn()" style="text-align:center;direction:ltr"></div>'
       +'<div><label>'+esc(rng(T('raw_dports_lbl'),1,RAW_DPORTS_MAX))+'</label>'
         +'<input id="'+idp+'rawdports" class="mono" inputmode="numeric" maxlength="2" placeholder="1" oninput="'+fnp+'SprotWarn()" style="text-align:center;direction:ltr"></div>'
     +'</div>'
     +'<div class="warncap no" id="'+idp+'sprotwarn" style="display:none;margin-top:8px"></div></div></div>'
 +'<div id="'+idp+'bandrow" style="display:none;margin-top:11px">'
   +'<label class="first">'+esc(T('band_lbl'))+'</label>'
   +'<div class="grid2">'
     +'<div><label>'+esc(T('band_lo'))+'</label>'
       +'<input id="'+idp+'bandlo" class="mono" inputmode="numeric" maxlength="5" placeholder="'+RAW_ROT_LO+'" data-ha="'+esc(idp)+'" oninput="bandWarnUpd(hA(this))" style="text-align:center;direction:ltr"></div>'
     +'<div><label>'+esc(T('band_hi'))+'</label>'
       +'<input id="'+idp+'bandhi" class="mono" inputmode="numeric" maxlength="5" placeholder="'+RAW_ROT_HI+'" data-ha="'+esc(idp)+'" oninput="bandWarnUpd(hA(this))" style="text-align:center;direction:ltr"></div>'
   +'</div>'
   +'<div class="muted" style="font-size:11px;margin-top:4px">'+esc(T('band_hint').replace('{lo}',String(RAW_ROT_LO)).replace('{hi}',String(RAW_ROT_HI)))+'</div>'
   +'<div class="warncap no" id="'+idp+'bandwarn" style="display:none;margin-top:8px"></div></div>'
 +'<div id="'+idp+'ctbrow" style="display:none">'
   +'<div class="tglbox"><div class="tglsw" id="'+idp+'ctbsw" onclick="'+fnp+'ToggleCtb()"></div>'
     +'<div class="tt"><b>'+esc(T('ctb_t'))+'</b><small>'+esc(T('ctb_d'))+'</small></div></div></div>'
 +'</div>'}
function ctbOn(S){return S.Tr=='raw'&&(S.RawProfile=='udp'||S.RawProfile=='tcp')}
function ctbVis(idp,S){var w=el(idp+'ctbrow'),on=ctbOn(S);
 if(!on)S.Ctb=false;
 if(w)w.style.display=on?'':'none';
 var sw=el(idp+'ctbsw');if(sw)sw.classList.toggle('on',on&&!!S.Ctb)}
function ctbToggle(idp,S){if(!ctbOn(S))return;S.Ctb=!S.Ctb;ctbVis(idp,S)}
var PORT_MAX=65535;
function rng(lbl,lo,hi){return lbl+' (بازه '+lo+' تا '+hi+')'}
var PORT_RUNG_TRANSPORTS=['udp','tcp','ws'];
function portTriesOn(S){
 if(S.Tr=='raw')return (S.RawProfile=='udp'||S.RawProfile=='tcp')&&!!S.SportRandom;
 return PORT_RUNG_TRANSPORTS.indexOf(S.Tr)>=0}
function portTriesSection(idp){return '<div id="'+idp+'sptries" style="display:none;margin-top:11px">'
 +'<label class="first">'+esc(rng(T('porttries_lbl'),1,PORT_TRIES_MAX))+'</label>'
 +'<input id="'+idp+'porttries" class="mono" inputmode="numeric" maxlength="2" placeholder="2" style="text-align:center;direction:ltr" data-ha="'+esc(idp)+'" oninput="portTriesWarnUpd(hA(this))">'
 +'<div class="warncap no" id="'+idp+'ptwarn" style="display:none;margin-top:8px"></div></div>'}
function portTriesN(idp){var e=el(idp+'porttries');if(!e)return 0;var n=parseInt((e.value||'').trim(),10);return isNaN(n)?0:n}
function portTriesErr(idp,S){if(!portTriesOn(S))return '';var n=portTriesN(idp);
 return (n===0||(n>=1&&n<=PORT_TRIES_MAX))?'':T('porttries_bad')}
function portTriesWarnUpd(idp){var w=el(idp+'ptwarn');if(!w)return;
 var n=portTriesN(idp),e=(n===0||(n>=1&&n<=PORT_TRIES_MAX))?'':T('porttries_bad');
 if(e){w.style.display='';w.innerHTML=ic('warn')+'<span>'+esc(e)+'</span>'}else{w.style.display='none';w.innerHTML=''}}
function portTriesVis(idp,S){var w=el(idp+'sptries');if(w)w.style.display=portTriesOn(S)?'':'none'}
var SPROT_DEF=4;
function sprotOn(S){return S.Tr=='raw'&&(S.RawProfile=='udp'||S.RawProfile=='tcp')}
function sprotLive(S){return sprotOn(S)&&!!S.Sprot}
function sprotN(idp){var e=el(idp+'rawsprot');if(!e)return 0;var n=parseInt((e.value||'').trim(),10);return isNaN(n)?0:n}
function sprotVis(idp,S){var w=el(idp+'sprotrow');var on=sprotOn(S);
 if(!on)S.Sprot=false;
 if(w)w.style.display=on?'':'none';
 var sw=el(idp+'sprotsw');if(sw)sw.classList.toggle('on',sprotLive(S));
 var b=el(idp+'sprotbody');if(b)b.style.display=sprotLive(S)?'':'none';
 var src=el(idp+'srcblk');if(src)src.classList.toggle('portlock',sprotLive(S));
 sprotWarnUpd(idp,S);bandVis(idp,S)}
function sprotToggle(idp,S){if(!sprotOn(S))return;S.Sprot=!S.Sprot;
 if(S.Sprot){var e=el(idp+'rawsprot');if(e&&!sprotN(idp))e.value=String(SPROT_DEF);
  S.SportRandom=false;sportPaint(idp,false)}
 sprotVis(idp,S);ctbVis(idp,S);portTriesVis(idp,S)}
function dportsN(idp){var e=el(idp+'rawdports');if(!e)return 0;var n=parseInt((e.value||'').trim(),10);return isNaN(n)?0:n}
function bandN(idp,which){var e=el(idp+which);if(!e)return 0;var n=parseInt((e.value||'').trim(),10);return isNaN(n)?0:n}
function bandOn(S){return sprotOn(S)&&(!!S.Sprot||!!S.SportRandom)}
function bandVis(idp,S){var w=el(idp+'bandrow');if(w)w.style.display=bandOn(S)?'':'none';bandWarnUpd(idp)}
function bandErr(idp){var lo=bandN(idp,'bandlo'),hi=bandN(idp,'bandhi');
 if(!lo&&!hi)return '';
 if(!(lo>=RAW_BAND_MIN_LO&&lo<=65535)||!(hi>=RAW_BAND_MIN_LO&&hi<=65535)||hi<lo)return T('band_bad').replace('{n}',String(RAW_BAND_MIN_LO));
 if(hi-lo+1<RAW_BAND_MIN_SPAN)return T('band_narrow').replace('{n}',String(RAW_BAND_MIN_SPAN));
 return ''}
function bandWarnUpd(idp){var w=el(idp+'bandwarn');if(!w)return;var e=bandErr(idp);
 if(e){w.style.display='';w.innerHTML=ic('warn')+'<span>'+esc(e)+'</span>'}else{w.style.display='none';w.innerHTML=''}}
function sprotErr(idp,S){if(!sprotLive(S))return '';var n=sprotN(idp);
 if(!(n>=1&&n<=RAW_SPROT_MAX))return T('raw_sprot_bad');
 var d=dportsN(idp);
 return (d===0||(d>=1&&d<=RAW_DPORTS_MAX))?'':T('raw_dports_bad').replace('{n}',String(RAW_DPORTS_MAX))}
function sprotWarnUpd(idp,S){var w=el(idp+'sprotwarn');if(!w)return;var e=sprotErr(idp,S);
 if(e){w.style.display='';w.innerHTML=ic('warn')+'<span>'+esc(e)+'</span>'}else{w.style.display='none';w.innerHTML=''}}
function workersSection(idp,fnp){
 var one=function(sd){return '<div id="'+idp+'wkone_'+sd+'">'+'<div class="muted" style="font-size:11px;margin-top:7px" id="'+idp+'wklbl_'+sd+'"></div>'
   +'<div class="trwrap"><div class="seg2 trbar" id="'+idp+'wkg_'+sd+'" onscroll="trFade(this)">'
   +_WKMAX.map(function(n){return '<button type="button" class="segopt'+(n==1?' on':'')+'" id="'+idp+'wk_'+sd+'_'+n+'" data-ha="'+esc(sd)+'" data-hb="'+n+'" onclick="'+fnp+'SetWorkers(hA(this),+hB(this))"><b>'+n+'</b><span>'+esc(T('workers_'+n))+'</span></button>'}).join('')
   +'</div></div></div>'};
 return '<div id="'+idp+'wrkrow" style="display:none;margin-top:11px">'
 +'<label class="first">'+esc(T('workers_lbl'))+'</label>'
 +'<div id="'+idp+'wkpair" style="display:flex;flex-direction:column">'+one('a')+one('b')+'</div>'
 +'</div>'}

function workersPaint(idp,sd,n){n=wkClamp(n);
 _WKMAX.forEach(function(k){var b=el(idp+'wk_'+sd+'_'+k);if(b)b.classList.toggle('on',k==n)})}
function workersLbl(nm,cpus){var s=T('workers_lbl_node').replace(/\\{n\\}/g,function(){return nm||''});
 return num(cpus)?s+' · '+T('workers_lbl_cores').replace(/\\{c\\}/g,function(){return String(num(cpus))}):s}
function workersLbls(idp,a,b,srv){
 [['a',a],['b',b]].forEach(function(x){var e=el(idp+'wklbl_'+x[0]);if(!e)return;
  e.textContent=workersLbl(x[1][0],x[1][1])});
 [['a',a],['b',b]].forEach(function(x){var w=el(idp+'wkone_'+x[0]);if(w)w.style.order=(x[0]==srv)?0:1})}
function workersVis(idp,S,a,b){var on=wkCarrier(S);
 if(!on){S.WorkersA=1;S.WorkersB=1}
 var w=el(idp+'wrkrow');if(w)w.style.display=on?'':'none';
 workersPaint(idp,'a',S.WorkersA);workersPaint(idp,'b',S.WorkersB);
 workersLbls(idp,a,b,S.Srv=='b'?'b':'a');
 if(on){trFade(el(idp+'wkg_a'));trFade(el(idp+'wkg_b'))}}
function sportPaint(idp,on){var g=el(idp+'spg');if(!g)return;
 var f=el(idp+'sp_fix'),r=el(idp+'sp_rnd');
 if(f)f.classList.toggle('on',!on); if(r)r.classList.toggle('on',!!on)
 var w=el(idp+'spfix');if(w)w.style.display=on?'none':'';
 var i=el(idp+'rawsport');
 if(i){if(on)i.value='';else if(!i.value)i.value=String(RAW_SPORT_FIX)}
 sportPresetPaint(idp)}
function sportPresetPaint(idp){var g=el(idp+'spg2');if(!g)return;var i=el(idp+'rawsport');
 var n=parseInt((i&&i.value)||'',10);
 Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id==idp+'sp_'+n)})}
function sportErr(idp){var e=el(idp+'rawsport');if(!e)return '';
 var s=(e.value||'').trim();if(!s)return '';
 var n=parseInt(s,10);return (n>=1&&n<=65535)?'':T('raw_sport_bad')}
function portErr(idp){var e=el(idp+'rawport');if(!e)return '';
 var s=(e.value||'').trim();if(!s)return '';
 var n=parseInt(s,10);return (n>=1&&n<=65535)?'':T('raw_port_bad')}
function rawProtoOwner(n){var m=_ENUMS.raw_protos;for(var k in m){if(m[k]===n)return k}return ''}
function protoWarnUpd(idp,val){var n=parseInt(val,10);var g=el(idp+'ppg');
 if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id==idp+'pp_'+n)});
 var w=el(idp+'protowarn');if(!w)return;
 var own=rawProtoOwner(n),h=own?(ic('warn')+'<span>'+esc(T('raw_proto_owned').replace('{n}',n).replace(/\\{p\\}/g,own))+'</span>'):'';
 w.innerHTML=h;w.style.display=h?'':'none'}
function rawProtoErr(idp){var e=el(idp+'rawproto');if(!e)return '';
 var s=(e.value||'').trim();if(!s)return '';
 var n=parseInt(s,10);
 if(!(n>=1&&n<=255))return T('raw_proto_bad');
 var own=rawProtoOwner(n);
 return own?T('raw_proto_owned').replace('{n}',n).replace(/\\{p\\}/g,own):''}
function FEC_RATES(){return [{d:20,p:2,n:T('fec_light'),ov:T('fec_ov10')},{d:16,p:4,n:T('fec_balanced'),ov:T('fec_ov25')},{d:8,p:4,n:T('fec_strong'),ov:T('fec_ov50')}]}

function fecSection(idp,fnp,fec,fd,fp,dg){return '<div id="'+idp+'fecrow" class="tglbox" style="margin-top:11px'+(dg?'':';display:none')+'"><div class="tglsw'+(fec&&dg?' on':'')+'" id="'+idp+'fecsw" onclick="'+fnp+'ToggleFec()"></div><div class="tt"><b>'+esc(T('fec_t'))+'</b><small>'+esc(T('fec_d'))+'</small></div></div>'
 +'<div id="'+idp+'fecrates" style="'+(fec?'':'display:none')+'"><label>'+esc(T('fec_rate_lbl'))+'</label><div class="pgrid">'+FEC_RATES().map(function(r){var sel=(r.d==(fd||16)&&r.p==(fp||4));return '<button type="button" class="ptile'+(sel?' on':'')+'" data-fd="'+r.d+'" data-fp="'+r.p+'" data-ha="'+r.d+'" data-hb="'+r.p+'" onclick="'+fnp+'SetFecRate(+hA(this),+hB(this))"><div class="pn">'+r.d+'+'+r.p+'</div><div class="pmeta">'+esc(r.n)+'</div><div class="pmeta" style="color:var(--gold)">'+esc(r.ov)+'</div></button>'}).join('')+'</div><div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+esc(T('fec_note'))+'</div></div>'}
function DS_MODES(){return [{v:'ttl',t:T('ds_m_ttl_t'),s:T('ds_m_ttl_s')},{v:'badsum',t:T('ds_m_bad_t'),s:T('ds_m_bad_s')},{v:'both',t:T('ds_m_both_t'),s:T('ds_m_both_s')}]}
function desyncSection(idp,fnp,on,ttl,count,mode,show){return '<div id="'+idp+'dsrow" class="tglbox" style="margin-top:11px'+(show?'':';display:none')+'"><div class="tglsw'+(on&&show?' on':'')+'" id="'+idp+'dssw" onclick="'+fnp+'ToggleDesync()"></div><div class="tt"><b>'+esc(T('ds_t'))+'</b><small>'+esc(T('ds_d'))+'</small></div></div>'
 +'<div id="'+idp+'dsbody" style="'+(on&&show?'':'display:none')+'"><label>'+esc(T('ds_mode_lbl'))+'</label><div class="seg2" id="'+idp+'dsmodeseg">'+DS_MODES().map(function(m){return '<button type="button" class="segopt'+(m.v==(mode||'ttl')?' on':'')+'" id="'+idp+'dsm_'+m.v+'" data-ha="'+esc(m.v)+'" onclick="'+fnp+'SetDesyncMode(hA(this))"><b>'+esc(m.t)+'</b><span>'+esc(m.s)+'</span></button>'}).join('')+'</div>'
 +'<div class="grid2"><div><label>'+esc(T('ds_ttl_lbl'))+'</label><input id="'+idp+'dsttl" dir="ltr" inputmode="numeric" value="'+(ttl||4)+'"></div><div><label>'+esc(T('ds_count_lbl'))+'</label><input id="'+idp+'dscount" dir="ltr" inputmode="numeric" value="'+(count||2)+'"></div></div>'
 +'<div class="warncap no" id="'+idp+'dsttlcap" style="display:none;margin-top:8px">'+ic('warn')+'<span>'+esc(T('ds_ttl_cap'))+'</span></div>'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:6px">'+esc(T('ds_note'))+'</div></div>'}
function corToggleDesync(){_corS.Desync=!_corS.Desync;var s=el('e_dssw');if(s)s.classList.toggle('on',_corS.Desync);var b=el('e_dsbody');if(b)b.style.display=_corS.Desync?'':'none'}
function corSetDesyncMode(m){_corS.DesyncMode=m;var g=el('e_dsmodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_dsm_'+m)})}
function desyncOk(S){return S.Tr=='raw'||S.Tr=='tcp'||(S.Tr=='ws'&&S.Cdn=='ws')}
function desyncInjects(S){return S.Tr=='tcp'||(S.Tr=='ws'&&S.Cdn=='ws')}
function desyncTtlCap(idp,S){var cap=el(idp+'dsttlcap'),inj=desyncInjects(S);if(cap)cap.style.display=inj?'':'none';
 var t=el(idp+'dsttl');if(t&&inj){var n=parseInt(t.value,10);if(n>8)t.value='8'}}
function corDesyncGate(){var dg=desyncOk(_corS),row=el('e_dsrow');if(!dg){_corS.Desync=false;var s=el('e_dssw');if(s)s.classList.remove('on');var b=el('e_dsbody');if(b)b.style.display='none'}if(row)row.style.display=dg?'':'none';desyncTtlCap('e_',_corS)}
function ceToggleDesync(){_eeS.Desync=!_eeS.Desync;var s=el('ee_dssw');if(s)s.classList.toggle('on',_eeS.Desync);var b=el('ee_dsbody');if(b)b.style.display=_eeS.Desync?'':'none'}
function ceSetDesyncMode(m){_eeS.DesyncMode=m;var g=el('ee_dsmodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_dsm_'+m)})}
function ceDesyncGate(){var dg=desyncOk(_eeS),row=el('ee_dsrow');if(!dg){_eeS.Desync=false;var s=el('ee_dssw');if(s)s.classList.remove('on');var b=el('ee_dsbody');if(b)b.style.display='none'}if(row)row.style.display=dg?'':'none';desyncTtlCap('ee_',_eeS)}
function wsToggleRows(idp,fnp,tls,ech,echproxy,echproxyurl,sni,pos,mode,ttl,show){var hide=show?'':';display:none';var pxhide=(ech&&show)?'':';display:none';var pxfhide=(echproxy&&ech&&show)?'':';display:none';
 return '<div class="tglbox" id="'+idp+'wstlsrow" style="margin-top:10px'+hide+'"><div class="tglsw'+(tls?' on':'')+'" id="'+idp+'wstls" onclick="'+fnp+'ToggleWsTls()"></div><div class="tt"><b>'+esc(T('wstls_t'))+'</b><small>'+esc(T('wstls_d'))+'</small></div></div>'
  +'<div class="tglbox" id="'+idp+'wsechrow" style="margin-top:9px'+hide+'"><div class="tglsw'+(ech?' on':'')+'" id="'+idp+'wsech" onclick="'+fnp+'ToggleEch()"></div><div class="tt"><b>'+esc(T('ech_t'))+'</b><small>'+esc(T('ech_d'))+'</small></div></div>'
  +'<div class="tglbox" id="'+idp+'echpxrow" style="margin-top:9px'+pxhide+'"><div class="tglsw'+(echproxy?' on':'')+'" id="'+idp+'echpx" onclick="'+fnp+'ToggleEchProxy()"></div><div class="tt"><b>'+esc(T('echpx_t'))+'</b><small>'+esc(T('echpx_d'))+'</small></div></div>'
  +'<div id="'+idp+'echpxbody" style="margin-top:6px'+pxfhide+'"><input id="'+idp+'echproxyurl" dir="ltr" placeholder="socks5://host:1080  |  http://user:pass@host:8080" value="'+esc(echproxyurl||'')+'"></div>'
  +'<div class="tglbox" id="'+idp+'snisplitrow" style="margin-top:9px'+hide+'"><div class="tglsw'+(sni?' on':'')+'" id="'+idp+'snisplit" onclick="'+fnp+'ToggleSni()"></div><div class="tt"><b>'+esc(T('sni_t'))+'</b><small>'+esc(T('sni_d'))+'</small></div></div>'
  +'<div id="'+idp+'snisplitbody" style="margin-top:6px'+((sni&&show)?'':';display:none')+'"><label>'+esc(T('sni_pos_lbl'))+'</label><input id="'+idp+'snisplitpos" type="number" min="0" max="1400" value="'+(pos||0)+'">'
  +'<label style="margin-top:10px;display:block">'+esc(T('sni_mode_lbl'))+'</label><div class="seg2" id="'+idp+'snimodeseg">'+SNI_MODES().map(function(m){return '<button type="button" class="segopt'+(m.v==(mode||'split')?' on':'')+'" id="'+idp+'snim_'+m.v+'" data-ha="'+esc(m.v)+'" onclick="'+fnp+'SetSniMode(hA(this))"><b>'+esc(m.v)+'</b><span>'+esc(m.s)+'</span></button>'}).join('')+'</div>'
  +'<div id="'+idp+'snittlbody" style="margin-top:6px'+((mode=='disorder')?'':';display:none')+'"><label>'+esc(T('sni_ttl_lbl'))+'</label><input id="'+idp+'splitttl" type="number" min="0" max="__SPLITTTLMAX__" value="'+(ttl||0)+'"></div></div>';}
function SNI_MODES(){return [{v:'split',s:T('m_split_s')},{v:'disorder',s:T('m_dis_s')},{v:'fake',s:T('m_fake_s')}]}
function wsSection(idp,fnp,host,path,tls,edge,ech,cdn,lid,shape){return '<div id="'+idp+'wsblk" style="display:none">'
 +'<label>'+esc(T('ws_prof_lbl'))+'</label><div class="pgrid p3" id="'+idp+'wspg">'+wsProfTiles(fnp,wsProfOf({Cdn:cdn}))+'</div>'
 +'<div class="warncap no" id="'+idp+'grpczone" style="display:none;margin-top:8px">'+ic('warn')+'<span>'+esc(T('grpc_zone_warn'))+'</span></div>'
 +'<div id="'+idp+'cdnprow" style="display:none;margin-bottom:8px"><label style="margin-top:2px">'+esc(T('cdn_shape_lbl'))+'</label>'
 +'<div style="display:flex;gap:8px">'+cdnShapeInputs(idp,shape)+'</div>'
 +'</div>'
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
 var sel=ssHTML(idp+'poolrot',rotOpts.map(function(o){return {v:o[0],label:o[1]}}),poolGet(idp).rotate,T('rot_int_lbl'));
 function block(kind,label,ph){
   return '<div class="pacc"><div class="pacchd" data-acc role="button" tabindex="0" data-ha="'+esc(idp)+'" data-hb="'+esc(kind)+'" onclick="poolAcc(hA(this),hB(this))">'
     +'<div class="pacctl"><div class="pacct">'+label+'</div><div class="paccs" id="'+idp+'hd_'+kind+'"></div></div>'
     +'<div style="display:flex;align-items:center;gap:8px"><div class="pchev open" id="'+idp+'chev_'+kind+'">&#9662;</div></div></div>'
     +'<div class="paccbody" id="'+idp+'body_'+kind+'">'
     +'<div id="'+idp+'lst_'+kind+'" style="display:flex;flex-direction:column;gap:6px"></div>'
     +'<div style="display:flex;gap:6px;margin-top:8px"><input id="'+idp+'add_'+kind+'" class="mono" dir="ltr" style="flex:1;text-align:left" placeholder="'+ph+'"><button type="button" data-ha="'+esc(idp)+'" data-hb="'+esc(kind)+'" onclick="poolAdd(hA(this),hB(this))" style="background:var(--acc);color:#fff;border:none;border-radius:9px;min-width:42px;font-size:18px;cursor:pointer">+</button></div>'
     +'</div></div>';}
 return '<div class="warncap no" id="'+idp+'poolstale" style="display:none;margin-bottom:8px"></div>'
   +block('ip',T('pool_ip_lbl'),'104.16.0.1:443')
   +block('sni',T('pool_sni_lbl'),'cdn.example.com')
   +'<label style="margin-top:14px">'+esc(T('rot_int_lbl'))+'</label>'+sel;}


function corRawVis(){var w=el('e_rawblk');if(w)w.style.display=(_corS.Tr=='raw')?'':'none'}
function corPortTriesVis(){portTriesVis('e_',_corS)}
function corDnsVis(){var w=el('e_dnsblk');if(w)w.style.display=(_corS.Tr=='dns')?'':'none'}
function trFade(bar){if(!bar)return;var w=bar.parentNode;if(!w)return;w.classList.toggle('atend',Math.abs(bar.scrollLeft)+bar.clientWidth>=bar.scrollWidth-4)}
function corPortGate(){var p=el('e_port');if(!p)return;var np=(_corS.Tr=='raw'||_corS.Tr=='dns');var w=el('e_coreportrow');if(w)w.style.display=np?'none':'';if(np){p.value='';return}if(_corS.Tr=='ws'){if(!p.value)p.value='80';p.placeholder=T('port_ws_ph');return}if(p.value=='80')p.value='';p.placeholder=T('port_band_ph');corPortDraw()}
async function corPortDraw(){var p=el('e_port');if(!p||p.value)return;
 var r=await j('next-port').catch(function(){return null});
 var q=el('e_port');if(q&&!q.value&&r&&r.ok&&r.port)q.value=String(r.port)}
function dnsSection(idp,fnp){return '<div id="'+idp+'dnsblk" style="display:none">'
 +'<label class="first">'+esc(T('dns_zone_lbl'))+'</label>'
 +'<input id="'+idp+'dnszone" class="mono" placeholder="t.example.com" style="direction:ltr">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:5px">'+T('dns_zone_note')+'</div>'
 +'<label>'+esc(T('dns_resolvers_lbl'))+'</label>'
 +'<input id="'+idp+'dnsresolvers" class="mono" placeholder="10.202.10.202, 10.202.10.102" style="direction:ltr">'
 +'<div class="muted" style="font-size:11px;line-height:1.7;margin-top:5px">'+T('dns_resolvers_note')+'</div>'
 +'<div class="autonote" style="margin-top:11px">'+ic('warn')+'<span>'+T('dns_delegation_note')+'</span></div></div>'}
function corSetProfile(p){_corS.RawProfile=p;var g=el('e_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});corProtoVis();corPortVis();corPortTriesVis()}
function corSetProto(val){var i=el('e_rawproto');if(i)i.value=val;protoWarnUpd('e_',val)}
function corProtoWarn(){var i=el('e_rawproto');if(i)protoWarnUpd('e_',i.value)}
function protoVisOn(S){return S.Tr=='raw'&&S.RawProfile=='bare'}
function corSetPort(v){var i=el('e_rawport');if(i)i.value=v;corPortWarn()}
function corSetSport(on){if(sprotLive(_corS))return;_corS.SportRandom=!!on;sportPaint('e_',_corS.SportRandom);corPortTriesVis();bandVis('e_',_corS)}
function corSetSportPort(n){if(sprotLive(_corS))return;var i=el('e_rawsport');if(i)i.value=n;sportPresetPaint('e_')}
function corSportWarn(){sportPresetPaint('e_')}
function corPortWarn(){var i=el('e_rawport');if(!i)return;var n=parseInt(i.value,10),g=el('e_rpg');
 if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='e_rp_'+n)})}
function corPortVis(){var w=el('e_portrow');if(!w)return;
 var on=(_corS.Tr=='raw'&&(_corS.RawProfile=='udp'||_corS.RawProfile=='tcp'));w.style.display=on?'':'none';
 if(on){var i=el('e_rawport');if(i&&!i.value)i.value='443';corPortWarn();sportPaint('e_',_corS.SportRandom)}
 sprotVis('e_',_corS);ctbVis('e_',_corS)}
function corSprotWarn(){sprotWarnUpd('e_',_corS)}
function ceSprotWarn(){sprotWarnUpd('ee_',_eeS)}
function corToggleSprot(){sprotToggle('e_',_corS);corFecGate()}
function corToggleCtb(){ctbToggle('e_',_corS)}
function ceToggleCtb(){ctbToggle('ee_',_eeS)}
function ceToggleSprot(){sprotToggle('ee_',_eeS);ceFecGate()}
function corSetWorkers(sd,n){_corS[sd=='a'?'WorkersA':'WorkersB']=n;workersPaint('e_',sd,n)}
function corWorkersVis(){var a=ssVal('e_a'),b=ssVal('e_b');
 workersVis('e_',_corS,[nodeName(a),nodeCpus(a)],[nodeName(b),nodeCpus(b)])}
function corProtoVis(){var w=el('e_protorow');if(!w)return;var show=protoVisOn(_corS);w.style.display=show?'':'none';if(show){var i=el('e_rawproto');if(i&&!i.value)i.value='253';corProtoWarn()}}
function corToggleGso(){_corS.Gso=!_corS.Gso;var s=el('e_gso');if(s)s.classList.toggle('on',_corS.Gso)}
function corToggleObfs(){if(ssVal('e_cipher')=='none')return;_corS.Obfs=!_corS.Obfs;var s=el('e_obfs');if(s)s.classList.toggle('on',_corS.Obfs)}
function corToggleCover(){if(_corS.Tr!='tcp')return;_corS.Cover=!_corS.Cover;var s=el('e_cover');if(s)s.classList.toggle('on',_corS.Cover);corSniVis()}
function corSniVis(){var w=el('e_snirow');if(w)w.style.display=(_corS.Cover&&_corS.Tr=='tcp')?'':'none'}
function corCoverGate(){var ok=_corS.Tr=='tcp'&&ssVal('e_cipher')!='none',row=el('e_coverrow'),s=el('e_cover');if(!ok){_corS.Cover=false;if(s)s.classList.remove('on')}if(row)row.style.display=ok?'':'none';corSniVis()}
function _obfsGate(px,S){var off=ssVal(px+'cipher')=='none'||S.Tr=='dns',row=el(px+'obfsrow'),s=el(px+'obfs');
 if(off){S.Obfs=false;if(s)s.classList.remove('on')}if(row)row.style.display=off?'none':''}
function onCorCipher(){_obfsGate('e_',_corS);corCoverGate()}
async function openCoreModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(on.length<2){toast(T('node_min2'),'err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});_corS.Srv='a';_corS.Tr='udp';_corS.Obfs=true;_corS.Cover=false;_corS.RawProfile='bare';_corS.SportRandom=false;_corS.Sprot=false;_corS.Gso=false;_corS.WsTls=false;_corS.Ech=false;_corS.EchProxy=false;_corS.SniSplit=false;_corS.SplitPos=0;_corS.SniMode='split';_corS.SplitTtl=0;_corS.Cdn='ws';_corS.Fec=false;_corS.FecData=16;_corS.FecParity=4;_corS.Desync=false;_corS.DesyncTtl=4;_corS.DesyncCount=2;_corS.DesyncMode='ttl';_corS.WorkersA=1;_corS.WorkersB=1;_eeS.PoolLid='';_peerLid='';_rotS['e_']={on:false,secs:600,aIps:[],bIps:[],aSel:{},bSel:{}};poolInit('e_',null);
 var _t1='<div class="ctabp on" data-cp="ip"><div class="grid2"><div id="e_awrap"><label class="first" id="e_alab"></label>'+ssHTML('e_a',items,items[0].v,T('srv_node'),'onCorNode')+'</div>'+
  '<div id="e_bwrap"><label class="first" id="e_blab"></label>'+ssHTML('e_b',items,items[1].v,T('cli_node'),'onCorNode')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="e_aip"></div><div id="e_bip"></div></div>'+
  '<div id="e_rotrow"></div>'+rotSetHTML('e_')+
  '<label>'+esc(T('roles_lbl'))+'</label><div class="seg2" id="e_roles"><button type="button" class="segopt on" id="e_srv_a" onclick="corSetSrv(\\'a\\')"></button><button type="button" class="segopt" id="e_srv_b" onclick="corSetSrv(\\'b\\')"></button></div></div>';
 var _t2='<div class="ctabp" data-cp="set"><label>'+esc(T('enc_method_lbl'))+'</label>'+ssHTML('e_cipher',CORE_CIPHERS(),'auto',T('cipher_ph'),'onCorCipher')+
  '<label>'+esc(T('transport_lbl'))+'</label><div class="trwrap" id="e_trwrap"><div class="seg2 trbar" id="e_trbar" onscroll="trFade(this)"><button type="button" class="segopt on" id="e_tr_udp" onclick="corSetTr(\\'udp\\')"><b>UDP</b><span>'+esc(T('tr_udp_d'))+'</span></button><button type="button" class="segopt" id="e_tr_tcp" onclick="corSetTr(\\'tcp\\')"><b>TCP</b><span>'+esc(T('tr_tcp_d'))+'</span></button><button type="button" class="segopt" id="e_tr_raw" onclick="corSetTr(\\'raw\\')"><b>RAW</b><span>'+esc(T('tr_raw_d'))+'</span></button><button type="button" class="segopt" id="e_tr_ws" onclick="corSetTr(\\'ws\\')"><b>CDN</b><span>'+esc(T('tr_ws_d'))+'</span></button><button type="button" class="segopt" id="e_tr_dns" onclick="corSetTr(\\'dns\\')"><b>DNS</b><span>'+esc(T('tr_dns_d'))+'</span></button></div></div>'+
  '<div id="e_rawblk" style="display:none"><label>'+esc(T('raw_prof_lbl'))+'</label><div class="pgrid" id="e_pg">'+rawTiles('cor','bare')+'</div>'+protoSection('e_','cor')+portSection('e_','cor')+'</div>'+
  portTriesSection('e_')+
  workersSection('e_','cor')+
  wsSection('e_','cor','','',false,'',false,'ws','',null)+
  dnsSection('e_','cor')+
  '<div class="tglbox" id="e_obfsrow"><div class="tglsw'+(_corS.Obfs?' on':'')+'" id="e_obfs" onclick="corToggleObfs()"></div><div class="tt"><b>'+esc(T('obfs_t'))+'</b><small>'+esc(T('obfs_d'))+'</small></div></div>'+
  '<div class="tglbox" id="e_coverrow" style="display:none"><div class="tglsw" id="e_cover" onclick="corToggleCover()"></div><div class="tt"><b>'+esc(T('cover_t'))+'</b><small>'+esc(T('cover_d'))+'</small></div></div>'+
  wsToggleRows('e_','cor',false,false,false,'',false,0,'split',0,false)+
  '<div id="e_snirow" style="display:none"><label>'+esc(T('cover_sni_lbl'))+'</label><input id="e_sni" placeholder="'+esc(T('cover_sni_ph'))+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+T('cover_sni_note1')+'</div></div>'+
  '<div class="tglbox" id="e_gsorow"><div class="tglsw" id="e_gso" onclick="corToggleGso()"></div><div class="tt"><b>'+esc(T('gso_t'))+'</b><small>'+esc(T('gso_d'))+'</small></div></div>'+
  fecSection('e_','cor',_corS.Fec,_corS.FecData,_corS.FecParity,corFecDatagram())+
  desyncSection('e_','cor',false,4,2,'ttl',false)+
  '<label>'+esc(T('core_range_lbl'))+'</label>'+ssHTML('e_snr',SUBNETRANGES(),'192.168',T('range'),'onCorSubRange')+'<div id="e_snc"></div>'+
  '<div id="e_coreportrow"><label>'+esc(rng(T('core_port_lbl'),1,PORT_MAX))+'</label><input id="e_port" inputmode="numeric" placeholder="'+esc(T('port_band_ph'))+'"></div></div>';
 var b=corTabsHTML()+_t1+_t2+'<div class="msg" id="e_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic(COR_IC)+'</span><div class="ttl"><h3>'+esc(T('core_tun_t'))+'</h3><div class="sb">'+esc(T('core_tun_sub'))+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doCreateCore()">'+esc(T('create_tun_btn'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 corRoleLbls();renderCorIps();corRotVis();corCoverGate();corPortGate();corPortTriesVis();corDesyncGate();corCdnShapeGate();corWorkersVis();trFade(el('e_trbar'))}
function onCorNode(){corRotVis('e_');corRoleLbls();corWorkersVis()}   
function renderCorIps(){renderRotIps('e_')}
var _rotS={};
function rotSt(px){if(!_rotS[px])_rotS[px]={on:false,aIps:[],bIps:[],aSel:{},bSel:{}};return _rotS[px]}
function corTabsHTML(){return '<div class="ctabs"><button type="button" class="ctab on" data-ct="ip" onclick="corTab(this,\\'ip\\')">'+ic('pin')+esc(T('cor_tab_ips'))+'</button><button type="button" class="ctab" data-ct="set" onclick="corTab(this,\\'set\\')">'+ic('cog')+esc(T('cor_tab_set'))+'</button></div>'}
function corTab(btn,which){var box=btn.closest('.mbody');if(!box)return;Array.prototype.forEach.call(box.querySelectorAll('.ctab'),function(t){t.classList.toggle('on',t.getAttribute('data-ct')==which)});Array.prototype.forEach.call(box.querySelectorAll('.ctabp'),function(p){p.classList.toggle('on',p.getAttribute('data-cp')==which)});box.scrollTop=0;var _tb=box.querySelector('.trbar');if(_tb)trFade(_tb)}
var ROT_PRESETS=[180,300,600,900,1800,3600];
var ROT_LABELS={180:'rot_3m',300:'rot_5m',600:'rot_10m',900:'rot_15m',1800:'rot_30m',3600:'rot_1h'};
function rotSetHTML(px){var st=rotSt(px);
 var items=ROT_PRESETS.map(function(v){return {v:v,label:T(ROT_LABELS[v])}});
 items.push({v:0,label:T('rot_onfail')});
 return '<div id="'+px+'rotset" style="display:none;margin-top:2px"><label class="first">'+esc(T('rot_interval'))+'</label>'+
 ssHTML(px+'rotsecs',items,st.secs,T('rot_interval'))+'</div>'}
function rotTr(px){return px=='e_'?_corS.Tr:_eeS.Tr}
function rotIsDirect(px){return _ENUMS.tr_direct.indexOf(rotTr(px))>=0}
function rotRefreshIps(px){var st=rotSt(px);st.aIps=nodeIps(ssVal(px+'a'));st.bIps=nodeIps(ssVal(px+'b'))}
function rotFirstSel(px,side){var st=rotSt(px),ips=(side=='a')?st.aIps:st.bIps,sel=(side=='a')?st.aSel:st.bSel;
 for(var i=0;i<ips.length;i++){if(sel[ips[i]])return ips[i]}return ''}
function pickedIP(px,side,stored){var st=rotSt(px),ips=(side=='a')?st.aIps:st.bIps,sel=(side=='a')?st.aSel:st.bSel;
 if(st.on&&ips.length>1)return (stored&&sel[stored]&&stored)||rotFirstSel(px,side)||ips[0]||'';
 if(el('ssb_'+px+side+'ip_sel'))return ssVal(px+side+'ip_sel');
 return (stored&&ips.indexOf(stored)>=0)?stored:''}
function corRotVis(px){px=px||'e_';var st=rotSt(px);rotRefreshIps(px);var w=el(px+'rotrow');if(!w)return;
 var multi=(st.aIps.length>1||st.bIps.length>1)&&rotIsDirect(px);
 if(!multi){st.on=false;w.innerHTML='';var r0=el(px+'rotset');if(r0)r0.style.display='none';renderRotIps(px);return}
 w.innerHTML='<div class="tglbox" style="margin-top:12px"><div class="tglsw'+(st.on?' on':'')+'" id="'+px+'rotsw" data-ha="'+esc(px)+'" onclick="corToggleRot(hA(this))"></div><div class="tt"><b>'+esc(T('rot_t'))+'</b><small>'+esc(T('rot_d'))+'</small></div></div>';
 var rs=el(px+'rotset');if(rs)rs.style.display=st.on?'block':'none';renderRotIps(px)}
function corToggleRot(px){var st=rotSt(px);st.on=!st.on;var s=el(px+'rotsw');if(s)s.classList.toggle('on',st.on);var rs=el(px+'rotset');if(rs)rs.style.display=st.on?'block':'none';renderRotIps(px)}
function ceStoredIP(px,side){if(px!='ee_')return '';
 var l=(FLEET||[]).filter(function(x){return x.id==_eeS.Lid})[0];
 return (l&&(side=='a'?l.a_ip:l.b_ip))||''}
function ceSeedGate(px){if(px!='ee_')return;
 if(_eeS.IpLid===_eeS.Lid)return;
 delete SEL['ee_aip_sel'];delete SEL['ee_bip_sel'];_eeS.IpLid=_eeS.Lid}
function renderRotIps(px){ceSeedGate(px);var srv=(px=='e_')?_corS.Srv:_eeS.Srv;['a','b'].forEach(function(side){var w=el(px+side+'ip');if(!w)return;
 var st=rotSt(px),ips=(side=='a')?st.aIps:st.bIps,isDst=(side=='a')?(srv=='a'):(srv!='a'),lab=isDst?T('dst_ip'):T('src_ip');
 w.style.order=isDst?'0':'1';
 if(st.on&&ips.length>1)w.innerHTML=rotPoolHTML(px,side,ips,lab);
 else w.innerHTML=ipField(px+side+'ip_sel',ips,lab,ceStoredIP(px,side))})}
function rotPoolHTML(px,side,ips,lab){var st=rotSt(px),sel=(side=='a')?st.aSel:st.bSel;
 var CKI='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><circle cx="12" cy="12" r="9"/><path d="M8.3 12.4l2.6 2.6 4.8-5.4" stroke-linecap="round" stroke-linejoin="round"/></svg>';
 var OFI='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/></svg>';
 var rows=ips.map(function(ip){var on=!!sel[ip];
  return '<div class="rrow'+(on?' on':'')+'" data-ha="'+esc(px)+'" data-hb="'+esc(side)+'" onclick="rotToggleIp(hA(this),hB(this),this)" data-ip="'+esc(ip)+'"><span class="sic">'+(on?CKI:OFI)+'</span><span class="rip">'+esc(ip)+'</span></div>'}).join('');
 return '<label class="first">'+lab+' <span style="color:var(--acc)">('+rotCount(px,side)+')</span></label><div class="rpool">'+rows+'</div>'}
function rotCount(px,side){var st=rotSt(px),sel=(side=='a')?st.aSel:st.bSel,ips=(side=='a')?st.aIps:st.bIps,n=0;ips.forEach(function(ip){if(sel[ip])n++});return n}
function rotToggleIp(px,side,row){var st=rotSt(px),sel=(side=='a')?st.aSel:st.bSel,ip=row.getAttribute('data-ip');
 if(sel[ip]){if(rotCount(px,side)<=2){toast(T('rot_min2'),'err');return}delete sel[ip]}else sel[ip]=true;  
 renderRotIps(px)}
function rotCollect(px){var st=rotSt(px);if(!st.on)return null;
 function pool(side){var ips=(side=='a')?st.aIps:st.bIps,sel=(side=='a')?st.aSel:st.bSel,out=[];ips.forEach(function(ip){if(sel[ip])out.push(ip)});return out}
 var ap=pool('a'),bp=pool('b');if(ap.length<2&&bp.length<2)return null;
 var secs=parseInt(ssVal(px+'rotsecs'))||0;
 return {ip_rotate:true,a_ip_pool:ap,b_ip_pool:bp,rotate_secs:secs,a_ip:ap[0]||'',b_ip:bp[0]||''}}
function rotValidate(px){var st=rotSt(px);if(!st.on)return null;
 if(rotCount(px,'a')<2&&rotCount(px,'b')<2)return T('rot_min2');   
 return null}
function onCorSubRange(){var w=el('e_snc');if(!w)return;w.innerHTML=(ssVal('e_snr')=='custom')?'<label>'+esc(T('custom_subnet'))+'</label><input id="e_subnet" placeholder="'+esc(T('ph_subnet'))+'">':''}
function onCeSubRange(){var w=el('ee_snc');if(!w)return;
 var l=(FLEET||[]).filter(function(x){return x.id==_eeS.Lid})[0]||{},r=ssVal('ee_snr');
 if(r=='custom'){w.innerHTML='<label>'+esc(T('custom_subnet'))+'</label><input id="ee_subnet" class="mono" value="'+esc(l.subnet||'')+'">';return}
 w.innerHTML='<div class="muted" style="font-size:11px;margin:6px 2px 0">'+esc(T('core_subnet_lbl'))+': <b class="mono">'+esc(subnetForBase(l.type,l.tunnel_id,r)||'—')+'</b></div>'}
function corRoleLbls(){var an=nodeName(ssVal('e_a')),bn=nodeName(ssVal('e_b')),a=el('e_srv_a'),b=el('e_srv_b');
 if(a)a.innerHTML='<b>'+esc(an)+' '+esc(T('role_server_word'))+'</b><span>'+esc(bn)+' '+esc(T('role_client_word'))+'</span>';
 if(b)b.innerHTML='<b>'+esc(bn)+' '+esc(T('role_server_word'))+'</b><span>'+esc(an)+' '+esc(T('role_client_word'))+'</span>';
 corNodeLbls()}
function corNodeLbls(){var srvA=(_corS.Srv=='a'),la=el('e_alab'),lb=el('e_blab');
 if(la)la.textContent=srvA?T('srv_node'):T('cli_node');
 if(lb)lb.textContent=srvA?T('cli_node'):T('srv_node');
 var A=el('e_awrap'),B=el('e_bwrap');
 if(A)A.style.order=srvA?'0':'1';
 if(B)B.style.order=srvA?'1':'0'}
function corSetSrv(s){_corS.Srv=s;var a=el('e_srv_a'),b=el('e_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b');corNodeLbls();renderRotIps('e_')}
function _collectCoreBody(S,px,m,body){
 if(S.Tr=='raw'){if(ssVal(px+'cipher')=='none'){formErr(m,T('raw_need_enc'));return true}body.raw_profile=S.RawProfile;if(S.RawProfile=='bare'){var _pe=rawProtoErr(px);if(_pe){formErr(m,_pe);return true}var _rp=parseInt(v(px+'rawproto')||'253',10);body.raw_proto=_rp}
  var _sre=sprotErr(px,S);if(_sre){formErr(m,_sre);return true}
  if(bandOn(S)){var _be=bandErr(px);if(_be){formErr(m,_be);return true}}
  body.raw_sport_rotate=sprotLive(S)?sprotN(px):0;
  body.raw_dports=sprotLive(S)?dportsN(px):0;
  body.raw_sport_lo=bandOn(S)?bandN(px,'bandlo'):0;
  body.raw_sport_hi=bandOn(S)?bandN(px,'bandhi'):0;
  body.conntrack_bypass=ctbOn(S)&&!!S.Ctb;
  if(S.RawProfile=='udp'||S.RawProfile=='tcp'){var _po=portErr(px);if(_po){formErr(m,_po);return true}
   var _rt=parseInt(v(px+'rawport'),10);if(_rt>=1&&_rt<=65535)body.raw_port=_rt
   if(body.raw_sport_rotate){body.raw_sport_random=false;body.raw_sport=0}
   else{var _se=sportErr(px);if(_se){formErr(m,_se);return true}
    body.raw_sport_random=!!S.SportRandom;
    var _st=parseInt(v(px+'rawsport'),10);
    body.raw_sport=(!S.SportRandom&&_st>=1&&_st<=65535)?_st:0}}}
 var _pte=portTriesErr(px,S);if(_pte){formErr(m,_pte);return true}
 if(portTriesOn(S)){body.port_tries=portTriesN(px)}
 if(S.Tr=='dns'){if(ssVal(px+'cipher')=='none'){formErr(m,T('dns_need_enc'));return true}var _dz=(v(px+'dnszone')||'').trim().toLowerCase();if(!_dz){formErr(m,T('dns_need_zone'));return true}var _dr=(v(px+'dnsresolvers')||'').split(/[\\s,]+/).filter(Boolean);if(!_dr.length){formErr(m,T('dns_need_resolvers'));return true}body.dns_zone=_dz;body.dns_resolvers=_dr}
 if(fecDatagram(S)){body.fec=!!S.Fec;if(body.fec){body.fec_data=S.FecData;body.fec_parity=S.FecParity}}
 if(wkCarrier(S)){body.a_workers=wkClamp(S.WorkersA);body.b_workers=wkClamp(S.WorkersB)}
 if(desyncOk(S)){body.fake_desync=S.Desync;if(S.Desync){body.fake_ttl=parseInt(v(px+'dsttl'))||4;body.fake_count=parseInt(v(px+'dscount'))||2;body.fake_mode=S.DesyncMode;
  if(body.fake_mode=='both'&&body.fake_count<2){formErr(m,T('ds_both_needs2'));return true}}}
 if(S.Tr=='ws'){body.ws_path=(v(px+'wspath')||'').trim();body.ws_tls=S.WsTls;body.ech=S.Ech;body.ech_proxy=(S.Ech&&S.EchProxy);if(S.Ech&&S.EchProxy)body.ech_proxy_url=(v(px+'echproxyurl')||'').trim();body.sni_split=S.SniSplit;if(S.SniSplit){body.split_pos=parseInt(v(px+'snisplitpos'))||0;body.sni_mode=S.SniMode;if(S.SniMode=='disorder')body.split_ttl=parseInt(v(px+'splitttl'))||0;}body.cdn_carrier=S.Cdn;if(S.Cdn=='http'||S.Cdn=='grpc')cdnShapeBody(px,body,S.Cdn);if(poolGet(px+'').pool){var pe=poolCollect(px+'',body);if(pe!==true){formErr(m,pe);return true}}else{body.ws_pool=false;body.ws_host=(v(px+'wshost')||'').trim();body.edge_ip=(v(px+'wsedge')||'').trim();if(S.WsTls&&!body.ws_host){formErr(m,T('wss_need_host'));return true}if(S.Ech&&!S.WsTls){formErr(m,T('ech_need_wss'));return true}if(S.Cdn=='grpc'&&!S.WsTls){formErr(m,T('cdn_need_wss'));return true}}}
 return false}
async function doCreateCore(){var m=el('e_msg');m.className='msg';var a=ssVal('e_a'),bb=ssVal('e_b');
 if(a==bb){formErr(m,T('two_diff_nodes'));return}
 var body={a_node:a,b_node:bb,type:'core',server_side:_corS.Srv,cipher:ssVal('e_cipher'),transport:_corS.Tr,obfs:_corS.Obfs,cover:(_corS.Cover&&_corS.Tr=='tcp'),gso:_corS.Gso};
 if(_collectCoreBody(_corS,'e_',m,body))return;
 if(body.cover){var sni=(v('e_sni')||'').trim();if(!sni){formErr(m,T('cover_need_sni'));return}body.cover_sni=sni}
 var _rverr=rotValidate('e_');if(_rverr){formErr(m,_rverr);return}
 var aip=pickedIP('e_','a','');if(aip)body.a_ip=aip;
 var bare=pickedIP('e_','b','');if(bare)body.b_ip=bare;
 var _rc=rotCollect('e_');if(_rc){body.ip_rotate=true;body.a_ip_pool=_rc.a_ip_pool;body.b_ip_pool=_rc.b_ip_pool;body.rotate_secs=_rc.rotate_secs}
 var range=ssVal('e_snr');if(range=='custom'){var sub=v('e_subnet');if(sub)body.subnet=sub}else{body.subnet_base=range}
 var port=v('e_port');if(port)body.port=port;
 m.textContent=T('creating_core');
 var r=await post('create-tunnel',body);
 if(!(r.ok&&r.d.act)){formErr(m,perr(r));return}
 var vr=await actAccepted(r.d.act,m);
 if(vr.gone)return;
 if(vr.err){formErr(m,vr.err);return}
 closeModal(m.closest('.modalov'));refreshCore()}
_eeS.Srv='a',_eeS.Tr='udp',_eeS.Obfs=false,_eeS.Cover=false,_eeS.RawProfile='bare',_eeS.Sprot=false,_eeS.Gso=false,_eeS.WsTls=false,_eeS.Ech=false,_eeS.EchProxy=false,_eeS.Cdn='ws',_eeS.Fec=false,_eeS.FecData=16,_eeS.FecParity=4,_eeS.Desync=false,_eeS.DesyncTtl=4,_eeS.DesyncCount=2,_eeS.DesyncMode='ttl',_eeS.SniSplit=false,_eeS.SplitPos=0,_eeS.SniMode='split',_eeS.SplitTtl=0;
function ceApplyGates(){ceRawVis();ceDnsVis();ceWsVis();cePortGate();ceCoverGate();ceFecGate();ceProtoVis();cePortVis();cePortTriesVis();ceDesyncGate();ceCdnShapeGate();corRotVis('ee_');ceWorkersVis();onEeCipher()}   
function ceSetTr(t){_eeS.Tr=t;_ENUMS.tr_all.forEach(function(x){var b=el('ee_tr_'+x);if(b)b.classList.toggle('on',t==x)});ceApplyGates()}

function ceWsVis(){var ws=_eeS.Tr=='ws';var w=el('ee_wsblk');if(w)w.style.display=ws?'':'none';var t=el('ee_wstlsrow'),e=el('ee_wsechrow');if(t)t.style.display=ws?'':'none';if(e)e.style.display=ws?'':'none';var sr=el('ee_snisplitrow');if(sr)sr.style.display=ws?'':'none';var sb=el('ee_snisplitbody');if(sb)sb.style.display=(ws&&_eeS.SniSplit)?'':'none';ceEchPxGate();if(ws){poolVis('ee_');ceWssGate()}}
function ceToggleWsTls(){_eeS.WsTls=!_eeS.WsTls;var s=el('ee_wstls');if(s)s.classList.toggle('on',_eeS.WsTls);if(!_eeS.WsTls){if(_eeS.Ech){_eeS.Ech=false;var e=el('ee_wsech');if(e)e.classList.remove('on')}if(_eeS.SniSplit){_eeS.SniSplit=false;var q=el('ee_snisplit');if(q)q.classList.remove('on');var b=el('ee_snisplitbody');if(b)b.style.display='none'}}ceEchPxGate()}
function ceToggleSni(){if(!_eeS.WsTls){_eeS.SniSplit=false;var q=el('ee_snisplit');if(q)q.classList.remove('on');alert(T('sni_need_wss'));return}_eeS.SniSplit=!_eeS.SniSplit;var s=el('ee_snisplit');if(s)s.classList.toggle('on',_eeS.SniSplit);var b=el('ee_snisplitbody');if(b)b.style.display=_eeS.SniSplit?'':'none'}
function ceSetSniMode(m){_eeS.SniMode=m;var g=el('ee_snimodeseg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_snim_'+m)});var b=el('ee_snittlbody');if(b)b.style.display=(m=='disorder')?'':'none'}
function ceWssGate(){var mand=poolGet('ee_').pool||_eeS.Cdn=='grpc';var row=el('ee_wstlsrow'),s=el('ee_wstls');if(mand){_eeS.WsTls=true;if(s)s.classList.add('on');if(row)row.classList.add('dis')}else if(row)row.classList.remove('dis')}
function ceToggleEch(){if(!_eeS.WsTls){_eeS.Ech=false;var e=el('ee_wsech');if(e)e.classList.remove('on');ceEchPxGate();alert(T('ech_need_wss_alert'));return}_eeS.Ech=!_eeS.Ech;var s=el('ee_wsech');if(s)s.classList.toggle('on',_eeS.Ech);ceEchPxGate()}
function ceToggleEchProxy(){_eeS.EchProxy=!_eeS.EchProxy;var s=el('ee_echpx');if(s)s.classList.toggle('on',_eeS.EchProxy);var b=el('ee_echpxbody');if(b)b.style.display=_eeS.EchProxy?'':'none'}
function ceEchPxGate(){var vis=(_eeS.Tr=='ws'&&_eeS.Ech),row=el('ee_echpxrow');if(!vis){_eeS.EchProxy=false;var s=el('ee_echpx');if(s)s.classList.remove('on')}if(row)row.style.display=vis?'':'none';var b=el('ee_echpxbody');if(b)b.style.display=(vis&&_eeS.EchProxy)?'':'none'}



function ceFecDatagram(){return fecDatagram(_eeS)}
function ceToggleFec(){if(!ceFecDatagram())return;_eeS.Fec=!_eeS.Fec;var s=el('ee_fecsw');if(s)s.classList.toggle('on',_eeS.Fec);var r=el('ee_fecrates');if(r)r.style.display=_eeS.Fec?'':'none';ceWorkersVis()}   
function ceSetFecRate(d,p){_eeS.FecData=d;_eeS.FecParity=p;var g=el('ee_fecrates');if(g)Array.prototype.forEach.call(g.querySelectorAll('[data-fd]'),function(t){t.classList.toggle('on',parseInt(t.getAttribute('data-fd'))==d&&parseInt(t.getAttribute('data-fp'))==p)})}
function ceFecGate(){var dg=ceFecDatagram(),row=el('ee_fecrow');if(!dg){_eeS.Fec=false;var s=el('ee_fecsw');if(s)s.classList.remove('on');var r=el('ee_fecrates');if(r)r.style.display='none'}if(row)row.style.display=dg?'':'none'}
function ceRawVis(){var w=el('ee_rawblk');if(w)w.style.display=(_eeS.Tr=='raw')?'':'none'}
function cePortTriesVis(){portTriesVis('ee_',_eeS)}
function ceDnsVis(){var w=el('ee_dnsblk');if(w)w.style.display=(_eeS.Tr=='dns')?'':'none'}
function cePortGate(){var p=el('ee_port');if(!p)return;var np=(_eeS.Tr=='raw'||_eeS.Tr=='dns');var w=el('ee_coreportrow');if(w)w.style.display=np?'none':'';if(np){p.value='';return}if(_eeS.Tr=='ws'){if(!p.value)p.value='80';p.placeholder=T('port_ws_ph');return}if(p.value=='80')p.value='';p.placeholder=T('port_band_ph')}
function ceSetProfile(p){_eeS.RawProfile=p;var g=el('ee_pg');if(g)Array.prototype.forEach.call(g.querySelectorAll('.ptile'),function(t){t.classList.toggle('on',t.getAttribute('data-p')==p)});ceProtoVis();cePortVis();cePortTriesVis()}
function ceSetProto(val){var i=el('ee_rawproto');if(i)i.value=val;protoWarnUpd('ee_',val)}
function ceProtoWarn(){var i=el('ee_rawproto');if(i)protoWarnUpd('ee_',i.value)}
function ceSetPort(v){var i=el('ee_rawport');if(i)i.value=v;cePortWarn()}
function ceSetSport(on){if(sprotLive(_eeS))return;_eeS.SportRandom=!!on;sportPaint('ee_',_eeS.SportRandom);cePortTriesVis();bandVis('ee_',_eeS)}
function ceSetSportPort(n){if(sprotLive(_eeS))return;var i=el('ee_rawsport');if(i)i.value=n;sportPresetPaint('ee_')}
function ceSportWarn(){sportPresetPaint('ee_')}
function cePortWarn(){var i=el('ee_rawport');if(!i)return;var n=parseInt(i.value,10),g=el('ee_rpg');
 if(g)Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='ee_rp_'+n)})}
function cePortVis(){var w=el('ee_portrow');if(!w)return;
 var on=(_eeS.Tr=='raw'&&(_eeS.RawProfile=='udp'||_eeS.RawProfile=='tcp'));w.style.display=on?'':'none';
 if(on){var i=el('ee_rawport');if(i&&!i.value)i.value='443';cePortWarn();sportPaint('ee_',_eeS.SportRandom)}
 sprotVis('ee_',_eeS);ctbVis('ee_',_eeS)}
function ceSetWorkers(sd,n){_eeS[sd=='a'?'WorkersA':'WorkersB']=n;workersPaint('ee_',sd,n)}
function ceWorkersVis(){var a=ssVal('ee_a'),b=ssVal('ee_b');
 workersVis('ee_',_eeS,[ceNodeName(a),nodeCpus(a)],[ceNodeName(b),nodeCpus(b)])}
function ceProtoVis(){var w=el('ee_protorow');if(!w)return;var show=protoVisOn(_eeS);w.style.display=show?'':'none';if(show){var i=el('ee_rawproto');if(i&&!i.value)i.value='253';ceProtoWarn()}}
function ceToggleGso(){_eeS.Gso=!_eeS.Gso;var s=el('ee_gso');if(s)s.classList.toggle('on',_eeS.Gso)}
function ceToggleObfs(){if(ssVal('ee_cipher')=='none')return;_eeS.Obfs=!_eeS.Obfs;var s=el('ee_obfs');if(s)s.classList.toggle('on',_eeS.Obfs)}
function ceToggleCover(){if(_eeS.Tr!='tcp')return;_eeS.Cover=!_eeS.Cover;var s=el('ee_cover');if(s)s.classList.toggle('on',_eeS.Cover);ceSniVis()}
function ceSniVis(){var w=el('ee_snirow');if(w)w.style.display=(_eeS.Cover&&_eeS.Tr=='tcp')?'':'none'}
function ceCoverGate(){var ok=_eeS.Tr=='tcp'&&ssVal('ee_cipher')!='none',row=el('ee_coverrow'),s=el('ee_cover');if(!ok){_eeS.Cover=false;if(s)s.classList.remove('on')}if(row)row.style.display=ok?'':'none';ceSniVis()}
function onEeCipher(){_obfsGate('ee_',_eeS);ceCoverGate()}
function ceNodeItems(l){var out=[],seen={};
 (NODES||[]).forEach(function(n){if(!n.online)return;seen[n.id]=1;out.push({v:n.id,label:n.name,sub:n.host})});
 [[l.a_node,l.a_name],[l.b_node,l.b_name]].forEach(function(p){if(!p[0]||seen[p[0]])return;seen[p[0]]=1;
  var n=(NODES||[]).filter(function(x){return x.id==p[0]})[0];
  out.push({v:p[0],label:(n&&n.name)||p[1]||p[0],sub:(n&&n.host)||''})});
 _eeS.NodeItems=out;return out}
function ceNodeName(id){var it=(_eeS.NodeItems||[]).filter(function(x){return x.v==id})[0];
 return (it&&it.label)||nodeName(id)}
async function openCoreEdit(id){var l=FLEET.filter(function(x){return x.id==id})[0];if(!l){toast(T('not_found'),'err');return}
 var _nr=await j('node-names').catch(function(){return null});
 if(!_nr||!_nr.nodes){toast(T('failed'),'err');return}
 NODES=_nr.nodes;
 var _nitems=ceNodeItems(l);_eeS.NodeA=l.a_node;_eeS.NodeB=l.b_node;
 _eeS.Srv=(l.server_side=='b')?'b':'a';_eeS.Tr=(['tcp','raw','ws','dns'].indexOf(l.transport)>=0)?l.transport:'udp';_eeS.Obfs=!!l.obfs;_eeS.Cover=!!l.cover&&_eeS.Tr=='tcp';_eeS.RawProfile=l.raw_profile||'bare';_eeS.SportRandom=!!l.raw_sport_random;_eeS.Sprot=!!l.raw_sport_rotate;_eeS.Ctb=!!l.conntrack_bypass;_eeS.Gso=!!l.gso;_eeS.WsTls=!!l.ws_tls;_eeS.Ech=!!l.ech;_eeS.EchProxy=!!l.ech_proxy;_eeS.SniSplit=!!l.sni_split;_eeS.SplitPos=l.split_pos||0;_eeS.SniMode=(l.sni_mode=='disorder'||l.sni_mode=='fake')?l.sni_mode:'split';_eeS.SplitTtl=l.split_ttl||0;_eeS.Cdn=(l.cdn_carrier=='http'||l.cdn_carrier=='grpc')?l.cdn_carrier:'ws';_eeS.Fec=!!l.fec;_eeS.FecData=l.fec_data||16;_eeS.FecParity=l.fec_parity||4;_eeS.Desync=!!l.fake_desync;_eeS.DesyncTtl=l.fake_ttl||4;_eeS.DesyncCount=l.fake_count||2;_eeS.DesyncMode=l.fake_mode||'ttl';_eeS.WorkersA=wkClamp(l.a_workers);_eeS.WorkersB=wkClamp(l.b_workers);_eeS.Lid=l.id;_eeS.PoolLid=(l.ws_pool?l.id:'');poolInit('ee_',l);_peerLid=(l.ip_rotate?l.id:'');_peerData={dst:null,src:null,now:0,polledMs:0,selPending:null,open:{}};   
 _rotS['ee_']={on:!!l.ip_rotate,secs:(l.rotate_secs!=null?l.rotate_secs:600),aIps:nodeIps(l.a_node),bIps:nodeIps(l.b_node),aSel:{},bSel:{}};
 (l.a_ip_pool||[]).forEach(function(ip){_rotS['ee_'].aSel[ip]=true});(l.b_ip_pool||[]).forEach(function(ip){_rotS['ee_'].bSel[ip]=true});
 if(l.a_ip)_rotS['ee_'].aSel[l.a_ip]=true;if(l.b_ip)_rotS['ee_'].bSel[l.b_ip]=true;
 var _t1='<div class="ctabp on" data-cp="ip"><div class="muted" style="font-size:12px;margin-bottom:10px"><span class="mono">'+esc(l.name)+'</span></div>'+
  '<div class="grid2"><div id="ee_awrap"><label class="first" id="ee_alab"></label>'+ssHTML('ee_a',_nitems,l.a_node,T('srv_node'),'onCeNode')+'</div>'+
  '<div id="ee_bwrap"><label class="first" id="ee_blab"></label>'+ssHTML('ee_b',_nitems,l.b_node,T('cli_node'),'onCeNode')+'</div></div>'+
  '<div class="grid2" style="margin-top:11px"><div id="ee_aip"></div><div id="ee_bip"></div></div>'+
  '<div id="ee_rotrow"></div>'+rotSetHTML('ee_')+'<div id="ee_peerlive"></div>'+
  '<label>'+esc(T('roles_lbl'))+'</label><div class="seg2"><button type="button" class="segopt'+(_eeS.Srv=='a'?' on':'')+'" id="ee_srv_a" onclick="ceSetSrv(\\'a\\')"></button><button type="button" class="segopt'+(_eeS.Srv=='b'?' on':'')+'" id="ee_srv_b" onclick="ceSetSrv(\\'b\\')"></button></div></div>';
 var _t2='<div class="ctabp" data-cp="set"><label>'+esc(T('enc_method_lbl'))+'</label>'+ssHTML('ee_cipher',CORE_CIPHERS(),(l.cipher||'auto'),T('cipher_ph'),'onEeCipher')+
  '<label>'+esc(T('transport_lbl'))+'</label><div class="trwrap" id="ee_trwrap"><div class="seg2 trbar" id="ee_trbar" onscroll="trFade(this)"><button type="button" class="segopt'+(_eeS.Tr=='udp'?' on':'')+'" id="ee_tr_udp" onclick="ceSetTr(\\'udp\\')"><b>UDP</b><span>'+esc(T('tr_udp_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='tcp'?' on':'')+'" id="ee_tr_tcp" onclick="ceSetTr(\\'tcp\\')"><b>TCP</b><span>'+esc(T('tr_tcp_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='raw'?' on':'')+'" id="ee_tr_raw" onclick="ceSetTr(\\'raw\\')"><b>RAW</b><span>'+esc(T('tr_raw_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='ws'?' on':'')+'" id="ee_tr_ws" onclick="ceSetTr(\\'ws\\')"><b>CDN</b><span>'+esc(T('tr_ws_d'))+'</span></button><button type="button" class="segopt'+(_eeS.Tr=='dns'?' on':'')+'" id="ee_tr_dns" onclick="ceSetTr(\\'dns\\')"><b>DNS</b><span>'+esc(T('tr_dns_d'))+'</span></button></div></div>'+
  '<div id="ee_rawblk" style="display:'+((_eeS.Tr=='raw')?'':'none')+'"><label>'+esc(T('raw_prof_lbl'))+'</label><div class="pgrid" id="ee_pg">'+rawTiles('ce',_eeS.RawProfile)+'</div>'+protoSection('ee_','ce')+portSection('ee_','ce')+'</div>'+
  portTriesSection('ee_')+
  workersSection('ee_','ce')+
  wsSection('ee_','ce',l.ws_host,l.ws_path,_eeS.WsTls,l.edge_ip,_eeS.Ech,_eeS.Cdn,l.id,l)+
  dnsSection('ee_','ce')+
  '<div class="tglbox" id="ee_obfsrow"'+((l.cipher=='none')?' style="display:none"':'')+'><div class="tglsw'+(_eeS.Obfs?' on':'')+'" id="ee_obfs" onclick="ceToggleObfs()"></div><div class="tt"><b>'+esc(T('obfs_t'))+'</b><small>'+esc(T('obfs_d'))+'</small></div></div>'+
  '<div class="tglbox" id="ee_coverrow"'+((_eeS.Tr!='tcp')?' style="display:none"':'')+'><div class="tglsw'+(_eeS.Cover?' on':'')+'" id="ee_cover" onclick="ceToggleCover()"></div><div class="tt"><b>'+esc(T('cover_t'))+'</b><small>'+esc(T('cover_d'))+'</small></div></div>'+
  wsToggleRows('ee_','ce',_eeS.WsTls,_eeS.Ech,_eeS.EchProxy,(l.ech_proxy_url||''),_eeS.SniSplit,_eeS.SplitPos,_eeS.SniMode,_eeS.SplitTtl,_eeS.Tr=='ws')+
  '<div id="ee_snirow" style="display:'+((_eeS.Cover&&_eeS.Tr=='tcp')?'':'none')+'"><label>'+esc(T('cover_sni_lbl'))+'</label><input id="ee_sni" placeholder="'+esc(T('cover_sni_ph'))+'" value="'+esc(l.cover_sni||'')+'"><div class="muted" style="font-size:11px;margin-top:5px;line-height:1.7">'+T('cover_sni_note2')+'</div></div>'+
  '<div class="tglbox" id="ee_gsorow"><div class="tglsw'+(_eeS.Gso?' on':'')+'" id="ee_gso" onclick="ceToggleGso()"></div><div class="tt"><b>'+esc(T('gso_t'))+'</b><small>'+esc(T('gso_d'))+'</small></div></div>'+
  fecSection('ee_','ce',_eeS.Fec,_eeS.FecData,_eeS.FecParity,ceFecDatagram())+
  desyncSection('ee_','ce',_eeS.Desync,_eeS.DesyncTtl,_eeS.DesyncCount,_eeS.DesyncMode,desyncOk(_eeS))+
  '<label>'+esc(T('core_range_lbl'))+'</label>'+ssHTML('ee_snr',SUBNETRANGES(),subnetBaseOf(l),T('range'),'onCeSubRange')+'<div id="ee_snc"></div>'+
  '<div id="ee_coreportrow"><label>'+esc(rng(T('core_port_lbl2'),1,PORT_MAX))+'</label><input id="ee_port" inputmode="numeric" value="'+esc(l.port||'')+'" placeholder="'+esc(T('port_band_ph'))+'"></div>'+
  '<div class="muted" style="font-size:11px;margin:2px 2px 0">'+esc(T('core_edit_note'))+'</div></div>';
 var b=corTabsHTML()+_t1+_t2+'<div class="msg" id="ee_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('pen')+'</span><div class="ttl"><h3>'+esc(T('core_edit_t'))+'</h3><div class="sb">'+esc(l.name)+'</div></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" data-ha="'+esc(id)+'" onclick="doCoreEdit(hA(this))">'+esc(T('save_rebuild'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>',{cls:'edit'});
 ceRoleLbls();renderRotIps('ee_');cePrefillFields(l);onCeSubRange();ceApplyGates();trFade(el('ee_trbar'));if(_eeS.PoolLid)setTimeout(poolTick,200);if(_peerLid)setTimeout(peerTick,200)}
function cePrefillFields(l){
 [['ee_rawproto',l.raw_proto],['ee_rawport',l.raw_port],['ee_rawsport',l.raw_sport],['ee_rawsprot',l.raw_sport_rotate],['ee_rawdports',l.raw_dports],['ee_bandlo',l.raw_sport_lo],['ee_bandhi',l.raw_sport_hi],
  ['ee_porttries',l.port_tries],['ee_dnszone',l.dns_zone],
  ['ee_dnsresolvers',(l.dns_resolvers||[]).join(', ')]].forEach(function(p){
   var e=el(p[0]);if(e&&p[1])e.value=p[1]})}
function ceRoleLbls(){var an=ceNodeName(ssVal('ee_a')),bn=ceNodeName(ssVal('ee_b')),a=el('ee_srv_a'),b=el('ee_srv_b');
 if(a)a.innerHTML='<b>'+esc(an)+' '+esc(T('role_server_word'))+'</b><span>'+esc(bn)+' '+esc(T('role_client_word'))+'</span>';
 if(b)b.innerHTML='<b>'+esc(bn)+' '+esc(T('role_server_word'))+'</b><span>'+esc(an)+' '+esc(T('role_client_word'))+'</span>';
 ceNodeLbls()}
function ceNodeLbls(){var srvA=(_eeS.Srv=='a'),la=el('ee_alab'),lb=el('ee_blab');
 if(la)la.textContent=srvA?T('srv_node'):T('cli_node');
 if(lb)lb.textContent=srvA?T('cli_node'):T('srv_node');
 var A=el('ee_awrap'),B=el('ee_bwrap');
 if(A)A.style.order=srvA?'0':'1';
 if(B)B.style.order=srvA?'1':'0'}
function onCeNode(){var a=ssVal('ee_a'),b=ssVal('ee_b');
 if(a!=_eeS.NodeA||b!=_eeS.NodeB){_eeS.NodeA=a;_eeS.NodeB=b;
  delete SEL['ee_aip_sel'];delete SEL['ee_bip_sel'];
  var st=rotSt('ee_');st.aSel={};st.bSel={}}
 corRotVis('ee_');ceRoleLbls();ceWorkersVis()}
function ceSetSrv(s){_eeS.Srv=s;var a=el('ee_srv_a'),b=el('ee_srv_b');if(a)a.classList.toggle('on',s=='a');if(b)b.classList.toggle('on',s=='b');ceNodeLbls();renderRotIps('ee_')}
async function doCoreEdit(id){var m=el('ee_msg');m.className='msg';
 var l=FLEET.filter(function(x){return x.id==id})[0]||{};
 var _na=ssVal('ee_a'),_nb=ssVal('ee_b');
 if(_na==_nb){formErr(m,T('two_diff_nodes'));return}
 m.textContent=T('saving_rebuild_both');
 var body={id:id,type:'core',a_node:_na,b_node:_nb,server_side:_eeS.Srv,cipher:ssVal('ee_cipher'),transport:_eeS.Tr,obfs:_eeS.Obfs,cover:(_eeS.Cover&&_eeS.Tr=='tcp'),gso:_eeS.Gso};
 if(_collectCoreBody(_eeS,'ee_',m,body))return;
 if(body.cover){var sni=(v('ee_sni')||'').trim();if(!sni){formErr(m,T('cover_need_sni'));return}body.cover_sni=sni}
 var _rverr2=rotValidate('ee_');if(_rverr2){formErr(m,_rverr2);return}
 var aip=pickedIP('ee_','a',l.a_ip||'');if(aip)body.a_ip=aip;
 var bare=pickedIP('ee_','b',l.b_ip||'');if(bare)body.b_ip=bare;
 var _rc2=rotCollect('ee_');body.ip_rotate=!!(_rc2);if(_rc2){body.a_ip_pool=_rc2.a_ip_pool;body.b_ip_pool=_rc2.b_ip_pool;body.rotate_secs=_rc2.rotate_secs}
 var _sr=ssVal('ee_snr');
 if(_sr=='custom'){var sub=v('ee_subnet');if(sub)body.subnet=sub}
 else{var _sb=subnetForBase('core',l.tunnel_id,_sr);if(_sb)body.subnet=_sb}
 var port=v('ee_port');if(port)body.port=port;
 var r=await post('edit-link',body);
 if(!(r.ok&&r.d.act)){formErr(m,perr(r));return}
 var vr=await actAccepted(r.d.act,m);
 if(vr.gone)return;
 if(vr.err){formErr(m,vr.err);return}
 closeModal(m.closest('.modalov'));refreshCore()}

var PX=[];
async function pxLoad(){var r=await j('proxies').catch(function(){return{}});PX=r.proxies||[]}
function proxiesSkel(){el('view').innerHTML=vhead('globe','nav_proxies','px_sub')+
 '<button class="primary" onclick="openPxModal(null)" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+esc(T('px_add'))+'</button>'+
 '<div id="pxList">'+skCards('proxies')+'</div>';
 refreshProxies()}
async function refreshProxies(){if(listBusy())return;await pxLoad();
 var box=el('pxList');if(!box||listBusy())return;   
 setList(box,PX.length?PX.map(function(p,i){return {k:p.id,h:pxCard(p,i)}}):[{k:'__empty',h:'<div class="card muted">'+esc(T('px_empty'))+'</div>'}])}
function pxCard(p,i){var open=!!TOPEN[p.id];
 var dotk=p.online?'on':(p.pending?'':'off');
 var st=p.status||{};
 var ttl=p.pending?T('pending_check'):(p.online?T('online'):T('offline'))
  +(st.error?' — '+terr(st.error):'');
 var used=p.nodes&&p.nodes.length?esc(T('px_used_by'))+esc(p.nodes.join('، ')):'<span class="muted">'+esc(T('px_used_none'))+'</span>';
 var head='<div class="chead" onclick="cardTogFromEl(this)"><span class="grow"></span>'
  +'<div class="hmain" style="direction:ltr;align-items:flex-start;gap:2px;flex:0 0 auto;min-width:0">'
  +'<div class="name" style="text-align:left">'+esc(p.name)+'</div>'
  +'<div class="muted mono" style="font-size:12px">'+esc(p.addr)+'</div></div>'
  +'<span class="ndot '+dotk+'" title="'+esc(ttl)+'"></span>'+CHEVI+'</div>';
 var meta='<div class="pxused">'+used+'</div>'
  +(st.error?'<div class="pxused" style="color:var(--bad)">'+esc(terr(st.error))+'</div>':'');
 var acts='<div class="nact iconly"><button class="act ok" title="'+esc(T('px_test'))+'" data-ha="'+i+'" onclick="testPx(+hA(this))">'+ic('bolt')+'</button>'
  +'<button class="act warn" title="'+esc(T('tip_edit'))+'" data-ha="'+i+'" onclick="openPxModal(+hA(this))">'+ic('pen')+'</button>'
  +'<button class="act danger" title="'+esc(T('tip_delete'))+'" data-ha="'+i+'" onclick="delPx(+hA(this))">'+ic('trash')+'</button></div>';
 return '<div class="card node acc'+(open?' open':'')+'" id="c_'+esc(p.id)+'" data-rid="'+esc(p.id)+'">'
  +head+'<div class="cbody"><div class="cbody-in">'+meta+acts
  +rmsgHTML('pxm_'+p.id)+'</div></div></div>'}
async function testPx(i){var p=PX[i];if(!p)return;var k='pxm_'+p.id;
 rmsgSet(k,'',esc(T('px_testing')));
 var r=await post('proxy-test',{id:p.id});var d=r.d||{};
 if(r.ok&&d.ok){rmsgSet(k,'ok',CK+esc(' '+T('px_up')+' · '+num(d.ms)+'ms'))}
 else{rmsgClear(k);formErr(null,terr(d.error||T('failed')))}}
function openPxModal(i){var p=(i==null)?null:PX[i];
 var sc=(p&&p.scheme)||'socks5';
 var seg=function(s,lbl){return '<button type="button" data-s="'+s+'"'+(sc==s?' class="on"':'')+' data-ha="'+esc(s)+'" onclick="pxScheme(hA(this))">'+lbl+'</button>'};
 var body='<label class="first">'+esc(T('px_name'))+'</label><input id="px_name" maxlength="40" value="'+esc(p?p.name:'')+'">'
  +'<div class="authhd" style="margin-top:16px"><span class="t">'+esc(T('px_type'))+'</span><span class="authseg" id="px_seg">'+seg('socks5','SOCKS5')+seg('http','HTTP')+'</span></div>'
  +'<div class="grid2"><div><label class="first">'+esc(T('px_ip'))+'</label><input id="px_host" class="mono" value="'+esc(p?p.host:'')+'"></div>'
  +'<div><label class="first">'+esc(rng(T('px_port'),1,PORT_MAX))+'</label><input id="px_port" class="mono" inputmode="numeric" value="'+esc(p?String(p.port):'')+'"></div></div>'
  +'<div class="grid2"><div><label>'+esc(T('px_user'))+'</label><input id="px_user" placeholder="'+esc(T('px_opt'))+'" value="'+esc(p?p.user:'')+'"></div>'
  +'<div><label>'+esc(T('px_pass'))+'</label><input id="px_pass" type="password" autocomplete="new-password" placeholder="'+esc((p&&p.has_pass)?T('px_pass_keep'):T('px_opt'))+'" value=""></div></div>'
  +'<div class="muted" style="font-size:11.5px;line-height:1.9;margin-top:6px">'+esc(T('px_hint'))+'</div>'
  +'<div class="msg" id="px_msg"></div>';
 var ov=openModal('<div class="msticky"><span class="medi">'+ic(p?'pen':'plus')+'</span><div class="ttl"><h3>'+esc(T(p?'px_edit_t':'px_add_t'))+'</h3>'+(p?'<div class="sb">'+esc(p.name)+'</div>':'')+'</div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+body+'</div><div class="mfoot"><button class="primary" onclick="savePx(this)">'+esc(T(p?'save':'add'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');
 ov._px=p?p.id:''}
function pxScheme(s){document.querySelectorAll('#px_seg button').forEach(function(b){b.classList.toggle('on',b.dataset.s==s)})}
function pxSchemeVal(){var b=document.querySelector('#px_seg button.on');return b?b.dataset.s:'socks5'}
async function savePx(btn){var m=el('px_msg'),ov=btn.closest('.modalov'),pid=(ov&&ov._px)||'';
 var b={name:v('px_name'),scheme:pxSchemeVal(),host:v('px_host'),port:v('px_port'),
        user:v('px_user'),pass:(el('px_pass')?el('px_pass').value:'')};if(pid)b.id=pid;
 var r=await post(pid?'proxy-edit':'proxy-add',b);
 if(r.ok&&r.d.ok){closeModal(ov);toast(T('px_saved'),'ok');refreshProxies()}
 else{formErr(m,perr(r))}}
async function delPx(i){var p=PX[i];if(!p)return;if(!await confirmBox(T('px_del_confirm')))return;
 var r=await post('proxy-del',{id:p.id});
 if(r.ok&&r.d.ok){toast(T('px_deleted'),'ok');refreshProxies()}else{toast(perr(r),'err')}}
function pxFields(pre,node,lbl,sub){
 var on=!!(node&&node.proxy_on),sel=(node&&node.proxy_id)||'';
 var opts=PX.map(function(p){return {v:p.id,label:p.name,sub:p.addr}});
 var pick=opts.length
  ?ssHTML(pre+'proxy_id',opts,sel||opts[0].v,'','')
  :'<div class="muted" style="font-size:12px">'+esc(T('nd_proxy_none'))+'</div>';
 return '<div class="tglbox"><div class="tglsw'+(on?' on':'')+'" id="'+pre+'proxy_tgl" data-ha="'+esc(pre)+'" onclick="pxToggle(hA(this))"></div>'
  +'<div class="tt"><b>'+esc(T(lbl||'nd_proxy_on'))+'</b><small>'+esc(T(sub||'nd_proxy_all'))+'</small></div></div>'
  +'<div id="'+pre+'proxy_box"'+(on?'':' style="display:none"')+'>'
  +'<label>'+esc(T('nd_proxy_pick'))+'</label>'+pick+'</div>'}
function pxToggle(pre){var sw=el(pre+'proxy_tgl');if(!sw)return;var on=!sw.classList.contains('on');
 sw.classList.toggle('on',on);var b=el(pre+'proxy_box');if(b)b.style.display=on?'':'none'}
function pxBody(pre){var sw=el(pre+'proxy_tgl');var on=!!(sw&&sw.classList.contains('on'));
 return {proxy_on:on,proxy_id:on?ssVal(pre+'proxy_id'):''}}

function portfwSkel(){el('view').innerHTML=vhead('fwd','nav_portfw','pf_sub')+
 '<button class="primary" onclick="openPfAddModal()" style="margin:0 0 14px;display:inline-flex;align-items:center;gap:6px">'+ic('plus')+esc(T('pf_add'))+'</button>'+
 '<div class="sec">'+ic('activity','var(--acc)')+' '+esc(T('pf_active'))+'</div>'+toolbar('portfw',T('pf_search'))+'<div id="pfList">'+skCards('portfw')+'</div>';
 refreshPortfw()}
async function openPfAddModal(){var r=await j('node-names');NODES=r.nodes||[];var on=NODES.filter(function(n){return n.online});
 if(!on.length){toast(T('pf_no_online'),'err');return}
 var items=on.map(function(n){return {v:n.id,label:n.name,sub:n.host}});
 var b='<label class="first">'+esc(T('pf_node'))+'</label>'+ssHTML('pf_node',items,items[0].v,T('pf_node'),'renderPfLip')+'<div id="pf_lipwrap"></div><div class="grid2"><div><label>'+esc(rng(T('pf_listen_port'),1,PORT_MAX))+'</label><input id="pf_lp" placeholder="8080"></div><div><label>'+esc(rng(T('pf_dst_port'),1,PORT_MAX))+'</label><input id="pf_dp" placeholder="443"></div></div><label>'+esc(T('pf_dst_ips'))+'</label><input id="pf_ips" placeholder="10.0.0.1, 10.0.0.2"><label>'+esc(T('pf_rot_min'))+'</label><input id="pf_int" placeholder="5"><div class="msg" id="pf_msg"></div>';
 openModal('<div class="msticky"><span class="medi">'+ic('plus')+'</span><div class="ttl"><h3>'+esc(T('pf_add_t'))+'</h3></div><button class="mx" onclick="closeModal(this.closest(\\'.modalov\\'))">✕</button></div><div class="mbody">'+b+'</div><div class="mfoot"><button class="primary" onclick="doPortfw()">'+esc(T('add'))+'</button><button class="ghost" onclick="closeModal(this.closest(\\'.modalov\\'))">'+esc(T('cancel'))+'</button></div>');
 renderPfLip()}
function renderPfLip(){var w=el('pf_lipwrap');if(!w)return;var ips=nodeIps(ssVal('pf_node'));
 if(ips.length>1){w.innerHTML='<label>'+esc(T('pf_lip_full'))+'</label>'+ssHTML('pf_lip',ipItems(ips),(SEL['pf_lip']&&ips.indexOf(SEL['pf_lip'])>=0?SEL['pf_lip']:ips[0]),T('ip'),'')}
 else{w.innerHTML='';delete SEL['pf_lip']}}   
async function refreshPortfw(){if(listBusy())return;var box=el('pfList');if(!box)return;var r=await j('portfw-list?q='+encodeURIComponent(QRY.portfw));PF=(r.portfw||[]).filter(function(x){return x.name});
 if(listBusy())return;   
 setList(box,PF.length?PF.map(function(p,i){return {k:p.node_id.length+':'+p.node_id+p.name,h:pfCard(p,i)}}):[{k:'__empty',h:'<div class="card muted">'+(QRY.portfw?T('no_results'):T('pf_empty'))+'</div>'}])}
function pfCard(p,i){var h=p.health||{};
 var st=h.rule?(h.reachable?'<span class="badge ok">'+esc(T('pf_active_badge'))+CK+'</span>':'<span class="badge bad">'+esc(T('pf_rule'))+CK+' · '+esc(T('pf_dest'))+XK+'</span>'):'<span class="badge bad">'+esc(T('pf_disabled'))+'</span>';
 var rotOn=p.switch_interval>0,multi=(p.dst_ips||[]).length>1;
 var lip=p.listen_ip||p.node_ip||'';   
 var rotchip=rotOn?'<span class="tag" style="display:inline-flex;align-items:center;gap:4px;color:var(--gold);border-color:color-mix(in srgb,var(--gold) 34%,transparent);background:var(--goldw);direction:ltr">'+ic('redo')+(p.switch_interval/60)+'m</span>':'';
 var key=p.node_id+p.name,open=!!TOPEN[key];
 var route='<b class="mono" dir="ltr" style="color:var(--sub);font-size:12px">'+esc(p.listen_port)+' ↔ '+esc(p.dst_port)+'</b>';   
 var head='<div class="chead" onclick="cardTogFromEl(this)">'+grip()+'<div class="hmain"><div class="hrow1"><span class="hname">'+esc(p.node)+'</span><span class="ctag" style="color:#fb923c;background:color-mix(in srgb,#fb923c 15%,transparent)">portfw</span>'+route+'<span class="hpeers">'+rotchip+st+'</span></div></div>'+CHEVI+'</div>';   
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
 var acts='<div class="nact iconly"><button class="act reset" title="'+esc(T('tip_reset'))+'" data-ha="'+i+'" onclick="resetPfTraffic(+hA(this))">'+ic('reset')+'</button>'+((multi&&h.active)?'<button class="act" title="'+esc(T('pf_rotate_now'))+'" style="color:#fb923c;border-color:color-mix(in srgb,#fb923c 46%,transparent)" data-ha="'+i+'" onclick="pfNext(+hA(this))">'+ic('redo')+'</button>':'')+'<button class="act warn" title="'+esc(T('tip_edit'))+'" data-ha="'+i+'" onclick="openPfEdit(+hA(this))">'+ic('pen')+'</button><button class="act danger" title="'+esc(T('tip_delete'))+'" data-ha="'+i+'" onclick="delPf(+hA(this))">'+ic('trash')+'</button></div>';
 return '<div class="card acc'+(open?' open':'')+'" id="c_'+esc(key)+'" data-rid="'+esc(key)+'" data-rk="portfw">'+head+'<div class="cbody"><div class="cbody-in">'+body+traf+acts+'</div></div></div>'}
function pfTgl(){var sw=el('pe_tgl'),on=!sw.classList.contains('on');sw.classList.toggle('on',on);
 setT('pe_tgllbl',on?T('on_word'):T('off_word'));var w=el('pe_intwrap');if(w)w.style.display=on?'block':'none'}
async function savePfEdit(btn){var ov=btn.closest('.modalov'),p=ov&&ov._pf;if(!p)return;var m=el('pem');var lp=v('pe_lp'),dp=v('pe_dp'),ips=v('pe_ips');
 if(!lp||!dp||!ips){formErr(m,T('pf_need_ports'));return}
 var rot=el('pe_tgl').classList.contains('on'),intv=v('pe_int');
 m.className='msg';m.textContent=T('saving');
 var lip=el('ssb_pe_lip')?ssVal('pe_lip'):'';   
 var r=await post('portfw-edit',{node:p.node_id,name:p.name,listen_port:lp,dst_port:dp,dst_ips:ips,rotate:rot,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(ov)}else{formErr(m,perr(r))}}
async function doPortfw(){var m=el('pf_msg');var node=ssVal('pf_node'),lp=v('pf_lp'),dp=v('pf_dp'),ips=v('pf_ips'),intv=v('pf_int');
 if(!node||!lp||!dp||!ips){formErr(m,T('pf_need_all'));return}
 m.className='msg';m.textContent=T('creating_dots');
 var lip=el('ssb_pf_lip')?ssVal('pf_lip'):'';   
 var r=await post('portfw',{node:node,listen_port:lp,dst_port:dp,dst_ips:ips,interval_min:intv||5,listen_ip:lip});
 if(r.ok&&r.d.ok){closeModal(m.closest('.modalov'));toast(T('pf_created')+r.d.name,'ok')}
 else{formErr(m,terr(r.d.error||T('failed')))}}
async function pfNext(i){var p=PF[i];if(!p)return;var b=el('pfact_'+i),old=b?b.textContent:'';if(b)b.textContent='…';
 var r=await post('portfw-next',{node:p.node_id,name:p.name});
 if(r.ok&&r.d.ok){if(b)b.textContent=r.d.active;toast(T('pf_rotate_done')+r.d.active,'ok')}
 else{if(b)b.textContent=old;toast(terr((r.d&&(r.d.error||r.d.msg))||T('pf_rotate_failed')),'err')}}
async function delPf(i){var p=PF[i];if(!p)return;if(!await confirmBox(T('pf_del_confirm')))return;var r=await post('portfw-del',{node:p.node_id,name:p.name});
 if(!(r.ok&&r.d&&r.d.ok))toast(terr((r.d&&(r.d.msg||r.d.error)))||T('failed'),'err');
 refreshPortfw()}

var RDY=null;
async function loadReadiness(){try{RDY=await j('readiness')}catch(e){return}paintReady()}
function paintReady(){var b=el('rdbar');if(!b)return;
 if(!RDY||RDY.ok){setHTML(b,'');return}
 var miss=[];
 if(!RDY.agent)miss.push(T('rdy_agent'));
 if(!RDY.core)miss.push(RDY.core_version?T('rdy_core_arch').replace('{a}',(RDY.core_missing||[]).join('، ')):T('rdy_core'));
 setHTML(b,'<div class="rdbar">'+ic('warn')+'<div class="rdtx"><b>'+esc(T('rdy_title'))+'</b>'+
  '<span>'+esc(miss.join(' · ')+' — '+T('rdy_why'))+'</span></div>'+
  '<button type="button" class="ghost" onclick="goReady()">'+esc(T('rdy_go'))+'</button></div>')}
function goReady(){cur='settings';render()}

var DLV={agent:'push',core:'push'};
var DLV_OPTS=[['push','dlv_push_t'],['github','dlv_git_t'],['panel','dlv_pan_t']];
function dlSeg(kind){
 return '<div class="opdlv"><label>'+esc(T('dlv_lbl'))+'</label><div class="seg2" id="dlseg_'+kind+'">'+
  DLV_OPTS.map(function(o){return '<button type="button" class="segopt'+(o[0]==DLV[kind]?' on':'')+'" id="dlo_'+kind+'_'+o[0]+'" data-ha="'+esc(kind)+'" data-hb="'+esc(o[0])+'" onclick="setDelivery(hA(this),hB(this))"><b>'+esc(T(o[1]))+'</b></button>'}).join('')+
  '</div></div>'}
function paintDelivery(){['agent','core'].forEach(function(k){var g=el('dlseg_'+k);if(!g)return;
 Array.prototype.forEach.call(g.querySelectorAll('.segopt'),function(x){x.classList.toggle('on',x.id=='dlo_'+k+'_'+DLV[k])})});
 var b=el('cor_git_lbl');if(b)setHTML(b,esc(T(DLV.core=='github'?'cor_pick_git':'ag_fetch_git')))}
async function setDelivery(k,v){if(DLV[k]==v)return;var b={};b[k+'_delivery']=v;
 var was=DLV[k];DLV[k]=v;paintDelivery();          
 var r=await post('settings-set',b);
 if(r.ok&&r.d.ok)toast(T('set_saved'),'ok');else{DLV[k]=was;paintDelivery();toast(perr(r),'err')}}
function agentBody(){return ''+
 '<div class="opgrid">'+
 '<div class="card opc sc-panel">'+
  '<div class="ophd"><span class="sgt">'+ic(AG_IC)+'</span><b>'+esc(T('ag_node_agent'))+'</b><span class="grow"></span><span id="ag_status"></span></div>'+
  '<div class="opmeta" id="ag_meta"></div>'+
  '<div class="oprow">'+
    '<button class="primary" id="ag_git_btn" onclick="agFetchGit()">'+ic('redo')+esc(T('ag_fetch_git'))+'</button>'+
    '<button class="ghost" onclick="el(\\'ag_file\\').click()">'+ic('plus')+esc(T('ag_file_btn'))+'</button>'+
  '</div>'+
  dlSeg('agent')+
  '<div class="msg" id="ag_git_msg"></div><div class="msg" id="ag_msg"></div>'+
  '<input type="file" id="ag_file" accept=".py" style="display:none" onchange="agPick(this)">'+
  '<button class="primary opgo" onclick="agPush(\\'all\\')">'+ic('redo')+esc(T('ag_push_all'))+'</button>'+
 '</div>'+
 '<div class="card opc sc-perf">'+
  '<div class="ophd"><span class="sgt">'+ic(COR_IC)+'</span><b>'+esc(T('ag_data_core'))+'</b><span class="grow"></span><span id="cor_status"></span></div>'+
  '<div class="opmeta" id="cor_meta"></div>'+
  '<div class="oprow"><div id="cor_ver_box"></div>'+
    '<button type="button" class="ghost corcheck" onclick="corCheck()">'+ic('redo')+esc(T('cor_check'))+'</button></div>'+
  '<div class="oprow">'+
    '<button class="primary" style="background:#8b5cf6" id="cor_git_btn" onclick="corStage()">'+ic('redo')+'<span id="cor_git_lbl">'+esc(T('ag_fetch_git'))+'</span></button>'+
    '<button class="ghost" onclick="el(\\'cor_file\\').click()">'+ic('plus')+esc(T('ag_binary'))+'</button>'+
    '<button class="ghost opdel" id="cor_del" style="display:none" onclick="corDelBlob()" title="'+esc(T('cor_del_blob'))+'">'+ic('trash')+'</button>'+
  '</div>'+
  dlSeg('core')+
  '<div class="msg" id="cor_msg"></div>'+
  '<input type="file" id="cor_file" style="display:none" onchange="agCorPick(this)">'+
  '<button class="primary opgo" style="background:#8b5cf6" onclick="corPushAll()">'+ic('redo')+esc(T('ag_install_all'))+'</button>'+
 '</div>'+
 '</div>'+
 '<div class="card opc" id="dlpx_card" style="margin-top:14px">'+
  '<div class="ophd"><span class="sgt">'+ic('shield')+'</span><b>'+esc(T('dlpx_title'))+'</b></div>'+
  '<div class="opmeta"><span class="muted">'+esc(T('dlpx_sub'))+'</span></div>'+
  '<div id="dlpx_fields"></div>'+
  '<div class="msg" id="dlpx_msg"></div>'+
  '<button class="primary opgo" onclick="dlpxSave()">'+ic('redo')+esc(T('save'))+'</button>'+
 '</div>'+
 '<div class="sec" style="margin-top:16px">'+ic('server','var(--acc)')+' '+esc(T('nodes_fleet'))+'</div>'+
 '<div class="toolbar"><input id="q_agent" class="search" placeholder="'+esc(T('ag_search'))+'" oninput="onSearch(\\'agent\\')"></div>'+
 '<div id="agList">'+skCards('agent')+'</div>'}
function agentSkel(){el('view').innerHTML=vhead(AG_IC,'ag_title','ag_sub')+agentBody();refreshAgent()}
var DLPX=null;
async function dlpxPaint(){var box=el('dlpx_fields');if(!box||box.firstChild)return;
 if(!DLPX){
  await pxLoad();
  var st=await j('settings').catch(function(){return{}});
  DLPX={on:!!st.dl_proxy_on,id:String(st.dl_proxy_id||'')}}
 box=el('dlpx_fields');if(!box||box.firstChild)return;
 box.innerHTML=PX.length
  ?pxFields('dlpx_',{proxy_on:DLPX.on,proxy_id:DLPX.id},'dlpx_on','dlpx_via')
  :'<div class="muted" style="font-size:12px">'+esc(T('dlpx_none'))+'</div>'}
async function dlpxSave(){var m=el('dlpx_msg');if(!m)return;
 if(!PX.length){formErr(m,T('dlpx_none'));return}
 var b=pxBody('dlpx_');
 var r=await post('settings-set',{dl_proxy_on:b.proxy_on,dl_proxy_id:b.proxy_id});
 if(r.ok&&r.d.ok){DLPX={on:b.proxy_on,id:b.proxy_id};m.className='msg ok';m.textContent=T('set_saved')}
 else{formErr(m,perr(r))}}
async function refreshAgent(){var info=await j('agent-info').catch(function(){return{none:true}});AGMETA=info;
 dlpxPaint();
 if(info&&info.delivery){DLV.agent=info.delivery;paintDelivery()}   
 loadReadiness();   
 var st=el('ag_status'),mt=el('ag_meta');
 if(st)st.innerHTML=(info&&!info.none)?'<span class="badge ok">'+esc(T('ag_ready'))+'</span>':'<span class="badge na">'+esc(T('ag_empty'))+'</span>';
 if(mt)mt.innerHTML=(info&&!info.none)?
  '<span>'+esc(T('ag_word_agent'))+'</span><span class="mono">v'+num(info.version)+'</span><span class="sep"></span><span class="mono">'+esc(String(info.sha256||'').slice(0,12))+'</span><span class="sep"></span><span>'+Math.round(num(info.size)/1024)+' '+esc(T('unit_kb'))+'</span>'
  :'<span class="muted">'+esc(T('ag_no_agent_loaded'))+'</span>';
 loadCoreVersions();
 var box=el('agList');if(!box)return;
 var r=await j('nodes?q='+encodeURIComponent(QRY.agent));var nodes=r.nodes||[];
 AGNODES=nodes;
 setList(box,nodes.length?nodes.map(function(n){return {k:n.id,h:agRow(n)}}):[{k:'__empty',h:'<div class="card muted">'+esc(T('ag_no_item'))+'</div>'}]);
 if(PUSHSTATE)pushPaint(PUSHSTATE);
 if(!PUSHJOB)pushAdopt()}
var CORVERS=[],STAGED=null,AGNODES=[];
async function loadCoreVersions(want){
 var r=await j('core-versions').catch(function(){return{versions:[]}});
 CORVERS=r.versions||[];STAGED=r.staged||null;
 if(r.delivery){DLV.core=r.delivery;paintDelivery()}
 var stt=el('cor_status');
 if(stt)stt.innerHTML=STAGED?'<span class="badge ok">'+esc(T('ag_ready'))+'</span>':'<span class="badge na">'+esc(T('ag_empty'))+'</span>';
 var mt=el('cor_meta');
 if(mt){
  if(STAGED){var a=(STAGED.arches&&STAGED.arches[0])||'amd64';var sh=(STAGED.sha&&STAGED.sha[a])||'';var sz=(STAGED.size&&STAGED.size[a])||0;
   mt.innerHTML='<span>'+esc(T('ag_word_core'))+'</span><span class="mono">'+esc(STAGED.version)+'</span>'+(sh?'<span class="sep"></span><span class="mono">'+esc(String(sh).slice(0,12))+'</span>':'')+(sz?'<span class="sep"></span><span>'+(sz/1048576).toFixed(1)+' '+esc(T('unit_mb_full'))+'</span>':'')+((STAGED.arches||[]).length?'<span class="sep"></span><span>'+esc(STAGED.arches.join(' · '))+'</span>':'');}
  else mt.innerHTML='<span class="muted">'+esc(T('ag_no_core_staged'))+'</span>';
 }
 var box=el('cor_ver_box');if(!box)return;   
 var db=el('cor_del');
 if(db)db.style.display=CORVERS.filter(function(x){return x.custom}).length?'':'none';
 var items=CORVERS.map(function(x){return {v:x.id,label:x.label||x.id}});
 var sel=want||ssVal('corver')||corVerSaved()||(items.length?items[0].v:'');
 if(!items.filter(function(x){return String(x.v)==String(sel)}).length)sel=items.length?items[0].v:'';
 box.innerHTML=items.length?ssHTML('corver',items,sel,T('ag_pick_version'),'corVerPicked')
   :'<div class="corempty">'+esc(T('cor_ver_empty'))+'</div>'}
function corVerSaved(){try{return localStorage.getItem('tnl.corver')||''}catch(e){return ''}}
function corVerSave(v){try{if(v)localStorage.setItem('tnl.corver',v)}catch(e){}}
function corVerPicked(){corVerSave(ssVal('corver'));
 var box=el('agList');if(!box||!AGNODES.length)return;
 setList(box,AGNODES.map(function(n){return {k:n.id,h:agRow(n)}}));
 if(PUSHSTATE)pushPaint(PUSHSTATE)}
async function corDelBlob(){
 if(!await confirmBox(T('cor_del_blob_q')))return;
 var m=el('cor_msg');m.className='msg';m.textContent=T('cor_deleting');
 var r=await post('core-delete-blob',{});
 if(!(r.ok&&r.d.ok)){formErr(m,perr(r)||terr(r.d.error)||T('failed'));return}
 m.className='msg ok';m.textContent=T('cor_del_blob_ok');
 await loadCoreVersions()}
async function corCheck(){var m=el('cor_msg');if(m){m.className='msg';m.textContent=T('cor_checking')}
 var res=await post('core-check',{});var d=(res&&res.d)||{};
 if(!(res.ok&&d.ok)){if(m){formErr(m,terr(d.error||T('err_github')))}return}
 await loadCoreVersions();
 if(m){m.className='msg ok';
  m.textContent=!d.count?T('cor_check_none')
    :d.first_check?T('cor_check_first').replace('{n}',d.count)
    :d.newer?T('cor_check_new'):T('cor_check_same')}}
function corStagePaint(pct){var m=el('cor_msg');if(!m)return;
 m.className='msg';
 setHTML(m,'<div class="pushbar"><i style="width:'+Math.max(0,Math.min(100,num(pct)))+'%"></i></div>'
  +'<div class="plbl"><span>'+esc(T('cor_downloading'))+'</span><b>'+Math.max(0,Math.min(100,num(pct)))+'%</b></div>'
  +'<button type="button" class="ghost" style="margin-top:8px" onclick="corStageCancel()">'+ic('xc')+esc(T('cor_dl_cancel'))+'</button>')}
function corStageDone(d){var m=el('cor_msg');if(!m)return;var mis=d.missing||[];
 m.className=mis.length?'msg':'msg ok';
 m.innerHTML=T('cor_staged_pre')+esc(d.version)+T(d.meta_only?'cor_picked_post':'cor_staged_post')+
  ((d.arches||[]).length?' ('+esc(d.arches.join(', '))+')':'')+
  (mis.length?esc(T('cor_arch_missing').replace('{a}',mis.join('، '))):CK);
 loadCoreVersions();loadReadiness()}
async function corStageCancel(){await post('core-stage-cancel',{})}
async function corStagePoll(){
 for(;;){
  var r=await j('core-stage-status').catch(function(){return null});
  if(!r||!r.ok)return;
  if(r.done){if(r.err)formErr(el('cor_msg'),terr(r.err));else corStageDone(r);return}
  corStagePaint(r.pct);
  await new Promise(function(res){setTimeout(res,400)})}}
async function corStage(){var ver=ssVal('corver')||'latest';var m=el('cor_msg');m.className='msg';
 m.textContent=T(DLV.core=='github'?'cor_picking':'cor_downloading');
 var res=await post('core-stage',{version:ver});
 if(!(res.ok&&res.d&&res.d.ok)){formErr(m,terr((res.d&&(res.d.error||res.d.msg))||T('err_github')));return}
 if(res.d.done){corStageDone(res.d);return}
 corStagePaint(0);await corStagePoll()}
async function corPushStaged(id){var ver=ssVal('corver')||'';
 await pushStart('update-core',ver?{ids:[id],version:ver}:{ids:[id]},[id])}
async function corPushAll(){var ver=ssVal('corver');if(!ver){toast(T('ag_pick_ver'),'err');return}
 var r=await j('node-names');var ids=(r.nodes||[]).filter(function(n){return n.online}).map(function(n){return n.id});
 if(!ids.length){toast(T('ag_no_online'),'err');return}
 if(!await confirmBox(T('ag_confirm_core')+ver+T('ag_confirm_core2')+ids.length+T('ag_confirm_core3'),T('yes_all')))return;
 await pushStart('update-core',{ids:ids,version:ver},ids)}
function agCorPick(inp){var f=inp.files&&inp.files[0];if(!f)return;inp.value='';
 var m=el('cor_msg');m.className='msg';m.textContent=T('cor_reading_upload');
 var rd=new FileReader();
 rd.onload=function(){var b=String(rd.result||'');var i=b.indexOf(',');agCorUpload(i>=0?b.slice(i+1):b,f.name)};
 rd.onerror=function(){formErr(m,T('cor_read_fail'))};
 rd.readAsDataURL(f)}
async function agCorUpload(b64,name){var m=el('cor_msg');
 var res=await post('core-upload',{data:b64,name:name});
 if(res.ok&&res.d&&res.d.ok){m.className='msg ok';m.innerHTML=T('cor_bin_saved_pre')+esc(name)+' · '+Math.round(res.d.size/1024)+'KB · <span class="mono">'+esc(res.d.sha256)+'</span>'+CK+T('cor_bin_saved_post');
  await loadCoreVersions('custom')}
 else{formErr(m,terr((res.d&&res.d.error))||T('failed'))}}
var AG_IC='server',COR_IC='cpu';
function vNum(v){var m=/^v?(\\d+)\\.(\\d+)\\.(\\d+)/.exec(String(v||''));return m?(+m[1])*1e6+(+m[2])*1e3+(+m[3]):-1}
function vNewer(a,b){var x=vNum(a),y=vNum(b);return x>=0&&y>=0&&x>y}
function agRow(n){var i=n.info||{};var agver=i.version?('v'+num(i.version)):'—';
 var cinst=!!(i.core_sha&&String(i.core_sha).length);            
 var carch=i.arch||'amd64';var ssha=(STAGED&&STAGED.sha&&STAGED.sha[carch])||'';
 var agup=!!(AGMETA&&!AGMETA.none&&i.sha256!==AGMETA.sha256);    
 var want=String(ssVal('corver')||'');
 var sver=String((STAGED&&STAGED.version)||'');
 var wantDiff=!!(want&&want!='custom'&&cinst&&String(i.core_ver||'')!==want);
 var cdiff=!!(STAGED&&(!cinst||(ssha?String(i.core_sha)!==String(ssha).slice(0,12)
   :!!sver&&String(i.core_ver||'')!==sver)));
 var cup=cdiff&&!vNewer(i.core_ver,sver);
 var LA=T('ag_lbl_agent'),LC=T('ag_lbl_core');
 function vp(icon,cls,ver,tip){return '<span class="vp '+cls+'" title="'+esc(tip)+'">'+ic(icon)+esc(ver)+'</span>'}
 var agcls,agtip,agdis;
 if(!n.online){agcls='offl';agtip=LA+': '+T('offline');agdis=1}
 else if(!AGMETA||AGMETA.none){agcls='offl';agtip=LA;agdis=1}
 else if(agup){agcls='up';agtip=LA+': '+T('ag_up_avail');agdis=0}
 else{agcls='ok';agtip=LA+': '+T('ag_uptodate');agdis=1}
 var ccls,ctip,cdis;
 if(!n.online){ccls='offl';ctip=LC+': '+T('offline');cdis=1}
 else if(!cinst){ccls='na';ctip=LC+': '+T('ag_not_installed');cdis=!(STAGED||want)}
 else if(cup){ccls='up';ctip=LC+': '+T('ag_up_avail');cdis=0}
 else if(wantDiff||cdiff){ccls='ok';ctip=LC+': '+T('ag_ver_pick').replace('{v}',want||sver);cdis=0}
 else{ccls='ok';ctip=LC+': '+T('ag_uptodate');cdis=1}
 return '<div class="nx">'+
   '<div class="nxh"><span class="ndot '+(n.online?'on':'off')+'"></span>'+
     '<span class="nmwrap"><span class="nm">'+esc(n.name)+'</span>'+
       '<span class="nxhost">'+esc(n.host||'')+'</span></span></div>'+
   '<div class="nxv">'+vp(AG_IC,agcls,agver,agtip)+
     vp(COR_IC,ccls,cinst?String(i.core_ver||'?'):'—',ctip)+'</div>'+   
   '<div class="msg agres" id="agres_'+n.id+'"></div>'+
   '<div class="nxa">'+
     '<button class="ib'+(agup&&n.online?' up':'')+'"'+(agdis?' disabled':'')+' title="'+esc(T('ag_send')+' '+LA)+'" data-ha="'+esc(n.id)+'" onclick="agPush(hA(this))">'+ic(AG_IC)+'</button>'+
     '<button class="ib'+(cup&&n.online?' up':'')+'"'+(cdis?' disabled':'')+' title="'+esc(T('ag_send')+' '+LC)+'" data-ha="'+esc(n.id)+'" onclick="corPushStaged(hA(this))">'+ic(COR_IC)+'</button>'+
   '</div></div>'}
function agPick(inp){var f=inp.files&&inp.files[0];if(!f)return;inp.value='';var rd=new FileReader();rd.onload=function(){window._agCode=rd.result;agUpload()};rd.readAsText(f)}
async function agUpload(){var m=el('ag_msg');var code=window._agCode;
 if(!code||!code.trim()){formErr(m,T('ag_pick_file_first'));return}
 m.className='msg';m.textContent=T('ag_checking_saving');
 var r=await post('agent-upload',{code:code});
 if(r.ok&&r.d.ok){m.className='msg ok';m.textContent=T('ag_saved_pre')+r.d.version+' · '+r.d.sha256;window._agCode=null;refreshAgent()}
 else{formErr(m,terr(r.d.error)||T('failed'))}}
async function agFetchGit(){var m=el('ag_git_msg'),btn=el('ag_git_btn');
 m.className='msg';m.textContent=T('ag_fetching_git');if(btn)btn.disabled=true;
 var r=await post('agent-fetch-git',{});
 if(!(r.ok&&r.d.ok)){formErr(m,terr(r.d.error)||T('failed'));if(btn)btn.disabled=false;return}
 m.className='msg ok';m.innerHTML=T('ag_fetched_pre')+esc(r.d.version)+' · <span class="mono">'+esc(r.d.sha256)+'</span>'+T('ag_fetched_post')+CK;
 if(btn)btn.disabled=false;
 await refreshAgent()}
var PUSHJOB=null,PUSHSTATE=null,PUSH_ALL='*';
async function pushAdopt(){if(PUSHJOB)return;
 var r=await j('push-status').catch(function(){return null});
 if(!r||!r.ok||r.idle||!r.job||r.done)return;
 PUSHJOB=PUSH_ALL;pushPaint(r);pushPoll(PUSH_ALL)}
async function pushCancel(){if(!PUSHJOB)return;
 if(!await confirmBox(T('ag_p_cancel_q'),T('ag_p_cancel')))return;
 var r=await post('push-cancel',{job:PUSHJOB});
 if(!(r.ok&&r.d&&r.d.ok))toast(perr(r),'err')}
async function pushPause(want){if(!PUSHJOB)return;
 var r=await post('push-pause',{job:PUSHJOB,paused:!!want});
 if(!(r.ok&&r.d&&r.d.ok)){toast(perr(r),'err');return}
 if(PUSHSTATE){PUSHSTATE.paused=!!want;pushFab(PUSHSTATE)}}   
function pushWord(st){
 if(st.state=='wait')return T('ag_p_wait');
 if(st.state=='skip')return T('ag_p_skip');
 if(st.state=='same')return T('ag_p_same');
 if(st.state=='ok')return T('ag_p_ok');
 if(st.state=='err')return T('upe_'+(st.err||'failed'))||T('ag_p_err');
 if(!st.step)return T('ag_p_wait');
 var w=T('ups_'+st.step);
 return num(st.sn)>1?w+' · '+T('ups_of').replace('{i}',num(st.si)).replace('{n}',num(st.sn)):w}
function pushBar(st){
 var pct=Math.max(0,Math.min(100,num(st.pct)));
 var cls=st.state=='err'?' err':((st.state=='ok'||st.state=='same')?' ok':'');
 var txt=pushWord(st);
 if(st.state=='ok'&&num(st.restarted)>0)txt+=' · '+T('ups_restarted').replace('{n}',num(st.restarted));
 return '<div class="pushbar'+cls+'"><i style="width:'+pct+'%"></i></div>'
  +'<div class="plbl"'+(st.detail?' title="'+esc(st.detail)+'"':'')+'><span>'+esc(txt)+'</span><b>'+pct+'%</b></div>'}
function pushFab(d){var box=el('pushFab');if(!box)return;
 var live=d&&!d.done;
 document.body.classList.toggle('pushing',!!live);   
 if(!live){setHTML(box,'');return}
 var ns=d.nodes||{},order=d.order||[],done=0;
 order.forEach(function(nid){var s=(ns[nid]||{}).state;
   if(s=='ok'||s=='same'||s=='err'||s=='skip')done++});
 var pz=!!d.paused;
 var stoppable=order.some(function(nid){var s=(ns[nid]||{}).state;return s=='wait'||s=='run'});
 setHTML(box,'<div class="pfab"><span class="pfn">'+num(done)+'<s>/'+num(order.length)+'</s></span>'+
   '<button class="pfb"'+(pz?' disabled':'')+' title="'+esc(T('ag_p_pause'))+'" onclick="pushPause(true)">'+ic('pause')+'</button>'+
   '<button class="pfb"'+(pz?'':' disabled')+' title="'+esc(T('ag_p_resume'))+'" onclick="pushPause(false)">'+ic('play')+'</button>'+
   '<button class="pfb stop"'+(stoppable?'':' disabled')+' title="'+esc(T(stoppable?'ag_p_cancel':'ag_p_cancel_none'))+'" onclick="pushCancel()">'+ic('xc')+'</button></div>')}
function pushPaint(d){PUSHSTATE=d;var ns=d.nodes||{};
 (d.order||[]).forEach(function(nid){var m=el('agres_'+nid),st=ns[nid];if(!m||!st)return;
   m.className='msg agres'+(st.state=='err'?' err':((st.state=='ok'||st.state=='same')?' ok':''));
   var bar=m.querySelector('.pushbar'),fill=bar&&bar.querySelector('i'),lbl=m.querySelector('.plbl');
   if(!bar||!fill||!lbl){setHTML(m,pushBar(st));return}
   var pct=Math.max(0,Math.min(100,num(st.pct)));
   bar.className='pushbar'+(st.state=='err'?' err':((st.state=='ok'||st.state=='same')?' ok':''));
   fill.style.width=pct+'%';
   var txt=pushWord(st);
   if(st.state=='ok'&&num(st.restarted)>0)txt+=' · '+T('ups_restarted').replace('{n}',num(st.restarted));
   var sp=lbl.querySelector('span'),bo=lbl.querySelector('b');
   if(sp&&sp.textContent!==txt)sp.textContent=txt;
   if(bo)bo.textContent=pct+'%';
   if(st.detail)lbl.title=st.detail;else lbl.removeAttribute('title')});
 pushFab(d)}
async function pushPoll(job){var fails=0;
 try{
  for(;;){
    var r=await j('push-status?job='+encodeURIComponent(job)+'&_='+Date.now()).catch(function(){return null});
    if(!r||!r.ok){if(++fails>=45){toast(T('ag_p_lost'),'err');return}}
    else{fails=0;pushPaint(r);if(r.done)break}
    await new Promise(function(res){setTimeout(res,400)})}
  setTimeout(function(){if(cur=='agent'||cur=='settings')refreshAgent()},4500)}
 finally{PUSHJOB=null;PUSHSTATE=null;pushFab(null)}}   
function pushSeed(ids,on){(ids||[]).forEach(function(id){var m=el('agres_'+id);if(!m)return;
 m.className='msg agres';setHTML(m,on?pushBar({state:'run',pct:0,step:'start',si:0,sn:1}):'')})}
async function pushStart(cmd,body,ids){
 pushSeed(ids,1);
 var res=await post(cmd,body);
 if(!(res.ok&&res.d)){pushSeed(ids,0);toast(perr(res),'err');return}
 if(res.d.none){pushSeed(ids,0);toast(T('ag_p_none'),'ok');return}
 if(!res.d.job){pushSeed(ids,0);toast(perr(res),'err');return}
 if(PUSHJOB)return;
 PUSHJOB=PUSH_ALL;await pushPoll(PUSH_ALL)}
async function agPush(target){if(!AGMETA||AGMETA.none){toast(T('ag_pick_first'),'err');return}
 var ids;
 if(target=='all'){var r=await j('node-names');ids=(r.nodes||[]).filter(function(n){return n.online}).map(function(n){return n.id});
  if(!ids.length){toast(T('ag_no_online'),'err');return}
  if(!await confirmBox(T('ag_confirm_all')+ids.length+T('ag_confirm_all2'),T('yes_all')))return}
 else{ids=[target]}
 await pushStart('update-agent',{ids:ids},ids)}
function refresh(){var p;if(cur=='overview')p=refreshOverview();else if(cur=='nodes')p=refreshNodes();else if(cur=='tunnels')p=refreshTunnels();else if(cur=='core')p=refreshCore();else if(cur=='proxies')p=refreshProxies();else if(cur=='portfw')p=refreshPortfw();else if(cur=='agent')p=refreshAgent();else if(cur=='logs')p=refreshLogs();else if(cur=='settings'&&el('agList'))p=refreshAgent();return Promise.resolve(p)}
function fmtEvTime(ts){var d=new Date(ts*1000);try{return d.toLocaleString('fa-IR-u-nu-latn',{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})}catch(e){return d.toISOString().slice(0,16).replace('T',' ')}}
function logsSkel(){el('view').innerHTML='<div class="sodlog"><span class="sodsweep"></span>'+
 vhead('list','logs_title','logs_sub')+
 '<div class="tbtnrow"><button class="chkall" onclick="logsClear()">'+ic('trash')+esc(T('logs_clear'))+'</button></div>'+
 toolbar('logs',T('logs_search'))+
 '<div id="logChips"></div>'+
 '<div id="logList">'+skLog()+skLog()+skLog()+skLog()+skLog()+'</div></div>';
 LOGPAINT='';markLogsSeen();refreshLogs();}   
function skLog(){return '<div class="card logcard" style="display:flex;margin-bottom:9px;padding:0;box-shadow:var(--sh-sm)">'+
 '<span class="sk" style="width:5px;flex:0 0 auto;border-radius:0"></span>'+
 '<div style="display:flex;gap:11px;align-items:flex-start;padding:12px 13px;flex:1;min-width:0">'+
   '<span class="sk" style="width:30px;height:30px;border-radius:9px;flex:0 0 auto"></span>'+
   '<div style="flex:1;min-width:0;display:flex;flex-direction:column;gap:8px"><span class="sk" style="width:62%;height:13px"></span><span class="sk" style="width:40%;height:11px"></span></div>'+
   '<span class="sk" style="width:38px;height:11px;flex:0 0 auto"></span>'+
 '</div></div>';}
function logIco(e){var k=e.kind;
 if(k=='rot'||k=='edge')return 'swap';
 if(k=='burn')return 'warn';
 if(k=='heal')return 'check';
 return e.level=='bad'?'xc':(e.level=='warn'?'warn':'okc');}
var LOGEVS=[],LOGFILTER='all',LOGSIG='',LOGQ='',LOGPAINT='',LOGSHOW=200;
var LOGPAGE=200;   
function logCounts(){var found=logFound(),c={all:found.length,tunnel:0,rot:0,ech:0,node:0,auth:0,sys:0,err:0};
 found.forEach(function(e){c[e.cat]++;if(e.level=='bad')c.err++});return c}
function logResolveFilter(){var c=logCounts();
 if(LOGFILTER!='all'&&!(c[LOGFILTER]>0))LOGFILTER='all';
 return c}
function logChipsHTML(c){
 c=c||logCounts();   
 var order=[['all','logc_all'],['tunnel','logc_tunnel'],['rot','logc_rot'],['ech','logc_ech'],['node','logc_node'],['auth','logc_auth'],['sys','logc_sys'],['err','logc_err']];
 return '<div class="logchips">'+order.filter(function(o){return o[0]=='all'||c[o[0]]>0}).map(function(o){var k=o[0];   
   return '<div class="fchip'+(LOGFILTER==k?' on':'')+'" data-f="'+k+'" data-ha="'+esc(k)+'" onclick="logFilter(hA(this))">'+esc(T(o[1]))+'<span class="ct">'+(c[k]||0)+'</span></div>';}).join('')+'</div>';}
var _lfQ=null,_lfSrc=null,_lfOut=null;
function logFound(){var q=(QRY.logs||'').trim().toLowerCase();
 if(!q)return LOGEVS;
 if(q===_lfQ&&LOGEVS===_lfSrc)return _lfOut;   
 _lfQ=q;_lfSrc=LOGEVS;
 return (_lfOut=LOGEVS.filter(function(e){return ((e.fa||'')+' '+(e.dfa||'')).toLowerCase().indexOf(q)>=0}))}
function logRows(){
 var all=logFound().filter(function(e){return LOGFILTER=='all'?true:LOGFILTER=='err'?e.level=='bad':e.cat==LOGFILTER;});
 if(!all.length)return [{k:'__empty',h:'<div class="card muted">'+esc(T('logs_no_match'))+'</div>'}];
 var evs=all.slice(0,LOGSHOW),rest=all.length-evs.length;
 var rows=evs.map(function(e){
   var k=evKey(e);
   return {k:k,h:sodEvent(e,k)}});
 if(rest>0)rows.push({k:'__more',h:'<div class="card muted logmore" role="button" tabindex="0" onclick="logMore()" onkeydown="logMoreKey(event)">'+
   esc(T('logs_more').replace('{n}',rest))+'</div>'});
 return rows}
var SOD_LEAD=3,SOD_INLINE_MAX=34;
function sodLevel(e){return e.level=='bad'?'bad':(e.level=='warn'?'warn':'ok')}
function sodSentence(title,notes){
 var t=String(title||'').trim();
 for(var i=0;i<notes.length;i++){
  var nx=String(notes[i]||'').trim();
  if(!nx)continue;
  t+=(/[.!\u061F\u06D4]$/.test(t)?' ':' \u2014 ')+nx;
 }
 return t}
function sodEvent(e,k){
 var p=evParts(e),sp=evSplit(p.lines);
 var lead=[],rest=[];
 sp.rows.forEach(function(r){
  if(lead.length<SOD_LEAD&&String(r.v).length<=SOD_INLINE_MAX)lead.push(r);else rest.push(r)});
 var sen='<div class="ssen">'+esc(sodSentence(p.title,sp.notes))+'</div>';
 if(lead.length)sen+='<div class="svals">'+lead.map(function(r){
  return '<span class="sp"><span class="sk2">'+esc(r.k)+'</span><span class="sval">'+esc(r.v)+'</span></span>'}).join('')+'</div>';
 var fold='';
 if(rest.length){
  fold='<div class="sfold">'+rest.map(function(r){
   return '<div class="sr"><b>'+esc(r.k)+'</b><span>'+esc(r.v)+'</span></div>'}).join('')+'</div>'+
   '<span class="smore"><span class="more">'+esc(T('sod_more'))+'</span>'+
   '<span class="less">'+esc(T('sod_less'))+'</span></span>';
 }
 var tap=rest.length?(' sodtap'+(LOGOPEN[k]?' open':'')+'" role="button" tabindex="0" aria-expanded="'+
   (LOGOPEN[k]?'true':'false')+'" data-ha="'+esc(k)+'" onclick="logFold(hA(this),event)" onkeydown="logKey(event,hA(this))'):'';
 return '<div id="lf'+esc(k)+'" class="sodev '+sodLevel(e)+tap+'">'+
   '<span class="sbar"></span>'+
   '<div><div class="shead"><span class="slv">'+esc(T('sod_'+sodLevel(e)))+'</span>'+
     '<span class="stime">'+esc(fmtEvTime(e.ts))+'</span></div>'+
     sen+fold+'</div></div>'}
function logMore(){LOGSHOW+=LOGPAGE;logPaint()}
function logMoreKey(e){if(e.key===' '||e.key==='Enter'){e.preventDefault();logMore()}}
function evKey(e){var s=(e.ts||0)+'|'+(e.fa||'')+'|'+(e.dfa||''),h=0;
 for(var i=0;i<s.length;i++)h=((h<<5)-h+s.charCodeAt(i))|0;
 return 'k'+(h>>>0);}
function logFilter(k){LOGFILTER=k;logPaint()}
function logPaint(){
 var box=el('logList');if(!box)return;
 if(LOGSIG+'|'+LOGFILTER+'|'+(QRY.logs||'')+'|'+LOGSHOW===LOGPAINT)return;
 var counts=logResolveFilter();     
 var q=LOGFILTER+'|'+(QRY.logs||'');
 if(q!==LOGQ){LOGQ=q;LOGSHOW=LOGPAGE}
 LOGPAINT=LOGSIG+'|'+q+'|'+LOGSHOW;
 var ch=el('logChips');
 if(!LOGEVS.length){if(ch)ch.innerHTML='';setList(box,[{k:'__empty',h:'<div class="card muted">'+esc(T('logs_empty'))+'</div>'}]);return}
 if(ch){var old=ch.querySelector('.logchips'),sl=old?old.scrollLeft:0;ch.innerHTML=logChipsHTML(counts);var nw=ch.querySelector('.logchips');if(nw)nw.scrollLeft=sl}
 setList(box,logRows())}
function evParts(e){
 var det=e.dfa||'';
 return{title:e.fa||'',lines:det?det.split('\\n'):[]};
}
function evEndpoints(v){var p=v.split(' ← ');
 if(p.length!=2)return esc(v);
 return '<span class="ep">'+esc(p[0])+'</span><span class="ep-a">←</span><span class="ep">'+esc(p[1])+'</span>';}
function evSplit(lines){var rows=[],notes=[];
 for(var i=0;i<(lines||[]).length;i++){var l=lines[i],c=l.indexOf(': ');
  var k=c>0?l.slice(0,c):'';
  if(k&&k.length<=16&&!/[\u060C\u061B\u061F.!?()\u00AB\u00BB\u2014]/.test(k))rows.push({k:k,v:l.slice(c+2)});
  else notes.push(l);}
 return {rows:rows,notes:notes}}
function evFolds(lines){return evSplit(lines).rows.length>0}
function evDetail(lines,id){if(!lines||!lines.length)return '';
 var sp=evSplit(lines),rows=sp.rows,notes=sp.notes;
 var out='';
 if(rows.length)out+='<div class="lfromto">'+rows.map(function(m){
   return '<div class="lft'+(m.k=='\u0628\u0647'?' to':'')+'"><span class="k">'+esc(m.k)+':</span>'+
          '<span class="v">'+evEndpoints(m.v)+'</span></div>'}).join('')+'</div>';
 for(var j=0;j<notes.length;j++)out+='<div class="lnote" dir="auto">'+esc(notes[j])+'</div>';
 if(!rows.length)return out;
 return '<div class="lfold'+(LOGOPEN[id]?' open':'')+'" id="lf'+id+'">'+
   '<div class="lfbody">'+out+'</div></div>';}
var LOGOPEN={};
function logFold(id,e){
 try{if(window.getSelection&&String(window.getSelection())!=='')return}catch(_){}
 LOGOPEN[id]=!LOGOPEN[id];
 var b=el('lf'+id);if(b)b.classList.toggle('open',!!LOGOPEN[id]);
 var c=e&&e.currentTarget;if(c&&c.setAttribute)c.setAttribute('aria-expanded',LOGOPEN[id]?'true':'false');}
function logKey(e,id){if(e.key===' '||e.key==='Enter'){e.preventDefault();logFold(id,e)}}

async function refreshLogs(){
 if(!el('logList'))return;
 var sig=EVSEQ+':'+LOGN;
 if(sig!==LOGSIG){
  var r=await j('events').catch(function(){return null});
  if(r&&r.events){LOGEVS=r.events;LOGSIG=sig}}
 logPaint()}
async function logsClear(){if(!await confirmBox(T('logs_clear_confirm')))return;var r=await post('events-clear',{});
 if(!(r.ok&&r.d&&r.d.ok)){toast(perr(r),'err');return}
 toast(T('logs_cleared'),'ok');
 LOGEVS=[];LOGSIG='';LOGPAINT='';refreshLogs();}
function render(){setnav();RMSG={};setLS('tnl_page',cur);
 if(cur=='overview')overviewSkel();else if(cur=='nodes')nodesSkel();else if(cur=='tunnels')tunnelsSkel();else if(cur=='core')coreSkel();else if(cur=='proxies'){proxiesSkel();return}else if(cur=='portfw'){portfwSkel();return}else if(cur=='agent'){agentSkel();return}else if(cur=='logs'){logsSkel();return}else if(cur=='settings'){settingsSkel();refreshSettings();return}
 refresh()}
function refreshFleet(){return cur=='core'?refreshCore():refreshTunnels()}
function settingsSkel(){el('view').innerHTML=vhead('cog','nav_settings','set_sub')+'<div id="setBox" class="stpage"><div class="card muted">'+esc(T('loading'))+'</div></div>'}
var _setMode='alert',_modeOv=null;
function modeLabel(m){return m=='auto'?T('set_mode_auto'):T('set_mode_alert')}
async function refreshSettings(){var s=await j('settings').catch(function(){return{}});var box=el('setBox');if(!box)return;
 _setMode=(s.reconcile_mode=='auto')?'auto':'alert';
 box.innerHTML='<div class="stgrid">'+settingsGroups(s)+'</div>'+saveBar()+
  '<div class="sec" style="margin-top:16px">'+ic('redo','var(--acc)')+' '+esc(T('set_agent_update'))+'</div>'+agentBody();
 tunPmBind();refreshAgent()}
function tgExp(b){var r=b.closest('.sr');var o=r.classList.toggle('exp-open');b.setAttribute('aria-expanded',o?'true':'false');b.textContent=o?'×':'؟'}
function qr(lbl,ck,xk,ctl){return '<div class="sr"><div class="srtop"><b class="srlbl">'+lbl+'</b><button type="button" class="srq" onclick="tgExp(this)" aria-expanded="false">؟</button><div class="srctl">'+ctl+'</div></div><div class="srexp"><p>'+T(ck)+'</p><p class="srex">'+T(xk)+'</p></div></div>'}
function sgCard(icn,tk,ck,cls,rows){return '<div class="card sg '+cls+'"><div class="sghd"><span class="sgt">'+ic(icn)+'</span><b>'+T(tk)+'</b><span class="schip">'+T(ck)+'</span></div><div class="sgb">'+rows+'</div></div>'}
function saveBar(){return '<p class="stnote">'+esc(T('set_apply_note'))+'</p>'+
 '<div class="stsave">'+
 '<button class="ghost" onclick="resetSettings()">'+ic('reset')+esc(T('set_reset'))+'</button>'+
 '<button class="primary" onclick="saveSettings()">'+ic('check')+esc(T('save'))+'</button>'+
 '<span class="msg" id="set_msg"></span></div>'}
function _sv(s,k){return (s&&s[k]!=null&&s[k]!=='')?s[k]:_SETDEF[k]}
function _tv(s,k){var t=(s&&s.tuning)||{};return (t[k]!=null?t[k]:_TUNDEF[k])}
function _tvMin(s,k){return Math.max(1,Math.round(num(_tv(s,k))/60))}
function _minSec(x){var n=parseInt(x);return n>=1?n*60:NaN}
function tNum(id,val,mn,mx,st){return '<input id="'+id+'" class="search" type="number" step="'+(st||1)+'" min="'+mn+'" max="'+mx+'" value="'+esc(String(val))+'">'}
function settingsGroups(s){
 var panel=
  qr(T('set_on_ipchange'),'set_on_ipchange_d','set_x_ipchange','<button type="button" class="setfield" onclick="openModePopup()"><span class="val" id="set_mode_val">'+modeLabel(_setMode)+'</span><span class="cv">'+ic('chev')+'</span></button>')+
  qr(T('set_rec_int'),'set_rec_range','set_x_rec','<input id="set_rec" class="search" type="number" min="5" max="3600" value="'+esc(String(_sv(s,'reconcile_interval')))+'">')+
  qr(T('set_poll_int'),'set_poll_range','set_x_poll','<input id="set_poll" class="search" type="number" step="0.1" min="0.3" max="60" value="'+esc(String(_sv(s,'poll_interval')))+'">')+
  qr(T('set_ui_int'),'set_ui_range','set_x_ui','<input id="set_ui" class="search" type="number" step="0.1" min="0.3" max="60" value="'+esc(String(_sv(s,'ui_interval')))+'">')+
  qr(T('set_ech_int'),'set_ech_range','set_x_ech','<input id="set_ech" class="search" type="number" step="1" min="0" max="1440" value="'+esc(String(_sv(s,'ech_refresh_mins')))+'">')+
  qr(T('set_upwin'),'set_upwin_d','set_x_upwin',ssHTML('set_upwin',[{v:'1',label:T('h1')},{v:'3',label:T('h3')},{v:'6',label:T('h6')},{v:'8',label:T('h8')},{v:'12',label:T('h12')},{v:'24',label:T('h24')}],String(_sv(s,'uptime_window')),'',''));
 var conn=
  qr(T('set_t_minlive'),'set_t_minlive_d','set_x_minlive',tNum('set_t_minlive',_tv(s,'min_liveness_secs'),1,3600))+
  qr(T('set_t_probemin'),'set_t_probemin_d','set_x_probemin',tNum('set_t_probemin',_tv(s,'probe_min_pct'),5,100,5))+
  '<p class="srnote" id="tun_pmhint"></p>'+
  qr(T('set_t_revive'),'set_t_revive_d','set_x_revive','<input id="set_t_revive" class="search wtxt" type="text" inputmode="numeric" value="'+esc(_tv(s,'ladder_revive').join(', '))+'">');
 var pool=
  qr(T('set_t_suspect'),'set_t_suspect_d','set_x_suspect','<input id="set_t_suspect" class="search wtxt" type="text" inputmode="numeric" value="'+esc(_tv(s,'suspect_backoff').map(function(x){return Math.max(1,Math.round(num(x)/60))}).join(', '))+'">')+
  qr(T('set_t_deadretest'),'set_t_deadretest_d','set_x_deadretest',tNum('set_t_deadretest',_tvMin(s,'dead_retest_secs'),1,1440));
 var perf=
  qr(T('set_t_sockbuf'),'set_t_sockbuf_d','set_x_sockbuf',tNum('set_t_sockbuf',_tv(s,'sock_buf_mb'),0,64));
 return sgCard('cog','set_g1','set_g1c','sc-panel',panel)+
  sgCard('activity','set_gkd','set_gkdc','sc-conn',conn)+
  sgCard('redo','set_g2','set_g2c','sc-pool',pool)+
  sgCard('bolt','set_g5','set_g5c','sc-perf',perf)}
function _collectTuning(){
 var sb=(v('set_t_suspect')||'').split(',').map(function(x){return _minSec(x.trim())}).filter(function(n){return !isNaN(n)});
 var rv=(v('set_t_revive')||'').split(',').map(function(x){return parseInt(x.trim(),10)}).filter(function(n){return !isNaN(n)});
 var t={dead_retest_secs:_minSec(v('set_t_deadretest')),min_liveness_secs:parseInt(v('set_t_minlive')),probe_min_pct:parseInt(v('set_t_probemin')),sock_buf_mb:parseInt(v('set_t_sockbuf'))};
 if(sb.length)t.suspect_backoff=sb;
 if(rv.length)t.ladder_revive=rv;
 return t}
function tunStepBad(t){for(var k in _TUNSTEP){var s=_TUNSTEP[k][0];
  if(s&&typeof t[k]=='number'&&!isNaN(t[k])&&t[k]%s)
   return T('set_step_bad').replace('{f}',_TUNSTEP[k][1]).replace('{s}',s).replace('{v}',t[k]);}
 return ''}
function tunPmSync(){var p=el('set_t_probemin'),h=el('tun_pmhint');if(!p||!h)return;
 var v=Math.max(5,Math.min(100,parseInt(p.value)||0));   
 h.textContent=T('set_pm_hint').replace('{n}',Math.ceil(v*_PROBESAMP/100)).replace('{c}',_PROBESAMP)}
function tunPmBind(){var p=el('set_t_probemin');if(p)p.addEventListener('input',tunPmSync);
 tunPmSync()}
async function resetSettings(){if(!await confirmBox(T('set_reset_confirm'),T('set_reset_yes')))return;
 var b={tuning:_TUNDEF};for(var k in _SETDEF)b[k]=_SETDEF[k];
 var r=await post('settings-set',b);
 if(r.ok&&r.d.ok){toast(T('set_saved'),'ok');refreshSettings()}
 else{toast(perr(r),'err')}}
function openModePopup(){var opt=function(m,df){return '<div class="mopt'+(_setMode==m?' on':'')+'" data-ha="'+esc(m)+'" onclick="pickMode(hA(this))"><span class="mrad"></span><span class="mt">'+modeLabel(m)+'</span>'+(df?'<span class="mdf">'+esc(T('set_default'))+'</span>':'')+'</div>'};
 _modeOv=openModal('<div class="modelist">'+opt('auto',false)+opt('alert',true)+'</div>',{cls:'modesheet'})}
function pickMode(m){_setMode=m;setT('set_mode_val',modeLabel(m));if(_modeOv){closeModal(_modeOv);_modeOv=null}}
async function saveSettings(){var m=el('set_msg');
 var tun=_collectTuning(),bad=tunStepBad(tun);
 if(bad){if(m)formErr(m,bad);return}
 if(m){m.className='msg';m.textContent=T('saving')}
 var r=await post('settings-set',{reconcile_mode:_setMode,reconcile_interval:v('set_rec'),poll_interval:v('set_poll'),ui_interval:v('set_ui'),ech_refresh_mins:v('set_ech'),uptime_window:ssVal('set_upwin'),tuning:tun});
 if(r.ok&&r.d.ok){if(m){m.className='msg';m.textContent=''}toast(T('set_saved'),'ok')}
 else{if(m){formErr(m,perr(r))}}}
function tick(){if(document.hidden){clearTimeout(TT);TT=setTimeout(tick,Math.max(UIV,4000));return}  
 updateSidebar();refreshActs().catch(function(){});
 refresh().catch(function(){}).then(function(){clearTimeout(TT);TT=setTimeout(tick,UIV)})}
document.addEventListener('visibilitychange',function(){if(!document.hidden){clearTimeout(TT);tick()}});
document.addEventListener('keydown',function(e){if(e.key!='Enter'&&e.key!=' ')return;
 var h=e.target&&e.target.closest&&e.target.closest('[data-acc]');if(!h)return;
 e.preventDefault();h.click()});
document.addEventListener('keydown',function(e){if(!((e.ctrlKey||e.metaKey)&&(e.key=='k'||e.key=='K')))return;
 if(PAL){e.preventDefault();closePal();return}
 var tn=e.target&&e.target.tagName;
 if(tn=='INPUT'||tn=='SELECT'||tn=='TEXTAREA'||document.querySelector('.modalov'))return;  
 e.preventDefault();openPal()});
function openPal(){if(PAL)return;var ov=document.createElement('div');ov.className='modalov palov';
 ov.innerHTML='<div class="pal"><div class="palin">'+ic('search')+'<input id="pal_q" placeholder="'+esc(T('pal_search'))+'" autocomplete="off"><kbd>Esc</kbd></div><div class="pallist" id="pal_list"></div><div class="palfoot"><span><kbd>↑</kbd><kbd>↓</kbd> '+esc(T('pal_move'))+'</span><span><kbd>↵</kbd> '+esc(T('pal_pick'))+'</span><span><kbd>Esc</kbd> '+esc(T('pal_close'))+'</span></div></div>';
 document.body.appendChild(ov);PAL=ov;try{document.body.style.overflow='hidden'}catch(e){}
 ov.addEventListener('mousedown',function(e){if(e.target===ov)closePal()});
 var inp=el('pal_q');inp.addEventListener('input',function(){palRender(inp.value)});inp.addEventListener('keydown',palKey);
 PALDATA={nodes:[],tuns:[]};
 j('node-names').then(function(r){PALDATA.nodes=r.nodes||[];palRender(inp.value)}).catch(function(){});
 j('fleet?limit=100').then(function(r){PALDATA.tuns=r.links||[];palRender(inp.value)}).catch(function(){});
 palRender('');inp.focus()}
function closePal(){if(!PAL)return;PAL.remove();PAL=null;try{if(!document.querySelector('.modalov'))document.body.style.overflow=''}catch(e){}}
function palNav(p){cur=p;closePal();render()}
function palActions(){return [
 {i:'dash',label:T('nav_overview'),act:function(){palNav('overview')}},{i:'server',label:T('nav_nodes'),act:function(){palNav('nodes')}},
 {i:'link',label:T('nav_tunnels'),act:function(){palNav('tunnels')}},{i:'globe',label:T('nav_portfw'),act:function(){palNav('portfw')}},
 {i:'plus',label:T('pal_add_tun'),act:function(){cur='tunnels';closePal();render();setTimeout(openCreateModal,300)}},{i:'redo',label:T('pal_agent'),act:function(){palNav('agent')}},
 {i:'activity',label:T('pal_checkall'),act:function(){cur='tunnels';closePal();render();setTimeout(function(){if(window.checkAll)checkAll()},600)}},
 {i:document.body.classList.contains('dark')?'sun':'moon',label:T('pal_theme'),act:function(){closePal();toggleTheme()}}]}
function palRender(q){q=(q||'').trim().toLowerCase();
 var nodes=(PALDATA.nodes||[]).filter(function(n){return !q||n.name.toLowerCase().indexOf(q)>=0||(n.host||'').indexOf(q)>=0}).slice(0,6)
  .map(function(n){return {i:'server',label:esc(n.name),sub:esc(n.host),act:function(){cur='nodes';QRY.nodes=n.name;closePal();render()}}});
 var tuns=(PALDATA.tuns||[]).filter(function(l){return !q||((l.a_name||'')+' '+(l.b_name||'')+' '+(l.name||'')+' '+(l.type||'')).toLowerCase().indexOf(q)>=0}).slice(0,6)
  .map(function(l){return {i:'link',label:esc(l.a_name)+' ↔ '+esc(l.b_name),sub:esc(l.name),act:function(){var pg=(l.type=='core')?'core':'tunnels';cur=pg;QRY[pg]=l.name;closePal();render()}}});
 var acts=palActions().filter(function(a){return !q||a.label.toLowerCase().indexOf(q)>=0});
 var groups=[[T('pal_g_nodes'),nodes],[T('pal_g_tuns'),tuns],[T('pal_g_acts'),acts]];PALITEMS=[];var html='';
 groups.forEach(function(g){if(!g[1].length)return;html+='<div class="palsec">'+g[0]+'</div>';
  g[1].forEach(function(it){var idx=PALITEMS.length;PALITEMS.push(it);
   html+='<div class="palrow" data-ha="'+idx+'" onmouseenter="palHover(this)" onclick="palGo(hA(this))"><span class="gi">'+ic(it.i)+'</span>'+it.label+(it.sub?'<span class="sub mono">'+it.sub+'</span>':'')+'</div>'})});
 if(!PALITEMS.length)html='<div class="palrow" style="cursor:default;color:var(--sub)">'+esc(T('pal_none'))+'</div>';
 var lst=el('pal_list');if(lst)lst.innerHTML=html;PALIDX=0;palHi()}
function palHi(){document.querySelectorAll('#pal_list .palrow').forEach(function(r,i){r.classList.toggle('sel',i==PALIDX)})}
function palHover(e){PALIDX=+hA(e);palHi()}
function palGo(i){var it=PALITEMS[+i];if(it&&it.act)it.act()}
function palKey(e){if(e.key=='ArrowDown'){e.preventDefault();PALIDX=Math.min(PALIDX+1,PALITEMS.length-1);palHi();palSc()}
 else if(e.key=='ArrowUp'){e.preventDefault();PALIDX=Math.max(PALIDX-1,0);palHi();palSc()}
 else if(e.key=='Enter'){e.preventDefault();palGo(PALIDX)}else if(e.key=='Escape'){e.preventDefault();closePal()}}
function palSc(){var r=document.querySelectorAll('#pal_list .palrow')[PALIDX];if(r)r.scrollIntoView({block:'nearest'})}
(async function(){var p=getLS('tnl_page');
 if(['overview','nodes','proxies','tunnels','core','portfw','logs','settings','agent'].indexOf(p)>=0)cur=p;
 await loadReadiness();
 if(RDY&&!RDY.ok)cur='settings';
 render();updateSidebar();
 refreshActs().catch(function(){});   
 TT=setTimeout(tick,6000)})();
</script></body></html>"""

INDEX_HTML = INDEX_HTML.replace("__TUNDEF_JSON__", json.dumps(_TUNING_DEFAULTS, separators=(",", ":")))
INDEX_HTML = INDEX_HTML.replace("__TUNSTEP_JSON__", json.dumps(_TUNING_STEPS, ensure_ascii=False, separators=(",", ":")))
INDEX_HTML = INDEX_HTML.replace("__PROBE_SAMPLES__", str(_PROBE_SAMPLES))
INDEX_HTML = INDEX_HTML.replace("__LOGKEEPH__", str(EVENTS_TTL // 3600))
INDEX_HTML = INDEX_HTML.replace("__LOGMAX__", str(EVENTS_MAX))
INDEX_HTML = INDEX_HTML.replace("__SETDEF_JSON__", json.dumps(
    {k: v for k, v in settings_defaults().items() if k != "tuning"}, separators=(",", ":")))
INDEX_HTML = INDEX_HTML.replace("__ENUMS_JSON__", json.dumps(
    {"ciphers": list(CORE_CIPHERS), "tr_all": list(CORE_TRANSPORTS), "tr_direct": list(DIRECT_TRANSPORTS),
     "raw_protos": {k: v for k, v in CORE_RAW_PROFILE_PROTOS.items() if k != "bare"},
     "edge_ports": {"tls": list(_EDGE_TLS_PORTS), "plain": list(_EDGE_PLAIN_PORTS)}},
    separators=(",", ":")))
INDEX_HTML = INDEX_HTML.replace("__SPLITTTLMAX__", str(SPLIT_TTL_MAX))
INDEX_HTML = INDEX_HTML.replace("__WORKERSMAX__", str(CORE_MAX_WORKERS))


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
    conf["secret"] = secrets.token_hex(32)
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
    if os.path.realpath(SELF_PATH) != INSTALLED:
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
    conf = load_conf() if os.path.isfile(WEB_CONF) else {}
    conf["port"] = int(input(f"Panel port [{conf.get('port', 8080)}]: ").strip() or conf.get("port", 8080))
    set_password(conf)
    write_service()
    svc("enable")
    svc("restart")
    try:
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


_BUSY_BODY = json.dumps({"error": "پنل شلوغ است — چند لحظه بعد دوباره"}, ensure_ascii=False).encode()
_BUSY_RESP = (b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\n"
              b"Content-Length: " + str(len(_BUSY_BODY)).encode() +
              b"\r\nConnection: close\r\n\r\n" + _BUSY_BODY)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128
    _MAX_WORKERS = 256
    _sem = threading.BoundedSemaphore(_MAX_WORKERS)

    def _refuse(self, request):
        try:
            request.sendall(_BUSY_RESP)
            request.setblocking(False)
            for _ in range(4):
                if not request.recv(65536):
                    break
        except OSError:
            pass
        self.shutdown_request(request)

    def process_request(self, request, client_address):
        if not self._sem.acquire(blocking=False):
            self._refuse(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._sem.release()
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
    global _CENTRAL_PORT, _CENTRAL_TLS
    _CENTRAL_PORT = int(conf.get("port", 8080))
    _CENTRAL_TLS = bool(conf.get("tls"))
    _seed_settings()
    try:
        _signing_keys()
    except Exception as e:
        print(f"warning: could not init signing key (openssl missing?): {e}")
    _tf_load()
    _uh_load()
    checkin_ctr_load()
    threading.Thread(target=poller_loop, daemon=True).start()
    threading.Thread(target=traffic_persist_loop, daemon=True).start()
    threading.Thread(target=reconcile_loop, daemon=True).start()
    threading.Thread(target=events_loop, daemon=True).start()
    threading.Thread(target=ech_refresh_loop, daemon=True).start()
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
