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
UI_DIR = os.path.join(CENTRAL_DIR, "ui")
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
CORE_TRANSPORTS       = ("udp", "tcp", "raw", "ws")
SOCKBUF_TRANSPORTS    = ("udp", "raw")
MIN_ROTATE_SECS       = 10
DIRECT_TRANSPORTS     = ("udp", "tcp", "raw")
PORT_RUNG_TRANSPORTS  = ("udp", "tcp", "ws")
PORTED_RAW_PROFILES   = ("udp", "tcp")
DATAGRAM_TRANSPORTS   = ("udp", "raw")
DESYNC_TRANSPORTS     = ("raw", "tcp", "ws")
DESYNC_INJECT_TTL_MAX = 8
SPLIT_TTL_MAX = DESYNC_INJECT_TTL_MAX
CORE_MAX_WORKERS = 8
QUEUEING_TRANSPORTS = ("raw", "udp")
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
                      "probe_min_pct": "حداقلِ بسته‌های برگشتی",
                      "sock_buf_mb": "بافرِ سوکت"}
_TUNING_RANGES = {
    "dead_retest_secs": (5, 86400),
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
        "log_hidden": [],
        "api_external": False,
        "api_token_hash": "",
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
    if "api_external" in d:
        out["api_external"] = bool(d["api_external"])
    if "dl_proxy_on" in d or "dl_proxy_id" in d:
        on = bool(d.get("dl_proxy_on", out.get("dl_proxy_on")))
        pid = str(d.get("dl_proxy_id", out.get("dl_proxy_id")) or "").strip()
        if on:
            if not pid:
                raise ValueError("یک پروکسی از فهرست انتخاب کن")
            if not get_proxy(pid):
                raise ValueError("پروکسی پیدا نشد — شاید حذف شده باشد")
        out["dl_proxy_on"], out["dl_proxy_id"] = on, pid if on else ""
    if "log_hidden" in d:
        raw = d["log_hidden"]
        if not isinstance(raw, list):
            raise ValueError("فهرستِ فیلترِ لاگ باید یک آرایه باشد")
        picked = {str(x) for x in raw}
        bad = sorted(picked - set(EV_TYPE_GROUP))
        if bad:
            raise ValueError("این نوعِ رویداد را نمی‌شناسم: " + "، ".join(bad))
        out["log_hidden"] = [t for t, _g, _fa in EV_TYPES if t in picked]
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
        _moved[nid] = {"to": new, "to_port": new_port}
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


_EV_END_MISSING = {"srv": "نودِ سرورِ این تونل پیدا نشد",
                   "cli": "نودِ کلاینتِ این تونل پیدا نشد"}


def _srv_is_a(L):
    return L.get("server_side") != "b"


def _node_id_of(L, end):
    return L.get("a_node") if (end == "srv") == _srv_is_a(L) else L.get("b_node")


def _client_node(L):
    return get_node(_node_id_of(L, "cli"))


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
    "ping": "pg", "list": "ls", "check": "ck", "tunnel": "mk", "delete": "dl",
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
        _pc[n["id"]] = {"ping": ping, "list": lst}
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
                    "sport_lo", "sport_hi", "conntrack_bypass", "port_tries", "a_workers", "b_workers",
                    "fec", "fec_data", "fec_parity", "ws_host", "ws_path", "ws_tls",
                    "sni_split", "split_pos", "sni_mode", "split_ttl", "cdn_carrier",
                    "http_up_workers", "http_up_batch_kb", "http_streams", "http_up_rate",
                    "ech", "ws_ech", "ech_proxy", "ech_proxy_id", "edge_ip", "ws_pool",
                    "ws_edge_ips", "ws_edge_snis",
                    "ws_rotate_secs", "gso",
                    "fake_desync", "fake_ttl", "fake_count", "fake_mode") + _ROTATION_KEYS


_PANEL_ONLY_KEYS = ("ech_proxy", "ech_proxy_id", "ech", "ws_pool")


def _node_extra(extra):
    e = dict(extra)
    skip = _ROTATION_KEYS + _WORKERS_KEYS + _PANEL_ONLY_KEYS
    return {k: v for k, v in e.items() if k not in skip}


def _rotate_secs(raw, hi, what):
    try:
        n = int(raw or 0)
    except (TypeError, ValueError):
        raise ValueError("«%s» باید عدد باشد" % what)
    if n < 0 or n > hi:
        raise ValueError("«%s» باید بین 0 تا %d ثانیه باشد" % (what, hi))
    if 0 < n < MIN_ROTATE_SECS:
        raise ValueError("«%s» یا 0 است (فقط روی خرابی) یا دستِ‌کم %d ثانیه — زیرِ آن پروب فرصتِ قضاوت ندارد و هسته بالا نمی‌آید" % (what, MIN_ROTATE_SECS))
    return n


def _apply_core_rotation(body, is_client, own_pool, peer_pool, rotate_secs):
    if is_client:
        if len(peer_pool) >= 2:
            body["peer_ips"] = list(peer_pool)
        if len(own_pool) >= 2:
            body["src_ips"] = list(own_pool)
        body["peer_rotate_secs"] = rotate_secs
        return
    if len(own_pool) >= 2:
        body["pool_listen"] = True
        if body.get("transport") in ("udp", "tcp"):
            body["listen_ips"] = list(own_pool)
    if len(peer_pool) >= 2 and body.get("transport") == "raw":
        body["peer_src_ips"] = list(peer_pool)


def _core_rotation_bodies(src, a_body, b_body, a_ips=None, b_ips=None):
    if not src.get("ip_rotate") or src.get("transport") not in DIRECT_TRANSPORTS:
        return
    ap, bp = list(src.get("a_ip_pool") or []), list(src.get("b_ip_pool") or [])
    if a_ips is not None:
        ap = [x for x in ap if x in a_ips]
    if b_ips is not None:
        bp = [x for x in bp if x in b_ips]
    if len(ap) < 2 and len(bp) < 2:
        return
    rs = int(src.get("rotate_secs") or 0)
    _apply_core_rotation(a_body, a_body.get("role") == "client", ap, bp, rs)
    _apply_core_rotation(b_body, b_body.get("role") == "client", bp, ap, rs)


def _core_workers_bodies(src, a_body, b_body):
    for body, key in ((a_body, "a_workers"), (b_body, "b_workers")):
        n = _link_workers(src, key)
        if n > 1:
            body["workers"] = n


def _apply_core_tuning(a_body, b_body):
    tn = _settings_tuning()
    if "sock_buf_mb" in tn and a_body.get("transport") in SOCKBUF_TRANSPORTS:
        _mb = max(0, min(64, int(tn["sock_buf_mb"])))
        a_body["sock_buf"] = b_body["sock_buf"] = -1 if _mb == 0 else _mb * (1 << 20)
    _tn = {k: v for k, v in tn.items()
           if k not in ("sock_buf_mb", "probe_min_pct")}
    if _tn:
        for body in (a_body, b_body):
            if body.get("role") == "client":
                body["tuning"] = _tn


def _apply_probe_tuning(*bodies):
    tn = _settings_tuning()
    if "probe_min_pct" not in tn:
        return
    lo, hi = _TUNING_RANGES["probe_min_pct"]
    v = max(lo, min(hi, int(tn["probe_min_pct"])))
    for b in bodies:
        b["probe_min_pct"] = v


HTTP_SHAPE = {"http_up_workers": (1, 16, 8), "http_up_batch_kb": (8, 512, 512),
              "http_up_rate": (0, 1000, 0), "http_streams": (1, 16, 1)}
HTTP_SHAPE_GRPC = ("http_streams",)


def _ech_or_stored(host, fetched, stored):
    if fetched:
        return fetched
    if stored:
        log_event("warn", "ech-stale",
                  "کلیدِ ECH برای «%s» تازه خوانده نشد" % host,
                  "رکوردِ HTTPS/ech= در دسترس نبود؛ کلیدِ ذخیره‌شده به کار رفت. اگر کلاودفلر"
                  " کلید را چرخانده باشد این تونل تا خواندنِ بعدی بالا نمی‌آید.")
        return stored
    log_event("warn", "ech-stale",
              "کلیدِ ECH برای «%s» نه تازه خوانده شد نه ذخیره‌ای دارد" % host,
              "این تونل بدونِ ECH بالا می‌آید، یعنی SNI در روشناییِ روز می‌رود. تا وقتی رکوردِ"
              " HTTPS/ech= دوباره خوانده شود همین‌طور می‌ماند.")
    return ""


def _tunnel_extra(src):
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
    if src.get("sport_lo") and src.get("sport_hi"):
        e["sport_lo"] = src["sport_lo"]
        e["sport_hi"] = src["sport_hi"]
    if src.get("conntrack_bypass"):
        e["conntrack_bypass"] = True
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
        _cdn = _cdn_carrier(src, None)
        e["cdn_carrier"] = _cdn
        e.update(_cdn_shape_fields(src, None, _cdn))
    if src.get("ech"):
        host = src.get("ws_host")
        if host:
            e["ws_ech"] = _ech_or_stored(host, _fetch_ech(host, _ech_px(src)), src.get("ws_ech"))
        elif src.get("ws_ech"):
            e["ws_ech"] = src["ws_ech"]
    if src.get("edge_ip"):
        e["edge_ip"] = src["edge_ip"]
    if src.get("ws_pool") and src.get("ws_edge_ips") and src.get("ws_edge_snis"):
        e["ws_tls"] = True
        e["ws_edge_ips"] = src["ws_edge_ips"]
        pool_ech = bool(src.get("ech"))
        hosts = [s.get("host") for s in src["ws_edge_snis"] if isinstance(s, dict) and s.get("host")]
        ech_map = _fetch_ech_map(hosts, _ech_px(src)) if pool_ech else {}
        psnis = []
        for s in src["ws_edge_snis"]:
            if not (isinstance(s, dict) and s.get("host")):
                continue
            h = s.get("host")
            ec = _ech_or_stored(h, ech_map.get(h, ""), s.get("ech")) if pool_ech else ""
            psnis.append({"host": h, "ech": ec, "path": s.get("path") or src.get("ws_path") or "/"})
        e["ws_edge_snis"] = psnis
        _rs = src.get("ws_rotate_secs")
        e["ws_rotate_secs"] = int(_rs) if _rs is not None else 600
    if src.get("gso"):
        e["gso"] = True
    return _node_extra(_carried(e, _shape_of({}, src)))


def _core_role(L, node_id):
    if L.get("type") != "core":
        return None
    return "server" if node_id == _node_id_of(L, "srv") else "client"


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
            heat.append({"name": nm, "pct": None, "online": False})
            if _cache_get(nid):
                alerts.append({"level": "bad", "kind": "node", "msg": f"نودِ «{nm}» آفلاین است"})
            mv = moved_to(nid)
            if mv:
                alerts.append({"level": "warn", "kind": "node",                                "msg": f"نودِ «{nm}» از {mv} جواب می‌دهد — هوستش را عوض کن"})
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
                worst[key] = {"name": nm, "pct": val}
            if val >= UP_CRIT:
                alerts.append({"level": "bad", "kind": key, "msg": f"{lab}ِ «{nm}» به {val}٪ رسیده"})
        w = max(cpu, ram, disk)
        heat.append({"name": nm, "pct": w, "online": True})
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
            "tunnels": tun, "portfw": pf,
            "health_score": score,
            "central": central_stats(),
            "heat": heat, "worst": worst,
            "crit": len(crit),
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
    out = {"ok": True, "node_wiped": node_ok}
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
        t["host"], t["port"] = new, newp
        save_json(NODES_FILE, nodes)
    _moved_clear(n["id"])
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
                tunnels.append({"name": L.get("name"),
                                "rx_bps": t["rx_bps"], "tx_bps": t["tx_bps"],
                                "rx_total": t["crx"], "tx_total": t["ctx"]})
    portfw = []
    lst = _cached_list(n["id"])
    for c in (lst.get("configs") or []):
        if c.get("type") != "portfw":
            continue
        t = ifs.get("pf:" + str(c.get("name") or ""))
        if t:
            portfw.append({"name": c.get("name"),
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
    m = re.search(r'^AGENT_VERSION\s*=\s*(\d+)', src, re.M)
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
            _push_set(jid, nid, pct=at(i + 1, 0), restarted=r.get("restarted"),
                      failed=len(r.get("failed") or []))
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
            return {"ok": True}
        for j in live:
            j["cancel"] = True
            _skip_waiting(j)
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
    return {"versions": out, "staged": _staged_info(),             "delivery": _delivery_mode("core")}


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


def _overlay_ips(L):
    try:
        net = ipaddress.ip_network(str(L.get("subnet") or ""), strict=False)
    except ValueError:
        return
    ttype, srv = L.get("type"), L.get("server_side")
    for is_a in (True, False):
        yield str(net.network_address + overlay_host(ttype, srv, is_a))


def _link_haystack(L, nodes):
    for f in (L["a_name"], L["b_name"], L.get("name"), L.get("type"),
              L.get("tunnel_id"), L.get("subnet")):
        if f not in (None, ""):
            yield str(f).lower()
    for ip in _overlay_ips(L):
        yield ip
    for s in ("a", "b"):
        for f in [L.get(s + "_ip"), nodes.get(L.get(s + "_node"), {}).get("host"),
                  *(L.get(s + "_ip_pool") or [])]:
            if f:
                yield str(f).lower()


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
        links = [L for L in links if any(q in h for h in _link_haystack(L, nodes))]
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
            _cl = lb if _srv_is_a(L) else la
            _sp = (_cl.get("sports") or {}).get(L["name"])
            if _sp:
                rec["sport_live"] = int(_sp)
            _srv = la if _srv_is_a(L) else lb
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
            srvA = _srv_is_a(L)
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


def _desync_fields(d, shape, cur=None, is_http=False):
    out = {}
    transport = shape[0]
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
    if _shape_consumes("fake_ttl", *shape):
        out["fake_ttl"] = min(ttl, DESYNC_INJECT_TTL_MAX)
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
    if not src.get("ech_proxy"):
        return ""
    p = get_proxy(str(src.get("ech_proxy_id") or ""))
    if not p:
        raise ValueError("پروکسیِ ECH این تونل دیگر وجود ندارد — یکی بساز و در ویرایشِ تونل انتخابش کن")
    return proxy_url(p)


def _ech_proxy_fields(d, cur, out):
    on = bool(d.get("ech_proxy") if "ech_proxy" in d else cur.get("ech_proxy"))
    if not on:
        return ""
    pid = str((d.get("ech_proxy_id") if "ech_proxy_id" in d else cur.get("ech_proxy_id")) or "").strip()
    p = get_proxy(pid)
    if not p:
        raise ValueError("پروکسیِ ECH انتخاب نشده — از بخشِ «پروکسی‌ها» یکی بساز و انتخابش کن")
    out["ech_proxy"] = True
    out["ech_proxy_id"] = pid
    return proxy_url(p)


def _cdn_carrier(d, cur):
    v = str((d.get("cdn_carrier") if "cdn_carrier" in d else (cur or {}).get("cdn_carrier")) or "ws").strip().lower()
    if v not in ("ws", "http", "grpc"):
        raise ValueError("حاملِ CDN نامعتبر است")
    return v


def _sni_split_fields(d, cur, ech=False):
    on = d.get("sni_split") if ("sni_split" in d) else cur.get("sni_split")
    if not on:
        return {}
    sp = int((d.get("split_pos") if "split_pos" in d else cur.get("split_pos")) or 0)
    if sp < 0 or sp > 1400:
        raise ValueError("split_pos باید بین 0 تا 1400 باشد (0 = خودکار، وسطِ دامنه)")
    if ech and not sp:
        raise ValueError("با ECHِ روشن نامِ دامنه در ClientHello رمز است، پس نقطهٔ برشِ خودکار پیدا نمی‌شود و هیچ چیزی تکه نمی‌شود — یا «نقطهٔ برش» را دستی بگذار یا تقسیمِ SNI را خاموش کن")
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
    if out.get("ws_tls") and not edge:
        raise ValueError("wss یعنی TLS روی لبهٔ CDN باز می‌شود، ولی «آی‌پیِ لبهٔ CDN» خالی است — "
                         "کلاینت مستقیم به خودِ سرور دیال می‌کند و هستهٔ سرور هیچ‌جا TLS را باز نمی‌کند، "
                         "پس تونل هرگز بالا نمی‌آید. آی‌پیِ لبه را بگذار یا wss را خاموش کن")
    ech = d.get("ech") if ("ech" in d) else cur.get("ech")
    if ech:
        if not out.get("ws_tls"):
            raise ValueError("ECH به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن")
        cfg = _fetch_ech(host, _ech_proxy_fields(d, cur, out))
        if not cfg:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد)" % host)
        out["ech"] = True
        out["ws_ech"] = cfg
    cdn = _cdn_carrier(d, cur)
    xh = cdn != "ws"
    if bool(xh):
        if cdn == "grpc" and not out.get("ws_tls"):
            raise ValueError("حاملِ grpc به wss نیاز دارد (برای HTTP/2 به لبه) — اول wss را روشن کن")
        out["cdn_carrier"] = cdn
        out.update(_cdn_shape_fields(d, cur, cdn))
    ss = _sni_split_fields(d, cur, bool(out.get("ech")))
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
            hp = ""
            if isinstance(x, dict):
                hp = str(x.get("path") or "").strip()
                x = x.get("host", "")
            x = str(x).strip().lower()
            if not x or x in seen:
                continue
            if not re.match(_DOMAIN_RE, x):
                raise ValueError("دامنهٔ (SNI) نامعتبر (باید یک دامنهٔ معتبر باشد): %s" % x)
            seen.add(x)
            res.append((x, hp))
        return res

    clean_ips, clean_snis = _ips("ws_edge_ips"), _hosts("ws_edge_snis")
    clean_hosts = [h for h, _ in clean_snis]
    if not clean_ips:
        raise ValueError("استخر به حداقل یک آی‌پیِ لبه نیاز دارد")
    if not clean_hosts:
        raise ValueError("استخر به حداقل یک دامنهٔ (SNI) نیاز دارد")
    if len(clean_ips) < 2 and len(clean_hosts) < 2:
        raise ValueError("استخرِ لبه باید دستِ‌کم روی یک محور بچرخد — یا ۲ آی‌پیِ لبه یا ۲ دامنه")
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
    for h, hp in clean_snis:
        ec = ech_map.get(h, "") if ech_on else ""
        if ech_on and not ec:
            raise ValueError("کلیدِ ECH برای «%s» پیدا نشد — روی کلودفلر ECH فعال است؟ (رکوردِ HTTPS باید ech= داشته باشد). استخر با ECH روشن ساخته نمی‌شود." % h)
        if hp and not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", hp):
            raise ValueError("مسیرِ WebSocket برای «%s» نامعتبر است (باید با / شروع شود)" % h)
        snis.append({"host": h, "ech": ec, "path": hp or path})
    res = {
        "ws_pool": True,
        "ws_tls": True,
        "ech": ech_on,
        "cdn_carrier": _cdn_carrier(d, cur),
        "ws_edge_ips": clean_ips,
        "ws_edge_snis": snis,
        "ws_rotate_secs": _rotate_secs(_ws_rotate_default(d, cur), 28800, "فاصلهٔ چرخشِ لبه"),
        "ws_path": path,
    }
    res.update(_cdn_shape_fields(d, cur, res["cdn_carrier"]))
    res.update(_sni_split_fields(d, cur, ech_on))
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


_SHAPE_RAW_PORTED = ("raw_port", "raw_sport", "raw_sport_random", "raw_sport_rotate",
                     "raw_dports", "conntrack_bypass")
_SHAPE_TCP_ONLY = ("cover", "cover_sni")
_SHAPE_WS_ONLY = ("ws_host", "ws_path", "ws_tls", "cdn_carrier", "ech", "ws_ech", "ech_proxy",
                  "ech_proxy_id", "edge_ip", "ws_pool", "ws_edge_ips", "ws_edge_snis",
                  "ws_rotate_secs", "sni_split", "split_pos", "sni_mode", "split_ttl",
                  "http_up_workers", "http_up_batch_kb", "http_up_rate", "http_streams")
_SHAPE_DATAGRAM = ("fec", "fec_data", "fec_parity", "a_workers", "b_workers")
_SHAPE_DESYNC = ("fake_desync", "fake_count", "fake_mode")


def _shape_consumes(key, transport, profile, srand, moving=True, dsmode="ttl"):
    ported = transport == "raw" and profile in PORTED_RAW_PROFILES
    if key == "fake_ttl":
        return transport in DESYNC_TRANSPORTS and not (transport == "raw" and dsmode == "badsum")
    if key in _SHAPE_RAW_PORTED:
        return ported
    if key == "raw_proto":
        return transport == "raw" and profile == "bare"
    if key == "raw_profile":
        return transport == "raw"
    if key in _SHAPE_TCP_ONLY:
        return transport == "tcp"
    if key in _SHAPE_WS_ONLY:
        return transport == "ws"
    if key in _SHAPE_DATAGRAM:
        return transport in QUEUEING_TRANSPORTS
    if key in _SHAPE_DESYNC:
        return transport != "udp"
    if key in ("sport_lo", "sport_hi"):
        return (ported and moving) if transport == "raw" else transport in PORT_RUNG_TRANSPORTS
    if key == "port_tries":
        return (ported and srand) if transport == "raw" else transport in PORT_RUNG_TRANSPORTS
    if key in _ROTATION_KEYS:
        return transport in DIRECT_TRANSPORTS
    return True


def _shape_of(d, cur):
    transport = str(d.get("transport") or cur.get("transport") or "udp").strip().lower()
    profile = str(d.get("raw_profile") or cur.get("raw_profile") or "bare").strip().lower()
    ported = profile in PORTED_RAW_PROFILES
    if "raw_sport_random" in d:
        srand = bool(d["raw_sport_random"])
    else:
        srand = bool(cur.get("raw_sport_random")) and ported
    if "raw_sport_rotate" in d:
        rot = bool(d["raw_sport_rotate"])
    else:
        rot = bool(cur.get("raw_sport_rotate")) and ported
    dsmode = str((d.get("fake_mode") if "fake_mode" in d else cur.get("fake_mode")) or "ttl").strip().lower()
    return transport, profile, srand, srand or rot, dsmode


def _carried(cur, shape):
    return {k: v for k, v in cur.items() if _shape_consumes(k, *shape)}


def _needs_tunnel_port(ttype, d, cur):
    if ttype in ("l2tpv3", "fou"):
        return True
    return ttype == "core" and _shape_of(d, cur)[0] != "raw"


def _core_extra(d, cur, a_ip, b_ip, a_ips, b_ips):
    shape = _shape_of(d, cur)
    cur = _carried(cur, shape)
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
        _srand_req, _rsport_req = "raw_sport_random" in d, "raw_sport" in d
        _srand = bool(d["raw_sport_random"] if _srand_req else cur.get("raw_sport_random"))
        try:
            _rsport = int((d["raw_sport"] if _rsport_req else cur.get("raw_sport")) or 0)
        except (TypeError, ValueError):
            _rsport = 0
        if _srand and _rsport and _srand_req and _rsport_req:
            raise ValueError("«پورتِ مبدأ» یا ثابت است یا چرخان — هر دو با هم نمی‌شود")
        if _rsport_req and _rsport and not _srand_req:
            _srand = False
        if _srand_req and _srand and not _rsport_req:
            _rsport = 0
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
        elif _rrot and "raw_sport_rotate" in d:
            raise ValueError(f"«چرخشِ پورتِ مبدأ» فقط برای پروفایلِ udp و tcp است؛ «{profile}» هیچ پورتی جعل نمی‌کند")
        _ctb = bool(d["conntrack_bypass"]) if "conntrack_bypass" in d else bool(cur.get("conntrack_bypass"))
        if _ctb:
            if profile not in ("udp", "tcp"):
                raise ValueError(f"«رد شدن از conntrack» فقط برای پروفایلِ udp و tcp معنا دارد؛ «{profile}» به‌ازای هر پکت جریانِ تازه نمی‌سازد")
            ce["conntrack_bypass"] = True
    if transport == "ws":
        ce.update(_ws_fields(d, transport, cur))
    ce.update(_fec_fields(d, transport, cur))
    ce.update(_workers_field(d, transport, bool(ce.get("fec")), cur))
    ce.update(_desync_fields(d, shape, cur, ce.get("cdn_carrier", "ws") != "ws"))
    if (bool(d.get("obfs")) if "obfs" in d else bool(cur.get("obfs"))):
        if cipher == "none":
            raise ValueError("استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)")
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
        _blo = int((d["sport_lo"] if "sport_lo" in d else cur.get("sport_lo")) or 0)
        _bhi = int((d["sport_hi"] if "sport_hi" in d else cur.get("sport_hi")) or 0)
    except (TypeError, ValueError):
        _blo = _bhi = 0
    if (_blo or _bhi) and not _shape_consumes("sport_lo", *shape):
        _blo = _bhi = 0
    if _blo or _bhi:
        if not (RAW_BAND_MIN_LO <= _blo <= _bhi <= 65535):
            raise ValueError(f"«بازهٔ پورتِ مبدأ» باید دو پورتِ بینِ {RAW_BAND_MIN_LO} تا 65535 باشد و ابتدایش از انتهایش کوچک‌تر — زیرِ {RAW_BAND_MIN_LO} پورتِ ممتاز است و هیچ حاملی دلیلی برای ادعای آن ندارد")
        if _bhi - _blo + 1 < RAW_BAND_MIN_SPAN:
            raise ValueError(f"«بازهٔ پورتِ مبدأ» دستِ‌کم باید {RAW_BAND_MIN_SPAN} پورت پهنا داشته باشد؛ باریک‌تر از آن یعنی پورتِ ثابت با چند قدمِ اضافه")
        ce["sport_lo"], ce["sport_hi"] = _blo, _bhi
    try:
        _ptries = int((d["port_tries"] if "port_tries" in d else cur.get("port_tries")) or 0)
    except (TypeError, ValueError):
        _ptries = 0
    if _ptries and not _shape_consumes("port_tries", *shape):
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
                ce["rotate_secs"] = _rotate_secs(d.get("rotate_secs"), 86400, "فاصلهٔ چرخش")
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
    if _needs_tunnel_port(ttype, d, {}):
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
                          "b_node": B["id"], "b_name": B["name"], "b_ip": b_ip, 
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
    return {"ok": True, "name": name}


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
            return {"ok": True,                     "msg": "لینک حذف شد؛ پاک‌سازیِ سمتِ «" + "»، «".join(deferred) + "» وقتی نود برگشت خودکار انجام می‌شود"}
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
        extra = _tunnel_extra(L)
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
        _core_rotation_bodies(L, a_body, b_body,
                              _flat_ips(_cached_ping(A["id"])) if A else None,
                              _flat_ips(_cached_ping(B["id"])) if B else None)
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
    return _edge_status_of(L, _client_node(L), _EV_END_MISSING["cli"])


def _edge_status_of(L, node, missing):
    is_pool = bool(L.get("ws_pool"))
    if not node:
        return {"ok": True, "pool": is_pool, "active": "", "health": [], "events": [], "error": missing}
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
    if _needs_tunnel_port(ttype, d, L):
        _asked = "port" in d and not str(d.get("port") or "").strip()
        _moved_carrier = ttype == "core" and str(d.get("transport") or "") != str(L.get("transport") or "")
        _stale = _asked or _moved_carrier or L.get("type") not in ("l2tpv3", "fou", "core")
        port = int(d.get("port") or 0) or (0 if _stale else L.get("port")) or free_tunnel_port(A, B, exclude_id=L["id"])
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
        return {"ok": True, "name": old_name, "msg": "چیزی برای تغییر نبود"}
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
    return {"ok": True, "name": new_name}


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
    return {"ok": True, "from": cli["name"], "to": srv["name"], "secs": secs,
            "up_streams": int(q.get("up_streams") or 0), "down_streams": int(q.get("down_streams") or 0),
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
        raise ValueError("؛ ".join(errs))
    return {"ok": True}


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
        _core_rotation_bodies(L, a_body, b_body, a_ips, b_ips)
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
    return {"ok": True, "enabled": enabled, "both": both,             "failed": [names[t] for t in bad],
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
                    log_event("warn", "ech-gone", f"تونلِ «{nm}»: حذفِ رکوردِ ECH",
                              f"کلید از DNS ناپدید شد؛ تونل فعلاً بدون ECH بازسازی شد. تنظیمِ ECH همچنان روشن است و "
                              f"پنل هر {_mins_label} دقیقه دوباره امتحان می‌کند — به‌محضِ برگشتنِ رکورد خودش برمی‌گردد")
                else:
                    log_event("bad", "ech-gone", f"تونلِ «{nm}»: حذفِ رکوردِ ECH", "تنزل به wss ساده شد ولی بازسازی شکست خورد — تونل هنوز قطع است")
            continue
        if gone and _ech_blank(lid, gone):
            names = "، ".join(gone)
            if _ech_safe_rebuild(lid):
                log_event("warn", "ech-gone", f"تونلِ «{nm}»: حذفِ رکوردِ ECH روی بخشی از استخر",
                          f"رکوردِ ECHِ {names} از DNS ناپدید شده؛ همان دامنه‌ها بدون ECH بازسازی شدند و "
                          f"بقیهٔ استخر دست‌نخورده ماند. پنل هر {_mins_label} دقیقه دوباره امتحان می‌کند")
            else:
                log_event("bad", "ech-gone", f"تونلِ «{nm}»: حذفِ رکوردِ ECH روی بخشی از استخر",
                          f"کلیدِ کهنهٔ {names} پاک شد ولی بازسازی شکست خورد — رفتن روی آن دامنه‌ها هنوز می‌میرد")
        changed, chmap = _ech_write(lid, kind, updates, degrade=False)
        if changed and chmap and blank_before:
            if _ech_safe_rebuild(lid):
                log_event("ok", "ech-back", f"تونلِ «{nm}»: بازگشتِ ECH",
                          "رکوردِ ECH دوباره منتشر شد؛ تونل با کلیدِ تازه بازسازی شد")
            else:
                log_event("bad", "ech-back", f"تونلِ «{nm}»: بازگشتِ ECH",
                          "رکوردِ ECH برگشت ولی بازسازی شکست خورد — تونل هنوز بدون ECH است")
        if changed and chmap:
            tried, pushed = _ech_live_push(lid, chmap)
            dfa = "\n".join("دامنه: %s\nکلیدِ ECH: %s" % (h, k) for h, k in chmap.items())
            if pushed:
                dfa += "\nنودِ مقصد: %s" % pushed
                log_event("ok", "ech-refresh", "کلیدِ ECHِ تونلِ «%s» تازه شد و زنده به هسته push شد (هر %s دقیقه)" % (nm, _mins_label), dfa)
            elif tried:
                if _ech_safe_rebuild(lid):
                    log_event("warn", "ech-refresh", "کلیدِ ECHِ تونلِ «%s» تازه شد ولی pushِ زنده نرسید" % nm, dfa + "\nنود جواب نداد؛ تونل با کلیدِ تازه بازسازی شد")
                else:
                    log_event("bad", "ech-refresh", "کلیدِ ECHِ تونلِ «%s» تازه شد ولی به هسته نرسید" % nm, dfa + "\nنه pushِ زنده جواب داد نه بازسازی — هسته هنوز کلیدِ کهنه دارد")
            else:
                log_event("ok", "ech-refresh", "کلیدِ ECHِ تونلِ «%s» با تایمرِ زمان‌بندی‌شده تازه شد (هر %s دقیقه)" % (nm, _mins_label), dfa)
        reachable, down, stalled = _ech_pool_state(lid) if kind == "pool" else (False, False, False)
        if kind == "pool" and (down or stalled):
            if lid not in _ech_down_rebuilt or changed:
                _ech_down_rebuilt.add(lid)
                why_fa = "قطع بود" if down else "همهٔ لبه‌هایش سرِ ECH می‌سوختند"
                if _ech_safe_rebuild(lid):
                    log_event("ok", "ech-rotate", f"تونلِ «{nm}»: چرخشِ کلیدِ ECH", f"{why_fa}؛ با کلیدِ تازه بازسازی شد")
                else:
                    log_event("bad", "ech-rotate", f"تونلِ «{nm}»: چرخشِ کلیدِ ECH", f"{why_fa}؛ بازسازی با کلیدِ تازه شکست خورد — تونل هنوز قطع است")
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
            log_event("ok", "ech-rebuild", f"تونلِ «{nm}»: بازسازیِ سریعِ ECH", f"{why_fa}")
        else:
            log_event("bad", "ech-rebuild", f"تونلِ «{nm}»: بازسازیِ سریعِ ECH", f"{why_fa}؛ شکست خورد — تونل هنوز قطع است")
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
            log_event("ok", "ech-seq-reset",
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
            log_event("ok", "ech-saved",
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

EV_GROUPS = (("tunnel", "تونل"), ("node", "نود"), ("rot", "چرخش و استخر"),
             ("ech", "ECH"), ("cfg", "تنظیم"), ("auth", "ورود"))
EV_TYPES = (
    ("link-up", "tunnel", "تونل وصل شد"),
    ("link-down", "tunnel", "تونل قطع شد"),
    ("link-reconnect", "tunnel", "تونل خودش دوباره وصل شد"),
    ("node-up", "node", "نود آنلاین شد"),
    ("node-down", "node", "نود آفلاین شد"),
    ("node-moved", "node", "نشانیِ نود جابه‌جا شد"),
    ("rot-due", "rot", "چرخش طبقِ زمان‌بندی"),
    ("rot-forced", "rot", "چرخشِ اجباری — مسیر جواب نداد"),
    ("rehandshake", "rot", "دست‌دادنِ دوباره، پیش از سوزاندن"),
    ("port-roll", "rot", "برگشت با چرخشِ پورتِ مبدأ"),
    ("ladder-revive", "rot", "ازسرگیریِ نردبان"),
    ("burn", "rot", "سوختنِ آدرس"),
    ("heal", "rot", "برگشتِ آدرس به فهرستِ سالم"),
    ("pool-degraded", "rot", "توقفِ چرخش — فقط یکی مانده"),
    ("pool-resumed", "rot", "ازسرگیریِ چرخشِ استخر"),
    ("ech-heal", "ech", "ترمیمِ خودکارِ کلیدِ ECH در هسته"),
    ("ech-gone", "ech", "حذفِ رکوردِ ECH از DNS"),
    ("ech-back", "ech", "بازگشتِ رکوردِ ECH"),
    ("ech-refresh", "ech", "تازه‌شدنِ کلیدِ ECH"),
    ("ech-rotate", "ech", "چرخشِ کلیدِ ECH"),
    ("ech-rebuild", "ech", "بازسازیِ سریعِ ECH"),
    ("ech-saved", "ech", "ذخیرهٔ کلیدِ خودترمیمِ هسته"),
    ("ech-seq-reset", "ech", "صفر شدنِ شمارندهٔ رویدادِ هسته"),
    ("cfg-clamped", "cfg", "تنظیمی که کامل اعمال نشد"),
    ("auth-in", "auth", "ورودِ موفق به پنل"),
    ("auth-out", "auth", "خروج از پنل"),
    ("auth-fail", "auth", "تلاشِ ناموفقِ ورود"),
    ("auth-lock", "auth", "قفلِ نشانی پس از تلاشِ زیاد"),
)
EV_TYPE_GROUP = {t: g for t, g, _fa in EV_TYPES}
_events_lock = threading.Lock()
_ev_seq_total = None
_ev_list = None
_ev_dirty = False
_ev_state = {"init": False, "nodes": {}, "links": {}, "evseq": {}, "rotip": {}, "links_coarse_down": set()}


def _ev_ip(detail):
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", str(detail or ""))
    return m.group(0) if m else ""
def _ev_value(detail):
    tag, _, rest = str(detail or "").partition(":")
    return rest.strip() if tag in ("ip", "sni") and rest.strip() else ""



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
    "ladder-revive": ("warn", "ازسرگیریِ نردبان پس از بن‌بست"),
}


def _ev_rot(kind, code):
    if kind not in ("down", "rot"):
        return None
    ax = _EV_ROT_AXIS.get(code)
    if ax is None:
        lvl_fa = _EV_ROT_CODE.get(code) if kind == "down" else None
        return (lvl_fa[0], lvl_fa[1], "", code) if lvl_fa else None
    axis, fa = ax
    if kind == "rot":
        return ("ok", fa + " — طبقِ زمان‌بندی", axis, "rot-due")
    return ("warn", fa + " — اجباری: مسیر جواب نداد", axis, "rot-forced")


_ROT_PARTNER = {"dst": "src", "src": "dst", "ip": "sni", "sni": "ip"}


def _ev_seed_axes(lid, is_pool, active):
    active = str(active or "")
    if not active:
        return
    if is_pool:
        left, sep, right = active.partition(" · ")
        pairs = (("ip", left.strip()), ("sni", right.strip() if sep else ""))
    else:
        pairs = (("dst", _ev_ip(active)),)
    for ax, v in pairs:
        if v:
            _ev_state["rotip"].setdefault(lid + ":" + ax, v)


def _rot_pair(axis, prev, cur, other):
    if not cur:
        return ""
    pair = (lambda one: f"{other} ← {one}" if other else one) if axis in ("src", "sni") \
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
        return ("bad", "link-down", f"تونلِ «{nm}»: قطع شد", rf)
    if kind == "up":
        rf = _EV_UP_CODE.get(code, "تونل وصل شد")
        return ("ok", "link-reconnect", f"تونلِ «{nm}»: وصلِ مجدد", rf)
    if kind == "burn":
        what = _HEAL_AXIS.get(str(detail or "").split(":", 1)[0], "آی‌پی")
        return ("warn", "burn", f"تونلِ «{nm}»: سوختنِ {what}", f"{what}: {key}")
    if kind == "cfg":
        if code == "sockbuf-clamped":
            parts = key.split()
            title = f"تونلِ «{nm}»: بافرِ سوکت به‌اندازه‌ای که خواستی اعمال نشد"
            if len(parts) == 3 and parts[0] == "send":
                return ("warn", "cfg-clamped", title,
                        f"بافرِ ارسال: {_mib(parts[1])} خواسته شد، {_mib(parts[2])} اعمال شد\n"
                        f"چاره: net.core.wmem_max را روی آن نود بالا ببر، یا CAP_NET_ADMIN به سرویس بده")
            if len(parts) == 3:
                return ("warn", "cfg-clamped", title,
                        f"بافرِ دریافت: {_mib(parts[1])} خواسته شد، {_mib(parts[2])} اعمال شد\n"
                        f"چاره: net.core.rmem_max را روی آن نود بالا ببر، یا CAP_NET_ADMIN به سرویس بده")
        return ("warn", "cfg-clamped", f"تونلِ «{nm}»: یک تنظیم آن‌طور که خواسته شد اعمال نشد", f"جزئیات: {key}")
    if kind == "heal":
        if code == "tun-probe":
            what = _HEAL_AXIS.get(str(detail or "").split(":", 1)[0], "آی‌پی")
            return ("ok", "heal", f"تونلِ «{nm}»: بازگشتِ {what}",
                    f"{key}\nپروبِ نود دید ترافیک واقعاً از این مسیر رد می‌شود")
    if kind == "pool":
        what = _HEAL_AXIS.get(axis, "آی‌پی")
        left = key if sep and axis in _HEAL_AXIS else ""
        if code == "degraded":
            return ("warn", "pool-degraded",
                    f"تونلِ «{nm}»: توقفِ چرخشِ {what} — فقط یکی در دسترس مانده",
                    (f"در دسترس: {left}\n" if left else "")
                    + "بقیه سوخته‌اند و نوبتِ آزمایشِ دوباره‌شان نرسیده؛ تا آن موقع روی همان یک می‌ماند")
        return ("ok", "pool-resumed", f"تونلِ «{nm}»: ازسرگیریِ چرخشِ {what}",
                (f"در دسترس: {left}\n" if left else "")
                + "دوباره بیش از یک مورد در دسترسِ چرخش است")
    if kind == "ech":
        host, _, k = key.partition(" ")
        dfa = ("دامنه: %s\n" % host if host else "") + ("کلیدِ تازهٔ ECH: %s" % k if k else "")
        return ("ok", "ech-heal", f"تونلِ «{nm}»: ترمیمِ خودکارِ کلیدِ ECH", dfa)
    return None


def _ingest_core_events(lid, end, nm, events, first):
    key = lid + "|" + end
    clean = []
    if isinstance(events, list):
        for e in events:
            if not isinstance(e, dict):
                continue
            try:
                sq = int(e.get("seq") or 0)
            except (TypeError, ValueError):
                continue
            clean.append((sq, e))
    mx = max([0] + [sq for sq, _ in clean])
    if first:
        _ev_state["evseq"][key] = mx
        return
    last = _ev_state["evseq"].get(key, 0)
    if clean and mx < last:
        last = 0
    for sq, e in sorted(clean, key=lambda x: x[0]):
        if sq <= last:
            continue
        ekind, ecode, edet = str(e.get("kind") or ""), str(e.get("code") or ""), str(e.get("detail") or "")
        rot = _ev_rot(ekind, ecode)
        if rot and end == "cli" and ecode == "port-roll":
            kv = dict(w.split(":", 1) for w in edet.split() if ":" in w)
            tries, sport = kv.get("tries"), kv.get("sport")
            fa = f"تونلِ «{nm}»: با چرخشِ پورتِ مبدأ"
            if tries:
                fa += f" پس از {tries} تلاش"
            if sport:
                fa += f"، با پورتِ {sport}"
            fa += " برگشت"
            log_event(rot[0], rot[3], fa)
            continue
        if rot and end == "cli" and rot[2]:
            axis = rot[2]
            val = _ev_value(edet) or _ev_ip(edet)
            rk = lid + ":" + axis
            prev = _ev_state["rotip"].get(rk)
            if val:
                _ev_state["rotip"][rk] = val
            other = _ev_state["rotip"].get(lid + ":" + _ROT_PARTNER[axis]) or ""
            log_event(rot[0], rot[3], f"تونلِ «{nm}»: {rot[1]}",
                      _rot_pair(axis, prev, val, other))
            continue
        if rot:
            log_event(rot[0], rot[3], f"تونلِ «{nm}»: {rot[1]}")
            continue
        txt = _ev_core_text(ekind, ecode, edet, nm)
        if txt:
            log_event(txt[0], txt[1], txt[2], txt[3])
    _ev_state["evseq"][key] = max(last, mx)


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
    hidden = _ev_hidden()
    with _events_lock:
        return len(_ev_shown(_ev_all(), hidden))


def _ev_cat(t):
    return EV_TYPE_GROUP.get(t, "sys")


def _ev_hidden():
    h = get_settings().get("log_hidden")
    return {str(t) for t in h if str(t) in EV_TYPE_GROUP} if isinstance(h, list) else set()


def _ev_shown(evs, hidden):
    return [e for e in evs if e.get("kind") not in hidden] if hidden else list(evs)


def _ev_prune(evs, now=None):
    cut = (time.time() if now is None else now) - EVENTS_TTL
    return [e for e in evs if isinstance(e, dict) and _sint(e.get("ts")) >= cut]


def ev_sweep():
    global _ev_list, _ev_dirty
    with _events_lock:
        before = len(_ev_all())
        _ev_list = _ev_prune(_ev_list)
        if len(_ev_list) != before:
            _ev_dirty = True
        _ev_flush()
        return before - len(_ev_list)


def log_event(level, kind, fa, dfa=""):
    global _ev_seq_total, _ev_dirty
    shown = kind not in _ev_hidden()
    with _events_lock:
        _ev_all().insert(0, {"ts": int(time.time()), "level": level, "kind": kind,
                             "fa": fa, "dfa": dfa})
        if shown:
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
            log_event("ok", "node-up", f"نودِ «{nm}»: آنلاین شد")
        else:
            log_event("bad", "node-down", f"نودِ «{nm}»: آفلاین شد")
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
            bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in CORE_TRANSPORTS)
        if up:
            if precise_core and lid not in _ev_state["links_coarse_down"]:
                pass
            else:
                log_event("ok", "link-up", f"تونلِ «{nm}»: وصل شد")
            _ev_state["links_coarse_down"].discard(lid)
        else:
            a_off = _cache_get(L.get("a_node")) and not _node_online(L.get("a_node"))
            b_off = _cache_get(L.get("b_node")) and not _node_online(L.get("b_node"))
            if precise_core and not (a_off or b_off):
                pass
            else:
                rf = _link_down_reason(L, nmap)
                log_event("bad", "link-down", f"تونلِ «{nm}»: قطع شد", rf)
                if precise_core:
                    _ev_state["links_coarse_down"].add(lid)
    for lid in [k for k in _ev_state["links"] if k not in seen]:
        _ev_state["links"].pop(lid, None)
        _ev_state["links_coarse_down"].discard(lid)

    seen = set()
    todo = [L for L in links if L.get("type") == "core" and L.get("enabled", True)
            and (bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in CORE_TRANSPORTS)]

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

    _nodes = {n["id"]: n for n in nodes}

    def _es(t):
        L, end = t
        try:
            return _edge_status_of(L, _nodes.get(_node_id_of(L, end)), _EV_END_MISSING[end])
        except Exception:
            return None
    ends = [(L, e) for L in todo for e in ("cli", "srv")]
    pre = dict(zip(((L["id"], e) for L, e in ends), parallel_map(_es, ends)))
    for L in links:
        if L.get("type") != "core" or not L.get("enabled", True):
            continue
        is_pool = bool(L.get("ws_pool"))
        tr = str(L.get("transport") or "").lower()
        if not is_pool and tr not in CORE_TRANSPORTS:
            continue
        lid = L["id"]
        seen.add(lid)
        nm = L.get("name", "")
        for end in ("cli", "srv"):
            r = pre.get((lid, end))
            if not r or "error" in r:
                continue
            try:
                if end == "cli":
                    _ev_seed_axes(lid, is_pool, r.get("active"))
                _ingest_core_events(lid, end, nm, r.get("events"), first)
            except Exception:
                continue
    for k in [k for k in _ev_state["evseq"] if k.split("|", 1)[0] not in seen]:
        _ev_state["evseq"].pop(k, None)
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
    cut = time.time() - EVENTS_TTL
    hidden = _ev_hidden()
    evs = [dict(e, cat=_ev_cat(e.get("kind")))
           for e in _ev_shown(load_events(), hidden) if _sint(e.get("ts")) >= cut]
    return {"ok": True, "events": evs, "hidden": sorted(hidden)}


def api_events_clear(d):
    global _ev_dirty
    with _events_lock:
        _ev_all()[:] = []
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
                "online": bool(p.get("ok")),
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
    return {"ok": True}


def settings_public(obj):
    return {k: v for k, v in obj.items() if k != "api_token_hash"}


def api_settings(d):
    return settings_public(get_settings())


def api_settings_set(d):
    with _settings_lock:
        obj = validate_settings(d or {})
        _settings.clear()
        _settings.update(obj)
        save_json(SETTINGS_FILE, obj)
    return {"ok": True, "settings": settings_public(obj)}


def api_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def api_token_new(d):
    token = secrets.token_urlsafe(32)
    with _settings_lock:
        obj = get_settings()
        obj["api_token_hash"] = api_token_hash(token)
        _settings.clear()
        _settings.update(obj)
        save_json(SETTINGS_FILE, obj)
    return {"ok": True, "token": token}


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
        return {"ok": True, "host": host, "port": port}
    if node_call(n_snap, "ping", "GET", timeout=5).get("ok"):
        _moved_clear(n_snap["id"])
        return {"ok": True, "host": host, "port": port}
    probe = dict(n_snap)
    probe["host"], probe["port"] = want_host, want_port
    if not node_call(probe, "ping", "GET", timeout=5).get("ok"):
        return {"ok": False, "unconfirmed": True, "host": host, "port": port}
    if get_settings().get("reconcile_mode") != "auto":
        if _moved_note(n_snap["id"], n_snap.get("name") or "", host, want_host, want_port):
            log_event("warn", "node-moved", f"نودِ «{n_snap.get('name')}»: جابه‌جاییِ نشانی",
                      f"از {host}:{port} به {want_host}:{want_port} رفته و از نشانیِ تازه جواب می‌دهد — روی"
                      " کارتِ نود نشانِ هشدار را بزن و «تنظیم به‌عنوانِ آی‌پیِ نود»، بعد تونل‌هایش را بازسازی کن."
                      " (برای انجامِ خودکار، حالتِ آشتی را «خودکار» بگذار.)")
        return {"ok": True, "host": host, "port": port, "moved_to": want_host}
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
    return {"ok": True, "host": host, "port": port}


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


UI_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".webmanifest": "application/manifest+json",
    ".woff2": "font/woff2",
}


def ui_asset(rel):
    root = os.path.realpath(UI_DIR)
    full = os.path.realpath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        return None, ""
    if not os.path.isfile(full):
        return None, ""
    with open(full, "rb") as fh:
        return fh.read(), UI_TYPES.get(os.path.splitext(full)[1], "application/octet-stream")


def ui_config():
    return {
        "tuning_defaults": _TUNING_DEFAULTS,
        "tuning_steps": _TUNING_STEPS,
        "probe_samples": _PROBE_SAMPLES,
        "ev_types": [list(x) for x in EV_TYPES],
        "ev_groups": [list(x) for x in EV_GROUPS],
        "settings_defaults": {k: v for k, v in settings_defaults().items() if k != "tuning"},
        "split_ttl_max": SPLIT_TTL_MAX,
        "workers_max": CORE_MAX_WORKERS,
        "enums": {
            "ciphers": list(CORE_CIPHERS), "tr_all": list(CORE_TRANSPORTS),
            "tr_direct": list(DIRECT_TRANSPORTS), "tr_rung": list(PORT_RUNG_TRANSPORTS),
            "raw_ported": list(PORTED_RAW_PROFILES),
            "http_shape": {k: {"lo": lo, "hi": hi, "d": dflt} for k, (lo, hi, dflt) in HTTP_SHAPE.items()},
            "http_shape_grpc": list(HTTP_SHAPE_GRPC),
            "raw_protos": {k: v for k, v in CORE_RAW_PROFILE_PROTOS.items() if k != "bare"},
            "edge_ports": {"tls": list(_EDGE_TLS_PORTS), "plain": list(_EDGE_PLAIN_PORTS)},
        },
    }


def api_ui_config(d):
    return ui_config()


def _dispatch(cmd, d):
    return API[cmd](d)


API = {
    "nodes": api_nodes, "node-names": api_node_names, "summary": api_summary, "next-port": api_next_port,
    "settings": api_settings, "settings-set": api_settings_set, "readiness": api_readiness,
    "ui-config": api_ui_config, "api-token-new": api_token_new,
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
             "act-cancel", "api-token-new"}
TOKEN_DENY = {"settings-set", "api-token-new"}
API_MSG = {
    "unauthorized": ("وارد نشده‌اید", 401, "not logged in: send Authorization: Bearer <token>"),
    "locked": ("تلاشِ زیاد — چند دقیقه صبر کن", 429, "too many failed attempts from this address; try again in a few minutes"),
    "api_disabled": ("API در دسترس نیست", 403, "API is not available: external API access is switched off in the panel settings"),
    "bad_token": ("توکنِ API نامعتبر است", 401, "invalid API token"),
    "token_denied": ("این درخواست با توکنِ API مجاز نیست", 403, "this endpoint is not available with an API token"),
    "unknown_route": ("مسیرِ ناشناخته", 404, "unknown API route"),
    "post_only": ("این درخواست باید POST باشد", 405, "this endpoint requires POST"),
    "bad_request": ("درخواستِ نامعتبر", 403, "invalid request"),
    "internal": ("خطای داخلی", 500, "internal error"),
}


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

    def _send(self, code, body, ctype="application/json", extra=None, big=False, cache="no-store"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False)
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
        self.send_header("Cache-Control", cache)
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
            page, ctype = ui_asset("index.html" if self._user() else "login.html")
            if page is None:
                self._send(500, {"error": "رابط کاربری نصب نشده — پوشهٔ ui کنارِ دادهٔ پنل نیست"})
                return
            self._send(200, page, ctype, cache="no-store")
        elif path.startswith("/assets/"):
            if not self._user():
                self._send(404, {"error": "پیدا نشد"})
                return
            blob, ctype = ui_asset(path[1:])
            if blob is None:
                self._send(404, {"error": "پیدا نشد"})
                return
            self._send(200, blob, ctype, cache="public, max-age=31536000, immutable")
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
                self._auth_log("ok", "auth-out", "خروج از پنل انجام شد و همهٔ نشست‌های باز باطل شدند.")
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

    def _auth_log(self, level, etype, title, extra=None):
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
        log_event(level, etype, title, "\n".join(rows))

    def _login(self):
        d = self._body()
        ip = self._client_ip()
        if rate_limited(ip):
            if note_blocked(ip):
                self._auth_log("bad", "auth-lock", "تلاش برای ورود در حالی که این نشانی قفل است همچنان ادامه دارد.")
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
            self._auth_log("ok", "auth-in", "ورود موفق به پنل انجام شد.")
            self._send(200, {"ok": True}, extra={"Set-Cookie": cookie})
        else:
            note_fail(ip)
            tries = fail_count(ip)
            who = "درست" if user_ok else "ناشناخته"
            if tries >= FAIL_LIMIT:
                self._auth_log("bad", "auth-lock", "پس از %d تلاشِ ناموفق در %d دقیقه، ورود از این نشانی قفل شد."
                               % (tries, FAIL_WINDOW // 60),
                               ["نام کاربری: %s" % who])
            else:
                self._auth_log("warn", "auth-fail", "یک تلاشِ ناموفق برای ورود ثبت شد؛ تلاشِ %d از %d مجاز."
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

    def _fail(self, code, en, drain=False):
        fa, status, msg = API_MSG[code]
        if drain and self.command == "POST":
            self._body()
        self._send(status, {"error": code, "message": msg} if en else {"error": fa})

    def _bearer_check(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return "unauthorized"
        ip = self._client_ip()
        if rate_limited(ip):
            if note_blocked(ip):
                self._auth_log("bad", "auth-lock", "درخواست با توکنِ API از نشانیِ قفل‌شده همچنان ادامه دارد.")
            return "locked"
        s = get_settings()
        if not s.get("api_external"):
            note_fail(ip)
            self._auth_log("warn", "auth-fail", "درخواست با توکنِ API رد شد؛ دسترسیِ بیرونی به API خاموش است.")
            return "api_disabled"
        stored = str(s.get("api_token_hash") or "")
        if stored and hmac.compare_digest(api_token_hash(auth[7:].strip()), stored):
            return None
        note_fail(ip)
        self._auth_log("warn", "auth-fail", "درخواست با توکنِ APIِ نامعتبر رد شد.")
        return "bad_token"

    def _api(self, cmd, method):
        en = self.headers.get("Authorization", "").startswith("Bearer ")
        via_token = False
        if not self._user():
            why = self._bearer_check()
            if why:
                self._fail(why, en)
                return
            via_token = True
        if cmd not in API:
            self._fail("unknown_route", en, drain=True)
            return
        if via_token and cmd in TOKEN_DENY:
            self._fail("token_denied", en, drain=True)
            return
        if cmd in MUTATIONS:
            if method != "POST":
                self._fail("post_only", en)
                return
            if not via_token and self.headers.get("X-Requested-With") != "tnl-central":
                self._fail("bad_request", en, drain=True)
                return
        d = self._body(cap=20971520 if cmd == "core-upload" else 1048576) if method == "POST" else query_dict(self.path)
        try:
            self._send(200, _dispatch(cmd, d))
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception:
            log_internal("api %s" % cmd)
            self._fail("internal", en)


SERVICE = "tnl-central.service"


def svc(*a):
    subprocess.run(["systemctl", *a, SERVICE])


def service_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", SERVICE]).returncode == 0


def service_settled(tries=6):
    for _ in range(tries):
        if service_active():
            return True
        time.sleep(1)
    return False


DEP_PACKAGES = ("openssl", "ca-certificates", "iproute2", "openssh-client", "sshpass")
DEP_BINARIES = ("openssl", "ssh", "sshpass", "ip", "systemctl")


def missing_binaries():
    return [b for b in DEP_BINARIES if not shutil.which(b)]


def _port_or(value, fallback):
    try:
        p = int(str(value).strip())
    except Exception:
        return fallback
    return p if 1 <= p <= 65535 else fallback


def install_deps():
    if not missing_binaries():
        print("[✔] dependencies already present.")
        return
    print("[*] installing dependencies: " + " ".join(DEP_PACKAGES))
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    try:
        subprocess.run(["apt-get", "update", "-qq"], env=env, timeout=300)
        subprocess.run(["apt-get", "install", "-yqq", *DEP_PACKAGES], env=env, timeout=900)
    except Exception as e:
        print(f"[!] apt failed: {e}")
    still = missing_binaries()
    if still:
        print("[✘] still missing after install: " + " ".join(still))
        print("    install them by hand and run --install again.")
        sys.exit(1)
    print("[✔] dependencies ready.")


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


def _colour_ok():
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_COLOUR = _colour_ok()


def paint(code, text):
    return "[" + code + "m" + str(text) + "[0m" if _COLOUR else str(text)


def bold(t):
    return paint("1", t)


def dim(t):
    return paint("2", t)


def red(t):
    return paint("31", t)


def green(t):
    return paint("32", t)


def gold(t):
    return paint("33", t)


def cyan(t):
    return paint("36", t)


OK = green("[v]")
BAD = red("[x]")
WARN = gold("[!]")
STEP = cyan("[*]")

def ui_files():
    try:
        return len(os.listdir(os.path.join(UI_DIR, "assets")))
    except OSError:
        return 0


def install_ui():
    src = os.path.join(os.path.dirname(SELF_PATH), "ui")
    if os.path.realpath(src) == os.path.realpath(UI_DIR):
        return "same"
    if not os.path.isdir(os.path.join(src, "assets")):
        return "missing"
    staged = UI_DIR + ".new"
    shutil.rmtree(staged, ignore_errors=True)
    shutil.copytree(src, staged)
    shutil.rmtree(UI_DIR, ignore_errors=True)
    os.replace(staged, UI_DIR)
    return "copied"


def step(n, total, title):
    print()
    print("%s %s" % (cyan("[%d/%d]" % (n, total)), bold(title)))


def do_install():
    if not sys.stdin.isatty():
        print("%s install asks for a username and a password, so it needs a terminal." % BAD)
        return False
    total = 6

    step(1, total, "files")
    os.makedirs(CENTRAL_DIR, exist_ok=True)
    os.chmod(CENTRAL_DIR, 0o700)
    if os.path.realpath(SELF_PATH) != INSTALLED:
        shutil.copy2(SELF_PATH, INSTALLED)
        os.chmod(INSTALLED, 0o755)
        print("%s panel installed at %s" % (OK, INSTALLED))
    else:
        print("%s already running from %s" % (OK, INSTALLED))
    outcome = install_ui()
    if outcome == "copied":
        print("%s web ui installed - %d files" % (OK, ui_files()))
    elif outcome == "same" and ui_files():
        print("%s web ui already in place - %d files" % (OK, ui_files()))
    else:
        print("%s no ui folder next to %s" % (BAD, SELF_PATH))
        print("    unpack the release tarball and run it from inside that folder.")
        return False

    step(2, total, "dependencies")
    install_deps()

    step(3, total, "port and login")
    conf = load_conf() if os.path.isfile(WEB_CONF) else {}
    have = conf.get("port", 8080)
    conf["port"] = _port_or(input("Panel port [%s]: " % have), have)
    set_password(conf)

    step(4, total, "signing key")
    try:
        _signing_keys()
        print("%s rsa key ready" % OK)
    except Exception as e:
        print("%s openssl could not create the signing key (%s)" % (BAD, e))
        print("    without it every push to a node is refused, so the install stops here.")
        return False

    step(5, total, "service")
    write_service()
    svc("enable")
    svc("restart")
    if not service_settled():
        print("%s the service did not come up - journalctl -u %s" % (BAD, SERVICE))
        return False
    print("%s %s is active" % (OK, SERVICE))

    step(6, total, "core and agent")
    try:
        info = _stage_core("latest")
        print("%s core %s staged (%s)" % (OK, info["version"], ", ".join(info["arches"])))
    except Exception as e:
        print("%s could not pre-download the core (%s)" % (WARN, e))
        print("    stage it later from the panel: %s" % dim("هستهٔ داده / دریافت از گیت‌هاب"))
    try:
        meta = api_agent_fetch_git({})
        print("%s node agent v%s staged" % (OK, meta["version"]))
    except Exception as e:
        print("%s could not pre-download the node agent (%s)" % (WARN, e))
        print("    stage it later from the panel: %s" % dim("تنظیمات / بروزرسانیِ ایجنت"))

    print()
    print("%s tnl-central is installed and running." % green("[done]"))
    print("      open %s   user: %s" % (cyan("http://%s:%s/" % (central_ip(), conf["port"])), bold(conf.get("user"))))
    return True

def change_port():
    if not os.path.isfile(WEB_CONF):
        print("Not configured yet - run Install first.")
        return
    conf = load_conf()
    have = conf.get("port", 8080)
    p = input(f"New panel port [{have}]: ").strip()
    if not p:
        return
    conf["port"] = _port_or(p, have)
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


MENU = [
    ("1", "Install / reinstall", "asks for the port and a password"),
    ("2", "Update the web UI", "copies the ui folder next to this script"),
    ("3", "Restart the service", "picks up a replaced tnl-central.py"),
    ("4", "Change the port", ""),
    ("5", "Change the password", ""),
    ("6", "Uninstall", "keeps nodes, links and settings"),
    ("0", "Exit", ""),
]


def status():
    exists = os.path.isfile(SERVICE_FILE)
    conf = load_conf() if os.path.isfile(WEB_CONF) else {}
    if service_active():
        state = green("active")
    elif exists:
        state = gold("stopped")
    else:
        state = red("not installed")
    files = ui_files()
    ui = green("%d files" % files) if files else red("missing - use 2")
    print()
    print("  %s  %s" % (dim("service"), state))
    print("  %s  %s" % (dim("panel  "), cyan("http://%s:%s/" % (central_ip(), conf.get("port", "-")))))
    print("  %s  %s" % (dim("user   "), conf.get("user", "-")))
    print("  %s  %s" % (dim("web ui "), ui))
    print("  %s  %d nodes %s %d links" % (dim("fleet  "), len(load_nodes()), dim("/"), len(load_links())))


def refresh_ui():
    outcome = install_ui()
    if outcome == "copied":
        print("%s web ui refreshed - %d files in %s" % (OK, ui_files(), UI_DIR))
        return True
    if outcome == "same":
        print("%s this IS the installed copy, so there is nothing beside it to copy from." % WARN)
        print("    unpack the release tarball and run it from there:")
        print("    %s" % dim("cd /tmp/tnl && python3 tnl-central.py"))
        return False
    print("%s no ui folder next to %s" % (BAD, SELF_PATH))
    print("    unpack the release tarball and run this from inside it.")
    return False


def menu():
    if os.geteuid() != 0:
        print("Run as root (sudo).")
        sys.exit(1)
    os.makedirs(CENTRAL_DIR, exist_ok=True)
    while True:
        print()
        print(bold(cyan("=== tnl-central . control plane ===")))
        status()
        print()
        for key, title, note in MENU:
            line = "  %s %s" % (cyan(key + ")"), title)
            print(line + ("  " + dim(note) if note else ""))
        try:
            c = input(nl_prompt()).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        try:
            if c == "1":
                do_install()
            elif c == "2":
                refresh_ui()
            elif c == "3":
                do_restart()
            elif c == "4":
                change_port()
            elif c == "5":
                change_password()
            elif c == "6":
                uninstall()
            elif c == "0":
                return
            else:
                print("%s pick one of %s" % (WARN, ", ".join(k for k, _, _ in MENU)))
        except KeyboardInterrupt:
            print()
            print("%s cancelled - nothing was changed." % WARN)
        except SystemExit:
            print("%s that step stopped early." % WARN)
        except Exception as e:
            print("%s %s" % (BAD, e))


def nl_prompt():
    return "\n" + bold("choice: ")

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
        if not do_install():
            sys.exit(1)
    elif arg == "--install-ui":
        if os.geteuid() != 0:
            print("Run as root (sudo).")
            sys.exit(1)
        if not refresh_ui():
            sys.exit(1)
    elif arg == "--set-pass":
        if os.geteuid() != 0:
            print("Run as root (sudo).")
            sys.exit(1)
        change_password()
    else:
        menu()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        sys.exit(130)
