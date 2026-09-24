#!/usr/bin/env python3

import base64
import getpass
import gzip
import hashlib
import hmac
import http.client
import importlib.util
import io
import ipaddress
import ssl
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CENTRAL_DIR = "/opt/tnl-central"
WEB_CONF = os.path.join(CENTRAL_DIR, "web.conf")
UI_DIR = os.path.join(CENTRAL_DIR, "ui")
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
_drift = {}
_drift_lock = threading.Lock()
_CENTRAL_PORT = 0
_CENTRAL_TLS = False
_BOOT_ID = secrets.token_hex(8)
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


def _central_headers(node, proxied):
    if not _CENTRAL_PORT:
        return {}
    h = {"X-Central-Port": str(_CENTRAL_PORT), "X-Central-TLS": "1" if _CENTRAL_TLS else "0"}
    ip = _panel_host_for(node, proxied)
    if is_ipv4(ip):
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


class Tx(str):
    def __new__(cls, fa, en):
        s = str.__new__(cls, fa)
        s.en = en
        return s

    def __reduce__(self):
        return Tx, (str(self), self.en)


def _fa_arg(v):
    return "، ".join(map(str, v)) if isinstance(v, (list, tuple)) else v


def _en(v):
    if isinstance(v, (list, tuple)):
        return ", ".join(str(_en(x)) for x in v)
    return v.en if isinstance(v, Tx) else v


def tx(fa, en, *a, **kw):
    if not (a or kw):
        return Tx(fa, en)
    return Tx(fa.format(*map(_fa_arg, a), **{k: _fa_arg(v) for k, v in kw.items()}),
              en.format(*map(_en, a), **{k: _en(v) for k, v in kw.items()}))


def tx_join(sep, parts, en_sep=None):
    parts = list(parts)
    return Tx(sep.join(map(str, parts)), (sep if en_sep is None else en_sep).join(str(_en(p)) for p in parts))


def tx_cut(t, n):
    return Tx(str(t)[:n], str(_en(t))[:n])


class Bad(ValueError):
    def __init__(self, code, fa, en=None, *a, **kw):
        self.code = code
        super().__init__(fa if en is None else tx(fa, en, *a, **kw))


def _no_node():
    return Bad("node_not_found", "نود پیدا نشد", "node not found")


def _no_tunnel():
    return Bad("tunnel_not_found", "تونل پیدا نشد", "tunnel not found")


def _no_proxy():
    return Bad("proxy_not_found", "پروکسی پیدا نشد", "proxy not found")


def _no_item():
    return Bad("item_not_found", "مورد پیدا نشد", "item not found")


def _no_job():
    return Bad("job_not_running", "این کار دیگر در جریان نیست", "this job is no longer running")


def _ends_gone():
    return Bad("node_not_found", "یکی از نودهای این تونل دیگر در پنل ثبت نیست", "one of this tunnel's nodes is no longer registered")


def _no_custom_core():
    return Bad("no_custom_core", "هیچ باینریِ سفارشی‌ای بارگذاری نشده", "no custom core binary is uploaded")


_FAILED = tx("ناموفق", "failed")


def _why(e):
    t = e.args[0] if len(e.args) == 1 else None
    return t if isinstance(t, Tx) else Tx(str(e), str(e))


def _code(e):
    if isinstance(e, (Bad, RegistryError)):
        return e.code
    return "invalid_request" if isinstance(e, ValueError) else "internal"


def _err_en(e, status):
    return {"code": status, "error": _code(e), "message": _why(e).en}


def _is_fail(v):
    return isinstance(v, dict) and isinstance(v.get("code"), str) and bool(v["code"]) and "error" in v


def _en_out(v):
    if isinstance(v, Tx):
        return v.en
    if _is_fail(v):
        return _en_fail(v)
    if isinstance(v, dict):
        return {k: _en_out(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_en_out(x) for x in v]
    return v


def _en_fail(v):
    out = {}
    for k, x in v.items():
        if k == "code":
            out["code"] = v.get("http", 400)
        elif k == "error":
            out["error"], out["message"] = v["code"], _en_out(x)
        elif k != "http":
            out[k] = _en_out(x)
    return out


def _en_reply(res):
    out = _en_out(res)
    if not isinstance(out, dict):
        return 200, out
    status = out["code"] if _is_fail(res) else 200
    return status, {"code": status, **{k: x for k, x in out.items() if k != "code"}}


def _copy(v):
    if isinstance(v, dict):
        return {k: _copy(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_copy(x) for x in v]
    return v


def _int_or(v, bad):
    if isinstance(v, int) and not isinstance(v, bool):
        return v
    try:
        return int(str(v).strip())
    except ValueError:
        raise bad from None


def _num_or(v, bad):
    try:
        return float(str(v).strip())
    except ValueError:
        raise bad from None


def _int_in(v, lo, hi, bad):
    n = _int_or(v, bad)
    if not lo <= n <= hi:
        raise bad
    return n


def _bad_tunnel_port():
    return Bad("bad_port", "پورت باید عددی بینِ 1 تا 65535 باشد", "port must be a number from 1 to 65535")


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


class RegistryError(Exception):
    code = "store_error"


def read_json(path, kind):
    name = os.path.basename(path)
    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        raise RegistryError(tx("فایلِ «{0}» روی دیسکِ پنل نیست", "file '{0}' is not on the panel's disk", name))
    except (OSError, ValueError) as e:
        raise RegistryError(tx("فایلِ «{0}» خوانده نشد — تا درست نشود پنل رویِ آن چیزی نمی‌نویسد: {1}",
                               "file '{0}' could not be read — the panel will not write over it until it is fixed: {1}",
                               name, str(e)[:120]))
    if not isinstance(data, kind):
        raise RegistryError(tx("فایلِ «{0}» شکلِ درستی ندارد", "file '{0}' has the wrong shape", name))
    return data


def load_conf():
    return read_json(WEB_CONF, dict)


def save_bytes(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path) or CENTRAL_DIR, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def save_json(path, obj):
    save_bytes(path, json.dumps(obj, indent=2).encode(), 0o600)


REDIS_SOCK = "/run/tnl-redis/redis.sock"
REDIS_DIR = "/var/lib/tnl-redis"
REDIS_CONF = "/etc/tnl-redis.conf"
REDIS_SERVICE = "tnl-redis.service"
REDIS_UNIT_FILE = "/etc/systemd/system/" + REDIS_SERVICE
REDIS_TIMEOUT = 10
REDIS_MUST = {"appendonly": "yes", "appendfsync": "always", "maxmemory-policy": "noeviction", "save": ""}
STORE_FREE_MIN = 1 << 30
STORE_DOWN = tx("ذخیره‌سازِ پنل (ردیس) در دسترس نیست", "the panel's store (Redis) is unavailable")
STORE_RO = "رکوردِ ذخیره‌شده فقط‌خواندنی است — تغییر فقط از راهِ store_edit/store_tx"


class StoreError(RegistryError):
    code = "store_unavailable"


class StoreUnknown(StoreError):
    code = "store_unknown"


def _ro(*a, **k):
    raise TypeError(STORE_RO)


class _FrozenDict(dict):
    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _ro

    def __copy__(self):
        return dict(self)

    def __deepcopy__(self, memo):
        return _thaw(self)


class _FrozenList(list):
    __setitem__ = __delitem__ = append = extend = insert = pop = remove = clear = sort = reverse = _ro
    __iadd__ = __imul__ = _ro

    def __copy__(self):
        return list(self)

    def __deepcopy__(self, memo):
        return _thaw(self)


def _freeze(v):
    if isinstance(v, dict):
        return _FrozenDict((k, _freeze(x)) for k, x in v.items())
    if isinstance(v, list):
        return _FrozenList(_freeze(x) for x in v)
    return v


def _thaw(v):
    return json.loads(json.dumps(v))


def _enc(v):
    return json.dumps(v, ensure_ascii=False, separators=(",", ":"))


_R = None
_R_lock = threading.Lock()


def _redis_client(db=0, decode=True):
    try:
        import redis
        from redis.backoff import NoBackoff
        from redis.retry import Retry
    except ImportError:
        raise StoreError(tx("کتابخانهٔ پایتونِ ردیس (python3-redis) نصب نیست — نصب را دوباره اجرا کن: "
                            "sudo python3 tnl-central.py --install",
                            "the Redis Python library (python3-redis) is not installed — run the install again: "
                            "sudo python3 tnl-central.py --install")) from None
    return redis.Redis(unix_socket_path=REDIS_SOCK, db=db, decode_responses=decode, socket_timeout=REDIS_TIMEOUT,
                       socket_connect_timeout=3, retry=Retry(NoBackoff(), 0))


def _redis():
    global _R
    if _R is None:
        with _R_lock:
            if _R is None:
                _R = _redis_client()
    return _R


def _store_exc(e):
    rx = sys.modules.get("redis.exceptions")
    return isinstance(e, OSError) or (rx is not None and isinstance(e, rx.RedisError))


def _store_why(e):
    s = str(e)
    rx = sys.modules.get("redis.exceptions")
    if "maxmemory" in s or s.startswith("OOM"):
        return tx("حافظهٔ ردیس پر است", "Redis memory is full")
    if "MISCONF" in s:
        return tx("ردیس نمی‌تواند روی دیسک بنویسد", "Redis cannot write to disk")
    if isinstance(e, TimeoutError) or (rx is not None and isinstance(e, rx.TimeoutError)):
        return tx("ردیس دیر جواب داد", "Redis answered too late")
    if isinstance(e, OSError) or (rx is not None and isinstance(e, rx.ConnectionError)):
        return tx("اتصال به ردیس برقرار نشد", "could not connect to Redis")
    return tx("ردیس خطا داد", "Redis returned an error")


def _store_msg(e):
    if isinstance(e, RegistryError):
        return _why(e)
    if _store_exc(e):
        return tx("{0} ({1})", "{0} ({1})", STORE_DOWN, _store_why(e))
    raise e


class _Snap:
    __slots__ = ("rows", "by_id", "score")

    def __init__(self, rows=(), score=None):
        self.rows = tuple(rows)
        self.by_id = {r["id"]: r for r in self.rows}
        self.score = score or {}


class _Coll:
    def __init__(self, name, label):
        self.name, self.label = name, label
        self.hkey, self.okey = "tnl:" + name, "tnl:" + name + ":order"
        self.snap = _Snap()


_NODES = _Coll("nodes", tx("نودها", "nodes"))
_LINKS = _Coll("links", tx("تونل‌ها", "tunnels"))
_PROXIES = _Coll("proxies", tx("پروکسی‌ها", "proxies"))
_COLLS = {c.name: c for c in (_NODES, _LINKS, _PROXIES)}
_GROUPS = ("nodes", "links", "proxies", "settings", "pending", "moved", "pforder")
K_PFORDER = "tnl:portfw:order"


class _Mirror:
    def __init__(self):
        self.loaded = False
        self.settings = None
        self.pending = {}
        self.moved = {}
        self.pforder = ()
        self.bad = frozenset()


_M = _Mirror()
_bad_lock = threading.Lock()


def _mark_bad(groups, bad):
    with _bad_lock:
        _M.bad = (_M.bad | set(groups)) if bad else (_M.bad - set(groups))


_BAD = object()


def _json_field(key, field, raw, kind):
    try:
        v = json.loads(raw)
    except (TypeError, ValueError):
        v = _BAD
    if v is _BAD or (kind is not None and not isinstance(v, kind)):
        raise RegistryError(tx("دادهٔ «{0}{1}» در ردیس خراب است", "data '{0}{1}' in Redis is corrupt",
                               key, " / " + field if field else ""))
    return v


def _coll_parse(c, order, raw):
    ids = [m for m, _s in order]
    if set(ids) != set(raw) or len(ids) != len(raw):
        odd = sorted(set(raw) ^ set(ids))[:4]
        raise RegistryError(tx("ترتیب و رکوردهای «{0}» ({1}) در ردیس با هم نمی‌خوانند: {2}",
                               "the order and the records of '{0}' ({1}) in Redis do not match: {2}",
                               c.label, c.hkey, odd))
    rows = []
    for rid in ids:
        rec = _json_field(c.hkey, rid, raw[rid], dict)
        if rec.get("id") != rid:
            raise RegistryError(tx("شناسهٔ رکوردِ «{0}» ({1} / {2}) در ردیس با کلیدش یکی نیست",
                                   "the record id of '{0}' ({1} / {2}) in Redis does not match its key",
                                   c.label, c.hkey, rid))
        rows.append(rec)
    return rows, {m: float(s) for m, s in order}


def _store_read(r, groups):
    p = r.pipeline(transaction=True)
    for g in groups:
        if g in _COLLS:
            p.zrange(_COLLS[g].okey, 0, -1, withscores=True)
            p.hgetall(_COLLS[g].hkey)
        elif g == "pforder":
            p.get(K_PFORDER)
        else:
            p.hgetall("tnl:" + g)
    res = iter(p.execute())
    out = {}
    for g in groups:
        if g in _COLLS:
            out[g] = _coll_parse(_COLLS[g], next(res), next(res))
        elif g == "pforder":
            out[g] = _json_field(K_PFORDER, "", next(res) or "[]", list)
        else:
            want = {"pending": list, "moved": dict}.get(g)
            out[g] = {k: _json_field("tnl:" + g, k, v, want) for k, v in next(res).items()}
    return out


def _store_publish(data):
    for g, v in data.items():
        if g in _COLLS:
            rows, score = v
            _COLLS[g].snap = _Snap([_freeze(x) for x in rows], score)
        elif g == "settings":
            _M.settings = _freeze(settings_full(v))
        elif g == "pending":
            _M.pending = {k: tuple(str(x) for x in names) for k, names in v.items() if names}
        elif g == "moved":
            _M.moved = {k: _freeze(x) for k, x in v.items()}
        elif g == "pforder":
            _M.pforder = tuple(str(x) for x in v)


def _store_guard(r):
    bad = []
    for k, want in REDIS_MUST.items():
        got = r.config_get(k).get(k)
        if got != want:
            bad.append(tx("{0}={1} (باید «{2}» باشد)", "{0}={1} (must be '{2}')", k, "?" if got is None else got, want))
    if bad:
        raise StoreError(tx("ردیس با تنظیمِ امن اجرا نمی‌شود: {0} — فایلِ {1} را درست کن یا نصب را دوباره اجرا کن",
                            "Redis is not running with the safe settings: {0} — fix {1} or run the install again",
                            bad, REDIS_CONF))


_store_boot_lock = threading.Lock()


def store_boot(wait=0):
    with _store_boot_lock:
        if _M.loaded:
            return
        r = _redis()
        until = time.time() + wait
        while True:
            try:
                r.ping()
                break
            except Exception as e:
                if not _store_exc(e):
                    raise
                if time.time() >= until:
                    raise StoreError(tx("{0} — systemctl status {1}", "{0} — systemctl status {1}",
                                        _store_msg(e), REDIS_SERVICE)) from None
                time.sleep(1)
        try:
            _store_guard(r)
            data = _store_read(r, _GROUPS)
        except RegistryError:
            raise
        except Exception as e:
            raise StoreError(_store_msg(e)) from None
        _store_publish(data)
        _M.loaded = True


def _store_ready():
    if not _M.loaded:
        store_boot()


def _store_resync(groups):
    try:
        data = _store_read(_redis(), sorted(groups))
    except RegistryError:
        raise
    except Exception as e:
        raise StoreError(_store_msg(e)) from None
    _store_publish(data)
    _mark_bad(groups, False)


def _group_lock(g):
    return {"pending": _pending_lock, "moved": _moved_lock}.get(g, _reg_lock)


class _Tx:
    def __init__(self):
        self.ops = []

    def put(self, c, rec):
        self.ops.append(("put", c.name, rec["id"], _enc(rec)))

    def drop(self, c, rid):
        self.ops.append(("drop", c.name, rid))

    def order(self, c, ids):
        self.ops.append(("order", c.name, [str(x) for x in ids]))

    def settings(self, obj):
        self.ops.append(("settings", {k: _enc(v) for k, v in obj.items()}))

    def pending(self, nid, names):
        self.ops.append(("pending", nid, [str(x) for x in names]))

    def moved(self, nid, val):
        self.ops.append(("moved", nid, val))

    def pforder(self, keys):
        self.ops.append(("pforder", [str(x) for x in keys]))

    def raw(self, fn):
        self.ops.append(("raw", fn))


def _op_group(op):
    if op[0] in ("put", "drop", "order"):
        return op[1]
    return None if op[0] == "raw" else op[0]


class _TxWork:
    def __init__(self, groups):
        self.colls = {}
        for g in groups:
            if g in _COLLS:
                s = _COLLS[g].snap
                self.colls[g] = ([x["id"] for x in s.rows], dict(s.by_id), dict(s.score))
        self.settings = self.pforder = None
        self.pending = dict(_M.pending) if "pending" in groups else None
        self.moved = dict(_M.moved) if "moved" in groups else None

    def emit(self, p, op):
        kind = op[0]
        if kind in ("put", "drop", "order"):
            c = _COLLS[op[1]]
            ids, by, sc = self.colls[op[1]]
        if kind == "put":
            rid, payload = op[2], op[3]
            p.hset(c.hkey, rid, payload)
            if rid not in by:
                sc[rid] = max(sc.values(), default=-1.0) + 1
                ids.append(rid)
                p.zadd(c.okey, {rid: sc[rid]})
            by[rid] = _freeze(json.loads(payload))
        elif kind == "drop":
            rid = op[2]
            p.hdel(c.hkey, rid)
            p.zrem(c.okey, rid)
            if rid in by:
                ids.remove(rid)
                by.pop(rid)
                sc.pop(rid, None)
        elif kind == "order":
            new_ids = op[2]
            if sorted(new_ids) != sorted(ids):
                raise Bad("order_stale", "ترتیبِ تازه با فهرستِ فعلی نمی‌خواند — صفحه را تازه کن و دوباره بکش",
                          "the new order does not match the current list — reload and try again")
            slots = sorted(sc[i] for i in ids)
            moved = {rid: slots[k] for k, rid in enumerate(new_ids) if sc[rid] != slots[k]}
            if moved:
                p.zadd(c.okey, moved)
                sc.update(moved)
            ids[:] = new_ids
        elif kind == "settings":
            p.delete("tnl:settings")
            if op[1]:
                p.hset("tnl:settings", mapping=op[1])
            self.settings = {k: json.loads(v) for k, v in op[1].items()}
        elif kind == "pending":
            nid, names = op[1], op[2]
            if names:
                p.hset("tnl:pending", nid, _enc(names))
                self.pending[nid] = tuple(names)
            else:
                p.hdel("tnl:pending", nid)
                self.pending.pop(nid, None)
        elif kind == "moved":
            nid, val = op[1], op[2]
            if val is None:
                p.hdel("tnl:moved", nid)
                self.moved.pop(nid, None)
            else:
                p.hset("tnl:moved", nid, _enc(val))
                self.moved[nid] = _freeze(val)
        elif kind == "pforder":
            p.set(K_PFORDER, _enc(op[1]))
            self.pforder = tuple(op[1])
        else:
            op[1](p)

    def publish(self):
        for g, (ids, by, sc) in self.colls.items():
            _COLLS[g].snap = _Snap([by[i] for i in ids], sc)
        if self.settings is not None:
            _M.settings = _freeze(settings_full(self.settings))
        if self.pending is not None:
            _M.pending = self.pending
        if self.moved is not None:
            _M.moved = self.moved
        if self.pforder is not None:
            _M.pforder = self.pforder


def _op_landed(op):
    kind = op[0]
    if kind == "put":
        return _COLLS[op[1]].snap.by_id.get(op[2]) == json.loads(op[3])
    if kind == "drop":
        return op[2] not in _COLLS[op[1]].snap.by_id
    if kind == "order":
        return [x["id"] for x in _COLLS[op[1]].snap.rows] == op[2]
    if kind == "settings":
        return all(_M.settings.get(k) == json.loads(v) for k, v in op[1].items())
    if kind == "pending":
        return _M.pending.get(op[1], ()) == tuple(op[2])
    if kind == "moved":
        return _M.moved.get(op[1]) == op[2]
    if kind == "pforder":
        return _M.pforder == tuple(op[1])
    return True


def _tx_commit(ops):
    if not ops:
        return
    _store_ready()
    groups = {g for g in map(_op_group, ops) if g}
    if groups & _M.bad:
        _store_resync(groups & _M.bad)
    work = _TxWork(groups)
    p = _redis().pipeline(transaction=True)
    for op in ops:
        work.emit(p, op)
    try:
        p.execute()
    except Exception as e:
        if not _store_exc(e):
            raise
        log_warn("store", "write failed: %s" % str(e)[:300])
        unknown = StoreUnknown(tx("{0} — معلوم نیست این تغییر ذخیره شد یا نه؛ وقتی برگشت، فهرست را دوباره ببین",
                                  "{0} — it is unknown whether this change was saved; when it is back, check the list again",
                                  STORE_DOWN))
        if not groups:
            raise unknown from None
        try:
            _store_resync(groups)
        except StoreError:
            _mark_bad(groups, True)
            raise unknown from None
        if all(_op_landed(op) for op in ops):
            log_warn("store", "the write landed despite the error")
            return
        raise StoreError(tx("ذخیره نشد — {0}", "not saved — {0}", _store_why(e))) from None
    work.publish()


class store_tx:
    def __enter__(self):
        self.t = _Tx()
        return self.t

    def __exit__(self, et, ev, tb):
        if et is None:
            _tx_commit(self.t.ops)
        return False


def store_edit(c, rid, fn):
    cur = c.snap.by_id.get(rid)
    if cur is None:
        return None
    new = _thaw(cur)
    fn(new)
    if new != cur:
        with store_tx() as t:
            t.put(c, new)
    return c.snap.by_id.get(rid)


_store_issues = []


def _store_health():
    global _store_issues
    issues = []
    try:
        r = _redis()
        _store_guard(r)
        info = r.info("persistence")
        if info.get("aof_last_write_status", "ok") != "ok":
            issues.append(tx("ردیس نتوانست دادهٔ پنل را روی دیسک بنویسد (aof_last_write_status)",
                             "Redis could not write the panel's data to disk (aof_last_write_status)"))
        if info.get("aof_last_bgrewrite_status", "ok") != "ok":
            issues.append(tx("فشرده‌سازیِ فایلِ ردیس (AOF rewrite) شکست خورد",
                             "compacting the Redis file (AOF rewrite) failed"))
        for g in sorted(_M.bad):
            with _group_lock(g):
                if g in _M.bad:
                    _store_resync({g})
    except Exception as e:
        issues.append(_store_msg(e))
    try:
        st = os.statvfs(REDIS_DIR)
        free = st.f_bavail * st.f_frsize
        if free < STORE_FREE_MIN:
            issues.append(tx("روی دیسکِ ردیس فقط {0:.1f} گیگابایت جا مانده — اگر پر شود، پنل هیچ تغییری را ذخیره نمی‌کند",
                             "only {0:.1f} GB is left on the Redis disk — if it fills up, the panel saves no change",
                             free / 1e9))
    except OSError:
        pass
    if _M.bad:
        issues.append(tx("این بخش‌ها بعد از خطای ذخیره هنوز با ردیس هماهنگ نشده‌اند: {0}",
                         "these parts are still out of sync with Redis after a save error: {0}", sorted(_M.bad)))
    with _events_lock:
        backlog = len(_ev_out)
    if backlog and time.time() - _ev_saved[0] > 60:
        issues.append(tx("{0} رویدادِ لاگ هنوز در ردیس ذخیره نشده", "{0} log events are not saved in Redis yet", backlog))
    _store_issues = issues


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
_TUNING_LIST_LABELS = {"suspect_backoff": tx("زمان‌بندیِ تستِ مجددِ موقت‌سوخته", "retest schedule of a suspect IP"),
                       "ladder_revive": tx("صبر پیش از تلاشِ دوبارهٔ نردبان", "wait before the ladder tries again")}
_TUNING_NUM_LABELS = {"dead_retest_secs": tx("تستِ مجددِ آی‌پیِ سوخته", "retest of a dead IP"),
                      "probe_min_pct": tx("حداقلِ بسته‌های برگشتی", "minimum returned packets"),
                      "sock_buf_mb": tx("بافرِ سوکت", "socket buffer")}
_TUNING_STEPS = {"probe_min_pct": (5, _TUNING_NUM_LABELS["probe_min_pct"])}
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
        raise Bad("bad_raw_proto", "شمارهٔ پروتکلِ IP باید بینِ 1 تا 255 باشد", "the IP protocol number must be from 1 to 255")
    owner = _raw_proto_owner(proto)
    if owner:
        raise Bad("raw_proto_taken",
                  "پروتکلِ {0} مالِ پروفایلِ «{1}» است. این حامل هیچ هدری نمی‌سازد، پس پاکت با "
                  "شمارهٔ {0} بیرون می‌رود ولی جای هدرِ {1} دادهٔ رمزشده دارد — دستگاه‌های میانِ راه "
                  "آن را بدشکل می‌بینند و می‌اندازند. پروفایلِ «{1}» را انتخاب کن که هدرش را هم می‌سازد.",
                  "protocol {0} belongs to the '{1}' profile. This carrier builds no header, so the packet leaves "
                  "with protocol {0} but has encrypted data where the {1} header should be — middleboxes see it "
                  "as malformed and drop it. Pick the '{1}' profile, which builds the header too.",
                  int(proto), owner)


def _validate_tuning(raw, base=None):
    out = dict(_TUNING_DEFAULTS)
    if isinstance(base, dict):
        out.update({k: base[k] for k in _TUNING_DEFAULTS if k in base})
    if not isinstance(raw, dict):
        return out
    for k, (lo, hi) in _TUNING_RANGES.items():
        if k in raw and raw[k] in (None, ""):
            raise Bad("tuning_empty", "«{0}» را خالی نگذار — عددی بینِ {1} تا {2} بگذار",
                      "'{0}' must not be empty — enter a number from {1} to {2}", _TUNING_NUM_LABELS.get(k, k), lo, hi)
        if k in raw and raw[k] not in (None, ""):
            try:
                v = int(raw[k])
            except (TypeError, ValueError):
                raise Bad("tuning_not_int", "«{0}» باید عددِ صحیح باشد", "'{0}' must be a whole number",
                          _TUNING_NUM_LABELS.get(k, k))
            step, label = _TUNING_STEPS.get(k, (0, ""))
            if step and v % step:
                raise Bad("tuning_step", "«{0}» باید مضربی از {1} باشد — {2} پذیرفته نیست",
                          "'{0}' must be a multiple of {1} — {2} is not accepted", label, step, v)
            if not lo <= v <= hi:
                raise Bad("tuning_range", "«{0}» باید بینِ {1} تا {2} باشد — {3} پذیرفته نیست",
                          "'{0}' must be from {1} to {2} — {3} is not accepted", _TUNING_NUM_LABELS.get(k, k), lo, hi, v)
            out[k] = v
    for k, (lo, hi) in _TUNING_LIST_RANGES.items():
        if k not in raw:
            continue
        try:
            steps = [int(x) for x in raw[k]] if isinstance(raw[k], (list, tuple)) else []
        except (TypeError, ValueError):
            steps = []
        if not steps:
            raise Bad("tuning_list", "«{0}» باید یک یا چند عددِ صحیح بینِ {1} تا {2} ثانیه باشد",
                      "'{0}' must be one or more whole numbers from {1} to {2} seconds", _TUNING_LIST_LABELS[k], lo, hi)
        for iv in steps:
            if not lo <= iv <= hi:
                raise Bad("tuning_range", "«{0}» باید بینِ {1} تا {2} ثانیه باشد — {3} پذیرفته نیست",
                          "'{0}' must be from {1} to {2} seconds — {3} is not accepted", _TUNING_LIST_LABELS[k], lo, hi, iv)
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


def settings_full(raw):
    d = settings_defaults()
    d.update(raw)
    return d


DELIVERY_MODES = ("push", "github", "panel")


def get_settings():
    _store_ready()
    return dict(_M.settings)


def validate_settings(d):
    out = get_settings()
    if "reconcile_mode" in d:
        m = str(d["reconcile_mode"]).strip().lower()
        if m not in ("auto", "alert"):
            raise Bad("bad_reconcile_mode", "حالت باید auto یا alert باشد", "the mode must be auto or alert")
        out["reconcile_mode"] = m
    if "reconcile_interval" in d and d["reconcile_interval"] not in (None, ""):
        sec = _num_or(d["reconcile_interval"], Bad("bad_number", "بازهٔ بررسیِ ترمیم باید عدد باشد (ثانیه)",
                                                   "the repair check interval must be a number (seconds)"))
        out["reconcile_interval"] = int(round(max(5, min(3600, sec))))
    if "poll_interval" in d and d["poll_interval"] not in (None, ""):
        out["poll_interval"] = max(0.3, min(60.0, round(_num_or(d["poll_interval"], Bad(
            "bad_number", "بازهٔ پایشِ فلیت باید عدد باشد (ثانیه)", "the fleet poll interval must be a number (seconds)")), 2)))
    if "ui_interval" in d and d["ui_interval"] not in (None, ""):
        out["ui_interval"] = max(0.3, min(60.0, round(_num_or(d["ui_interval"], Bad(
            "bad_number", "بازهٔ رفرشِ نمایش باید عدد باشد (ثانیه)", "the screen refresh interval must be a number (seconds)")), 2)))
    if "uptime_window" in d and d["uptime_window"] not in (None, ""):
        w = _int_or(d["uptime_window"], Bad("bad_number", "بازهٔ نمودارِ دسترس‌پذیری نامعتبر است",
                                            "the uptime chart window is invalid"))
        out["uptime_window"] = w if w in (1, 3, 6, 8, 12, 24) else 1
    if "ech_refresh_mins" in d and d["ech_refresh_mins"] not in (None, ""):
        m = round(_num_or(d["ech_refresh_mins"], Bad("bad_number", "بازهٔ تازه‌سازیِ کلیدِ ECH باید عدد باشد (دقیقه)",
                                                     "the ECH key refresh interval must be a number (minutes)")), 2)
        out["ech_refresh_mins"] = 0.0 if m <= 0 else max(1.0, min(1440.0, m))
    for k in ("agent_delivery", "core_delivery"):
        if k in d:
            m = str(d[k]).strip().lower()
            if m not in DELIVERY_MODES:
                raise Bad("bad_delivery", "حالتِ تحویل باید یکی از push / github / panel باشد",
                          "the delivery mode must be push, github or panel")
            out[k] = m
    if "api_external" in d:
        out["api_external"] = bool(d["api_external"])
    if "dl_proxy_on" in d or "dl_proxy_id" in d:
        on = bool(d.get("dl_proxy_on", out.get("dl_proxy_on")))
        pid = str(d.get("dl_proxy_id", out.get("dl_proxy_id")) or "").strip()
        if on:
            if not pid:
                raise Bad("proxy_missing", "یک پروکسی از فهرست انتخاب کن", "pick a proxy from the list")
            if not get_proxy(pid):
                raise Bad("proxy_not_found", "پروکسی پیدا نشد — شاید حذف شده باشد", "proxy not found — it may have been deleted")
        out["dl_proxy_on"], out["dl_proxy_id"] = on, pid if on else ""
    if "log_hidden" in d:
        raw = d["log_hidden"]
        if not isinstance(raw, list):
            raise Bad("bad_log_filter", "فهرستِ فیلترِ لاگ باید یک آرایه باشد", "the log filter must be an array")
        picked = {str(x) for x in raw}
        bad = sorted(picked - set(EV_TYPE_GROUP))
        if bad:
            raise Bad("unknown_event_type", "این نوعِ رویداد را نمی‌شناسم: {0}", "unknown event type: {0}", bad)
        out["log_hidden"] = [t for t, _g, _label in EV_TYPES if t in picked]
    if "tuning" in d:
        out["tuning"] = _validate_tuning(d["tuning"], out.get("tuning"))
    return out


_moved_lock = threading.Lock()


def _moved_note(nid, name, old, new, new_port):
    with _moved_lock:
        prev = _M.moved.get(nid)
        fresh = not prev or (prev.get("to"), prev.get("to_port")) != (new, new_port)
        if fresh:
            with store_tx() as t:
                t.moved(nid, {"to": new, "to_port": new_port})
        return fresh


def _moved_clear(nid):
    with _moved_lock:
        if nid in _M.moved:
            with store_tx() as t:
                t.moved(nid, None)


def _moved_gc(valid):
    stale = [k for k in _M.moved if k not in valid]
    if not stale:
        return
    try:
        with _moved_lock, store_tx() as t:
            for k in stale:
                t.moved(k, None)
    except StoreError as e:
        log_warn("moved", str(e))


def moved_to(nid):
    v = _M.moved.get(nid)
    return v["to"] if v else ""


def moved_port(nid):
    v = _M.moved.get(nid)
    return int(v.get("to_port") or 0) if v else 0


def moved_addr(nid):
    v = _M.moved.get(nid)
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


def secret_eq(a, b):
    return hmac.compare_digest(str(a).encode("utf-8", "surrogatepass"),
                               str(b).encode("utf-8", "surrogatepass"))


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERS)
    return salt, dk.hex()


def verify_password(conf, password):
    try:
        _, got = hash_password(password, conf.get("salt", ""))
    except Exception:
        return False
    return secret_eq(got, conf.get("hash", ""))


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
    if not secret_eq(good, sig):
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


def _gate(store, key, gap, cap):
    now = time.time()
    if now - store.get(key, 0.0) < gap:
        return False
    store.pop(key, None)
    store[key] = now
    while len(store) > cap:
        del store[next(iter(store))]
    return True


def note_blocked(ip):
    with _fails_lock:
        return _gate(_blk_logged, ip, FAIL_WINDOW, FAIL_MAX_KEYS)


def log_internal(where):
    sys.stderr.write("tnl-central: %s failed\n%s" % (where, traceback.format_exc()))
    sys.stderr.flush()


WARN_GAP = 60
WARN_MAX_KEYS = 512
_warn_last = {}
_warn_lock = threading.Lock()


def log_warn(key, msg):
    with _warn_lock:
        if not _gate(_warn_last, key, WARN_GAP, WARN_MAX_KEYS):
            return
    print("tnl-central: %s: %s" % (key, msg), file=sys.stderr, flush=True)


def load_nodes():
    _store_ready()
    return list(_NODES.snap.rows)


def load_links():
    _store_ready()
    return list(_LINKS.snap.rows)


def get_node(nid):
    _store_ready()
    return _NODES.snap.by_id.get(nid)


def get_link(lid):
    _store_ready()
    return _LINKS.snap.by_id.get(lid)


def load_proxies():
    _store_ready()
    return list(_PROXIES.snap.rows)


def get_proxy(pid):
    _store_ready()
    return _PROXIES.snap.by_id.get(pid)


def node_proxy(node):
    if not (node or {}).get("proxy_on"):
        return ""
    p = get_proxy(str(node.get("proxy_id") or ""))
    return proxy_url(p) if p else ""


def _pending_add(node_id, name):
    if not node_id or not name:
        return True
    with _pending_lock:
        cur = _M.pending.get(node_id, ())
        if name in cur:
            return True
        try:
            with store_tx() as t:
                t.pending(node_id, cur + (name,))
            return True
        except StoreError as e:
            log_warn("pending", str(e))
            return False


def _pending_remove(node_id, name):
    with _pending_lock:
        cur = _M.pending.get(node_id, ())
        if name not in cur:
            return
        try:
            with store_tx() as t:
                t.pending(node_id, [x for x in cur if x != name])
        except StoreError as e:
            log_warn("pending", str(e))


def _pending_names(node_id):
    _store_ready()
    return list(_M.pending.get(node_id, ()))


def _pending_counts():
    _store_ready()
    return {k: len(v) for k, v in _M.pending.items()}


def _pending_gc(valid):
    stale = [k for k in _M.pending if k not in valid]
    if not stale:
        return
    try:
        with _pending_lock, store_tx() as t:
            for k in stale:
                t.pending(k, ())
    except StoreError as e:
        log_warn("pending", str(e))


_hold_lock = threading.Lock()
_held_names = {}


def _name_hold(owner, nids, name):
    with _hold_lock:
        _held_names[owner] = ({x for x in nids if x}, name)


def _name_free(owner):
    with _hold_lock:
        _held_names.pop(owner, None)


def _name_busy(nid, name):
    with _hold_lock:
        return any(name == nm and nid in ids for ids, nm in _held_names.values())


_EV_END_MISSING = {"srv": tx("نودِ سرورِ این تونل پیدا نشد", "the server node of this tunnel was not found"),
                   "cli": tx("نودِ کلاینتِ این تونل پیدا نشد", "the client node of this tunnel was not found")}


def _srv_is_a(L):
    return L.get("server_side") != "b"


def _node_id_of(L, end):
    return L.get("a_node") if (end == "srv") == _srv_is_a(L) else L.get("b_node")


def _client_node(L):
    return get_node(_node_id_of(L, "cli"))


_PX_CLOSED = tx("پروکسی اتصال را بست", "the proxy closed the connection")
_PX_WANTS_AUTH = tx("پروکسی یوزر/پسورد می‌خواهد", "the proxy wants a username and password")
_PX_BAD_AUTH = tx("یوزر/پسوردِ پروکسی پذیرفته نشد", "the proxy rejected the username and password")
_PX_BAD_METHOD = tx("پروکسی روشِ احرازِ ما را نپذیرفت", "the proxy rejected our authentication method")


def _recvn(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise OSError(_PX_CLOSED)
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
                raise OSError(_PX_WANTS_AUTH)
            u, w = pu.encode(), (pw or "").encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
            if _recvn(s, 2)[1] != 0:
                raise OSError(_PX_BAD_AUTH)
        elif method != 0:
            raise OSError(_PX_BAD_METHOD)
        try:
            addr = b"\x01" + socket.inet_aton(dh)
        except OSError:
            hb = dh.encode()
            addr = b"\x03" + bytes([len(hb)]) + hb
        s.sendall(b"\x05\x01\x00" + addr + int(dp).to_bytes(2, "big"))
        rep = _recvn(s, 4)
        if rep[1] != 0:
            raise OSError(tx("پروکسیِ SOCKS5 اتصال به مقصد را نساخت (کدِ {0})",
                             "the SOCKS5 proxy did not open the connection to the target (code {0})", rep[1]))
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
                raise OSError(_PX_CLOSED)
            buf += c
            if len(buf) > 65536:
                raise OSError(tx("پاسخِ پروکسی بیش از حد بزرگ است", "the proxy's answer is too large"))
        line = buf.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200" not in line:
            raise OSError(tx("پروکسی CONNECT را رد کرد: {0}", "the proxy refused CONNECT: {0}", line[:80]))
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
        raise Bad("unknown_node_route", "مسیرِ ناشناخته روی نود: {0!r}", "unknown route on the node: {0!r}", endpoint)


def proxy_parts(proxy):
    pu = urllib.parse.urlparse(proxy if "://" in proxy else "socks5://" + proxy)
    uq = lambda v: urllib.parse.unquote(v) if v else v
    return ((pu.scheme or "socks5").lower(), pu.hostname, pu.port,
            uq(pu.username) or "", uq(pu.password) or "")


def _proxy_socket(proxy, dh, dp, timeout):
    scheme, host, port, user, pw = proxy_parts(proxy)
    if not host or not port:
        raise OSError(tx("نشانیِ پروکسی نامعتبر است", "the proxy address is invalid"))
    if scheme.startswith("socks"):
        return _socks5_socket(host, port, user, pw, dh, dp, timeout)
    if scheme in ("http", "https", "connect"):
        return _http_connect_socket(host, port, user, pw, dh, dp, timeout)
    raise OSError(tx("نوعِ پروکسیِ «{0}» پشتیبانی نمی‌شود", "proxy type '{0}' is not supported", scheme))


def _net_why(e):
    r = getattr(e, "reason", None)
    if isinstance(r, BaseException):
        e = r
    if len(e.args) == 1 and isinstance(e.args[0], Tx):
        return e.args[0]
    return str(getattr(e, "strerror", None) or e)


_NODE_CUT = tx("نود وسطِ ارسال اتصال را بست", "the node closed the connection during the upload")
_NODE_UNREADABLE = tx("پاسخِ نود قابلِ خواندن نبود", "the node's answer could not be read")


def _node_http(status):
    return {"ok": False, "error": tx("پاسخِ HTTP {0} از نود", "HTTP {0} answer from the node", status)}


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
        headers.update(_central_headers(node, True))
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
            return _node_http(status)
        if _retry and _stale_ctr(node, out):
            return _node_call_proxied(node, proxy, endpoint, method, body, timeout, _retry=False)
        return out
    except Exception as e:
        return {"ok": False, "offline": True, "error": tx_cut(tx("پروکسی: {0}", "proxy: {0}", _net_why(e)), 90)}
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
    except Exception as e:
        return {"ok": False, "code": "panel", "error": tx("کلیدِ امضایِ پنل ساخته نشد (openssl?): {0}",
                                                          "the panel's signing key was not created (openssl?): {0}",
                                                          str(e)[:80])}
    r = node_call(node, "set-update-key", "POST", {"pubkey": pub}, timeout=15)
    if r.get("ok"):
        return r
    nm = node.get("name", "?")
    if r.get("offline"):
        return {"ok": False, "code": "offline", "error": tx("نودِ «{0}» جواب نداد", "node '{0}' did not answer", nm)}
    return {"ok": False, "code": "update_key",
            "error": tx("نودِ «{0}» کلیدِ امضایِ پنل را نپذیرفت؛ بدونِ آن هر پوشی رد می‌شود: {1}",
                        "node '{0}' did not accept the panel's signing key; without it every push is refused: {1}",
                        nm, r.get("error") or r.get("msg") or "?")}


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
    return {"ok": False, "offline": True, "error": tx("پاسخِ نود امضای معتبر ندارد", "the node's answer has no valid signature")}


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
    for k, v in _central_headers(node, False).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            if not _resp_verified(node, ctr, r.status, raw, r.headers.get("X-Resp-Sig", "")):
                return _unsigned_reply()
            out = json.loads(raw.decode())
            return out if isinstance(out, dict) else {"ok": False, "error": _NODE_UNREADABLE}
    except urllib.error.HTTPError as e:
        raw = e.read()
        if not _resp_verified(node, ctr, e.code, raw, e.headers.get("X-Resp-Sig", "")):
            return _unsigned_reply()
        try:
            out = json.loads(raw.decode())
        except Exception:
            out = None
        if not isinstance(out, dict):
            return _node_http(e.code)
        if _retry and _stale_ctr(node, out):
            return node_call(node, endpoint, method, body, timeout, _retry=False)
        return out
    except Exception as e:
        return {"ok": False, "offline": True, "error": tx_cut(_net_why(e), 80)}


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
        head += ["%s: %s" % kv for kv in _central_headers(node, bool(proxy)).items()]
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
                    raise OSError(_NODE_CUT)
                break
            n = sock.send(data[sent:sent + chunk])
            if not n:
                raise OSError(_NODE_CUT)
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
                raise OSError(tx("نود در مهلت جواب نداد", "the node did not answer in time"))
            try:
                b = sock.recv(65536)
            except socket.timeout:
                continue
            if not b:
                break
            raw += b
            if len(raw) > 1048576:
                raise OSError(tx("پاسخِ نود بیش از حد بزرگ است", "the node's answer is too large"))
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
            return {"ok": False, "error": tx("HTTP {0} از نود", "HTTP {0} from the node", status)}
        if not isinstance(out, dict):
            return {"ok": False, "error": _NODE_UNREADABLE}
        if _retry and _stale_ctr(node, out):
            return node_push(node, endpoint, body, on_progress, timeout, chunk, should_abort,
                             _retry=False)
        return out
    except Exception as e:
        return {"ok": False, "offline": True, "error": tx_cut(_net_why(e), 90)}
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
NODE_DOWN_PINGS = 3
NODE_GROUP_SECS = 10
NODE_HOLD_SECS = 30
CORE_SILENT_SECS = 30
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
_addr_gen = {}
_addr_gen_lock = threading.Lock()


def _addr_bump(nid):
    with _addr_gen_lock:
        _addr_gen[nid] = _addr_gen.get(nid, 0) + 1


def _addr_at(nid):
    with _addr_gen_lock:
        return _addr_gen.get(nid, 0)


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
        if _name_busy(nid, nm):
            continue
        if nm in live:
            _pending_remove(nid, nm)
            continue
        r = node_call(n, "delete", "POST", {"name": nm}, timeout=8)
        if r.get("ok"):
            _pending_remove(nid, nm)
            _tf_forget(nid, [nm])


def _tun_ok(h):
    if isinstance(h, dict) and h.get("up") is None:
        return None
    return bool(isinstance(h, dict) and h.get("up") and not h.get("dead"))


def _mark(prev, val, at):
    return prev if prev and prev[0] == val else (val, at)


def _marks(prev, ping, lst, ping_at, list_at):
    ok = bool(ping.get("ok"))
    seen = lst.get("configs") is not None
    tun = prev.get("tun") or {}
    node = _mark(prev.get("node"), ok, ping_at)
    fails = 0 if ok else prev.get("fails", 0) + 1
    conf = prev.get("conf")
    if ok or fails >= NODE_DOWN_PINGS:
        conf = _mark(conf, ok, node[1])
    return {"node": node, "fails": fails, "conf": conf,
            "seen": _mark(prev.get("seen"), seen, list_at),
            "tun": {nm: _mark(tun.get(nm), _tun_ok(h), list_at)
                    for nm, h in (lst.get("health") or {}).items()} if seen else tun}


def _poll_node(n):
    gen = _addr_at(n["id"])
    ping_at = time.time()
    _t0 = time.perf_counter()
    ping = node_call(n, "ping", "GET", timeout=6)
    if ping.get("ok"):
        ping = {**ping, "rtt_ms": int((time.perf_counter() - _t0) * 1000)}
    t_ping = time.time()
    if gen != _addr_at(n["id"]):
        return
    if not _tombed(n["id"], t_ping):
        if ping.get("ok"):
            s = ping.get("stats") or {}
            _tf_ingest(n["id"], s.get("net"), s.get("uptime"), t_ping)
        else:
            _tf_zero_rates(n["id"])
        _uh_sample(n["id"], bool(ping.get("ok")), t_ping)
    if ping.get("offline"):
        list_at, lst = ping_at, ping
    else:
        list_at = time.time()
        lst = node_call(n, "list", "GET", timeout=12)
    now = time.time()
    if _tombed(n["id"], now) or gen != _addr_at(n["id"]):
        return
    with _pc_lock:
        prev = (_pc.get(n["id"]) or {}).get("marks") or {}
        _pc[n["id"]] = {"ping": ping, "list": lst, "marks": _marks(prev, ping, lst, ping_at, list_at)}
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


NODE_STATE = ("_pc", "_tf", "_uh", "_addr_gen")


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
    _moved_gc(valid)


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
                for store in (_px, _px_relay, _px_reach):
                    for pid in [k for k in store if k not in live_px]:
                        store.pop(pid, None)
            for p in pxs:
                with inflight_lock:
                    if ("px:" + p["id"]) in inflight:
                        continue
                    inflight.add("px:" + p["id"])
                ex.submit(_run_px, p)
        except RegistryError as e:
            log_warn("poll", str(e))
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
                    raise OSError(_PX_CLOSED)
                head += c
            if head[0:1] != b"\x05":
                raise OSError(tx("پاسخِ پروکسی SOCKS5 نیست", "the proxy's answer is not SOCKS5"))
            method = head[1]
            if method == 0xFF:
                raise OSError(_PX_BAD_METHOD)
            if method == 2:
                if not user:
                    raise OSError(_PX_WANTS_AUTH)
                u, w = user.encode(), pw.encode()
                s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
                ares = b""
                while len(ares) < 2:
                    c = s.recv(2 - len(ares))
                    if not c:
                        raise OSError(tx("پروکسی هنگامِ احراز اتصال را بست", "the proxy closed the connection during authentication"))
                    ares += c
                if ares[1] != 0:
                    raise OSError(_PX_BAD_AUTH)
        else:
            s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (host, port, host, port)).encode()
                      + ((b"Proxy-Authorization: Basic "
                          + base64.b64encode(("%s:%s" % (user, pw)).encode()) + b"\r\n") if user else b"")
                      + b"\r\n")
            line = b""
            while b"\r\n" not in line:
                c = s.recv(256)
                if not c:
                    raise OSError(tx("پروکسی بدونِ پاسخ اتصال را بست", "the proxy closed the connection without an answer"))
                line += c
                if len(line) > 8192:
                    break
            if not line.startswith(b"HTTP/"):
                raise OSError(tx("پاسخِ پروکسی HTTP نیست", "the proxy's answer is not HTTP"))
            code = line.split(b" ")[1].decode(errors="replace") if b" " in line else "?"
            if code == "407":
                raise OSError(tx("یوزر/پسوردِ پروکسی پذیرفته نشد (407)", "the proxy rejected the username and password (407)"))
    except Exception as e:
        return {"ok": False, "ms": None, "code": "proxy_unreachable", "error": tx_cut(_net_why(e), 90), "ts": time.time()}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return {"ok": True, "ms": int((time.monotonic() - t0) * 1000), "error": "", "ts": time.time()}


PX_RELAY_GAP = 15
PX_REACH_GAP = 60
PX_REACH_HOST = "www.google.com"
PX_REACH_PATH = "/generate_204"
PX_ECHO_TTL = 120
_px_relay = {}
_px_reach = {}
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
            raise OSError(tx("چیزی برنگشت", "nothing came back"))
        line += c
        if len(line) > 4096:
            break
    if not line.startswith(b"HTTP/"):
        raise OSError(tx("پاسخِ عبوری HTTP نیست", "the relayed answer is not HTTP"))


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
        return {"ok": False, "skipped": False, "ts": time.time(), "code": "proxy_no_relay",
                "error": tx("پروکسی عبور نمی‌دهد — {0}", "the proxy does not relay — {0}", tx_cut(_net_why(e), 60))}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return {"ok": True, "skipped": False, "error": "", "ts": time.time()}


def _proxy_reach(p, timeout=8):
    t0 = time.monotonic()
    sock = None
    conn = None
    try:
        sock = _proxy_socket(proxy_url(p), PX_REACH_HOST, 443, timeout)
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=PX_REACH_HOST)
        sock = None
        conn = http.client.HTTPConnection(PX_REACH_HOST, 443, timeout=timeout)
        conn.sock = tls
        conn.request("GET", PX_REACH_PATH, headers={"user-agent": "tnl-central"})
        code = conn.getresponse().status
        if code not in (200, 204):
            raise OSError("HTTP %d" % code)
    except Exception as e:
        return {"ok": False, "ms": None, "ts": time.time(), "code": "proxy_no_reach",
                "error": tx("از پروکسی به گوگل نرسید — {0}", "could not reach Google through the proxy — {0}",
                            tx_cut(_net_why(e), 60))}
    finally:
        for c in (conn, sock):
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass
    return {"ok": True, "ms": int((time.monotonic() - t0) * 1000), "error": "", "ts": time.time()}


def _px_key(p):
    return (p["scheme"], p["host"], int(p["port"]), p.get("user") or "", p.get("pass") or "")


def _px_cached(store, p, gap, probe, fresh=False):
    key = _px_key(p)
    with _px_lock:
        prev = store.get(p["id"])
    if fresh or not prev or prev[0] != key or time.time() - prev[1]["ts"] >= gap:
        res = probe(p)
        with _px_lock:
            store[p["id"]] = (key, res)
        return res
    return prev[1]


def _px_deep(p, st, fresh=False):
    if not st.get("ok"):
        return st
    relay = _px_cached(_px_relay, p, PX_RELAY_GAP, _proxy_relay, fresh)
    if not (relay.get("skipped") or relay.get("ok")):
        return {**st, "ok": False, "code": relay["code"], "error": relay["error"]}
    reach = _px_cached(_px_reach, p, PX_REACH_GAP, _proxy_reach, fresh)
    if not reach.get("ok"):
        return {**st, "ok": False, "code": reach["code"], "error": reach["error"]}
    return {**st, "reach": reach["ms"]}


def _px_sweep(p):
    _px_publish(p, _px_deep(p, _proxy_probe(p)))


def _px_publish(p, st):
    with _px_lock:
        _px[p["id"]] = (_px_key(p), st)


def _px_get(p):
    with _px_lock:
        got = _px.get(p["id"])
    return dict(got[1]) if got and got[0] == _px_key(p) else {}


def _cached_ping(nid):
    return (_cache_get(nid) or {}).get("ping") or {}


def _node_answered(nid):
    return bool(_cached_ping(nid).get("ok")) or _cached_list(nid).get("configs") is not None


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
            s = e["if"].pop(key, None)
            if s and len(e["seed"]) < TF_IF_MAX:
                e["seed"][key] = [int(s["crx"]), int(s["ctx"])]
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
        if not e:
            return {}
        out = {k: {"prx": 0, "ptx": 0, "rx_bps": 0.0, "tx_bps": 0.0,
                   "crx": int(v[0]), "ctx": int(v[1]), "miss": 0}
               for k, v in e["seed"].items() if isinstance(v, list) and len(v) == 2}
        out.update({k: dict(v) for k, v in e["if"].items()})
        return out


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
            _uh[nid] = {"ring": [], "bts": now, "up": 1 if up else 0, "tot": 1, "n": 0}
            return
        e["up"] = e.get("up", 0) + (1 if up else 0)
        e["tot"] = e.get("tot", 0) + 1
        if now - e["bts"] >= UPTIME_BUCKET:
            frac = e["up"] / e["tot"] if e["tot"] else 1.0
            missed = min(int((now - e["bts"]) / UPTIME_BUCKET), UPTIME_KEEP)
            e["ring"].extend([frac] * missed)
            e["n"] = e.get("n", 0) + missed
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


K_TRAFFIC = "tnl:traffic"
K_UPTIME = "tnl:uptime:"
K_CHECKIN = "tnl:checkin"
_tf_flushed = {}
_uh_flushed = {}


def _stats_read(r):
    tf, ck, up = {}, {}, {}
    for k, v in r.hgetall(K_TRAFFIC).items():
        try:
            d = json.loads(v)
            tf[k] = {i: [int(x[0]), int(x[1])] for i, x in d.items() if isinstance(x, list) and len(x) == 2}
        except (ValueError, TypeError, AttributeError, IndexError):
            log_warn("stats", "bad traffic field %s in redis skipped" % k)
    for k, v in r.hgetall(K_CHECKIN).items():
        try:
            ck[k] = int(v)
        except (TypeError, ValueError):
            log_warn("stats", "bad checkin field %s in redis skipped" % k)
    ukeys = list(r.scan_iter(K_UPTIME + "*", count=1000))
    p = r.pipeline(transaction=False)
    for k in ukeys:
        p.lrange(k, 0, -1)
    for k, ring in zip(ukeys, p.execute()):
        try:
            up[k[len(K_UPTIME):]] = [max(0.0, min(1.0, float(x))) for x in ring][-UPTIME_KEEP:]
        except ValueError:
            log_warn("stats", "bad uptime list %s in redis skipped" % k)
    return tf, ck, up


def _stats_boot():
    r = _redis()
    valid = {n["id"] for n in load_nodes()}
    tf_raw, ck_raw, rings = _stats_read(r)
    stale = [k for k in set(tf_raw) | set(ck_raw) | set(rings) if k not in valid]
    if stale:
        with _reg_lock, store_tx() as t:
            for nid in stale:
                t.raw(lambda p, nid=nid: _stats_forget(p, nid))
    now = time.time()
    with _tf_lock:
        for nid in valid & set(tf_raw):
            e = _tf.setdefault(nid, {"prev_ts": 0.0, "prev_up": None, "if": {}, "seed": {}})
            e["seed"].update(tf_raw[nid])
            _tf_flushed[nid] = _enc(tf_raw[nid])
    with _uh_lock:
        for nid in valid & set(rings):
            ring = rings[nid]
            _uh[nid] = {"ring": ring, "bts": now, "up": 0, "tot": 0, "n": len(ring)}
            _uh_flushed[nid] = len(ring)
    with _checkin_ctr_lock:
        for nid in valid & set(ck_raw):
            _checkin_ctr[nid] = _checkin_ctr_saved[nid] = ck_raw[nid]


def _stats_forget(p, nid):
    p.hdel(K_TRAFFIC, nid)
    p.hdel(K_CHECKIN, nid)
    p.delete(K_UPTIME + nid)


def _stats_drop(nid):
    with _tf_lock:
        _tf.pop(nid, None)
        _tf_flushed.pop(nid, None)
    with _uh_lock:
        _uh.pop(nid, None)
        _uh_flushed.pop(nid, None)
    with _checkin_ctr_lock:
        _checkin_ctr.pop(nid, None)
        _checkin_ctr_saved.pop(nid, None)


def _persist_stats():
    with _reg_lock:
        valid = {n["id"] for n in load_nodes()}
        tf = {k: _enc(v) for k, v in _tf_snapshot().items() if k in valid}
        with _tf_lock:
            tf_new = {k: v for k, v in tf.items() if _tf_flushed.get(k) != v}
        with _uh_lock:
            uh_new = {}
            for nid, e in _uh.items():
                fresh = e.get("n", 0) - _uh_flushed.get(nid, 0)
                if fresh > 0 and nid in valid:
                    uh_new[nid] = (e["n"], e["ring"][-min(fresh, UPTIME_KEEP):])
        if not tf_new and not uh_new:
            return
        p = _redis().pipeline(transaction=True)
        if tf_new:
            p.hset(K_TRAFFIC, mapping=tf_new)
        for nid, (_n, vals) in uh_new.items():
            if vals:
                p.rpush(K_UPTIME + nid, *vals)
                p.ltrim(K_UPTIME + nid, -UPTIME_KEEP, -1)
        p.execute()
    with _tf_lock:
        _tf_flushed.update(tf_new)
    with _uh_lock:
        _uh_flushed.update({nid: n for nid, (n, _v) in uh_new.items()})


def traffic_persist_loop():
    while True:
        time.sleep(60)
        try:
            _persist_stats()
        except Exception as e:
            try:
                log_warn("persist", _store_msg(e))
            except Exception:
                log_internal("persist")
        try:
            _store_health()
        except Exception:
            log_internal("store health")


def query_dict(path):
    return {k: v[-1] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(path).query).items()}


def _list_query(d):
    return str(d.get("q") or "").strip().lower()


def _q_match(q, values):
    if len(q) > 1 and q[0] == q[-1] == '"':
        return any(q[1:-1] == v for v in values)
    return any(q in v for v in values)


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
        raise Bad("tunnel_id_range", "شناسهٔ {0} در بازهٔ «{1}/{2}» جا نمی‌شود "
                  "(این بازه {3} تونل می‌گیرد)؛ بازهٔ بزرگ‌تری انتخاب کن",
                  "tunnel id {0} does not fit in the range '{1}/{2}' (this range takes {3} tunnels); pick a larger range",
                  tid, net, prefix, cap)
    return "%s/24" % (ipaddress.IPv4Address(int(ipaddress.IPv4Address(net)) + tid * 256))


PORT_BAND_LO = 20000
PORT_BAND_HI = 29999


def rand_port(taken=()):
    free = [p for p in range(PORT_BAND_LO, PORT_BAND_HI + 1) if p not in taken]
    if not free:
        raise Bad("no_free_port", "پورتِ آزادی در بازهٔ {0} تا {1} نمانده است",
                  "no free port is left from {0} to {1}", PORT_BAND_LO, PORT_BAND_HI)
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
        net = ipaddress.ip_network(sub, strict=False)
    except Exception:
        return False
    if net.version != (6 if ttype == "sit" else 4):
        return False
    return net.prefixlen <= (126 if net.version == 6 else 30)


def carry_subnet(ttype, tid, stored, base=None):
    return stored if stored and _subnet_fits(ttype, stored) else subnet_default(ttype, tid, base)


def norm_subnet(ttype, tid, provided, base=None):
    want6 = (ttype == "sit")
    if not provided:
        return subnet_default(ttype, tid, base)
    if _subnet_fits(ttype, provided):
        return provided
    raise Bad("bad_subnet", "سابنتِ «{0}» خوانده نمی‌شود — این تونل به یک شبکهٔ {1} نیاز دارد، مثلاً {2}",
              "subnet '{0}' cannot be read — this tunnel needs an {1} network, for example {2}",
              provided, "IPv6" if want6 else "IPv4", subnet_default(ttype, tid, base))


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
                    "ws_rotate_secs", "ws_port_roll", "gso",
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
        raise Bad("bad_number", "«{0}» باید عدد باشد", "'{0}' must be a number", what)
    if n < 0 or n > hi:
        raise Bad("rotate_range", "«{0}» باید بین 0 تا {1} ثانیه باشد", "'{0}' must be from 0 to {1} seconds", what, hi)
    if 0 < n < MIN_ROTATE_SECS:
        raise Bad("rotate_too_short",
                  "«{0}» یا 0 است (فقط روی خرابی) یا دستِ‌کم {1} ثانیه — زیرِ آن پروب فرصتِ قضاوت ندارد و هسته بالا نمی‌آید",
                  "'{0}' is either 0 (only on failure) or at least {1} seconds — below that the probe has no time "
                  "to judge and the core does not come up", what, MIN_ROTATE_SECS)
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


def _pool_with(ip, pool, live):
    got = [x for x in (str(p).strip() for p in (pool or [])) if x in live]
    return got if ip in got else [ip] + got


def _live_pool(pool, live):
    got = [x for x in (pool or []) if x]
    return [x for x in got if x in live] if live else got


def _core_rotation_bodies(src, a_body, b_body, a_ips=None, b_ips=None):
    if not src.get("ip_rotate") or src.get("transport") not in DIRECT_TRANSPORTS:
        return
    ap = _live_pool(src.get("a_ip_pool"), a_ips)
    bp = _live_pool(src.get("b_ip_pool"), b_ips)
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


def _ech_why(fetched):
    if fetched is None:
        return tx("نه dig نه هیچ DoH‌ی جواب نداد — یعنی DNS یا پروکسیِ خودِ پنل قطع است، نه اینکه رکورد پاک شده باشد",
                  "neither dig nor any DoH answered — the panel's own DNS or proxy is down, the record was not removed")
    return tx("رکوردِ HTTPS جواب داد ولی ech= نداشت", "the HTTPS record answered but had no ech=")


def _ech_or_stored(host, fetched, stored):
    if fetched:
        return fetched
    if stored:
        log_event("warn", "ech-stale",
                  tx("کلیدِ ECH برای «{0}» تازه خوانده نشد", "the ECH key for '{0}' was not read fresh", host),
                  tx("{0}؛ کلیدِ ذخیره‌شده به کار رفت. اگر کلاودفلر"
                     " کلید را چرخانده باشد این تونل تا خواندنِ بعدی بالا نمی‌آید.",
                     "{0}; the stored key was used. If Cloudflare rotated the key, this tunnel stays down until the next read.",
                     _ech_why(fetched)))
        return stored
    log_event("warn", "ech-stale",
              tx("کلیدِ ECH برای «{0}» نه تازه خوانده شد نه ذخیره‌ای دارد",
                 "the ECH key for '{0}' was neither read fresh nor stored", host),
              tx("این تونل بدونِ ECH بالا می‌آید، یعنی SNI در روشناییِ روز می‌رود. تا وقتی رکوردِ"
                 " HTTPS/ech= دوباره خوانده شود همین‌طور می‌ماند.",
                 "this tunnel comes up without ECH, so the SNI travels in the clear. It stays so until the "
                 "HTTPS/ech= record is read again."))
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
        if src.get("ws_port_roll"):
            e["ws_port_roll"] = True
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
            raise Bad("missing_field", "فیلدِ «{0}» فرستاده نشد", "field '{0}' is missing", k)


def valid_proxy_ref(d):
    on = bool(d.get("proxy_on"))
    pid = str(d.get("proxy_id") or "").strip()
    if not on:
        return False, ""
    if not pid or not get_proxy(pid):
        raise Bad("proxy_missing", "پروکسی انتخاب نشده — از بخشِ «پروکسی‌ها» یکی بساز و انتخابش کن",
                  "no proxy picked — create one under proxies and pick it")
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
        return {**base, "online": False, "pending": True, "info": {"error": tx("در حال بررسی…", "checking…")}}
    p = c["ping"]
    return {**base, "online": bool(p.get("ok")),
            "info": p if p.get("ok") else {"error": p.get("error", "unreachable")}}


def api_nodes(d):
    q = _list_query(d or {})
    nodes = load_nodes()
    if q:
        nodes = [n for n in nodes if _q_match(q, (n["name"].lower(), n["host"].lower()))]
    _ensure_cached(nodes)
    _pend = _pending_counts()
    _pxn = _proxy_names()
    return {"nodes": [_node_view(n, _pend, _pxn) for n in nodes], "total": len(nodes),
            "uptime_window": get_settings().get("uptime_window", 1)}


def api_node_names(d):
    q = _list_query(d)
    out = []
    for n in load_nodes():
        if q and not _q_match(q, (n["name"].lower(), n["host"].lower())):
            continue
        p = _cached_ping(n["id"])
        out.append({"id": n["id"], "name": n["name"], "host": n["host"], "hidden": bool(n.get("disabled")),
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
    _ev_total, _ev_newest, _ev_unread = _ev_badge((d or {}).get("seen"))
    nodes = load_nodes()
    links = load_links()
    try:
        with open(AGENT_META) as f:
            staged_sha = json.load(f).get("sha256")
    except Exception:
        staged_sha = None

    on = mu = mt = du = dt = 0
    heat, crit, alerts, outdated = [], [], [], 0
    alerts.extend({"level": "bad", "kind": "store", "tab": "settings", "msg": m} for m in _store_issues)
    worst = {"disk": None, "ram": None, "cpu": None}
    for n in nodes:
        nid, nm = n["id"], n.get("name", "")
        p = _cached_ping(nid)
        if not p.get("ok"):
            heat.append({"name": nm, "pct": None, "online": False})
            if _cache_get(nid):
                alerts.append({"level": "bad", "kind": "node", "msg": tx("نودِ «{0}» آفلاین است", "node '{0}' is offline", nm)})
            mv = moved_addr(nid)
            if mv:
                alerts.append({"level": "warn", "kind": "node", "msg": tx(
                    "نودِ «{0}» از {1} جواب می‌دهد — نشانی‌اش را عوض کن",
                    "node '{0}' answers from {1} — change its address", nm, mv)})
            continue
        on += 1
        if staged_sha and p.get("sha256") and p.get("sha256") != staged_sha:
            outdated += 1
        s = p.get("stats") if isinstance(p.get("stats"), dict) else {}
        mu += _sint(s.get("mem_used_mb")); mt += _sint(s.get("mem_total_mb"))
        du += _sint(s.get("disk_used_mb")); dt += _sint(s.get("disk_total_mb"))
        cpu = round(_sflt(s.get("cpu_pct")))
        disk = round(_sflt(s.get("disk_pct")))
        ram = round(_sint(s.get("mem_used_mb")) / _sint(s.get("mem_total_mb")) * 100) if _sint(s.get("mem_total_mb")) else 0
        for key, val, lab in (("disk", disk, tx("دیسکِ", "disk")), ("ram", ram, tx("رمِ", "RAM")), ("cpu", cpu, tx("CPU", "CPU"))):
            if worst[key] is None or val > worst[key]["pct"]:
                worst[key] = {"name": nm, "pct": val}
            if val >= UP_CRIT:
                alerts.append({"level": "bad", "kind": key, "msg": tx("{0} «{1}» به {2}٪ رسیده", "{0} of '{1}' is at {2}%",
                                                                      lab, nm, val)})
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
        types[L.get("type", "")] = types.get(L.get("type", ""), 0) + 1
        if not L.get("enabled", True):
            off_n += 1
            continue
        ah, _a = _link_side_health(L, "a_node")
        bh, _b = _link_side_health(L, "b_node")
        state = _link_mark(L)[0]
        if state is None:
            continue
        tab = "core" if L.get("type") == "core" else "tunnels"
        if link_drift(L["id"]):
            drift_n += 1
            alerts.append({"level": "warn", "kind": "drift", "tab": tab, "id": L["id"], "msg": tx(
                "تونلِ «{0}» نیازمندِ بازسازی است", "tunnel '{0}' needs a rebuild", L.get("name"))})
            continue
        if not state:
            down += 1
            alerts.append({"level": "bad", "kind": "link", "tab": tab, "id": L["id"], "msg": tx(
                "تونلِ «{0}» قطع است", "tunnel '{0}' is down", L.get("name"))})
            continue
        sides = [h for h in (ah, bh) if isinstance(h, dict)]
        if any(h.get("alive") is True for h in sides):
            up += 1
        else:
            noping += 1
        lrtt = max([_sflt(h.get("rtt_ms")) for h in sides if h.get("rtt_ms") is not None] or [0])
        lloss = max([_sflt(h.get("loss_pct")) for h in sides] or [0])
        if lrtt > 0:
            rtts.append(lrtt)
        if lrtt > PING_BAD:
            cand = {"name": L.get("name"),
                    "a": nmap.get(L.get("a_node"), L.get("a_name", "")),
                    "b": nmap.get(L.get("b_node"), L.get("b_name", "")),
                    "rtt": lrtt, "loss": lloss}
            if worst_tun is None or (cand["loss"], cand["rtt"]) > (worst_tun["loss"], worst_tun["rtt"]):
                worst_tun = cand
    for who, nm in _stray_snapshot():
        alerts.append({"level": "warn", "kind": "stray", "tab": "nodes",
                       "msg": tx("تونلِ «{0}» روی نودِ «{1}» هست ولی در پنل ثبت نیست",
                                 "tunnel '{0}' is on node '{1}' but not registered in the panel", nm, who)})
    if outdated:
        alerts.append({"level": "warn", "kind": "agent", "msg": tx(
            "ایجنتِ {0} نود با ایجنتِ پنل یکی نیست", "the agent on {0} nodes differs from the panel's agent", outdated)})

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
    alerts.sort(key=lambda a: a["level"] != "bad")
    return {"nodes_online": on, "nodes_total": len(nodes),
            "proxies": len(load_proxies()),
            "links": len(links) - n_core, "core": n_core, "link_total": len(links),
            "portfw": sum(len(_pf_node_configs(n["id"])[0]) for n in nodes),
            "health_score": score,
            "central": central_stats(),
            "heat": heat, "worst": worst,
            "crit": len(crit),
            "alerts": alerts[:10], "alert_count": len(alerts),
            "link_up": up, "link_noping": noping, "link_down": down, "link_drift": drift_n,
            "link_off": off_n,
            "link_types": types, "worst_tunnel": worst_tun,
            "subnet_free": subnet_free_counts(links),
            "fleet_avg_ping": round(sum(rtts) / len(rtts)) if rtts else None,
            "uptime_avg": (int(sum(ups) / len(ups) * 10) / 10 if ups else 100), "uptime_down_nodes": downcnt, "uptime_window": win,
            "mem_used_mb": mu, "mem_total_mb": mt, "disk_used_mb": du, "disk_total_mb": dt,
            "fleet_rx_bps": frx_bps, "fleet_tx_bps": ftx_bps,
            "fleet_rx_total": frx, "fleet_tx_total": ftx,
            "ev_seq": _ev_newest, "log_count": _ev_total, "log_unread": _ev_unread, "boot": _BOOT_ID,
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


def _node_token(value):
    token = str(value or "").strip()
    if token and len(token) < 16:
        raise Bad("token_short", "توکن کوتاه است — حداقل ۱۶ کاراکتر بگذار", "the token is too short — use at least 16 characters")
    return token


def _node_name(v):
    name = str(v).strip()
    if not re.match(r"^[A-Za-z0-9 _.-]{1,40}$", name):
        raise Bad("bad_node_name", "نامِ نود نامعتبر است", "invalid node name")
    return name


def _node_host(v):
    host = str(v).strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise Bad("bad_node_host", "آی‌پی یا هاستِ نود نامعتبر است", "invalid node IP or host")
    return host


def _node_port(v):
    return _int_in(v, 1, 65535, Bad("bad_port", "پورت نامعتبر است", "invalid port"))


def _node_unique(nodes, name, host):
    if _name_taken(nodes, name):
        raise Bad("node_name_taken", "نودی با نامِ «{0}» از قبل وجود دارد — یک نامِ یکتا انتخاب کن",
                  "a node named '{0}' already exists — pick a unique name", name)
    if _host_taken(nodes, host):
        raise Bad("node_host_taken", "نودی با آی‌پیِ «{0}» از قبل وجود دارد", "a node with IP '{0}' already exists", host)


def api_node_add(d):
    _require(d, ["name", "host", "port", "token"])
    name, host, port = _node_name(d["name"]), _node_host(d["host"]), _node_port(d["port"])
    token = _node_token(d["token"])
    if not token:
        raise Bad("token_missing", "توکن لازم است", "a token is required")
    with _reg_lock:
        pon, pid = valid_proxy_ref(d)
        node = {"id": secrets.token_hex(5), "name": name, "host": host, "port": port, "token": token,
                "proxy_on": pon, "proxy_id": pid}
        _node_unique(load_nodes(), name, host)
        with store_tx() as t:
            t.put(_NODES, node)
    threading.Thread(target=_node_first_contact, args=(node,), daemon=True).start()
    return {"ok": True, "id": node["id"], "checking": True}


_NODE_REL = "https://github.com/Angize/TUNNEL-MANAGER-NODE/releases"
_NODE_REL_LATEST = "https://api.github.com/repos/Angize/TUNNEL-MANAGER-NODE/releases/latest"
_AGENT_VER_RE = re.compile(r'^AGENT_VERSION = "(dev|v\d+\.\d+\.\d+)"\r?$', re.M)


def _agent_release_url(version):
    return f"{_NODE_REL}/download/{version}/tnl-node.py"


_INSTALL_STEPS = [("ssh", tx("اتصالِ SSH", "SSH connection")), ("agent", tx("رساندنِ ایجنت به نود", "delivering the agent to the node")),
                  ("install", tx("نصب و راه‌اندازیِ سرویس", "installing and starting the service")),
                  ("register", tx("ثبت و اتصال در پنل", "registering and connecting in the panel"))]
_INSTALL_LABELS = dict(_INSTALL_STEPS)
_install_jobs = {}
_install_lock = threading.Lock()


def _scrub(s):
    return re.sub(r"TNL_NODE_TOKEN=\S+", "TNL_NODE_TOKEN=***", s or "")[-1400:]


def _install_get(jid):
    with _install_lock:
        j = _install_jobs.get(jid)
        return _copy(j) if j else None


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
                    s["log"] = Tx(_scrub(log), _scrub(_en(log))) if isinstance(log, Tx) else _scrub(log)
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
            raise OSError("the proxy closed the connection")
        b += c
    return b

def _socks5(s, pu, pw, dh, dp):
    s.sendall(b"\x05\x02\x00\x02" if pu else b"\x05\x01\x00")
    method = _recvn(s, 2)[1]
    if method == 2:
        if not pu:
            raise OSError("the proxy wants a username and password")
        u, w = pu.encode(), (pw or "").encode()
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(w)]) + w)
        if _recvn(s, 2)[1] != 0:
            raise OSError("the proxy rejected the username and password")
    elif method != 0:
        raise OSError("the proxy rejected our authentication method")
    try:
        addr = b"\x01" + socket.inet_aton(dh)
    except OSError:
        hb = dh.encode()
        addr = b"\x03" + bytes([len(hb)]) + hb
    s.sendall(b"\x05\x01\x00" + addr + int(dp).to_bytes(2, "big"))
    rep = _recvn(s, 4)
    if rep[1] != 0:
        raise OSError("the SOCKS5 proxy did not open the connection to the target (code %d)" % rep[1])
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
            raise OSError("the proxy closed the connection")
        buf += c
        if len(buf) > 65536:
            raise OSError("the proxy's answer is too large")
    line = buf.split(b"\r\n", 1)[0].decode("latin1")
    if " 200" not in line:
        raise OSError("the proxy refused CONNECT: " + line[:80])
    return buf.split(b"\r\n\r\n", 1)[1]

def main():
    dh, dp = sys.argv[1], int(sys.argv[2])
    scheme = (os.environ.get("TNL_PXY_SCHEME") or "socks5").lower()
    ph = os.environ.get("TNL_PXY_HOST") or ""
    pp = int(os.environ.get("TNL_PXY_PORT") or 0)
    pu = os.environ.get("TNL_PXY_USER") or None
    pw = os.environ.get("TNL_PXY_PASS") or None
    if not ph or not pp:
        raise OSError("no proxy host or port was given")
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
        save_bytes(p, _PROXY_RELAY_SRC.encode(), 0o600)
        _proxy_relay_path = p
        return p


def _ssh_argv(cfg, remote_cmd):
    opts = ["-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={SSH_KNOWN_HOSTS}",
            "-o", "ConnectTimeout=15", "-p", str(cfg["port"])]
    env = dict(os.environ)
    proxy = (cfg.get("proxy") or "").strip()
    if proxy:
        scheme, phost, pport, puser, ppass = proxy_parts(proxy)
        env["TNL_PXY_SCHEME"] = scheme
        env["TNL_PXY_HOST"] = phost or ""
        env["TNL_PXY_PORT"] = str(pport or "")
        env["TNL_PXY_USER"] = puser
        env["TNL_PXY_PASS"] = ppass
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
        _install_finish(jid, False, tx("نصب در مرحلهٔ «{0}» متوقف شد", "the install stopped at step '{0}'", _INSTALL_LABELS[key]))

    try:
        _install_step(jid, "ssh", "run")
        rc, out, err = _ssh_run(cfg, "echo TNL_SSH_OK", 30)
        if rc == 127:
            return fail("ssh", tx("ابزارِ SSH روی سرورِ مرکزی نیست", "the SSH tools are not on the central server"),
                        tx("برای احرازِ رمز، sshpass لازم است:  sudo apt install -y sshpass\n(یا از کلیدِ خصوصی استفاده کن)",
                           "password login needs sshpass:  sudo apt install -y sshpass\n(or use a private key)"))
        if rc != 0 or "TNL_SSH_OK" not in out:
            return fail("ssh", tx("اتصالِ SSH ناموفق", "SSH connection failed"), (err or out).strip())
        _install_step(jid, "ssh", "ok", tx("{0}@{1}:{2} — وصل شد", "{0}@{1}:{2} — connected", cfg["user"], cfg["host"], cfg["port"]))

        _install_step(jid, "agent", "run")
        try:
            raw, ameta = _deliverable_agent(_delivery_mode("agent"))
        except OSError:
            return fail("agent", tx("ایجنتی روی پنل آماده نیست", "no agent is ready on the panel"),
                        tx("در «تنظیمات» ایجنت را از گیت‌هاب بگیر یا فایلش را بارگذاری کن، بعد دوباره امتحان کن.",
                           "in settings, fetch the agent from GitHub or upload its file, then try again."))
        except ValueError as e:
            return fail("agent", tx("ایجنتِ پنل برای این حالتِ تحویل آماده نیست", "the panel's agent is not ready for this delivery mode"),
                        _why(e))
        verify = f"echo '{ameta['sha256']}  /tmp/tnl-node.py' | sha256sum -c - >/dev/null; echo TNL_RECV_OK"
        if _delivery_mode("agent") == "github":
            url = _agent_release_url(ameta["version"])
            recv = (f"set -e; umask 077; (curl -fsSL {url} -o /tmp/tnl-node.py"
                    f" || wget -qO /tmp/tnl-node.py {url}); echo TNL_DL_OK; {verify}")
            stdin, how = None, tx("از گیت‌هاب", "from GitHub")
        else:
            recv, stdin, how = (f"set -e; umask 077; base64 -d > /tmp/tnl-node.py; echo TNL_DL_OK; {verify}",
                                base64.b64encode(raw).decode(), tx("از پنل", "from the panel"))
        rc, out, err = _ssh_run(cfg, recv, 120, stdin_text=stdin)
        if "TNL_DL_OK" not in out:
            return fail("agent", tx("دریافتِ ایجنت روی نود ناموفق (curl/wget؟ دسترسیِ اینترنت؟)",
                                    "the node could not download the agent (curl/wget? internet access?)"), (err or out).strip())
        if rc != 0 or "TNL_RECV_OK" not in out:
            return fail("agent", tx("فایلِ رسیده با ایجنتِ آمادهٔ پنل یکی نیست",
                                    "the file that arrived differs from the panel's ready agent"), (err or out).strip())
        _install_step(jid, "agent", "ok", tx("tnl-node.py {0} {1} رسید", "tnl-node.py {0} arrived {1}", ameta["version"], how))

        _install_step(jid, "install", "run", tx("نصبِ وابستگی‌ها ممکن است چند دقیقه طول بکشد…",
                                                 "installing the dependencies may take a few minutes…"))
        sudo = "" if cfg["user"] == "root" else "sudo -n "
        rc, out, err = _ssh_run(cfg, f"{sudo}python3 /tmp/tnl-node.py --auto-install {agent_port}", 900)
        combined = ((out or "") + "\n" + (err or "")).strip()
        if rc != 0 or "TNL_INSTALL_OK" not in out:
            return fail("install", tx("نصب/راه‌اندازیِ سرویس ناموفق", "installing or starting the service failed"), combined)
        m = re.search(r"TNL_NODE_TOKEN=(\S+)", out)
        if not m:
            return fail("install", tx("توکن از خروجیِ نصب خوانده نشد", "the token could not be read from the install output"), combined)
        token = m.group(1)
        _install_step(jid, "install", "ok", tx("ایجنت نصب و اجرا شد", "the agent is installed and running"))

        _install_step(jid, "register", "run")
        node = {"id": secrets.token_hex(5), "name": name, "host": cfg["host"],
                "port": agent_port, "token": token, "proxy_on": pon, "proxy_id": pid}
        with _reg_lock:
            nodes = load_nodes()
            if _name_taken(nodes, name):
                return fail("register", tx("نودی با نامِ «{0}» در این فاصله اضافه شد — نام باید یکتا باشد",
                                           "a node named '{0}' was added meanwhile — the name must be unique", name))
            if _host_taken(nodes, cfg["host"]):
                return fail("register", tx("نودی با آی‌پیِ «{0}» در این فاصله اضافه شد",
                                           "a node with IP '{0}' was added meanwhile", cfg["host"]))
            with store_tx() as t:
                t.put(_NODES, node)
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
                      tx("نود وصل شد و آنلاین است", "the node is connected and online") if online else
                      tx("ثبت شد ولی هنوز پاسخ نمی‌دهد (پورتِ ایجنت را به سرورِ مرکزی باز کن)",
                         "registered but not answering yet (open the agent port to the central server)"))
        _install_finish(jid, True, tx("«{0}» نصب و وصل شد", "'{0}' is installed and connected", name) if online else
                        tx("«{0}» ثبت شد؛ در انتظارِ آنلاین‌شدن", "'{0}' is registered; waiting for it to come online", name))
    except Exception as e:
        fail(_install_running(jid), tx("خطای غیرمنتظره", "unexpected error"), _why(e))
    finally:
        _release_proxies("install:" + jid)
        kf = cfg.get("keyfile")
        if kf:
            try:
                os.remove(kf)
            except Exception:
                pass


def api_node_install(d):
    _gate_ready(True)
    _require(d, ["name", "ssh_host"])
    name, host = _node_name(d["name"]), _node_host(d["ssh_host"])
    _node_unique(load_nodes(), name, host)
    ssh_port = _int_in(d.get("ssh_port") or 22, 1, 65535, Bad("bad_ssh_port", "پورتِ SSH نامعتبر است", "invalid SSH port"))
    user = str(d.get("ssh_user") or "root").strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,32}$", user):
        raise Bad("bad_ssh_user", "کاربرِ SSH نامعتبر است", "invalid SSH user")
    agent_port = _int_in(d.get("agent_port") or 8099, 1, 65535,
                         Bad("bad_agent_port", "پورتِ ایجنت نامعتبر است", "invalid agent port"))
    pon, pid = valid_proxy_ref(d)
    password = str(d.get("ssh_pass") or "")
    key = str(d.get("ssh_key") or "").strip()
    if not password and not key:
        raise Bad("ssh_auth_missing", "رمزِ SSH یا کلیدِ خصوصی لازم است", "an SSH password or a private key is required")
    jid = secrets.token_hex(6)
    if pon:
        _hold_proxy(pid, "install:" + jid)
    try:
        cfg = {"host": host, "port": ssh_port, "user": user, "password": password,
               "proxy": node_proxy({"proxy_on": pon, "proxy_id": pid})}
        if key:
            fd, kp = tempfile.mkstemp(prefix="tnlkey_")
            with os.fdopen(fd, "wb") as f:
                f.write((key if key.endswith(chr(10)) else key + chr(10)).encode())
            os.chmod(kp, 0o600)
            cfg["keyfile"], cfg["password"] = kp, ""
        now = int(time.time())
        with _install_lock:
            for k in [k for k, v in _install_jobs.items() if now - v.get("ts", now) > 3600]:
                _install_jobs.pop(k, None)
            _install_jobs[jid] = {"steps": [{"key": k, "label": l, "state": "wait", "detail": "", "log": ""}
                                            for k, l in _INSTALL_STEPS],
                                  "done": False, "ok": False, "banner": "", "node_id": None, "ts": now}
        threading.Thread(target=_install_worker, args=(jid, cfg, name, agent_port, pon, pid), daemon=True).start()
    except Exception:
        _release_proxies("install:" + jid)
        raise
    return {"ok": True, "job": jid}


def api_node_install_status(d):
    _require(d, ["job"])
    j = _install_get(d["job"])
    if not j:
        raise _no_job()
    return {**j, "ok": True, "success": bool(j.get("ok"))}


def api_node_edit(d):
    _require(d, ["id", "name", "host", "port"])
    name, host, port = _node_name(d["name"]), _node_host(d["host"]), _node_port(d["port"])
    token = _node_token(d.get("token"))
    with _reg_lock:
        pon, pid = valid_proxy_ref(d)
        nodes = load_nodes()
        n = next((x for x in nodes if x["id"] == d["id"]), None)
        if not n:
            raise _no_node()
        if _name_taken(nodes, name, exclude_id=d["id"]):
            raise Bad("node_name_taken", "نودِ دیگری با نامِ «{0}» وجود دارد — نام باید یکتا باشد",
                      "another node is named '{0}' — the name must be unique", name)
        if _host_taken(nodes, host, exclude_id=d["id"]):
            raise Bad("node_host_taken", "نودِ دیگری با آی‌پیِ «{0}» وجود دارد", "another node has IP '{0}'", host)
        n2 = _thaw(n)
        n2["name"], n2["host"], n2["port"] = name, host, port
        n2["proxy_on"], n2["proxy_id"] = pon, pid
        if token:
            n2["token"] = token
        with store_tx() as t:
            t.put(_NODES, n2)
            for L in load_links():
                ends = [k for k in ("a", "b") if L.get(k + "_node") == d["id"] and L.get(k + "_name") != name]
                if ends:
                    L2 = _thaw(L)
                    for k in ends:
                        L2[k + "_name"] = name
                    t.put(_LINKS, L2)
        _addr_bump(d["id"])
    if moved_addr(d["id"]) in ("%s:%d" % (host, port), "%s:0" % host):
        _moved_clear(d["id"])
    _refresh_bg([d["id"]])
    return {"ok": True, "checking": True}


def api_node_toggle(d):
    _require(d, ["id"])
    want = bool(d.get("disabled"))

    def flip(x):
        if want:
            x["disabled"] = True
        else:
            x.pop("disabled", None)
    with _reg_lock:
        if store_edit(_NODES, d["id"], flip) is None:
            raise _no_node()
    return {"ok": True, "disabled": want}


def api_node_del(d):
    _require(d, ["id"])
    nid = d["id"]
    force = bool(d.get("wipe_force") or d.get("force"))
    n = get_node(nid)
    if not n:
        raise _no_node()
    if force and _known_offline(n):
        node_ok = False
    else:
        r = node_call(n, "wipe", "POST", {}, timeout=NODE_OP_TIMEOUT)
        node_ok = bool(r.get("ok"))
        if not node_ok:
            raise Bad("node_wipe_failed",
                      "پاک‌سازیِ سمتِ نود ناتمام ماند: {0} — اگر نود قطع است چند لحظه صبر کن تا وضعیتش قرمز شود بعد «پاک‌سازیِ اجباری» بزن.",
                      "the cleanup on the node did not finish: {0} — if the node is down, wait until it shows red, then use force",
                      r.get("error") or r.get("msg") or tx("خطا", "error"))
    with _reg_lock:
        links = load_links()
        mine = [L for L in links if L.get("a_node") == nid or L.get("b_node") == nid]
        mine_ids = {L["id"] for L in mine}
    _park_failed, _dropped = [], []

    def _del_peer_half(L):
        peer_id = L["b_node"] if L["a_node"] == nid else L["a_node"]
        pn = get_node(peer_id)
        if not pn:
            return
        with _PairLock(peer_id, peer_id):
            rr = node_call(pn, "delete", "POST", {"name": L["name"]}, timeout=8)
        if rr.get("ok"):
            _dropped.append(L["name"])
        elif not _pending_add(peer_id, L["name"]):
            _park_failed.append(tx("«{0}» روی نودِ «{1}»", "'{0}' on node '{1}'", L["name"], pn["name"]))
    parallel_map(_del_peer_half, mine, workers=32)
    if _park_failed:
        raise Bad("pending_write_failed",
                  "نودِ «{0}» {1} و نیمهٔ {2} تونل از نودِ روبه‌رو برداشته شد، "
                  "ولی صفِ حذفِ معلق برای {3} نوشته نشد — برای همین رکوردِ نود و تونل‌ها دست‌نخورده ماند "
                  "تا تونلِ یتیم نماند. جای دیسکِ پنل را باز کن و دوباره بزن.",
                  "node '{0}' {1} and half of {2} tunnels were removed from the peer node, but the pending-delete "
                  "queue for {3} was not written — so the node and tunnel records were left as they are, to leave "
                  "no orphan tunnel. Free disk space on the panel and try again.",
                  n["name"], tx("پاک شد", "was wiped") if node_ok else tx("پاک نشد (قطع بود)", "was not wiped (it was down)"),
                  len(_dropped), _park_failed)
    with _reg_lock, _pending_lock, _moved_lock, store_tx() as t:
        for lid in mine_ids:
            t.drop(_LINKS, lid)
        t.drop(_NODES, nid)
        t.pending(nid, ())
        t.moved(nid, None)
        t.raw(lambda p: _stats_forget(p, nid))
    with _tomb_lock:
        _tomb[nid] = time.time() + 20
    with _pc_lock:
        _pc.pop(nid, None)
    _stats_drop(nid)
    return {"ok": True, "node_wiped": node_ok}


def api_node_test(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise _no_node()
    t0 = time.perf_counter()
    p = node_call(n, "ping", "GET")
    if not p.get("ok"):
        return {**_node_soft(p, "unreachable"), "info": p}
    return {"ok": True, "info": {**p, "rtt_ms": int((time.perf_counter() - t0) * 1000)}}


def api_node_adopt_ip(d):
    _require(d, ["id"])
    n = get_node(str(d["id"]))
    if not n:
        raise _no_node()
    new, newp = moved_to(n["id"]), moved_port(n["id"]) or int(n.get("port") or 0)
    if not new:
        raise Bad("no_new_address", "آدرسِ تازه‌ای برای این نود ثبت نشده", "no new address is recorded for this node")
    probe = dict(n)
    probe["host"], probe["port"] = new, newp
    if not node_call(probe, "ping", "GET", timeout=8).get("ok"):
        pxp = get_proxy(str(n.get("proxy_id") or "")) if n.get("proxy_on") else None
        px = _px_get(pxp) if pxp else {}
        if px and not px.get("ok"):
            raise Bad("node_proxy_down", "پروکسیِ این نود قطع است، پس هیچ آدرسی از آن رد نمی‌شود — اول پروکسی را درست کن",
                      "this node's proxy is down, so no address gets through it — fix the proxy first")
        raise Bad("new_address_silent", "نشانیِ {0}:{1} همین حالا جواب نمی‌دهد — چیزی عوض نشد",
                  "address {0}:{1} does not answer right now — nothing changed", new, newp)
    with _reg_lock:
        nodes = load_nodes()
        t = next((x for x in nodes if x["id"] == n["id"]), None)
        if not t:
            raise _no_node()
        if _host_taken(nodes, new, exclude_id=n["id"]):
            raise Bad("node_host_taken", "نودِ دیگری از قبل روی «{0}» ثبت است — دو نود با یک نشانی "
                      "بعداً قابلِ ویرایش نیستند؛ اول آن یکی را درست کن",
                      "another node is already registered on '{0}' — two nodes with one address cannot be "
                      "edited later; fix that one first", new)
        store_edit(_NODES, n["id"], lambda x: x.update(host=new, port=newp))
        _addr_bump(n["id"])
    _moved_clear(n["id"])
    _refresh_cache([n["id"]])
    return {"ok": True, "host": new, "port": newp}


def api_node_kernel_tune(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise _no_node()
    action = str(d.get("action") or "status")
    if action not in ("apply", "revert", "status"):
        raise Bad("bad_action", "عملیاتِ نامعتبر", "invalid action")
    p = node_call(n, "kernel-tune", "POST", {"action": action}, timeout=15)
    if not p.get("ok"):
        return _node_soft(p, "unreachable")
    return {"ok": True, "active": bool(p.get("active")), "cc": str(p.get("cc") or ""),
            "qdisc": str(p.get("qdisc") or ""), "bbr_available": bool(p.get("bbr_available"))}


def api_node_stats(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise _no_node()
    p = node_call(n, "ping", "GET", timeout=8)
    if not p.get("ok"):
        return {"online": False, "error": p.get("error", "unreachable")}
    return {"online": True, "stats": p.get("stats") or {},
            "tunnels": p.get("tunnels"), "portfw": p.get("portfw"), "hostname": p.get("hostname")}


def api_node_traffic(d):
    _require(d, ["id"])
    n = get_node(d["id"])
    if not n:
        raise _no_node()
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


def _store_agent_src(src, msgs, extra_meta=None, want_ver=None):
    raw = src.encode()
    if len(raw) > 262144:
        raise Bad("agent_too_big", msgs["too_big"])
    try:
        compile(src, "tnl-node.py", "exec")
    except SyntaxError as e:
        raise Bad("agent_bad_python", tx("{0}{1}", "{0}{1}", msgs["bad_py"], str(e)))
    if '"agent": "tnl-node"' not in src:
        raise Bad("not_an_agent", msgs["not_agent"])
    m = _AGENT_VER_RE.search(src)
    if not m or (want_ver and m.group(1) != want_ver):
        raise Bad("agent_version_missing", msgs["no_ver"])
    ver, sha = m.group(1), hashlib.sha256(raw).hexdigest()
    meta = {"version": ver, "sha256": sha, "size": len(raw), "uploaded_ts": int(time.time())}
    if extra_meta:
        meta.update(extra_meta)
    with _agent_lock:
        save_bytes(AGENT_FILE, raw)
        save_json(AGENT_META, meta)
    return {"ok": True, "version": ver, "sha256": sha[:12]}


def api_agent_upload(d):
    _require(d, ["code"])
    src = d["code"]
    if not isinstance(src, str) or not src.strip():
        raise Bad("empty_code", "کد خالی است", "the code is empty")
    return _store_agent_src(src, {
        "too_big": tx("فایل بیش از حد بزرگ است", "the file is too large"),
        "bad_py": tx("کد پایتون نامعتبر: ", "invalid Python code: "),
        "not_agent": tx("این فایل ایجنتِ نود نیست", "this file is not the node agent"),
        "no_ver": tx("خطِ AGENT_VERSION (dev یا vX.Y.Z) در این فایل نیست", "the file has no AGENT_VERSION line (dev or vX.Y.Z)"),
    })


def api_agent_fetch_git(d):
    tag = ""
    try:
        tag = str(json.loads(_gh_get(_NODE_REL_LATEST, 30, {"Accept": "application/vnd.github+json"}))
                  .get("tag_name") or "")
        url = _agent_release_url(tag)
        want = _sha_file(url + ".sha256")
        raw = _gh_get(url, 30)
    except Exception as e:
        if isinstance(e, urllib.error.HTTPError) and e.code == 404:
            if tag:
                raise Bad("agent_release_missing", "ریلیزِ {0} فایلِ ایجنت را ندارد", "release {0} has no agent file", tag)
            raise Bad("agent_release_missing", "ایجنت هنوز هیچ ریلیزی روی گیت‌هاب ندارد", "the agent has no release on GitHub yet")
        raise Bad("github_failed", "دریافت از گیت‌هاب ناموفق: {0}", "download from GitHub failed: {0}", _gh_why(e))
    if hashlib.sha256(raw).hexdigest() != want:
        raise Bad("checksum_mismatch", "فایلِ ریلیزِ {0} با چک‌سامِ خودش نمی‌خواند",
                  "the release file of {0} does not match its checksum", tag)
    try:
        src = raw.decode()
    except UnicodeDecodeError:
        raise Bad("agent_not_utf8", "فایلِ ریلیزِ {0} متنِ UTF-8 نیست", "the release file of {0} is not UTF-8 text", tag)
    return _store_agent_src(src, {
        "too_big": tx("فایلِ دریافتی بیش از حد بزرگ است", "the downloaded file is too large"),
        "bad_py": tx("کدِ دریافتی نامعتبر: ", "the downloaded code is invalid: "),
        "not_agent": tx("فایلِ دریافتی ایجنتِ نود نیست", "the downloaded file is not the node agent"),
        "no_ver": tx("نسخهٔ داخلِ فایلِ ریلیز با تگِ {0} یکی نیست", "the version inside the release file differs from tag {0}", tag),
    }, {"source": "git"}, want_ver=tag)


def api_agent_info(d):
    try:
        with open(AGENT_META) as f:
            meta = json.load(f)
    except Exception:
        meta = {"none": True}
    return {**meta, "delivery": _delivery_mode("agent")}


def _staged_agent():
    with _agent_lock:
        with open(AGENT_FILE, "rb") as f:
            raw = f.read()
        meta = read_json(AGENT_META, dict)
    return raw, meta


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


def _panel_host_for(node, proxied):
    return central_host() if proxied else _route_src(str(node.get("host") or ""))


def _panel_origin_for(node):
    if not _CENTRAL_PORT:
        return ""
    ip = _panel_host_for(node, bool(node_proxy(node)))
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
        if not tok or not secret_eq(hashlib.sha256(tok.encode()).hexdigest(), fp):
            continue
        return n if hmac.compare_digest(hmac.new(tok.encode(), msg, hashlib.sha256).digest(), got) else None
    return None


_NO_ORIGIN = tx("پنل هنوز آدرسِ خودش را نمی‌داند، پس نمی‌تواند نشانیِ دانلود بدهد — "
                "حالتِ تحویل را روی «پنل آپلود کند» یا «از گیت‌هاب» بگذار",
                "the panel does not know its own address yet, so it cannot hand out a download link — "
                "set the delivery mode to push or GitHub")


def _agent_meta_or_empty():
    try:
        return _staged_agent()[1]
    except Exception:
        return {}


def _agent_delivery_check(meta, mode):
    if mode == "github" and meta.get("source") != "git":
        raise Bad("agent_not_on_github", "این ایجنت از فایل بارگذاری شده و روی گیت‌هاب نیست — یا «دریافت از گیت‌هاب» را بزن، "
                  "یا حالتِ تحویلِ ایجنت را عوض کن",
                  "this agent was uploaded from a file and is not on GitHub — fetch it from GitHub or change the agent delivery mode")


def _agent_update_body(node, raw, meta, sig):
    mode = _delivery_mode("agent")
    _agent_delivery_check(meta, mode)
    body = {"sha256": meta["sha256"], "sig": sig}
    if mode == "push":
        return {"code": raw.decode(), **body}
    if mode == "github":
        return {"url": _agent_release_url(meta["version"]), **body}
    url = _panel_dl_url(node, "ag")
    if not url:
        raise Bad("no_panel_origin", _NO_ORIGIN)
    return {"url": url, **body}


def _core_delivery_check(mode, custom):
    if mode == "github" and custom:
        raise Bad("core_not_on_github", "این باینری روی پنل بارگذاری شده و روی گیت‌هاب نیست — "
                  "حالتِ تحویلِ هسته را روی «پنل آپلود کند» یا «نود از پنل بگیرد» بگذار",
                  "this binary was uploaded to the panel and is not on GitHub — set the core delivery mode to push or panel")


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
        raise Bad("no_panel_origin", _NO_ORIGIN)
    return {"url": url, **body}


def _readiness():
    try:
        _staged_agent()
        agent = True
    except Exception:
        agent = False
    info = _staged_info()
    gh = _delivery_mode("core") == "github"
    if gh:
        missing = []
    else:
        ver = (info or {}).get("version") or ""
        missing = [a for a in CORE_ARCHES if not (ver and os.path.isfile(_stage_path(ver, a)))]
    custom = not gh and bool(_core_blob_info())
    core = (bool(info) and not missing) or custom
    return {"agent": agent, "core": core, "core_missing": [] if core else missing,
            "core_version": (info or {}).get("version", "") or ("custom" if custom else ""),
            "ok": agent and core}


def api_readiness(d):
    return _readiness()


def _gate_ready(need_agent):
    r = _readiness()
    miss = []
    if need_agent and not r["agent"]:
        miss.append(tx("ایجنتِ نود", "the node agent"))
    if not r["core"]:
        miss.append(tx("هستهٔ داده برای معماریِ {0}", "the data core for {0}", r["core_missing"]) if r["core_version"]
                    else tx("هستهٔ داده", "the data core"))
    if miss:
        raise Bad("not_ready", "این کار به چیزی نیاز دارد که هنوز روی پنل آماده نیست: {0} — در «تنظیمات» آن را بگیر و دوباره امتحان کن",
                  "this needs something that is not ready on the panel yet: {0} — get it in settings and try again",
                  tx_join(" و ", miss, " and "))


def _dl_artifact(kind, arch):
    if kind == "ag":
        return _staged_agent()[0]
    if kind == "co":
        b = _staged_bytes(arch)
        return b[0] if b else None
    if kind == "cb":
        b = _core_blob_bytes()
        return b[0] if b else None
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
PUSH_KEEP = 3600
PUSH_TRACK_MIN = 256 * 1024
_dl_watch = {}
_dl_watch_lock = threading.Lock()


PUSH_BUSY_STATES = ("wait", "run")


def _busy_nodes(kind):
    return {nid for v in _push_jobs.values() if not v["done"] and v["kind"] == kind
            for nid, s in v["nodes"].items() if s["state"] in PUSH_BUSY_STATES}


def _push_job_new(kind, nodes):
    jid = secrets.token_hex(6)
    now = int(time.time())
    with _push_lock:
        for k in [k for k, v in _push_jobs.items()
                  if v["done"] and now - v.get("ts", now) > PUSH_KEEP]:
            _push_jobs.pop(k, None)
            _push_batch.discard(k)
        busy = _busy_nodes(kind)
        nodes = [x for x in nodes if x["id"] not in busy]
        if not nodes:
            raise Bad("update_running", "همین به‌روزرسانی روی این نود در جریان است — تا تمام‌شدنش صبر کن",
                      "this update is already running on this node — wait until it finishes")
        global _push_final
        if not _push_live():
            _push_batch.clear()
            _push_final = None
        _push_batch.add(jid)
        _push_jobs[jid] = {"kind": kind, "order": [n["id"] for n in nodes], "done": False, "ts": now,
                           "cancel": False, "paused": False,
                           "nodes": {n["id"]: {"name": n["name"], "state": "wait", "pct": 0,
                                               "step": "", "si": 0, "sn": 0, "remote": False,
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
            row = dict(j["nodes"][nid])
            cur = nodes.get(nid)
            if cur is None:
                order.append(nid)
                nodes[nid] = row
            elif cur["state"] not in PUSH_BUSY_STATES and row["state"] in PUSH_BUSY_STATES:
                nodes[nid] = row
    return {"ok": True, "job": PUSH_ALL, "kind": kinds.pop() if len(kinds) == 1 else "mixed",
            "done": all(_push_jobs[jid]["done"] for jid in jids),
            "cancel": cancel, "paused": paused, "order": order, "nodes": nodes}


def _push_seal_locked():
    global _push_final
    _push_final = _push_merge_locked(sorted(_push_batch, key=lambda k: _push_jobs[k].get("ts", 0)))


def _push_merged():
    with _push_lock:
        live = _push_live()
        if not live:
            return dict(_push_final) if _push_final else None
        jids = [k for k in _push_batch if k in _push_jobs] or live
        return _push_merge_locked(sorted(jids, key=lambda k: _push_jobs[k].get("ts", 0)))


def _push_set(jid, nid, **kw):
    if "state" in kw and kw["state"] not in PUSH_STATES:
        raise Bad("bad_push_state", "وضعیتِ ناشناختهٔ آپلود: {0!r}", "unknown upload state: {0!r}", kw["state"])
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
                _push_set(jid, nid, state="run", step="paused", si=i + 1, sn=n, pct=at(i, 0), remote=False)
                while _push_paused(jid):
                    if _push_cancelled(jid):
                        _push_set(jid, nid, state="skip", step=code)
                        return
                    time.sleep(0.2)
            _push_set(jid, nid, state="run", step=code, si=i + 1, sn=n, pct=at(i, 0), remote=False)
            if not keyed:
                k = _ensure_update_key(fresh)
                if not k.get("ok"):
                    _push_set(jid, nid, state="err", step=code, err=k["code"], detail=k["error"], pct=0)
                    return
                keyed = True
            try:
                body = build(fresh, _BuildCtx(jid, nid, at, i))
            except _Cancelled:
                _push_set(jid, nid, state="skip", step=code, pct=0)
                return
            except ValueError as e:
                _push_set(jid, nid, state="err", err="unbuildable", detail=_why(e))
                return
            _push_set(jid, nid, step=code, pct=at(i, 0))
            if body is None:
                _push_set(jid, nid, state="skip", step=code)
                return

            def moved(sent, total, _nid=nid, _i=i):
                if sent >= total:
                    _push_set(jid, _nid, pct=at(_i, 0.95), remote=True)
                else:
                    _push_set(jid, _nid, pct=at(_i, (sent / total) * 0.95), remote=False)

            def prog(sent, total, _nid=nid):
                if total >= PUSH_TRACK_MIN:
                    moved(sent, total)
                elif sent >= total:
                    _push_set(jid, _nid, remote=True)

            with _dl_watch_lock:
                _dl_watch[nid] = moved
            try:
                r = node_push(fresh, endpoint, body, on_progress=prog, timeout=timeout,
                              should_abort=lambda: _push_cancelled(jid))
            finally:
                with _dl_watch_lock:
                    if _dl_watch.get(nid) is moved:
                        del _dl_watch[nid]
            if r.get("cancelled"):
                _push_set(jid, nid, state="skip", step=code,
                          detail=tx("درخواست کامل به نود رسیده بود — ممکن است همین مرحله را انجام داده باشد",
                                    "the whole request had reached the node — it may have done this step")
                                 if r.get("delivered") else "")
                return
            if not r.get("ok"):
                _push_set(jid, nid, state="err", step=code,
                          err=str(r.get("code") or ("offline" if r.get("offline") else "failed")),
                          detail=r.get("error") or r.get("msg") or "")
                return
            if gate and gate(r):
                _push_set(jid, nid, state="same", step=code, pct=100)
                return
            _push_set(jid, nid, pct=at(i + 1, 0), remote=False, restarted=r.get("restarted"),
                      failed=len(r.get("failed") or []))
        _push_set(jid, nid, state="ok", pct=100, remote=False)
    except Exception as e:
        _push_set(jid, nid, state="err", err="panel", detail=tx_cut(_why(e), 120))


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
            raise _no_job()
        return {"ok": True, "job": jid, "kind": j["kind"], "done": j["done"],
                "cancel": bool(j.get("cancel")), "paused": bool(j.get("paused")), "order": list(j["order"]),
                "nodes": {k: dict(v) for k, v in j["nodes"].items()}}


def api_push_cancel(d):
    jid = str((d or {}).get("job") or "") or PUSH_ALL
    with _push_lock:
        targets = _push_live() if jid == PUSH_ALL else [jid]
        js = [_push_jobs[k] for k in targets if k in _push_jobs]
        if not js:
            raise _no_job()
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
            raise _no_job()
        live = [j for j in js if not j["done"] and not j.get("cancel")]
        if not live:
            return {"ok": True, "done": True}
        for j in live:
            j["paused"] = want
    return {"ok": True, "job": jid, "paused": want}


def _update_targets(d):
    _require(d, ["ids"])
    if not isinstance(d.get("ids"), list):
        raise Bad("bad_ids", "فهرستِ شناسه‌ها نامعتبر است", "the id list is invalid")
    nodes = [n for n in (get_node(i) for i in dict.fromkeys(d["ids"])) if n]
    if not nodes:
        raise Bad("no_nodes", "نودی انتخاب نشده", "no node selected")
    return nodes


def _core_current(ping, sha):
    got = str(ping.get("core_sha") or "")
    return bool(got) and sha.startswith(got)


def _update_start(kind, nodes, plan):
    jid = _push_start(kind, nodes, plan)
    return {"ok": True, "job": jid} if jid else {"ok": True, "none": True}


def _deliverable_agent(mode):
    have = _agent_meta_or_empty()
    if mode == "github" and (not have or have.get("source") == "git"):
        try:
            api_agent_fetch_git({})
        except Exception:
            if not have:
                raise
    raw, meta = _staged_agent()
    _agent_delivery_check(meta, mode)
    return raw, meta


def api_update_agent(d):
    nodes = _update_targets(d)
    try:
        raw, meta = _deliverable_agent(_delivery_mode("agent"))
    except OSError:
        raise Bad("no_agent", "ابتدا یک ایجنت بارگذاری کنید", "load an agent first")
    sig = _sign_sha(meta["sha256"])
    enc = _body_cache(lambda n: _agent_update_body(n, raw, meta, sig))
    plan = [("check", "ping", lambda _n, _c=None: {}, 15,
             lambda r, _w=meta["sha256"]: str(r.get("sha256") or "") == _w),
            ("deliver", "update", enc, 60, None)]
    return _update_start("agent", nodes, plan)


def api_update_core(d):
    nodes = _update_targets(d)
    version = str((d or {}).get("version") or "").strip()
    if version == "custom":
        blob = _core_blob_bytes()
        if not blob:
            raise _no_custom_core()
        _core_delivery_check(_delivery_mode("core"), True)
        raw, sha = blob
        b64 = base64.b64encode(raw).decode()
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
        raise Bad("no_core", "هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه انتخاب کن",
                  "no core is ready on the panel — pick a version first")

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
                raise Bad("core_fetch_failed", staged["err"])
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
                staged["err"] = tx("نسخهٔ «{0}» از گیت‌هاب گرفته نشد: {1}", "version '{0}' could not be fetched from GitHub: {1}",
                                   version, _gh_why(e))
                raise Bad("core_fetch_failed", staged["err"])
            staged["done"] = True
        finally:
            staging.release()

    def check_body(_n, ctx=None):
        ensure(ctx)
        return {}

    def prep(n):
        arch = _node_arch(n)
        if not arch:
            raise Bad("node_arch_unknown", "معماریِ نود مشخص نشد — نود باید یک‌بار پاسخ بدهد تا باینریِ درست فرستاده شود", "the node's architecture is unknown — the node must answer once so the right binary is sent")
        if arch not in parts:
            if gh:
                ver = str((_staged_info() or {}).get("version") or "")
                if not ver:
                    raise Bad("no_version", "هیچ نسخه‌ای انتخاب نشده — اول یک نسخه انتخاب کن", "no version is picked — pick a version first")
                parts[arch] = ("", "", ver, "", arch)
            else:
                b = _staged_bytes(arch)
                if not b:
                    raise Bad("no_core", "هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن", "no core is ready on the panel — download a version first")
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
        out[0] = {**out[0], "label": tx("{0} (تازه‌ترین)", "{0} (latest)", out[0].get("label") or out[0]["id"]), "latest": True}
    info = _core_blob_info()
    if info:
        out.append({"id": "custom", "label": tx("باینریِ آپلودشده{0}", "uploaded binary{0}",
                                                " · " + info["name"] if info.get("name") else ""),
                    "custom": True, "sha256": info.get("sha256", "")[:12], "size": info.get("size")})
    rd = _readiness()
    return {"versions": out, "staged": _staged_info(), "delivery": _delivery_mode("core"),
            "ready": rd["core"], "missing": rd["core_missing"]}


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
        raise _no_custom_core()
    return {"ok": True}


def api_core_check(d):
    before = list(_core_versions_cache["data"] or [])
    prev_top = (before[0].get("id") if before else "")
    try:
        vers = _fetch_core_versions()
    except Exception as e:
        return {"ok": False, "code": "github_failed",
                "error": tx("دریافت از گیت‌هاب ناموفق: {0}", "download from GitHub failed: {0}", _gh_why(e))}
    with _core_versions_lock:
        _core_versions_cache["data"] = vers
        _core_versions_cache["ts"] = time.time()
    top = (vers[0].get("id") if vers else "")
    return {"ok": True, "count": len(vers), "latest": top, "newer": bool(top and top != prev_top),
            "first_check": not before, "staged": (_staged_info() or {}).get("version", "")}


def _core_blob_bytes():
    info = _core_blob_info()
    if not info:
        return None
    with _core_blob_lock:
        with open(CORE_BLOB, "rb") as f:
            return f.read(), info["sha256"]


def _core_blob_info():
    try:
        with open(CORE_BLOB_META) as f:
            m = json.load(f)
        if os.path.isfile(CORE_BLOB):
            return m
    except Exception:
        pass
    return None


CORE_UPLOAD_MB = 15
CORE_UPLOAD_MAX = CORE_UPLOAD_MB * 1024 * 1024


def api_core_upload(d):
    _require(d, ["data"])
    try:
        raw = base64.b64decode(d["data"], validate=True)
    except Exception:
        raise Bad("bad_base64", "فایل base64 نامعتبر است", "the file is not valid base64")
    if len(raw) < 100000:
        raise Bad("core_too_small", "فایل خیلی کوچک است — این باینریِ هسته نیست", "the file is too small — this is not a core binary")
    if len(raw) > CORE_UPLOAD_MAX:
        raise Bad("core_too_big", "فایل بیش از حد بزرگ است — حداکثر {0} مگابایت", "the file is too large — at most {0} MB",
                  CORE_UPLOAD_MB)
    if raw[:4] != b"\x7fELF":
        raise Bad("not_elf", "این یک باینریِ ELF لینوکسی نیست", "this is not a Linux ELF binary")
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
            raise Bad("bad_core_version", "نسخهٔ هسته نامعتبر است — فقط حروف/عدد و کاراکترهای «._+-» مجاز است",
                      "invalid core version — only letters, digits and ._+- are allowed")
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
            raise OSError(tx("از راهِ پروکسی فقط نشانیِ https دریافت می‌شود", "only https addresses are fetched through the proxy"))
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
                    raise OSError(tx("گیت‌هاب به نشانیِ نامعلومی هدایت کرد", "GitHub redirected to an unknown address"))
                url = urllib.parse.urljoin(url, loc)
                continue
            if r.status != 200:
                raise urllib.error.HTTPError(url, r.status, r.reason or "", r.headers, None)
            return _read_body(r, r.getheader("Content-Length"), on_progress, should_abort)
        finally:
            for c in (sock, conn):
                if c is not None:
                    try:
                        c.close()
                    except Exception:
                        pass
    raise OSError(tx("گیت‌هاب بیش از حد پشتِ‌سرِهم هدایت کرد", "GitHub redirected too many times in a row"))


def _gh_why(e):
    if isinstance(e, urllib.error.HTTPError):
        if e.code == 404:
            return tx("این نسخه یا فایل روی گیت‌هاب نیست (HTTP 404)", "this version or file is not on GitHub (HTTP 404)")
        if e.code in (403, 429):
            return tx("گیت‌هاب درخواست را محدود کرد (HTTP {0}) — کمی بعد دوباره امتحان کن",
                      "GitHub rate-limited the request (HTTP {0}) — try again a little later", e.code)
        return tx("گیت‌هاب خطای HTTP {0} داد", "GitHub returned HTTP {0}", e.code)
    w = _net_why(e)
    s = str(w).strip()
    return tx_cut(Tx(s, str(_en(w)).strip()), 120) if s else type(e).__name__


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


def _check_arch(arch):
    if arch not in CORE_ARCHES:
        raise Bad("bad_arch", "معماریِ نامعتبر — فقط amd64 یا arm64 مجاز است", "invalid architecture — only amd64 or arm64")


def _release_asset_url(version, arch):
    _check_arch(arch)
    asset = f"tnl-core-linux-{arch}"
    return (f"{_CORE_REL_DL}/latest/download/{asset}" if version in ("latest", "")
            else f"{_CORE_REL_DL}/download/{version}/{asset}")


def _sha_file(url, should_abort=None):
    sha = (_dl(url, 30, should_abort=should_abort).decode("ascii", "replace").split() or [""])[0].lower()
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
        raise RuntimeError(tx("چک‌سامِ فایل در انتشارِ گیت‌هاب نیست", "the GitHub release has no checksum for the file"))
    return sha


def _fetch_release(version, arch, on_progress=None, should_abort=None):
    base = _release_asset_url(version, arch)
    sha = _sha_file(base + ".sha256", should_abort)
    raw = _dl(base, 180, on_progress=on_progress, should_abort=should_abort)
    if hashlib.sha256(raw).hexdigest() != sha:
        raise RuntimeError(tx("چک‌سامِ فایلِ دریافت‌شده با انتشارِ گیت‌هاب نمی‌خواند",
                              "the checksum of the downloaded file does not match the GitHub release"))
    return raw, sha


def _stage_path(version, arch):
    return os.path.join(CORE_STAGE_DIR, "tnl-core-%s-%s" % (re.sub(r"[^A-Za-z0-9._-]", "_", str(version)), arch))


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
    return all(os.path.isfile(_stage_path(info.get("version"), a)) for a in arches)


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
            save_bytes(_stage_path(rel, arch), raw)
            got.append(arch)
            shas[arch] = sha
            sizes[arch] = len(raw)
        save_json(CORE_STAGE_META, {"version": rel, "arches": got, "sha": shas, "size": sizes, "ts": int(time.time())})
        _stage_purge(rel)
    return {"version": rel, "arches": got, "missing": [a for a in CORE_ARCHES if a not in got]}


def _stage_core_meta(version):
    rel = _resolve_core_version(version)
    got = list(CORE_ARCHES)
    with _core_stage_lock:
        save_json(CORE_STAGE_META, {"version": rel, "arches": got, "sha": {}, "size": {},
                                    "ts": int(time.time()), "meta_only": True})
    return {"version": rel, "arches": got, "missing": []}


def _stage_purge(version):
    keep = {os.path.basename(_stage_path(version, a)) for a in CORE_ARCHES}
    try:
        stale = [nm for nm in os.listdir(CORE_STAGE_DIR) if nm not in keep]
    except OSError:
        return
    for nm in stale:
        try:
            os.remove(os.path.join(CORE_STAGE_DIR, nm))
        except OSError:
            pass


def _staged_bytes(arch):
    _check_arch(arch)
    info = _staged_info()
    if not info:
        return None
    ver = info["version"]
    want = str((info.get("sha") or {}).get(arch) or "")
    p = _stage_path(ver, arch)
    try:
        with open(p, "rb") as f:
            raw = f.read()
    except OSError:
        raw = b""
    sha = hashlib.sha256(raw).hexdigest()
    if raw and (not want or sha == want):
        return raw, sha, ver
    try:
        raw, sha = _fetch_release(ver, arch)
    except Exception:
        return None
    save_bytes(p, raw)
    return raw, sha, ver


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
        return {"ok": False, "error": tx("معماریِ نود مشخص نشد — نود باید یک‌بار پاسخ بدهد تا باینریِ درست فرستاده شود", "the node's architecture is unknown — the node must answer once so the right binary is sent")}
    custom = False
    if _delivery_mode("core") == "github":
        sha, ver, b64 = "", str((_staged_info() or {}).get("version") or ""), ""
        if not ver:
            return {"ok": False, "error": tx("هیچ نسخه‌ای انتخاب نشده — اول یک نسخه انتخاب کن", "no version is picked — pick a version first")}
    else:
        b = _staged_bytes(arch)
        if b:
            raw, sha, ver = b
        else:
            blob = _core_blob_bytes()
            if not blob:
                return {"ok": False, "error": tx("هیچ هسته‌ای روی پنل آماده نیست — اول یک نسخه دانلود کن", "no core is ready on the panel — download a version first")}
            (raw, sha), ver, custom = blob, "custom", True
        b64 = base64.b64encode(raw).decode()
    sig = _sign_sha(sha) if sha else ""
    try:
        body = _core_install_body(node, b64, sha, ver, sig, arch, custom)
    except ValueError as e:
        return {"ok": False, "error": _why(e)}
    k = _ensure_update_key(node)
    if not k.get("ok"):
        return k
    r = node_call(node, "core-put", "POST", body, timeout=NODE_UPLOAD_TIMEOUT)
    if not r.get("ok") or r.get("code") == "same":
        return r
    ap = (_github_grant(ver, arch) if _delivery_mode("core") == "github"
          else {"sha256": sha, "version": ver, "sig": sig})
    return node_call(node, "core-apply", "POST", ap, timeout=NODE_UPLOAD_TIMEOUT)


def _push_staged_on_add(node):
    try:
        if _readiness()["core"]:
            _push_staged(node)
    except Exception:
        pass


def _node_tunnel(node, body):
    r = node_call(node, "tunnel", "POST", body, timeout=NODE_OP_TIMEOUT)
    err = str(r.get("error") or r.get("msg") or "")
    if not r.get("ok") and "core not installed" in err:
        pr = _push_staged(node)
        if not pr.get("ok"):
            r["error"] = tx("هسته روی نودِ «{0}» نصب نیست و رساندنِ آن هم نشد: {1}",
                            "the core is not installed on node '{0}' and delivering it failed too: {1}",
                            node.get("name", "?"), pr.get("error") or pr.get("code") or pr.get("msg") or "?")
            return r
        r = node_call(node, "tunnel", "POST", body, timeout=NODE_OP_TIMEOUT)
    return r


_stage_job = {"id": "", "version": "", "sent": 0, "total": 0, "done": True, "cancel": False,
              "code": "", "error": "", "arches": [], "missing": []}
_stage_job_lock = threading.Lock()


def _stage_job_view():
    with _stage_job_lock:
        j = dict(_stage_job)
    pct = int(100 * j["sent"] / j["total"]) if j["total"] else 0
    return {"ok": True, "job": j["id"], "version": j["version"], "done": j["done"], "cancel": j["cancel"],
            **({"code": j["code"], "error": j["error"]} if j["code"] else {}),
            "arches": j["arches"], "missing": j["missing"], "pct": max(0, min(100, pct))}


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
            _stage_job.update(code="cancelled", error=tx("لغو شد", "cancelled"))
    except Exception as e:
        with _stage_job_lock:
            _stage_job.update(code="download_failed", error=_gh_why(e))
    finally:
        with _stage_job_lock:
            _stage_job["done"] = True


def api_core_stage(d):
    version = str((d or {}).get("version") or "latest").strip()
    if version == "custom":
        raise Bad("custom_not_stageable", "باینریِ آپلودشده از گیت‌هاب گرفته یا انتخاب نمی‌شود — همان را با «نصبِ هسته روی همهٔ نودها» یا از منوی هر نود نصب کن",
                  "the uploaded binary is not fetched or picked from GitHub — install it with update-core (version custom)")
    if _delivery_mode("core") == "github":
        info = _stage_core_meta(version)
        return {"ok": True, "meta_only": True, "done": True, **info}
    with _stage_job_lock:
        if not _stage_job["done"]:
            raise Bad("download_running", "یک دانلود همین حالا در جریان است — صبر کن یا لغوش کن",
                      "a download is already running — wait or cancel it")
        _stage_job.update(id=secrets.token_hex(6), version=version, sent=0, total=0, done=False,
                          cancel=False, code="", error="", arches=[], missing=[])
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
        links = [L for L in links if _q_match(q, _link_haystack(L, nodes))]
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
        rec = {**pub, "a_online": _node_answered(L["a_node"]), "b_online": _node_answered(L["b_node"]),
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
            rec["a_ip_rot"] = len(_live_pool(L.get("a_ip_pool"), a_ips)) >= 2
            rec["b_ip_rot"] = len(_live_pool(L.get("b_ip_pool"), b_ips)) >= 2
            if a_act:
                rec["a_ip_active"] = a_act
            if b_act:
                rec["b_ip_active"] = b_act
        out.append(rec)
    return {"links": out, "total": total}


def api_link_view(d):
    _require(d, ["id"])
    with _reg_lock:
        L = get_link(d["id"])
        if L is None:
            raise _no_tunnel()
        side = "a" if L.get("view_side") == "b" else "b"
        store_edit(_LINKS, L["id"], lambda x: x.update(view_side=side))
    return {"ok": True, "view_side": side}


def api_traffic_reset(d):
    d = d or {}
    if d.get("id"):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)
        if not L:
            raise _no_tunnel()
        _tf_reset(L["a_node"], [L["name"]])
        _tf_reset(L["b_node"], [L["name"]])
        return {"ok": True}
    if d.get("node"):
        n = get_node(d["node"])
        if not n:
            raise _no_node()
        _tf_reset(n["id"], ["pf:" + _pf_name(d["name"])] if d.get("name") else ["_node"])
        return {"ok": True}
    raise Bad("missing_target", "شناسهٔ تونل یا نود فرستاده نشد", "no tunnel or node id was sent")


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


def _shared_ports(ttype, exclude_id=None):
    if ttype != "vxlan":
        return frozenset()
    held = set()
    for L in load_links():
        if L.get("type") != "vxlan" or L.get("id") == exclude_id or L.get("enabled") is False:
            continue
        p = int(L.get("port") or 4789)
        held.update({(L.get("a_node"), "", p, "udp"), (L.get("b_node"), "", p, "udp")})
    return frozenset(held)


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
            onip = tx(" (روی {0})", " (on {0})", ip) if ip else ""
            raise Bad("port_busy", "پورتِ {0}/{1} روی نودِ «{2}»{3} اشغال است{4}؛ یک پورتِ دیگر انتخاب کن",
                      "port {0}/{1} on node '{2}'{3} is in use{4}; pick another port",
                      port, proto.upper(), node["name"], onip, tail)


def _core_bind_keys(bindings):
    return {(n["id"], ip or "", int(p), pr) for n, ip, p, pr in bindings}


def _own_ports(L, A, B):
    return frozenset(_core_bind_keys(_port_bindings(
        L.get("type"), L.get("port"), L.get("transport"), L.get("server_side"), int(L["tunnel_id"]), A, B,
        L.get("a_ip"), L.get("b_ip"), L.get("a_ip_pool"), L.get("b_ip_pool"))))


def _guard_server_ports(ttype, src, server_side, tid, A, B, a_ip, b_ip, L=None, own=frozenset()):
    binds = _port_bindings(ttype, src.get("port"), src.get("transport"), server_side, tid, A, B, a_ip, b_ip,
                           src.get("a_ip_pool"), src.get("b_ip_pool"))
    lid = L.get("id") if L else None
    if ttype == "core":
        clash = _core_l4_conflict(binds, exclude_id=lid)
        if clash:
            raise Bad("server_port_taken", "همین آی‌پی و پورتِ سرور از قبل مالِ تونلِ «{0}» است. پورتِ دیگری بگذار "
                      "یا حاملِ دیگری انتخاب کن — روی یک آی‌پی، حاملِ متفاوت یا پورتِ متفاوت مجاز است.",
                      "this server IP and port already belong to tunnel '{0}'. Use another port or another carrier "
                      "— one IP allows a different carrier or a different port.", clash.get("name"))
    _guard_port_conflicts(binds, exclude=own | _shared_ports(ttype, lid))




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
                raise Bad("bad_workers", "تعدادِ صفِ موازی نامعتبر است", "invalid number of parallel queues")
            if not 1 <= n <= CORE_MAX_WORKERS:
                raise Bad("bad_workers", "تعدادِ صفِ موازی باید بینِ 1 تا {0} باشد",
                          "the number of parallel queues must be from 1 to {0}", CORE_MAX_WORKERS)
        else:
            n = int(cur.get(key) or 1)
        if n > 1:
            out[key] = n
    if not out:
        return {}
    if transport not in QUEUEING_TRANSPORTS or fec_on:
        if asked_any:
            raise Bad("workers_not_allowed", "«صف‌های موازی» فقط برای حاملِ raw یا udp و بدونِ FEC است؛ "
                      "جای دیگر هستهٔ اختصاصی همان یک صف را برمی‌دارد",
                      "parallel queues are only for the raw or udp carrier without FEC; elsewhere the core keeps one queue")
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
    fec_bad = Bad("bad_fec", "مقادیرِ FEC نامعتبر است (داده و پریتی هر کدام ≥1، مجموع ≤255)",
                  "invalid FEC values (data and parity each ≥1, sum ≤255)")
    fd = _int_or(d.get("fec_data") or cur.get("fec_data") or 16, fec_bad)
    fp = _int_or(d.get("fec_parity") or cur.get("fec_parity") or 4, fec_bad)
    if fd < 1 or fp < 1 or fd + fp > 255:
        raise fec_bad
    if fd > 64:
        raise Bad("bad_fec", "دادهٔ FEC حداکثر 64 است — بالاتر از آن فریمِ بازسازی‌شده بیرونِ پنجرهٔ ضدِ تکرارِ گیرنده می‌افتد و دور ریخته می‌شود (یعنی پهنای‌باندِ FEC مصرف می‌شود و هیچ ترمیمی نمی‌کند)",
                  "FEC data is at most 64 — above that a rebuilt frame falls outside the receiver's anti-replay window "
                  "and is dropped (FEC bandwidth is spent and repairs nothing)")
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
    ttl = _int_in(d.get("fake_ttl") or cur.get("fake_ttl") or 4, 1, 255,
                  Bad("bad_fake_ttl", "TTL طعمه باید بین 1 تا 255 باشد", "the decoy TTL must be from 1 to 255"))
    if _shape_consumes("fake_ttl", *shape):
        out["fake_ttl"] = min(ttl, DESYNC_INJECT_TTL_MAX)
    cnt = _int_in(d.get("fake_count") or cur.get("fake_count") or 2, 1, 64,
                  Bad("bad_fake_count", "تعدادِ طعمه باید بین 1 تا 64 باشد", "the decoy count must be from 1 to 64"))
    out["fake_count"] = cnt
    mode = str(d.get("fake_mode") or cur.get("fake_mode") or "ttl").strip().lower()
    if mode not in ("ttl", "badsum", "both"):
        raise Bad("bad_fake_mode", "حالتِ طعمه نامعتبر است", "invalid decoy mode")
    if mode == "both" and cnt == 1:
        raise Bad("bad_fake_mode", "حالتِ «هر دو» به حداقل 2 طعمه نیاز دارد (یک طعمه نمی‌تواند هم‌زمان TTL‌پایین و چک‌سام‌خراب باشد)",
                  "mode 'both' needs at least 2 decoys (one decoy cannot be low-TTL and bad-checksum at once)")
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
            p = subprocess.run(["dig", "+short", "HTTPS", host], capture_output=True, timeout=6)
        except Exception:
            return False, ""
        if p.returncode != 0:
            return False, ""
        return True, _ech_from_text(p.stdout.decode("utf-8", "replace"))

    def via_doh(base):
        try:
            req = urllib.request.Request("%s?name=%s&type=HTTPS" % (base, host),
                                         headers={"accept": "application/dns-json", "user-agent": "tnl-central"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return False, ""
        return True, _ech_from_doh_answers(data)

    def via_doh_proxy(dhost, dpath):
        sock = None
        try:
            scheme, phost, pport, puser, ppass = proxy_parts(proxy)
            if not phost or not pport:
                return False, ""
            if scheme.startswith("socks"):
                sock = _socks5_socket(phost, pport, puser, ppass, dhost, 443, 7)
            elif scheme in ("http", "https", "connect"):
                sock = _http_connect_socket(phost, pport, puser, ppass, dhost, 443, 7)
            else:
                return False, ""
            tls = ssl.create_default_context().wrap_socket(sock, server_hostname=dhost)
            sock = None
            conn = http.client.HTTPConnection(dhost, 443, timeout=7)
            conn.sock = tls
            conn.request("GET", "%s?name=%s&type=HTTPS" % (dpath, host),
                         headers={"accept": "application/dns-json", "user-agent": "tnl-central"})
            data = json.loads(conn.getresponse().read().decode("utf-8", "replace"))
            conn.close()
            return True, _ech_from_doh_answers(data)
        except Exception:
            return False, ""
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    doh = ["https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query",
           "https://dns.google/resolve", "https://8.8.8.8/resolve"]
    if proxy:
        tasks = [lambda: via_doh_proxy("cloudflare-dns.com", "/dns-query"),
                 lambda: via_doh_proxy("dns.google", "/resolve")]
    else:
        tasks = [via_dig] + [(lambda b=b: via_doh(b)) for b in doh]
    answered = False
    for attempt in range(3):
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks))
        futs = [ex.submit(t) for t in tasks]
        found = ""
        try:
            for f in concurrent.futures.as_completed(futs, timeout=8):
                try:
                    ok, v = f.result()
                except Exception:
                    ok, v = False, ""
                answered = answered or ok
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
    return "" if answered else None


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
                out[futs[f]] = f.result()
            except Exception:
                out[futs[f]] = None
    return out


def _ech_px(src):
    if not src.get("ech_proxy"):
        return ""
    p = get_proxy(str(src.get("ech_proxy_id") or ""))
    if not p:
        raise Bad("ech_proxy_missing", "پروکسیِ ECH این تونل دیگر وجود ندارد — یکی بساز و در ویرایشِ تونل انتخابش کن",
                  "this tunnel's ECH proxy no longer exists — create one and pick it when editing the tunnel")
    return proxy_url(p)


def _ech_proxy_fields(d, cur, out):
    on = bool(d.get("ech_proxy") if "ech_proxy" in d else cur.get("ech_proxy"))
    if not on:
        return ""
    pid = str((d.get("ech_proxy_id") if "ech_proxy_id" in d else cur.get("ech_proxy_id")) or "").strip()
    p = get_proxy(pid)
    if not p:
        raise Bad("ech_proxy_missing", "پروکسیِ ECH انتخاب نشده — از بخشِ «پروکسی‌ها» یکی بساز و انتخابش کن",
                  "no ECH proxy picked — create one under proxies and pick it")
    out["ech_proxy"] = True
    out["ech_proxy_id"] = pid
    return proxy_url(p)


def _cdn_carrier(d, cur):
    v = str((d.get("cdn_carrier") if "cdn_carrier" in d else (cur or {}).get("cdn_carrier")) or "ws").strip().lower()
    if v not in ("ws", "http", "grpc"):
        raise Bad("bad_cdn_carrier", "حاملِ CDN نامعتبر است", "invalid CDN carrier")
    return v


def _sni_split_fields(d, cur, ech=False):
    on = d.get("sni_split") if ("sni_split" in d) else cur.get("sni_split")
    if not on:
        return {}
    sp = _int_in((d.get("split_pos") if "split_pos" in d else cur.get("split_pos")) or 0, 0, 1400,
                 Bad("bad_split_pos", "split_pos باید بین 0 تا 1400 باشد (0 = خودکار، وسطِ دامنه)",
                     "split_pos must be from 0 to 1400 (0 = automatic, middle of the domain)"))
    if ech and not sp:
        raise Bad("split_needs_pos", "با ECH روشن نامِ دامنه در ClientHello رمز است، پس نقطهٔ برشِ خودکار پیدا نمی‌شود و هیچ چیزی تکه نمی‌شود — یا «نقطهٔ برش» را دستی بگذار یا تقسیمِ SNI را خاموش کن",
                  "with ECH on, the domain in the ClientHello is encrypted, so no automatic split point is found and "
                  "nothing is split — set split_pos by hand or turn SNI splitting off")
    out = {"sni_split": True}
    if sp:
        out["split_pos"] = sp
    mode = str((d.get("sni_mode") if "sni_mode" in d else cur.get("sni_mode")) or "split").strip().lower()
    if mode not in ("split", "disorder", "fake"):
        raise Bad("bad_sni_mode", "حالتِ SNI نامعتبر است (split / disorder / fake)", "invalid SNI mode (split / disorder / fake)")
    if mode != "split":
        out["sni_mode"] = mode
    if mode == "disorder":
        st = _int_in((d.get("split_ttl") if "split_ttl" in d else cur.get("split_ttl")) or 0, 0, SPLIT_TTL_MAX,
                     Bad("bad_split_ttl", "split_ttl باید بین 0 تا {0} باشد (0 = پیش‌فرض)؛ بالاتر از آن سگمنتِ سرْ به سرور می‌رسد و disorder بی‌اثر می‌شود",
                         "split_ttl must be from 0 to {0} (0 = default); above that the head segment reaches the server "
                         "and disorder has no effect", SPLIT_TTL_MAX))
        if st:
            out["split_ttl"] = st
    return out


_EDGE_PLAIN_PORTS = (80, 8080, 8880, 2052, 2082, 2086, 2095)
_EDGE_TLS_PORTS = (443, 2053, 2083, 2087, 2096, 8443)


def _edge_port_ok(port, tls):
    allowed = _EDGE_TLS_PORTS if tls else _EDGE_PLAIN_PORTS
    if port in allowed:
        return
    if tls:
        raise Bad("bad_edge_port",
                  "wss (TLS به CDN) روشن است، پس پورتِ لبه باید یکی از پورت‌های HTTPS باشد: {0} — "
                  "پورتِ {1} قبول نیست. (یا wss را خاموش کن و پورتِ HTTP بگذار.)",
                  "wss (TLS to the CDN) is on, so the edge port must be one of the HTTPS ports: {0} — "
                  "port {1} is not accepted. (Or turn wss off and use an HTTP port.)", list(allowed), port)
    raise Bad("bad_edge_port",
              "wss خاموش است، پس پورتِ لبه باید یکی از پورت‌های HTTP باشد: {0} — "
              "پورتِ {1} قبول نیست. (یا wss را روشن کن و 443 بگذار.)",
              "wss is off, so the edge port must be one of the HTTP ports: {0} — "
              "port {1} is not accepted. (Or turn wss on and use 443.)", list(allowed), port)


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
            raise Bad("bad_number", "مقدارِ «{0}» باید عدد باشد", "'{0}' must be a number", k)
        if v < lo or v > hi:
            raise Bad("out_of_range", "«{0}» باید بین {1} و {2} باشد", "'{0}' must be from {1} to {2}", k, lo, hi)
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
        raise Bad("bad_ws_host", "دامنهٔ WebSocket (ws_host) نامعتبر است", "invalid WebSocket domain (ws_host)")
    if host:
        out["ws_host"] = host
    path = str((d["ws_path"] if "ws_path" in d else cur.get("ws_path")) or "").strip()
    if path:
        if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", path):
            raise Bad("bad_ws_path", "مسیرِ WebSocket (ws_path) نامعتبر است (باید با / شروع شود)",
                      "invalid WebSocket path (ws_path) (must start with /)")
        out["ws_path"] = path
    tls = d.get("ws_tls") if ("ws_tls" in d) else cur.get("ws_tls")
    if bool(tls):
        if not host:
            raise Bad("wss_needs_host", "برای wss (TLS به CDN) باید دامنه (ws_host) را وارد کنی",
                      "wss (TLS to the CDN) needs a domain (ws_host)")
        out["ws_tls"] = True
    edge = str((d["edge_ip"] if "edge_ip" in d else cur.get("edge_ip")) or "").strip()
    if edge:
        eh = edge.rpartition(":")[0] or edge
        if not re.match(r"^[A-Za-z0-9.\-]{1,253}$", eh):
            raise Bad("bad_edge_ip", "آدرسِ لبهٔ CDN (edge_ip) نامعتبر است", "invalid CDN edge address (edge_ip)")
        ep = edge.rpartition(":")[2] if ":" in edge else ""
        if ep.isdigit():
            _edge_port_ok(int(ep), bool(out.get("ws_tls")))
        out["edge_ip"] = edge
    if out.get("ws_tls") and not edge:
        raise Bad("wss_needs_edge", "wss یعنی TLS روی لبهٔ CDN باز می‌شود، ولی «آی‌پیِ لبهٔ CDN» خالی است — "
                  "کلاینت مستقیم به خودِ سرور دیال می‌کند و هستهٔ سرور هیچ‌جا TLS را باز نمی‌کند، "
                  "پس تونل هرگز بالا نمی‌آید. آی‌پیِ لبه را بگذار یا wss را خاموش کن",
                  "wss means TLS ends at the CDN edge, but the edge IP is empty — the client dials the server "
                  "directly and the server core never ends TLS, so the tunnel never comes up. Set the edge IP or turn wss off")
    ech = d.get("ech") if ("ech" in d) else cur.get("ech")
    if ech:
        if not out.get("ws_tls"):
            raise Bad("ech_needs_wss", "ECH به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن",
                      "ECH needs wss — turn wss (TLS to the CDN) on first")
        cfg = _fetch_ech(host, _ech_proxy_fields(d, cur, out))
        if not cfg:
            raise Bad("ech_key_missing", "کلیدِ ECH برای «{0}» به دست نیامد — {1}", "no ECH key was found for '{0}' — {1}",
                      host, _ech_why(cfg))
        out["ech"] = True
        out["ws_ech"] = cfg
    cdn = _cdn_carrier(d, cur)
    xh = cdn != "ws"
    if bool(xh):
        if cdn == "grpc" and not out.get("ws_tls"):
            raise Bad("grpc_needs_wss", "حاملِ grpc به wss نیاز دارد (برای HTTP/2 به لبه) — اول wss را روشن کن",
                      "the grpc carrier needs wss (for HTTP/2 to the edge) — turn wss on first")
        out["cdn_carrier"] = cdn
        out.update(_cdn_shape_fields(d, cur, cdn))
    ss = _sni_split_fields(d, cur, bool(out.get("ech")))
    if ss:
        if not out.get("ws_tls"):
            raise Bad("split_needs_wss", "تقسیمِ SNI به wss نیاز دارد — اول wss (TLS به CDN) را روشن کن",
                      "SNI splitting needs wss — turn wss (TLS to the CDN) on first")
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
                raise Bad("bad_edge_ip", "آی‌پیِ لبهٔ نامعتبر (باید IPv4:port باشد؛ دامنه مجاز نیست — استخر مستقیم به آی‌پی وصل می‌شود): {0}",
                          "invalid edge IP (must be IPv4:port; no domain — the pool dials the IP directly): {0}", x)
            _edge_port_ok(int(p), True)
            v = "%s:%s" % (h, p)
            if v in seen:
                continue
            seen.add(v)
            res.append(v)
        return res

    old_path = str(cur.get("ws_path") or "").strip()

    def _hosts(key):
        seen, res = set(), []
        for x in _list(key):
            hp = ""
            if isinstance(x, dict):
                hp = str(x.get("path") or "").strip()
                x = x.get("host", "")
            if hp == old_path:
                hp = ""
            x = str(x).strip().lower()
            if not x or x in seen:
                continue
            if not re.match(_DOMAIN_RE, x):
                raise Bad("bad_sni", "دامنهٔ (SNI) نامعتبر (باید یک دامنهٔ معتبر باشد): {0}",
                          "invalid domain (SNI) (must be a valid domain): {0}", x)
            seen.add(x)
            res.append((x, hp))
        return res

    clean_ips, clean_snis = _ips("ws_edge_ips"), _hosts("ws_edge_snis")
    clean_hosts = [h for h, _ in clean_snis]
    if not clean_ips:
        raise Bad("pool_needs_ip", "استخر به حداقل یک آی‌پیِ لبه نیاز دارد", "the pool needs at least one edge IP")
    if not clean_hosts:
        raise Bad("pool_needs_sni", "استخر به حداقل یک دامنهٔ (SNI) نیاز دارد", "the pool needs at least one domain (SNI)")
    if len(clean_ips) < 2 and len(clean_hosts) < 2:
        raise Bad("pool_no_axis", "استخرِ لبه باید دستِ‌کم روی یک محور بچرخد — یا ۲ آی‌پیِ لبه یا ۲ دامنه",
                  "the edge pool must rotate on at least one axis — 2 edge IPs or 2 domains")
    if len(clean_ips) > 64 or len(clean_hosts) > 64:
        raise Bad("pool_too_big", "استخر خیلی بزرگ است (حداکثر 64)", "the pool is too large (at most 64)")
    path = str((d["ws_path"] if "ws_path" in d else cur.get("ws_path")) or "").strip() or "/"
    if not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", path):
        raise Bad("bad_ws_path", "مسیر (path) نامعتبر است", "invalid path")
    ech_on = bool(d.get("ech") if "ech" in d else cur.get("ech"))
    _epx_store = {}
    _epx = _ech_proxy_fields(d, cur, _epx_store) if ech_on else ""
    ech_map = _fetch_ech_map(clean_hosts, _epx) if ech_on else {}
    snis = []
    for h, hp in clean_snis:
        ec = ech_map.get(h, "") if ech_on else ""
        if ech_on and not ec:
            raise Bad("ech_key_missing", "کلیدِ ECH برای «{0}» به دست نیامد — {1}. استخر با ECH روشن ساخته نمی‌شود.",
                      "no ECH key was found for '{0}' — {1}. The pool is not built with ECH on.", h, _ech_why(ec))
        if hp and not re.match(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{0,255}$", hp):
            raise Bad("bad_ws_path", "مسیرِ WebSocket برای «{0}» نامعتبر است (باید با / شروع شود)",
                      "invalid WebSocket path for '{0}' (must start with /)", h)
        snis.append({"host": h, "ech": ec, "path": hp or path})
    res = {
        "ws_pool": True,
        "ws_tls": True,
        "ech": ech_on,
        "cdn_carrier": _cdn_carrier(d, cur),
        "ws_edge_ips": clean_ips,
        "ws_edge_snis": snis,
        "ws_rotate_secs": _rotate_secs(_ws_rotate_default(d, cur), 28800, tx("فاصلهٔ چرخشِ لبه", "edge rotation interval")),
        "ws_port_roll": bool(d["ws_port_roll"] if "ws_port_roll" in d else cur.get("ws_port_roll")),
        "ws_path": path,
    }
    res.update(_cdn_shape_fields(d, cur, res["cdn_carrier"]))
    res.update(_sni_split_fields(d, cur, ech_on))
    res.update(_epx_store)
    return res


def _create_family(d, ttype):
    if ttype != "core":
        return ttype
    transport = str(d.get("transport") or "udp").strip().lower()
    return _cdn_carrier(d, None) if transport == "ws" else transport


TID_HOLD = 1800
_tid_lock = threading.Lock()
_tid_busy = {}


def _tid_held():
    now = time.monotonic()
    with _tid_lock:
        for k in [k for k, v in _tid_busy.items() if v[1] <= now]:
            _tid_busy.pop(k, None)
        return set(_tid_busy)


def _tid_reserve(tid, owner):
    now = time.monotonic()
    with _tid_lock:
        cur = _tid_busy.get(tid)
        if cur and cur[1] > now:
            return False
        _tid_busy[tid] = (owner, now + TID_HOLD)
        return True


def _tid_free(owner):
    with _tid_lock:
        for k in [k for k, v in _tid_busy.items() if v[0] == owner]:
            _tid_busy.pop(k, None)


def api_create_tunnel(d):
    d = d or {}
    A, B = get_node(d.get("a_node")), get_node(d.get("b_node"))
    ttype = str(d.get("type") or "")

    def build(h):
        try:
            with _PairLock(d.get("a_node"), d.get("b_node")):
                return _create_tunnel_impl(d, h)
        finally:
            _tid_free(h["key"])
            _name_free(h["key"])
            _release_proxies(h["key"])

    return act_start("new:" + secrets.token_hex(4), build,
                     target="%s ↔ %s" % ((A or {}).get("name", "?"), (B or {}).get("name", "?")),
                     page="core" if ttype == "core" else "tunnels",
                     ttype=_create_family(d, ttype))


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
                  "ws_rotate_secs", "ws_port_roll", "sni_split", "split_pos", "sni_mode", "split_ttl",
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
        raise Bad("bad_cipher", "روشِ رمزنگاری نامعتبر است", "invalid cipher")
    ce["cipher"] = cipher
    if cipher != "none":
        ce["psk"] = cur.get("psk") or secrets.token_hex(32)
    transport = str(d.get("transport") or cur.get("transport") or "udp").strip().lower()
    if transport not in CORE_TRANSPORTS:
        raise Bad("bad_transport", "حاملِ اتصال نامعتبر است", "invalid carrier")
    ce["transport"] = transport
    if transport == "raw":
        if cipher == "none":
            raise Bad("raw_needs_cipher", "حاملِ raw به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)",
                      "the raw carrier needs encryption (do not set the cipher to none)")
        profile = str(d.get("raw_profile") or cur.get("raw_profile") or "bare").strip().lower()
        if profile not in CORE_RAW_PROFILES:
            raise Bad("bad_raw_profile", "پروفایلِ raw نامعتبر است", "invalid raw profile")
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
                raise Bad("bad_raw_port", "پورتِ حامل باید بینِ 1 تا 65535 باشد", "the carrier port must be from 1 to 65535")
            ce["raw_port"] = _rport
        elif _rport and "raw_port" in d:
            raise Bad("raw_port_not_allowed", "«پورتِ حامل» فقط برای پروفایلِ udp و tcp است؛ «{0}» هیچ پورتی جعل نمی‌کند",
                      "raw_port is only for the udp and tcp profiles; '{0}' fakes no port", profile)
        _srand_req, _rsport_req = "raw_sport_random" in d, "raw_sport" in d
        _srand = bool(d["raw_sport_random"] if _srand_req else cur.get("raw_sport_random"))
        try:
            _rsport = int((d["raw_sport"] if _rsport_req else cur.get("raw_sport")) or 0)
        except (TypeError, ValueError):
            _rsport = 0
        if _srand and _rsport and _srand_req and _rsport_req:
            raise Bad("sport_conflict", "«پورتِ مبدأ» یا ثابت است یا چرخان — هر دو با هم نمی‌شود",
                      "the source port is either fixed or random — not both")
        if _rsport_req and _rsport and not _srand_req:
            _srand = False
        if _srand_req and _srand and not _rsport_req:
            _rsport = 0
        if profile in ("udp", "tcp"):
            if _srand:
                ce["raw_sport_random"] = True
            elif _rsport:
                if not 1 <= _rsport <= 65535:
                    raise Bad("bad_raw_sport", "پورتِ مبدأ باید بینِ 1 تا 65535 باشد", "the source port must be from 1 to 65535")
                ce["raw_sport"] = _rsport
        else:
            if _srand and "raw_sport_random" in d:
                raise Bad("raw_sport_not_allowed", "«پورتِ مبدأِ چرخان» فقط برای پروفایلِ udp و tcp است؛ «{0}» هیچ پورتی جعل نمی‌کند",
                          "raw_sport_random is only for the udp and tcp profiles; '{0}' fakes no port", profile)
            if _rsport and "raw_sport" in d:
                raise Bad("raw_sport_not_allowed", "«پورتِ مبدأ» فقط برای پروفایلِ udp و tcp است؛ «{0}» هیچ پورتی جعل نمی‌کند",
                          "raw_sport is only for the udp and tcp profiles; '{0}' fakes no port", profile)
        try:
            _rrot = int((d["raw_sport_rotate"] if "raw_sport_rotate" in d else cur.get("raw_sport_rotate")) or 0)
        except (TypeError, ValueError):
            _rrot = 0
        if profile in ("udp", "tcp"):
            if _rrot:
                if not 1 <= _rrot <= RAW_SPROT_MAX:
                    raise Bad("bad_sport_rotate", "«چرخشِ پورتِ مبدأ» باید بینِ 1 تا {0} باشد (هر چند پکت یک پورتِ تازه؛ زیرِ سقفِ per-tuple میدل‌باکس)",
                              "raw_sport_rotate must be from 1 to {0} (a fresh port every few packets; under the middlebox per-tuple cap)",
                              RAW_SPROT_MAX)
                if _srand or _rsport:
                    raise Bad("sport_conflict", "«چرخشِ پورتِ مبدأ» پورت را مدام عوض می‌کند، پس با «پورتِ مبدأِ ثابت» یا «رندومِ واکنشی» جمع نمی‌شود",
                              "raw_sport_rotate keeps changing the port, so it does not combine with a fixed or random source port")
                ce["raw_sport_rotate"] = _rrot
                try:
                    _rdp = int((d["raw_dports"] if "raw_dports" in d else cur.get("raw_dports")) or 0)
                except (TypeError, ValueError):
                    _rdp = 0
                if _rdp:
                    if not 1 <= _rdp <= RAW_DPORTS_MAX:
                        raise Bad("bad_raw_dports", "«چند پورتِ مقصد» باید بینِ 1 تا {0} باشد",
                                  "raw_dports must be from 1 to {0}", RAW_DPORTS_MAX)
                    ce["raw_dports"] = _rdp
            elif _sint(d.get("raw_dports")) and "raw_dports" in d:
                raise Bad("dports_need_rotate", "«چند پورتِ مقصد» بدونِ «چرخشِ پورتِ مبدأ» بی‌اثر است — با مبدأِ ثابت هر پکت باز هم در همان سطلِ میدل‌باکس می‌افتد. اول چرخش را روشن کن",
                          "raw_dports has no effect without raw_sport_rotate — with a fixed source every packet still lands "
                          "in the same middlebox bucket. Turn rotation on first")
        elif _rrot and "raw_sport_rotate" in d:
            raise Bad("raw_sport_not_allowed", "«چرخشِ پورتِ مبدأ» فقط برای پروفایلِ udp و tcp است؛ «{0}» هیچ پورتی جعل نمی‌کند",
                      "raw_sport_rotate is only for the udp and tcp profiles; '{0}' fakes no port", profile)
        _ctb = bool(d["conntrack_bypass"]) if "conntrack_bypass" in d else bool(cur.get("conntrack_bypass"))
        if _ctb:
            if profile not in ("udp", "tcp"):
                raise Bad("conntrack_not_allowed", "«رد شدن از conntrack» فقط برای پروفایلِ udp و tcp معنا دارد؛ «{0}» به‌ازای هر پکت جریانِ تازه نمی‌سازد",
                          "conntrack_bypass only makes sense for the udp and tcp profiles; '{0}' does not open a new flow per packet",
                          profile)
            ce["conntrack_bypass"] = True
    if transport == "ws":
        ce.update(_ws_fields(d, transport, cur))
    ce.update(_fec_fields(d, transport, cur))
    ce.update(_workers_field(d, transport, bool(ce.get("fec")), cur))
    ce.update(_desync_fields(d, shape, cur, ce.get("cdn_carrier", "ws") != "ws"))
    if (bool(d.get("obfs")) if "obfs" in d else bool(cur.get("obfs"))):
        if cipher == "none":
            raise Bad("obfs_needs_cipher", "استتار به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)",
                      "obfuscation needs encryption (do not set the cipher to none)")
        ce["obfs"] = True
    cover = (bool(d.get("cover")) if "cover" in d else bool(cur.get("cover"))) and transport == "tcp"
    if cover and cipher == "none":
        raise Bad("cover_needs_cipher", "پوششِ TLS به رمزنگاری نیاز دارد (رمز را «بدونِ رمز» نگذار)",
                  "the TLS cover needs encryption (do not set the cipher to none)")
    cover_sni = str((d["cover_sni"] if "cover_sni" in d else cur.get("cover_sni")) or "").strip()
    if cover_sni and not re.match(r"^[A-Za-z0-9.-]{1,253}$", cover_sni):
        raise Bad("bad_cover_sni", "دامنهٔ نمایشی (SNI) نامعتبر است", "invalid cover domain (SNI)")
    if cover and not cover_sni:
        raise Bad("cover_needs_sni", "برای پوششِ TLS باید دامنهٔ نمایشی (SNI) را وارد کنی", "the TLS cover needs a cover domain (SNI)")
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
            raise Bad("bad_sport_band", "«بازهٔ پورتِ مبدأ» باید دو پورتِ بینِ {0} تا 65535 باشد و ابتدایش از انتهایش کوچک‌تر — زیرِ {0} پورتِ ممتاز است و هیچ حاملی دلیلی برای ادعای آن ندارد",
                      "the source port band must be two ports from {0} to 65535, low before high — below {0} ports are "
                      "privileged and no carrier has a reason to claim them", RAW_BAND_MIN_LO)
        if _bhi - _blo + 1 < RAW_BAND_MIN_SPAN:
            raise Bad("bad_sport_band", "«بازهٔ پورتِ مبدأ» دستِ‌کم باید {0} پورت پهنا داشته باشد؛ باریک‌تر از آن یعنی پورتِ ثابت با چند قدمِ اضافه",
                      "the source port band must be at least {0} ports wide; narrower is a fixed port with extra steps",
                      RAW_BAND_MIN_SPAN)
        ce["sport_lo"], ce["sport_hi"] = _blo, _bhi
    try:
        _ptries = int((d["port_tries"] if "port_tries" in d else cur.get("port_tries")) or 0)
    except (TypeError, ValueError):
        _ptries = 0
    if _ptries and (not _shape_consumes("port_tries", *shape) or (ce.get("ws_pool") and not ce.get("ws_port_roll"))):
        _ptries = 0
    if _ptries:
        if not 1 <= _ptries <= PORT_TRIES_MAX:
            raise Bad("bad_port_tries", "تعدادِ قرعهٔ پورتِ مبدأ باید بینِ 1 تا {0} باشد",
                      "port_tries must be from 1 to {0}", PORT_TRIES_MAX)
        ce["port_tries"] = _ptries
    if (bool(d.get("gso")) if "gso" in d else bool(cur.get("gso"))):
        ce["gso"] = True
    if "ip_rotate" in d:
        if transport in DIRECT_TRANSPORTS and bool(d.get("ip_rotate")):
            ap = _pool_with(a_ip, d.get("a_ip_pool"), a_ips)
            bp = _pool_with(b_ip, d.get("b_ip_pool"), b_ips)
            if len(ap) >= 2 or len(bp) >= 2:
                ce["ip_rotate"] = True
                ce["a_ip_pool"], ce["b_ip_pool"] = ap, bp
                ce["rotate_secs"] = _rotate_secs(d.get("rotate_secs"), 86400, tx("فاصلهٔ چرخش", "rotation interval"))
    elif cur.get("ip_rotate"):
        for _k in _ROTATION_KEYS:
            if cur.get(_k) is not None:
                ce[_k] = cur[_k]
    server_side = d.get("server_side") if d.get("server_side") in ("a", "b") else (cur.get("server_side") or "a")
    return ce, server_side


CREATE_STEPS = 4
_STEP_READ = tx("خواندنِ وضعیتِ دو نود", "reading both nodes")


def _step_build(N):
    return tx("ساخت روی نودِ «{0}»", "building on node '{0}'", N["name"])


def _node_failed(N, r, tail=""):
    return Bad("node_failed", "نودِ «{0}»: {1}{2}", "node '{0}': {1}{2}", N["name"], r.get("error") or r.get("msg"), tail)


def _tunnel_type(d):
    if d["type"] not in TYPES:
        raise Bad("bad_type", "نوعِ تونل نامعتبر است", "invalid tunnel type")
    return d["type"]


def _distinct_ends(A, B):
    if A["id"] == B["id"]:
        raise Bad("same_node", "دو سرِ تونل باید دو نودِ متفاوت باشند", "the two ends of a tunnel must be two different nodes")


def _want_ip(d, key, N, ips):
    want = str(d.get(key) or "").strip()
    if want and want not in ips:
        raise Bad("ip_not_on_node", "آی‌پیِ «{0}» روی نودِ «{1}» نیست", "IP '{0}' is not on node '{1}'", want, N["name"])
    return want


def _subnet_prefix(d):
    s = str(d.get("subnet") or "").strip()
    if s and "/" not in s:
        raise Bad("subnet_needs_prefix", "سابنت باید پیشوند داشته باشد — مثلاً 192.168.9.0/24",
                  "the subnet needs a prefix — for example 192.168.9.0/24")


def _create_tunnel_impl(d, h):
    act_step(h, _STEP_READ, 0, CREATE_STEPS)
    _require(d, ["a_node", "b_node", "type"])
    A, B = get_node(d["a_node"]), get_node(d["b_node"])
    if not A or not B:
        raise _no_node()
    _distinct_ends(A, B)
    ttype = _tunnel_type(d)
    if ttype == "core":
        _gate_ready(False)
    pa, pb = _ping_both(A, B)
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
    want_a, want_b = _want_ip(d, "a_ip", A, a_ips), _want_ip(d, "b_ip", B, b_ips)
    a_ip = want_a or (a_ips[0] if a_ips else None)
    b_ip = want_b or (b_ips[0] if b_ips else None)
    _guard_ends(A, B, a_ip, b_ip, ttype)
    la = node_call(A, "list", "GET", timeout=30)
    lb = node_call(B, "list", "GET", timeout=30)
    if la.get("configs") is None or lb.get("configs") is None:
        raise Bad("node_list_failed", "فهرستِ تونل‌های یک نود خوانده نشد (مشغول یا قطع) — برای جلوگیری از تداخلِ شناسه متوقف شد",
                  "a node's tunnel list could not be read (busy or down) — stopped to avoid an id clash")
    used = {int(x["tunnel_id"]) for x in load_links() if str(x.get("tunnel_id", "")).isdigit()}
    for L in (la, lb):
        for c in L.get("configs", []):
            try:
                used.add(int(c.get("id")))
            except Exception:
                pass
    used |= _tid_held()
    _cap = (TID_MAX if ttype == "sit" or str(d.get("subnet") or "").strip()
            else subnet_cap(d.get("subnet_base")))
    id_bad = Bad("tunnel_id_range", "شناسهٔ تونل خارج از محدوده است ({0} تا {1})",
                 "the tunnel id is out of range ({0} to {1})", TID_MIN, _cap)
    explicit = _int_or(d.get("id") or 0, id_bad)
    if explicit and not TID_MIN <= explicit <= _cap:
        raise id_bad
    if explicit and explicit in used:
        raise Bad("tunnel_id_taken", "شناسهٔ {0} از قبل روی این فلیت استفاده شده است",
                  "id {0} is already used on this fleet", explicit)
    tid = explicit or next((i for i in range(TID_MIN, _cap + 1) if i not in used), 0)
    if not tid:
        raise Bad("no_free_id", "شناسهٔ آزادی در این بازه نمانده است ({0} تونل می‌گیرد)؛ "
                  "بازهٔ بزرگ‌تری انتخاب کن یا سابنت را دستی بده",
                  "no free id is left in this range (it takes {0} tunnels); pick a larger range or give the subnet by hand",
                  _cap)
    if not _tid_reserve(tid, h["key"]):
        raise Bad("tunnel_id_busy", "شناسهٔ {0} همین الان دارد روی جفتِ دیگری ساخته می‌شود — "
                  "چند لحظه بعد دوباره بزن",
                  "id {0} is being built on another pair right now — try again in a moment", tid)
    _subnet_prefix(d)
    subnet = norm_subnet(ttype, tid, d.get("subnet"), d.get("subnet_base"))
    name = tunnel_name(ttype, tid)
    _name_hold(h["key"], (A["id"], B["id"]), name)
    _guard_subnet_overlap(A, B, subnet)
    _guard_addr_on_another_iface(pa, pb, A, B, subnet, {name})
    extra = {}
    if _needs_tunnel_port(ttype, d, {}):
        port = _int_in(d.get("port") or 0, 0, 65535, _bad_tunnel_port()) or free_tunnel_port(A, B)
        extra["port"] = port
    if ttype == "vxlan":
        port = _int_in(d.get("port") or 4789, 1, 65535, _bad_tunnel_port())
        extra["port"] = port
    if ttype == "ipsec":
        extra["psk"] = secrets.token_hex(32)
    server_side = None
    if ttype == "core":
        ce, server_side = _core_extra(d, {}, a_ip, b_ip, a_ips, b_ips)
        extra.update(ce)
        if extra.get("ech_proxy"):
            _hold_proxy(extra["ech_proxy_id"], h["key"])
    _guard_server_ports(ttype, extra, server_side, tid, A, B, a_ip, b_ip)
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
    act_step(h, _step_build(A), 1, CREATE_STEPS)
    ra = _node_tunnel(A, a_body)
    if not ra.get("ok"):
        tail = _drop_tunnel_from([A], name)
        raise _node_failed(A, ra, tail)
    try:
        act_step(h, _step_build(B), 2, CREATE_STEPS, more=False)
    except ActCancelled:
        _drop_tunnel_from([A], name)
        raise
    rb = _node_tunnel(B, b_body)
    if not rb.get("ok"):
        tail = _drop_tunnel_from(_node_set(A, B), name)
        raise _node_failed(B, rb, tail or _HALF_UNDONE)
    act_step(h, tx("ثبتِ تونل", "saving the tunnel"), 3, CREATE_STEPS, stop=False)
    rec = {"id": secrets.token_hex(6), "name": name, "type": ttype, "subnet": subnet,
           "tunnel_id": tid, "a_node": A["id"], "a_name": A["name"], "a_ip": a_ip,
           "b_node": B["id"], "b_name": B["name"], "b_ip": b_ip,
           **extra, **({"server_side": server_side} if ttype == "core" else {})}
    try:
        with _reg_lock, _pending_lock, store_tx() as t:
            t.put(_LINKS, rec)
            for nid in {A["id"], B["id"]}:
                cur = _M.pending.get(nid, ())
                if name in cur:
                    t.pending(nid, [x for x in cur if x != name])
    except StoreUnknown as e:
        _refresh_cache([A["id"], B["id"]])
        raise Bad("save_unknown", "تونل روی هر دو نود ساخته شد ولی {0} — برای همین برچیده نشد. اگر بعداً در فهرست نبود، "
                  "به‌صورتِ «تونلِ ثبت‌نشده» روی نود نشان داده می‌شود و می‌توانی پاکش کنی",
                  "the tunnel was built on both nodes but {0} — so it was not torn down. If it is missing from the list "
                  "later, it shows on the node as an unregistered tunnel and you can delete it", _why(e)) from None
    except Exception as e:
        tail = _drop_tunnel_from(_node_set(A, B), name)
        raise Bad("save_failed", "ذخیرهٔ رکوردِ لینک شکست خورد{0} ({1})", "saving the link record failed{0} ({1})",
                  tail or _HALF_UNDONE, tx_cut(_why(e), 80))
    _refresh_cache([A["id"], B["id"]])
    return {"ok": True, "name": name}


def api_delete_link(d):
    def run(h):
        try:
            return _delete_link_impl(d, h)
        finally:
            _name_free(h["key"])

    return act_link(d, run)


DELETE_STEPS = 3


def _delete_link_impl(d, h):
    act_step(h, tx("بررسیِ دو سر", "checking both ends"), 0, DELETE_STEPS)
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()
    with _PairLock(L["a_node"], L["b_node"]):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)
        if not L:
            return {"ok": True}
        _name_hold(h["key"], (L["a_node"], L["b_node"]), L["name"])
        force = bool(d.get("force"))
        ends = [(L["a_node"], L["a_name"]), (L["b_node"], L["b_name"])]
        if not force:
            off = [nm for nid, nm in ends if not _node_answered(nid)]
            if off:
                _refresh_cache([L["a_node"], L["b_node"]])
                return {"ok": False, "offer": "force", "code": "node_offline", "msg": tx(
                    "نودِ «{0}» در دسترس نیست — لینک دست‌نخورده نگه داشته شد؛ وقتی نود برگشت دوباره حذف کن، یا «حذفِ اجباری» را بزن",
                    "node '{0}' is unreachable — the link was left untouched; delete again when the node is back, or use force",
                    tx_join("»، «", off, "', '"))}
        errs, deferred = [], []

        def defer(nid, nm):
            if _pending_add(nid, L["name"]):
                deferred.append(nm)
            else:
                errs.append(tx("{0}: صفِ حذفِ معلق نوشته نشد", "{0}: the pending-delete queue was not written", nm))

        act_step(h, tx("برچیدنِ تونل روی دو نود", "removing the tunnel from both nodes"), 1, DELETE_STEPS, more=False)
        for nid, nm in ends:
            n = get_node(nid)
            if not n:
                continue
            if force and _known_offline(n):
                defer(nid, nm)
                continue
            r = node_call(n, "delete", "POST", {"name": L["name"]})
            if not r.get("ok"):
                if not force:
                    errs.append(tx("{0}: {1}", "{0}: {1}", nm, r.get("error")))
                else:
                    defer(nid, nm)
        if errs:
            _refresh_cache([L["a_node"], L["b_node"]])
            return {"ok": False, "offer": "force", "code": "delete_failed", "msg": tx(
                "{0} — لینک نگه داشته شد؛ وقتی نود در دسترس شد دوباره حذف کن، یا «حذفِ اجباری» را بزن",
                "{0} — the link was kept; delete again when the node is reachable, or use force", tx_join("; ", errs))}
        act_step(h, tx("برداشتنِ رکورد", "removing the record"), 2, DELETE_STEPS, stop=False)
        with _reg_lock, store_tx() as t:
            t.drop(_LINKS, d["id"])
        _tf_forget(L["a_node"], [L["name"]])
        _tf_forget(L["b_node"], [L["name"]])
        _refresh_cache([L["a_node"], L["b_node"]])
        if deferred:
            return {"ok": True, "msg": tx("لینک حذف شد؛ پاک‌سازیِ سمتِ «{0}» وقتی نود برگشت خودکار انجام می‌شود",
                                          "the link was deleted; the cleanup on '{0}' runs by itself when the node is back",
                                          tx_join("»، «", deferred, "', '"))}
        return {"ok": True}


REORDER_MAX = 256


def api_reorder(d):
    _require(d, ["kind", "id", "targets"])
    kind = d["kind"]
    aid = str(d["id"])
    targets = d["targets"]
    if not isinstance(targets, list) or len(targets) > REORDER_MAX:
        raise Bad("bad_order", "فهرستِ ترتیب نامعتبر است (حداکثر {0} مورد)", "the order list is invalid (at most {0} items)",
                  REORDER_MAX)
    targets = [str(t) for t in targets if str(t) != aid]
    if not targets:
        return {"ok": True}
    if kind == "portfw":
        return _reorder_portfw(aid, targets)
    if kind == "nodes":
        coll = _NODES
    elif kind in ("core", "tunnels"):
        coll = _LINKS
    else:
        raise Bad("bad_kind", "نوعِ نامعتبر", "invalid kind")
    with _reg_lock:
        _store_ready()
        ids = [x["id"] for x in coll.snap.rows]
        pos = {rid: i for i, rid in enumerate(ids)}
        if aid not in pos or any(t not in pos for t in targets):
            raise _no_item()
        for bid in targets:
            i, jx = pos[aid], pos[bid]
            ids[i], ids[jx] = ids[jx], ids[i]
            pos[aid], pos[bid] = jx, i
        with store_tx() as t:
            t.order(coll, ids)
    return {"ok": True}


RESTORE_RETRY_GAP = 3


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
        _core_rotation_bodies(
            L, a_body, b_body,
            _flat_ips(_cached_ping(A["id"])) if A else None,
            _flat_ips(_cached_ping(B["id"])) if B else None)
        _core_workers_bodies(L, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
    _apply_probe_tuning(a_body, b_body)
    def put_back(pair):
        N, body = pair
        if not N:
            return ""
        for attempt in (0, 1):
            try:
                r = node_call(N, "tunnel", "POST", body, timeout=NODE_OP_TIMEOUT)
            except Exception:
                r = {"offline": True}
            if r.get("ok"):
                return ""
            if attempt == 0 and r.get("offline"):
                time.sleep(RESTORE_RETRY_GAP)
            else:
                break
        return N["name"]

    stuck = [x for x in parallel_map(put_back, ((A, a_body), (B, b_body))) if x]
    if stuck:
        _set_drift(L["id"], True)
    return stuck


def _restore_tail(stuck):
    if not stuck:
        return tx(" (تونلِ قبلی بازگردانده شد)", " (the previous tunnel was restored)")
    return tx(" (بازگردانیِ تونلِ قبلی روی «{0}» هم نشد — آن سر الان تونل ندارد؛ «بازسازی» را بزن)",
              " (restoring the previous tunnel on '{0}' failed too — that end has no tunnel now; rebuild it)",
              tx_join("»، «", stuck, "', '"))


def api_edit_link(d):
    def edit(h):
        a, b = _link_nodes(d)
        try:
            with _PairLock(a, b, (d or {}).get("a_node"), (d or {}).get("b_node")):
                return _edit_link_impl(d, h)
        finally:
            _release_proxies(h["key"])

    return act_link(d, edit)


def api_edge_status(d):
    d = d or {}
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L:
        raise _no_tunnel()
    if L.get("type") != "core":
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


def _node_soft(r, fallback):
    return {"ok": False, "code": "node_offline" if r.get("offline") else "node_failed",
            "error": r.get("error") or r.get("msg") or fallback}


def _pool_kind(d, kinds):
    _require(d, ["id", "kind", "key"])
    if d["kind"] not in kinds:
        raise Bad("bad_kind", "kind باید {0} یا {1} باشد", "kind must be {0} or {1}", *kinds)


def _retest_now(d, resolve, kinds):
    d = d or {}
    _pool_kind(d, kinds)
    L, node = resolve(d)
    r = node_call(node, "retest-now", "POST",
                  {"name": L.get("name"), "kind": d["kind"], "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return _node_soft(r, tx("ناموفق بود", "failed"))
    return {"ok": True}


def api_pool_retest_now(d):
    return _retest_now(d, _ws_pool_client, ("ip", "sni"))


_SELECT_FAILED = tx("انتخاب ناموفق بود", "selecting failed")


def api_pool_select(d):
    d = d or {}
    _pool_kind(d, ("ip", "sni"))
    L, node = _ws_pool_client(d)
    r = node_call(node, "pool-select", "POST", {"name": L.get("name"), "kind": d["kind"], "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return _node_soft(r, _SELECT_FAILED)
    return {"ok": True}


def _pool_client(d, flag, missing):
    _require(d, ["id"])
    L = next((x for x in load_links() if x.get("id") == d["id"]), None)
    if not L or L.get("type") != "core" or not L.get(flag):
        raise missing
    node = _client_node(L)
    if not node:
        raise Bad("client_node_not_found", "نودِ کلاینت پیدا نشد", "the client node was not found")
    return L, node


def _ws_pool_client(d):
    return _pool_client(d, "ws_pool", Bad("no_edge_pool", "این لینک استخرِ لبه ندارد", "this link has no edge pool"))


def _peer_pool_client(d):
    return _pool_client(d, "ip_rotate", Bad("no_ip_pool", "این لینک استخرِ آی‌پی ندارد", "this link has no IP pool"))


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
    if not L:
        raise _no_tunnel()
    if L.get("type") != "core" or not L.get("ip_rotate"):
        return {"ok": True, "pool": False, "now": int(time.time()), "dst": dict(empty), "src": dict(empty)}
    node = _client_node(L)
    if not node:
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty),
                "error": _EV_END_MISSING["cli"]}
    r = node_call(node, "peer-status", "POST", {"name": L.get("name")}, timeout=10)
    if not r.get("ok"):
        return {"ok": True, "pool": True, "now": int(time.time()), "dst": dict(empty), "src": dict(empty), "error": r.get("error") or r.get("msg")}
    node_now = int(r.get("now") or 0)
    return {"ok": True, "pool": True, "now": node_now, "dst": _peer_sec_norm(r.get("dst")), "src": _peer_sec_norm(r.get("src"))}


def api_peer_retest_now(d):
    return _retest_now(d, _peer_pool_client, ("dst", "src"))


def api_peer_select(d):
    d = d or {}
    _require(d, ["id", "key"])
    side = "src" if str(d.get("side")) == "src" else "dst"
    L, node = _peer_pool_client(d)
    r = node_call(node, "peer-select", "POST", {"name": L.get("name"), "side": side, "key": str(d["key"])}, timeout=10)
    if not r.get("ok"):
        return _node_soft(r, _SELECT_FAILED)
    return {"ok": True}



EDIT_STEPS = 4


def _node_set(*nodes):
    out, seen = [], set()
    for n in nodes:
        if n and n["id"] not in seen:
            seen.add(n["id"])
            out.append(n)
    return out


def _drop_tunnel(node, name):
    if node_call(node, "delete", "POST", {"name": name}).get("ok"):
        _pending_remove(node["id"], name)
        return "done"
    try:
        return "queued" if _pending_add(node["id"], name) else "lost"
    except RegistryError as e:
        log_warn("pending", str(e))
        return "lost"


def _drop_tunnel_from(nodes, name):
    queued, lost = [], []
    for N in nodes:
        st = _drop_tunnel(N, name)
        if st == "queued":
            queued.append(N.get("name") or N["id"])
        elif st == "lost":
            lost.append(N.get("name") or N["id"])
    return _drop_tail(name, queued, lost)


_HALF_UNDONE = tx(" (تغییراتِ نیم‌کاره روی دو نود برچیده شد)", " (the half-done changes on both nodes were undone)")


def _drop_tail(name, queued, lost):
    parts = []
    if queued:
        parts.append(tx("، «{0}» روی «{1}» پاک نشد و در صفِ پاک‌سازی رفت "
                        "— به‌محضِ جواب‌دادنِ نود خودکار برداشته می‌شود",
                        ", '{0}' was not removed on '{1}' and went into the cleanup queue "
                        "— it is removed by itself as soon as the node answers",
                        name, tx_join("»، «", queued, "', '")))
    if lost:
        parts.append(tx("، هشدار: «{0}» روی «{1}» پاک نشد و در صفِ پاک‌سازی هم ثبت نشد "
                        "— دستی تمیزش کن",
                        ", warning: '{0}' was not removed on '{1}' and not queued for cleanup either "
                        "— clean it by hand",
                        name, tx_join("»، «", lost, "', '")))
    return tx_join("", parts) if parts else ""


def _guard_arrival_free(was_a, was_b, A, B, tid, names):
    stay = {n["id"] for n in (was_a, was_b) if n}
    for N in _node_set(A, B):
        if N["id"] in stay:
            continue
        lst = node_call(N, "list", "GET", timeout=30)
        if lst.get("configs") is None:
            raise Bad("node_list_failed", "فهرستِ تونل‌های نودِ «{0}» خوانده نشد (مشغول یا قطع) — "
                      "برای اینکه تونلِ دیگری روی آن پاک نشود متوقف شد",
                      "the tunnel list of node '{0}' could not be read (busy or down) — stopped so no other tunnel "
                      "on it gets deleted", N["name"])
        for c in (lst.get("configs") or []):
            if str(c.get("name") or "") in names or _sint(c.get("id")) == tid:
                raise Bad("tunnel_id_taken", "نودِ «{0}» از قبل تونلی با همین شناسه ({1}) دارد. "
                          "اگر مالِ همین تونل و از جابه‌جاییِ قبلی مانده، اول از روی آن نود "
                          "پاکش کن؛ وگرنه شناسه‌ها تداخل دارند",
                          "node '{0}' already has a tunnel with this id ({1}). If it belongs to this tunnel and is "
                          "left from an earlier move, delete it from that node first; otherwise the ids clash",
                          N["name"], tid)


def _undo_apply(was_a, was_b, A, B, name, renamed):
    stay = {n["id"] for n in (was_a, was_b) if n}
    return _drop_tunnel_from([N for N in _node_set(A, B) if renamed or N["id"] not in stay], name)


def _edit_link_impl(d, h):
    act_step(h, _STEP_READ, 0, EDIT_STEPS)
    _require(d, ["id", "type"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()
    ttype = _tunnel_type(d)
    was_a, was_b = get_node(L["a_node"]), get_node(L["b_node"])
    A = get_node(d["a_node"]) if str(d.get("a_node") or "").strip() else was_a
    B = get_node(d["b_node"]) if str(d.get("b_node") or "").strip() else was_b
    if not A or not B:
        raise Bad("node_not_found", "نودِ این تونل در پنل ثبت نیست — یکی از نودهای موجود را انتخاب کن",
                  "this tunnel's node is not registered in the panel — pick one of the existing nodes")
    _distinct_ends(A, B)
    moved = A["id"] != L["a_node"] or B["id"] != L["b_node"]
    pa, pb = _ping_both(A, B)
    tid = int(L["tunnel_id"])
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
    want_a, want_b = _want_ip(d, "a_ip", A, a_ips), _want_ip(d, "b_ip", B, b_ips)
    a_ip = (want_a if want_a in a_ips else
            (L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)))
    b_ip = (want_b if want_b in b_ips else
            (L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)))
    _guard_ends(A, B, a_ip, b_ip, ttype, exclude_id=L["id"])
    _subnet_prefix(d)
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
        port = (_int_in(d.get("port") or 0, 0, 65535, _bad_tunnel_port()) or (0 if _stale else L.get("port"))
                or free_tunnel_port(A, B, exclude_id=L["id"]))
        extra["port"] = port
    if ttype == "vxlan":
        _asked = "port" in d and not str(d.get("port") or "").strip()
        port = (_int_in(d.get("port") or 0, 0, 65535, _bad_tunnel_port())
                or (0 if _asked else (L.get("port") if L.get("type") == "vxlan" else 0)) or 4789)
        extra["port"] = port
    if ttype == "ipsec":
        extra["psk"] = L.get("psk") if (L.get("type") == "ipsec" and L.get("psk")) else secrets.token_hex(32)
    server_side = None
    if ttype == "core":
        ce, server_side = _core_extra(d, L, a_ip, b_ip, a_ips, b_ips)
        extra.update(ce)
        if extra.get("ech_proxy"):
            _hold_proxy(extra["ech_proxy_id"], h["key"])
    port_same = ("port" not in extra) or (extra["port"] == L.get("port"))
    if not moved and ttype != "core" and ttype == L["type"] and subnet == L["subnet"] and a_ip == L["a_ip"] and b_ip == L["b_ip"] and port_same:
        return {"ok": True, "name": old_name, "msg": tx("چیزی برای تغییر نبود", "nothing to change")}
    _guard_server_ports(ttype, extra, server_side, tid, A, B, a_ip, b_ip, L, _own_ports(L, was_a or A, was_b or B))
    if moved:
        _guard_arrival_free(was_a, was_b, A, B, tid, {old_name, new_name})
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
    touched = False
    try:
        if name_changed or type_changed or moved or ttype == "core":
            act_step(h, tx("برچیدنِ پیکربندیِ قبلی", "removing the old setup"), 1, EDIT_STEPS)
            touched = True
            gone = _drop_tunnel_from(_node_set(was_a, was_b, A, B), old_name)
            if gone:
                raise Bad("old_setup_stuck", "پیکربندیِ قبلیِ این تونل برچیده نشد، پس جابه‌جایی انجام نشد{0}",
                          "the old setup of this tunnel was not removed, so the move did not happen{0}", gone)
        act_step(h, tx("اعمال روی نودِ «{0}»", "applying on node '{0}'", A["name"]), 2, EDIT_STEPS)
        touched = True
        ra = _node_tunnel(A, a_body)
        if not ra.get("ok"):
            raise _node_failed(A, ra)
        act_step(h, tx("اعمال روی نودِ «{0}»", "applying on node '{0}'", B["name"]), 3, EDIT_STEPS, more=False)
        rb = _node_tunnel(B, b_body)
        if not rb.get("ok"):
            raise _node_failed(B, rb)
    except Exception as e:
        if touched:
            undone = _undo_apply(was_a, was_b, A, B, new_name, name_changed)
            stuck = _restore_link(was_a, was_b, L)
            if isinstance(e, ValueError):
                raise Bad(_code(e), tx("{0}{1}{2}", "{0}{1}{2}", _why(e), undone, _restore_tail(stuck))) from None
        raise
    act_step(h, tx("ثبتِ تغییر", "saving the change"), 3, EDIT_STEPS, stop=False)

    def apply(x):
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
    with _reg_lock:
        store_edit(_LINKS, L["id"], apply)
    _refresh_cache([L["a_node"], L["b_node"], A["id"], B["id"]])
    return {"ok": True, "name": new_name}


SPEED_SECS = 8
SPEED_STREAMS = 8


def api_link_speed(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()
    if L.get("enabled") is False:
        raise Bad("tunnel_off", "این تونل خاموش است — اول روشنش کن", "this tunnel is off — turn it on first")
    srv_is_a = L.get("server_side") != "b"
    srv = get_node(L["a_node"] if srv_is_a else L["b_node"])
    cli = get_node(L["b_node"] if srv_is_a else L["a_node"])
    if not srv or not cli:
        raise _no_node()
    secs, streams = SPEED_SECS, SPEED_STREAMS
    r = node_call(srv, "speedtest", "POST", {"name": L["name"], "mode": "serve", "secs": secs},
                  timeout=NODE_OP_TIMEOUT)
    if not r.get("ok"):
        raise Bad("speedtest_failed", "نودِ «{0}» گیرندهٔ تست را بالا نیاورد: {1}",
                  "node '{0}' did not start the test receiver: {1}", srv["name"], r.get("error") or r.get("msg") or "?")
    q = node_call(cli, "speedtest", "POST",
                  {"name": L["name"], "mode": "run", "peer_ip": r.get("ip"), "port": r.get("port"),
                   "secs": secs, "streams": streams}, timeout=secs * 2 + 60)
    if not q.get("ok"):
        raise Bad("speedtest_failed", "نودِ «{0}» تست را اجرا نکرد: {1}", "node '{0}' did not run the test: {1}",
                  cli["name"], q.get("error") or q.get("msg") or "?")
    return {"ok": True, "from": cli["name"], "to": srv["name"], "secs": secs,
            "up_streams": int(q.get("up_streams") or 0), "down_streams": int(q.get("down_streams") or 0),
            "up_mbit": q.get("up_mbit"), "down_mbit": q.get("down_mbit")}


def api_check_link(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()

    def chk(nid):
        n = get_node(nid)
        if not n:
            return {"online": False, "health": None}
        r = node_call(n, "check", "POST", {"name": L["name"]}, timeout=30)
        if r.get("ok"):
            return {"online": True, "health": r.get("health"), "error": ""}
        if r.get("offline"):
            return {"online": False, "health": None, "error": ""}
        return {"online": True, "health": None, "error": r.get("error") or r.get("msg") or ""}

    a, b = parallel_map(chk, [L["a_node"], L["b_node"]])
    return {"ok": True, "name": L["name"], "a_online": a["online"], "b_online": b["online"],
            "a_health": a["health"], "b_health": b["health"],
            "a_error": a["error"], "b_error": b["error"]}


def api_restart_link(d):
    def restart(h):
        a, b = _link_nodes(d)
        with _PairLock(a, b):
            return _restart_link_impl(d, h)

    return act_link(d, restart)


def _restart_link_impl(d, h):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()
    if L["type"] != "core":
        raise Bad("not_core", "فقط تونلِ هسته پروسه‌ای دارد که ری‌استارت شود", "only a core tunnel has a process to restart")
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise _ends_gone()
    ends, errs = [], []
    for i, (side, N) in enumerate((("a", A), ("b", B))):
        act_step(h, tx("ری‌استارتِ هسته روی نودِ «{0}»", "restarting the core on node '{0}'", N["name"]), i, 2,
                 stop=(i == 0), more=False)
        r = node_call(N, "core-restart", "POST", {"name": L["name"]}, timeout=30)
        ok = bool(r.get("ok"))
        ends.append({"side": side, "node": N["name"], "ok": ok})
        if not ok:
            errs.append(tx("{0}: {1}", "{0}: {1}", N["name"], r.get("error") or r.get("msg") or "?"))
    if errs:
        raise Bad("restart_failed", tx_join("؛ ", errs, "; "))
    return {"ok": True}


_rb_lock = threading.Lock()
_rb_last = {}
RB_KEEP = 900


def _rb_note(lid, ok, error=None):
    with _rb_lock:
        for k in [k for k, v in _rb_last.items() if time.time() - v["ts"] > RB_KEEP]:
            _rb_last.pop(k, None)
        _rb_last[lid] = {"ok": ok, "error": tx_cut(_why(error), 200) if error is not None else "", "ts": int(time.time())}


def rb_last(lid):
    with _rb_lock:
        v = _rb_last.get(lid)
        return dict(v) if v and time.time() - v["ts"] <= RB_KEEP else None


def _rebuild_job(d):
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

    return rebuild


def api_rebuild_link(d):
    return act_link(d, _rebuild_job(d))


REBUILD_STEPS = 4


def _rebuild_link_impl(d, h):
    act_step(h, _STEP_READ, 0, REBUILD_STEPS)
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()
    A, B = get_node(L["a_node"]), get_node(L["b_node"])
    if not A or not B:
        raise _ends_gone()
    pa, pb = _ping_both(A, B)
    tid, ttype, subnet, name = int(L["tunnel_id"]), L["type"], L["subnet"], L["name"]
    a_ips = _flat_ips(pa)
    b_ips = _flat_ips(pb)
    want_a, want_b = str(d.get("a_ip") or "").strip(), str(d.get("b_ip") or "").strip()
    a_ip = (want_a if want_a in a_ips else
            (L["a_ip"] if L["a_ip"] in a_ips else (a_ips[0] if a_ips else None)))
    b_ip = (want_b if want_b in b_ips else
            (L["b_ip"] if L["b_ip"] in b_ips else (b_ips[0] if b_ips else None)))
    _guard_ends(A, B, a_ip, b_ip, ttype, exclude_id=L["id"])
    src = L
    if ttype == "core" and L.get("ip_rotate"):
        src = dict(L, a_ip_pool=_pool_with(a_ip, L.get("a_ip_pool"), a_ips),
                   b_ip_pool=_pool_with(b_ip, L.get("b_ip_pool"), b_ips))
    _guard_server_ports(ttype, src, L.get("server_side"), tid, A, B, a_ip, b_ip, L, _own_ports(L, A, B))
    _guard_addr_on_another_iface(pa, pb, A, B, subnet, {name})
    extra = _tunnel_extra(L)
    a_body = {"type": ttype, "self_ip": a_ip, "peer_ip": b_ip, "subnet": subnet, "id": tid, "name": name,
              "host": overlay_host(ttype, L.get("server_side"), True), "enabled": L.get("enabled", True), **extra}
    b_body = {"type": ttype, "self_ip": b_ip, "peer_ip": a_ip, "subnet": subnet, "id": tid, "name": name,
              "host": overlay_host(ttype, L.get("server_side"), False), "enabled": L.get("enabled", True), **extra}
    if ttype == "core":
        a_body["role"], b_body["role"] = _core_role(L, A["id"]), _core_role(L, B["id"])
        _core_rotation_bodies(src, a_body, b_body, a_ips, b_ips)
        _core_workers_bodies(L, a_body, b_body)
        _apply_core_tuning(a_body, b_body)
    _apply_probe_tuning(a_body, b_body)
    act_step(h, tx("برچیدنِ هر دو سر", "removing both ends"), 1, REBUILD_STEPS)
    try:
        node_call(A, "delete", "POST", {"name": name})
        node_call(B, "delete", "POST", {"name": name})
        act_step(h, _step_build(A), 2, REBUILD_STEPS)
        ra = _node_tunnel(A, a_body)
        if not ra.get("ok"):
            raise _node_failed(A, ra)
        act_step(h, _step_build(B), 3, REBUILD_STEPS, more=False)
        rb = _node_tunnel(B, b_body)
        if not rb.get("ok"):
            raise _node_failed(B, rb)
    except Exception as e:
        stuck = _restore_link(A, B, L, extra)
        if isinstance(e, ValueError):
            raise Bad(_code(e), tx("{0}{1}", "{0}{1}", _why(e), _restore_tail(stuck))) from None
        raise
    moved = a_ip != L["a_ip"] or b_ip != L["b_ip"]
    if moved and bool(d.get("pin", True)):
        with _reg_lock:
            store_edit(_LINKS, L["id"], lambda x: x.update({"a_ip": a_ip, "b_ip": b_ip,
                       **{k: src[k] for k in ("a_ip_pool", "b_ip_pool") if src is not L}}))
        moved = False
    _set_drift(L["id"], moved)
    _refresh_cache([L["a_node"], L["b_node"]])
    return {"ok": True, "name": name}


CARD_TAGS = 6


def api_link_tag(d):
    _require(d, ["id"])
    tag = _int_in(d.get("tag") or 0, 0, CARD_TAGS, Bad("bad_tag", "رنگِ نشانه‌گذاری نامعتبر است", "invalid tag colour"))
    def paint(x):
        if tag:
            x["tag"] = tag
        else:
            x.pop("tag", None)
    with _reg_lock:
        coll = _LINKS if get_link(d["id"]) else _NODES
        if store_edit(coll, d["id"], paint) is None:
            raise _no_item()
    return {"ok": True, "tag": tag}


def _link_enable(N, L, enabled):
    return node_call(N, "link-enable", "POST", {"name": L["name"], "enabled": enabled}, timeout=NODE_OP_TIMEOUT)


def api_link_toggle(d):
    _require(d, ["id"])
    enabled = bool(d.get("enabled"))
    a, b = _link_nodes(d)
    if not a or not b:
        raise _no_tunnel()
    with _PairLock(a, b):
        L = next((x for x in load_links() if x["id"] == d["id"]), None)
        if not L:
            raise _no_tunnel()
        ends = [get_node(L["a_node"]), get_node(L["b_node"])]
        if not all(ends):
            raise _ends_gone()
        off = [N["name"] for N in ends if _known_offline(N)]
        if off:
            raise Bad("node_offline", "نودِ «{0}» در دسترس نیست — تونل روی هیچ سری عوض نشد",
                      "node '{0}' is unreachable — the tunnel changed on neither end", tx_join("»، «", off, "', '"))
        was = L.get("enabled") is not False
        done = []
        try:
            for N in ends:
                r = _link_enable(N, L, enabled)
                if not r.get("ok"):
                    why = tx("جواب نداد", "did not answer") if r.get("offline") else (
                        r.get("error") or r.get("msg") or _FAILED)
                    back = [M["name"] for M in done]
                    stuck = [M["name"] for M in done if not _link_enable(M, L, was).get("ok")]
                    if stuck:
                        tail = tx("؛ برگرداندنِ «{0}» هم نشد — آن سر روی حالتِ جدید مانده است",
                                  "; turning '{0}' back failed too — that end stays in the new state",
                                  tx_join("»، «", stuck, "', '"))
                    elif back:
                        tail = tx(" — «{0}» به حالتِ قبل برگشت", " — '{0}' went back to the old state",
                                  tx_join("»، «", back, "', '"))
                    else:
                        tail = tx(" — تونل عوض نشد", " — the tunnel did not change")
                    raise Bad("toggle_failed", "{0}: {1}{2}", "{0}: {1}{2}", N["name"], why, tail)
                done.append(N)
            with _reg_lock:
                store_edit(_LINKS, d["id"], lambda x: x.update(enabled=enabled))
        finally:
            _refresh_cache([L["a_node"], L["b_node"]])
    return {"ok": True, "enabled": enabled}


RECONCILE_GAP = 15
RECONCILE_RETRY = 60
_reconcile_last = {}


def _stray_rows(nodes, links):
    want = {}
    for L in links:
        for k in ("a_node", "b_node"):
            want.setdefault(L.get(k), set()).add(str(L.get("name") or ""))
    _store_ready()
    pend = _M.pending
    out = []
    for n in nodes:
        cfgs = _cached_list(n["id"]).get("configs")
        if cfgs is None:
            continue
        known = want.get(n["id"], set()) | set(pend.get(n["id"], ()))
        for c in cfgs:
            nm = str(c.get("name") or "")
            if nm and c.get("type") != "portfw" and nm not in known:
                out.append((n, nm))
    return out


_stray_lock = threading.Lock()
_stray_seen = {}
_stray_live = []
_STRAY_BODY = tx("این پیکربندی از یک ساخت یا جابه‌جاییِ نیمه‌کاره مانده و پنل هیچ رکوردی برایش ندارد؛ "
                 "تا وقتی هست، شناسه‌اش روی آن نود اشغال است. اگر لازمش نداری، از همان نود پاکش کن.",
                 "this setup is left from a half-done build or move and the panel has no record of it; "
                 "while it exists its id is taken on that node. If you do not need it, delete it on that node.")


def _stray_scan(nodes, links):
    fresh, live, told = {}, [], []
    with _stray_lock:
        for n, nm in _stray_rows(nodes, links):
            key = (n["id"], nm)
            if key not in _stray_seen:
                fresh[key] = False
                continue
            fresh[key] = True
            live.append((n.get("name") or n["id"], nm))
            if not _stray_seen[key]:
                told.append(live[-1])
        _stray_seen.clear()
        _stray_seen.update(fresh)
        _stray_live[:] = live
    for who, nm in told:
        log_event("warn", "link-stray",
                  tx("نودِ «{0}»: تونلِ «{1}» روی نود هست ولی در پنل ثبت نیست",
                     "node '{0}': tunnel '{1}' is on the node but not registered in the panel", who, nm), _STRAY_BODY)


def _stray_snapshot():
    with _stray_lock:
        return list(_stray_live)


def _reconcile_once():
    mode = get_settings().get("reconcile_mode", "alert")
    now = time.time()
    links = load_links()
    _stray_scan(load_nodes(), links)
    valid_ids = {L["id"] for L in links}
    for k in [k for k in _reconcile_last if k not in valid_ids]:
        _reconcile_last.pop(k, None)
    with _drift_lock:
        for k in [k for k in _drift if k not in valid_ids]:
            _drift.pop(k, None)
    todo = []
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
        todo.append(L["id"])
    for lid in todo:
        try:
            _rebuild_now(lid)
        except ValueError:
            pass
        _reconcile_last[lid] = time.time()


def reconcile_loop():
    last = time.monotonic()
    while True:
        time.sleep(1.0)
        try:
            gap = max(5, int(get_settings().get("reconcile_interval", RECONCILE_GAP) or RECONCILE_GAP))
        except Exception:
            gap = RECONCILE_GAP
        if time.monotonic() - last < gap:
            continue
        last = time.monotonic()
        try:
            _reconcile_once()
        except RegistryError as e:
            log_warn("reconcile", str(e))
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
    chmap = {}

    def apply(x):
        if degrade:
            if x.get("ws_ech"):
                x.pop("ws_ech", None)
            for s in (x.get("ws_edge_snis") or []):
                if isinstance(s, dict) and s.get("ech"):
                    s["ech"] = ""
        elif kind == "single":
            nk = updates.get(x.get("ws_host"), "")
            if nk and nk != x.get("ws_ech", ""):
                x["ws_ech"] = nk
                chmap[x.get("ws_host")] = nk
        else:
            for s in (x.get("ws_edge_snis") or []):
                if not isinstance(s, dict):
                    continue
                nk = updates.get(s.get("host"), "")
                if nk and nk != s.get("ech", ""):
                    s["ech"] = nk
                    chmap[s.get("host")] = nk
    with _reg_lock:
        before = get_link(lid)
        after = store_edit(_LINKS, lid, apply)
    return after is not before, chmap


def _ech_blank(lid, hosts):
    want = set(hosts)

    def apply(x):
        for s in (x.get("ws_edge_snis") or []):
            if isinstance(s, dict) and s.get("host") in want and s.get("ech"):
                s["ech"] = ""
    with _reg_lock:
        before = get_link(lid)
        after = store_edit(_LINKS, lid, apply)
    return after is not before


def _ech_keys_blank(L, kind, hosts):
    if kind == "single":
        return not str(L.get("ws_ech") or "").strip()
    return all(not str(s.get("ech") or "").strip()
               for s in (L.get("ws_edge_snis") or [])
               if isinstance(s, dict) and s.get("host") in hosts)


def _ech_safe_rebuild(lid):
    try:
        return _rebuild_now(lid, pin=get_settings().get("reconcile_mode") == "auto")
    except ValueError:
        return False


def _ech_refresh_once():
    try:
        mins_label = "%g" % float(get_settings().get("ech_refresh_mins", 15) or 15)
    except Exception:
        mins_label = "15"
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
        try:
            _ech_refresh_link(L, hk[0], hk[1], mins_label)
        except Exception:
            log_internal("ech refresh %s" % L.get("name"))


ECH_NOTE_GAP = 3600
_ech_note_lock = threading.Lock()
_ech_unknown_warned = {}


def _ech_unknown_note(lid, nm, hosts):
    with _ech_note_lock:
        if not _gate(_ech_unknown_warned, str(lid), ECH_NOTE_GAP, WARN_MAX_KEYS):
            return
    log_event("warn", "ech-stale", tx("تونلِ «{0}»: کلیدِ ECH بررسی نشد", "tunnel '{0}': the ECH key was not checked", nm),
              tx_join(chr(10), [tx("دامنه‌ها: {0}", "domains: {0}", hosts), _ech_why(None),
                                tx("تا وقتی معلوم نشود، پنل نه کلید را دور می‌ریزد نه تونل را بازمی‌سازد",
                                   "until it is known, the panel neither drops the key nor rebuilds the tunnel")]))


def _ech_rows(chmap):
    return tx_join(chr(10), [tx("دامنه: {0}\nکلیدِ ECH: {1}", "domain: {0}\nECH key: {1}", h, k) for h, k in chmap.items()])


def _ech_down_why(down):
    return tx("قطع بود", "it was down") if down else tx("همهٔ لبه‌هایش سرِ ECH می‌سوختند", "all its edges were burning on ECH")


def _ech_flush(lid, notes):
    if not notes:
        return None
    ok = _ech_safe_rebuild(lid)
    for kind, title, level, ok_body, bad_body in notes:
        log_event(level if ok else "bad", kind, title, ok_body if ok else bad_body)
    return ok


def _ech_refresh_link(L, kind, hosts, mins_label):
    lid, nm = L.get("id"), L.get("name")
    ech_map = _fetch_ech_map(hosts, _ech_px(L))
    updates, gone, unknown = {}, [], []
    for h in hosts:
        nk = ech_map.get(h, "")
        key = (lid, h)
        if nk:
            with _ech_empty_lock:
                _ech_empty.pop(key, None)
            updates[h] = nk
        elif nk is None:
            unknown.append(h)
        else:
            with _ech_empty_lock:
                _ech_empty[key] = _ech_empty.get(key, 0) + 1
                if _ech_empty[key] >= _ECH_EMPTY_CYCLES:
                    gone.append(h)
    if unknown:
        _ech_unknown_note(lid, nm, unknown)
    notes = []
    removed = bool(hosts) and len(gone) == len(hosts)
    blank_before = _ech_keys_blank(L, kind, set(hosts))
    if removed:
        if _ech_write(lid, kind, {}, degrade=True)[0]:
            notes.append(("ech-gone", tx("تونلِ «{0}»: حذفِ رکوردِ ECH", "tunnel '{0}': ECH record removed", nm), "warn",
                          tx("کلید از DNS ناپدید شد؛ تونل فعلاً بدون ECH بازسازی شد. تنظیمِ ECH همچنان روشن است و "
                             "پنل هر {0} دقیقه دوباره امتحان می‌کند — به‌محضِ برگشتنِ رکورد خودش برمی‌گردد",
                             "the key vanished from DNS; the tunnel was rebuilt without ECH for now. ECH stays on and "
                             "the panel retries every {0} minutes — it comes back by itself as soon as the record returns",
                             mins_label),
                          tx("تنزل به wss ساده شد ولی بازسازی شکست خورد — تونل هنوز قطع است",
                             "it fell back to plain wss but the rebuild failed — the tunnel is still down")))
        _ech_flush(lid, notes)
        return
    if gone and _ech_blank(lid, gone):
        notes.append(("ech-gone", tx("تونلِ «{0}»: حذفِ رکوردِ ECH روی بخشی از استخر",
                                     "tunnel '{0}': ECH record removed on part of the pool", nm), "warn",
                      tx("رکوردِ ECH {0} از DNS ناپدید شده؛ همان دامنه‌ها بدون ECH بازسازی شدند و "
                         "بقیهٔ استخر دست‌نخورده ماند. پنل هر {1} دقیقه دوباره امتحان می‌کند",
                         "the ECH record of {0} vanished from DNS; those domains were rebuilt without ECH and "
                         "the rest of the pool was left alone. The panel retries every {1} minutes", gone, mins_label),
                      tx("کلیدِ کهنهٔ {0} پاک شد ولی بازسازی شکست خورد — رفتن روی آن دامنه‌ها هنوز می‌میرد",
                         "the stale key of {0} was cleared but the rebuild failed — moving onto those domains still dies", gone)))
    changed, chmap = _ech_write(lid, kind, updates, degrade=False)
    if changed and chmap and blank_before:
        notes.append(("ech-back", tx("تونلِ «{0}»: بازگشتِ ECH", "tunnel '{0}': ECH is back", nm), "ok",
                      tx("رکوردِ ECH دوباره منتشر شد؛ تونل با کلیدِ تازه بازسازی شد",
                         "the ECH record was published again; the tunnel was rebuilt with the new key"),
                      tx("رکوردِ ECH برگشت ولی بازسازی شکست خورد — تونل هنوز بدون ECH است",
                         "the ECH record is back but the rebuild failed — the tunnel is still without ECH")))
    if changed and chmap:
        tried, pushed = _ech_live_push(lid, chmap)
        dfa = _ech_rows(chmap)
        if pushed:
            log_event("ok", "ech-refresh",
                      tx("کلیدِ ECH تونلِ «{0}» تازه شد و بی‌بازسازی به هسته رسید (هر {1} دقیقه)",
                         "the ECH key of tunnel '{0}' was refreshed and reached the core without a rebuild (every {1} minutes)",
                         nm, mins_label),
                      tx("{0}\nنودِ مقصد: {1}", "{0}\ntarget node: {1}", dfa, pushed))
        elif tried:
            notes.append(("ech-refresh", tx("کلیدِ ECH تونلِ «{0}» تازه شد ولی بی‌بازسازی به هسته نرسید",
                                            "the ECH key of tunnel '{0}' was refreshed but did not reach the core without a rebuild",
                                            nm), "warn",
                          tx("{0}\nنود جواب نداد؛ تونل با کلیدِ تازه بازسازی شد",
                             "{0}\nthe node did not answer; the tunnel was rebuilt with the new key", dfa),
                          tx("{0}\nنه رساندنِ بی‌بازسازی جواب داد نه بازسازی — هسته هنوز کلیدِ کهنه دارد",
                             "{0}\nneither the live push nor the rebuild worked — the core still has the old key", dfa)))
        else:
            log_event("ok", "ech-refresh",
                      tx("کلیدِ ECH تونلِ «{0}» با تایمرِ زمان‌بندی‌شده تازه شد (هر {1} دقیقه)",
                         "the ECH key of tunnel '{0}' was refreshed by the scheduled timer (every {1} minutes)",
                         nm, mins_label), dfa)
    _reachable, down, stalled = _ech_pool_state(lid) if kind == "pool" else (False, False, False)
    mark = kind == "pool" and (down or stalled) and (lid not in _ech_down_rebuilt or changed)
    if mark:
        why = _ech_down_why(down)
        notes.append(("ech-rotate", tx("تونلِ «{0}»: چرخشِ کلیدِ ECH", "tunnel '{0}': ECH key rotation", nm), "ok",
                      tx("{0}؛ با کلیدِ تازه بازسازی شد", "{0}; rebuilt with the new key", why),
                      tx("{0}؛ بازسازی با کلیدِ تازه شکست خورد — تونل هنوز قطع است",
                         "{0}; the rebuild with the new key failed — the tunnel is still down", why)))
    ok = _ech_flush(lid, notes)
    if mark and ok:
        _ech_down_rebuilt.add(lid)
    elif not (kind == "pool" and (down or stalled)):
        _ech_down_rebuilt.discard(lid)


def _ech_heal_once():
    for L in load_links():
        hk = _ech_link_hosts(L)
        if not hk or hk[0] != "pool":
            continue
        try:
            _ech_heal_link(L, hk[0], hk[1])
        except Exception:
            log_internal("ech heal %s" % L.get("name"))


def _ech_heal_link(L, kind, hosts):
    lid, nm = L.get("id"), L.get("name")
    _reachable, down, stalled = _ech_pool_state(lid)
    if not (down or stalled):
        _ech_down_rebuilt.discard(lid)
        return
    if lid in _ech_down_rebuilt:
        return
    updates = {h: k for h, k in _fetch_ech_map(hosts, _ech_px(L)).items() if k}
    _ech_write(lid, kind, updates, degrade=False)
    _ech_down_rebuilt.add(lid)
    why = _ech_down_why(down)
    title = tx("تونلِ «{0}»: بازسازیِ سریعِ ECH", "tunnel '{0}': quick ECH rebuild", nm)
    if _ech_safe_rebuild(lid):
        log_event("ok", "ech-rebuild", title, why)
    else:
        log_event("bad", "ech-rebuild", title, tx("{0}؛ شکست خورد — تونل هنوز قطع است", "{0}; failed — the tunnel is still down", why))
        _ech_down_rebuilt.discard(lid)


def _ech_ingest_selfheal():
    live_ids = set()
    for L in load_links():
        hk = _ech_link_hosts(L)
        if not hk:
            continue
        live_ids.add(L.get("id"))
        try:
            _ech_ingest_link(L, hk[0], hk[1])
        except Exception:
            log_internal("ech self-heal %s" % L.get("name"))
    for dead in [k for k in _ech_healed_seq if k not in live_ids]:
        _ech_healed_seq.pop(dead, None)


def _ech_ingest_link(L, kind, hosts):
    lid, nm = L.get("id"), L.get("name")
    try:
        st = api_edge_status({"id": lid})
    except Exception:
        return
    if not st.get("ok") or st.get("error"):
        return
    hostset = set(hosts)
    clean = _core_event_marks(st.get("events"))
    seen = _ech_healed_seq.get(lid, (0, 0))
    latest = {}
    for at, e in clean:
        if at <= seen or str(e.get("kind")) != "ech" or str(e.get("code")) != "self_heal":
            continue
        parts = str(e.get("detail") or "").split(" ", 1)
        if len(parts) != 2:
            continue
        host, b64 = parts[0], parts[1].strip()
        if host in hostset and b64 and len(b64) <= 4096 and re.match(r"^[A-Za-z0-9+/=]+$", b64):
            latest[host] = (at, b64)
    if clean:
        _ech_healed_seq[lid] = max(seen, clean[-1][0])
    if not latest:
        return
    changed, chmap = _ech_write(lid, kind, {h: v[1] for h, v in latest.items()}, degrade=False)
    if changed and chmap:
        log_event("ok", "ech-saved",
                  tx("کلیدِ ECH خودترمیمِ هستهٔ تونلِ «{0}» در پنل ذخیره شد؛ بازسازیِ بعدی دیگر به کلیدِ کهنه برنمی‌گردد",
                     "the self-healed ECH key of tunnel '{0}' was saved in the panel; the next rebuild no longer goes back to the old key",
                     nm), _ech_rows(chmap))


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


EVENTS_TTL = 24 * 3600
K_EVENTS = "tnl:events"
EV_BATCH = 500

EV_GROUPS = (("tunnel", tx("تونل", "tunnel")), ("node", tx("نود", "node")), ("rot", tx("چرخش و استخر", "rotation and pools")),
             ("ech", tx("ECH", "ECH")), ("cfg", tx("تنظیم", "settings")), ("auth", tx("ورود", "login")), ("api", tx("API", "API")))
EV_TYPES = (
    ("link-up", "tunnel", tx("تونل وصل شد", "tunnel up")),
    ("link-down", "tunnel", tx("تونل قطع شد", "tunnel down")),
    ("link-reconnect", "tunnel", tx("تونل خودش دوباره وصل شد", "tunnel reconnected by itself")),
    ("link-stray", "tunnel", tx("تونلی روی نود که در پنل ثبت نیست", "tunnel on a node that is not registered")),
    ("node-up", "node", tx("نود آنلاین شد", "node online")),
    ("node-down", "node", tx("نود آفلاین شد", "node offline")),
    ("node-moved", "node", tx("نشانیِ نود جابه‌جا شد", "node address moved")),
    ("rot-due", "rot", tx("چرخش طبقِ زمان‌بندی", "scheduled rotation")),
    ("rot-forced", "rot", tx("چرخشِ اجباری — مسیر جواب نداد", "forced rotation — the path did not answer")),
    ("rehandshake", "rot", tx("دست‌دادنِ دوباره، پیش از سوزاندن", "rehandshake before burning")),
    ("port-roll", "rot", tx("برگشت با چرخشِ پورتِ مبدأ", "recovered by a source-port roll")),
    ("ladder-revive", "rot", tx("ازسرگیریِ نردبان", "ladder revived")),
    ("burn", "rot", tx("سوختنِ آدرس", "address burned")),
    ("heal", "rot", tx("برگشتِ آدرس به فهرستِ سالم", "address back on the healthy list")),
    ("ech-heal", "ech", tx("ترمیمِ خودکارِ کلیدِ ECH در هسته", "ECH key self-heal in the core")),
    ("ech-gone", "ech", tx("حذفِ رکوردِ ECH از DNS", "ECH record removed from DNS")),
    ("ech-back", "ech", tx("بازگشتِ رکوردِ ECH", "ECH record back")),
    ("ech-refresh", "ech", tx("تازه‌شدنِ کلیدِ ECH", "ECH key refreshed")),
    ("ech-rotate", "ech", tx("چرخشِ کلیدِ ECH", "ECH key rotation")),
    ("ech-stale", "ech", tx("کلیدِ ECH تازه خوانده نشد", "ECH key not read fresh")),
    ("ech-rebuild", "ech", tx("بازسازیِ سریعِ ECH", "quick ECH rebuild")),
    ("ech-saved", "ech", tx("ذخیرهٔ کلیدِ خودترمیمِ هسته", "self-healed core key saved")),
    ("cfg-clamped", "cfg", tx("تنظیمی که کامل اعمال نشد", "setting not fully applied")),
    ("auth-fail", "auth", tx("تلاشِ ناموفقِ ورود", "failed login")),
    ("auth-lock", "auth", tx("قفلِ نشانی پس از تلاشِ زیاد", "address locked after many tries")),
    ("api-refused", "api", tx("درخواستِ ردشدهٔ API", "refused API request")),
    ("api-error", "api", tx("درخواستِ API با خطا", "API request with an error")),
    ("api-lock", "api", tx("قفلِ نشانی پس از توکنِ غلطِ زیاد", "address locked after many wrong tokens")),
)
EV_TYPE_GROUP = {t: g for t, g, _label in EV_TYPES}
_events_lock = threading.Lock()
_ev_list = None
_ev_last = (0, 0)
_ev_out = []
_ev_wake = threading.Event()
_ev_saved = [0.0]
_ev_state = {"init": False, "nodes": {}, "held": [], "links": {}, "evseq": {}, "rotip": {},
             "links_coarse_down": set(), "coarse_hold": {}, "core_down": {}}


def _ev_ip(detail):
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?", str(detail or ""))
    return m.group(0) if m else ""
def _ev_value(detail):
    tag, _, rest = str(detail or "").partition(":")
    return rest.strip() if tag in ("ip", "sni") and rest.strip() else ""



_LINK_LOST = tx("اتصال قطع شد", "connection lost")
_EV_DOWN_CODE = {
    "ping_timeout": tx("بی‌پاسخ ماند (keepalive) — گلوگاه/بلاک‌هول یا سرِ مقابل خاموش",
                       "no answer (keepalive) — a bottleneck or black hole, or the other end is off"),
    "reset": tx("اتصال ریست شد (RST — احتمالاً کشتنِ DPI)", "connection reset (RST — probably a DPI kill)"),
    "refused": tx("اتصال رد شد", "connection refused"),
    "timeout": tx("مهلتِ اتصال تمام شد / بی‌مسیر", "connection timed out / no route"),
    "eof": tx("اتصال بسته شد (EOF)", "connection closed (EOF)"),
    "tls": tx("دستِ TLS شکست خورد (احتمالاً SNI بلاک شده)", "TLS handshake failed (the SNI is probably blocked)"),
    "ws_upgrade": tx("ارتقاءِ WebSocket رد شد (Origin/CDN)", "WebSocket upgrade refused (Origin/CDN)"),
    "closed": _LINK_LOST,
    "dropped": _LINK_LOST,
}
_ANY_IP = tx("آی‌پی", "IP")
_HEAL_AXIS = {"dst": tx("آی‌پیِ مقصد", "destination IP"), "src": tx("آی‌پیِ مبدأ", "source IP"),
              "ip": tx("آی‌پیِ لبه", "edge IP"), "sni": tx("دامنهٔ SNI", "SNI domain")}

_EV_UP_CODE = {
    "reconnect": tx("پس از افتِ سشن، خودکار وصل شد", "reconnected by itself after the session dropped"),
}
_EV_ROT_AXIS = {
    "peer-rotate": ("dst", tx("چرخش آی‌پیِ مقصد", "destination IP rotation")),
    "src-rotate":  ("src", tx("چرخش آی‌پیِ مبدأ", "source IP rotation")),
    "edge-rotate": ("ip",  tx("چرخش لبهٔ CDN", "CDN edge rotation")),
    "sni-rotate":  ("sni", tx("چرخش دامنه", "domain rotation")),
}
_EV_ROT_CODE = {
    "rehandshake": ("warn", tx("دست‌دادنِ دوباره، پیش از سوزاندنِ هر آدرسی", "rehandshake before burning any address")),
    "port-roll": ("ok", tx("با چرخشِ پورتِ مبدأ برگشت", "recovered by a source-port roll")),
    "ladder-revive": ("warn", tx("ازسرگیریِ نردبان پس از بن‌بست", "ladder revived after a dead end")),
}


def _ev_rot(kind, code):
    if kind not in ("down", "rot"):
        return None
    ax = _EV_ROT_AXIS.get(code)
    if ax is None:
        lvl = _EV_ROT_CODE.get(code) if kind == "down" else None
        return (lvl[0], lvl[1], "", code) if lvl else None
    axis, label = ax
    if kind == "rot":
        return ("ok", tx("{0} — طبقِ زمان‌بندی", "{0} — on schedule", label), axis, "rot-due")
    return ("warn", tx("{0} — اجباری: مسیر جواب نداد", "{0} — forced: the path did not answer", label), axis, "rot-forced")


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
        return tx("از: {0}\nبه: {1}", "from: {0}\nto: {1}", pair(prev), pair(cur))
    return tx("به: {0}", "to: {0}", pair(cur))


def _mib(b):
    try:
        n = int(b)
    except (TypeError, ValueError):
        return str(b)
    if n >= 1 << 20:
        return tx("{0:.1f} مگابایت", "{0:.1f} MB", n / float(1 << 20))
    if n >= 1 << 10:
        return tx("{0:.0f} کیلوبایت", "{0:.0f} KB", n / float(1 << 10))
    return tx("{0} بایت", "{0} bytes", n)


def _down_title(nm):
    return tx("تونلِ «{0}»: قطع شد", "tunnel '{0}': down", nm)


def _ev_core_text(kind, code, detail, nm):
    raw = str(detail or "")
    axis, sep, rest = raw.partition(":")
    key = rest if sep and axis in ("dst", "src", "ip", "sni") else raw
    if kind == "down":
        rf = _EV_DOWN_CODE.get(code, _LINK_LOST)
        return ("bad", "link-down", _down_title(nm), rf)
    if kind == "up":
        rf = _EV_UP_CODE.get(code, tx("تونل وصل شد", "tunnel up"))
        return ("ok", "link-reconnect", tx("تونلِ «{0}»: وصلِ مجدد", "tunnel '{0}': reconnected", nm), rf)
    if kind == "burn":
        what = _HEAL_AXIS.get(str(detail or "").split(":", 1)[0], _ANY_IP)
        return ("warn", "burn", tx("تونلِ «{0}»: سوختنِ {1}", "tunnel '{0}': {1} burned", nm, what),
                tx("{0}: {1}", "{0}: {1}", what, key))
    if kind == "cfg":
        if code == "sockbuf-clamped":
            parts = key.split()
            title = tx("تونلِ «{0}»: بافرِ سوکت به‌اندازه‌ای که خواستی اعمال نشد",
                       "tunnel '{0}': the socket buffer was not applied at the size you asked for", nm)
            if len(parts) == 3 and parts[0] == "send":
                return ("warn", "cfg-clamped", title,
                        tx("بافرِ ارسال: {0} خواسته شد، {1} اعمال شد\n"
                           "چاره: net.core.wmem_max را روی آن نود بالا ببر، یا CAP_NET_ADMIN به سرویس بده",
                           "send buffer: {0} asked, {1} applied\n"
                           "fix: raise net.core.wmem_max on that node, or give the service CAP_NET_ADMIN",
                           _mib(parts[1]), _mib(parts[2])))
            if len(parts) == 3:
                return ("warn", "cfg-clamped", title,
                        tx("بافرِ دریافت: {0} خواسته شد، {1} اعمال شد\n"
                           "چاره: net.core.rmem_max را روی آن نود بالا ببر، یا CAP_NET_ADMIN به سرویس بده",
                           "receive buffer: {0} asked, {1} applied\n"
                           "fix: raise net.core.rmem_max on that node, or give the service CAP_NET_ADMIN",
                           _mib(parts[1]), _mib(parts[2])))
        return ("warn", "cfg-clamped", tx("تونلِ «{0}»: یک تنظیم آن‌طور که خواسته شد اعمال نشد",
                                          "tunnel '{0}': a setting was not applied as asked", nm),
                tx("جزئیات: {0}", "details: {0}", key))
    if kind == "heal":
        if code == "tun-probe":
            what = _HEAL_AXIS.get(str(detail or "").split(":", 1)[0], _ANY_IP)
            return ("ok", "heal", tx("تونلِ «{0}»: بازگشتِ {1}", "tunnel '{0}': {1} is back", nm, what),
                    tx("{0}\nپروبِ نود دید ترافیک واقعاً از این مسیر رد می‌شود",
                       "{0}\nthe node's probe saw traffic really pass on this path", key))
    if kind == "ech":
        host, _, k = key.partition(" ")
        rows = []
        if host:
            rows.append(tx("دامنه: {0}\n", "domain: {0}\n", host))
        if k:
            rows.append(tx("کلیدِ تازهٔ ECH: {0}", "new ECH key: {0}", k))
        return ("ok", "ech-heal", tx("تونلِ «{0}»: ترمیمِ خودکارِ کلیدِ ECH", "tunnel '{0}': ECH key self-heal", nm),
                tx_join("", rows))
    return None


def _core_event_marks(events):
    return sorted((((_sint(e.get("ts")), _sint(e.get("seq"))), e)
                   for e in (events if isinstance(events, list) else []) if isinstance(e, dict)),
                  key=lambda x: x[0])


def _ingest_core_events(lid, end, nm, events):
    key = lid + "|" + end
    clean = _core_event_marks(events)
    newest = clean[-1][0] if clean else (0, 0)
    last = _ev_state["evseq"].get(key, (0, 0))
    if last is None:
        _ev_state["evseq"][key] = newest
        return
    for at, e in clean:
        if at <= last:
            continue
        ts = at[0] or None
        ekind, ecode, edet = str(e.get("kind") or ""), str(e.get("code") or ""), str(e.get("detail") or "")
        if ekind == "down":
            _ev_state["core_down"][lid] = time.time()
        rot = _ev_rot(ekind, ecode)
        if rot and end == "cli" and ecode == "port-roll":
            kv = dict(w.split(":", 1) for w in edet.split() if ":" in w)
            tries, sport = kv.get("tries"), kv.get("sport")
            log_event(rot[0], rot[3], tx("تونلِ «{0}»: با چرخشِ پورتِ مبدأ{1}{2} برگشت",
                                         "tunnel '{0}': recovered by a source-port roll{1}{2}", nm,
                                         tx(" پس از {0} تلاش", " after {0} tries", tries) if tries else "",
                                         tx("، با پورتِ {0}", ", on port {0}", sport) if sport else ""), ts=ts)
            continue
        if rot:
            detail = ""
            if end == "cli" and rot[2]:
                axis = rot[2]
                val = _ev_value(edet) or _ev_ip(edet)
                rk = lid + ":" + axis
                prev = _ev_state["rotip"].get(rk)
                if val:
                    _ev_state["rotip"][rk] = val
                other = _ev_state["rotip"].get(lid + ":" + _ROT_PARTNER[axis]) or ""
                detail = _rot_pair(axis, prev, val, other)
            log_event(rot[0], rot[3], tx("تونلِ «{0}»: {1}", "tunnel '{0}': {1}", nm, rot[1]), detail, ts=ts)
            continue
        txt = _ev_core_text(ekind, ecode, edet, nm)
        if txt:
            log_event(txt[0], txt[1], txt[2], txt[3], ts=ts)
    _ev_state["evseq"][key] = max(last, newest)


def _ev_key(s):
    a, _, b = str(s or "").partition("-")
    try:
        return int(a), int(b or 0)
    except ValueError:
        return 0, 0


def _ev_next_id():
    global _ev_last
    ms = int(time.time() * 1000)
    last_ms, last_n = _ev_last
    _ev_last = (ms, 0) if ms > last_ms else (last_ms, last_n + 1)
    return "%d-%d" % _ev_last


def _ev_boot():
    global _ev_last
    r = _redis()
    p = r.pipeline(transaction=True)
    p.exists(K_EVENTS)
    p.xrange(K_EVENTS, "-", "+")
    there, rows = p.execute()
    last = (int(time.time() * 1000), 0)
    if there:
        last = max(last, _ev_key(r.xinfo_stream(K_EVENTS)["last-generated-id"]))
    out = [{"ts": _sint(f.get("ts")), "id": eid, "level": f.get("level", ""), "kind": f.get("kind", ""),
            "text": Tx(f.get("fa", ""), f.get("en", "")), "detail": Tx(f.get("dfa", ""), f.get("den", ""))}
           for eid, f in rows]
    _ev_last = last
    out = _ev_prune(out)
    out.sort(key=lambda e: (e["ts"], _ev_key(e["id"])), reverse=True)
    return out


def events_boot():
    global _ev_list
    with _events_lock:
        _ev_list = _ev_boot()


def _ev_all():
    global _ev_list, _ev_last
    if _ev_list is None:
        try:
            _ev_list = _ev_boot()
        except Exception as e:
            log_warn("events", _store_msg(e))
            _ev_list, _ev_last = [], (int(time.time() * 1000), 0)
    return _ev_list


def load_events():
    with _events_lock:
        return list(_ev_all())


def _ev_batch():
    with _events_lock:
        batch = []
        for op in _ev_out[:EV_BATCH]:
            batch.append(op)
            if op[0] == "clear":
                break
        return batch


def _ev_drain():
    batch = _ev_batch()
    if not batch:
        return True
    cut = (int(time.time()) - EVENTS_TTL) * 1000
    p = _redis().pipeline(transaction=True)
    for op in batch:
        if op[0] == "add":
            e = op[1]
            f = {"ts": e["ts"], "level": e["level"], "kind": e["kind"], "fa": str(e["text"]), "en": e["text"].en,
                 "dfa": str(e["detail"]), "den": e["detail"].en}
            p.xadd(K_EVENTS, f, id=e["id"], minid=cut, approximate=True)
        elif op[0] == "clear":
            p.xtrim(K_EVENTS, maxlen=0, approximate=False)
        else:
            p.xtrim(K_EVENTS, minid=cut, approximate=True)
    try:
        res = p.execute(raise_on_error=False)
    except Exception as e:
        log_warn("events", _store_msg(e))
        return False
    for op, r in zip(batch, res):
        if isinstance(r, Exception) and not (op[0] == "add" and "equal or smaller" in str(r)):
            log_warn("events", "events were not saved in Redis: %s" % _en(_store_why(r)))
            return False
    with _events_lock:
        del _ev_out[:len(batch)]
    _ev_saved[0] = time.time()
    return True


def _ev_writer_loop():
    while True:
        _ev_wake.wait(1.0)
        _ev_wake.clear()
        try:
            while _ev_out and _ev_drain():
                pass
        except Exception:
            log_internal("event writer")


def _ev_badge(seen):
    hidden = _ev_hidden()
    mark = _ev_key(seen)
    total = unread = 0
    newest = (0, 0)
    with _events_lock:
        for e in _ev_all():
            if e.get("kind") in hidden:
                continue
            total += 1
            k = _ev_key(e["id"])
            if k > newest:
                newest = k
            if k > mark:
                unread += 1
    return total, "%d-%d" % newest, unread


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
    global _ev_list
    with _events_lock:
        before = len(_ev_all())
        _ev_list = _ev_prune(_ev_list)
        if not _ev_out or _ev_out[-1][0] != "trim":
            _ev_out.append(("trim",))
    _ev_wake.set()
    return before - len(_ev_list)


def log_event(level, kind, text, detail="", ts=None):
    now = int(time.time())
    at = min(int(ts), now) if ts else now
    with _events_lock:
        lst = _ev_all()
        e = {"ts": at, "id": _ev_next_id(), "level": level, "kind": kind,
             "text": Tx(str(text), str(_en(text))), "detail": Tx(str(detail), str(_en(detail)))}
        pos = next((i for i, x in enumerate(lst) if _sint(x.get("ts")) <= at), len(lst))
        lst.insert(pos, e)
        if at >= now - EVENTS_TTL:
            _ev_out.append(("add", e))
    _ev_wake.set()


def _link_mark(L):
    seen, blind = [], []
    for k in ("a_node", "b_node"):
        m = (_cache_get(L[k]) or {}).get("marks")
        if not m:
            continue
        if not m["seen"][0]:
            blind.append(m["seen"][1])
            continue
        seen.append(m["tun"].get(L["name"]) or (False, m["seen"][1]))
    if not seen or any(ok is None for ok, _ in seen):
        return None, None
    if all(ok for ok, _ in seen):
        return True, max([at for _, at in seen] + blind)
    return False, min(at for ok, at in seen if not ok)


def _link_blind(L):
    return [k for k in ("a_node", "b_node") if not _link_side_health(L, k)[1]]


def _link_down_reason(L, nmap, silent=False):
    blind = _link_blind(L)
    if blind:
        seen = "b_node" if blind[0] == "a_node" else "a_node"
        return tx("فقط سرِ «{0}» دیده می‌شود و تونل را قطع می‌بیند؛ سرِ «{1}» از پنل در دسترس نیست",
                  "only end '{0}' is visible and sees the tunnel down; end '{1}' is unreachable from the panel",
                  nmap.get(L.get(seen), ""), nmap.get(L.get(blind[0]), ""))
    if link_drift(L["id"]):
        return tx("IP عوض شده — نیازمندِ بازسازی", "the IP changed — needs a rebuild")
    if silent:
        return tx("هستهٔ تونل از این قطعی هیچ گزارشی نداد — احتمالاً هستهٔ یک سر از کار افتاده",
                  "the tunnel core reported nothing about this outage — the core on one end probably died")
    return tx("قابلِ دسترسی نیست (کریر/سرِ مقابل)", "unreachable (carrier / other end)")


def _ev_flip(store, key, state, since, first):
    prev = store.get(key)
    if prev and prev[0] == state:
        return None, prev
    at = max(since, prev[1]) if prev else since
    store[key] = (state, at, bool(prev) and not first)
    return (at if prev and not first else None), prev


def _fa_span(secs):
    s = max(1, int(round(secs)))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = [tx("{0} {1}", "{0} {1}", v, unit) for v, unit in
             ((d, tx("روز", "d")), (h, tx("ساعت", "h")), (m, tx("دقیقه", "min")), (s, tx("ثانیه", "s"))) if v]
    return tx_join(" و ", parts[:2], " and ")


def _name_key(name):
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r"(\d+)", name)]


def _ev_clusters(items, key):
    out = []
    for it in sorted(items, key=lambda h: h[key]):
        if out and it[key] - out[-1][0][key] <= NODE_GROUP_SECS:
            out[-1].append(it)
        else:
            out.append([it])
    return out


def _node_path_rows(nodes, members, t0):
    st = _ev_state["nodes"]
    rows = []
    for key, behind in ((tx("مستقیم", "direct"), False), (tx("پشتِ پروکسی", "behind a proxy"), True)):
        others = [n["id"] for n in nodes if n["id"] not in members and n["id"] in st
                  and bool(n.get("proxy_on")) == behind
                  and not (st[n["id"]][0] is False and (st[n["id"]][1] < t0 or not st[n["id"]][2]))]
        if others:
            up = sum(1 for nid in others if st[nid][0])
            rows.append(tx("{0}: {1} از {2} آنلاین ماندند", "{0}: {1} of {2} stayed online", key, up, len(others)))
    return rows


def _names_row(names, members):
    return tx("نودها: {0}", "nodes: {0}", sorted((names[nid] for nid in members), key=_name_key))


def _node_events(nodes, first):
    st, held = _ev_state["nodes"], _ev_state["held"]
    marks = {}
    for n in nodes:
        m = (_cache_get(n["id"]) or {}).get("marks")
        if not m or not m["conf"]:
            continue
        marks[n["id"]] = m
        online, since = m["conf"]
        at, prev = _ev_flip(st, n["id"], online, since, first)
        if at is not None:
            held.append({"nid": n["id"], "up": online, "at": at, "held": time.time(),
                         "down": prev[1] if online and prev[2] else None})
    names = {n["id"]: n.get("name", "") for n in nodes}
    for nid in [k for k in st if k not in names]:
        st.pop(nid, None)
    held[:] = [h for h in held if h["nid"] in names]

    now = time.time()
    pending = [m["node"][1] for m in marks.values() if not m["node"][0] and m["conf"][0]]
    for grp in _ev_clusters([h for h in held if not h["up"]], "at"):
        t0 = grp[0]["at"]
        if (now - min(h["held"] for h in grp) < NODE_HOLD_SECS
                and any(abs(p - t0) <= NODE_GROUP_SECS for p in pending)):
            continue
        members = {h["nid"] for h in grp}
        if len(grp) == 1:
            log_event("bad", "node-down", tx("نودِ «{0}»: آفلاین شد", "node '{0}': offline", names[grp[0]["nid"]]), ts=t0)
        else:
            rows = _node_path_rows(nodes, members, t0)
            rows.append(_names_row(names, members))
            log_event("bad", "node-down", tx("{0} نود با هم آفلاین شدند", "{0} nodes went offline together", len(grp)),
                      tx_join("\n", rows), ts=t0)
        held[:] = [h for h in held if h not in grp]

    downs = {h["nid"] for h in held if not h["up"]}
    ups = [h for h in held if h["up"]]
    for grp in _ev_clusters([h for h in ups if h["down"] is not None], "down") + [
            [h] for h in ups if h["down"] is None]:
        members = {h["nid"] for h in grp}
        if members & downs:
            continue
        d0 = grp[0]["down"]
        waiting = d0 is not None and any(
            s[0] is False and s[2] and abs(s[1] - d0) <= NODE_GROUP_SECS
            for nid, s in st.items() if nid not in members)
        if waiting and now - min(h["held"] for h in grp) < NODE_HOLD_SECS:
            continue
        last = max(h["at"] for h in grp)
        if len(grp) == 1:
            nm = names[grp[0]["nid"]]
            tail = tx(" — {0} قطع بود", " — it was down for {0}", _fa_span(last - d0)) if d0 is not None else ""
            log_event("ok", "node-up", tx("نودِ «{0}»: آنلاین شد{1}", "node '{0}': online{1}", nm, tail), ts=last)
        else:
            log_event("ok", "node-up", tx("{0} نود دوباره آنلاین شدند — {1} قطع بودند",
                                          "{0} nodes came back online — they were down for {1}", len(grp), _fa_span(last - d0)),
                      _names_row(names, members), ts=last)
        held[:] = [h for h in held if h not in grp]


def _events_once():
    nodes = load_nodes()
    links = load_links()
    nmap = {n["id"]: n.get("name", "") for n in nodes}
    first = not _ev_state["init"]
    _node_events(nodes, first)

    seen = set()
    for L in links:
        lid = L["id"]
        seen.add(lid)
        if not L.get("enabled", True):
            _ev_state["links"].pop(lid, None)
            _ev_state["links_coarse_down"].discard(lid)
            continue
        up, since = _link_mark(L)
        if up is None:
            continue
        at, _ = _ev_flip(_ev_state["links"], lid, up, since, first)
        if at is None:
            continue
        nm = L.get("name", "")
        precise_core = L.get("type") == "core" and (
            bool(L.get("ws_pool")) or str(L.get("transport") or "").lower() in CORE_TRANSPORTS)
        if up:
            _ev_state["coarse_hold"].pop(lid, None)
            if not precise_core or lid in _ev_state["links_coarse_down"]:
                log_event("ok", "link-up", tx("تونلِ «{0}»: وصل شد", "tunnel '{0}': up", nm), ts=at)
            _ev_state["links_coarse_down"].discard(lid)
        elif not precise_core or _link_blind(L):
            log_event("bad", "link-down", _down_title(nm), _link_down_reason(L, nmap), ts=at)
            if precise_core:
                _ev_state["links_coarse_down"].add(lid)
        else:
            _ev_state["coarse_hold"][lid] = at
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
            if first:
                _ev_state["evseq"].setdefault(lid + "|" + end, None)
            r = pre.get((lid, end))
            if not r or "error" in r:
                continue
            try:
                if end == "cli":
                    _ev_seed_axes(lid, is_pool, r.get("active"))
                _ingest_core_events(lid, end, nm, r.get("events"))
            except Exception:
                continue
    for k in [k for k in _ev_state["evseq"] if k.split("|", 1)[0] not in seen]:
        _ev_state["evseq"].pop(k, None)
    for rk in [k for k in _ev_state["rotip"] if k.rsplit(":", 1)[0] not in seen]:
        _ev_state["rotip"].pop(rk, None)

    live = {L["id"]: L for L in links if L.get("enabled", True)}
    now = time.time()
    for lid, at in list(_ev_state["coarse_hold"].items()):
        L = live.get(lid)
        if L is None or _ev_state["core_down"].get(lid, 0) >= at - CORE_SILENT_SECS:
            del _ev_state["coarse_hold"][lid]
        elif now - at >= CORE_SILENT_SECS:
            del _ev_state["coarse_hold"][lid]
            _ev_state["links_coarse_down"].add(lid)
            log_event("bad", "link-down", _down_title(L.get("name", "")),
                      _link_down_reason(L, nmap, silent=True), ts=at)
    for lid in [k for k in _ev_state["core_down"] if k not in live]:
        del _ev_state["core_down"][lid]

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
    recent = [e for e in load_events() if _sint(e.get("ts")) >= cut]
    evs = [dict(e, cat=_ev_cat(e.get("kind"))) for e in _ev_shown(recent, hidden)]
    return {"ok": True, "events": evs, "hidden": sorted(hidden), "hidden_out": len(recent) - len(evs)}


def api_events_clear(d):
    with _events_lock:
        _ev_all()[:] = []
        _ev_out.append(("clear",))
    _ev_wake.set()
    return {"ok": True}


PF_PORT_LABELS = {"listen_port": tx("پورتِ ورودی", "the listen port"), "dst_port": tx("پورتِ مقصد", "the destination port")}


def _pf_field(k, v):
    if k in PF_PORT_LABELS:
        p = _sint(v)
        if not 1 <= p <= 65535:
            raise Bad("bad_port", "{0} باید بینِ ۱ تا ۶۵۵۳۵ باشد", "{0} must be from 1 to 65535", PF_PORT_LABELS[k])
        return p
    if k == "dst_ips":
        raw = v if isinstance(v, list) else re.split(r"[\s,]+", str(v))
        ips = [str(x).strip() for x in raw if str(x).strip()]
        if not ips or not all(is_ipv4(x) for x in ips):
            raise Bad("bad_dst_ips", "فهرستِ آی‌پیِ مقصد باید حداقل یک آدرسِ IPv4 داشته باشد",
                      "the destination IP list must have at least one IPv4 address")
        return ips
    if k == "listen_ip":
        s = str(v).strip()
        if not is_ipv4(s):
            raise Bad("bad_listen_ip", "آی‌پیِ شنود نامعتبر است", "invalid listen IP")
        return s
    if k == "iface":
        s = str(v).strip()
        if not re.match(r"^[A-Za-z0-9._-]{1,15}$", s):
            raise Bad("bad_iface", "نامِ کارتِ شبکه نامعتبر است", "invalid network interface name")
        return s
    if k == "interval_min":
        m = _sint(v)
        if not 1 <= m <= 1440:
            raise Bad("bad_interval", "بازهٔ چرخش باید بینِ ۱ تا ۱۴۴۰ دقیقه باشد", "the rotation interval must be from 1 to 1440 minutes")
        return m
    return v


def _pf_name(v):
    s = str(v).strip()
    if not re.match(r"^[A-Za-z0-9_.-]{1,40}$", s):
        raise Bad("bad_portfw_name", "نامِ پورت‌فوروارد نامعتبر است — فقط حروف/عدد و «._-» (1 تا 40 کاراکتر) مجاز است",
                  "invalid port-forward name — only letters, digits and ._- (1 to 40 characters)")
    return s


def _pf_push(n, endpoint, body, timeout=NODE_OP_TIMEOUT, ret="name"):
    r = node_call(n, endpoint, "POST", body, timeout=timeout)
    if not r.get("ok"):
        raise Bad("node_failed", r.get("error") or r.get("msg") or tx("نود کار را انجام نداد", "the node did not do it"))
    _refresh_cache([n["id"]])
    return {"ok": True, ret: r.get(ret)}


def api_portfw(d):
    _require(d, ["node", "listen_port", "dst_port", "dst_ips"])
    n = get_node(d["node"])
    if not n:
        raise _no_node()
    body = {"listen_port": _pf_field("listen_port", d["listen_port"]),
            "dst_port": _pf_field("dst_port", d["dst_port"]),
            "dst_ips": _pf_field("dst_ips", d["dst_ips"]),
            "rotate": bool(d.get("rotate"))}
    if body["rotate"]:
        body["interval_min"] = _pf_field("interval_min", d.get("interval_min"))
    if d.get("iface"):
        body["iface"] = _pf_field("iface", d["iface"])
    if d.get("listen_ip"):
        body["listen_ip"] = _pf_field("listen_ip", d["listen_ip"])
    return _pf_push(n, "portfw", body)


def _pf_key(node_id, name):
    return str(node_id) + str(name)


def _pf_load_order():
    _store_ready()
    return list(_M.pforder)


def _pf_sorted(seq, key_of):
    order = _pf_load_order()
    rank = {k: i for i, k in enumerate(order)}
    big = len(order)
    return [x for _, x in sorted(enumerate(seq), key=lambda p: (rank.get(key_of(p[1]), big), p[0]))]


_pf_last = {}
_pf_lock = threading.Lock()


def _pf_node_configs(nid):
    r = _cached_list(nid)
    if r.get("configs") is None:
        with _pf_lock:
            return _pf_last.get(nid, []), None
    cfgs = [c for c in r["configs"] if c.get("type") == "portfw"]
    with _pf_lock:
        _pf_last[nid] = cfgs
    return cfgs, r.get("health") or {}


def _pf_natural_keys():
    return [_pf_key(n["id"], c.get("name")) for n in load_nodes()
            for c in _pf_node_configs(n["id"])[0] if c.get("name")]


def _reorder_portfw(a, targets):
    natural = _pf_natural_keys()
    with _reg_lock:
        cur = _pf_sorted(natural, lambda k: k)
        if a not in cur or any(b not in cur for b in targets):
            raise _no_item()
        for b in targets:
            ia, ib = cur.index(a), cur.index(b)
            cur[ia], cur[ib] = cur[ib], cur[ia]
        with store_tx() as t:
            t.pforder(cur)
    return {"ok": True}


def api_portfw_list(d):
    q = _list_query(d)
    all_pf = []
    nodes = load_nodes()
    ids = {n["id"] for n in nodes}
    with _pf_lock:
        for nid in [k for k in _pf_last if k not in ids]:
            _pf_last.pop(nid, None)
    for n in nodes:
        cfgs, h = _pf_node_configs(n["id"])
        node_ips = _flat_ips(_cached_ping(n["id"]))
        node_ip = node_ips[0] if len(node_ips) == 1 else ""
        tf = _tf_read(n["id"])
        for c in cfgs:
            if q:
                hay = (n["name"].lower(), str(c.get("listen_port", "")), str(c.get("dst_port", "")),
                       str(c.get("iface") or "").lower(), c.get("listen_ip") or node_ip, *c.get("dst_ips", []))
                if not any(q in v for v in hay if v):
                    continue
            t = tf.get("pf:" + str(c.get("name") or ""))
            bw = ({"rx_bps": t["rx_bps"], "tx_bps": t["tx_bps"], "rx_total": t["crx"], "tx_total": t["ctx"]}
                  if t else {"rx_bps": 0.0, "tx_bps": 0.0, "rx_total": 0, "tx_total": 0})
            all_pf.append({"node": n["name"], "node_id": n["id"], "name": c.get("name"),
                           "iface": c.get("iface"), "listen_port": c.get("listen_port"),
                           "listen_ip": c.get("listen_ip") or "", "node_ip": node_ip,
                           "dst_port": c.get("dst_port"), "dst_ips": c.get("dst_ips", []),
                           "switch_interval": c.get("switch_interval", 0),
                           "health": h.get(c.get("name")) if h is not None else None, "offline": h is None,
                           **bw})
    all_pf = _pf_sorted(all_pf, lambda it: _pf_key(it["node_id"], it["name"]))
    return {"portfw": all_pf, "total": len(all_pf)}


def api_portfw_edit(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise _no_node()
    body = {"name": _pf_name(d["name"])}
    for k in ("listen_port", "dst_port", "dst_ips", "iface", "listen_ip"):
        if d.get(k) not in (None, ""):
            body[k] = _pf_field(k, d[k])
    if d.get("listen_ip") == "":
        body["listen_ip"] = ""
    if "rotate" in d:
        body["rotate"] = bool(d["rotate"])
    if body.get("rotate", True) and d.get("interval_min") not in (None, ""):
        body["interval_min"] = _pf_field("interval_min", d["interval_min"])
    return _pf_push(n, "portfw-edit", body)


def api_portfw_next(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise _no_node()
    return _pf_push(n, "portfw-next", {"name": _pf_name(d["name"])}, timeout=NODE_OP_TIMEOUT, ret="active")


def api_portfw_del(d):
    _require(d, ["node", "name"])
    n = get_node(d["node"])
    if not n:
        raise _no_node()
    name = _pf_name(d["name"])
    cfgs, health = _pf_node_configs(n["id"])
    if health is None and not cfgs:
        raise Bad("node_not_read", "وضعیتِ نودِ «{0}» هنوز خوانده نشده — چند لحظه بعد دوباره بزن",
                  "the state of node '{0}' is not read yet — try again in a moment", n.get("name") or n["id"])
    if name not in [str(c.get("name") or "") for c in cfgs]:
        raise Bad("portfw_not_found", "روی نودِ «{0}» پورت‌فورواردی به نامِ «{1}» ثبت نیست "
                  "— برای اینکه تونلی به همین نام پاک نشود متوقف شد",
                  "node '{0}' has no port forward named '{1}' — stopped so a tunnel with the same name is not deleted",
                  n.get("name") or n["id"], name)
    r = node_call(n, "delete", "POST", {"name": name})
    if r.get("ok"):
        _tf_forget(n["id"], ["pf:" + name])
    _refresh_cache([n["id"]])
    return {"ok": True} if r.get("ok") else _node_soft(r, _FAILED)


def _flat_ips(ping):
    return [ip for ips in (ping.get("ips") or {}).values() for ip in ips]


def _ping_both(A, B):
    pa, pb = node_call(A, "ping", "GET"), node_call(B, "ping", "GET")
    for N, p in ((A, pa), (B, pb)):
        if not p.get("ok"):
            raise Bad("node_offline", "نودِ «{0}» آفلاین است", "node '{0}' is offline", N["name"])
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
                    raise Bad("subnet_on_iface",
                              "نودِ «{0}» همین حالا {1} را روی کارتِ «{2}» دارد و با سابنتِ "
                              "«{3}» هم‌پوشانی می‌کند. لینوکس این را رد نمی‌کند، ولی مسیرِ آن بازه دوتا "
                              "می‌شود و ترافیک می‌تواند از همان کارت برود در حالی که تونل سبز نشان داده "
                              "می‌شود. بازهٔ دیگری انتخاب کن یا آن آدرس را از «{2}» بردار.",
                              "node '{0}' already has {1} on interface '{2}', which overlaps subnet '{3}'. Linux "
                              "allows it, but that range gets two routes and traffic can leave through that "
                              "interface while the tunnel shows green. Pick another range or remove that address from '{2}'.",
                              node["name"], addr, iface, subnet)


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
            raise Bad("subnet_overlap", "سابنتِ «{0}» با تونلِ «{1}»{2} روی یک نودِ مشترک هم‌پوشانی دارد؛ بازهٔ دیگری انتخاب کن",
                      "subnet '{0}' overlaps tunnel '{1}'{2} on a shared node; pick another range",
                      subnet, L.get("name"), its)


def _guard_ends(A, B, a_ip, b_ip, ttype, exclude_id=None):
    if not is_ipv4(a_ip or "") or not is_ipv4(b_ip or ""):
        raise Bad("node_ips_unread", "آی‌پیِ نودها خوانده نشد", "the nodes' IPs could not be read")
    if a_ip == b_ip:
        raise Bad("same_ip", "آی‌پیِ دو سرِ تونل یکی است؛ برای هر طرف یک آی‌پیِ متفاوت انتخاب کن",
                  "both ends of the tunnel have the same IP; pick a different IP for each side")
    new_pair = frozenset([(A["id"], a_ip), (B["id"], b_ip)])
    for L in load_links():
        if exclude_id is not None and L.get("id") == exclude_id:
            continue
        same_pair = frozenset([(L.get("a_node"), L.get("a_ip")), (L.get("b_node"), L.get("b_ip"))]) == new_pair
        if L.get("type") == ttype and same_pair and ttype != "core":
            raise Bad("tunnel_exists", "یک تونلِ {0} با همین آی‌پی‌ها بینِ این دو نود از قبل هست",
                      "a {0} tunnel with these IPs already exists between these two nodes", ttype)
        if ttype in IPIP_FAMILY and L.get("type") in IPIP_FAMILY and same_pair:
            raise Bad("tunnel_exists", "تونلِ «{0}» از قبل روی همین جفت آی‌پیِ نود هست؛ ipip و fou با هم روی یک جفت نمی‌شوند.",
                      "tunnel '{0}' already uses this pair of node IPs; ipip and fou cannot share one pair.", L.get("name"))


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
    for c in (_cached_list(nid).get("configs") or []):
        if c.get("type") == "portfw":
            for ip in ([c["listen_ip"]] if c.get("listen_ip") else live):
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
        raise _no_node()
    return {"online": bool(_cached_ping(n["id"]).get("ok")), "ips": _node_ip_tags(n["id"])}


def api_link_rebuild_info(d):
    _require(d, ["id"])
    L = next((x for x in load_links() if x["id"] == d["id"]), None)
    if not L:
        raise _no_tunnel()

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


def _proxy_uses():
    out = {}

    def use(pid):
        return out.setdefault(str(pid or ""), {"nodes": [], "tunnels": [], "panel": False})

    for n in load_nodes():
        if n.get("proxy_on"):
            use(n.get("proxy_id"))["nodes"].append(n["name"])
    for L in load_links():
        if L.get("ech_proxy"):
            use(L.get("ech_proxy_id"))["tunnels"].append(L["name"])
    st = get_settings()
    if st.get("dl_proxy_on"):
        use(st.get("dl_proxy_id"))["panel"] = True
    return out


def proxy_url(p):
    auth = ""
    if p.get("user"):
        q = lambda v: urllib.parse.quote(str(v or ""), safe="")
        auth = "%s:%s@" % (q(p["user"]), q(p.get("pass")))
    return "%s://%s%s:%d" % (p["scheme"], auth, p["host"], int(p["port"]))


_proxy_holds = {}


def _hold_proxy(pid, holder):
    with _reg_lock:
        if not get_proxy(pid):
            raise Bad("proxy_not_found", "پروکسیِ انتخاب‌شده همین حالا حذف شد — پروکسیِ دیگری انتخاب کن و دوباره بزن",
                      "the chosen proxy was just deleted — pick another proxy and try again")
        _proxy_holds.setdefault(pid, set()).add(holder)


def _release_proxies(holder):
    with _reg_lock:
        for pid in [pid for pid, holders in _proxy_holds.items() if holder in holders]:
            _proxy_holds[pid].discard(holder)
            if not _proxy_holds[pid]:
                del _proxy_holds[pid]


def _proxy_row(p, uses=None):
    st = _px_get(p)
    u = (uses if uses is not None else _proxy_uses()).get(p["id"]) or {"nodes": [], "tunnels": [], "panel": False}
    return {"id": p["id"], "name": p["name"], "scheme": p["scheme"], "host": p["host"],
            "port": int(p["port"]), "user": p.get("user") or "", "has_pass": bool(p.get("pass")),
            "addr": "%s://%s:%d" % (p["scheme"], p["host"], int(p["port"])),
            "nodes": u["nodes"], "tunnels": u["tunnels"], "panel": u["panel"],
            "online": bool(st.get("ok")), "pending": not st, "status": st}


def api_proxies(d):
    uses = _proxy_uses()
    return {"proxies": [_proxy_row(p, uses) for p in load_proxies()]}


def _proxy_name(d, taken):
    name = str(d.get("name") or "").strip()
    if not 1 <= len(name) <= 40:
        raise Bad("bad_proxy_name", "نامِ پروکسی لازم است (حداکثر ۴۰ نویسه)", "a proxy name is required (at most 40 characters)")
    if name.lower() in taken:
        raise Bad("proxy_name_taken", "پروکسیِ دیگری با همین نام هست", "another proxy has this name")
    return name


def _proxy_fields(d):
    scheme = str(d.get("scheme") or "socks5").strip().lower()
    if scheme not in ("socks5", "http"):
        raise Bad("bad_proxy_scheme", "نوعِ پروکسی باید socks5 یا http باشد", "the proxy type must be socks5 or http")
    host = str(d.get("host") or "").strip()
    if not (is_ipv4(host) or re.match(r"^[A-Za-z0-9.-]{1,253}$", host)):
        raise Bad("bad_proxy_host", "آی‌پی یا هاستِ پروکسی نامعتبر است", "invalid proxy IP or host")
    port = _int_in(d.get("port") or "", 1, 65535,
                   Bad("bad_proxy_port", "پورتِ پروکسی نامعتبر است (1 تا 65535)", "invalid proxy port (1 to 65535)"))
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
        with store_tx() as t:
            t.put(_PROXIES, p)
    return {"ok": True, "proxy": _proxy_row(p)}


def _node_ids(d, key):
    v = d.get(key, [])
    if not isinstance(v, list):
        raise Bad("bad_ids", "فهرستِ نودهای این پروکسی نامعتبر است", "this proxy's node list is invalid")
    return {str(x) for x in v}


def _assign_proxy(pid, add, drop):
    out = []
    for n in load_nodes():
        has = bool(n.get("proxy_on")) and str(n.get("proxy_id") or "") == pid
        if n["id"] in add and not has:
            on = True
        elif n["id"] in drop and has:
            on = False
        else:
            continue
        n2 = _thaw(n)
        n2["proxy_on"], n2["proxy_id"] = on, pid if on else ""
        out.append(n2)
    return out


def api_proxy_edit(d):
    _require(d, ["id"])
    scheme, host, port, user, pw = _proxy_fields(d)
    add, drop = _node_ids(d, "nodes_on"), _node_ids(d, "nodes_off")
    with _reg_lock:
        ps = load_proxies()
        cur = next((x for x in ps if x["id"] == d["id"]), None)
        if not cur:
            raise _no_proxy()
        p = _thaw(cur)
        p["name"] = _proxy_name(d, {x["name"].lower() for x in ps if x["id"] != p["id"]})
        p["scheme"], p["host"], p["port"], p["user"] = scheme, host, port, user
        if pw:
            p["pass"] = pw
        elif not user:
            p["pass"] = ""
        flips = _assign_proxy(p["id"], add, drop) if add or drop else []
        with store_tx() as t:
            t.put(_PROXIES, p)
            for n2 in flips:
                t.put(_NODES, n2)
        moved = [n2["id"] for n2 in flips]
        for nid in moved:
            _addr_bump(nid)
    if moved:
        _refresh_bg(moved)
    return {"ok": True, "proxy": _proxy_row(p)}


def api_proxy_test(d):
    _require(d, ["id"])
    p = get_proxy(str(d["id"]))
    if not p:
        raise _no_proxy()
    out = _px_deep(p, _proxy_probe(p, timeout=8), fresh=True)
    _px_publish(p, out)
    return out


def api_proxy_del(d):
    _require(d, ["id"])
    with _reg_lock:
        ps = load_proxies()
        p = next((x for x in ps if x["id"] == d["id"]), None)
        if not p:
            raise _no_proxy()
        u = _proxy_uses().get(p["id"])
        if u:
            where = []
            if u["panel"]:
                where.append(tx("دانلودهای خودِ پنل", "the panel's own downloads"))
            if u["nodes"]:
                where.append(tx("نودهای «{0}»", "nodes '{0}'", tx_join("»، «", u["nodes"], "', '")))
            if u["tunnels"]:
                where.append(tx("ECH در تونل‌های «{0}»", "ECH in tunnels '{0}'", tx_join("»، «", u["tunnels"], "', '")))
            raise Bad("proxy_in_use", "این پروکسی هنوز استفاده می‌شود: {0} — اول آن‌ها را از این پروکسی جدا کن",
                      "this proxy is still in use: {0} — detach them from this proxy first", tx_join("؛ ", where, "; "))
        if p["id"] in _proxy_holds:
            raise Bad("proxy_busy", "یک نصبِ نود یا ساخت/ویرایشِ تونل که همین حالا در جریان است از این پروکسی استفاده می‌کند — بعد از تمام‌شدنش دوباره حذف کن",
                      "a node install or a tunnel build/edit running right now uses this proxy — delete again after it finishes")
        with store_tx() as t:
            t.drop(_PROXIES, p["id"])
    return {"ok": True}


def settings_public(obj):
    return {k: v for k, v in obj.items() if k != "api_token_hash"}


def api_settings(d):
    return settings_public(get_settings())


def api_settings_set(d):
    with _reg_lock:
        obj = validate_settings(d or {})
        with store_tx() as t:
            t.settings(obj)
    return {"ok": True, "settings": settings_public(obj)}


def api_token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def api_token_new(d):
    token = secrets.token_urlsafe(32)
    with _reg_lock:
        obj = get_settings()
        obj["api_token_hash"] = api_token_hash(token)
        with store_tx() as t:
            t.settings(obj)
    return {"ok": True, "token": token}


BACKUP_MAX_MB = 32
BACKUP_MAX = BACKUP_MAX_MB * 1024 * 1024
BACKUP_KEYS = "redis/"
BACKUP_SIGN = "sign_key.pem"
_BACKUP_SNAP = ("local out = {} "
                "for _, k in ipairs(redis.call('keys', 'tnl:*')) do "
                "out[#out + 1] = k "
                "out[#out + 1] = redis.call('dump', k) "
                "end "
                "return out")
_restore_lock = threading.Lock()


def _backup_view(nodes, links, proxies):
    core = sum(1 for L in links if L.get("type") == "core")
    return {"nodes": len(nodes), "core": core, "system": len(links) - core, "proxies": len(proxies)}


def _ev_count(r):
    return len(_ev_prune([{"ts": _sint(f.get("ts"))} for _eid, f in r.xrange(K_EVENTS, "-", "+")]))


def _settings_flat(s):
    out = {k: v for k, v in s.items() if k != "tuning"}
    tun = dict(_TUNING_DEFAULTS)
    tun.update(s.get("tuning") or {})
    out.update(("tuning." + k, v) for k, v in tun.items())
    return out


def _settings_diff(cur, raw, px_now, px_after):
    a, b = _settings_flat(cur), _settings_flat(settings_full(raw))
    names = ({x["id"]: x["name"] for x in px_now}, {x["id"]: x["name"] for x in px_after})
    keys = sorted(set(a) | set(b))
    changed = []
    for k in keys:
        if a.get(k) == b.get(k):
            continue
        if k == "api_token_hash":
            changed.append({"key": k, "secret": True})
        elif k == "dl_proxy_id":
            changed.append({"key": k, "old": names[0].get(a.get(k), a.get(k)), "new": names[1].get(b.get(k), b.get(k))})
        else:
            changed.append({"key": k, "old": a.get(k), "new": b.get(k)})
    return {"changed": changed, "total": len(keys)}


def api_backup(d):
    raw = _redis_client(decode=False)
    try:
        with _reg_lock:
            flat = raw.eval(_BACKUP_SNAP, 0)
            c = _backup_view(load_nodes(), load_links(), load_proxies())
    except Exception as e:
        raise StoreError(_store_msg(e)) from None
    finally:
        raw.close()
    with open(_signing_keys()[0], "rb") as f:
        members = [(BACKUP_SIGN, f.read())]
    members += [(BACKUP_KEYS + k.decode(), v) for k, v in zip(flat[0::2], flat[1::2])]
    now = int(time.time())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(data), now, 0o600
            tar.addfile(ti, io.BytesIO(data))
    return {"ok": True, "data": base64.b64encode(buf.getvalue()).decode(), **c}


def _backup_open(blob):
    keys, sign, made, total = {}, None, 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            for ti in tar:
                total += ti.size
                if not ti.isfile() or total > BACKUP_MAX * 4:
                    raise ValueError
                if ti.name != BACKUP_SIGN and not ti.name.startswith(BACKUP_KEYS + "tnl:"):
                    raise ValueError
                data = tar.extractfile(ti).read()
                made = max(made, int(ti.mtime))
                if ti.name == BACKUP_SIGN:
                    sign = data
                else:
                    keys[ti.name[len(BACKUP_KEYS):]] = data
    except (tarfile.TarError, OSError, EOFError, zlib.error, ValueError):
        sign = None
    if sign is None:
        raise Bad("bad_backup", "این فایل بکاپِ پنل نیست یا خراب است", "this file is not a panel backup or it is damaged")
    return keys, sign, made


def _pem_pub(pem):
    r = subprocess.run(["openssl", "rsa", "-pubout"], input=pem, capture_output=True)
    if r.returncode != 0:
        raise Bad("bad_backup", "کلیدِ امضای داخلِ بکاپ خراب است", "the signing key inside the backup is damaged")
    return r.stdout.decode()


def _backup_stage(keys):
    raw, dec = _redis_client(db=1, decode=False), _redis_client(db=1)
    try:
        p = raw.pipeline(transaction=True)
        p.flushdb()
        for k, v in keys.items():
            p.restore(k, 0, v)
        p.execute()
        data = _store_read(dec, _GROUPS)
        data["events"] = _ev_count(dec)
    except RegistryError as e:
        raise Bad("bad_backup", "دادهٔ داخلِ بکاپ خراب است — {0}", "the data inside the backup is damaged — {0}", _why(e)) from None
    except Exception as e:
        rx = sys.modules.get("redis.exceptions")
        if rx is not None and isinstance(e, rx.ResponseError):
            raise Bad("bad_backup", "ردیس دادهٔ این بکاپ را نپذیرفت — فایل خراب است یا با ردیسِ جدیدتری ساخته شده",
                      "Redis refused this backup's data — the file is damaged or was made by a newer Redis") from None
        raise StoreError(_store_msg(e)) from None
    finally:
        raw.close()
        dec.close()
    return data


def _backup_unstage():
    raw = _redis_client(db=1)
    try:
        raw.flushdb()
    except Exception as e:
        log_warn("backup", "staged restore data left in redis db 1: %s" % _store_msg(e))
    finally:
        raw.close()


def _backup_swap():
    for lk in (_reg_lock, _pending_lock, _moved_lock):
        lk.acquire()
    raw = _redis_client(db=1)
    try:
        p = raw.pipeline(transaction=True)
        p.swapdb(0, 1)
        p.flushdb()
        p.execute()
    except Exception as e:
        raise StoreError(tx("بازگردانی کامل نشد ({0}) — پنل دوباره راه می‌افتد؛ بعد از بالا آمدن، فهرست‌ها را ببین",
                            "the restore did not finish ({0}) — the panel restarts; check the lists once it is up",
                            _store_why(e))) from None
    finally:
        raw.close()
        threading.Thread(target=_restart_self, daemon=True).start()


def _restart_self():
    time.sleep(0.5)
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except OSError:
        os._exit(1)


def api_backup_restore(d):
    _require(d, ["data"])
    try:
        blob = base64.b64decode(d["data"], validate=True)
    except (ValueError, TypeError):
        raise Bad("bad_base64", "فایلِ بکاپ base64 نامعتبر است", "the backup file is not valid base64")
    if len(blob) > BACKUP_MAX:
        raise Bad("backup_too_big", "فایلِ بکاپ بیش از حد بزرگ است — حداکثر {0} مگابایت", "the backup file is too large — at most {0} MB",
                  BACKUP_MAX_MB)
    keys, sign, made = _backup_open(blob)
    pub = _pem_pub(sign)
    if not _restore_lock.acquire(blocking=False):
        raise Bad("restore_running", "یک بازگردانیِ دیگر در جریان است", "another restore is running")
    swapping = False
    try:
        got = _backup_stage(keys)
        nodes = load_nodes()
        after = dict(_backup_view(got["nodes"][0], got["links"][0], got["proxies"][0]), events=got["events"])
        out = {"ok": True, "made": made, "same_key": pub == _signing_keys()[1], "boot": _BOOT_ID,
               "now": dict(_backup_view(nodes, load_links(), load_proxies()), events=_ev_count(_redis())),
               "after": after,
               "portfw": sum(len(_pf_node_configs(n["id"])[0]) for n in nodes),
               "settings": _settings_diff(get_settings(), got["settings"], load_proxies(), got["proxies"][0])}
        if not d.get("apply"):
            return out
        try:
            save_bytes(_signing_keys()[0], sign, 0o600)
        except OSError:
            raise Bad("backup_key_write", "کلیدِ امضای بکاپ روی دیسک نوشته نشد — چیزی عوض نشد",
                      "the backup's signing key could not be written to disk — nothing changed") from None
        swapping = True
        _backup_swap()
        return dict(out, restarting=True)
    finally:
        if not swapping:
            _backup_unstage()
            _restore_lock.release()


CHECKIN_CTR_PERSIST_MS = 60000

_checkin_ctr = {}
_checkin_ctr_saved = {}
_checkin_ctr_lock = threading.Lock()


def checkin_ctr_accept(nid, ctr):
    with _checkin_ctr_lock:
        if ctr <= _checkin_ctr.get(nid, 0):
            return False
        _checkin_ctr[nid] = ctr
        if ctr - _checkin_ctr_saved.get(nid, 0) < CHECKIN_CTR_PERSIST_MS:
            return True
    try:
        _redis().hset(K_CHECKIN, nid, ctr)
    except Exception as e:
        if not _store_exc(e):
            raise
        log_warn("checkin", "%s (%s)" % (STORE_DOWN, _store_why(e)))
        return True
    with _checkin_ctr_lock:
        if ctr > _checkin_ctr_saved.get(nid, 0):
            _checkin_ctr_saved[nid] = ctr
    return True


def _checkin_claimant(d):
    fp = str(d.get("fp") or "")
    sig = str(d.get("sig") or "")
    if len(fp) != 64 or not sig:
        return None, "unauthorized"
    signed = {k: v for k, v in d.items() if k != "sig"}
    msg = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
    try:
        got = base64.b64decode(sig, validate=True)
    except Exception:
        return None, "unauthorized"
    for node in load_nodes():
        tok = str(node.get("token") or "")
        if not tok or not secret_eq(hashlib.sha256(tok.encode()).hexdigest(), fp):
            continue
        if not hmac.compare_digest(hmac.new(tok.encode(), msg, hashlib.sha256).digest(), got):
            return None, "unauthorized"
        try:
            ctr = int(d.get("ctr") or 0)
        except (TypeError, ValueError):
            return None, "unauthorized"
        if not checkin_ctr_accept(node["id"], ctr):
            return None, "stale"
        return node, ""
    return None, "unauthorized"


def api_checkin_impl(source_ip, d):
    n, why = _checkin_claimant(d or {})
    if not n:
        if why == "stale":
            return {"ok": False, "stale": True,
                    "error": "شمارندهٔ این درخواست از درخواستِ قبلیِ همین نود عقب‌تر است "
                             "— یا تکرارِ یک پیامِ قدیمی است یا ساعتِ نود عقب رفته"}
        return {"ok": False, "unauthorized": True,
                "error": "درخواستِ نود امضا ندارد یا نود ناشناخته است"}
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
            log_event("warn", "node-moved", tx("نودِ «{0}»: جابه‌جاییِ نشانی", "node '{0}': address moved", n_snap.get("name")),
                      tx("از {0}:{1} به {2}:{3} رفته و از نشانیِ تازه جواب می‌دهد — روی"
                         " کارتِ نود نشانِ هشدار را بزن و «تنظیم به‌عنوانِ نشانیِ نود»، بعد تونل‌هایش را بازسازی کن."
                         " (برای انجامِ خودکار، حالتِ آشتی را «خودکار» بگذار.)",
                         "it moved from {0}:{1} to {2}:{3} and answers from the new address — adopt the new address "
                         "(node-adopt-ip), then rebuild its tunnels. (To do it by itself, set the repair mode to auto.)",
                         host, port, want_host, want_port))
        return {"ok": True, "host": host, "port": port, "moved_to": want_host}
    _moved_clear(n_snap["id"])
    with _reg_lock:
        nodes = load_nodes()
        n = next((x for x in nodes if secret_eq(x.get("token", ""), tok)), None)
        if not n:
            return {"ok": False, "error": "نودِ ناشناخته"}
        if _host_taken(nodes, want_host, exclude_id=n["id"]):
            return {"ok": False, "clash": True, "host": host, "port": port,
                    "error": "نودِ دیگری از قبل روی این نشانی ثبت است؛ نشانی عوض نشد"}
        host, port, nid = want_host, want_port, n["id"]
        store_edit(_NODES, nid, lambda x: x.update(host=want_host, port=want_port))
        _addr_bump(nid)
    _refresh_cache([nid])
    return {"ok": True, "host": host, "port": port}


ACT_KEEP = 20
ACT_KEEP_FAIL = 600

_acts = {}
_act_lock = threading.RLock()


class ActCancelled(Exception):
    pass


def act_step(h, step, i=0, n=0, stop=True, more=None):
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


def _act_open(key, target="", page="", ttype=""):
    with _act_lock:
        _act_prune()
        cur = _acts.get(key)
        if cur and cur["state"] == "run":
            raise Bad("job_running", "همین کار روی این مورد در جریان است — تا تمام‌شدنش صبر کن",
                      "this job is already running on this item — wait until it finishes")
        h = {"key": key, "target": target, "page": page, "ttype": ttype,
             "state": "run", "step": "", "si": 0, "sn": 0, "pct": 0, "note": "", "offer": "",
             "cancel": False, "can": True, "started": int(time.time()), "ended": 0}
        _acts[key] = h
    return h


def _act_run(h, fn):
    try:
        res = fn(h)
        res = res if isinstance(res, dict) else {}
        with _act_lock:
            if res.get("ok") is False:
                h.update(state="fail", step="", code=str(res.get("code") or "failed"), http=400,
                         error=tx_cut(res.get("msg") or res.get("error") or _FAILED, 300),
                         offer=str(res.get("offer") or ""), ended=int(time.time()))
            else:
                h.update(state="done", step="", pct=100, si=h["sn"], can=False,
                         note=tx_cut(res.get("msg") or "", 300), ended=int(time.time()))
    except ActCancelled:
        with _act_lock:
            h.update(state="cancel", step="", ended=int(time.time()))
    except Exception as e:
        with _act_lock:
            h.update(state="fail", step="", code=_code(e), http=400 if isinstance(e, ValueError) else 500,
                     error=tx_cut(_why(e) if str(e) else _FAILED, 300), ended=int(time.time()))


def act_start(key, fn, target="", page="", ttype=""):
    h = _act_open(key, target, page, ttype)
    threading.Thread(target=_act_run, args=(h, fn), daemon=True).start()
    return {"ok": True, "act": key}


def _link_act_key(d):
    lid = (d or {}).get("id")
    L = next((x for x in load_links() if x["id"] == lid), None)
    if not L:
        raise _no_tunnel()
    return "link:" + str(lid), L.get("name") or ""


def act_link(d, fn):
    key, name = _link_act_key(d)
    return act_start(key, fn, target=name)


def _rebuild_now(lid, pin=True):
    d = {"id": lid, "pin": pin}
    h = _act_open(*_link_act_key(d))
    _act_run(h, _rebuild_job(d))
    return h["state"] == "done"


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
            raise _no_job()
        if not h.get("can"):
            raise Bad("job_past_cancel", "این کار از مرحله‌ای گذشته که بشود جلویش را گرفت — تا تمام‌شدنش صبر کن",
                      "this job is past the point where it can be stopped — wait until it finishes")
        h["cancel"] = True
        h["step"] = tx("در حالِ لغو…", "cancelling…")
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
PUBLIC_ASSET = re.compile(r"/assets/fonts/[A-Za-z0-9_-]+\.woff2")


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
        "tuning_ranges": {**_TUNING_RANGES, **_TUNING_LIST_RANGES},
        "probe_samples": _PROBE_SAMPLES,
        "ev_types": [list(x) for x in EV_TYPES],
        "ev_groups": [list(x) for x in EV_GROUPS],
        "settings_defaults": {k: v for k, v in settings_defaults().items() if k != "tuning"},
        "split_ttl_max": SPLIT_TTL_MAX,
        "workers_max": CORE_MAX_WORKERS,
        "usage_crit_pct": UP_CRIT,
        "api": [[cmd, "POST" if cmd in MUTATIONS else "GET", cmd not in TOKEN_DENY] for cmd in API],
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
    "backup": api_backup, "backup-restore": api_backup_restore,
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
             "act-cancel", "api-token-new", "backup", "backup-restore"}
TOKEN_DENY = {"settings-set", "api-token-new", "backup", "backup-restore"}
API_MSG = {
    "unauthorized": ("وارد نشده‌اید", 401, "unauthorized"),
    "locked": ("تلاشِ زیاد — چند دقیقه صبر کن", 429, "too many failed attempts from this address; try again in a few minutes"),
    "api_disabled": ("API در دسترس نیست", 403, "API is not available"),
    "bad_token": ("توکنِ API نامعتبر است", 401, "invalid API token"),
    "token_denied": ("این درخواست با توکنِ API مجاز نیست", 403, "this endpoint is not available with an API token"),
    "unknown_route": ("مسیرِ ناشناخته", 404, "unknown API route"),
    "post_only": ("این درخواست باید POST باشد", 405, "this endpoint requires POST"),
    "bad_request": ("درخواستِ نامعتبر", 403, "invalid request"),
    "internal": ("خطای داخلی", 500, "internal error"),
    "too_large": ("درخواست بیش از حد بزرگ است — فایلِ هسته حداکثر %d و فایلِ بکاپ حداکثر %d مگابایت است"
                  % (CORE_UPLOAD_MB, BACKUP_MAX_MB), 413,
                  "request body too large; a core binary is at most %d MB, a backup %d MB"
                  % (CORE_UPLOAD_MB, BACKUP_MAX_MB)),
}
API_REFUSED = {
    "api_disabled": ("درخواستِ API «{0}» رد شد — دسترسیِ بیرونی به API خاموش است.",
                     "API request '{0}' refused — outside access to the API is off."),
    "bad_token": ("درخواستِ API «{0}» رد شد — توکن نامعتبر است.", "API request '{0}' refused — invalid token."),
    "token_denied": ("درخواستِ API «{0}» رد شد — این مسیر با توکن مجاز نیست.",
                     "API request '{0}' refused — this route is not allowed with a token."),
    "unknown_route": ("درخواستِ API «{0}» رد شد — مسیرِ ناشناخته.", "API request '{0}' refused — unknown route."),
    "post_only": ("درخواستِ API «{0}» رد شد — باید POST باشد.", "API request '{0}' refused — it must be POST."),
    "too_large": ("درخواستِ API «{0}» رد شد — بدنهٔ درخواست بیش از حد بزرگ بود.",
                  "API request '{0}' refused — the request body was too large."),
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

    def _send(self, code, body, ctype="application/json", extra=None, big=False, cache="no-store", on_chunk=None):
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
                         "style-src 'self' 'unsafe-inline'; "
                         "font-src 'self'; img-src 'self' data:; "
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
                if on_chunk:
                    on_chunk(min(len(mv), i + self.SEND_CHUNK))
        finally:
            if sock:
                sock.settimeout(prev)

    BODY_CAP = 1048576
    DRAIN_MAX = 64 * 1048576

    def _content_length(self):
        try:
            return max(int(self.headers.get("Content-Length", "0")), 0)
        except ValueError:
            return 0

    def _drain(self, n):
        left = min(n, self.DRAIN_MAX)
        while left > 0:
            chunk = self.rfile.read(min(left, 65536))
            if not chunk:
                break
            left -= len(chunk)

    def _body(self, cap=BODY_CAP):
        n = min(self._content_length(), cap)
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
            if not PUBLIC_ASSET.fullmatch(path) and not self._user():
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
        rows = [tx("از: {0}", "from: {0}", self._client_ip())] + list(extra or [])
        b = ua_browser(ua)
        if b:
            rows.append(tx("مرورگر: {0}", "browser: {0}", b))
        sysname = ua_system(ua)
        if sysname:
            rows.append(tx("دستگاه: {0}", "device: {0}", sysname))
        if ua:
            rows.append(tx("نشانه: {0}", "user agent: {0}", ua[:UA_MAX]))
        log_event(level, etype, title, tx_join("\n", rows))

    def _login(self):
        d = self._body()
        ip = self._client_ip()
        if rate_limited(ip):
            if note_blocked(ip):
                self._auth_log("bad", "auth-lock", tx("تلاش برای ورود در حالی که این نشانی قفل است همچنان ادامه دارد.",
                                                      "login attempts go on while this address is locked."))
            self._send(429, {"error": "تلاشِ زیاد — چند دقیقه صبر کن"})
            return
        if not _login_gate.acquire(blocking=False):
            self._send(429, {"error": "تلاشِ زیاد — چند لحظه صبر کن"})
            return
        try:
            conf = self._conf()
            time.sleep(0.3)
            user_ok = secret_eq(d.get("user", ""), conf.get("user") or "")
            pass_ok = verify_password(conf, str(d.get("pass", "")))
        finally:
            _login_gate.release()
        if user_ok and pass_ok:
            secure = "; Secure" if conf.get("tls") else ""
            cookie = f"tnl_session={make_token(conf, conf['user'])}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict{secure}"
            self._send(200, {"ok": True}, extra={"Set-Cookie": cookie})
        else:
            note_fail(ip)
            tries = fail_count(ip)
            who = tx("نام کاربری: {0}", "username: {0}", tx("درست", "right") if user_ok else tx("ناشناخته", "unknown"))
            if tries >= FAIL_LIMIT:
                self._auth_log("bad", "auth-lock", tx("پس از {0} تلاشِ ناموفق در {1} دقیقه، ورود از این نشانی قفل شد.",
                                                      "after {0} failed tries in {1} minutes, logins from this address are locked.",
                                                      tries, FAIL_WINDOW // 60), [who])
            else:
                self._auth_log("warn", "auth-fail", tx("یک تلاشِ ناموفق برای ورود ثبت شد؛ تلاشِ {0} از {1} مجاز.",
                                                       "a failed login was recorded; try {0} of {1} allowed.",
                                                       tries, FAIL_LIMIT), [who])
            self._send(401, {"error": "نام کاربری یا رمز اشتباه است"})

    def _dl(self):
        ip = self._client_ip()
        if rate_limited(ip):
            self._send(429, {"error": "تلاشِ زیاد — چند دقیقه صبر کن"})
            return
        q = {k: v[0] for k, v in
             urllib.parse.parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "").items()}
        node = _dl_ticket_node(q)
        if not node:
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
        with _dl_watch_lock:
            watch = _dl_watch.get(node["id"])
        tick = (lambda sent, _w=watch, _s=start, _t=len(raw): _w(_s + sent, _t)) if watch else None
        if start:
            self._send(206, raw[start:], "application/octet-stream", big=True, on_chunk=tick,
                       extra={"Accept-Ranges": "bytes",
                              "Content-Range": "bytes %d-%d/%d" % (start, len(raw) - 1, len(raw))})
            return
        self._send(200, raw, "application/octet-stream", big=True, on_chunk=tick,
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
        except RegistryError as e:
            log_warn("checkin", str(e))
            self._send(500, {"error": str(e)})
            return
        except Exception:
            log_internal("checkin")
            self._send(500, {"error": "خطای داخلی"})
            return
        if res.get("unauthorized"):
            note_fail(ip)
            self._send(401, res)
            return
        self._send(200 if res.get("ok") else 409, res)

    def _fail(self, code, en, drain=False):
        fa, status, msg = API_MSG[code]
        if drain and self.command == "POST":
            self._drain(self._content_length())
        self._send(status, {"code": status, "error": code, "message": msg} if en else {"error": fa})

    def _bearer_check(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return "unauthorized"
        ip = self._client_ip()
        if rate_limited(ip):
            if note_blocked(ip):
                self._auth_log("bad", "api-lock", tx("درخواست با توکنِ API از نشانیِ قفل‌شده همچنان ادامه دارد.",
                                                     "API token requests go on from a locked address."))
            return "locked"
        s = get_settings()
        if not s.get("api_external"):
            note_fail(ip)
            return "api_disabled"
        stored = str(s.get("api_token_hash") or "")
        if stored and secret_eq(api_token_hash(auth[7:].strip()), stored):
            return None
        note_fail(ip)
        return "bad_token"

    def _api_log(self, level, kind, title, cmd, method, status):
        self._auth_log(level, kind, title, [tx("مسیر: {0} /api/{1}", "route: {0} /api/{1}", method, cmd),
                                            tx("نتیجه: {0}", "result: {0}", status)])

    def _refuse(self, code, cmd, method, en, drain=False):
        self._fail(code, en, drain)
        if en and code in API_REFUSED:
            self._api_log("warn", "api-refused", tx(*API_REFUSED[code], cmd), cmd, method, API_MSG[code][1])

    def _api(self, cmd, method):
        en = (self.headers.get("Authorization", "").startswith("Bearer ")
              or "tnl_session" not in self.headers.get("Cookie", ""))
        via_token = False
        if not self._user():
            why = self._bearer_check()
            if why:
                self._refuse(why, cmd, method, en)
                return
            via_token = True
        if cmd not in API:
            self._refuse("unknown_route", cmd, method, en, drain=True)
            return
        if via_token and cmd in TOKEN_DENY:
            self._refuse("token_denied", cmd, method, en, drain=True)
            return
        if cmd in MUTATIONS:
            if method != "POST":
                self._refuse("post_only", cmd, method, en)
                return
            if not via_token and self.headers.get("X-Requested-With") != "tnl-central":
                self._refuse("bad_request", cmd, method, en, drain=True)
                return
        cap = {"core-upload": CORE_UPLOAD_MAX, "backup-restore": BACKUP_MAX}.get(cmd, 0) * 4 // 3 + self.BODY_CAP
        if method == "POST" and self._content_length() > cap:
            self._refuse("too_large", cmd, method, en, drain=True)
            return
        d = self._body(cap=cap) if method == "POST" else query_dict(self.path)
        try:
            res = _dispatch(cmd, d)
            self._send(*(_en_reply(res) if via_token else (200, res)))
        except ValueError as e:
            self._send(400, _err_en(e, 400) if via_token else {"error": str(e)})
            if via_token:
                self._api_log("warn", "api-error", tx("درخواستِ API «{0}» با خطا برگشت: {1}",
                                                      "API request '{0}' returned an error: {1}", cmd, _why(e)), cmd, method, 400)
        except RegistryError as e:
            log_warn("api %s" % cmd, str(e))
            self._send(500, _err_en(e, 500) if via_token else {"error": str(e)})
            if via_token:
                self._api_log("bad", "api-error", tx("درخواستِ API «{0}» به خطایِ دادهٔ پنل خورد.",
                                                     "API request '{0}' hit a panel data error.", cmd), cmd, method, 500)
        except Exception:
            log_internal("api %s" % cmd)
            self._fail("internal", en)
            if via_token:
                self._api_log("bad", "api-error", tx("درخواستِ API «{0}» به خطای داخلی خورد.",
                                                     "API request '{0}' hit an internal error.", cmd), cmd, method, 500)


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


DEP_PACKAGES = ("openssl", "ca-certificates", "iproute2", "openssh-client", "sshpass", "redis-server", "python3-redis")
DEP_BINARIES = ("openssl", "ssh", "sshpass", "ip", "systemctl", "redis-server")


def missing_binaries():
    miss = [b for b in DEP_BINARIES if not shutil.which(b)]
    if importlib.util.find_spec("redis") is None:
        miss.append("python3-redis")
    return miss


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
    importlib.invalidate_caches()
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
    stored = cli_conf(False)
    stored.update({"user": conf["user"], "salt": salt, "hash": h,
                   "secret": secrets.token_hex(32),
                   "port": conf.get("port", stored.get("port", 8080))})
    save_json(WEB_CONF, stored)
    conf.clear()
    conf.update(stored)


REDIS_CONF_TEXT = f"""port 0
unixsocket {REDIS_SOCK}
unixsocketperm 770
dir {REDIS_DIR}
appendonly yes
appendfsync always
appenddirname "appendonlydir"
aof-use-rdb-preamble yes
no-appendfsync-on-rewrite no
save ""
maxmemory-policy noeviction
databases 2
protected-mode yes
daemonize no
supervised systemd
loglevel notice
logfile ""
"""

REDIS_UNIT_TEXT = f"""[Unit]
Description=Redis store for tnl-central
After=network.target
StartLimitIntervalSec=0

[Service]
Type=notify
User=redis
Group=redis
ExecStart=/usr/bin/redis-server {REDIS_CONF}
RuntimeDirectory=tnl-redis
RuntimeDirectoryMode=0750
StateDirectory=tnl-redis
StateDirectoryMode=0750
UMask=0077
LimitNOFILE=65536
Restart=always
RestartSec=2
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
"""


def install_store():
    with open(REDIS_CONF, "w") as f:
        f.write(REDIS_CONF_TEXT)
    os.chmod(REDIS_CONF, 0o644)
    with open(REDIS_UNIT_FILE, "w") as f:
        f.write(REDIS_UNIT_TEXT)
    subprocess.run(["systemctl", "disable", "--now", "redis-server.service"], capture_output=True)
    subprocess.run(["systemctl", "daemon-reload"])
    subprocess.run(["systemctl", "enable", REDIS_SERVICE], capture_output=True)
    subprocess.run(["systemctl", "restart", REDIS_SERVICE])
    try:
        store_boot(wait=30)
    except RegistryError as e:
        print("%s %s" % (BAD, e))
        print("    journalctl -u %s" % REDIS_SERVICE)
        return False
    print("%s redis store ready at %s (appendfsync always)" % (OK, REDIS_SOCK))
    return True


def write_service():
    with open(SERVICE_FILE, "w") as f:
        f.write(f"""[Unit]
Description=tnl central panel
After=network-online.target {REDIS_SERVICE}
Wants=network-online.target {REDIS_SERVICE}

[Service]
Type=simple
ExecStart=/usr/bin/python3 {INSTALLED} --serve
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
    staged, prev = UI_DIR + ".new", UI_DIR + ".old"
    shutil.rmtree(staged, ignore_errors=True)
    shutil.rmtree(prev, ignore_errors=True)
    shutil.copytree(src, staged)
    if os.path.isdir(UI_DIR):
        os.rename(UI_DIR, prev)
    os.replace(staged, UI_DIR)
    shutil.rmtree(prev, ignore_errors=True)
    return "copied"


def step(n, total, title):
    print()
    print("%s %s" % (cyan("[%d/%d]" % (n, total)), bold(title)))


def do_install():
    if not sys.stdin.isatty():
        print("%s install asks for a username and a password, so it needs a terminal." % BAD)
        return False
    total = 7

    step(1, total, "dependencies")
    install_deps()

    step(2, total, "redis store")
    if not install_store():
        return False

    step(3, total, "files")
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

    step(4, total, "port and login")
    conf = cli_conf()
    have = conf.get("port", 8080)
    conf["port"] = _port_or(input("Panel port [%s]: " % have), have)
    set_password(conf)

    step(5, total, "signing key")
    try:
        _signing_keys()
        print("%s rsa key ready" % OK)
    except Exception as e:
        print("%s openssl could not create the signing key (%s)" % (BAD, e))
        print("    without it every push to a node is refused, so the install stops here.")
        return False

    step(6, total, "service")
    write_service()
    svc("enable")
    svc("restart")
    if not service_settled():
        print("%s the service did not come up - journalctl -u %s" % (BAD, SERVICE))
        return False
    print("%s %s is active" % (OK, SERVICE))

    step(7, total, "core and agent")
    try:
        info = _stage_core("latest")
        print("%s core %s staged (%s)" % (OK, info["version"], ", ".join(info["arches"])))
    except Exception as e:
        print("%s could not pre-download the core (%s)" % (WARN, e))
        print("    stage it later from the panel: %s" % dim("هستهٔ داده / دریافت از گیت‌هاب"))
    try:
        meta = api_agent_fetch_git({})
        print("%s node agent %s staged" % (OK, meta["version"]))
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
    have = load_conf().get("port", 8080)
    p = input(f"New panel port [{have}]: ").strip()
    if not p:
        return
    port = _port_or(p, 0)
    if not port:
        print(f"[!] {p} is not a port between 1 and 65535 - nothing changed.")
        return
    conf = load_conf()
    conf["port"] = port
    save_json(WEB_CONF, conf)
    if os.path.isfile(SERVICE_FILE):
        svc("restart")
        if not service_settled():
            print(f"[!] port saved as {port} but {SERVICE} did not come up - journalctl -u {SERVICE}")
            return
    print(f"[✔] port set to {port} — open http://{central_ip()}:{port}/")


def change_password():
    if not os.path.isfile(WEB_CONF):
        print("Not configured yet - run Install first.")
        return
    set_password(load_conf())
    if os.path.isfile(SERVICE_FILE):
        svc("restart")
        if not service_settled():
            print(f"[!] password saved but {SERVICE} did not come up - journalctl -u {SERVICE}")
            return
    print("[✔] password updated.")


def uninstall():
    if input("Uninstall the central panel? [y/N]: ").strip().lower() != "y":
        return
    svc("stop")
    svc("disable")
    subprocess.run(["systemctl", "disable", "--now", REDIS_SERVICE], capture_output=True)
    for path in (SERVICE_FILE, REDIS_UNIT_FILE):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    subprocess.run(["systemctl", "daemon-reload"])
    print(f"[✔] services removed (nodes, links and settings kept in {REDIS_DIR}; install again to use them).")


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


def cli_conf(loud=True):
    if not os.path.isfile(WEB_CONF):
        return {}
    try:
        return load_conf()
    except RegistryError as e:
        if loud:
            print("%s %s" % (WARN, e))
            print("    the panel settings below are replaced by what you type now.")
        return {}


def status():
    exists = os.path.isfile(SERVICE_FILE)
    conf = cli_conf(False)
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
    try:
        fleet = "%d nodes %s %d links" % (len(load_nodes()), dim("/"), len(load_links()))
    except RegistryError as e:
        fleet = red(str(e))
    print("  %s  %s" % (dim("fleet  "), fleet))


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

_BUSY_BODY = json.dumps({"code": 503, "error": "busy", "message": "the panel is busy — try again in a moment"}).encode()
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
    global _CENTRAL_PORT, _CENTRAL_TLS
    try:
        conf = load_conf()
    except RegistryError as e:
        print("tnl-central did not start - %s" % e)
        print("fix or remove that file, then run the setup menu:  sudo python3 tnl-central.py")
        sys.exit(1)
    try:
        store_boot(wait=60)
        _stats_boot()
        events_boot()
    except Exception as e:
        print("tnl-central did not start - %s" % _store_msg(e))
        sys.exit(1)
    _backup_unstage()
    _CENTRAL_PORT = int(conf.get("port", 8080))
    _CENTRAL_TLS = bool(conf.get("tls"))
    try:
        _signing_keys()
    except Exception as e:
        print(f"warning: could not init signing key (openssl missing?): {e}")
    _store_health()
    threading.Thread(target=_ev_writer_loop, daemon=True).start()
    threading.Thread(target=poller_loop, daemon=True).start()
    threading.Thread(target=traffic_persist_loop, daemon=True).start()
    threading.Thread(target=reconcile_loop, daemon=True).start()
    threading.Thread(target=events_loop, daemon=True).start()
    threading.Thread(target=ech_refresh_loop, daemon=True).start()
    httpd = BoundedThreadingHTTPServer(("0.0.0.0", int(conf.get("port", 8080))), Handler)
    httpd.conf = conf
    print(f"tnl-central on http://0.0.0.0:{conf.get('port', 8080)}/")
    signal.signal(signal.SIGTERM, _stop_on_term)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _flush_on_stop()


def _stop_on_term(signum, frame):
    raise KeyboardInterrupt


def _flush_on_stop():
    try:
        for _ in range(50):
            if not _ev_out or not _ev_drain():
                break
    except Exception:
        log_internal("events on stop")
    try:
        _persist_stats()
    except Exception:
        log_internal("persist on stop")


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
