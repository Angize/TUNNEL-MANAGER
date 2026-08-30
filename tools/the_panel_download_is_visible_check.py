#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: while the panel is downloading the core, the row says so, moves, and can be stopped.

In «نود از پنل» and «پنل آپلود کند» the panel must hold the binary, so the first thing an install job
does is pull ~21 MB from github. Measured on the live panel that is about four seconds in which the row
under the button said «در نوبت» and then «در حالِ بررسی», neither of which is true, at 0%, with a cancel
button that could not reach the transfer because the download was one uninterruptible read().

Three claims, and all three are about what the OPERATOR can see and do:

  * the step is named for what is happening -- `stage`, not `check`, and never `wait`;
  * the bar moves while the bytes arrive, in step with them, and reaches the end of its phase;
  * pressing cancel mid-transfer really stops the read, the node ends up `skip`, and nothing is left
    half-staged on disk or half-recorded in the meta.

github delivery is asserted in the same run: it stages no bytes, so it must NOT put the operator
through a stage phase at all.

Exit 1 on any failure.
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, "..")))
PANEL = os.path.join(ROOT, "tnl-central.py")

FAILED = []
CORE = {"amd64": b"\x7fELF" + b"A" * 400000, "arm64": b"\x7fELF" + b"B" * 400000}
SHA = {a: hashlib.sha256(r).hexdigest() for a, r in CORE.items()}
CHUNKS = 20
PER_CHUNK = 0.05
NODES = [{"id": "n1", "name": "IR02", "host": "10.0.0.1", "port": 8099, "token": "t1"}]


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location("tnl_dlvis_check", PANEL)
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
        sys.exit("these panel paths still point at the real state dir: %s" % left)
    return m


class Slow:
    """A body that arrives in pieces, so should_abort has somewhere to bite."""

    def __init__(self, blob):
        self.blob = blob
        self.i = 0
        self.headers = {"Content-Length": str(len(blob))}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def getheader(self, k):
        return self.headers.get(k)

    def read(self, n=None):
        if self.i >= len(self.blob):
            return b""
        time.sleep(PER_CHUNK)
        step = max(1, len(self.blob) // CHUNKS)
        out = self.blob[self.i:self.i + step]
        self.i += len(out)
        return out


def wire(m, sent):
    m.save_json(m.NODES_FILE, [dict(n) for n in NODES])
    m.log_event = lambda *a, **k: None
    m._cached_ping = lambda nid: {"arch": "amd64", "sha256": "", "core_sha": "", "core_ver": ""}
    m._ensure_update_key = lambda node: None
    m.node_call = lambda node, ep, method="POST", body=None, timeout=8: {"ok": True, "arch": "amd64"}
    m._resolve_core_version = lambda v: v

    def push(node, endpoint, body, on_progress=None, timeout=None, chunk=65536, should_abort=None):
        if endpoint == "ping":
            return {"ok": True, "arch": "amd64", "sha256": "", "core_sha": "", "core_ver": ""}
        sent.append(endpoint)
        return {"ok": True}

    m.node_push = push

    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        arch = "arm64" if "arm64" in url else "amd64"
        if url.endswith(".sha256"):
            return Slow(SHA[arch].encode())
        return Slow(CORE[arch])

    m.urllib.request.urlopen = urlopen


def sample(m, jid, nid, seen, stop):
    while not stop.is_set():
        with m._push_lock:
            j = m._push_jobs.get(jid)
            v = dict(j["nodes"][nid]) if j and nid in j["nodes"] else None
        if v:
            key = (v.get("state"), v.get("step"), v.get("pct"))
            if not seen or seen[-1] != key:
                seen.append(key)
        time.sleep(0.02)


def run(m, arg, cancel_after=None):
    seen, sent_states = [], []
    r = m.api_update_core(arg)
    jid = r.get("job")
    stop = threading.Event()
    th = threading.Thread(target=sample, args=(m, jid, "n1", seen, stop), daemon=True)
    th.start()
    if cancel_after is not None:
        def kill():
            t = time.monotonic()
            while time.monotonic() - t < 20:
                if any(k[1] == "stage" and (k[2] or 0) >= cancel_after for k in seen):
                    m.api_push_cancel({"job": jid})
                    return
                time.sleep(0.02)
        threading.Thread(target=kill, daemon=True).start()
    t0 = time.monotonic()
    while time.monotonic() - t0 < 60:
        with m._push_lock:
            j = m._push_jobs.get(jid or "")
            if not j or j["done"]:
                break
        time.sleep(0.02)
    stop.set()
    th.join(timeout=2)
    with m._push_lock:
        j = m._push_jobs.get(jid or "")
        final = dict(j["nodes"]["n1"]) if j else {}
    return seen, final, sent_states


def main():
    state = tempfile.mkdtemp()
    m = load_panel(state)
    sent = []
    wire(m, sent)

    m.api_settings_set({"core_delivery": "panel"})
    t0 = time.monotonic()
    seen, final, _ = run(m, {"ids": ["n1"], "version": "v9.9.9"})
    full = time.monotonic() - t0
    steps = [k[1] for k in seen]
    stage_pcts = [k[2] for k in seen if k[1] == "stage"]

    check("the row is never told it is queued", "wait" not in [k[0] for k in seen], repr(seen[:4]))
    check("the step is named for the download, not for a check that is not happening",
          "stage" in steps and steps[0] in ("check", "stage"), repr(steps))
    check("  and the bar really moves while the bytes arrive",
          len(set(stage_pcts)) >= 5, "%d distinct percentages: %r" % (len(set(stage_pcts)), stage_pcts))
    check("  climbing, never going backwards", stage_pcts == sorted(stage_pcts), repr(stage_pcts))
    check("  and it gets to the end of its phase before the next step starts",
          max(stage_pcts or [0]) >= 30, "high water was %r" % (max(stage_pcts or [0]),))
    check("  then hands over to the steps that talk to the node",
          steps[-1] in ("install", "deliver", "check") and final.get("state") in ("ok", "same"),
          "%r %r" % (steps, final.get("state")))
    check("the binaries really landed on the panel",
          sorted(f for f in os.listdir(m.CORE_STAGE_DIR) if not f.endswith(".json"))
          == ["tnl-core-amd64", "tnl-core-arm64"], repr(os.listdir(m.CORE_STAGE_DIR)))

    for f in os.listdir(m.CORE_STAGE_DIR):
        os.remove(os.path.join(m.CORE_STAGE_DIR, f))
    if os.path.isfile(m.CORE_STAGE_META):
        os.remove(m.CORE_STAGE_META)
    sent[:] = []
    t0 = time.monotonic()
    seen, final, _ = run(m, {"ids": ["n1"], "version": "v9.9.9"}, cancel_after=3)
    took = time.monotonic() - t0
    check("cancel pressed mid-download really cuts the transfer",
          took < full * 0.5,
          "cancelled run took %.1fs; the same staging uninterrupted took %.1fs" % (took, full))
    check("  the node ends up skipped, not failed and not installed",
          final.get("state") == "skip", json.dumps(final, ensure_ascii=False))
    check("  nothing was pushed to it", not sent, repr(sent))
    check("  and no half-downloaded binary was left on the panel",
          not [f for f in os.listdir(m.CORE_STAGE_DIR) if not f.endswith(".json")],
          repr(os.listdir(m.CORE_STAGE_DIR)))
    check("  nor a meta claiming a version that is not there",
          (m._staged_info() or {}).get("version") != "v9.9.9",
          json.dumps(m._staged_info(), ensure_ascii=False))

    m.api_settings_set({"core_delivery": "github"})
    seen, final, _ = run(m, {"ids": ["n1"], "version": "v9.9.9"})
    check("github delivery stages no bytes, so it shows no download phase",
          "stage" not in [k[1] for k in seen] and final.get("state") in ("ok", "same"),
          "%r %r" % (seen, final.get("state")))

    print()
    if FAILED:
        print("%d failure(s)" % len(FAILED))
        return 1
    print("the operator sees the panel's own download, and can stop it while it runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
