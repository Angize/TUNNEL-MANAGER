#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: «دریافت از گیت‌هاب» reports how far it has got, and stops when told to.

The button pulled ~21 MB and said one static sentence for the whole of it -- «در حال دانلودِ هسته روی
پنل…» -- with nothing to press if the operator changed their mind or picked the wrong version. The
request was synchronous, so there was nowhere to hang a percentage or a cancel even in principle.

It is a job now. What that has to buy the operator:

  * the call comes back at once with a job, not after the bytes;
  * status climbs while the bytes arrive and lands on done with the version and arches;
  * cancel mid-transfer really cuts the read, is reported as cancelled, and leaves NOTHING behind --
    no half file, no meta naming a version that was never staged;
  * a second fetch started on top of a live one is refused rather than racing it into the same files;
  * github delivery stages no bytes, so it must still answer in one call, with no job to poll.

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
CHUNKS = 16
PER_CHUNK = 0.05


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load_panel(state):
    spec = importlib.util.spec_from_file_location("tnl_fetchbtn_check", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit("these panel paths still point at the real state dir: %s" % left)
    return m


class Slow:
    def __init__(self, blob):
        self.blob, self.i = blob, 0
        self.headers = {"Content-Length": str(len(blob))}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self, n=None):
        if self.i >= len(self.blob):
            return b""
        time.sleep(PER_CHUNK)
        step = len(self.blob) if n is None else max(1, len(self.blob) // CHUNKS)
        out = self.blob[self.i:self.i + step]
        self.i += len(out)
        return out


def wire(m):
    m.log_event = lambda *a, **k: None
    m._resolve_core_version = lambda v: v

    def urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        arch = "arm64" if "arm64" in url else "amd64"
        return Slow(SHA[arch].encode() if url.endswith(".sha256") else CORE[arch])

    m.urllib.request.urlopen = urlopen


def watch(m, seen, stop):
    while not stop.is_set():
        v = m.api_core_stage_status({})
        if not seen or seen[-1] != v["pct"]:
            seen.append(v["pct"])
        if v["done"]:
            return
        time.sleep(0.02)


def drain(m, limit=60.0):
    t = time.monotonic()
    while time.monotonic() - t < limit:
        v = m.api_core_stage_status({})
        if v["done"]:
            return v
        time.sleep(0.02)
    return m.api_core_stage_status({})


def blobs(m):
    return sorted(f for f in os.listdir(m.CORE_STAGE_DIR) if not f.endswith(".json"))


def main():
    m = load_panel(tempfile.mkdtemp())
    wire(m)
    m.api_settings_set({"core_delivery": "panel"})

    seen, stop = [], threading.Event()
    t0 = time.monotonic()
    r = m.api_core_stage({"version": "v9.9.9"})
    answered = time.monotonic() - t0
    th = threading.Thread(target=watch, args=(m, seen, stop), daemon=True)
    th.start()
    final = drain(m)
    full = time.monotonic() - t0
    stop.set()
    th.join(timeout=2)

    check("the button is answered at once, with a job, not after the download",
          answered < 0.3 and r.get("job") and r.get("done") is False,
          "answered in %.2fs -> %s" % (answered, json.dumps(r, ensure_ascii=False)))
    check("the percentage climbs while the bytes arrive",
          len(set(seen)) >= 5 and seen == sorted(seen), "%d distinct: %r" % (len(set(seen)), seen))
    check("  and it ends done, naming the version and the arches it got",
          final["done"] and not final["err"] and final["version"] == "v9.9.9"
          and sorted(final["arches"]) == ["amd64", "arm64"], json.dumps(final, ensure_ascii=False))
    check("  with both binaries really on disk",
          blobs(m) == ["tnl-core-amd64", "tnl-core-arm64"], repr(blobs(m)))

    for f in os.listdir(m.CORE_STAGE_DIR):
        os.remove(os.path.join(m.CORE_STAGE_DIR, f))
    if os.path.isfile(m.CORE_STAGE_META):
        os.remove(m.CORE_STAGE_META)

    t0 = time.monotonic()
    m.api_core_stage({"version": "v9.9.9"})
    try:
        m.api_core_stage({"version": "v9.9.9"})
        second, why = False, "a second fetch was accepted"
    except ValueError as e:
        second, why = "در جریان" in str(e), str(e)

    while m.api_core_stage_status({})["pct"] < 5 and time.monotonic() - t0 < 20:
        time.sleep(0.02)
    m.api_core_stage_cancel({})
    final = drain(m)
    took = time.monotonic() - t0

    check("a second fetch started on top of a live one is refused, not raced", second, why)
    check("cancel really cuts the transfer",
          took < full * 0.6, "cancelled after %.1fs; the same fetch uninterrupted took %.1fs" % (took, full))
    check("  and says it was cancelled, in Persian", final["done"] and "لغو" in final["err"],
          json.dumps(final, ensure_ascii=False))
    check("  leaving no half-downloaded binary behind", blobs(m) == [], repr(blobs(m)))
    check("  and no meta naming a version that was never staged",
          (m._staged_info() or {}).get("version") != "v9.9.9",
          json.dumps(m._staged_info(), ensure_ascii=False))
    check("  and the next fetch is allowed again",
          m.api_core_stage_status({})["done"] is True)

    m.api_settings_set({"core_delivery": "github"})
    r = m.api_core_stage({"version": "v9.9.9"})
    check("github delivery still answers in one call, with nothing to poll",
          r.get("done") is True and r.get("meta_only") is True and not r.get("job")
          and blobs(m) == [], json.dumps(r, ensure_ascii=False))

    print()
    if FAILED:
        print("%d failure(s)" % len(FAILED))
        return 1
    print("the fetch button shows how far it has got, and stops when told")
    return 0


if __name__ == "__main__":
    sys.exit(main())
