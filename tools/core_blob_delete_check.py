#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the uploaded core binary can be thrown away, and throwing it away really removes the choice.

Driven against the shipped endpoints with NOTHING stubbed -- not the event log, not the filesystem, only
the panel's state directory pointed at a temp dir. The bug this replaces reached the operator precisely
because a harness had stubbed `log_event` out: the endpoint was exercised end to end and the one wrong
call in it was replaced by a lambda that accepts anything.

    python3 tools/core_blob_delete_check.py
"""
import argparse
import base64
import importlib.util
import os
import shutil
import sys
import tempfile
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(panel, state):
    spec = importlib.util.spec_from_file_location("tnl_blob_del", panel)
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


def refuses(fn, arg, word):
    try:
        fn(arg)
        return False, "no error raised"
    except ValueError as e:
        return word in str(e), str(e)


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    state = tempfile.mkdtemp(prefix="tnl-blob-del-")
    try:
        m = load(str(a.panel), state)
        m.save_json(m.NODES_FILE, [{"id": "n1", "name": "N1", "host": "10.0.0.1", "port": 8099, "token": "t"}])

        ok, msg = refuses(m.api_core_delete_blob, {}, "بارگذاری")
        check("deleting nothing refuses, and says what is missing", ok, msg)

        raw = b"\x7fELF" + b"x" * 300000
        m.api_core_upload({"data": base64.b64encode(raw).decode(), "name": "tnl-core-linux-amd64"})
        check("the upload is on disk", os.path.isfile(m.CORE_BLOB) and os.path.isfile(m.CORE_BLOB_META))
        ids = [v["id"] for v in m.api_core_versions({})["versions"]]
        check("...and offered as its own choice", "custom" in ids, str(ids))

        before = len(m.load_events())
        r = m.api_core_delete_blob({})
        check("the delete answers ok", r.get("ok") is True, str(r))
        check("both files are gone", not os.path.isfile(m.CORE_BLOB) and not os.path.isfile(m.CORE_BLOB_META))
        ids = [v["id"] for v in m.api_core_versions({})["versions"]]
        check("the choice is gone from the version list", "custom" not in ids, str(ids))

        # the real log_event, not a stub: a wrong call shape here raises instead of passing quietly
        evs = m.load_events()
        check("it is written to the event log", len(evs) == before + 1, "%d -> %d" % (before, len(evs)))
        if evs:
            check("...at a severity the events page paints", evs[0].get("level") in ("ok", "warn", "bad"),
                  repr(evs[0].get("level")))
            check("...with a Persian title, under the core kind",
                  evs[0].get("kind") == "core" and any("؀" <= c <= "ۿ" for c in evs[0].get("fa", "")),
                  repr(evs[0])[:120])

        ok, msg = refuses(m.api_core_delete_blob, {}, "بارگذاری")
        check("deleting it twice refuses the second time", ok, msg)
        ok, msg = refuses(m.api_update_core, {"ids": ["n1"], "version": "custom"}, "بارگذاری")
        check("and installing «custom» afterwards refuses rather than pushing a stale file", ok, msg)
    finally:
        shutil.rmtree(state, ignore_errors=True)

    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("the uploaded binary can be deleted, and deleting it removes the choice with it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
