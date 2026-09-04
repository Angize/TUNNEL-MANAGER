#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the panel does not re-download a core it already holds, and the cards say what is happening.

Reported from the fleet screen: every node card read «دانلودِ هستهٔ روی پنل · گامِ ۱ از ۳ · ۰٪» while
the version the operator had picked was already downloaded on the panel. Three separate things made
that one screen, and each is checked here:

  1. `staged = {"done": not version}` -- staging was skipped only when NO version was named, and the
     form always names one (corPushAll refuses to start without it). So pushing the version the panel
     had just downloaded fetched both architectures from GitHub again, ~21 MB, before sending anything.

  2. The staging step is ONE shared, panel-side download, but `ensure(ctx)` ran per node and set the
     step on every one of them. Only the node that won the lock passed its `ctx.progress` to
     `_stage_core`, so that one card moved and all the others sat at 0% under the same words -- eight
     cards claiming to be downloading, one download.

  3. In `github` delivery mode the panel downloads NOTHING: `_stage_core_meta` writes a meta file and
     the nodes fetch from GitHub themselves. The step still said «دانلودِ هسته روی پنل».

The staging is driven for real -- `_stage_core` and `_stage_core_meta` are stubbed at the module, which
is where the panel itself calls them, and the step names are read back out of the job the push machinery
actually wrote.

    python3 tools/the_staging_step_tells_the_truth_check.py
"""
import importlib.util
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
fails = []
VER = "v2.109.0"


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "  -- %r" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel(state, tag):
    spec = importlib.util.spec_from_file_location("tnl_stage_" + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    return m


def seed_nodes(m, n):
    m.save_json(m.NODES_FILE, [{"id": "n%d" % i, "name": "N%d" % i, "host": "10.0.0.%d" % i,
                                "port": 8099, "token": "t" * 20} for i in range(n)])


def stage_on_disk(m, version, meta_only=False):
    """Put a staged core on the panel the way _stage_core leaves one."""
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    arches = list(m.CORE_ARCHES)
    if not meta_only:
        for a in arches:
            m.save_bytes(os.path.join(m.CORE_STAGE_DIR, "tnl-core-%s" % a), b"x" * 32)
    m.save_json(m.CORE_STAGE_META, {"version": version, "arches": arches,
                                    "sha": {a: "0" * 64 for a in arches} if not meta_only else {},
                                    "size": {}, "ts": int(time.time()),
                                    **({"meta_only": True} if meta_only else {})})


def run_update(m, mode, version, nodes=3, staged_version=None, staged_meta_only=False,
               stage_takes=0.0):
    """Drive api_update_core and hand back what the push job recorded per node."""
    seed_nodes(m, nodes)
    m.get_settings = lambda: {"core_delivery": mode}
    if staged_version:
        stage_on_disk(m, staged_version, meta_only=staged_meta_only)

    called = {"stage": 0, "meta": 0}
    seen_steps = {}
    gate = threading.Event()

    def fake_stage(v, on_progress=None, should_abort=None):
        called["stage"] += 1
        if stage_takes:
            if on_progress:
                on_progress(31, 100)
            gate.wait(stage_takes)
        stage_on_disk(m, v)
        return {"version": v, "arches": list(m.CORE_ARCHES), "missing": []}

    def fake_meta(v):
        called["meta"] += 1
        stage_on_disk(m, v, meta_only=True)
        return {"version": v, "arches": list(m.CORE_ARCHES), "missing": []}

    m._stage_core = fake_stage
    m._stage_core_meta = fake_meta
    m._node_arch = lambda n: "amd64"
    m._ensure_update_key = lambda n: None
    m._core_delivery_check = lambda *a, **k: None
    m._github_grant = lambda ver, arch: {"version": ver, "arch": arch}

    real_set = m._push_set

    def spy(jid, nid, **kw):
        if "step" in kw:
            seen_steps.setdefault(nid, []).append(kw["step"])
        real_set(jid, nid, **kw)
    m._push_set = spy

    # every node answers, and reports itself already current so the push settles at the check step
    def node_push(node, endpoint, body, **kw):
        time.sleep(0.02)
        return {"ok": True, "arch": "amd64", "core_ver": VER, "sha256": "0" * 64}
    m.node_push = node_push

    jid = m.api_update_core({"ids": [n["id"] for n in m.load_nodes()], "version": version})["job"]
    for _ in range(400):
        if m._push_jobs[jid]["done"]:
            break
        gate.set()
        time.sleep(0.05)
    gate.set()
    return called, seen_steps, m._push_jobs[jid]["nodes"]


def main():
    print("== the version is already on the panel: it is NOT downloaded again ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "already")
        called, steps, _ = run_update(m, "push", VER, nodes=3, staged_version=VER)
        check(called["stage"] == 0,
              "_stage_core is never called -- the operator's own words: «اون نسخه که انتخاب کردم "
              "رو پنل دانلود شده»", called)
        flat = [s for v in steps.values() for s in v]
        check("stage" not in flat,
              "and no card claims the panel is downloading anything", sorted(set(flat)))

    print("== a DIFFERENT version really is fetched, once, and only the fetcher says so ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "other")
        called, steps, _ = run_update(m, "push", "v2.200.0", nodes=4, staged_version=VER,
                                      stage_takes=0.25)
        check(called["stage"] == 1, "the panel downloads it exactly once for the whole fleet", called)
        downloading = [nid for nid, v in steps.items() if "stage" in v]
        waiting = [nid for nid, v in steps.items() if "stagewait" in v]
        check(len(downloading) == 1,
              "ONE card says «دانلودِ هسته روی پنل» -- there is one download", downloading)
        check(bool(waiting) and not (set(waiting) & set(downloading)),
              "the others say they are WAITING for it, instead of showing 0% of a download that is "
              "not theirs", {"waiting": waiting, "downloading": downloading})

    print("== github delivery: the panel downloads nothing, and does not say it does ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "gh")
        called, steps, _ = run_update(m, "github", "v2.200.0", nodes=3)
        check(called["stage"] == 0 and called["meta"] == 1,
              "only the meta is written -- the nodes fetch from GitHub themselves", called)
        flat = [s for v in steps.values() for s in v]
        check("stage" not in flat,
              "so no card says «دانلودِ هسته روی پنل»", sorted(set(flat)))

    print("== github delivery, and the meta already names that version ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "ghsame")
        called, steps, _ = run_update(m, "github", VER, nodes=2,
                                      staged_version=VER, staged_meta_only=True)
        check(called["meta"] == 0, "nothing is re-staged", called)

    print("== a meta-only stage is NOT enough for push delivery, which needs the bytes ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "metaonly")
        called, steps, _ = run_update(m, "push", VER, nodes=2,
                                      staged_version=VER, staged_meta_only=True)
        check(called["stage"] == 1,
              "the binaries are fetched, because github mode had only recorded the version", called)

    print("== the label the operator reads exists ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "i18n")
        js = m.INDEX_HTML
        check("ups_stagewait" in js, "ups_stagewait is defined, or the card renders a raw key")

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
