#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every path that builds a node body must apply every per-body core helper — all four of them.

There are FOUR builders, not three: create (_create_tunnel_impl), edit (_edit_link_impl), rebuild
(_rebuild_link_impl) and rollback (_restore_link). `workers` is stripped from the shared body by
_node_extra and re-added per body by _core_workers_bodies, and _restore_link was the one path that
never called it — so any failed edit or rebuild silently brought a 4-queue tunnel back on one queue,
with links.json and the dashboard still saying 4.

This is the shape of the bug, not the bug: a knob is added, three of four call sites learn about it,
and the fourth is found months later. So this drives the rollback path for real AND pins the class
statically: if a fifth helper or a fifth builder appears, every builder must still call every helper.

    python3 tools/every_build_path_carries_workers_check.py
"""
import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

BUILDERS = ("_create_tunnel_impl", "_edit_link_impl", "_rebuild_link_impl", "_restore_link")
HELPERS = ("_core_rotation_bodies", "_core_workers_bodies", "_apply_core_tuning", "_apply_probe_tuning")


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def calls_in(fn):
    out = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            out.add(node.func.id)
    return out


def static_pass(fails):
    tree = ast.parse(PANEL.read_text(encoding="utf-8"))
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    for name in BUILDERS:
        fn = fns.get(name)
        if fn is None:
            fails.append(f"{name} is gone; this check no longer covers the path it was written for")
            continue
        called = calls_in(fn)
        missing = [h for h in HELPERS if h not in called]
        print(("  ok   " if not missing else " FAIL ") + f"{name}: calls {len(HELPERS)-len(missing)}/{len(HELPERS)} helpers")
        if missing:
            fails.append(f"{name} never calls {missing} — that knob is dropped on this path")


def link_record():
    return {"type": "core", "transport": "udp", "name": "t1", "subnet": "10.20.30.0/24",
            "a_ip": "10.20.30.1", "b_ip": "10.20.30.2", "tunnel_id": 7,
            "a_node": 1, "b_node": 2, "server_side": "a", "enabled": True,
            "port": 5555, "psk": "0123456789abcdef0123456789abcdef",
            "cipher": "aes-256-gcm", "obfs": True,
            "ip_rotate": True, "rotate_secs": 600,
            "a_ip_pool": ["1.1.1.1", "1.1.1.2"], "b_ip_pool": ["2.2.2.2", "2.2.2.3"],
            "a_workers": 4, "b_workers": 4}


def live_pass(P, fails):
    sent = []
    P.node_call = lambda N, path, method, body=None, **kw: sent.append((N["id"], dict(body or {}))) or {"ok": True}
    P._settings_tuning = lambda: {}

    L = link_record()
    A, B = {"id": 1, "name": "A"}, {"id": 2, "name": "B"}
    extra = P._tunnel_extra(L, refetch_ech=False)

    P._restore_link(A, B, L, extra)
    got = dict(sent)
    if len(got) != 2:
        fails.append(f"the rollback POSTed {len(got)} bodies, want 2")
        return

    a_rb = {"type": "core", "role": "server", "transport": "udp"}
    b_rb = {"type": "core", "role": "client", "transport": "udp"}
    P._core_rotation_bodies(L, a_rb, b_rb)
    P._core_workers_bodies(L, a_rb, b_rb)
    P._apply_core_tuning(a_rb, b_rb)
    P._apply_probe_tuning(a_rb, b_rb)

    for nid, want in ((1, a_rb), (2, b_rb)):
        body = got[nid]
        for k, v in want.items():
            if k in ("type", "transport"):
                continue
            same = body.get(k) == v
            print(("  ok   " if same else " FAIL ") + f"rollback node {nid}: {k} = {body.get(k)!r}")
            if not same:
                fails.append(f"rollback node {nid}: {k} is {body.get(k)!r}, the other paths send {v!r}")

    for nid in (1, 2):
        if got[nid].get("workers") != 4:
            fails.append(f"rollback node {nid} came back with workers={got[nid].get('workers')!r}, "
                         f"not the 4 the operator set")


def main():
    fails = []
    static_pass(fails)
    print()
    live_pass(load_panel(), fails)
    print()
    if fails:
        print("FAILURES:")
        for f in fails:
            print("  - " + f)
        return 1
    print("all four build paths apply all four core-body helpers, and a rollback keeps workers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
