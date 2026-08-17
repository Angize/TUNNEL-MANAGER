#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The three build paths must produce the SAME rotation fields, and none of them may name a knob.

The panel builds a node body three independent ways — CREATE and EDIT go through
_core_rotation_bodies, REBUILD calls _apply_core_rotation itself from op_rebuild's own loop — and a
change made on one of them has twice landed while the other two kept the old shape. So this drives all
three for real and diffs the dictionaries, instead of asserting against the helper they happen to share.

It also pins the negative: no rotation body may carry a burn-POLICY key. The node's tun probe is the
only judge of a burned endpoint, the core burns on its verdict unconditionally, and a config field that
looks like an off switch is one an older core would read as "never burn anything".

    python3 tools/rotation_paths_agree_check.py
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# Keys that must never appear in a rotation body on any path: a policy over the burn verdict.
POLICY = ("peer_auto_burn", "ws_auto_burn", "auto_burn")


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", ROOT / "tnl-central.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def rotation_of(body):
    """Just the rotation-owned fields, which is what the three paths have to agree about."""
    return {k: v for k, v in body.items()
            if k in ("peer_ips", "src_ips", "peer_rotate_secs", "peer_auto_burn",
                     "pool_listen", "listen_ips", "peer_src_ips")}


def main():
    P = load_panel()
    fails = []
    A_IPS, B_IPS = ["1.1.1.1", "1.1.1.2"], ["2.2.2.2", "2.2.2.3"]

    for tr in P.DIRECT_TRANSPORTS:
        link = {"ip_rotate": True, "transport": tr, "type": "core",
                "a_ip_pool": A_IPS, "b_ip_pool": B_IPS, "rotate_secs": 600}

        # CREATE / EDIT: both reach the node body through _core_rotation_bodies.
        a_ce = {"role": "server", "transport": tr}
        b_ce = {"role": "client", "transport": tr}
        P._core_rotation_bodies(link, a_ce, b_ce)

        # REBUILD: op_rebuild loops the two ends and calls _apply_core_rotation directly.
        a_rb = {"role": "server", "transport": tr}
        b_rb = {"role": "client", "transport": tr}
        rs = max(0, min(86400, int(link.get("rotate_secs") or 0)))
        P._apply_core_rotation(a_rb, False, A_IPS, B_IPS, rs)
        P._apply_core_rotation(b_rb, True, B_IPS, A_IPS, rs)

        for side, ce, rb in (("server", a_ce, a_rb), ("client", b_ce, b_rb)):
            got_ce, got_rb = rotation_of(ce), rotation_of(rb)
            same = got_ce == got_rb
            print(("  ok   " if same else " FAIL ") + f"{tr:5} {side:6}: create/edit == rebuild")
            if not same:
                fails.append(f"{tr}/{side}: create/edit {got_ce} != rebuild {got_rb}")
            for body, path in ((ce, "create/edit"), (rb, "rebuild")):
                leaked = [k for k in POLICY if k in body]
                if leaked:
                    fails.append(f"{tr}/{side}/{path}: carries a burn-policy key {leaked}")

    # The CDN pool is the same question on its own two paths: _ws_pool_fields stores it, _tunnel_extra
    # replays it into a node body on a rebuild. Both used to carry the knob.
    stored = P._ws_pool_fields(
        {"ws_pool": True, "ws_edge_ips": ["1.2.3.4:443", "5.6.7.8:443"],
         "ws_edge_snis": [{"host": "a.example.com", "ech": "", "path": "/"}],
         "ws_rotate_secs": 600, "ws_path": "/"}, {})
    replayed = P._tunnel_extra(dict(stored, transport="ws", type="core"), refetch_ech=False)
    for name, d in (("_ws_pool_fields", stored), ("_tunnel_extra", replayed)):
        leaked = [k for k in POLICY if k in d]
        print(("  ok   " if not leaked else " FAIL ") + f"cdn   {name}: no burn-policy key")
        if leaked:
            fails.append(f"cdn/{name}: carries {leaked}")

    # The stored link record must not carry one either — that is where a rebuild would read it back from.
    for k in POLICY:
        if k in P._ROTATION_KEYS:
            fails.append(f"_ROTATION_KEYS still carries {k}, so it would be stored and replayed")

    print()
    if fails:
        print("FAILURES:")
        for f in fails:
            print("  - " + f)
        return 1
    print("all three paths agree, and no burn-policy key reaches a node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
