# -*- coding: utf-8 -*-
"""Guard: the tun-probe threshold reaches the node body, on every build path and every tunnel TYPE.

probe_min_pct is the one Settings knob the NODE consumes rather than forwards: tnl-node.py's health_of
reads it off the persisted config to decide whether a tunnel is carrying, which colours the dot and
decides whether an endpoint is burned or has its burn cleared. A path that forgets to stamp it leaves
that tunnel judged by the node's compiled-in default, silently, while Settings shows the operator's
number.

Two things make this its own guard rather than a case in config_contract.py:

  * config_contract drives _core_extra/_node_extra, and the stamping does NOT live there -- it happens
    at the four sites that assemble a_body/b_body. A green config_contract says nothing about it.
  * the knob applies to EVERY type, so it is stamped OUTSIDE the `if ttype == "core"` blocks that guard
    every other fleet-wide setting. That is exactly the kind of line a later edit folds back inside.

FOUR paths, not three: create, edit, rebuild, and the rollback restore -- which builds a node body of
its own and is the one everybody forgets, on the very path where the operator is already reading an
error about something else.

Exit 1 on any gap.
"""
import importlib.util
import os
import sys

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):   # Persian can appear in a failure message on a cp1252 console
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tnl-central.py")

A_ID, B_ID = 1, 2
A_IP, B_IP = "203.0.113.5", "198.51.100.7"
NODES = [{"id": A_ID, "name": "IR01", "host": A_IP}, {"id": B_ID, "name": "DE01", "host": B_IP}]
PCT = 42          # deliberately not the default, so "stamped" and "left alone" cannot look alike

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_central_probe", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def wire(P, links, tuning):
    """Capture every node body the panel sends. `tuning` is what Settings holds."""
    sent = []
    P.load_links = lambda: [dict(x) for x in links]
    P.get_node = lambda nid: next((n for n in NODES if n["id"] == nid), None)
    P._ping_both = lambda A, B: ({"ips": {"eth0": [A_IP]}}, {"ips": {"eth0": [B_IP]}})
    # This guard is not about the readiness gate; give it a panel that already holds both artifacts
    # so _gate_ready runs for real and passes, instead of stubbing the gate itself away.
    P._readiness = lambda: {"agent": True, "core": True, "core_missing": [],
                            "core_version": "v0.0.0", "ok": True}
    P._refresh_cache = lambda nids: None
    P._push_staged = lambda n: {"ok": True}
    P.get_settings = lambda: {"tuning": dict(tuning)}

    def node_call(node, op, method="GET", body=None, timeout=None, **kw):
        if op == "list":
            return {"configs": []}
        if op == "tunnel":
            sent.append(dict(body or {}))
        return {"ok": True}
    P.node_call = node_call
    P._node_tunnel = lambda node, body: (sent.append(dict(body)), {"ok": True, "tunnel_ip": "x"})[1]
    P.save_json = lambda path, obj: links.__setitem__(slice(None), [dict(x) for x in obj]) \
        if path == P.LINKS_FILE else None
    return sent


def link_rec(P, ttype, tid):
    rec = {"id": 7, "tunnel_id": tid, "name": P.tunnel_name(ttype, tid), "type": ttype,
           "a_node": A_ID, "b_node": B_ID, "a_ip": A_IP, "b_ip": B_IP,
           "subnet": P.subnet_default(ttype, tid), "enabled": True}
    if ttype == "core":
        rec.update({"port": 20001, "server_side": "a", "cipher": "auto", "transport": "udp",
                    "psk": "x" * 44})
    return rec


def create_req(ttype, tid):
    req = {"a_node": A_ID, "b_node": B_ID, "type": ttype, "id": tid}
    if ttype == "core":
        req.update({"transport": "udp", "cipher": "auto", "server_side": "a"})
    return req


def edit_req(P, ttype, tid):
    # The edit must actually CHANGE something. A non-core edit that changes nothing short-circuits with
    # {"unchanged": True} and never builds a body at all -- deliberate, so a no-op save costs no outage
    # -- and a guard that did not notice would be asserting over an empty list and calling it a pass.
    req = {"id": 7, "type": ttype, "a_node": A_ID, "b_node": B_ID,
           "subnet": P.subnet_default(ttype, tid + 1)}
    if ttype == "core":
        req.update({"transport": "udp", "cipher": "auto", "server_side": "a"})
    return req


def run_path(path, ttype, tid, tuning):
    """Drive ONE real build path and return every node body it produced."""
    P = load()
    links = [] if path == "create" else [link_rec(P, ttype, tid)]
    sent = wire(P, links, tuning)
    if path == "create":
        P._create_tunnel_impl(create_req(ttype, tid))
    elif path == "edit":
        P.api_edit_link(edit_req(P, ttype, tid))
    elif path == "rebuild":
        P._rebuild_link_impl({"id": 7})
    else:   # the rollback restore, which builds a body of its own
        L = link_rec(P, ttype, tid)
        P._restore_link(P.get_node(A_ID), P.get_node(B_ID), L)
    return sent


def main():
    # Every type the node accepts. The probe addresses them all, so a vxlan and a core tunnel on one
    # dashboard must be coloured -- and have their endpoints burned -- by the same rule.
    TYPES = ["core", "vxlan", "gre", "ipip", "l2tpv3", "fou"]
    PATHS = ["create", "edit", "rebuild", "restore"]

    print("== the operator set %d%%: every path, every type, must carry it ==" % PCT)
    for ttype in TYPES:
        for i, path in enumerate(PATHS):
            try:
                sent = run_path(path, ttype, 40 + i, {"probe_min_pct": PCT})
            except Exception as e:
                check(False, "%-7s %-8s BUILD FAILED: %s: %s" % (path, ttype, type(e).__name__, e))
                continue
            if not sent:
                check(False, "%-7s %-8s sent no node body at all -- this guard is reading the wrong "
                             "place and must not report success" % (path, ttype))
                continue
            bad = [b.get("probe_min_pct", "<missing>") for b in sent if b.get("probe_min_pct") != PCT]
            check(not bad, "%-7s %-8s all %d node bodies carry probe_min_pct=%d%s"
                  % (path, ttype, len(sent), PCT,
                     "" if not bad else " -- got %r; the node falls back to its own default and the "
                                        "operator's number is silently ignored" % (bad,)))

    print()
    print("== an untouched fleet stamps NOTHING, so the node keeps its own default ==")
    # Stamping the default anyway would be harmless today but pins the panel's number onto every stored
    # config, so a later change of the node default could never reach a tunnel nobody rebuilt.
    for ttype in ("core", "vxlan"):
        sent = run_path("create", ttype, 60, {})
        leaked = [b.get("probe_min_pct") for b in sent if "probe_min_pct" in b]
        check(not leaked, "%-8s create with Settings at default sends no probe_min_pct%s"
              % (ttype, "" if not leaked else " -- got %r" % (leaked,)))

    print()
    print("== and it is NOT smuggled into the core's `tuning` object, which the core would reject ==")
    # The core has no such knob. It rides top-level precisely so the panel<->core tuning contract
    # (tools/tuning_consistency.py) keeps meaning what it says.
    sent = run_path("create", "core", 61, {"probe_min_pct": PCT})
    inside = [b["tuning"] for b in sent if isinstance(b.get("tuning"), dict)
              and "probe_min_pct" in b["tuning"]]
    check(not inside, "probe_min_pct stays out of the `tuning` object%s"
          % ("" if not inside else " -- found it in %r" % (inside,)))

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the operator's probe threshold reaches every node body, on every path and every type.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
