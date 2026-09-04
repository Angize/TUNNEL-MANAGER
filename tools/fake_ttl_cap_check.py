#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake_ttl means two different things depending on the carrier, and every layer must say the same one.

    raw                  the decoy is a whole forged IPv4 packet aimed at a peer we hold no kernel
                         connection to, so the operator's hop budget is honoured verbatim: 1..255.
    tcp / ws             the decoy is a TCP segment INJECTED on the real connection's 4-tuple. A
                         well-formed one that actually reached the server would draw an RST or a
                         challenge-ACK and disturb the live flow, so core's specsTCP clamps it to
                         injectMaxTTL no matter what was configured.

The clamp is right; silence about it is not — every layer the operator can see must report the number
that actually flies. Two things are checked, because either alone can rot:

  1) the panel's ceiling IS core's injectMaxTTL, read out of core rather than copied. A constant
     duplicated across two repositories with no guard is a constant that will drift.
  2) all THREE panel build paths (create / edit / rebuild) clamp on the injecting carriers and DO NOT
     clamp on the forging ones. A gate added to one path says nothing about the other two.

    python3 tools/fake_ttl_cap_check.py
"""
import argparse
import ast
import importlib.util
import re
import sys
from pathlib import Path

A_IP, B_IP = "203.0.113.5", "198.51.100.7"
A_IPS, B_IPS = [A_IP, "203.0.113.6"], [B_IP, "198.51.100.8"]

# The carriers that support desync at all, and whether the core clamps their decoy TTL.
CARRIERS = [
    ("tcp", True),
    ("ws", True),
    ("raw", False),
]

# A TTL well above the cap, so a clamped path and an unclamped one cannot produce the same number.
ASKED = 30


def panel_const(src, name):
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    raise KeyError(name)


def load_panel(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def base_req(transport):
    req = {"transport": transport, "cipher": "auto",
           "fake_desync": True, "fake_ttl": ASKED, "fake_count": 2, "fake_mode": "ttl"}
    if transport == "ws":
        req.update(ws_host="cdn.example.com", ws_path="/", ws_tls=True)
    if transport == "raw":
        req.update(raw_profile="bare")
    return req


def three_paths(P, req):
    """fake_ttl in the node body as built by create, edit and rebuild."""
    ce, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
    create = P._node_extra(ce)
    stored = dict(ce)
    stored["type"] = "core"
    stored["transport"] = req["transport"]
    # An edit that resends everything, and a PARTIAL edit that resends nothing but the toggle — the
    # second is the one that falls back to the stored value, i.e. the path a clamp can miss.
    ce_full, _ = P._core_extra(dict(req), dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    partial = dict(req)
    partial.pop("fake_ttl")
    ce_part, _ = P._core_extra(partial, dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    return {
        "create": create.get("fake_ttl"),
        "edit (full)": P._node_extra(ce_full).get("fake_ttl"),
        "edit (partial)": P._node_extra(ce_part).get("fake_ttl"),
        "rebuild": P._tunnel_extra(dict(stored), refetch_ech=False).get("fake_ttl"),
    }


def main():
    here = Path(__file__).resolve()
    panel_root = here.parent.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=panel_root / "tnl-central.py")
    ap.add_argument("--core", default=panel_root.parent / "TUNNEL-MANAGER-CORE")
    a = ap.parse_args()

    panel_src = Path(a.panel).read_text(encoding="utf-8")
    desync_go = (Path(a.core) / "internal" / "packet" / "desync.go").read_text(encoding="utf-8")
    failures = []

    # 1) the ceiling is core's, not a number that happens to match today.
    m = re.search(r"^const injectMaxTTL = (\d+)$", desync_go, re.M)
    if not m:
        failures.append("could not find `const injectMaxTTL = N` in core's internal/packet/desync.go — "
                        "this check cannot read its authority, so it must not report success")
        core_cap = None
    else:
        core_cap = int(m.group(1))
        panel_cap = panel_const(panel_src, "DESYNC_INJECT_TTL_MAX")
        if panel_cap != core_cap:
            failures.append("panel DESYNC_INJECT_TTL_MAX=%r but core injectMaxTTL=%r — the panel would "
                            "store a TTL the wire does not carry" % (panel_cap, core_cap))
        else:
            print("  ok  panel ceiling %d == core injectMaxTTL" % core_cap)

    # 1b) split_ttl answers to the SAME ceiling. The disorder head's whole job is to expire in transit,
    # so a budget that reaches the peer makes it arrive whole and the mode is a no-op every layer still
    # reports as active — the same defect shape as a fake_ttl the wire does not carry.
    mh = re.search(r"^const MaxHopBudget = (\w+)$", desync_go, re.M)
    if not mh:
        failures.append("could not find `const MaxHopBudget = …` in core's internal/packet/desync.go — "
                        "split_ttl's authority is unreadable, so this check must not report success")
    else:
        core_hop = core_cap if mh.group(1) == "injectMaxTTL" else None
        if core_hop is None:
            failures.append("MaxHopBudget is no longer injectMaxTTL (it is %r) — this check reads it "
                            "through that alias and has gone blind" % mh.group(1))
        else:
            # Read through the module, not the AST: SPLIT_TTL_MAX is deliberately an alias of
            # DESYNC_INJECT_TTL_MAX, which literal_eval cannot resolve.
            panel_split = getattr(load_panel(a.panel), "SPLIT_TTL_MAX", None)
            if panel_split != core_hop:
                failures.append("panel SPLIT_TTL_MAX=%r but core MaxHopBudget=%r — the panel would let "
                                "the operator store a disorder TTL the core refuses"
                                % (panel_split, core_hop))
            else:
                print("  ok  panel SPLIT_TTL_MAX %d == core MaxHopBudget" % core_hop)
            # ...and the browser input must not offer more than the submit will accept.
            mi = re.search(r'id="\'\+idp\+\'splitttl" type="number" min="0" max="([^"]+)"', panel_src)
            if not mi:
                failures.append("the split_ttl input was not found in INDEX_HTML — this check went blind")
            elif mi.group(1) != "__SPLITTTLMAX__":
                failures.append("the split_ttl input hardcodes max=%r instead of the injected "
                                "__SPLITTTLMAX__, so the form and the validator can drift" % mi.group(1))
            else:
                print("  ok  the split_ttl input takes its max from SPLIT_TTL_MAX")

    panel_inject = set(panel_const(panel_src, "DESYNC_INJECT_TRANSPORTS"))
    want_inject = {t for t, clamps in CARRIERS if clamps}
    if panel_inject != want_inject:
        failures.append("DESYNC_INJECT_TRANSPORTS=%r, want %r — only the carriers that inject on a real "
                        "4-tuple clamp; raw forges a header and honours 1..255"
                        % (sorted(panel_inject), sorted(want_inject)))
    else:
        print("  ok  the injecting carriers are %s" % sorted(want_inject))

    # 2) every build path agrees, on every carrier.
    P = load_panel(a.panel)
    for transport, clamps in CARRIERS:
        want = (core_cap if clamps else ASKED) if core_cap is not None else None
        got = three_paths(P, base_req(transport))
        for path, val in got.items():
            if want is not None and val != want:
                failures.append("%s / %s: fake_ttl=%r, want %r — %s"
                                % (transport, path, val, want,
                                   "this carrier's decoys ride the real 4-tuple, so the core clamps them"
                                   if clamps else
                                   "this carrier forges its own header, so the operator's value stands"))
        print("  ok  %-6s asked %d -> %s" % (transport, ASKED, sorted(set(got.values()))))

    # 3) the browser must SHOW the ceiling where it applies. A value silently rewritten on save is the
    #    same lie one layer up. Read the DECODED INDEX_HTML, never the .py bytes.
    js = getattr(P, "INDEX_HTML", "")
    if "<script" not in js:
        failures.append("INDEX_HTML did not decode to anything with a <script> in it — this check "
                        "cannot read its subject, so it must not report success")
    else:
        for want, what in (
            ("function desyncInjects(S)", "one definition of which carriers inject"),
            ("desyncTtlCap('e_',_corS)", "the create form's gate applies it"),
            ("desyncTtlCap('ee_',_eeS)", "the edit form's gate applies it"),
            ("dsttlcap", "the form has somewhere to show the ceiling"),
        ):
            if want not in js:
                failures.append("browser JS: %s is missing (or the code moved and this check went "
                                "blind): %r not found" % (what, want))
        print("  ok  the browser shows and applies the ceiling on both forms")

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nfake_ttl reports what the wire carries, on every carrier and every build path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
