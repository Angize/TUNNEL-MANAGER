#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-path config contract guard for core tunnels.

The panel has THREE independent ways to build the body it sends a node:

    create    api_create_tunnel  -> _core_extra(d, cur={})  -> _node_extra
    edit      api_edit_link      -> _core_extra(d, cur=L)   -> _node_extra
    rebuild   api_rebuild_*      -> _tunnel_extra(L)

They must agree, or the panel reports success while the tunnel runs a config the operator did not
choose. This builds every carrier through all three paths and exits 1 when they disagree, or when a
key the operator set never reaches the node body. Run after touching any _core_extra / _tunnel_extra /
_*_fields helper:

    python3 tools/config_contract.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P = load_panel()

A_IP, B_IP = "203.0.113.5", "198.51.100.7"
A_IPS, B_IPS = [A_IP, "203.0.113.6"], [B_IP, "198.51.100.8"]

# Each case: the create request a form would send, plus the keys that MUST reach the node body.
CASES = [
    ("udp", {"transport": "udp", "cipher": "auto"}, {"transport": "udp"}),
    ("tcp+cover", {"transport": "tcp", "cipher": "auto", "cover": True, "cover_sni": "example.com"},
     {"transport": "tcp", "cover": True, "cover_sni": "example.com"}),
    ("raw/bare+proto", {"transport": "raw", "cipher": "auto", "raw_profile": "bare", "raw_proto": 58},
     {"transport": "raw", "raw_profile": "bare", "raw_proto": 58}),
    ("raw/udp+port", {"transport": "raw", "cipher": "auto", "raw_profile": "udp", "raw_port": 51820},
     {"transport": "raw", "raw_profile": "udp", "raw_port": 51820}),
    # The rolling source port is per-tunnel state like the port beside it: a rebuild that replays
    # everything BUT this one silently drops the tunnel back to a constant 4-tuple, which is the
    # condition it was turned on to escape — and nothing anywhere would say so.
    ("raw/tcp+rolling sport",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_sport_random": True},
     {"transport": "raw", "raw_profile": "tcp", "raw_sport_random": True}),
    ("raw/bare native", {"transport": "raw", "cipher": "auto", "raw_profile": "bare"},
     {"transport": "raw", "raw_profile": "bare"}),
    # Extra TUN queues are per-tunnel state exactly like the port beside them: a rebuild that replays
    # everything BUT this one drops the tunnel back to a single queue, which is the whole thing the
    # operator raised it to escape, and the panel would keep showing 4.
    ("raw/tcp+workers", {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "workers": 4},
     {"transport": "raw", "raw_profile": "tcp", "workers": 4}),
    ("raw/gre", {"transport": "raw", "cipher": "auto", "raw_profile": "gre"},
     {"transport": "raw", "raw_profile": "gre"}),
    ("raw/icmp+fec", {"transport": "raw", "cipher": "auto", "raw_profile": "icmp",
                      "fec": True, "fec_data": 10, "fec_parity": 3},
     {"transport": "raw", "raw_profile": "icmp", "fec": True, "fec_data": 10, "fec_parity": 3}),
    ("spoof/src", {"transport": "spoof", "cipher": "auto", "spoof_src": "192.0.2.7", "raw_proto": 58},
     {"transport": "spoof", "spoof_src": "192.0.2.7", "raw_proto": 58}),
    ("spoof/dst", {"transport": "spoof", "cipher": "auto", "spoof_dst": "185.51.200.10"},
     {"transport": "spoof", "spoof_dst": "185.51.200.10"}),
    ("spoof/both+desync", {"transport": "spoof", "cipher": "auto", "spoof_src": "192.0.2.7",
                           "spoof_dst": "185.51.200.10", "fake_desync": True, "fake_ttl": 5,
                           "fake_count": 3, "fake_mode": "ttl"},
     {"transport": "spoof", "spoof_src": "192.0.2.7", "spoof_dst": "185.51.200.10",
      "fake_desync": True, "fake_ttl": 5, "fake_count": 3, "fake_mode": "ttl"}),
    ("spoof+fec", {"transport": "spoof", "cipher": "auto", "spoof_src": "192.0.2.7",
                   "fec": True, "fec_data": 10, "fec_parity": 3},
     {"transport": "spoof", "spoof_src": "192.0.2.7", "fec": True}),
    ("flux/udp", {"transport": "flux", "cipher": "auto", "flux_carrier": "udp",
                  "flux_rotate_secs": 600, "flux_shape": "random"},
     {"transport": "flux", "flux_carrier": "udp", "flux_shape": "random"}),
    ("dns", {"transport": "dns", "cipher": "auto", "dns_zone": "t.example.com",
             "dns_resolvers": ["10.0.0.1"]},
     {"transport": "dns", "dns_zone": "t.example.com"}),
    ("ws/http+arvan", {"transport": "ws", "cipher": "auto", "ws_host": "cdn.example.com",
                       "ws_path": "/", "ws_tls": True, "cdn_carrier": "http", "cdn_profile": "arvan"},
     {"transport": "ws", "cdn_carrier": "http", "http_up_workers": 8, "http_up_batch_kb": 512}),
    # The DEFAULT profile is its own case — it carries its OWN measured numbers now, rather than
    # leaning on the core's defaults, so "cf reached the node" has to be asserted just like arvan's.
    ("ws/http+cf", {"transport": "ws", "cipher": "auto", "ws_host": "cdn.example.com",
                    "ws_path": "/", "ws_tls": True, "cdn_carrier": "http", "cdn_profile": "cf"},
     {"transport": "ws", "cdn_carrier": "http", "http_up_workers": 8, "http_up_batch_kb": 256}),
    # grpc has no POST ladder, so no profile applies and none of its knobs may appear. That sentence
    # stood here while NOTHING checked it: `must` only asserts the keys it lists, NEVER did not carry
    # the POST-ladder knobs, and check (3) compares the three paths against each other — so a leak
    # present on all three was invisible. HTTP_ONLY below is the check the comment was describing.
    ("ws/grpc", {"transport": "ws", "cipher": "auto", "ws_host": "cdn.example.com",
                 "ws_path": "/", "ws_tls": True, "cdn_carrier": "grpc"},
     {"transport": "ws", "cdn_carrier": "grpc"}),
    # An edge POOL is its own branch — _ws_fields returns to _ws_pool_fields before it ever reaches
    # the single-edge carrier block — so every ws case above says nothing about it. That gap is why a
    # pooled tunnel ignored the profile on all three paths for a whole release. ECH is off so this
    # never touches the network.
    ("ws-pool/http+arvan", {"transport": "ws", "cipher": "auto", "ws_pool": True, "ws_path": "/",
                            "ws_edge_ips": ["203.0.113.10", "203.0.113.11"],
                            "ws_edge_snis": ["a.example.com", "b.example.com"],
                            "ech": False, "cdn_carrier": "http", "cdn_profile": "arvan"},
     {"transport": "ws", "ws_pool": True, "cdn_carrier": "http",
      "http_up_workers": 8, "http_up_batch_kb": 512}),
    ("ws-pool/http+cf", {"transport": "ws", "cipher": "auto", "ws_pool": True, "ws_path": "/",
                         "ws_edge_ips": ["203.0.113.10", "203.0.113.11"],
                         "ws_edge_snis": ["a.example.com", "b.example.com"],
                         "ech": False, "cdn_carrier": "http", "cdn_profile": "cf"},
     {"transport": "ws", "ws_pool": True, "cdn_carrier": "http",
      "http_up_workers": 8, "http_up_batch_kb": 256}),
    # The PLAIN-WebSocket pool. Every pool case above sets an http carrier, so none of them covers the
    # default shape — and that is where the second real divergence was hiding: _ws_pool_fields stores
    # cdn_carrier ALWAYS (unlike _ws_fields, which stores it only when it is not "ws"), so create/edit
    # put `cdn_carrier: "ws"` in the node body while _tunnel_extra forwarded only http/grpc.
    ("ws-pool/ws", {"transport": "ws", "cipher": "auto", "ws_pool": True, "ws_path": "/",
                    "ws_edge_ips": ["203.0.113.10", "203.0.113.11"],
                    "ws_edge_snis": ["a.example.com", "b.example.com"],
                    "ech": False, "cdn_carrier": "ws"},
     {"transport": "ws", "ws_pool": True, "cdn_carrier": "ws"}),
    # A flux tunnel that has been bumped by "rotate now" — the case where flux_epoch_offset is a real
    # non-zero value rather than the 0 every flux tunnel stores from birth. Both have to survive all
    # three paths, and the zero one is what the guard has been red on since it was written.
    ("flux/udp+bumped", {"transport": "flux", "cipher": "auto", "flux_carrier": "udp",
                         "flux_rotate_secs": 600, "flux_shape": "random", "flux_epoch_offset": 3},
     {"transport": "flux", "flux_carrier": "udp", "flux_epoch_offset": 3}),
]

# Keys that legitimately differ between paths (not part of the contract).
IGNORE = {"psk", "ws_ech", "ech"}

# Keys that must NEVER reach a node, on any path. A node silently drops what it does not whitelist, so
# a panel-only key that leaks into a body is invisible at runtime — no error, no log, just a setting
# that does nothing.
NEVER = ("cdn_profile", "ws_edge_ips_burned", "ws_edge_snis_burned",
         "ip_rotate", "a_ip_pool", "b_ip_pool", "rotate_secs", "auto_burn")
# ...unless a case's own contract asks for it (none do today; the check reads `must` so a future
# carrier that legitimately needs one of these can say so instead of quietly disabling the guard).

# The POST-ladder knobs are a HARDER rule than NEVER: the core does not ignore them elsewhere, it
# REFUSES the whole config unless the role is client and the carrier is http — so a leak here is a
# tunnel that will not start on either end, with the panel reporting the save as successful. The rule
# is read from each case's own contract, so a new http-shaped carrier gets it for free.
HTTP_ONLY = ("http_up_workers", "http_up_batch_kb", "http_up_rate")


def build_create(req):
    ce, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
    return P._node_extra(ce)


def build_edit(req, stored):
    """An edit re-sends the same form values with the stored link as `cur`."""
    ce, _ = P._core_extra(dict(req), dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    return P._node_extra(ce)


def build_edit_partial(req, stored):
    """A PARTIAL edit: the operator changed nothing this form carries, so every value has to come back
    out of the STORED record — the panel's stated edit contract, and identical to the full resend.

    The full-resend arm above cannot exercise that at all: every helper reads
    `d.get(k) if k in d else cur.get(k)`, so when `d` is the whole request `cur` is never consulted."""
    ce, _ = P._core_extra({"transport": req["transport"]}, dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    return P._node_extra(ce)


def build_rebuild(stored):
    """Rebuild/restore replays the STORED record (no fresh ECH fetch, so it never hits the network)."""
    return P._tunnel_extra(dict(stored), refetch_ech=False)


def diff(name, path_a, a, path_b, b):
    out = []
    for k in sorted(set(a) | set(b)):
        if k in IGNORE:
            continue
        va, vb = a.get(k, "<missing>"), b.get(k, "<missing>")
        if va != vb:
            out.append("    %-20s %s=%r  vs  %s=%r" % (k, path_a, va, path_b, vb))
    return out


def main():
    failures = []
    for name, req, must in CASES:
        try:
            create = build_create(req)
            # The stored link record is `extra` merged into the row; _core_extra's own output is
            # exactly what gets stored, so reuse it as `cur` for the edit and rebuild paths.
            stored, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
            stored = dict(stored)
            stored["type"] = "core"
            edit = build_edit(req, stored)
            edit_partial = build_edit_partial(req, stored)
            rebuild = build_rebuild(stored)
        except Exception as e:
            failures.append("[%s] BUILD FAILED: %s: %s" % (name, type(e).__name__, e))
            continue

        # 1) every key the operator set must actually reach the node body, on every path.
        for path_name, body in (("create", create), ("edit", edit),
                                ("edit (partial)", edit_partial), ("rebuild", rebuild)):
            for k, want in must.items():
                if body.get(k) != want:
                    failures.append("[%s] %s: %s = %r, want %r" %
                                    (name, path_name, k, body.get(k, "<missing>"), want))

        # 2) no panel-only key may reach a node body, on any path — the node would drop it in silence.
        for path_name, body in (("create", create), ("edit", edit),
                                ("edit (partial)", edit_partial), ("rebuild", rebuild)):
            for k in NEVER:
                if k in body and k not in must:
                    failures.append("[%s] %s: %s = %r reached the node body; it is panel-only and the "
                                    "node drops unwhitelisted keys silently" % (name, path_name, k, body[k]))

        # 2b) ...and the POST-ladder knobs may appear ONLY on an http carrier, because the core
        #     refuses the config outright anywhere else. The positive half is already covered: the
        #     arvan/cf cases list the numbers in `must`, so this cannot be satisfied by never
        #     emitting them at all.
        if must.get("cdn_carrier") != "http":
            for path_name, body in (("create", create), ("edit", edit),
                                    ("edit (partial)", edit_partial), ("rebuild", rebuild)):
                for k in HTTP_ONLY:
                    if k in body:
                        failures.append("[%s] %s: %s = %r reached the node body on a %s carrier; the "
                                        "core REFUSES that config (http-carrier client only), so both "
                                        "ends would fail to start while the panel reported the save as "
                                        "successful" % (name, path_name, k, body[k],
                                                        must.get("cdn_carrier") or must.get("transport")))

        # 2c) ...and every key _core_extra produced must survive an EDIT's persistence step. That step
        #     keeps only the keys on one list, and a field missing from it has no symptom the edit can
        #     show: the node is rebuilt with the operator's value and reports success, while the record
        #     drops it — so the next rebuild silently reverts and the form shows the stale setting as
        #     live. Nothing above can see this, because every path here calls _core_extra directly.
        missing = sorted(set(stored) - {"type"} - set(P._LINK_EXTRA_KEYS))
        if missing:
            failures.append("[%s] _core_extra produced %s, which api_edit_link's _LINK_EXTRA_KEYS does "
                            "not keep — an edit would drop it from the stored link" % (name, missing))

        # 3) the three paths must agree with each other.
        for pa, a, pb, b in (("create", create, "edit", edit),
                             ("create", create, "edit (partial)", edit_partial),
                             ("create", create, "rebuild", rebuild)):
            d = diff(name, pa, a, pb, b)
            if d:
                failures.append("[%s] %s != %s:\n%s" % (name, pa, pb, "\n".join(d)))

        print("  ok  %s" % name)

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nall %d carriers agree across create / edit / rebuild" % len(CASES))
    return 0


if __name__ == "__main__":
    sys.exit(main())
