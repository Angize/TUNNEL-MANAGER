#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The panel must refuse every combination the CORE refuses.

When it does not, the operator fills in a form, the panel says «ذخیره شد», the node stores it and
builds a core config — and the core then exits on `validate()`. Both ends refuse to start, and nothing
between the button and the crash says why. On an EDIT of a live tunnel the damage lands at the next
core-update, far from the change that caused it.

A browser-side gate is not the funnel — `_core_extra` is, and create / edit / rebuild all go through
it, as does the HTTP API with no browser involved at all. Each case names the core rule it mirrors.
This is a MATRIX, not a transcription of `config.go`: most of the core's rules are about fields the
panel generates itself and cannot get wrong. What belongs here is anything an operator can express.

The CONTROLS at the bottom matter as much as the cases: without them "reject everything" would pass.

    python3 tools/core_rejects_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

A_IP, B_IP = "203.0.113.5", "198.51.100.7"
A_IPS, B_IPS = [A_IP, "203.0.113.6"], [B_IP, "198.51.100.8"]

WSS = {"transport": "ws", "cipher": "auto", "ws_host": "cdn.example.com", "ws_path": "/", "ws_tls": True}

# (name, request, the core rule it mirrors) — the panel MUST raise on every one of these.
MUST_REJECT = [
    ('fake_mode "both" with one decoy', {"transport": "tcp", "cipher": "auto", "fake_desync": True,
                                         "fake_mode": "both", "fake_count": 1},
     'config.go: fake_mode "both" needs fake_count >= 2'),
    ("cdn_carrier grpc without ws_tls", {"transport": "ws", "cipher": "auto", "ws_host": "c.example.com",
                                         "ws_path": "/", "ws_tls": False, "cdn_carrier": "grpc"},
     'config.go: cdn_carrier "grpc" requires ws_tls'),
    ("sni_split without ws_tls", {"transport": "ws", "cipher": "auto", "ws_host": "c.example.com",
                                  "ws_path": "/", "ws_tls": False, "sni_split": True, "sni_mode": "disorder"},
     "config.go: sni_split requires ws_tls on a client"),
    ("ws_tls without ws_host", {"transport": "ws", "cipher": "auto", "ws_host": "", "ws_path": "/",
                                "ws_tls": True},
     "config.go: ws_tls requires ws_host"),
    ("raw with crypto off", {"transport": "raw", "cipher": "none", "raw_profile": "bare"},
     "config.go: raw transport requires crypto enabled"),
    ("bare borrowing tcp's protocol number", {"transport": "raw", "cipher": "auto", "raw_profile": "bare",
                                             "raw_proto": 6},
     "config.go: rawProtoBorrowed — bare writes no L4 header, so proto 6 is ciphertext where the TCP "
     "header belongs and the path drops the flow"),
    ("bare borrowing esp's protocol number", {"transport": "raw", "cipher": "auto", "raw_profile": "bare",
                                             "raw_proto": 50},
     "config.go: rawProtoBorrowed — same, for every number a profile owns"),
    ("obfs with crypto off", {"transport": "tcp", "cipher": "none", "obfs": True},
     "config.go: obfs requires crypto enabled"),
    ("split_ttl out of range", dict(WSS, sni_split=True, sni_mode="disorder", split_ttl=300),
     "config.go: split_ttl must be between 0 and 255"),
    # This one passes the sum rule (fec_data+fec_parity<=255) and is still unrepairable: the decoder
    # delivers parity-recovered frames LAST, so past a full replay window (64) every one of them is
    # discarded as too old — full FEC bandwidth, zero repair.
    ("fec_data past the replay window", {"transport": "udp", "cipher": "auto", "fec": True,
                                         "fec_data": 65, "fec_parity": 3},
     "config.go: fec_data must be at most packet.MaxFecData"),
    ("a rolling source port on a profile that forges none",
     {"transport": "raw", "cipher": "auto", "raw_profile": "gre", "raw_sport_random": True},
     "config.go: raw_sport_random rolls the forged SOURCE port of the udp/tcp profiles only"),
    ("...and on the headerless one",
     {"transport": "raw", "cipher": "auto", "raw_profile": "bare", "raw_sport_random": True},
     "config.go: same rule, for every profile with no L4 header"),
    # The destination axis and the source band are two rules with two different preconditions, and
    # they were briefly ONE chained branch: with reactive random on, the band arm ran and the dports
    # rule never got a turn, so a destination count reached _core_extra, was refused by nothing, and
    # was dropped on the floor. Each of the four cells below is a different arm of that decision.
    ("a destination spread with the source port standing still",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_dports": 4},
     "config.go: raw_dports needs raw_sport_rotate; a fixed source lands in one bucket anyway"),
    ("a destination spread with only the REACTIVE source port moving",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_sport_random": True,
      "raw_dports": 4},
     "config.go: raw_dports rides raw_sport_rotate, not raw_sport_random"),
    ("a rotation band with the source port standing still",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp",
      "raw_sport_lo": 10000, "raw_sport_hi": 44999},
     "config.go: raw_sport_lo/hi bound a band that only exists while the port moves"),
    ("a rotation band narrower than the floor",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_sport_rotate": 6,
      "raw_sport_lo": 30000, "raw_sport_hi": 30098},
     "config.go: the band must span at least packet.MinSportBandSpan ports"),
    ("a rotation band reaching into the privileged ports",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_sport_rotate": 6,
      "raw_sport_lo": 500, "raw_sport_hi": 44999},
     "config.go: the band starts at packet.MinSportBandLo or above"),
    ("half a rotation band",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_sport_rotate": 6,
      "raw_sport_lo": 10000},
     "config.go: lo <= hi, and one alone is not a range"),
]

# EDITS of a STORED tunnel. The list above passes an empty `cur`, so it cannot express the thing that
# actually broke: a per-profile field the tunnel carries from its PREVIOUS profile must not block the
# change. raw_port did — every raw tunnel that had ever been udp/tcp became unable to move to any other
# profile, because _core_extra fell back to the stored port and refused it against the new profile. A
# field asked for in THIS request is a different thing and is still refused (see MUST_REJECT).
#   (name, stored link, edit request, keys that must be GONE from the result)
MUST_ACCEPT_EDIT = [
    ("stored udp+port -> %s drops the port" % prof,
     {"transport": "raw", "raw_profile": "udp", "raw_port": 443, "cipher": "auto"},
     {"transport": "raw", "cipher": "auto", "raw_profile": prof},
     ["raw_port"])
    for prof in ("bare", "gre", "icmp", "ipip", "esp", "l2tpv3", "ah", "ipcomp", "etherip")
] + [
    # The rolling source port inherits the SAME rule, and for the same reason: refusing a mode the
    # tunnel carried in from its previous profile is what made a profile change impossible in #356.
    ("stored tcp+rolling sport -> %s drops the mode" % prof,
     {"transport": "raw", "raw_profile": "tcp", "raw_sport_random": True, "cipher": "auto"},
     {"transport": "raw", "cipher": "auto", "raw_profile": prof},
     ["raw_sport_random"])
    for prof in ("bare", "gre", "icmp", "esp", "l2tpv3", "ipcomp")
] + [
    ("stored bare+proto -> gre drops the proto",
     {"transport": "raw", "raw_profile": "bare", "raw_proto": 252, "cipher": "auto"},
     {"transport": "raw", "cipher": "auto", "raw_profile": "gre"}, ["raw_proto"]),
    ("stored udp+port -> tcp KEEPS it (tcp forges ports too)",
     {"transport": "raw", "raw_profile": "udp", "raw_port": 51820, "cipher": "auto"},
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp"}, []),
]

# The other half of the contract: these are all LEGAL and must go straight through. Without them a
# panel that raised on everything would score a perfect pass here.
MUST_ACCEPT = [
    ("plain udp", {"transport": "udp", "cipher": "auto"}),
    ("obfs on tcp", {"transport": "tcp", "cipher": "auto", "obfs": True}),
    ('fake_mode "both" with two decoys', {"transport": "tcp", "cipher": "auto", "fake_desync": True,
                                          "fake_mode": "both", "fake_count": 2}),
    ('fake_mode "ttl" with one decoy', {"transport": "tcp", "cipher": "auto", "fake_desync": True,
                                        "fake_mode": "ttl", "fake_count": 1}),
    ("grpc with ws_tls", dict(WSS, cdn_carrier="grpc")),
    ("http carrier with a shape", dict(WSS, cdn_carrier="http", http_up_workers=12,
                                      http_up_batch_kb=256, http_streams=4)),
    ("sni_split with ws_tls", dict(WSS, sni_split=True, sni_mode="disorder", split_ttl=4)),
    ("fec on udp", {"transport": "udp", "cipher": "auto", "fec": True, "fec_data": 10, "fec_parity": 3}),
    ("a rolling source port on udp", {"transport": "raw", "cipher": "auto", "raw_profile": "udp",
                                      "raw_sport_random": True}),
    ("a rolling source port on tcp, beside a custom server port",
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_port": 4500,
      "raw_sport_random": True}),
    # The boundary itself must still be allowed: 64 is the largest block whose parity lands inside the
    # window, measured on the guard, and refusing it would be its own bug.
    ("fec_data exactly at the replay window", {"transport": "udp", "cipher": "auto", "fec": True,
                                               "fec_data": 64, "fec_parity": 3}),
]


# EDITS whose point is that a stored value is CLEARED. MUST_ACCEPT_EDIT above covers a key dropped
# because the profile changed; this covers the operator explicitly turning something OFF while staying
# on the same profile. Without an explicit false the request simply omits the key, `cur` supplies the
# stored true, and the feature can never be switched off again -- which is exactly what the first cut of
# the rolling source port did.
#   (name, stored link, edit request, keys that must be GONE from the result)
MUST_CLEAR_EDIT = [
    ("rolling sport OFF clears the stored ON",
     {"transport": "raw", "raw_profile": "tcp", "raw_sport_random": True, "cipher": "auto"},
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_sport_random": False},
     ["raw_sport_random"]),
]

# ...and the mirror: a PARTIAL edit that does not mention the key at all must LEAVE it alone, or every
# unrelated save (a "rotate now", a port change) would silently switch the mode off.
#   (name, stored link, edit request, keys that must SURVIVE with their stored value)
MUST_KEEP_EDIT = [
    ("a partial edit keeps the stored rolling sport",
     {"transport": "raw", "raw_profile": "tcp", "raw_sport_random": True, "cipher": "auto"},
     {"transport": "raw", "cipher": "auto", "raw_profile": "tcp", "raw_port": 4500},
     {"raw_sport_random": True}),
]


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    P = load_panel()
    failures = []

    for name, req, rule in MUST_REJECT:
        try:
            P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
        except ValueError:
            print("  ok  refused  %s" % name)
            continue
        except Exception as e:  # a crash is not a refusal: the operator gets a 500, not a reason
            failures.append("[%s] raised %s instead of a ValueError with a reason: %s"
                            % (name, type(e).__name__, e))
            continue
        failures.append("[%s] ACCEPTED — the core will refuse it (%s), so both ends of the tunnel "
                        "fail to start and nothing between the button and the crash says why"
                        % (name, rule))

    for name, req in MUST_ACCEPT:
        try:
            P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
            print("  ok  allowed  %s" % name)
        except Exception as e:
            failures.append("[%s] REFUSED a legal configuration: %s" % (name, e))

    for name, cur, req, gone in MUST_ACCEPT_EDIT:
        try:
            ce, _ = P._core_extra(dict(req), dict(cur), A_IP, B_IP, A_IPS, B_IPS)
        except Exception as e:
            failures.append("[%s] REFUSED a legal edit: %s" % (name, e))
            continue
        left = [k for k in gone if k in ce]
        if left:
            failures.append("[%s] kept %s from the previous profile" % (name, left))
        else:
            print("  ok  edit     %s" % name)

    for name, cur, req, gone in MUST_CLEAR_EDIT:
        try:
            ce, _ = P._core_extra(dict(req), dict(cur), A_IP, B_IP, A_IPS, B_IPS)
        except Exception as e:
            failures.append("[%s] REFUSED a legal edit: %s" % (name, e))
            continue
        left = [k for k in gone if k in ce]
        if left:
            failures.append("[%s] kept %s — the operator cannot turn it off; the stored value is "
                            "resurrected on every save" % (name, left))
        else:
            print("  ok  clear    %s" % name)

    for name, cur, req, keep in MUST_KEEP_EDIT:
        try:
            ce, _ = P._core_extra(dict(req), dict(cur), A_IP, B_IP, A_IPS, B_IPS)
        except Exception as e:
            failures.append("[%s] REFUSED a legal edit: %s" % (name, e))
            continue
        bad = {k: (ce.get(k), v) for k, v in keep.items() if ce.get(k) != v}
        if bad:
            failures.append("[%s] lost %s — an unrelated save must not switch it off" % (name, bad))
        else:
            print("  ok  keep     %s" % name)

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe panel refuses all %d configurations the core refuses, and allows all %d it accepts"
          % (len(MUST_REJECT), len(MUST_ACCEPT) + len(MUST_ACCEPT_EDIT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
