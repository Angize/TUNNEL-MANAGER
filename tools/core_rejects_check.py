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
DNS = {"transport": "dns", "cipher": "auto", "dns_zone": "t.example.com", "dns_resolvers": ["10.0.0.1"]}

# (name, request, the core rule it mirrors) — the panel MUST raise on every one of these.
MUST_REJECT = [
    ("obfs on dns", dict(DNS, obfs=True),
     'config.go: obfs is not supported on the dns transport'),
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
    ("dns without a zone", {"transport": "dns", "cipher": "auto", "dns_resolvers": ["10.0.0.1"]},
     "config.go: dns transport requires dns_zone"),
    ("spoof with neither src nor dst", {"transport": "spoof", "cipher": "auto"},
     "config.go: spoof transport requires at least one of spoof_src_ip / spoof_dst_ip"),
    ("raw with crypto off", {"transport": "raw", "cipher": "none", "raw_profile": "bip"},
     "config.go: raw transport requires crypto enabled"),
    ("flux with crypto off", {"transport": "flux", "cipher": "none", "flux_carrier": "udp"},
     "config.go: flux transport requires crypto enabled"),
    ("dns with crypto off", dict(DNS, cipher="none"),
     "config.go: dns transport requires crypto enabled"),
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
]

# The other half of the contract: these are all LEGAL and must go straight through. Without them a
# panel that raised on everything would score a perfect pass here.
MUST_ACCEPT = [
    ("plain udp", {"transport": "udp", "cipher": "auto"}),
    ("obfs on tcp", {"transport": "tcp", "cipher": "auto", "obfs": True}),
    ("obfs on flux", {"transport": "flux", "cipher": "auto", "flux_carrier": "udp", "obfs": True}),
    ('fake_mode "both" with two decoys', {"transport": "tcp", "cipher": "auto", "fake_desync": True,
                                          "fake_mode": "both", "fake_count": 2}),
    ('fake_mode "ttl" with one decoy', {"transport": "tcp", "cipher": "auto", "fake_desync": True,
                                        "fake_mode": "ttl", "fake_count": 1}),
    ("grpc with ws_tls", dict(WSS, cdn_carrier="grpc")),
    ("http carrier with a profile", dict(WSS, cdn_carrier="http", cdn_profile="arvan")),
    ("dns, plain", dict(DNS)),
    ("sni_split with ws_tls", dict(WSS, sni_split=True, sni_mode="disorder", split_ttl=4)),
    ("fec on udp", {"transport": "udp", "cipher": "auto", "fec": True, "fec_data": 10, "fec_parity": 3}),
    # The boundary itself must still be allowed: 64 is the largest block whose parity lands inside the
    # window, measured on the guard, and refusing it would be its own bug.
    ("fec_data exactly at the replay window", {"transport": "udp", "cipher": "auto", "fec": True,
                                               "fec_data": 64, "fec_parity": 3}),
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

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe panel refuses all %d configurations the core refuses, and allows all %d it accepts"
          % (len(MUST_REJECT), len(MUST_ACCEPT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
