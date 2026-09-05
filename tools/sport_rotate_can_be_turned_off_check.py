#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""raw_sport_rotate must be write-ONCE-able and turn-off-able, from the form the operator actually uses.

It also rides WITH fec now. The two were refused together on the claim that "the FEC send path does
not cycle the source port per packet"; the FEC emit path has called wire() -- which cycles -- since
2026-07-08, two months before the refusal was written, and a netns run shows eight distinct source
ports on the wire with both on. See CORE #480.

The bug this closes: the browser only put raw_sport_rotate in the request body when the typed value
parsed to 1..64, so typing the documented "off" value omitted the key, and _core_extra inherited the
stored one from `cur`. Rotation could be switched on and never off, and switching the profile to
anything but udp was rejected with an error naming a form row that is hidden for that profile.

So this drives the EDIT path (the only one with a non-empty `cur`) with the exact bodies the JS builds
for each operator gesture, instead of calling _core_extra with a hand-written body that already
contains the key. A test that hands the helper a body the form would never produce says nothing about
the form.

It also pins fec x rotate, which core refuses at startup: the panel must reject it here rather than
write a config that makes tnl-core exit.

    python3 tools/sport_rotate_can_be_turned_off_check.py
"""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IPS = ("1.1.1.1", "2.2.2.2", ["1.1.1.1"], ["2.2.2.2"])


def load_panel():
    spec = importlib.util.spec_from_file_location("panel", ROOT / "tnl-central.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def core_extra(P, body, cur):
    try:
        ce, _ = P._core_extra(body, cur, *IPS)
        return ce, None
    except ValueError as e:
        return None, str(e)


def form_body(profile, rotate_on, n=5, fec=False, sport_random=False, port=20401):
    """What _collectCoreBody emits for one state of the form: the rotate key is ALWAYS present on a
    raw carrier, 0 when the toggle is off, and the fixed/random source is cleared while it is on."""
    body = {"transport": "raw", "raw_profile": profile, "psk": "x" * 24,
            "cipher": "chacha20-poly1305", "tunnel_ip": "192.168.77.1/24"}
    body["raw_sport_rotate"] = n if (profile in ("udp", "tcp") and rotate_on) else 0
    if profile in ("udp", "tcp"):
        body["raw_port"] = port
        if body["raw_sport_rotate"]:
            body["raw_sport_random"] = False
            body["raw_sport"] = 0
        else:
            body["raw_sport_random"] = sport_random
            body["raw_sport"] = 0
    if fec:
        body["fec"] = True
    return body


def main():
    P = load_panel()
    fails = []
    stored = {"transport": "raw", "raw_profile": "udp", "raw_port": 20401, "raw_sport_rotate": 5,
              "psk": "x" * 24, "cipher": "chacha20-poly1305", "tunnel_ip": "192.168.77.1/24"}

    ce, err = core_extra(P, form_body("udp", False), stored)
    if err:
        fails.append("turning the toggle off was rejected: %s" % err)
    elif ce.get("raw_sport_rotate"):
        fails.append("the toggle was turned off and rotation survived as %r" % ce["raw_sport_rotate"])

    ce, err = core_extra(P, form_body("udp", True, n=3), stored)
    if err or ce.get("raw_sport_rotate") != 3:
        fails.append("changing the packet count to 3 gave %r / %s" % (ce and ce.get("raw_sport_rotate"), err))

    for profile in ("esp", "ah", "l2tpv3", "icmp", "bare", "gre", "ipip", "etherip", "ipcomp"):
        body = form_body(profile, False)
        body.pop("raw_port", None) if profile not in ("udp", "tcp") else None
        ce, err = core_extra(P, body, stored)
        if err:
            fails.append("a rotating tunnel could not be moved to profile %s: %s" % (profile, err))
        elif ce.get("raw_sport_rotate"):
            fails.append("profile %s kept raw_sport_rotate=%r" % (profile, ce["raw_sport_rotate"]))

    # tcp forges a port pair, so the BACKEND must accept the rotation there, not only the browser.
    # The operator hit this on a live raw:tcp tunnel: the toggle was offered, the body carried
    # raw_sport_rotate, and _core_extra refused it with a message naming the udp profile.
    for n in (1, 4, P.RAW_SPROT_MAX):
        ce, err = core_extra(P, form_body("tcp", True, n=n), {})
        if err or ce.get("raw_sport_rotate") != n:
            fails.append("raw:tcp with raw_sport_rotate=%d was refused by the panel backend: %r / %s"
                         % (n, ce and ce.get("raw_sport_rotate"), err))
    ce, err = core_extra(P, dict(form_body("tcp", True, n=4), raw_dports=4), {})
    if err or ce.get("raw_dports") != 4:
        fails.append("raw_dports on a rotating raw:tcp was refused: %r / %s"
                     % (ce and ce.get("raw_dports"), err))
    _, err = core_extra(P, form_body("tcp", True, n=P.RAW_SPROT_MAX + 1), {})
    if not err:
        fails.append("raw:tcp accepted raw_sport_rotate above the range")

    # a body that explicitly asks for rotation on a profile that cannot do it is still a real mistake
    body = form_body("udp", True)
    body["raw_profile"] = "esp"
    body.pop("raw_port", None)
    _, err = core_extra(P, body, stored)
    if not err:
        fails.append("raw_sport_rotate was accepted on the esp profile when the body asked for it")

    ce, err = core_extra(P, form_body("udp", True, fec=True), {})
    if err or not (ce.get("fec") and ce.get("raw_sport_rotate")):
        fails.append("fec + raw_sport_rotate was refused: %r / %s"
                     % (ce and {k: ce.get(k) for k in ("fec", "raw_sport_rotate")}, err))
    ce, err = core_extra(P, form_body("udp", False, fec=True), {})
    if err or not ce.get("fec"):
        fails.append("fec alone stopped working: %r / %s" % (ce and ce.get("fec"), err))

    # the toggle clears the other two source-port modes rather than colliding with them
    ce, err = core_extra(P, form_body("udp", True, sport_random=True), stored)
    if err or ce.get("raw_sport_random") or ce.get("raw_sport"):
        fails.append("the rotating body did not clear the fixed/random source: %r / %s" % (ce, err))

    # rotation must still be reachable at all, on the create path where cur is empty
    ce, err = core_extra(P, form_body("udp", True), {})
    if err or ce.get("raw_sport_rotate") != 5:
        fails.append("create with the toggle on gave %r / %s" % (ce and ce.get("raw_sport_rotate"), err))

    if "raw_sport_rotate" not in P._LINK_EXTRA_KEYS:
        fails.append("raw_sport_rotate is not in _LINK_EXTRA_KEYS, so it is not stored on the link")

    if fails:
        for f in fails:
            print("FAIL: %s" % f)
        return 1
    print("OK: the rotation toggle can be turned off, moved off a portless profile, and rides with fec")
    return 0


if __name__ == "__main__":
    sys.exit(main())
