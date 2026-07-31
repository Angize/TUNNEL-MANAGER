#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""split_ttl belongs to sni_mode=disorder, and to nothing else.

The panel offers ONE TTL input for both non-split SNI modes, and the two modes want OPPOSITE values
out of it:

    disorder  the head segment must EXPIRE before it reaches the server, so the TTL has to be LOW
              (core's default is 4).
    fake      the decoy is killed at the server by its bad TCP checksum, not by expiring, and its
              whole job is to reach the on-path DPI FIRST. A low TTL kills it before the DPI and turns
              the strongest SNI mode into an expensive no-op.

So a tunnel that stored 4 for disorder and then switched to fake shipped a decoy that died en route,
with the panel, the node and the core's own startup line all reporting the mode as on. core's
frag.go (fakeSegTTL) no longer reads the knob in fake mode at all — offering it here would be a
setting the operator picks and nothing consumes.

This drives all THREE panel build paths (create / edit / rebuild), because the panel has three and a
gate added to one of them says nothing about the other two.

    python3 tools/sni_mode_fields_check.py
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

A_IP, B_IP = "203.0.113.5", "198.51.100.7"
A_IPS, B_IPS = [A_IP, "203.0.113.6"], [B_IP, "198.51.100.8"]

BASE = {"transport": "ws", "cipher": "auto", "ws_host": "cdn.example.com",
        "ws_path": "/", "ws_tls": True, "sni_split": True}


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def three_paths(P, req):
    """The node body as built by create, edit and rebuild."""
    ce, _ = P._core_extra(dict(req), {}, A_IP, B_IP, A_IPS, B_IPS)
    create = P._node_extra(ce)
    stored = dict(ce)
    stored["type"] = "core"
    ce2, _ = P._core_extra(dict(req), dict(stored), A_IP, B_IP, A_IPS, B_IPS)
    edit = P._node_extra(ce2)
    rebuild = P._tunnel_extra(dict(stored), refetch_ech=False)
    return {"create": create, "edit": edit, "rebuild": rebuild}


def main():
    P = load_panel()
    src = open(PANEL, encoding="utf-8").read()
    failures = []

    # 1) fake mode must not carry the knob on ANY path — including when a value is stored, which is
    #    exactly what a tunnel that used disorder first looks like.
    for label, req in (
        ("fake, ttl set explicitly", dict(BASE, sni_mode="fake", split_ttl=4)),
        ("fake, no ttl", dict(BASE, sni_mode="fake")),
    ):
        for path, body in three_paths(P, req).items():
            if "split_ttl" in body:
                failures.append("[%s] %s: split_ttl=%r reached the node body; in fake mode the core "
                                "ignores it and a low value would kill the decoy before the DPI"
                                % (label, path, body["split_ttl"]))
            if body.get("sni_mode") != "fake":
                failures.append("[%s] %s: sni_mode=%r, want 'fake'" % (label, path, body.get("sni_mode")))
        print("  ok  %s" % label)

    # 2) ...and disorder must still carry it, so this cannot be satisfied by dropping the knob wholesale.
    req = dict(BASE, sni_mode="disorder", split_ttl=4)
    for path, body in three_paths(P, req).items():
        if body.get("split_ttl") != 4:
            failures.append("[disorder] %s: split_ttl=%r, want 4 — the head segment must expire "
                            "before the server" % (path, body.get("split_ttl", "<missing>")))
    print("  ok  disorder still carries split_ttl")

    # 3) the browser must not SHOW the input in fake mode either: a row the operator can fill in and
    #    that is then dropped on submit is its own kind of lie. Read from the DECODED INDEX_HTML —
    #    the string the browser really receives — never from the .py bytes, where the escapes are
    #    still doubled and a checker either chokes or, worse, passes on something nobody serves.
    js = getattr(P, "INDEX_HTML", "")
    if "<script" not in js:
        failures.append("INDEX_HTML did not decode to anything with a <script> in it — this check "
                        "cannot read its subject, so it must not report success")
    else:
        # Positive AND negative. The negative alone would pass vacuously the moment the surrounding
        # code is reformatted; the positive is what proves the gate is really there.
        for want, what in (
            ("snittlbody');if(b)b.style.display=(m=='disorder')", "the mode picker reveals the TTL row"),
            ("((mode=='disorder')?'':';display:none')", "the form renders the TTL row"),
            ("if(S.SniMode=='disorder')body.split_ttl", "the submit body carries split_ttl"),
        ):
            if want not in js:
                failures.append("browser JS: %s for something other than disorder (or the code moved "
                                "and this check went blind): %r not found" % (what, want))
        for bad, what in (
            ("snittlbody');if(b)b.style.display=(m!='split')", "the mode picker reveals the TTL row for any non-split mode"),
            ("((mode&&mode!='split')?'':';display:none')", "the form renders the TTL row for any non-split mode"),
            ("if(S.SniMode!='split')body.split_ttl", "the submit body carries split_ttl for any non-split mode"),
        ):
            if bad in js:
                failures.append("browser JS: %s — it belongs to disorder only" % what)
        print("  ok  the browser shows and sends it for disorder only")

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nsplit_ttl is a disorder-only knob on every path")
    return 0


if __name__ == "__main__":
    sys.exit(main())
