#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard for the ws edge-pool edit fallback.

Missing input on an edit falls back to the stored value. The stored ws_edge_snis is a list of
{host,ech,path} dicts, so a _hosts() that understands only plain host strings feeds str(dict) to the SNI
regex and hard-fails with «SNI نامعتبر», defeating the fallback. The UI always resends the string list,
so only a programmatic partial edit of a pooled link reaches this.

This reproduces that path and fails (exit 1) if it raises or drops a host. Run after touching
_ws_pool_fields:

    python3 tools/ws_pool_edit_test.py
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


def main():
    P = load_panel()
    # A stored pooled link exactly as _ws_pool_fields persists it: ws_edge_snis is [{host,ech,path}].
    stored = {
        "ws_pool": True, "ws_tls": True, "ech": False, "cdn_carrier": "ws",
        "ws_edge_ips": ["1.2.3.4:443", "5.6.7.8:443"],
        "ws_edge_ips_burned": [],
        "ws_edge_snis": [{"host": "a.example.com", "ech": "", "path": "/"},
                         {"host": "b.example.com", "ech": "", "path": "/"}],
        "ws_edge_snis_burned": [],
        "ws_rotate_secs": 600, "ws_auto_burn": True, "ws_path": "/",
    }
    # An edit that touches something else and OMITS ws_edge_snis: every pool field must fall back to the
    # stored value, including the SNI list (the documented contract). ech is off, so no key is fetched.
    try:
        res = P._ws_pool_fields({}, stored)
    except Exception as e:
        # backslashreplace so a Persian ValueError message can't itself crash the print on a non-UTF-8 console.
        detail = ("%s: %s" % (type(e).__name__, e)).encode("ascii", "backslashreplace").decode("ascii")
        print("FAIL: an edit omitting ws_edge_snis raised " + detail)
        print("      the stored [{host,...}] shape must fall back cleanly (the docstring promises it)")
        return 1

    got = [s.get("host") for s in res.get("ws_edge_snis", [])]
    want = ["a.example.com", "b.example.com"]
    if got != want:
        print("FAIL: fallback lost/renamed the stored hosts: got %r, want %r" % (got, want))
        return 1
    print("ok  an edit omitting ws_edge_snis falls back to the stored %d-host pool" % len(want))
    return 0


if __name__ == "__main__":
    sys.exit(main())
