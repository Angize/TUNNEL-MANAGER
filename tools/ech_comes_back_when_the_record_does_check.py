#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A tunnel that loses its ECH record must come back to ECH by itself when the record returns.

Three consecutive empty fetches -- 45 minutes at the 15-minute default -- used to set `ech = False`
on the stored link and rebuild both ends with the real hostname as cleartext SNI. `_ech_link_hosts`
then refused any link with `not L.get("ech")`, so that tunnel was never polled again: the operator's
setting had been turned off behind their back, and only a human re-enabling it could ever restore ECH.
A CDN rotating its ECHConfig, or one slow authoritative answer three cycles running, was enough.

Degrading is now about the KEY, not the setting: the stale key is cleared, `ech` stays on, the link
keeps being polled every cycle, and the first fetch that answers rebuilds the tunnel with the new key.

    python3 tools/ech_comes_back_when_the_record_does_check.py
"""
import base64
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

spec = importlib.util.spec_from_file_location("tnlc", PANEL)
m = importlib.util.module_from_spec(spec)
sys.modules["tnlc"] = m
spec.loader.exec_module(m)

KEY_OLD = base64.b64encode(b"ech-key-before-the-outage").decode()
KEY_NEW = base64.b64encode(b"ech-key-after-the-outage").decode()

LINK = {"id": 7, "name": "cdn7", "type": "core", "enabled": True,
        "ws_host": "front-a", "ws_ech": KEY_OLD, "ech": True}

rebuilt = []
answer = {"front-a": KEY_OLD}

m.load_links = lambda: [LINK]
m.log_event = lambda *a, **k: None
m.get_settings = lambda: {"ech_refresh_mins": 15}
m._fetch_ech_map = lambda hosts, px: dict(answer)
m._ech_px = lambda L: None
m._ech_live_push = lambda lid, chmap: ""
m._ech_pool_state = lambda lid: (False, False, False)
m._ech_safe_rebuild = lambda lid: (rebuilt.append(lid), True)[1]


m.save_json = lambda path, data: None

fails = []


def check(name, cond, detail=""):
    if cond:
        print("  ok   " + name)
        return
    fails.append(name)
    print("  FAIL " + name + (("\n       " + detail) if detail else ""))


for _ in range(m._ECH_EMPTY_CYCLES):
    answer = {}
    del rebuilt[:]
    m._ech_refresh_once()

check("the vanished record degrades the tunnel", LINK.get("ws_ech") in (None, ""), repr(LINK))
check("...and rebuilds it without ECH", rebuilt == [7], repr(rebuilt))
check("...but leaves the operator's ECH setting ON", LINK.get("ech") is True,
      "ech was turned off, so _ech_link_hosts refuses this link and it is never polled again")
check("...so the link is still watched", m._ech_link_hosts(LINK) == ("single", ["front-a"]),
      "the healer no longer looks at this tunnel at all")

answer = {"front-a": KEY_NEW}
del rebuilt[:]
m._ech_refresh_once()

check("the returning record is stored", LINK.get("ws_ech") == KEY_NEW, repr(LINK.get("ws_ech")))
check("...and the tunnel is rebuilt with it", rebuilt == [7], repr(rebuilt))

del rebuilt[:]
m._ech_refresh_once()
check("...and a steady key rebuilds nothing", rebuilt == [], repr(rebuilt))

print()
if fails:
    print("%d check(s) failed: %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("all checks passed")
