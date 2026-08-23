#!/usr/bin/env python3
"""Guard for G2, the lane that writes the core's in-band ECH self-heal back into the stored config.

The core's event seq counts from 1 in each PROCESS. The panel keeps a high-water mark per link so a
heal is ingested once; kept across a core restart, that mark is above every seq the new process will
ever emit, so G2 goes silent for good and every rebuild puts the stale key back.

Run with no arguments; exit 1 on failure.
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

KEY_1 = base64.b64encode(b"ech-key-generation-1").decode()
KEY_2 = base64.b64encode(b"ech-key-generation-2").decode()
KEY_3 = base64.b64encode(b"ech-key-generation-3").decode()
LINK = {"id": 7, "name": "cdn7"}

written = []
m.load_links = lambda: [LINK]
m._ech_link_hosts = lambda L: ("single", ["front-a"])
m._ech_write = lambda lid, kind, mapping, degrade=False: (True, dict(mapping))
m.log_event = lambda *a, **k: None
_write = m._ech_write


def ingest(seq, key):
    """One pass of the lane against a core reporting exactly this self_heal."""
    del written[:]
    m._ech_write = lambda lid, kind, mapping, degrade=False: (written.append(dict(mapping)), (True, dict(mapping)))[1]
    m.api_edge_status = lambda d: {"ok": True, "events": [
        {"kind": "ech", "code": "self_heal", "seq": seq, "detail": "front-a " + key}]}
    m._ech_ingest_selfheal()
    return written[0] if written else None


fails = []


def check(name, cond, detail=""):
    if cond:
        print("  ok   %s" % name)
        return
    fails.append(name)
    print("  FAIL %s%s" % (name, ("\n       " + detail) if detail else ""))


got = ingest(120, KEY_1)
check("a heal from a long-running core is persisted", got == {"front-a": KEY_1}, repr(got))

got = ingest(120, KEY_2)
check("...and the same seq is not persisted twice", got is None, repr(got))

# The core restarts. Its counter starts over, so every new heal carries a seq below the mark.
got = ingest(1, KEY_2)
check("a heal from a RESTARTED core is persisted", got == {"front-a": KEY_2},
      "the panel refused it as already-seen; every rebuild now puts the stale key back")

got = ingest(2, KEY_3)
check("...and the lane keeps working after the reset", got == {"front-a": KEY_3}, repr(got))

got = ingest(2, KEY_3)
check("...and still ingests each seq once", got is None, repr(got))

print()
if fails:
    print("%d check(s) failed: %s" % (len(fails), ", ".join(fails)))
    sys.exit(1)
print("all checks passed")
