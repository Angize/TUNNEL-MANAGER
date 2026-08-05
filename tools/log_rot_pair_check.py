#!/usr/bin/env python3
"""Guard: a rotation card names the src -> dst PAIR, even on a panel that just started.

Each half is remembered from the event ring itself. The DESTINATION also appears in the core's status
`active`, so it is always recoverable; the SOURCE appears nowhere else, so a fresh panel knew none until
one happened to rotate -- and since the destination rotates far more often, the cards right after a
restart were exactly the ones missing it. It is seeded from the live pool instead.

This drives the REAL ingest, stubbing only the two node RPCs: what broke was WHERE the other axis comes
from, and that lives in the ingest loop, not in the formatter. A guard calling _rot_pair directly would
have passed against the broken panel.

Exit 1 = a card lost its pair, or a half-empty arrow reached the log.
"""
import importlib.util
import sys

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
PANEL = __import__("pathlib").Path(__file__).resolve().parent.parent / "tnl-central.py"
spec = importlib.util.spec_from_file_location("c", PANEL)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

LINK = {"id": "L1", "type": "core", "enabled": True, "name": "core42",
        "transport": "raw", "ip_rotate": True, "a_node": "n1", "b_node": "n2"}

RING = []          # the core event ring the node would hand back
SRC_ACTIVE = ["94.183.210.128"]   # what peer-status reports as the live source (list so it can be emptied)
CARDS = []


def install():
    m.load_links = lambda: [LINK]
    m.load_events = lambda: []
    m.log_event = lambda level, kind, fa, dfa="": CARDS.append({"fa": fa, "dfa": dfa})
    m.api_edge_status = lambda d: {"ok": True, "pool": False, "active": "raw:bip · 78.47.72.179",
                                   "health": [], "events": list(RING), "now": 0, "ts": 0}
    m.api_peer_status = lambda d: {"ok": True, "pool": True, "now": 0,
                                   "dst": {"active": "78.47.72.179", "addrs": [], "health": [], "pin": "", "ts": 0},
                                   "src": {"active": SRC_ACTIVE[0] if SRC_ACTIVE else "",
                                           "addrs": [], "health": [], "pin": "", "ts": 0}}
    m._cache_get = lambda n: None
    m._node_online = lambda n: True
    m._link_down_reason = lambda L, nmap: ""
    m.load_nodes = lambda: []


def ev(seq, code, ip):
    return {"seq": seq, "ts": 0, "kind": "down", "code": code, "detail": "ip:" + ip}


def sweep():
    CARDS.clear()
    m._events_once()
    return list(CARDS)


def show(tag, cards):
    print(f"\n--- {tag} ---")
    for c in cards:
        print("  " + c["fa"])
        for ln in (c["dfa"].split("\n") if c["dfa"] else ["(no detail)"]):
            print("      " + ln)


fails = []


def want(cond, msg):
    print(("  ok   " if cond else " FAIL ") + msg)
    if not cond:
        fails.append(msg)


install()
# First sweep seeds the high-water silently, exactly as production does on a fresh panel.
RING[:] = [ev(1, "peer-rotate", "78.47.72.179")]
sweep()

print("=== a DESTINATION rotation, on a panel that has never seen a source rotation ===")
RING[:] = [ev(1, "peer-rotate", "78.47.72.179"), ev(2, "peer-rotate", "49.13.34.234")]
cards = sweep()
show("cards", cards)
want(len(cards) == 1, f"exactly one card, got {len(cards)}")
want(cards and "78.47.72.179 ← 94.183.210.128" in cards[0]["dfa"],
     "«از» must carry the source the tunnel was really on, destination-first for an RTL read")
want(cards and "49.13.34.234 ← 94.183.210.128" in cards[0]["dfa"],
     "«به» must carry it too — this is the whole bug")

print("\n=== then a SOURCE rotation: the destination half comes from the ring ===")
RING.append(ev(3, "src-rotate", "94.183.210.129"))
cards = sweep()
show("cards", cards)
want(cards and "49.13.34.234 ← 94.183.210.128" in cards[0]["dfa"],
     "«از» = the old source against the current destination")
want(cards and "49.13.34.234 ← 94.183.210.129" in cards[0]["dfa"], "«به» = the new source, same destination")

print("\n=== a node that cannot answer must not lose the card ===")
m._ev_state["rotip"].clear()
SRC_ACTIVE[:] = [""]
RING.append(ev(4, "peer-rotate", "78.47.72.179"))
cards = sweep()
show("cards", cards)
want(cards and cards[0]["dfa"].strip().endswith("78.47.72.179"),
     "with no source known it degrades to the single endpoint, as before")
want(cards and "←" not in cards[0]["dfa"], "and it must not print a half-empty arrow")

print(f"\n{len(fails)} failure(s)" if fails else "\nthe pair survives a fresh panel")
sys.exit(1 if fails else 0)
