#!/usr/bin/env python3
"""Guard: the conntrack bypass is offered, warned about, and never installed behind the operator's back.

A rotating source port mints one conntrack flow per new port. Measured on the live fleet: with
`every=4` that is ~5000 flows a second, and because `tcp_loose=1` makes a mid-stream packet an
ESTABLISHED entry with a 432000-second timeout, a 65536-entry table fills in about thirteen seconds
and stays pinned. `dmesg` then reads `nf_conntrack: table full, dropping packet` -- for this tunnel
AND for everything else on the node.

CORE #455 already tried to fix this inside the carrier and reverted it, for a reason that still
holds: an untracked packet is not ESTABLISHED, so `ufw default deny incoming` drops every reply and
the tunnel dies. Its conclusion was that a rule which changes how the HOST treats our packets is not
the carrier's to add, because the carrier cannot see the policy it lands in.

So this is the operator's switch, not the carrier's:

  * the NODE installs it, not the core, and only when the tunnel says so;
  * it installs the ACCEPT alongside the NOTRACK, which is the half whose absence killed ufw clients;
  * every rule carries the tunnel's owner tag, so the existing sweep removes them;
  * and when the switch is OFF and the table is filling, the card says so rather than staying silent.

    python3 tools/the_conntrack_bypass_is_opt_in_check.py
"""
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
NODE = Path(os.environ.get("NODE_DIR") or (ROOT.parent / "TUNNEL-MANAGER-NODE")) / "tnl-node.py"
IPS = ("203.0.113.5", "198.51.100.7", [], [])

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def core_extra(P, body, cur=None):
    try:
        ce, _ = P._core_extra(body, cur or {}, *IPS)
        return ce, None
    except ValueError as e:
        return None, str(e)


CARD = r"""
for (const c of CASES) { const h = ctbWarn(c[1]); console.log('@@' + JSON.stringify([c[0], !!h])) }
"""


def render(P, cases):
    import card_names_its_carrier_check as C
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    src = C.PRELUDE + "\n" + js + "\nconst CASES=" + json.dumps(cases) + ";" + CARD
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.js"
        p.write_text(src, encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8", timeout=90)
    if r.returncode != 0:
        print("FAIL: the page would not run:\n" + (r.stderr or "")[:700])
        sys.exit(1)
    return dict(json.loads(x[2:]) for x in r.stdout.splitlines() if x.startswith("@@"))


def main():
    sys.path.insert(0, str(ROOT / "tools"))
    P = load(PANEL, "tnl_ctb")
    raw = {"transport": "raw", "raw_profile": "tcp", "psk": "x" * 24, "cipher": "chacha20-poly1305",
           "tunnel_ip": "192.168.77.1/24", "raw_port": 20401, "raw_sport_rotate": 4}

    print("== the panel stores it, on every path that decides ==")
    ce, err = core_extra(P, dict(raw, conntrack_bypass=True))
    check(ce and ce.get("conntrack_bypass") is True, "a create/edit body turns it on", err or ce)
    ce, err = core_extra(P, dict(raw), {"conntrack_bypass": True, "raw_profile": "tcp"})
    check(ce and ce.get("conntrack_bypass") is True, "an edit that does not mention it inherits it", err or ce)
    ce, err = core_extra(P, dict(raw, conntrack_bypass=False), {"conntrack_bypass": True})
    check(ce is not None and not ce.get("conntrack_bypass"), "and it can be turned OFF again", err or ce)
    e = P._tunnel_extra({"type": "core", "transport": "raw", "raw_profile": "tcp",
                         "conntrack_bypass": True, "psk": "x" * 24}, refetch_ech=False)
    check(e.get("conntrack_bypass") is True, "a rebuild carries it forward", e)
    check("conntrack_bypass" in P._node_extra({"conntrack_bypass": True}),
          "and the NODE body carries it (the node is what installs the rules)")

    print("\n== a profile that forges no ports has nothing to bypass ==")
    ce, err = core_extra(P, {"transport": "raw", "raw_profile": "esp", "psk": "x" * 24,
                             "cipher": "chacha20-poly1305", "tunnel_ip": "192.168.77.1/24",
                             "conntrack_bypass": True})
    check(err is not None, "raw:esp with the bypass on is refused", ce)

    print("\n== the card warns exactly when it should ==")
    ct_full = {"count": 64000, "max": 65536, "pct": 98}
    cases = [
        ("rotating, table full, switch off", {"transport": "raw", "raw_profile": "tcp",
                                              "raw_sport_rotate": 4, "ct": ct_full}),
        ("reactive random, table full, switch off", {"transport": "raw", "raw_profile": "tcp",
                                                     "raw_sport_random": True, "ct": ct_full}),
        ("switch already on", {"transport": "raw", "raw_profile": "tcp", "raw_sport_rotate": 4,
                               "conntrack_bypass": True, "ct": ct_full}),
        ("table only 40% full", {"transport": "raw", "raw_profile": "tcp", "raw_sport_rotate": 4,
                                 "ct": {"count": 26000, "max": 65536, "pct": 40}}),
        ("nothing rotating", {"transport": "raw", "raw_profile": "tcp", "ct": ct_full}),
        ("a profile with no ports", {"transport": "raw", "raw_profile": "esp",
                                     "raw_sport_rotate": 4, "ct": ct_full}),
        ("the node reported no pressure", {"transport": "raw", "raw_profile": "tcp",
                                           "raw_sport_rotate": 4}),
        ("not a raw carrier", {"transport": "udp", "ct": ct_full}),
    ]
    want = {"rotating, table full, switch off": True,
            "reactive random, table full, switch off": True,
            "switch already on": False, "table only 40% full": False, "nothing rotating": False,
            "a profile with no ports": False, "the node reported no pressure": False,
            "not a raw carrier": False}
    got = render(P, cases)
    for k, w in want.items():
        check(got.get(k) is w, "%-42s -> %s" % (k, "warns" if w else "silent"), got.get(k))

    print("\n== the node installs the right rules, and only when asked ==")
    if not NODE.exists():
        print("  SKIP cross-repo check: no node checkout at %s" % NODE)
    else:
        N = load(NODE, "tnl_node_ctb")
        cfg = {"name": "core18", "type": "core", "role": "client", "transport": "raw",
               "raw_profile": "tcp", "remote_ip": "91.107.248.161"}
        rules = N._ct_bypass_rules(cfg)
        flat = [(t, c, " ".join(r)) for t, c, r in rules]
        check(any(t == "raw" and c == "OUTPUT" and "NOTRACK" in r for t, c, r in flat),
              "NOTRACK on the way out", flat)
        check(any(t == "raw" and c == "PREROUTING" and "NOTRACK" in r for t, c, r in flat),
              "NOTRACK on the way in", flat)
        check(any(t == "filter" and c == "INPUT" and "ACCEPT" in r for t, c, r in flat),
              "and an ACCEPT beside it — without this, ufw's deny drops every reply "
              "and the tunnel dies (CORE #455)", flat)
        check(all(N.RULE_OWNER_PREFIX + "core18" in r for _t, _c, r in flat),
              "every rule carries the owner tag, so the existing sweep removes them", flat)
        check(all("91.107.248.161" in r for _t, _c, r in flat),
              "and every rule is scoped to the peer, never global", flat)
        check(len(N._ct_bypass_rules(dict(cfg, raw_profile="esp"))) == 0,
              "a profile that forges no ports installs nothing")
        check(len(N._ct_bypass_rules(dict(cfg, transport="udp"))) == 0,
              "a non-raw carrier installs nothing")
        pooled = N._ct_bypass_rules(dict(cfg, peer_ips=["1.2.3.4:20000", "5.6.7.8"]))
        check(len(pooled) == 9, "an ip pool gets a rule per peer (%d)" % len(pooled))

        N.base_mtu = lambda *a, **k: 1500
        cc = N._core_config(dict(cfg, tunnel_ip="192.168.18.2/24", psk="x" * 40, cipher="auto",
                                 conntrack_bypass=True, iface="eth0"))
        check("conntrack_bypass" not in cc,
              "the CORE config never sees the key — this is the node's business, not the carrier's",
              sorted(k for k in cc if "conn" in k))

        src = NODE.read_text(encoding="utf-8")
        m = re.search(r"_core_relaunch\(name\)\s*\n\s*if _as_bool\(cfg\.get\(\"conntrack_bypass\"\)\)", src)
        check(bool(m), "build_core installs it AFTER the relaunch, so the sweep cannot eat it")

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("the bypass is the operator's switch, and the card asks for it when it is needed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
