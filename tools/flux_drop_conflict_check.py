"""Guard: a flux tunnel's anti-leak DROP rules are never invisible to the collision check.

The node installs, per flux tunnel, a DROP in the `raw` table's PREROUTING chain — the first kernel hook,
ahead of every socket. Whatever it matches is black-holed for the WHOLE host. The panel is the only place
that knows what else runs on that node, so `_flux_drop_conflict` refuses the build when those rules would
swallow another tunnel's traffic. The failure it prevents has no symptom an operator can chase: the other
tunnel simply stops carrying, with no event, no log, no probe reason, on a network that measures healthy.

That guard is only as good as `_flux_drop_points`. A carrier the function returns `[]` for is exempted
from the check entirely — it installs real kernel rules that nothing compares against. So:

  * every carrier the panel accepts must yield drop points, and
  * an UNKNOWN carrier must yield them too (fail-safe, not fail-open), and
  * the points must be UDP ports from the carrier's own pool — the one shape no other transport
    receives on — never a bare protocol number, and
  * the check must actually FIRE when a udp tunnel between the same nodes listens on a pool port.

Driven through the real functions with real link dicts; the last case runs `_flux_drop_conflict` against a
patched `load_links`, which is the path `api_tunnel_create` takes.

Exit 1 on any failure.
"""
import importlib.util
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
out = io.open(1, "w", encoding="utf-8", closefd=False)
bad = []


def chk(label, got, want):
    if got != want:
        bad.append(label)
        out.write("  FAIL %-62s %r != %r\n" % (label, got, want))
    else:
        out.write("  ok   %-62s %r\n" % (label, got))


spec = importlib.util.spec_from_file_location("tnl_central", os.path.join(ROOT, "tnl-central.py"))
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def flux_link(carrier, lid="f1", tid=41):
    # tunnel_id is mandatory on every link the panel stores and on both _flux_drop_conflict call sites;
    # _udp_recv_points derives the default port from it, so a fixture without one is not a real link.
    return {"id": lid, "type": "core", "transport": "flux", "flux_carrier": carrier, "tunnel_id": tid,
            "a_node": "n1", "b_node": "n2", "a_ip": "1.1.1.1", "b_ip": "2.2.2.2"}


CARRIERS = ("udp", "stun")   # pinned deliberately -- see the accepted-set check below


def core_extra(carrier):
    return P._core_extra({"transport": "flux", "id": 7, "cipher": "auto", "flux_carrier": carrier},
                         {}, "10.0.0.1", "10.0.0.2", ["10.0.0.1"], ["10.0.0.2"])


# ---- the accepted set is PINNED, not derived. Deriving it from _core_extra made this guard agree with
# whatever the code happened to allow, so re-adding a carrier passed silently. Both flux carriers ride
# UDP, and that is precisely why their PREROUTING DROP rules are narrow enough to be safe.
out.write("=== the carrier set the panel accepts is exactly %s ===\n" % (CARRIERS,))
for c in CARRIERS:
    try:
        core_extra(c)
        ok = True
    except Exception as e:
        ok = "%s: %s" % (type(e).__name__, e)
    chk("carrier %-5s is accepted" % c, ok, True)
for c in ("raw", "icmp", "bare", "gre", "tcp", "esp", "RAW", ""):
    if c == "":
        continue     # blank means "default", handled by the builder's own fallback
    try:
        core_extra(c)
        refused = False
    except Exception:
        refused = True
    chk("carrier %-5s is REFUSED" % c, refused, True)

# ---- drop points for EVERY carrier string, accepted or not. _flux_drop_points also runs over links read
# straight off disk, which never pass the builder's validation -- so an exemption keyed on a carrier the
# form no longer offers is still reachable, and is exactly how HIGH #1 stayed invisible. Anything that
# reaches this function must yield rules the collision check can see.
for c in list(CARRIERS) + ["raw", "icmp", "nonesuch", "", "UDP"]:
    pts = P._flux_drop_points(flux_link(c))
    chk("carrier %-8s yields drop points" % repr(c), len(pts) > 0, True)
    pool = P.FLUX_STUN_DPORTS if c == "stun" else P.FLUX_UDP_DPORTS
    chk("carrier %-8s uses only pool ports" % repr(c),
        sorted({p for _, _, p in pts}), sorted(pool))
    chk("carrier %-8s scopes each rule to a node+peer" % repr(c),
        all(n in ("n1", "n2") and a in ("1.1.1.1", "2.2.2.2") for n, a, _ in pts), True)

chk("a non-flux tunnel yields none", P._flux_drop_points(
    {"type": "core", "transport": "udp", "tunnel_id": 41, "a_node": "n1", "b_node": "n2"}), [])

# ---- the pools themselves. A rule is only safe because the port it drops is one no other tunnel
# receives on: the panel hands core/fou/l2tpv3 tunnels 20000+id, vxlan 4789, and dns is fixed at 53.
out.write("\n=== the pools stay clear of every port a tunnel of its own could receive on ===\n")
for name, pool in (("udp", P.FLUX_UDP_DPORTS), ("stun", P.FLUX_STUN_DPORTS)):
    chk("the %-4s pool is not empty" % name, len(pool) > 0, True)
    clash = [p for p in pool if p == 53 or p == 4789 or 20001 <= p <= 20255]
    chk("the %-4s pool collides with no tunnel port" % name, clash, [])

# ---- and the conflict really fires. A core/udp tunnel between the same pair, LISTENING on a pool port.
out.write("\n=== the collision is refused, not discovered later on the wire ===\n")
port = P.FLUX_UDP_DPORTS[0]
victim = {"id": "u1", "type": "core", "transport": "udp", "server_side": "a", "port": port,
          "tunnel_id": 42, "a_node": "n1", "b_node": "n2", "a_ip": "1.1.1.1", "b_ip": "2.2.2.2"}
saved = P.load_links
try:
    P.load_links = lambda: [victim]
    for c in CARRIERS:
        hit = P._flux_drop_conflict(flux_link(c))
        # stun's pool is a subset of udp's, so a port outside it legitimately does not collide.
        expect = port in (P.FLUX_STUN_DPORTS if c == "stun" else P.FLUX_UDP_DPORTS)
        chk("carrier %-5s vs a udp tunnel on :%d" % (c, port),
            (hit or {}).get("id") == "u1", expect)
    # the reverse direction too: the stored link is the flux one, the new build is the udp tunnel
    P.load_links = lambda: [flux_link("udp")]
    chk("and the mirror case (flux stored, udp built)",
        (P._flux_drop_conflict(victim) or {}).get("id"), "f1")
    # two flux tunnels between the same pair are NOT a conflict: neither receives UDP on a pool port
    chk("two flux tunnels are not a conflict",
        P._flux_drop_conflict(flux_link("udp", "f2")), None)
finally:
    P.load_links = saved

out.write("\n%s\n" % ("FAILURES: %s" % bad if bad else
                      "every accepted flux carrier is visible to the collision check"))
out.flush()
sys.exit(1 if bad else 0)
