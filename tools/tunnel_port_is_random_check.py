"""Guard: a new tunnel's port is drawn at random and never reuses one another tunnel already holds.

The allocator used to hand out the LOWEST free port from 20000 up. The first tunnel between two nodes
got 20000, the next 20001, the next 20002 — so anyone who saw one tunnel knew where to look for the
rest, and a node's tunnel count was readable off the port numbers alone.

It also scoped "free" to links that shared a node with this pair, which meant the same port number came
back on an unrelated pair. That is correct for the kernel (two tunnels on different machines may share
a number) but it hands an observer a second regularity for free.

So: one draw, `rand_port`, over a fixed band, and a port any link anywhere already holds is not in it.

Every property below is driven through the REAL `free_tunnel_port` with `load_links` swapped for a
synthetic fleet — no reimplementation of the allocator here, because a guard that reimplements what it
is guarding agrees with the bug.

Exit 1 on any mismatch.
"""
import importlib.util
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

A = {"id": "aaaa"}
B = {"id": "bbbb"}
C = {"id": "cccc"}
D = {"id": "dddd"}

fails = []


def check(ok, msg):
    print(("  ok  " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def load_panel():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    P = load_panel()
    lo, hi = P.PORT_BAND_LO, P.PORT_BAND_HI
    links = []
    P.load_links = lambda: links

    print("== 1) every draw lands inside the band ==")
    got = [P.free_tunnel_port(A, B) for _ in range(400)]
    check(all(lo <= p <= hi for p in got),
          "400 draws inside [%d,%d]: min=%d max=%d" % (lo, hi, min(got), max(got)))

    print("== 2) the draw is not the lowest free port ==")
    # The old allocator returned exactly lo every time against an empty fleet. One draw could land on
    # lo by chance; four hundred landing there is the old shape.
    check(got.count(lo) < 5,
          "%d of 400 draws returned the first port in the band (the old allocator returned it 400/400)"
          % got.count(lo))
    check(len(set(got)) > 350,
          "%d distinct ports in 400 draws — the draw spreads over the band" % len(set(got)))

    print("== 3) a port another tunnel holds is never drawn again ==")
    # 60 tunnels, allocated one after another exactly as the create path does it.
    links.clear()
    taken = []
    for i in range(60):
        p = P.free_tunnel_port(A, B)
        if p in taken:
            check(False, "draw %d reused port %d, which tunnel %d already holds" % (i, p, taken.index(p)))
            break
        taken.append(p)
        links.append({"id": "l%d" % i, "a_node": A["id"], "b_node": B["id"], "port": p})
    else:
        check(True, "60 tunnels on one node pair took 60 distinct ports")

    print("== 4) ...even when the other tunnel shares no node with this pair ==")
    # This is the behaviour that changed: `used` used to be filtered to links touching A or B.
    links.clear()
    links.extend({"id": "far%d" % i, "a_node": C["id"], "b_node": D["id"], "port": lo + i}
                 for i in range(hi - lo))
    p = P.free_tunnel_port(A, B)
    check(p == hi, "with every port but %d held by an UNRELATED pair, the draw returned %d" % (hi, p))

    print("== 5) an edit does not collide with the tunnel it is editing ==")
    links.clear()
    links.extend({"id": "far%d" % i, "a_node": C["id"], "b_node": D["id"], "port": lo + i}
                 for i in range(hi - lo + 1))
    links[7]["id"] = "mine"
    p = P.free_tunnel_port(A, B, exclude_id="mine")
    check(p == lo + 7, "the only port left is the edited tunnel's own %d, and the draw returned %d"
          % (lo + 7, p))

    print("== 6) a full band is an error, not a port outside it ==")
    links.clear()
    links.extend({"id": "l%d" % i, "a_node": A["id"], "b_node": B["id"], "port": lo + i}
                 for i in range(hi - lo + 1))
    try:
        p = P.free_tunnel_port(A, B)
        check(False, "a full band returned %d instead of raising" % p)
    except ValueError:
        check(True, "a full band raises rather than handing back a port outside it")

    print("== 7) rand_port is the one draw both paths go through ==")
    src = PANEL.read_text(encoding="utf-8")
    check(src.count("def rand_port(") == 1, "rand_port is defined once")
    check("free[secrets.randbelow(len(free))]" in src,
          "the draw uses secrets, not the predictable random module")
    check("while port in used" not in src, "the lowest-free-port walk is gone")

    print()
    if fails:
        print("FAILED %d check(s)" % len(fails))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
