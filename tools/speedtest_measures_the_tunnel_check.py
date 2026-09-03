"""Guard: the speed-test action measures the TUNNEL, and it measures the right direction.

The whole point of the button is that the number means the tunnel's own capacity. Two ways it could
quietly stop meaning that:

  - it could test between the nodes' PUBLIC addresses, which measures the internet path and would look
    fine while telling the operator nothing about the carrier they just reconfigured. The node never
    receives an address from the panel for this: the serving end reads its own tun interface and
    reports back the overlay address it bound, and the panel hands that -- and only that -- to the
    other end. So this asserts the panel passes back what serve returned and nothing it made up.
  - it could measure the wrong direction. Upload for the operator means Iran -> abroad, which is the
    tunnel's CLIENT -> SERVER leg, so the run must happen on the client end and the listener on the
    server end. A tunnel with server_side "b" has them the other way round, and getting that backwards
    would report the healthy leg while the broken one is the reason they pressed the button.

node_call is replaced so the panel's real handler runs against recorded node replies -- the shapes here
are what MMD-GE12 and MMD-IR12 actually returned on 2026-09-03, not invented ones.

Exit 1 on any mismatch.
"""
import importlib.util
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PANEL = Path(__file__).resolve().parent.parent / "tnl-central.py"

NODES = [{"id": "a1", "name": "GE-side", "host": "91.107.169.159"},
         {"id": "b1", "name": "IR-side", "host": "94.182.131.35"}]

SERVE_REPLY = {"ok": True, "ip": "192.168.17.1", "port": 5219, "secs": 8}
RUN_REPLY = {"ok": True, "secs": 8, "streams": 4, "up_mbit": 324.5, "down_mbit": 348.3}

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL  ") + msg)
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def drive(P, link, reply=None):
    calls = []

    def fake(node, op, method, body=None, timeout=None):
        calls.append({"node": node["name"], "op": op, "body": dict(body or {}), "timeout": timeout})
        if (body or {}).get("mode") == "serve":
            return (reply or {}).get("serve", SERVE_REPLY)
        return (reply or {}).get("run", RUN_REPLY)

    P.node_call = fake
    P.load_nodes = lambda: NODES
    P.get_node = lambda i: next((n for n in NODES if n["id"] == i), None)
    P.load_links = lambda: [link]
    try:
        return P.api_link_speed({"id": "L1"}), calls, None
    except ValueError as e:
        return None, calls, str(e)


def main():
    P = load()
    base = {"id": "L1", "name": "core17", "type": "core", "a_node": "a1", "b_node": "b1"}

    print("== the listener goes up on the server end, the run happens on the client end ==")
    for side, serves, runs in (("a", "GE-side", "IR-side"), ("b", "IR-side", "GE-side")):
        out, calls, err = drive(P, dict(base, server_side=side))
        modes = [(c["node"], c["body"].get("mode")) for c in calls]
        check(err is None and modes == [(serves, "serve"), (runs, "run")],
              "server_side=%s -> %s" % (side, modes if err is None else "refused: " + err))
        if out:
            check(out.get("from") == runs and out.get("to") == serves,
                  "  and it says the direction plainly: from=%s to=%s" % (out.get("from"), out.get("to")))

    print("== the address tested is the one the serving end reported, never a node's public IP ==")
    out, calls, err = drive(P, dict(base, server_side="a"))
    run_body = next((c["body"] for c in calls if c["body"].get("mode") == "run"), {})
    check(run_body.get("peer_ip") == SERVE_REPLY["ip"],
          "peer_ip passed to the runner is %r (serve reported %r)" % (run_body.get("peer_ip"), SERVE_REPLY["ip"]))
    check(run_body.get("port") == SERVE_REPLY["port"],
          "port passed to the runner is %r" % (run_body.get("port"),))
    publics = {n["host"] for n in NODES}
    check(not (publics & {str(v) for v in run_body.values()}),
          "no node's public address appears anywhere in the run request")
    check(run_body.get("name") == "core17", "the tunnel it tests is named: %r" % (run_body.get("name"),))

    print("== a tunnel with no server_side (gre, vxlan, fou) still works ==")
    out, calls, err = drive(P, dict(base, type="gre"))
    check(err is None and len(calls) == 2, "two calls, no error: %s" % (err or "ok"))

    print("== the numbers come back untouched ==")
    out, _, _ = drive(P, dict(base, server_side="a"))
    check(out and out.get("up_mbit") == RUN_REPLY["up_mbit"] and out.get("down_mbit") == RUN_REPLY["down_mbit"],
          "up=%s down=%s" % (out.get("up_mbit"), out.get("down_mbit")))

    print("== it refuses rather than reporting a meaningless zero ==")
    out, calls, err = drive(P, dict(base, server_side="a", enabled=False))
    check(err is not None and not calls, "a switched-off tunnel is refused before any node is called")
    out, calls, err = drive(P, dict(base, server_side="a"),
                            {"serve": {"ok": False, "error": "interface core17 has no IPv4 address"}})
    check(err is not None and "core17" in err, "a serving end with no tun address: %s" % (err or "ACCEPTED"))
    out, calls, err = drive(P, dict(base, server_side="a"), {"run": {"ok": False, "error": "bad peer"}})
    check(err is not None, "a runner that fails: %s" % (err or "ACCEPTED"))

    print("== the wire name says nothing, and both repos agree ==")
    src = PANEL.read_text(encoding="utf-8")
    check('"speedtest": "sd"' in src, "the panel maps speedtest onto a two-letter wire name")
    node = PANEL.parent.parent / "TUNNEL-MANAGER-NODE" / "tnl-node.py"
    if node.exists():
        check('"sd": "speedtest"' in node.read_text(encoding="utf-8"), "and the node maps it back")

    print()
    if fails:
        print("FAILED %d check(s)" % len(fails))
        return 1
    print("the button measures the tunnel itself, in the direction the operator means by upload")
    return 0


if __name__ == "__main__":
    sys.exit(main())
