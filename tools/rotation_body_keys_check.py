"""Guard: an IP-rotation body carries only the keys the core will accept for that transport.

`listen_ips` is read by the udp and tcp servers alone. Every other transport's server binds `listen`
and the core REFUSES the key: config.go returns "listen_ips is read only by the udp and tcp servers".
The panel built it for raw too, and the only thing between that and a core exiting at startup
was the node's whitelist happening to drop it again — a gate written for a different reason, two repos
away, which nothing ties to this.

So: drive the REAL builder for every direct transport and both roles, and pin the key sets. Pinned
here, not derived from the panel: a guard that asks the code under test what it should do agrees with
the bug. The core's own refusal is checked as a separate line, so relaxing it there shows up here
instead of silently making this guard wrong.

Exit 1 on any mismatch.
"""
import importlib.util
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent.parent
PANEL = HERE / "tnl-central.py"
CORE_CONFIG = HERE.parent / "TUNNEL-MANAGER-CORE" / "config.go"

# The transports whose SERVER may be handed listen_ips. Pinned.
LISTEN_IPS_OK = {"udp", "tcp"}


def load_panel():
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("tnl_central_rot", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    mod = load_panel()
    fails = []

    for tr in mod.DIRECT_TRANSPORTS:
        a = {"role": "server", "transport": tr}
        b = {"role": "client", "transport": tr}
        mod._core_rotation_bodies({"ip_rotate": True, "transport": tr,
                                   "a_ip_pool": ["1.1.1.1", "1.1.1.2"], "b_ip_pool": ["2.2.2.2"],
                                   "rotate_secs": 600}, a, b)
        want = tr in LISTEN_IPS_OK
        got = "listen_ips" in a
        ok = got == want
        print(("  ok   " if ok else " FAIL ") +
              f"{tr:5} server: listen_ips {'present' if got else 'absent'}"
              + ("" if ok else f"  <-- want {'present' if want else 'absent'}; the core refuses it here"))
        if not ok:
            fails.append(f"{tr}/listen_ips")
        # The rotation itself must still be applied — an empty body would pass the check above for the
        # wrong reason.
        if not a.get("pool_listen"):
            print(f" FAIL {tr:5} server: no pool_listen at all, so nothing above was really exercised")
            fails.append(f"{tr}/pool_listen")
        if not b.get("peer_ips"):
            print(f" FAIL {tr:5} client: no peer_ips at all, so nothing above was really exercised")
            fails.append(f"{tr}/peer_ips")
        # A client is never given listen_ips whatever its transport.
        if "listen_ips" in b:
            print(f" FAIL {tr:5} client: carries listen_ips, which is a server-only key")
            fails.append(f"{tr}/client-listen_ips")

    # And the premise: the core still refuses it. If this line goes, revisit LISTEN_IPS_OK rather than
    # trusting a guard whose reason has quietly expired.
    if CORE_CONFIG.exists():
        src = CORE_CONFIG.read_text(encoding="utf-8", errors="replace")
        ok = re.search(r'listen_ips is read only by the udp and tcp servers', src) is not None
        print(("  ok   " if ok else " FAIL ") +
              "core: config.go still refuses listen_ips on every other transport")
        if not ok:
            fails.append("core/refusal-gone")
    else:
        print("  --   core: config.go not beside the panel; the refusal itself was not re-checked")

    print()
    if fails:
        print(f"{len(fails)} rotation-body problem(s): {', '.join(fails)}")
        return 1
    print("a rotation body carries listen_ips only where a server reads it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
