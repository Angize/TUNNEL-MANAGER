#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every way out to a node must resolve through node_proxy — no exceptions, no third path.

A node the operator marked as proxied, reaching out in the clear, is the one failure the proxy feature
exists to prevent: on a filtered path the panel then talks to the node from an address the censor can
see, and the operator has no way to tell from the UI.

There are exactly TWO exits: the agent HTTP (node_call) and the SSH leg at install time (_ssh_argv's
ProxyCommand). This drives BOTH through their REAL entry points -- node_call() and api_node_install()
-- with only the connect primitives faked, so a path that skips node_proxy cannot pass by having a
helper that happens to be correct. Part 3 is a tripwire: a NEW outbound primitive anywhere in the
panel fails this check until it is either routed through the proxy or named here as node-unrelated.

    python3 tools/node_egress_uses_proxy_check.py
"""
import argparse
import ast
import importlib.util
import sys
from pathlib import Path

PX = {"id": "px1", "name": "P1", "scheme": "socks5", "host": "10.9.9.9", "port": 1080,
      "user": "pu", "pass": "pw"}
PX_HTTP = {"id": "px2", "name": "P2", "scheme": "http", "host": "10.9.9.8", "port": 3128,
           "user": "", "pass": ""}
RELAY = "/tmp/relay-sentinel.py"

# Outbound primitives, mapped to {owning function: how many call sites it may hold}. The COUNT is the
# point: keying on the function name alone lets a second, unproxied dial hide inside a function that is
# already allowed -- measured, it slipped through silently.
# A node's traffic may only leave via node_call / _node_call_proxied / the SSH relay, all of which
# resolve through node_proxy; every other entry here talks to GitHub or a DoH resolver, never to a node.
ALLOWED_EGRESS = {
    "urlopen": {
        "node_call": 1,              # DIRECT agent HTTP -- reached only when node_proxy returned ''
        "api_agent_fetch_git": 1,    # GitHub: the node agent source
        "_fetch_core_versions": 1,   # GitHub: the core release list
        "_dl": 1,                    # GitHub: a core release asset
        "via_doh": 1,                # public DoH resolver, for an ECH key
    },
    "create_connection": {
        "_socks5_socket": 1,         # to the PROXY, on node_call's and via_doh_proxy's behalf
        "_http_connect_socket": 1,   # to the PROXY, on node_call's and via_doh_proxy's behalf
        # Both reach the PROXY's own host:port, never a node: the fallback for «تستِ اتصال» and for the
        # poller's dot when no node takes that proxy yet, so there is nothing to reach THROUGH it.
        "api_proxy_test": 1,
        "_proxy_probe": 1,
    },
    # Neither dials: an already-tunneled socket is assigned to conn.sock, so conn.connect() never runs.
    "HTTPConnection": {
        "_node_call_proxied": 1,
        "via_doh_proxy": 1,          # a DoH resolver over the proxy, for an ECH key
    },
}


def load_panel(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------- part 1: the agent HTTP (node_call)
def wire_node_call(P, seen):
    """Fake ONLY the connect primitives. Returns a restore callable -- urllib is a process-wide module,
    and leaving it patched would silently poison whatever the next part drives."""
    real_urlopen = P.urllib.request.urlopen

    def direct(req, timeout=None):
        seen.append(("DIRECT", getattr(req, "full_url", str(req))))
        raise OSError("blocked by the guard")

    def socks(ph, pp, pu, pw, dh, dp, timeout):
        seen.append(("socks5", "%s:%s" % (ph, pp), "%s:%s" % (dh, dp), pu, pw))
        raise OSError("recorded by the guard")

    def connect(ph, pp, pu, pw, dh, dp, timeout):
        seen.append(("http", "%s:%s" % (ph, pp), "%s:%s" % (dh, dp), pu, pw))
        raise OSError("recorded by the guard")

    P.urllib.request.urlopen = direct
    P._socks5_socket = socks
    P._http_connect_socket = connect

    def restore():
        P.urllib.request.urlopen = real_urlopen

    return restore


def part1(P, failures):
    seen = []
    restore = wire_node_call(P, seen)
    proxies = [PX, PX_HTTP]
    P.load_proxies = lambda: list(proxies)

    node = {"id": "n1", "name": "DE01", "host": "91.107.190.159", "port": 8099, "token": "t"}
    cases = [
        ("proxy_on with a socks5 entry", {"proxy_on": True, "proxy_id": "px1"},
         [("socks5", "10.9.9.9:1080", "91.107.190.159:8099", "pu", "pw")]),
        ("proxy_on with an http entry", {"proxy_on": True, "proxy_id": "px2"},
         [("http", "10.9.9.8:3128", "91.107.190.159:8099", None, None)]),
        ("no proxy at all — a direct dial is correct here", {},
         [("DIRECT", "http://91.107.190.159:8099/api/ping")]),
        ("proxy_on with an id that names nothing — node_proxy says direct", {"proxy_on": True, "proxy_id": "gone"},
         [("DIRECT", "http://91.107.190.159:8099/api/ping")]),
        ("an id is stored but the toggle is off", {"proxy_on": False, "proxy_id": "px1"},
         [("DIRECT", "http://91.107.190.159:8099/api/ping")]),
    ]
    for label, ref, want in cases:
        seen.clear()
        n = dict(node, **ref)
        P.node_call(n, "ping", "GET")
        if seen != want:
            failures.append("[node_call: %s] the panel dialled %r, expected %r" % (label, seen, want))
            continue
        print("  ok  node_call — %-52s %s" % (label, seen[0][0]))

    # The class in one line: EVERY endpoint of a proxied node leaves through the proxy. Asserting the
    # whole dial, not just "no DIRECT" -- the negative form also passes when nothing is dialled at all.
    want = [("socks5", "10.9.9.9:1080", "91.107.190.159:8099", "pu", "pw")]
    for endpoint in ("ping", "status", "tunnel", "delete", "core-install", "kernel-tune"):
        seen.clear()
        P.node_call(dict(node, proxy_on=True, proxy_id="px1"), endpoint, "POST", {"x": 1})
        if seen != want:
            failures.append("[node_call: endpoint %r] dialled %r, expected %r" % (endpoint, seen, want))
    print("  ok  node_call — every endpoint leaves through the proxy (6 endpoints)")
    restore()


# ------------------------------------------------------- part 2: the SSH leg (real api_node_install)
class _InlineThread:
    """Run the install worker on THIS thread so the guard observes it instead of racing it."""

    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)


def part2(P, failures):
    argvs, saved = [], {}
    real_ssh_argv, real_thread = P._ssh_argv, P.threading.Thread

    def ssh_run(cfg, remote_cmd, timeout):
        argv, env = real_ssh_argv(cfg, remote_cmd)   # the REAL builder, on the REAL cfg
        argvs.append((argv, env))
        if remote_cmd == "echo TNL_SSH_OK":
            return 0, "TNL_SSH_OK\n", ""
        if "tnl-node.py" in remote_cmd and "--auto-install" in remote_cmd:
            return 0, "TNL_INSTALL_OK\nTNL_NODE_TOKEN=tok123\n", ""
        return 0, "TNL_DL_OK\n", ""

    P.load_proxies = lambda: [PX, PX_HTTP]
    P.load_nodes = lambda: []
    P.save_json = lambda path, obj: saved.__setitem__(path, obj)
    P._ensure_proxy_relay = lambda: RELAY
    P._ssh_run = ssh_run
    P.threading.Thread = _InlineThread
    P.node_call = lambda *a, **k: {"ok": True}
    P._refresh_cache = lambda *a, **k: None
    P._push_staged_on_add = lambda *a, **k: None
    P.get_node = lambda nid: None
    P.time.sleep = lambda *_: None

    base = {"name": "DE02", "ssh_host": "5.75.197.55", "ssh_pass": "pw", "agent_port": 8099}
    cases = [
        ("proxy_on socks5", dict(base, proxy_on=True, proxy_id="px1"), "10.9.9.9", "socks5", "px1"),
        ("proxy_on http", dict(base, proxy_on=True, proxy_id="px2"), "10.9.9.8", "http", "px2"),
        ("no proxy", dict(base), "", "", ""),
    ]
    for label, body, want_host, want_scheme, want_id in cases:
        argvs.clear()
        saved.clear()
        res = P.api_node_install(body)
        if not res.get("ok"):
            failures.append("[install: %s] the handler refused: %r" % (label, res))
            continue
        if not argvs:
            failures.append("[install: %s] no SSH command was built at all — this check saw nothing "
                            "and must not report success" % label)
            continue
        for argv, env in argvs:
            joined = " ".join(argv)
            has_pc = "ProxyCommand=" in joined
            if want_host and not has_pc:
                failures.append("[install: %s] the SSH leg carries NO ProxyCommand — the install talks "
                                "to the node in the clear while its agent HTTP is proxied: %r"
                                % (label, argv))
            if not want_host and has_pc:
                failures.append("[install: %s] an unproxied node got a ProxyCommand: %r" % (label, argv))
            if want_host and RELAY not in joined:
                failures.append("[install: %s] ProxyCommand does not run the relay: %r" % (label, argv))
            if env.get("TNL_PXY_HOST", "") != want_host:
                failures.append("[install: %s] relay aimed at TNL_PXY_HOST=%r, expected %r — the SSH leg "
                                "must use the SAME registry entry as node_call"
                                % (label, env.get("TNL_PXY_HOST", ""), want_host))
            if want_scheme and env.get("TNL_PXY_SCHEME", "") != want_scheme:
                failures.append("[install: %s] relay scheme=%r, expected %r"
                                % (label, env.get("TNL_PXY_SCHEME", ""), want_scheme))

        # The registered node has to KEEP the reference, or every later call falls back to direct.
        nodes = saved.get(P.NODES_FILE) or []
        if not nodes:
            failures.append("[install: %s] the install never registered the node, so this check cannot "
                            "see what it stored" % label)
        else:
            n = nodes[-1]
            if bool(n.get("proxy_on")) != bool(want_id) or str(n.get("proxy_id") or "") != want_id:
                failures.append("[install: %s] registered proxy_on=%r proxy_id=%r, expected %r/%r — the "
                                "node would go out direct on its very next call"
                                % (label, n.get("proxy_on"), n.get("proxy_id"), bool(want_id), want_id))
        print("  ok  install  — %-52s %s" % (label, want_host or "direct"))

    # A dangling id must be refused at the door, not downgraded to a direct install.
    try:
        P.api_node_install(dict(base, proxy_on=True, proxy_id="gone"))
        failures.append("[install: dangling proxy_id] accepted — the operator would get a node they "
                        "believe is proxied, installed in the clear")
    except ValueError:
        print("  ok  install  — %-52s refused" % "proxy_on with an id that names nothing")
    P.threading.Thread = real_thread   # threading is process-wide; do not leave it inlined


# ------------------------------------------------------------------- part 3: no third egress appears
def egress_sites(tree):
    """{primitive: {enclosing function: [linenos]}} — the INNERMOST function owns the call, so a nested
    helper is never filed under the function that happens to contain it."""
    found = {k: {} for k in ALLOWED_EGRESS}

    def visit(node, fname):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
            if name in found:
                found[name].setdefault(fname, []).append(node.lineno)
        for child in ast.iter_child_nodes(node):
            inner = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else fname
            visit(child, inner)

    visit(tree, "<module>")
    return found


def part3(P, panel_path, failures):
    text = panel_path.read_text(encoding="utf-8")
    found = egress_sites(ast.parse(text))

    total = 0
    for prim, allowed in sorted(ALLOWED_EGRESS.items()):
        for fname in sorted(set(found[prim]) | set(allowed)):
            got, want = found[prim].get(fname, []), allowed.get(fname, 0)
            total += len(got)
            if len(got) == want:
                continue
            if not want:
                failures.append("a NEW %s() call site in %s() (line %s) — if it can reach a node it must "
                                "go through node_proxy(); if it cannot, add it to ALLOWED_EGRESS and say "
                                "why" % (prim, fname, got[0]))
            elif not got:
                failures.append("%s() no longer calls %s() — this allowlist has gone stale, so the "
                                "tripwire is watching code that moved" % (fname, prim))
            else:
                failures.append("%s() holds %d %s() call site(s), expected %d (lines %s) — an ADDED dial "
                                "inside an already-allowed function is exactly what hides an unproxied "
                                "egress" % (fname, len(got), prim, want, got))
    print("  ok  tripwire — %d outbound call sites, all accounted for" % total)

    # The SSH exit's other half is a STRING in the panel, so the AST above cannot see it. The relay must
    # dial the PROXY (ph, pp) -- a relay that dialled the destination would leave SSH unproxied while
    # every ProxyCommand option still looked correct.
    relay = getattr(P, "_PROXY_RELAY_SRC", None)
    if not relay:
        failures.append("_PROXY_RELAY_SRC is gone — the SSH ProxyCommand relay this check assumes no "
                        "longer exists, so its half of the proof is missing")
        return
    dialled = []
    for node in ast.walk(ast.parse(relay)):
        if isinstance(node, ast.Call):
            f = node.func
            if (f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")) != "create_connection":
                continue
            arg = node.args[0] if node.args else None
            dialled.append(tuple(getattr(e, "id", "?") for e in arg.elts) if isinstance(arg, ast.Tuple)
                           else "?")
    if dialled != [("ph", "pp")]:
        failures.append("the SSH relay dials %r, expected exactly one connection to the proxy ('ph','pp') "
                        "— dialling the destination would silently unproxy every install" % (dialled,))
    else:
        print("  ok  relay    — the SSH ProxyCommand relay dials the proxy, not the node")


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()
    panel_path = Path(a.panel)

    P = load_panel(panel_path)
    failures = []
    part1(P, failures)
    part2(P, failures)
    part3(P, panel_path, failures)

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nboth exits to a node -- agent HTTP and the install SSH -- resolve through node_proxy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
