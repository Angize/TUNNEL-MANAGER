#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the core edit modal can move a tunnel to a different NODE, and the move is complete.

Until now the two nodes were the one thing the edit modal could not change. Everything else -- the
carrier, the cipher, the addresses, the roles, the subnet -- was editable in place, but to put an
existing tunnel on a different box you had to delete it and build it again, losing its id, its
history and its traffic counters. `_edit_link_impl` read its two nodes straight out of the stored
link and never looked at the request.

Moving a tunnel is not "the same edit with different arguments". Four things have to happen together
and any one of them left out is a silent mess on somebody's server:

  * the OLD node has to be told to delete the tunnel, or it keeps a live core, a tun device and a
    pile of iptables rules for a tunnel the panel now believes lives elsewhere -- an orphan nothing
    sweeps, because the sweeper only removes rules whose tunnel the node itself no longer has;
  * the NEW node has to be built with a self_ip that is actually ON it -- the stored address belongs
    to the box being left, so carrying it over would configure an address the new node does not own;
  * the registry has to record where it went, both the id and the cached name;
  * and if the build fails, the tunnel has to come back on the node it started on, with nothing left
    behind on the node it was moving to.

The lock matters too and cannot be seen from the outside: api_edit_link locked the pair it read from
the link, so a move took no lock at all on the node it was moving TO. Two concurrent edits could
build on that node at once. It now locks the union.

Driven through the real api_edit_link with a recording node layer, so every claim is about what the
panel actually sent to which node. The browser half runs the modal's own functions to prove the
picker offers other nodes and the submit carries them -- a backend that accepts a_node is worth
nothing if no screen can send one.

    python3 tools/an_edit_can_move_the_tunnel_check.py

Exit 1 on any failure.
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import act_wait                                                   # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
fails = []

IPS = {"na": ["203.0.113.5", "203.0.113.6"],
       "nb": ["198.51.100.9"],
       "nc": ["192.0.2.30", "192.0.2.31"],
       "nd": ["198.18.0.7"]}


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %r" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel(state, tag):
    spec = importlib.util.spec_from_file_location("tnl_move_" + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    return m


def rig(tag, fail_on=None, configs=None, list_dead=None):
    """A four-node panel holding one core tunnel on na<->nb. Returns (module, calls).

    configs: {node_id: [config, ...]} for what a node answers `list` with.
    list_dead: a node id whose `list` comes back unreadable."""
    state = tempfile.mkdtemp()
    m = load_panel(state, tag)
    m.save_json(m.NODES_FILE, [{"id": i, "name": i.upper(), "host": IPS[i][0], "port": 8099,
                                "token": "t" * 20} for i in ("na", "nb", "nc", "nd")])
    m.save_json(m.LINKS_FILE, [{
        "id": "L1", "name": "core7", "type": "core", "tunnel_id": 7,
        "subnet": "192.168.7.0/24", "transport": "udp", "cipher": "aes-256-gcm",
        "psk": "0" * 32, "port": 20007, "server_side": "a", "enabled": True,
        "a_node": "na", "a_name": "NA", "a_ip": IPS["na"][0],
        "b_node": "nb", "b_name": "NB", "b_ip": IPS["nb"][0]}])
    m._ping_both = lambda A, B: ({"ok": True, "ips": {"eth0": IPS[A["id"]]}},
                                 {"ok": True, "ips": {"eth0": IPS[B["id"]]}})
    m._flat_ips = lambda p: list((p.get("ips") or {}).get("eth0") or [])
    calls = []

    def node_call(n, op, *a, **k):
        calls.append((n["id"], op, (a[1] if len(a) > 1 and isinstance(a[1], dict) else {}).get("name")))
        if op == "list":
            if n["id"] == list_dead:
                return {"ok": False, "error": "busy"}
            return {"ok": True, "configs": (configs or {}).get(n["id"], [])}
        return {"ok": True}

    def node_tunnel(n, body, *a, **k):
        calls.append((n["id"], "tunnel", body.get("self_ip")))
        if fail_on and n["id"] == fail_on:
            return {"ok": False, "error": "refused"}
        return {"ok": True, "tunnel_ip": "192.168.7.1"}

    m.node_call = node_call
    m._node_tunnel = node_tunnel
    m._refresh_cache = lambda ids: calls.append(("cache", "refresh", tuple(sorted(str(i) for i in ids))))
    return m, calls


def edit(m, **extra):
    d = {"id": "L1", "type": "core", "cipher": "aes-256-gcm", "transport": "udp", "server_side": "a"}
    d.update(extra)
    try:
        act_wait.raising(m, lambda: m.api_edit_link(d))
        return None
    except Exception as e:                                        # noqa: BLE001
        return str(e)


def stored(m):
    return next((x for x in m.load_links() if x["id"] == "L1"), {})


def deleted_on(calls):
    return sorted({c[0] for c in calls if c[1] == "delete"})


def built_on(calls):
    return [(c[0], c[2]) for c in calls if c[1] == "tunnel"]


def backend():
    print("\n-- moving one end: the new node is built, the old one is emptied --")
    m, calls = rig("m1")
    err = edit(m, a_node="nc", a_ip=IPS["nc"][1])
    check(err is None, "the move runs", err)
    L = stored(m)
    check(L.get("a_node") == "nc", "the registry records the node it moved to", L.get("a_node"))
    check(L.get("a_name") == "NC", "  and the cached name with it", L.get("a_name"))
    check(L.get("a_ip") == IPS["nc"][1], "  and the address chosen ON that node", L.get("a_ip"))
    check(L.get("b_node") == "nb", "  and leaves the other end alone", L.get("b_node"))
    check("na" in deleted_on(calls), "the node it LEFT is told to delete the tunnel", deleted_on(calls))
    check(("nc", IPS["nc"][1]) in built_on(calls), "the node it arrived on is built", built_on(calls))
    check(not any(c[0] == "na" and c[1] == "tunnel" for c in calls),
          "and nothing is rebuilt on the node it left", built_on(calls))
    ref = [c[2] for c in calls if c[0] == "cache"]
    check(ref and set(ref[-1]) >= {"na", "nb", "nc"},
          "the cache is refreshed for the node it left AND the one it joined", ref)

    print("\n-- moving BOTH ends at once --")
    m, calls = rig("m2")
    err = edit(m, a_node="nc", b_node="nd", a_ip=IPS["nc"][0], b_ip=IPS["nd"][0])
    check(err is None, "the move runs", err)
    L = stored(m)
    check((L.get("a_node"), L.get("b_node")) == ("nc", "nd"),
          "both ends are recorded", (L.get("a_node"), L.get("b_node")))
    check(deleted_on(calls) == ["na", "nb", "nc", "nd"],
          "the old name is torn down on all four boxes before the build", deleted_on(calls))
    check(sorted(built_on(calls)) == sorted([("nc", IPS["nc"][0]), ("nd", IPS["nd"][0])]),
          "and only the two new ones are built", built_on(calls))

    print("\n-- the address cannot be carried onto a node that does not own it --")
    m, _ = rig("m3")
    err = edit(m, a_node="nc", a_ip=IPS["na"][0])
    check(err is not None and "203.0.113.5" in err,
          "an address from the old node is refused by name", err)
    check(stored(m).get("a_node") == "na", "and the tunnel has not moved", stored(m).get("a_node"))

    print("\n-- and with no address at all, the new node's own is chosen --")
    m, calls = rig("m4")
    err = edit(m, a_node="nc")
    check(err is None, "the move runs", err)
    check(stored(m).get("a_ip") == IPS["nc"][0],
          "the first address of the NEW node is used, not the stored one", stored(m).get("a_ip"))
    check(("nc", IPS["nc"][0]) in built_on(calls), "  and that is what the node was told",
          built_on(calls))

    print("\n-- both ends on one node is refused --")
    for label, extra in (("a moved onto b", {"a_node": "nb"}),
                         ("both moved to the same box", {"a_node": "nc", "b_node": "nc"})):
        m, calls = rig("m5" + label[:3])
        err = edit(m, **extra)
        check(err is not None, "%s is refused" % label, err)
        check(stored(m).get("a_node") == "na" and stored(m).get("b_node") == "nb",
              "  and nothing moved", (stored(m).get("a_node"), stored(m).get("b_node")))
        check(not any(c[1] == "tunnel" for c in calls), "  and no node was built", built_on(calls))

    print("\n-- a failed move puts the tunnel back and leaves nothing behind --")
    m, calls = rig("m6", fail_on="nc")
    err = edit(m, a_node="nc")
    check(err is not None and "بازگردانده" in err, "the operator is told it was rolled back", err)
    L = stored(m)
    check(L.get("a_node") == "na" and L.get("a_ip") == IPS["na"][0],
          "the registry still points at the old node", (L.get("a_node"), L.get("a_ip")))
    rebuilt = [c for c in calls if c[1] == "tunnel" and c[0] in ("na", "nb")]
    check(len(rebuilt) == 2, "the old pair is rebuilt as it was", rebuilt)
    check(any(c[0] == "nc" and c[1] == "delete" for c in calls[calls.index(
              next(c for c in calls if c[0] == "nc" and c[1] == "tunnel")):]),
          "and the node it was moving to is cleaned up after the failure",
          [c for c in calls if c[0] == "nc"])

    print("\n-- a node that already holds this id is not quietly overwritten --")
    for label, kw in (
            ("a config with the same name", {"configs": {"nc": [{"name": "core7", "id": 99}]}}),
            ("a config with the same id", {"configs": {"nc": [{"name": "other", "id": 7}]}})):
        m, calls = rig("m8" + label[2:5], **kw)
        err = edit(m, a_node="nc")
        check(err is not None, "%s: the move is refused" % label, err)
        check(stored(m).get("a_node") == "na", "  and nothing moved", stored(m).get("a_node"))
        check(not any(c[0] == "nc" and c[1] in ("delete", "tunnel") for c in calls),
              "  and that node is neither emptied nor built", [c for c in calls if c[0] == "nc"])

    m, calls = rig("m9", list_dead="nc")
    err = edit(m, a_node="nc")
    check(err is not None, "a node whose list cannot be read is refused, not assumed empty", err)
    check(not any(c[0] == "nc" and c[1] == "delete" for c in calls),
          "  and nothing is deleted on it", [c for c in calls if c[0] == "nc"])

    m, calls = rig("m10", configs={"nc": [{"name": "core9", "id": 9}]})
    err = edit(m, a_node="nc")
    check(err is None, "a node holding OTHER tunnels is fine to move onto", err)
    check(stored(m).get("a_node") == "nc", "  and the move lands", stored(m).get("a_node"))

    print("\n-- an ordinary edit that moves nothing behaves exactly as before --")
    m, calls = rig("m7")
    err = edit(m, transport="tcp")
    check(err is None, "the edit runs", err)
    L = stored(m)
    check((L.get("a_node"), L.get("b_node")) == ("na", "nb"), "the nodes are untouched",
          (L.get("a_node"), L.get("b_node")))
    check(deleted_on(calls) == ["na", "nb"], "only its own two nodes are touched", deleted_on(calls))
    check(sorted(built_on(calls)) == sorted([("na", IPS["na"][0]), ("nb", IPS["nb"][0])]),
          "and both are rebuilt in place", built_on(calls))
    check(not any(c[1] == "list" for c in calls),
          "and an edit that moves nothing asks no node for its list", calls)


def locking():
    print("\n-- the move locks the node it is moving TO, not only the pair it reads --")
    state = tempfile.mkdtemp()
    m = load_panel(state, "lock")
    seen = {}

    class Rec:
        def __init__(self, *ids):
            seen["ids"] = sorted({str(i) for i in ids if i})

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    m._PairLock = Rec
    m._link_nodes = lambda d: ("na", "nb")
    m._edit_link_impl = lambda d, h=None: {"ok": True}
    m.act_link = lambda d, fn: fn(None)
    m.api_edit_link({"id": "L1", "type": "core", "a_node": "nc", "b_node": "nb"})
    check(seen.get("ids") == ["na", "nb", "nc"],
          "old pair AND new node are all locked", seen.get("ids"))


def grab(js, name):
    i = js.index("function %s(" % name)
    depth, j, started = 0, i, False
    while j < len(js):
        if js[j] == "{":
            depth += 1
            started = True
        elif js[j] == "}":
            depth -= 1
            if started and depth == 0:
                return js[i:j + 1]
        j += 1
    raise SystemExit("could not read %s out of the page" % name)


SHIM = """
var _F={},SEL={},NODES=[],_eeS={Srv:'a'};
function el(id){return _F[id]||null}
function T(k){return k}
function esc(x){return String(x)}
function num(x){var n=parseInt(x,10);return isNaN(n)?0:n}
function ssVal(k){return SEL[k]}
function nodeName(id){var n=NODES.filter(function(x){return x.id==id})[0];return n?n.name:id}
var OUT={};
"""

GRAB = ("ceNodeItems", "ceNodeName")

DRIVER = """
NODES=[{id:'na',name:'NA',host:'h1',online:true},
       {id:'nb',name:'NB',host:'h2',online:true},
       {id:'nc',name:'NC',host:'h3',online:true},
       {id:'nx',name:'NX',host:'h4',online:false}];
OUT.offered = ceNodeItems({a_node:'na',a_name:'NA',b_node:'nb',b_name:'NB'}).map(function(x){return x.v});

NODES=[{id:'nc',name:'NC',host:'h3',online:true}];
var it = ceNodeItems({a_node:'na',a_name:'NA-STORED',b_node:'nb',b_name:'NB-STORED'});
OUT.offline_pair_kept = it.map(function(x){return x.v}).sort();
OUT.offline_pair_named = ceNodeName('na');
OUT.unknown_falls_back = ceNodeName('zz');
console.log('@@'+JSON.stringify(OUT));
"""


def browser():
    print("\n-- the modal offers other nodes, and keeps the tunnel's own even when they are down --")
    spec = importlib.util.spec_from_file_location("tnl_move_js", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    js = m.INDEX_HTML
    missing = [n for n in GRAB if ("function %s(" % n) not in js]
    if missing:
        check(False, "the page has no %s -- the node cannot be picked" % ", ".join(missing))
        return
    src = SHIM + "\n".join(grab(js, n) for n in GRAB) + DRIVER
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "m.js"
        f.write_text(src, encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        check(False, "the page's own functions would not run", (r.stderr or "")[:400])
        return
    out = json.loads([l for l in r.stdout.splitlines() if l.startswith("@@")][-1][2:])
    check(out["offered"] == ["na", "nb", "nc"],
          "every ONLINE node is offered, and an offline one is not", out["offered"])
    check(out["offline_pair_kept"] == ["na", "nb", "nc"],
          "the tunnel's own two are offered even when the list has neither", out["offline_pair_kept"])
    check(out["offline_pair_named"] == "NA-STORED",
          "and such a node keeps the name the tunnel remembers", out["offline_pair_named"])
    check(out["unknown_falls_back"] == "zz",
          "a node nothing knows falls back to its id rather than blank", out["unknown_falls_back"])

    print("\n-- and the submit carries the two node ids --")
    body = js[js.index("async function doCoreEdit("):]
    body = body[:body.index("var r=await post('edit-link'")]
    check("a_node:_na" in body and "b_node:_nb" in body,
          "doCoreEdit puts a_node and b_node in the request body")
    check("ssVal('ee_a')" in body and "ssVal('ee_b')" in body,
          "  read from the two node selects")
    check("two_diff_nodes" in body,
          "  and refuses one node on both ends before asking the panel")
    check("ssHTML('ee_a'" in js and "ssHTML('ee_b'" in js,
          "the modal actually renders the two selects")
    check("onCeNode" in js, "and a change re-renders what depends on the node")


def main():
    backend()
    locking()
    browser()
    print()
    if fails:
        print("FAILED (%d)" % len(fails))
        for f in fails:
            print("  - " + f)
        return 1
    print("an edit can move the tunnel, and the move is complete on both boxes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
