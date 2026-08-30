#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: in github delivery the panel touches the network for NOTHING, and the node still verifies.

The panel used to fetch the two .sha256 sidecars so it could sign a checksum. That is still the panel
spending its uplink on a release it never serves, and on a panel behind a bad link it is the step that
fails. So the sidecar moved to the node: the panel signs the download URL, the node fetches the binary
AND its checksum from the same release, and checks one against the other before anything is written.

The trust chain has to survive the move, so this does not test either side alone. It runs the REAL
api_update_core to build the bodies, tripwires every outbound call the PANEL could make, and then feeds
those exact bodies to the node's REAL op_core_put and op_core_apply with only the node's download
boundary stubbed. What installs on the node is what the panel authorized, or nothing.

Needs the node repo. Set NODE_REPO, or have TUNNEL-MANAGER-NODE beside this one.
Exit 1 on any failure.
"""
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL_REPO = os.path.dirname(HERE)
PANEL = os.path.join(PANEL_REPO, "tnl-central.py")
NODE_REPO = os.environ.get("NODE_REPO") or os.path.join(os.path.dirname(PANEL_REPO), "TUNNEL-MANAGER-NODE")
NODE = os.path.join(NODE_REPO, "tnl-node.py")

FAILED = []
CORE = {"amd64": b"\x7fELF" + b"A" * 300000, "arm64": b"\x7fELF" + b"B" * 300000}
SHA = {a: hashlib.sha256(r).hexdigest() for a, r in CORE.items()}
VER = "v9.9.9"
NODES = [{"id": "n1", "name": "a", "host": "10.0.0.1", "port": 8099, "token": "t1"},
         {"id": "n2", "name": "b", "host": "10.0.0.2", "port": 8099, "token": "t2"}]
ARCH = {"n1": "amd64", "n2": "arm64"}


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


def load(name, path, state=None):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    if state is None:
        return m
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit("these panel paths still point at the real state dir: %s" % left)
    return m


def wire_panel(P, sent, reached):
    P.save_json(P.NODES_FILE, [dict(n) for n in NODES])
    P.log_event = lambda *a, **k: None
    P._cached_ping = lambda nid: {"arch": ARCH.get(nid, ""), "sha256": "", "core_sha": "", "core_ver": ""}
    P._ensure_update_key = lambda node: None
    P.node_call = lambda node, ep, method="POST", body=None, timeout=8: {"ok": True, "arch": ARCH[node["id"]]}
    P._resolve_core_version = lambda v: v
    def dl(url, timeout, on_progress=None, should_abort=None):
        reached.append(url)
        arch = "arm64" if "arm64" in url else "amd64"
        return SHA[arch].encode() if url.endswith(".sha256") else CORE[arch]

    P._dl = dl
    P._fetch_core_versions = lambda: reached.append("RELEASES-API")

    def push(node, endpoint, body, on_progress=None, timeout=None, chunk=65536, should_abort=None):
        if endpoint == "ping":
            return {"ok": True, "arch": ARCH[node["id"]], "sha256": "", "core_sha": "", "core_ver": ""}
        raw = bytes(body) if isinstance(body, (bytes, bytearray)) else json.dumps(body or {}).encode()
        sent.append({"node": node["id"], "endpoint": endpoint, "body": json.loads(raw.decode())})
        return {"ok": True}

    P.node_push = push


def run_job(P, fn, arg):
    r = fn(arg)
    for _ in range(1200):
        with P._push_lock:
            j = P._push_jobs.get(r.get("job") or "")
            if not j or j["done"]:
                return {k: dict(v) for k, v in (j or {}).get("nodes", {}).items()}
        time.sleep(0.02)
    return {}


def node_env(N, tmp, serve):
    fetched = []

    def fake_fetch(url, max_bytes, timeout=180, budget=None):
        fetched.append(url)
        if url not in serve:
            raise OSError("HTTP 404 %s" % url)
        b = serve[url]
        if len(b) > max_bytes:
            raise ValueError("downloaded file is larger than %d bytes" % max_bytes)
        return b

    N._fetch_url = fake_fetch
    N.CONFIG_DIR = tmp
    N.NODE_CONF = os.path.join(tmp, "node.conf")
    N.CORE_BIN = os.path.join(tmp, "tnl-core")
    N.CORE_STAGED = N.CORE_BIN + ".new"
    N.build_core = lambda c: None
    N.raw_configs = lambda: []
    N.svc = lambda *a, **k: None
    N.logline = lambda *a, **k: None
    return fetched


def installed(N):
    if not os.path.isfile(N.CORE_BIN):
        return None
    with open(N.CORE_BIN, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    if not os.path.isfile(NODE):
        sys.exit("github-delivery: no node repo at %s (set NODE_REPO)" % NODE_REPO)
    state = tempfile.mkdtemp()
    tmp = tempfile.mkdtemp()
    P = load("tnl_central_ghe2e", PANEL, state)
    N = load("tnl_node_ghe2e", NODE)

    sent, reached = [], []
    wire_panel(P, sent, reached)
    P.api_settings_set({"core_delivery": "github", "agent_delivery": "github"})

    pub = P._signing_keys()[1]
    N.CONFIG_DIR, N.NODE_CONF = tmp, os.path.join(tmp, "node.conf")
    N.save_conf({"port": 8099, "token": "t", "update_pubkey": pub})

    nodes = run_job(P, P.api_update_core, {"ids": ["n1", "n2"], "version": VER})
    check("a github update finishes without the panel reaching the network at all",
          not reached and all(v["state"] in ("ok", "same") for v in nodes.values()),
          "panel fetched %r; nodes %s" % (reached, json.dumps(nodes, ensure_ascii=False)[:200]))
    check("  and nothing was written to the stage dir",
          not [f for f in os.listdir(P.CORE_STAGE_DIR) if not f.endswith(".json")],
          repr(os.listdir(P.CORE_STAGE_DIR)))
    check("  the panel still calls itself ready", P._readiness()["core"] is True,
          json.dumps(P._readiness(), ensure_ascii=False))

    put = {s["node"]: s["body"] for s in sent if s["endpoint"] == "core-put"}
    app = {s["node"]: s["body"] for s in sent if s["endpoint"] == "core-apply"}
    check("both steps carry a url, a version and a signature -- and no checksum, no bytes",
          len(put) == 2 and len(app) == 2 and
          all(b.get("url") and b.get("sig") and b.get("version") == VER
              and "sha256" not in b and "data" not in b
              for b in list(put.values()) + list(app.values())),
          json.dumps([put, app], ensure_ascii=False)[:300])
    check("  each architecture is sent its own release asset",
          put["n1"]["url"].endswith("amd64") and put["n2"]["url"].endswith("arm64"),
          repr([put["n1"]["url"], put["n2"]["url"]]))
    check("  and the two steps agree on the very same url",
          all(put[k]["url"] == app[k]["url"] for k in put), repr([put, app]))

    url = put["n1"]["url"]
    serve = {url: CORE["amd64"], url + ".sha256": (SHA["amd64"] + "  tnl-core-linux-amd64\n").encode()}
    fetched = node_env(N, tmp, serve)
    r1 = N.op_core_put(dict(put["n1"]))
    r2 = N.op_core_apply(dict(app["n1"]))
    check("the NODE takes that grant, fetches both halves itself, and installs",
          r1.get("ok") and r2.get("ok") and installed(N) == SHA["amd64"],
          json.dumps([r1, r2], ensure_ascii=False)[:200])
    check("  it really pulled the checksum from the release, not from the panel",
          (url + ".sha256") in fetched, repr(fetched))

    os.remove(N.CORE_BIN)
    bad = dict(serve)
    bad[url] = CORE["amd64"][:-1] + b"Z"
    fetched = node_env(N, tmp, bad)
    r1 = N.op_core_put(dict(put["n1"]))
    check("a binary that does not match the release checksum is refused",
          r1.get("code") == "sha_mismatch" and installed(N) is None,
          json.dumps(r1, ensure_ascii=False))

    forged = dict(put["n1"])
    forged["url"] = forged["url"].replace("tnl-core-linux-amd64", "evil")
    fetched = node_env(N, tmp, serve)
    r1 = N.op_core_put(forged)
    check("a url the panel did not sign is refused",
          r1.get("code") == "bad_signature" and installed(N) is None,
          json.dumps(r1, ensure_ascii=False))
    check("  and refused BEFORE the node downloads anything from it", not fetched, repr(fetched))

    nosig = dict(put["n1"])
    nosig.pop("sig", None)
    fetched = node_env(N, tmp, serve)
    r1 = N.op_core_put(nosig)
    check("a grant with no signature at all is refused",
          r1.get("code") == "bad_signature" and installed(N) is None and not fetched,
          json.dumps(r1, ensure_ascii=False))

    fetched = node_env(N, tmp, {url: CORE["amd64"]})
    r1 = N.op_core_put(dict(put["n1"]))
    check("a release that publishes no checksum installs nothing",
          r1.get("code") == "checksum_unavailable" and installed(N) is None,
          json.dumps(r1, ensure_ascii=False))

    fetched = node_env(N, tmp, serve)
    N.op_core_put(dict(put["n1"]))
    N.op_core_apply(dict(app["n1"]))
    r2 = N.op_core_apply(dict(app["n1"]))
    check("applying twice does not reinstall from nothing",
          installed(N) == SHA["amd64"] and r2.get("code") in ("same", "nothing_staged"),
          json.dumps(r2, ensure_ascii=False))

    sent[:] = []
    reached[:] = []
    P.api_settings_set({"core_delivery": "push"})
    run_job(P, P.api_update_core, {"ids": ["n1"], "version": VER})
    check("push mode is untouched: the panel still downloads and still sends the bytes",
          any(not u.endswith(".sha256") for u in reached), repr(reached))

    print()
    if FAILED:
        print("%d failure(s)" % len(FAILED))
        return 1
    print("the panel signs a url and spends nothing; the node proves the bytes against the release")
    return 0


if __name__ == "__main__":
    sys.exit(main())
