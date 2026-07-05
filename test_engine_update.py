#!/usr/bin/env python3
# Tests for the panel's engine version endpoints (no server/root/network needed).
# Run: python3 test_engine_update.py
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("tnlcentral", os.path.join(HERE, "tnl-central.py"))
tnl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tnl)

FAILS = []


def check(name, cond):
    print(("ok  " if cond else "FAIL") + "  " + name)
    if not cond:
        FAILS.append(name)


# ---- api_engine_versions always offers "latest", degrades gracefully offline ----
tnl._engine_versions_cache["data"] = [{"id": "v2", "label": "v2 — strict"}, {"id": "v1", "label": "v1 — stable"}]
tnl._engine_versions_cache["ts"] = 9e18  # keep the cache, don't hit the network
r = tnl.api_engine_versions({})
ids = [x["id"] for x in r["versions"]]
check("latest is first", ids[0] == "latest")
check("release tags follow", ids == ["latest", "v2", "v1"])

# offline (empty cache) still yields latest
tnl._engine_versions_cache["data"] = []
tnl._engine_versions_cache["ts"] = 9e18
check("degrades to just latest when no releases", [x["id"] for x in tnl.api_engine_versions({})["versions"]] == ["latest"])

# ---- api_engine_update fans out to each node's engine-update op ----
tnl.get_node = lambda i: {"id": i, "name": "N" + i} if i in ("a", "b") else None
CALLS = []


def fake_node_call(node, endpoint, method="POST", body=None, timeout=8):
    CALLS.append((node["id"], endpoint, dict(body or {})))
    if node["id"] == "b":
        return {"ok": False, "offline": True, "error": "unreachable"}
    return {"ok": True, "version": body["version"], "restarted": 3, "engine_sha": "deadbeef0000"}


tnl.node_call = fake_node_call
tnl.parallel_map = lambda fn, xs: [fn(x) for x in xs]

res = tnl.api_engine_update({"ids": ["a", "b", "ghost"], "version": "v1"})
byid = {r["id"]: r for r in res["results"]}
check("unknown node id dropped before dispatch", "ghost" not in byid and len(res["results"]) == 2)
check("each targeted node got the engine-update op", all(c[1] == "engine-update" for c in CALLS))
check("the chosen version is forwarded", all(c[2] == {"version": "v1"} for c in CALLS))
check("ok node reports version + restarted", byid["a"]["ok"] and byid["a"]["version"] == "v1" and byid["a"]["restarted"] == 3)
check("offline node surfaced as offline", byid["b"]["offline"] is True and byid["b"]["ok"] is False)

# bad request (missing version) rejected
try:
    tnl.api_engine_update({"ids": ["a"]})
    check("missing version rejected", False)
except ValueError:
    check("missing version rejected", True)

# engine-update is a mutation (POST + CSRF header gated)
check("engine-update is in MUTATIONS", "engine-update" in tnl.MUTATIONS)
check("engine-versions is read-only (not a mutation)", "engine-versions" not in tnl.MUTATIONS)
check("both endpoints registered", "engine-update" in tnl.API and "engine-versions" in tnl.API)

# ---- engine-upload: store a custom binary, then push it as version "custom" ----
import base64
import hashlib
import tempfile
import os
tmp = tempfile.mkdtemp()
tnl.ENGINE_BLOB = os.path.join(tmp, "engine.bin")
tnl.ENGINE_BLOB_META = os.path.join(tmp, "engine.meta.json")

# a non-ELF file is rejected
try:
    tnl.api_engine_upload({"data": base64.b64encode(b"not an elf" + b"x" * 200000).decode()})
    check("engine-upload rejects a non-ELF file", False)
except ValueError:
    check("engine-upload rejects a non-ELF file", True)

# a too-small file is rejected
try:
    tnl.api_engine_upload({"data": base64.b64encode(b"\x7fELFtiny").decode()})
    check("engine-upload rejects a too-small file", False)
except ValueError:
    check("engine-upload rejects a too-small file", True)

# a valid ELF is stored
blob = b"\x7fELF" + b"x" * 300000
good = hashlib.sha256(blob).hexdigest()
r = tnl.api_engine_upload({"data": base64.b64encode(blob).decode(), "name": "tnl-engine-custom"})
check("engine-upload stores a valid ELF", r.get("ok") and r.get("sha256") == good[:12])
check("engine-upload wrote the exact bytes", open(tnl.ENGINE_BLOB, "rb").read() == blob)

# now "custom" shows up in the version list
tnl._engine_versions_cache["data"] = []
tnl._engine_versions_cache["ts"] = 9e18
ids2 = [x["id"] for x in tnl.api_engine_versions({})["versions"]]
check("uploaded binary appears as the 'custom' version", "custom" in ids2)

# pushing version "custom" dispatches engine-install with the stored bytes + sha
CALLS2 = []


def fake_node_call2(node, endpoint, method="POST", body=None, timeout=8):
    CALLS2.append((endpoint, dict(body or {})))
    return {"ok": True, "version": "custom", "restarted": 1, "engine_sha": good[:12]}


tnl.node_call = fake_node_call2
tnl.get_node = lambda i: {"id": i, "name": "N" + i} if i == "a" else None
tnl.parallel_map = lambda fn, xs: [fn(x) for x in xs]
res2 = tnl.api_engine_update({"ids": ["a"], "version": "custom"})
check("custom push uses the engine-install op", CALLS2 and CALLS2[0][0] == "engine-install")
check("custom push forwards the verified sha", CALLS2[0][1].get("sha256") == good)
check("custom push sends the base64 bytes", base64.b64decode(CALLS2[0][1].get("data", "")) == blob)
check("custom push result ok", res2["results"][0]["ok"] is True)

check("engine-upload is a mutation", "engine-upload" in tnl.MUTATIONS and "engine-upload" in tnl.API)

print()
if FAILS:
    print("%d FAILED: %s" % (len(FAILS), ", ".join(FAILS)))
    sys.exit(1)
print("all engine-endpoint tests passed")
