#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A node already running the staged core must be skipped, and that judgement may not depend on
re-reading the 11 MB binary.

The check used to source the sha by calling _staged_bytes(arch) and caching the result in a dict shared
by every node of the job. That call returns None if the file is missing or a re-download fails, and the
caller cached "" -- so from that moment every remaining node failed the check and was sent the whole
binary again. Reported as: nodes that are already up to date get updated anyway, hit and miss.

This drives the REAL predicate out of api_update_core's plan, not a copy of its logic.

    python3 tools/up_to_date_nodes_are_skipped_check.py
"""
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PANEL = os.path.join(os.path.dirname(HERE), "tnl-central.py")

spec = importlib.util.spec_from_file_location("tnl_central", PANEL)
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)

SHA = "ada301acd22d73409cd6431f46e418268f10975cd631c2c84105709533fe2b46"
VER = "v2.92.0"
STAGE = tempfile.mkdtemp(prefix="stage")

P.CORE_STAGE_DIR = STAGE
P.CORE_STAGE_META = os.path.join(STAGE, "core-stage.meta.json")
json.dump({"version": VER, "arches": ["amd64", "arm64"],
           "sha": {"amd64": SHA, "arm64": "b" * 64}, "size": {"amd64": 1, "arm64": 1}, "ts": 0},
          io.open(P.CORE_STAGE_META, "w", encoding="utf-8"))

NODE = {"id": "n1", "name": "IR01", "host": "203.0.113.5", "port": 8099, "token": "x", "arch": "amd64"}
P._update_targets = lambda d: [NODE]
P._delivery_mode = lambda kind: "push"
P._core_delivery_check = lambda *a, **k: None
P._sign_sha = lambda sha: "sig"
P._node_arch = lambda n: "amd64"

captured = {}
P._update_start = lambda kind, nodes, plan: captured.update(plan=plan) or {"ok": True}

P.api_update_core({"version": VER})
gate = captured["plan"][0][4]

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


print("== the staged binary is NOT on disk: only the meta the staging wrote ==")
check(not os.path.isfile(os.path.join(STAGE, "tnl-core-amd64")),
      "setup: the binary really is absent, which is the state that used to poison the check")

up_to_date = {"arch": "amd64", "core_sha": SHA[:12], "core_ver": VER}
check(gate(up_to_date) is True,
      "a node reporting the staged sha is judged up to date and skipped")

check(gate({"arch": "amd64", "core_sha": "0123456789ab", "core_ver": "v2.90.0"}) is False,
      "a node on a different build is NOT skipped")

check(gate({"arch": "amd64", "core_ver": VER}) is False,
      "a node that reports no sha is not skipped on its version label alone")

check(gate({"arch": "riscv64", "core_sha": SHA[:12]}) is False,
      "an unknown architecture is never called up to date")

print()
print("== and the answer is the same for every node in the job, however many are asked ==")
answers = {gate(dict(up_to_date)) for _ in range(50)}
check(answers == {True},
      "50 nodes in a row all get the same answer (%r) -- no shared cache to poison" % (answers,))

shutil.rmtree(STAGE, ignore_errors=True)
print()
if fails:
    print("%d check(s) failed." % len(fails))
    sys.exit(1)
print("an up-to-date node is skipped, and the check does not depend on the binary being readable.")
