#!/usr/bin/env python3
"""Cross-repo tuning-knob consistency guard (consolidation Track B).

The operator-tunable timing knobs are declared in places that must agree:
  * core   TUNNEL-MANAGER-CORE/internal/packet/tuning.go  (the AUTHORITY: defaults in the var block,
           clamps in ApplyTuning) + config.go (keepalive / dead_after_secs top-level fields)
  * panel  TUNNEL-MANAGER/tnl-central.py    (_TUNING_DEFAULTS / _TUNING_RANGES; the browser _TUNDEF is
           now INJECTED from _TUNING_DEFAULTS at import, so it cannot drift -- verified here as "derived")
  * node   TUNNEL-MANAGER-NODE/tnl-node.py  (_TUNING_INT_KEYS -- the pass-through key roster)

The panel's own comment says the defaults "MUST match the core", but nothing enforced it. This script IS
that enforcement: it parses each source and fails (exit 1) with a diff on any drift. Run it from the panel
repo (paths default to the sibling checkout layout) or pass --core/--panel/--node.
"""
import argparse
import ast
import json
import re
import sys
from pathlib import Path

# panel-name -> how the same knob is spelled in the core's tuning.go var block and its TuningInput struct.
# suspect_backoff is a list; the rest are scalar. keepalive & dead_after_secs are NOT tuning-object knobs;
# they are top-level config.go fields, checked separately below.
TUNING_KNOBS = [
    # panel key,               go var name,           go ApplyTuning field,   is_list
    ("suspect_backoff",        "suspectBackoff",      "SuspectBackoff",       True),
    ("dead_retest_secs",       "deadRetest",          "DeadRetestSecs",       False),
    ("pin_ttl_secs",           "pinTTL",              "PinTTLSecs",           False),
    ("data_fail_threshold",    "dataFailThreshold",   "DataFailThreshold",    False),
    ("data_good_window_secs",  "dataGoodWindow",      "DataGoodWindowSecs",   False),
    ("idle_mult",              "idleMult",            "IdleMult",             False),
    ("idle_min_secs",          "idleMinSecs",         "IdleMinSecs",          False),
    ("session_stale_mult",     "sessionStaleMult",    "SessionStaleMult",     False),
    ("session_stale_min_secs", "sessionStaleMinSecs", "SessionStaleMinSecs",  False),
    ("ping_loss_threshold",    "pingLossThreshold",   "PingLossThreshold",    False),
    ("min_liveness_secs",      "minLiveness",         "MinLivenessSecs",      False),
    ("probe_timeout_secs",     "probeTimeout",        "ProbeTimeoutSecs",     False),
]

fails = []
def check(ok, msg):
    print(("  ok  " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


# ----------------------------------------------------------------- panel (Python constants via AST)
def panel_const(src, name):
    """Return the literal value assigned to a module-level `name = <literal>` in the source."""
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return ast.literal_eval(node.value)
    raise KeyError(name)


def panel_tundef(src):
    """The browser _TUNDEF as a dict, or the sentinel 'DERIVED' when it is injected from _TUNING_DEFAULTS
    at import (the placeholder form) -- in which case it structurally cannot drift."""
    if re.search(r"var\s+_TUNDEF\s*=\s*__TUNDEF_JSON__", src):
        if 'replace("__TUNDEF_JSON__"' not in src:
            raise ValueError("_TUNDEF placeholder present but no import-time injection wiring found")
        return "DERIVED"
    m = re.search(r"var\s+_TUNDEF\s*=\s*(\{.*?\})\s*;", src)
    if not m:
        raise KeyError("_TUNDEF")
    body = re.sub(r"([{,])\s*([A-Za-z_]\w*)\s*:", r'\1"\2":', m.group(1))  # quote bare JS keys
    return json.loads(body)


# ----------------------------------------------------------------- core tuning.go / config.go
def go_default(src, var, is_list):
    if is_list:
        m = re.search(re.escape(var) + r"\s*=\s*\[\]int64\{([^}]*)\}", src)
        if not m:
            raise KeyError(var)
        return [int(x) for x in re.findall(r"\d+", m.group(1))]
    # scalar: matches `deadRetest int64 = 1800`, `dataFailThreshold = 2`, `minLiveness = 20 * time.Second`
    m = re.search(re.escape(var) + r"\b[^=\n]*=\s*(\d+)", src)
    if not m:
        raise KeyError(var)
    return int(m.group(1))


def go_clamp(src, field):
    """The (lo, hi) ApplyTuning clamps a knob, or None when the clamp cannot be located.

    The suffix is optional because the core merged tclamp64/tclampInt into ONE generic
    `func tclamp[T int | int32 | int64]`. While this regex still demanded the suffix it matched
    nothing, so every knob reported core=None — the guard was red on all 11 ranges and, worse, was
    verifying nothing about them. Keep both spellings accepted so the guard survives either shape.
    """
    m = re.search(r"tclamp(?:64|Int)?\(t\." + re.escape(field) + r",\s*(\d+),\s*(\d+)\)", src)
    return (int(m.group(1)), int(m.group(2))) if m else None


def main():
    here = Path(__file__).resolve()
    panel_root = here.parent.parent            # <repo>/tools/this.py -> <repo>
    mmd = panel_root.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=panel_root / "tnl-central.py")
    ap.add_argument("--core", default=mmd / "TUNNEL-MANAGER-CORE")
    ap.add_argument("--node", default=mmd / "TUNNEL-MANAGER-NODE" / "tnl-node.py")
    a = ap.parse_args()

    panel_src = Path(a.panel).read_text(encoding="utf-8")
    tuning_go = (Path(a.core) / "internal" / "packet" / "tuning.go").read_text(encoding="utf-8")
    config_go = (Path(a.core) / "config.go").read_text(encoding="utf-8")
    node_src = Path(a.node).read_text(encoding="utf-8")

    p_def = panel_const(panel_src, "_TUNING_DEFAULTS")
    p_rng = panel_const(panel_src, "_TUNING_RANGES")
    js_def = panel_tundef(panel_src)
    n_keys = set(panel_const(node_src, "_TUNING_INT_KEYS"))
    derived = js_def == "DERIVED"

    def js_ok(key, val):
        return derived or js_def.get(key) == val

    print("== 1) tuning-object knobs: panel defaults/ranges vs core (tuning.go) ==")
    if derived:
        print("  ok  _TUNDEF is injected from _TUNING_DEFAULTS at import -- no JS literal to drift")
    for panel_key, go_var, go_field, is_list in TUNING_KNOBS:
        c_default = go_default(tuning_go, go_var, is_list)
        check(p_def.get(panel_key) == c_default,
              f"default {panel_key}: panel={p_def.get(panel_key)} core={c_default}")
        check(js_ok(panel_key, p_def.get(panel_key)),
              f"jsdef  {panel_key}: _TUNDEF={None if derived else js_def.get(panel_key)} py={p_def.get(panel_key)}")
        if not is_list:
            c_clamp = go_clamp(tuning_go, go_field)
            pr = p_rng.get(panel_key)
            pr = tuple(pr) if pr is not None else None
            if c_clamp is None:
                # Say WHY it is None. A silent "core=None" reads like drift the operator should fix in
                # the panel, when it actually means this guard stopped parsing tuning.go — which is how
                # it sat red-but-useless after tclamp64/tclampInt merged into a generic tclamp.
                check(False, f"range   {panel_key}: CANNOT PARSE the core clamp for t.{go_field}"
                             f" -- tuning.go changed shape and THIS SCRIPT is out of date (panel={pr})")
            else:
                check(pr == c_clamp, f"range   {panel_key}: panel={pr} core={c_clamp}")

    print("== 2) top-level config.go knobs (keepalive / dead_after_secs) ==")
    ka_def = int(re.search(r"c\.Keepalive\s*=\s*(\d+)", config_go).group(1))
    check(p_def.get("keepalive") == ka_def and js_ok("keepalive", ka_def),
          f"keepalive default: panel={p_def.get('keepalive')} core={ka_def}")
    print("  note  keepalive range 5..120 is panel/node-only; the core does not clamp the upper bound")
    da_m = re.search(r"c\.DeadAfterSecs\s*<\s*(\d+)\s*\|\|\s*c\.DeadAfterSecs\s*>\s*(\d+)", config_go)
    da_lo, da_hi = int(da_m.group(1)), int(da_m.group(2))
    check(p_def.get("dead_after_secs") == 0 and js_ok("dead_after_secs", 0),
          f"dead_after_secs default: panel={p_def.get('dead_after_secs')} core=0")
    check(tuple(p_rng.get("dead_after_secs"))[1] == da_hi,
          f"dead_after_secs max: panel={tuple(p_rng.get('dead_after_secs'))[1]} core={da_hi}")
    check(da_lo == 10, f"dead_after_secs core positive-floor is {da_lo} (panel floors a positive value to 10)")
    # sock_buf is the one knob stored in a DIFFERENT UNIT than the core reads: the panel keeps MiB
    # (sock_buf_mb) and _apply_core_tuning multiplies to bytes, so compare after converting. The core's
    # own default is written as a shift (4 << 20), and its clamp ceiling likewise.
    sb_def_m = re.search(r"c\.SockBuf\s*=\s*(\d+)\s*<<\s*20", config_go)
    sb_max_m = re.search(r"c\.SockBuf\s*>\s*(\d+)\s*<<\s*20", config_go)
    if not sb_def_m or not sb_max_m:
        check(False, "sock_buf: CANNOT PARSE the core default/clamp in config.go -- THIS SCRIPT is out of date")
    else:
        sb_def, sb_max = int(sb_def_m.group(1)), int(sb_max_m.group(1))
        check(p_def.get("sock_buf_mb") == sb_def and js_ok("sock_buf_mb", sb_def),
              f"sock_buf default: panel={p_def.get('sock_buf_mb')} MiB core={sb_def} MiB")
        check(tuple(p_rng.get("sock_buf_mb")) == (0, sb_max),
              f"sock_buf range: panel={tuple(p_rng.get('sock_buf_mb'))} core=(0 means off, max {sb_max} MiB)")

    print("== 3) node _TUNING_INT_KEYS roster ==")
    expected = {k for k, _v, _f, is_list in TUNING_KNOBS if not is_list}  # scalar tuning-object knobs
    check(n_keys == expected,
          f"node keys: extra={sorted(n_keys - expected)} missing={sorted(expected - n_keys)}")

    print("== 4) panel dict rosters agree ==")
    scalar_defaults = {k for k in p_def if k != "suspect_backoff"}
    check(scalar_defaults == set(p_rng),
          f"defaults-vs-ranges: only-in-defaults={sorted(scalar_defaults - set(p_rng))} "
          f"only-in-ranges={sorted(set(p_rng) - scalar_defaults)}")
    if not derived:
        check(set(js_def) == set(p_def),
              f"_TUNDEF-vs-_TUNING_DEFAULTS keys mismatch: only-in-js={sorted(set(js_def) - set(p_def))} "
              f"only-in-py={sorted(set(p_def) - set(js_def))}")

    print()
    if fails:
        print(f"DRIFT DETECTED - {len(fails)} mismatch(es).")
        return 1
    print("all tuning knobs consistent across core / panel / node.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
