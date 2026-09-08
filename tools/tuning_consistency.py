#!/usr/bin/env python3
"""Cross-repo tuning-knob consistency guard.

The operator-tunable timing knobs are declared in three places that must agree:
  * core   TUNNEL-MANAGER-CORE/internal/packet/tuning.go  (the AUTHORITY: defaults in the var block,
           clamps in ApplyTuning) + config.go (the sock_buf top-level field)
  * panel  TUNNEL-MANAGER/tnl-central.py    (_TUNING_DEFAULTS / _TUNING_RANGES; the browser _TUNDEF is
           now INJECTED from _TUNING_DEFAULTS at import, so it cannot drift -- verified here as "derived")
  * node   TUNNEL-MANAGER-NODE/tnl-node.py  (_TUNING_INT_KEYS -- the pass-through key roster)

This parses each source and fails (exit 1) with a diff on any drift. Run it from the panel repo (paths
default to the sibling checkout layout) or pass --core/--panel/--node.
"""
import argparse
import ast
import json
import re
import sys
from pathlib import Path

# panel-name -> how the same knob is spelled in the core's tuning.go var block and its TuningInput struct.
# suspect_backoff is a list; the rest are scalar. sock_buf is NOT a tuning-object knob; it is a
# top-level config.go field, checked separately below.
TUNING_KNOBS = [
    # panel key,               go var name,           go ApplyTuning field,   is_list
    ("suspect_backoff",        "suspectBackoff",      "SuspectBackoff",       True),
    ("dead_retest_secs",       "deadRetest",          "DeadRetestSecs",       False),
    ("min_liveness_secs",      "minLiveness",         "MinLivenessSecs",      False),
    ("ladder_revive",          "ladderRevive",        "LadderRevive",         True),
]

# Every list-shaped knob, which both the panel and the node carry as an explicit roster. A knob missing
# from either is dropped in silence: the core keeps its compiled-in default while Settings shows the
# operator a number that never travelled.
LIST_KNOBS = {k for k, _v, _f, is_list in TUNING_KNOBS if is_list}

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

    The suffix is optional: the core has carried both `tclamp64`/`tclampInt` and one generic
    `tclamp`. Accept either spelling, or the guard reports core=None for every knob and verifies
    nothing while looking merely red.
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

    print("== 2) top-level config.go knobs (sock_buf) ==")
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

    # Another copy of a core constant, so guard it the same way.
    rawprofile_go = (Path(a.core) / "internal" / "packet" / "rawprofile.go").read_text(encoding="utf-8")
    rule_go = (Path(a.core) / "internal" / "packet" / "ruleowner_linux.go").read_text(encoding="utf-8")
    # The const names are mixed-case (protoEtherIP, protoL2TPv3), so [A-Z0-9] silently captured only some
    # of them and the comparison ran against half a table. Match the whole identifier.
    consts = dict(re.findall(r"\bproto([A-Za-z0-9]+)\s*=\s*(\d+)", rawprofile_go))
    m = re.search(r"var\s+rawProfiles\s*=\s*map\[string\]int\{(.*?)\n\}", rawprofile_go, re.S)
    if not m or not consts:
        check(False, "CANNOT PARSE rawProfiles/proto consts in rawprofile.go -- THIS SCRIPT is out of date")
    else:
        core_map, unresolved = {}, []
        for name, sym in re.findall(r'"(\w+)":\s*proto([A-Za-z0-9]+)', m.group(1)):
            if sym in consts:
                core_map[name] = int(consts[sym])
            else:
                unresolved.append(sym)
        # A symbol we cannot resolve means the table read here is INCOMPLETE, and an incomplete table
        # compares equal to nothing useful -- say so instead of reporting a diff nobody can act on.
        check(not unresolved, f"every profile's proto const resolved (unresolved: {unresolved})")
        try:
            panel_map = panel_const(panel_src, "CORE_RAW_PROFILE_PROTOS")
        except KeyError:
            panel_map = None
            check(False, "CORE_RAW_PROFILE_PROTOS: missing from the panel")
        if panel_map is not None:
            check(panel_map == core_map, f"profile->proto: panel={panel_map} core={core_map}")

    # The NODE's copy of the same profiles, as carrier-header BYTES: it is the MTU arithmetic. A profile
    # missing there under-counts the overhead and every full-size packet fragments, silently.
    hm = re.search(r"var\s+rawHeaderLens\s*=\s*map\[string\]int\{(.*?)\n\}", rawprofile_go, re.S)
    if not hm:
        check(False, "CANNOT PARSE rawHeaderLens in rawprofile.go -- THIS SCRIPT is out of date")
    else:
        core_hdr = {n: int(v) for n, v in re.findall(r'"(\w+)":\s*(\d+)', hm.group(1))}
        try:
            node_hdr = panel_const(node_src, "RAW_HEADER_LEN")
        except KeyError:
            node_hdr = None
            check(False, "RAW_HEADER_LEN: missing from the node")
        if node_hdr is not None:
            check(node_hdr == core_hdr, f"profile->header bytes: node={node_hdr} core={core_hdr}")
        if panel_map is not None:
            check(set(core_hdr) == set(panel_map),
                  f"the two core tables cover the same profiles: sizes={sorted(core_hdr)} protos={sorted(panel_map)}")

    print("== 2c-bis) the MTU overhead constants the node MIRRORS from the core ==")
    # The node computes every tunnel's TUN MTU as base_mtu - overhead, and that arithmetic re-implements
    # core constants by VALUE. Under-count by one byte and every full-size packet fragments on a datagram
    # carrier -- or is dropped outright, since an oversize IP_HDRINCL send is refused with EMSGSIZE. The
    # RAW header table above is checked; these were not, so a core-side change could not be noticed here.
    obfs_go = (Path(a.core) / "internal" / "packet" / "obfs.go").read_text(encoding="utf-8")
    fec_go = (Path(a.core) / "internal" / "packet" / "fec_stream.go").read_text(encoding="utf-8")

    cm = re.search(r"obfsDataPadMax\s*=\s*(\d+)", obfs_go)
    nm = re.search(r"OBFS_DATA_PAD_MAX\s*=\s*(\d+)", node_src)
    if not cm or not nm:
        check(False, "CANNOT FIND the obfs pad max on both sides -- THIS SCRIPT is out of date "
                     f"(core={bool(cm)} node={bool(nm)})")
    else:
        check(cm.group(1) == nm.group(1),
              f"obfs data pad max: core={cm.group(1)} node={nm.group(1)}")

    # The node subtracts a single literal for FEC; the core builds it from named parts, so compare the SUM:
    # fecHdrLen (its own expression) + the 2-byte shard length. BOTH numbers are extracted -- an earlier
    # version matched the node's literal `13` and compared the core against a 13 baked into this script,
    # which looks like a two-way check but is really a three-way pin: consistent change on both sides would
    # still fail here, and the failure would name the guard's own constant rather than the drift.
    fm = re.search(r"fecHdrLen\s*=\s*([0-9+ ]+)", fec_go)
    nf = re.search(r'if transport in \("udp", "raw"\) and bool\(cfg\.get\("fec"\)\):\s*\n'
                   r"\s*overhead \+= (\d+)", node_src)
    if not fm or not nf:
        check(False, "CANNOT FIND the FEC per-packet overhead on both sides -- THIS SCRIPT is out of date "
                     f"(core={bool(fm)} node={bool(nf)})")
    else:
        core_fec = sum(int(x) for x in re.findall(r"\d+", fm.group(1))) + 2
        check(core_fec == int(nf.group(1)),
              f"FEC per-packet overhead: core={core_fec} node={nf.group(1)}")

    print("== 2d) the firewall-rule OWNER tag: core writes it, node sweeps by it ==")
    # Two copies of one string in two repositories, and nothing at runtime notices a mismatch: the core
    # would keep tagging, the node would keep sweeping, and they would simply never match again. Rules
    # would then accumulate exactly as they did before the tag existed -- silently, which is the whole
    # failure mode this was built to end.
    core_pref = re.search(r'ruleOwnerPrefix\s*=\s*"([^"]*)"', rule_go)
    node_pref = re.search(r'RULE_OWNER_PREFIX\s*=\s*"([^"]*)"', node_src)
    if not core_pref or not node_pref:
        check(False, "CANNOT PARSE the owner prefix (core=%s node=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_pref), bool(node_pref)))
    else:
        check(core_pref.group(1) == node_pref.group(1),
              f"owner prefix: core={core_pref.group(1)!r} node={node_pref.group(1)!r}")
    # The tag is the TUN device name; the sweep is called with the TUNNEL name. They are the same string
    # only because _core_config sets tun_name from it -- an implicit contract worth being explicit about.
    check(re.search(r'"tun_name":\s*name\s*,', node_src) is not None,
          "the core config's tun_name IS the tunnel name, which is what makes the sweep find the tag")

    print("== 2f) the raw carrier's FIXED client source port: the core owns it, the panel names it ==")
    # The tile under «ثابت» tells the operator the exact number the client will stamp. That number is a
    # core CONSTANT the panel cannot read, so the two can only agree by being checked -- and a tile that
    # quietly names the wrong port is worse than one that names none, because it is the only place the
    # operator learns what the choice does.
    rawprofile_go = (Path(a.core) / "internal" / "packet" / "rawprofile.go").read_text(encoding="utf-8")
    core_cli = re.search(r"rawClientPort\s*=\s*(\d+)", rawprofile_go)
    tile = re.search(r'raw_sport_fixed_m:"([^"]*)"', panel_src)
    if not core_cli or not tile:
        check(False, "CANNOT PARSE the fixed client port (core=%s panel=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_cli), bool(tile)))
    else:
        check(core_cli.group(1) in tile.group(1),
              "fixed client source port: core=%s panel tile=%r" % (core_cli.group(1), tile.group(1)))
    # The same two numbers again, this time as the values the CARD prints for a raw udp/tcp tunnel. The
    # tile above is prose the operator reads before choosing; these are what the card claims the running
    # tunnel is on, so a drifted copy here misreports a live wire rather than mislabelling a button.
    core_srv = re.search(r"rawServerPort\s*=\s*(\d+)", rawprofile_go)
    js_sport = re.search(r"RAW_SPORT_FIX\s*=\s*(\d+)", panel_src)
    js_dport = re.search(r"RAW_DPORT_DEF\s*=\s*(\d+)", panel_src)
    if not core_srv or not js_sport or not js_dport:
        check(False, "CANNOT PARSE the card's raw ports (core srv=%s panel sport=%s dport=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_srv), bool(js_sport), bool(js_dport)))
    else:
        check(js_sport.group(1) == core_cli.group(1),
              "card source port: panel RAW_SPORT_FIX=%s core rawClientPort=%s" % (js_sport.group(1), core_cli.group(1)))
        check(js_dport.group(1) == core_srv.group(1),
              "card destination port: panel RAW_DPORT_DEF=%s core rawServerPort=%s" % (js_dport.group(1), core_srv.group(1)))

    # The band the rotating source port is drawn from. The core owns it; the card prints it, and prints
    # its own copy whenever the core's live status has not arrived yet. A drifted copy tells the operator
    # the tunnel is walking ports it is not walking, which is the kind of wrong that survives a whole
    # debugging session because nothing contradicts it.
    # The band is per-tunnel now, so what has to agree is the DEFAULT -- the band a tunnel that says
    # nothing gets. Five copies: the core's two constants, the node's two, the panel's python pair, the
    # browser's form placeholders, and the browser's RAW_ROT_LO/HI that the card falls back to while the
    # core's live status has not arrived. A drifted card copy tells the operator the tunnel is walking
    # ports it is not walking; a drifted FORM copy puts a placeholder on screen that is not what saving
    # an empty field actually stores.
    core_lo = re.search(r"SportBandLoDefault\s*=\s*(\d+)", rawprofile_go)
    core_hi = re.search(r"SportBandHiDefault\s*=\s*(\d+)", rawprofile_go)
    core_min = re.search(r"MinSportBandSpan\s*=\s*(\d+)", rawprofile_go)
    core_mlo = re.search(r"MinSportBandLo\s*=\s*(\d+)", rawprofile_go)
    if not core_lo or not core_hi or not core_min or not core_mlo:
        check(False, "CANNOT PARSE the core's default band (lo=%s hi=%s min=%s minlo=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_lo), bool(core_hi), bool(core_min), bool(core_mlo)))
    else:
        lo, hi, mn, ml = core_lo.group(1), core_hi.group(1), core_min.group(1), core_mlo.group(1)
        for who, pat, want in (
                ("panel RAW_ROT_LO (the card)", r"RAW_ROT_LO\s*=\s*(\d+)", lo),
                ("panel RAW_ROT_HI (the card)", r"RAW_ROT_HI\s*=\s*(\d+)", hi),
                ("browser RAW_BAND_MIN_SPAN", r"RAW_BAND_MIN_SPAN\s*=\s*(\d+)\s*[,;]", mn),
                ("browser RAW_BAND_MIN_LO", r"RAW_BAND_MIN_LO\s*=\s*(\d+)\s*[,;]", ml),
                ("panel RAW_BAND_MIN_SPAN", r"^RAW_BAND_MIN_SPAN\s*=\s*(\d+)", mn),
                ("panel RAW_BAND_MIN_LO", r"^RAW_BAND_MIN_LO\s*=\s*(\d+)", ml)):
            m = re.search(pat, panel_src, re.M)
            check(m is not None and m.group(1) == want,
                  "default rotation band: %s=%s core=%s" % (who, m.group(1) if m else "MISSING", want))
        # The node carries only the two BOUNDS, not the default: it omits the keys when the operator
        # set no band and the core applies its own default, so a node-side copy of that default would
        # be a constant nothing reads.
        for who, pat, want in (("node MIN_BAND_SPAN", r"^MIN_BAND_SPAN\s*=\s*(\d+)", mn),
                               ("node MIN_BAND_LO", r"^MIN_BAND_LO\s*=\s*(\d+)", ml)):
            m = re.search(pat, node_src, re.M)
            check(m is not None and m.group(1) == want,
                  "default rotation band: %s=%s core=%s" % (who, m.group(1) if m else "MISSING", want))

    # How many destination ports the client may spread over. FOUR copies of this ceiling exist -- the
    # core's MaxDports, the node's MAX_DPORTS, the panel's python guard, and the panel's browser guard
    # -- and each one drifts in its own way. A panel that offers more than the core accepts is a tunnel
    # that dies on validate() with nothing on screen saying why; a NODE that accepts less silently
    # DROPS the key on the way to the core config, so the operator saves 12, the panel stores 12, and
    # the tunnel runs on one destination port with every screen still reading 12.
    core_md = re.search(r"MaxDports\s*=\s*(\d+)", rawprofile_go)
    node_md = re.search(r"^MAX_DPORTS\s*=\s*(\d+)", node_src, re.M)
    py_md = re.search(r"RAW_DPORTS_MAX\s*=\s*(\d+)", panel_src)
    js_md = re.search(r"RAW_DPORTS_MAX\s*=\s*(\d+)\s*[,;]", panel_src)
    if not core_md or not node_md or not py_md or not js_md:
        check(False, "CANNOT PARSE the destination-port ceiling (core=%s node=%s panel py=%s panel js=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_md), bool(node_md), bool(py_md), bool(js_md)))
    else:
        for who, m in (("node MAX_DPORTS", node_md), ("panel RAW_DPORTS_MAX", py_md),
                       ("browser RAW_DPORTS_MAX", js_md)):
            check(m.group(1) == core_md.group(1),
                  "destination-port ceiling: %s=%s core MaxDports=%s" % (who, m.group(1), core_md.group(1)))
        # The ceiling is only real if the pool can actually deliver it: dportSet opens with the
        # configured port and fills from the pool, so a pool of N yields at most N+1 distinct ports
        # when the configured one is not in it, and exactly N when it is. Raising MaxDports without
        # growing the pool gives the operator a number the core silently clamps.
        pool = re.search(r"var dportPool = \[\.\.\.\]uint16\{(.*?)\}", rawprofile_go, re.S)
        if not pool:
            check(False, "CANNOT PARSE dportPool -- THIS SCRIPT is out of date")
        else:
            ports = [p for p in re.findall(r"\d+", pool.group(1))]
            check(len(ports) >= int(core_md.group(1)),
                  "the pool can actually reach the ceiling: %d ports in dportPool, MaxDports=%s"
                  % (len(ports), core_md.group(1)))
            dupes = sorted({p for p in ports if ports.count(p) > 1})
            check(not dupes,
                  "dportPool has no duplicate, which would cost a whole lap%s"
                  % ("" if not dupes else " -- repeated: " + ", ".join(dupes)))
        # And the operator has to be able to TYPE the ceiling. The field carried maxlength="1" while
        # the ceiling went to 16, so every value above 9 was unreachable from the keyboard with the
        # form, the panel and the core all agreeing it was legal.
        want_len = len(core_md.group(1))
        fld = re.search(r"id=\"'\+idp\+'rawdports\"[^>]*maxlength=\"(\d+)\"", panel_src)
        if not fld:
            check(False, "CANNOT PARSE the destination-port input -- THIS SCRIPT is out of date")
        else:
            check(int(fld.group(1)) >= want_len,
                  "the destination-port field can hold the ceiling: maxlength=%s, MaxDports=%s needs %d digit(s)"
                  % (fld.group(1), core_md.group(1), want_len))

    # How many parallel send/receive queues a tunnel may run. The number lives in three places and the
    # core clamps silently, so a panel that offers more than the core accepts is a form the operator
    # fills in and a config the core quietly rewrites -- the tunnel then runs on a worker count nobody
    # chose and no screen shows. The guard does not encode the number; it only requires the three to
    # agree, so raising the ceiling stays possible and just has to be done in all three places.
    core_mw = re.search(r"const maxWorkers\s*=\s*(\d+)", config_go)
    panel_mw = re.search(r"CORE_MAX_WORKERS\s*=\s*(\d+)", panel_src)
    node_mw = re.search(r"^MAX_WORKERS\s*=\s*(\d+)", node_src, re.M)
    if not core_mw or not panel_mw or not node_mw:
        check(False, "CANNOT PARSE the worker ceiling (core=%s panel=%s node=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_mw), bool(panel_mw), bool(node_mw)))
    else:
        check(panel_mw.group(1) == core_mw.group(1),
              "worker ceiling: panel CORE_MAX_WORKERS=%s core maxWorkers=%s" % (panel_mw.group(1), core_mw.group(1)))
        check(node_mw.group(1) == core_mw.group(1),
              "worker ceiling: node MAX_WORKERS=%s core maxWorkers=%s" % (node_mw.group(1), core_mw.group(1)))

    # How often the forged source port is redrawn. Four copies: the core's maxSportEvery, the node's
    # MAX_SPROT_EVERY, the panel's python guard and the panel's browser guard. The form is what the
    # operator types into, and a form that accepts a number the core refuses is a tunnel that dies on
    # validate() with nothing on screen saying which field did it.
    core_se = re.search(r"const maxSportEvery\s*=\s*(\d+)", config_go)
    node_se = re.search(r"^MAX_SPROT_EVERY\s*=\s*(\d+)", node_src, re.M)
    py_se = re.search(r"^RAW_SPROT_MAX\s*=\s*(\d+)", panel_src, re.M)
    js_se = re.search(r"RAW_SPROT_MAX\s*=\s*(\d+)\s*[,;]", panel_src)
    if not core_se or not node_se or not py_se or not js_se:
        check(False, "CANNOT PARSE the source-port rotation ceiling (core=%s node=%s panel py=%s js=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_se), bool(node_se), bool(py_se), bool(js_se)))
    else:
        for who, m in (("node MAX_SPROT_EVERY", node_se), ("panel RAW_SPROT_MAX", py_se), ("browser RAW_SPROT_MAX", js_se)):
            check(m.group(1) == core_se.group(1),
                  "rotation ceiling: %s=%s core maxSportEvery=%s" % (who, m.group(1), core_se.group(1)))

    # How deep the ladder's port rung goes -- how many times the carrier redraws its source port before
    # it escalates. Same four-copy shape as the rotation ceiling above, and the same reason to pin it:
    # the CORE clamps this one SILENTLY (SetPortTries just lowers the number), so a panel that offers
    # more than the core takes is a tunnel running a rung depth the operator did not choose and no
    # screen reports. Note this is NOT the rotation knob beside it -- «چند بار پورتِ مبدأ عوض شود» is
    # the rung, «هر چند پکت» is the rotation -- and the two labels are close enough that they have been
    # confused before.
    portrung_go = (Path(a.core) / "internal" / "packet" / "portrung.go").read_text(encoding="utf-8")
    core_pt = re.search(r"const maxPortTries\s*=\s*(\d+)", portrung_go)
    node_pt = re.search(r"^MAX_PORT_TRIES\s*=\s*(\d+)", node_src, re.M)
    py_pt = re.search(r"^PORT_TRIES_MAX\s*=\s*(\d+)", panel_src, re.M)
    js_pt = re.search(r"PORT_TRIES_MAX\s*=\s*(\d+)\s*[,;]", panel_src)
    if not core_pt or not node_pt or not py_pt or not js_pt:
        check(False, "CANNOT PARSE the port-rung ceiling (core=%s node=%s panel py=%s js=%s) -- THIS SCRIPT is out of date"
                     % (bool(core_pt), bool(node_pt), bool(py_pt), bool(js_pt)))
    else:
        for who, m in (("node MAX_PORT_TRIES", node_pt), ("panel PORT_TRIES_MAX", py_pt), ("browser PORT_TRIES_MAX", js_pt)):
            check(m.group(1) == core_pt.group(1),
                  "port-rung ceiling: %s=%s core maxPortTries=%s" % (who, m.group(1), core_pt.group(1)))
    # The two step LISTS have their own ranges and must not share one. They are different clocks: the
    # revive wait is how long a dead-ended ladder sits before it gets its rungs back, judged by a node
    # that samples about once a second; the suspect backoff is how long a burned endpoint waits out a
    # censor. One shared 1..86400 filter let the form offer a 3-second revive that refills the ladder
    # before the last rung has been judged, and a 12-hour one that reads as "never".
    tuning_go = (Path(a.core) / "internal" / "packet" / "tuning.go").read_text(encoding="utf-8")
    for name, core_lo, core_hi, node_lo, node_hi in (
            ("revive", "reviveStepMin", "reviveStepMax", "REVIVE_STEP_MIN", "REVIVE_STEP_MAX"),
            ("backoff", "backoffStepMin", "backoffStepMax", "BACKOFF_STEP_MIN", "BACKOFF_STEP_MAX")):
        cl = re.search(core_lo + r"\sint64\s*=\s*(\d+)", tuning_go)
        ch = re.search(core_hi + r"\sint64\s*=\s*(\d+)", tuning_go)
        nl = re.search(r"^" + node_lo + r"\s*=\s*(\d+)", node_src, re.M)
        nh = re.search(r"^" + node_hi + r"\s*=\s*(\d+)", node_src, re.M)
        pm = re.search(r"^" + node_lo + r", " + node_hi + r"\s*=\s*(\d+), (\d+)", panel_src, re.M)
        if not (cl and ch and nl and nh and pm):
            check(False, "CANNOT PARSE the %s step range (core=%s/%s node=%s/%s panel=%s) -- THIS SCRIPT is out of date"
                         % (name, bool(cl), bool(ch), bool(nl), bool(nh), bool(pm)))
            continue
        for who, lo, hi in (("node", nl.group(1), nh.group(1)), ("panel", pm.group(1), pm.group(2))):
            check(lo == cl.group(1) and hi == ch.group(1),
                  "%s step range: %s=%s..%s core=%s..%s" % (name, who, lo, hi, cl.group(1), ch.group(1)))

    print("== 2e) the live PAIR: the core publishes it, the node keys its verdict on it ==")
    # The core publishes what the carrier is on as {low, high, low_kind, high_kind}, and the node reads
    # exactly those keys to name its tun-probe verdict. A mismatch is SILENT and total: the node reads
    # blanks, every verdict names nothing, and no endpoint is ever burned again. It replaced splitting
    # the DISPLAY label on a middle dot, which had the same failure mode and one more way to reach it.
    ws_pool_go = (Path(a.core) / "internal" / "packet" / "core_status.go").read_text(encoding="utf-8")
    core_keys = set(re.findall(r'json:"(low|high|low_kind|high_kind)"', ws_pool_go))
    node_keys = set(re.findall(r'pair\.get\("(low|high|low_kind|high_kind)"\)', node_src))
    check(core_keys == {"low", "high", "low_kind", "high_kind"},
          "the core publishes the whole pair: %s" % sorted(core_keys))
    check(core_keys == node_keys,
          "pair keys: core=%s node=%s -- a key the node does not read is a verdict that names nothing"
          % (sorted(core_keys), sorted(node_keys)))

    # And the axis KIND strings, which tag both the health rows and the select/retest commands. The node
    # filters on them and refuses anything else, so a rename on one side silently empties a whole view.
    # Order-free on purpose: WHICH axis is the low digit is the core's decision and it has already
    # changed once -- the edge pool swapped, so the edge is now the cheap digit and the domain the
    # one a spent row condemns. What must hold is that all four names exist and the node takes them.
    # ws_pool.go is gone -- every carrier walks a PeerPool, so peerPair carries the two kind names
    # as data and the four are declared once, as constants.
    peer_src = (Path(a.core) / "internal" / "packet" / "peer_pool.go").read_text(encoding="utf-8")
    kinds_go = set(re.findall(r'\n\taxis\w+\s*=\s*"(dst|src|sni|ip)"', peer_src))
    node_kinds = set(re.findall(r'kind not in ."dst", "src", "ip", "sni".', node_src))
    check(kinds_go == {"dst", "src", "ip", "sni"},
          "the core names all four axes: %s" % sorted(kinds_go))
    check(bool(node_kinds),
          "the node accepts exactly the four axis kinds the core tags its rows with")

    print("== 2f2) the core sidecars: one filename per channel, agreed by core and node ==")
    # The node WRITES these files and the core CLAIMS them by rename. Nothing reports a mismatch: the
    # node writes happily, the core reads a file that is never there, and every manual jump, every
    # retest and every tun-probe verdict silently does nothing while the panel says it was sent.
    status_go = (Path(a.core) / "internal" / "packet" / "core_status.go").read_text(encoding="utf-8")
    core_side = dict(re.findall(r'(\w+)Path\(\) string \{ return s\.sidecar\("\.(\w+)"\)', status_go))
    wipe = re.search(r'def _core_status_paths\(name\):(.*?)\n\n', node_src, re.S)
    boxes = {
        "verdict": re.search(r'def _report_carrying.*?_cfg_path\(name, "\.status\.(\w+)"\)', node_src, re.S),
        "select": re.search(r'def _write_cmd\(.*?_cfg_path\(name, "\.status\.(\w+)"\)', node_src, re.S),
        "echCmd": re.search(r'def op_ech_update.*?_cfg_path\(name, "\.status\.(\w+)"\)', node_src, re.S),
    }
    if not wipe or sorted(core_side) != ["echCmd", "select", "verdict"]:
        check(False, "CANNOT PARSE the sidecar names (core=%s wipe=%s) -- THIS SCRIPT is out of date"
                     % (sorted(core_side), bool(wipe)))
    else:
        for chan, suffix in sorted(core_side.items()):
            m = boxes.get(chan)
            check(m is not None and m.group(1) == suffix,
                  "%s: the core claims '.%s', the node writes %s"
                  % (chan, suffix, ("'.%s'" % m.group(1)) if m else "NOTHING THIS SCRIPT CAN FIND"))
            check(('"." + "%s"' % suffix) in wipe.group(1) or ('."%s"' % suffix) in wipe.group(1).replace(" ", "")
                  or ('.%s"' % suffix) in wipe.group(1),
                  "and deleting the tunnel removes the .%s file it wrote" % suffix)

    print("== 2g) the tun-probe threshold: panel offers it, the NODE consumes it ==")
    # The one Settings knob the node reads for itself instead of forwarding to the core, so its default
    # and range are a panel<->NODE contract with no core side at all. Drift is silent both ways: a panel
    # default that no longer matches the node's leaves an untouched fleet judged by a different number
    # than Settings displays (the panel omits a knob that equals its default, so nothing is stamped and
    # the node's own value decides), and a wider panel range lets the operator save a value the node
    # then clamps without saying so.
    n_pmin = re.search(r"^PROBE_MIN_PCT\s*=\s*(\d+)", node_src, re.M)
    n_rng = re.search(r"^PROBE_MIN_PCT_RANGE\s*=\s*\((\d+),\s*(\d+)\)", node_src, re.M)
    if not n_pmin or not n_rng:
        check(False, "CANNOT PARSE the node's PROBE_MIN_PCT/_RANGE (found=%s/%s) -- THIS SCRIPT is out "
                     "of date" % (bool(n_pmin), bool(n_rng)))
    else:
        check(p_def.get("probe_min_pct") == int(n_pmin.group(1)),
              f"probe_min_pct default: panel={p_def.get('probe_min_pct')} node={n_pmin.group(1)}")
        check(js_ok("probe_min_pct", p_def.get("probe_min_pct")),
              f"jsdef  probe_min_pct: _TUNDEF={None if derived else js_def.get('probe_min_pct')} "
              f"py={p_def.get('probe_min_pct')}")
        n_pair = (int(n_rng.group(1)), int(n_rng.group(2)))
        p_pair = tuple(p_rng.get("probe_min_pct")) if p_rng.get("probe_min_pct") else None
        check(p_pair == n_pair, f"probe_min_pct range: panel={p_pair} node={n_pair}")
    # It must NOT be a core knob. If it ever appears in tuning.go, the top-level/`tuning`-object split
    # in _apply_core_tuning is wrong and this guard's whole model of the knob is stale.
    check("probe_min_pct" not in tuning_go and "ProbeMinPct" not in tuning_go,
          "probe_min_pct is absent from tuning.go -- it is the node's knob, not the core's")
    # The SAMPLE COUNT the panel shows the operator ("15% = at least 3 of 20") is the node's PROBE_COUNT
    # mirrored. Nothing enforces it at runtime -- the percentage travels, not the count -- so if the node
    # ever samples a different number the panel keeps printing a sentence that is simply false, and the
    # operator tunes against it. Cheap to state, invisible to lose.
    n_cnt = re.search(r"^PROBE_COUNT\s*=\s*(\d+)", node_src, re.M)
    p_cnt = panel_const(panel_src, "_PROBE_SAMPLES")
    if not n_cnt:
        check(False, "CANNOT PARSE the node's PROBE_COUNT -- THIS SCRIPT is out of date")
    else:
        check(p_cnt == int(n_cnt.group(1)),
              f"probe sample count: panel _PROBE_SAMPLES={p_cnt} node PROBE_COUNT={n_cnt.group(1)}")
        # ...and the form's step must divide it evenly, or it offers settings that are not distinct
        # verdicts (with 20 samples, 11..15 all mean "3 of 20") or skips ones that are.
        m = re.search(r"tNum\('set_t_probemin',.*?,(\d+),(\d+),(\d+)\)", panel_src)
        if not m:
            check(False, "CANNOT PARSE the probe-threshold form control -- THIS SCRIPT is out of date")
        else:
            lo, hi, step = int(m.group(1)), int(m.group(2)), int(m.group(3))
            check(step * p_cnt == 100,
                  f"the form steps by {step}%, which must equal 100/{p_cnt} so every step is exactly "
                  f"one more required reply (otherwise it offers settings that are not distinct verdicts)")
            check((lo, hi) == (step, 100),
                  f"the form offers {lo}..{hi}%, want {step}..100 -- the lowest real setting is one "
                  f"step (a single reply), and anything under it is the same verdict wearing a "
                  f"different number")

    print("== 3) list-knob rosters: panel and node vs core ==")
    for who, src in (("panel", panel_src), ("node ", node_src)):
        try:
            got = set(panel_const(src, "_TUNING_LIST_KEYS"))
        except KeyError:
            check(False, f"{who} _TUNING_LIST_KEYS: MISSING -- every list knob is silently dropped")
            continue
        check(got == LIST_KNOBS,
              f"{who} _TUNING_LIST_KEYS: extra={sorted(got - LIST_KNOBS)} missing={sorted(LIST_KNOBS - got)}")

    print("== 3b) node _TUNING_INT_KEYS roster ==")
    expected = {k for k, _v, _f, is_list in TUNING_KNOBS if not is_list}  # scalar tuning-object knobs
    check(n_keys == expected,
          f"node keys: extra={sorted(n_keys - expected)} missing={sorted(expected - n_keys)}")

    print("== 4) panel dict rosters agree ==")
    scalar_defaults = {k for k in p_def if k not in LIST_KNOBS}
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
