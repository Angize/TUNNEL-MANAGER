#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the panel does not tell the operator something that is not so.

Nine claims from the 2026-09-04 audit that were left unsettled and then checked by hand. None of them
crashes anything; every one of them sends the operator somewhere wrong, or throws away work they had
already done. They are guarded together because they are one failure: a sentence, a badge or a cap
that was true when it was written and is not true now.

  * the install banner names the step that was RUNNING. The catch-all said `install` no matter what,
    and `install` is marked ok several lines before the register phase can throw -- so a failure while
    registering turned the ALREADY GREEN step red and pointed the operator at the wrong log.
  * a force-wipe of a dead node works on a cold ping cache. The gate read `.get("ok") is False`, and a
    cache with no entry answers None, so right after a panel restart the panel rang the dead node
    instead and refused the wipe with "wait until it goes red" -- which is what the operator had done.
  * a tuning value that is not a multiple of its step is refused BY THE FORM. `step="5"` in the HTML
    does not stop anybody typing 37; the backend then rejected the whole settings save, taking every
    other field the operator had changed with it.
  * a subnet the operator typed is either used or refused. norm_subnet silently substituted the
    default for anything it could not parse, so 192.168.99.0/33 became a different network with no
    message at all.
  * a sit tunnel is not capped by an IPv4 range it never touches. sit addresses as fd00:x:y::/64, and
    the id cap came from the IPv4 base -- 255 ids where 65535 are representable.
  * every operator-facing message the panel raises is Persian. 92 literals in 46 shapes were not, and
    "link not found" reaches the screen through the ordinary error path like any other.
  * the settings card's scope chip matches where its knobs actually go. It said «همهٔ تونل‌ها» while
    two of its three rows travel inside `if ttype == "core"`.
  * the unread badge counts what arrived since this browser first looked, not the whole history of the
    fleet. `seen` came from localStorage and a fresh browser reads 0.
  * the logs subtitle does not deny what the panel logs. It said manual actions never appear, and
    four of them do.

Everything here drives the panel's own functions; the install case runs the real _install_worker with
ssh and the registry stubbed so the exception lands in the register phase.

    python3 tools/the_panel_says_what_is_true_check.py
"""
import importlib.util
import io
import json
import os
import re
import sys
import tempfile

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PANEL = os.path.join(ROOT, "tnl-central.py")

fails = []
FA = re.compile(r"[؀-ۿ]")


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def load(tag):
    spec = importlib.util.spec_from_file_location("tnl_true_" + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    state = tempfile.mkdtemp()
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    return m


def the_banner_names_the_step_that_failed():
    print("== a failure while REGISTERING does not turn the install step red ==")
    m = load("inst")
    m._staged_agent = lambda: ("print('agent')", {"sha256": "0" * 64, "version": "v1"})
    m._ssh_run = lambda cfg, cmd, t, stdin_text=None: (
        0, "TNL_SSH_OK TNL_DL_OK TNL_RECV_OK TNL_INSTALL_OK TNL_NODE_TOKEN=" + "t" * 20, "")
    m._delivery_mode = lambda kind: "panel"

    def boom(*a, **k):
        raise RuntimeError("the registry disk is full")
    m.save_json = boom

    jid = m._install_start({"name": "IR9", "host": "10.0.0.9"}) if hasattr(m, "_install_start") else None
    if jid is None:
        with m._install_lock:
            jid = "j1"
            m._install_jobs[jid] = {"steps": [{"key": k, "state": "wait", "detail": "", "log": ""}
                                              for k, _ in m._INSTALL_STEPS],
                                    "done": False, "ok": False, "banner": "", "node_id": ""}
    cfg = {"user": "root", "host": "10.0.0.9", "port": 22, "keyfile": None}
    m._install_worker(jid, cfg, "IR9", 8099, False, "")

    with m._install_lock:
        j = m._install_jobs[jid]
        states = {s["key"]: s["state"] for s in j["steps"]}
        banner = j["banner"]
    check(states.get("install") == "ok",
          "the step that really succeeded is still green", states)
    check(states.get("register") == "err",
          "and the step that was running when it threw is the one that went red", states)
    check(m._INSTALL_LABELS["register"] in banner,
          "the banner names that step too, so the operator looks in the right place", banner)


def a_force_wipe_does_not_need_a_warm_cache():
    print("== a force-wipe of a dead node works on a cold ping cache ==")
    m = load("wipe")
    n = {"id": "n1", "name": "IR9", "host": "10.0.0.9", "port": 8099, "token": "t" * 20}
    rang = []

    def node_call(node, ep, meth="GET", body=None, timeout=None):
        rang.append(ep)
        return {"ok": False, "error": "unreachable"}
    m.node_call = node_call

    check(m._known_offline(n) is True,
          "with nothing in the cache the panel finds out for itself instead of guessing None")
    check(rang == ["ping"], "and what it does to find out is one ping", rang)

    rang[:] = []
    m._cache_put(n["id"], {"ping": {"ok": True}}) if hasattr(m, "_cache_put") else None
    m._cached_ping = lambda nid: {"ok": True}
    check(m._known_offline(n) is False, "a node the cache says is UP is not treated as gone")
    check(rang == [], "and a cached verdict is not re-pinged", rang)


def a_stepped_knob_is_refused_by_the_form():
    print("== a tuning value off its step is caught before the save is sent ==")
    m = load("step")
    js = m.INDEX_HTML
    check("function tunStepBad(" in js, "the browser has a step check at all")
    check("_TUNSTEP" in js and "__TUNSTEP_JSON__" not in js,
          "and the rule is injected from _TUNING_STEPS rather than typed twice")
    save = js[js.index("async function saveSettings("):]
    save = save[:save.index("\nfunction ")]
    check("tunStepBad" in save and save.index("tunStepBad") < save.index("post("),
          "saveSettings runs it BEFORE it posts, or the whole save is still lost", save[:200])
    for k, (step, _label) in m._TUNING_STEPS.items():
        lo, hi = m._TUNING_RANGES[k]
        bad = next(v for v in range(lo, hi + 1) if v % step)
        try:
            m._validate_tuning({k: bad})
            check(False, "the backend still refuses %s=%d, so the form check is the only thing "
                         "standing between the operator and a lost save" % (k, bad))
        except ValueError:
            check(True, "the backend refuses %s=%d, and now the form says so first" % (k, bad))


def a_typed_subnet_is_used_or_refused():
    print("== a subnet the operator typed is never silently swapped ==")
    m = load("sub")
    check(m.norm_subnet("core", 7, None) == m.subnet_default("core", 7),
          "nothing typed still gets the default")
    check(m.norm_subnet("core", 7, "192.168.99.0/24") == "192.168.99.0/24",
          "a usable one is used as typed")
    for ttype, bad in (("core", "192.168.99.0/33"), ("core", "not-a-network"),
                       ("sit", "192.168.99.0/24"), ("core", "fd00::/64")):
        try:
            got = m.norm_subnet(ttype, 7, bad)
            check(False, "%s %r was swapped for %s without a word" % (ttype, bad, got))
        except ValueError as e:
            check(bad in str(e), "%s %r is refused, and the message quotes it" % (ttype, bad), str(e))
    # A stored subnet being CARRIED through an edit is not something the operator typed: changing a
    # sit tunnel to core hands the old fd00::/64 back, and re-deriving that in silence is right.
    # Refusing it -- which is what the first version of this fix did -- makes that edit impossible.
    carried = m.carry_subnet("core", 5000, m.subnet_default("sit", 5000))
    check(carried.endswith("/24") and ":" not in carried,
          "a sit tunnel edited to core re-derives its subnet in silence", carried)
    check(m.carry_subnet("core", 7, "192.168.99.0/24") == "192.168.99.0/24",
          "and a carried subnet that still fits is kept")
    src = io.open(PANEL, encoding="utf-8").read()
    edit = src[src.index("def _edit_link_impl("):]
    edit = edit[:edit.index("carry_subnet") + 200]
    check("norm_subnet(ttype, tid, d[\"subnet\"])" in edit,
          "and the EDIT path still refuses a subnet the operator typed by hand")


def a_sit_tunnel_is_not_capped_by_an_ipv4_base():
    print("== a sit tunnel's id cap comes from its own addressing ==")
    m = load("sit")
    src = io.open(PANEL, encoding="utf-8").read()
    i = src.index("_cap = ")
    line = src[i:src.index("explicit = int(", i)]
    check('ttype == "sit"' in line,
          "the cap asks the tunnel TYPE, not only whether a subnet was typed", line.strip()[:120])
    wide = m.subnet_cap("192.168")
    check(m.TID_MAX > wide, "TID_MAX (%d) is wider than the default IPv4 base (%d), so the cap "
                            "mattered" % (m.TID_MAX, wide))
    check(m.subnet_default("sit", m.TID_MAX).startswith("fd00:"),
          "and sit really addresses out of fd00::/8 at that id", m.subnet_default("sit", m.TID_MAX))


def every_message_the_operator_can_see_is_persian():
    print("== every message the panel raises is in the language the panel is written in ==")
    src = io.open(PANEL, encoding="utf-8").read()
    bad = []
    for mm in re.finditer(r'(?:raise ValueError\(|"error":\s*)f?"([^"]{3,})"', src):
        t = mm.group(1)
        if not FA.search(t) and not t.startswith("\\u"):
            bad.append(t)
    check(not bad,
          "%d message(s) the operator can be shown, all Persian" %
          len(re.findall(r'(?:raise ValueError\(|"error":\s*)f?"[^"]{3,}"', src)),
          "still English:\n         " + "\n         ".join(sorted(set(bad))) if bad else None)


def the_scope_chip_matches_where_the_knobs_go():
    print("== the settings card says which tunnels its knobs reach ==")
    m = load("chip")
    src = io.open(PANEL, encoding="utf-8").read()
    core_only = src[src.index("def _apply_core_tuning("):src.index("def _apply_probe_tuning(")]
    every = src[src.index("def _apply_probe_tuning("):]
    every = every[:every.index("\n\n\n")] if "\n\n\n" in every else every[:400]
    check("probe_min_pct" in every, "probe_min_pct is the knob that goes to every tunnel")
    calls = [i for i in range(len(src)) if src.startswith("        _apply_core_tuning(a_body", i)]
    check(bool(calls) and all('if ttype == "core":' in src[max(0, i - 700):i] for i in calls),
          "and every call to _apply_core_tuning sits under `if ttype == \"core\"` (%d call sites)"
          % len(calls))
    chip = re.search(r'set_gkdc:"([^"]+)"', m.INDEX_HTML).group(1)
    check("همهٔ تونل‌ها" not in chip or "هسته" in chip,
          "so the chip may not claim the whole fleet without naming the exception", chip)
    check("هسته" in chip, "it names the core", chip)


def the_unread_badge_starts_at_zero():
    print("== the unread badge counts what arrived since this browser first looked ==")
    m = load("badge")
    js = m.INDEX_HTML
    i = js.index("EVSEQ=num(s.ev_seq)")
    blk = js[i:js.index("function setUnread(", i)]
    check("raw===''" in blk or "raw === ''" in blk,
          "a browser with nothing stored is seeded, not treated as having seen nothing", blk.strip())
    check("setLS('tnl_logs_seen'" in blk, "and the seed is written down, or every reload re-seeds")
    check("Math.max(0," in blk, "and the count can never go negative if the seq is reset", blk.strip())


def the_logs_subtitle_does_not_deny_what_is_logged():
    print("== the logs subtitle does not deny what the panel logs ==")
    m = load("logs")
    src = io.open(PANEL, encoding="utf-8").read()
    sub = re.search(r'logs_sub:"([^"]+)"', m.INDEX_HTML).group(1)
    manual = re.findall(r'log_event\("[a-z]+", "[a-z]+", (?:f?)"([^"]*(?:اپراتور|پروکسیِ)[^"]*)"', src)
    check(bool(manual), "the panel does log some deliberate operator actions", manual[:3])
    check("کارهای دستیِ شما اینجا نمی‌آید" not in sub,
          "so the subtitle may not say manual actions never appear", sub[:120])
    check("دستی" in sub, "and it says which ones do", sub[:160])


def main():
    for fn in (the_banner_names_the_step_that_failed,
               a_force_wipe_does_not_need_a_warm_cache,
               a_stepped_knob_is_refused_by_the_form,
               a_typed_subnet_is_used_or_refused,
               a_sit_tunnel_is_not_capped_by_an_ipv4_base,
               every_message_the_operator_can_see_is_persian,
               the_scope_chip_matches_where_the_knobs_go,
               the_unread_badge_starts_at_zero,
               the_logs_subtitle_does_not_deny_what_is_logged):
        try:
            fn()
        except Exception as e:
            check(False, "%s blew up: %r" % (fn.__name__, e))
        print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
