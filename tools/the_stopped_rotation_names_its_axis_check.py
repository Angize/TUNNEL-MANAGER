#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: «چرخش متوقف شد» says WHICH rotation stopped.

The core emits pool/degraded and pool/restored when a pool drops below two usable entries. It used to
be an edge-pool event only, so a direct tunnel with three destination IPs and two of them burned
rotated nowhere and told the operator nothing. Both pools report it now, and the detail carries the
axis (`dst:` / `src:` / `ip:` / `sni:`) exactly the way the burn and heal events already do.

Which means the panel may no longer hardcode «لبه». A destination pool that has stopped rotating and
is described as a CDN edge sends the operator to the wrong screen.

Three things are pinned:

  * every axis the core can tag the event with renders its own name, taken from _HEAL_AXIS -- the same
    table the burn and heal lines use, so there is one place to change a name;
  * the count the core measured (`1/3`) reaches the operator rather than being dropped on the floor;
  * a detail with NO axis still renders -- an older core on a node that has not been updated yet must
    not produce a KeyError or a raw key on the screen.

    python3 tools/the_stopped_rotation_names_its_axis_check.py
"""
import importlib.util
import os
import re
import sys

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PANEL = os.path.join(ROOT, "tnl-central.py")
CORE = os.environ.get("CORE_DIR") or os.path.join(os.path.dirname(ROOT), "TUNNEL-MANAGER-CORE")

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def load():
    spec = importlib.util.spec_from_file_location("tnl_rotaxis", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    m = load()

    print("== every axis the core can name renders as itself ==")
    for axis, want in sorted(m._HEAL_AXIS.items()):
        for code in ("degraded", "restored"):
            _lvl, _cat, title, body = m._ev_core_text("pool", code, "%s:1/3" % axis, "core13")
            check(want in title,
                  "%s/%s names «%s»" % (axis, code, want), title)
            check("1/3" in body,
                  "  and carries the count the core measured", body.replace("\n", " · "))

    print("\n== and it no longer calls a destination pool a CDN edge ==")
    _l, _c, title, _b = m._ev_core_text("pool", "degraded", "dst:1/4", "core13")
    check("لبه" not in title,
          "a stopped DESTINATION rotation is not described as an edge", title)

    print("\n== a detail with no axis still renders, for a core that has not been updated ==")
    for code in ("degraded", "restored"):
        _l, _c, title, body = m._ev_core_text("pool", code, "2/3", "core13")
        check(bool(title) and "{" not in title and "None" not in title,
              "%s without an axis renders a sentence" % code, title)
        check(isinstance(body, str), "  and a body", body)

    print("\n== the core really does tag every pool, and with these axis names ==")
    pp = os.path.join(CORE, "internal", "packet", "peer_pool.go")
    if not os.path.exists(pp):
        print("  SKIP cross-repo check: no core checkout at %s" % CORE)
    else:
        peer = open(pp, encoding="utf-8").read()
        check('ev("pool", "degraded"' in peer and 'ev("pool", "restored"' in peer,
              "the pool reports a stopped rotation at all")
        check(bool(re.search(r'detail := axis \+ ":"', peer)),
              "and puts its axis in the detail")
        # ws_pool.go is gone: every carrier walks a PeerPool now, so there is ONE reporter and the four
        # axis names are constants rather than literals scattered over the carriers. Read the constants,
        # then confirm nothing tags a pool with a name that is not one of them.
        names = dict(re.findall(r'\n\taxis(\w+)\s*=\s*"(\w+)"', peer))
        check(len(names) == 4,
              "the core declares four axis names and this script found them all: %s"
              % sorted(names.values()), sorted(names.items()))
        used, literal = set(), []
        pkg = os.path.join(CORE, "internal", "packet")
        for f in sorted(os.listdir(pkg)):
            if not f.endswith(".go") or f.endswith("_test.go"):
                continue
            src = open(os.path.join(pkg, f), encoding="utf-8").read()
            used |= set(re.findall(r'joinStatus\([^,]+, [^,]+, axis(\w+)\)', src))
            for lo, hi in re.findall(r'\.bind\([^,]+, [^,]+, axis(\w+), axis(\w+)\)', src):
                used |= {lo, hi}
            literal += [(f, a) for a in re.findall(r'joinStatus\([^,]+, [^,]+, "(\w+)"\)', src)]
            literal += [(f, a) for pair in re.findall(r'\.bind\([^,]+, [^,]+, "(\w+)", "(\w+)"\)', src)
                        for a in pair]
        check(not literal,
              "no carrier tags a pool with a bare string instead of the constant", literal)
        check(bool(used) and used <= set(names),
              "every pool the core tags uses one of those constants",
              sorted(used - set(names)))
        check(used == set(names), "and all four are actually in use", sorted(set(names) - used))
        axes = set(names.values())
        check(axes <= set(m._HEAL_AXIS),
              "and every one has a name in the panel",
              sorted(axes - set(m._HEAL_AXIS)))

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
