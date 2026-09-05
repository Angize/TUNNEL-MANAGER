#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every guard in tools/ is wired into CI, or the wiring is a lie.

Half the suite was not in `.github/workflows/ci.yml`: 48 of 98 files ran on every push and the other
50 ran only when somebody remembered to run them by hand -- which is to say, only when somebody
already suspected the thing they check. That is the worst possible state for a guard, because the
green tick still says "checked". The node repo has the proof of where it ends up:
`tools/rotate_excludes_fec_test.py` there had been red on unmodified main long enough that nobody
knew, and it was red for a reason worth knowing.

Wiring the 50 in fixes today. This file fixes tomorrow: the roster is the glob, so a guard that is
written and not wired fails HERE, by name, on the next push.

Two rosters have to agree and neither may be edited without the other noticing:

  * every `tools/*.py` is either referenced by a `python tools/<name>.py` step in ci.yml, or named in
    NOT_A_GUARD below;
  * every `python tools/<name>.py` step in ci.yml points at a file that exists -- a step left behind
    by a rename would fail on the runner, but it would fail as a missing file rather than as the
    check it was supposed to be.

`act_wait.py` is the one helper: the panel's actions run on a background thread and return an action
key, so guards import it to wait for the action to actually finish before reading the result. It is
named here, once, so that "this one is not a guard" is a decision somebody wrote down rather than an
omission nobody noticed.

    python3 tools/every_guard_runs_in_ci_check.py
"""
import os
import re
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")

NOT_A_GUARD = {"act_wait.py"}

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def main():
    if not os.path.exists(CI):
        print("FAIL no ci.yml at %s" % CI)
        return 1
    with open(CI, encoding="utf-8") as f:
        ci = f.read()

    referenced = set(re.findall(r"python tools/([A-Za-z0-9_]+\.py)", ci))
    on_disk = {f for f in os.listdir(HERE) if f.endswith(".py")}
    guards = on_disk - NOT_A_GUARD

    print("== every guard in tools/ is run by CI ==")
    missing = sorted(guards - referenced)
    check(not missing,
          "%d guard(s) in tools/, %d wired into ci.yml" % (len(guards), len(guards & referenced)),
          "NOT RUN BY CI:\n         " + "\n         ".join(missing) if missing else None)

    print("== and every step CI runs points at a file that is still there ==")
    gone = sorted(referenced - on_disk)
    check(not gone,
          "%d step(s) in ci.yml, all resolvable" % len(referenced),
          "ci.yml runs files that do not exist: " + ", ".join(gone) if gone else None)

    print("== the one file that is deliberately not a guard is still deliberately not a guard ==")
    stale = sorted(NOT_A_GUARD - on_disk)
    check(not stale, "NOT_A_GUARD names only files that exist",
          "excused but gone: " + ", ".join(stale) if stale else None)
    both = sorted(NOT_A_GUARD & referenced)
    check(not both,
          "and nothing is both excused and wired -- one of the two is then a lie",
          "excused AND in ci.yml: " + ", ".join(both) if both else None)

    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
