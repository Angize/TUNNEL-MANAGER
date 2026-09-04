#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: an out-of-range step in a tuning LIST is refused, and the two lists keep separate ranges.

«صبر پیش از تلاشِ دوبارهٔ نردبان» and «زمان‌بندیِ تستِ مجددِ موقت‌سوخته» are comma-separated lists. The
browser filtered each one to a hardcoded window and the panel filtered again to 1..86400 -- both
SILENTLY, by dropping the offending number out of the list. So typing `45, 3, 600` saved `45, 600`,
reported success, and the operator's 3 was simply not there. Worse, `3` alone left the list empty and
the stored default standing, with a green toast on top.

The two lists are different clocks and now have different ranges: the revive wait is 10..3600 (the node
judges a down tunnel about once a second, so a shorter wait refills the ladder before the last rung has
been judged; longer than an hour reads as "never"), while the suspect backoff keeps 1..86400 because a
burned endpoint waits out a censor, not a probe.

This drives the REAL settings path -- api_settings_set -> _validate_tuning -> what get_settings then
holds -- because the defect was a silent drop on the way in, and a test that called the filter would
have said nothing about what the operator sees.

    python3 tools/ladder_steps_are_reported_check.py
"""
import importlib.util
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, '..')))
PANEL = os.path.join(ROOT, 'tnl-central.py')
FAILED = []

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


def check(name, cond, detail=''):
    print(('  ok   ' if cond else ' FAIL  ') + name + (('  -- ' + str(detail)) if detail and not cond else ''))
    if not cond:
        FAILED.append(name)


def load_panel(state, tag):
    spec = importlib.util.spec_from_file_location('tnl_steps_' + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    return m


def save(m, key, steps):
    """Drive the real endpoint. Returns (error message or None, what was stored)."""
    try:
        m.api_settings_set({'tuning': {key: steps}})
        err = None
    except Exception as e:                                        # noqa: BLE001
        err = str(e)
    stored = (m.get_settings().get('tuning') or {}).get(key)
    return err, stored


def main():
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, 'a')
        missing = [n for n in ('REVIVE_STEP_MIN', 'REVIVE_STEP_MAX',
                               'BACKOFF_STEP_MIN', 'BACKOFF_STEP_MAX') if not hasattr(m, n)]
        if missing:
            print(' FAIL  the panel declares no %s -- the two step lists still share one range, so a'
                  ' number that is wrong for one of them can only be dropped in silence' % ', '.join(missing))
            return 1
        lo_r, hi_r = m.REVIVE_STEP_MIN, m.REVIVE_STEP_MAX
        lo_b, hi_b = m.BACKOFF_STEP_MIN, m.BACKOFF_STEP_MAX
        dflt_r = m._TUNING_DEFAULTS['ladder_revive']

        print('== the revive wait: %d..%d ==' % (lo_r, hi_r))
        err, got = save(m, 'ladder_revive', [lo_r, 45, hi_r])
        check('an in-range list is stored exactly', err is None and got == [lo_r, 45, hi_r], (err, got))

        for bad in (lo_r - 1, 1, 3, hi_r + 1, 7200, 86400):
            err, got = save(m, 'ladder_revive', [45, bad, 600])
            check('%-6d is REFUSED with a message, not dropped from the list' % bad, bool(err), (err, got))
            check('%-6d leaves the stored list alone' % bad, got == [lo_r, 45, hi_r], got)
            check('%-6d appears in the message the operator reads' % bad, err and str(bad) in err, err)

        err, got = save(m, 'ladder_revive', [3])
        check('a list of ONE bad number does not silently keep the default', bool(err), (err, got))

        print('== the suspect backoff keeps its own, wider range: %d..%d ==' % (lo_b, hi_b))
        err, got = save(m, 'suspect_backoff', [600, 7200, hi_b])
        check('a two-hour backoff step is still accepted', err is None and got == [600, 7200, hi_b], (err, got))
        err, got = save(m, 'suspect_backoff', [hi_b + 1])
        check('and its own ceiling still refuses', bool(err), (err, got))

        print('== the ranges are NOT the same object ==')
        check('revive is narrower than backoff', (lo_r, hi_r) != (lo_b, hi_b), ((lo_r, hi_r), (lo_b, hi_b)))
        check('the defaults all fit their own range',
              all(lo_r <= x <= hi_r for x in dflt_r), dflt_r)
        check('the backoff defaults fit theirs',
              all(lo_b <= x <= hi_b for x in m._TUNING_DEFAULTS['suspect_backoff']),
              m._TUNING_DEFAULTS['suspect_backoff'])

        print('== the browser stops filtering, so the refusal can reach the operator ==')
        js = m.INDEX_HTML
        check('the revive box no longer drops out-of-range numbers client-side',
              'return n>=5&&n<=86400' not in js and 'return n>=60&&n<=86400' not in js,
              'a client-side filter puts the silence back before the backend is ever asked')
        check('the help text states the range the backend enforces',
              ('%d تا %d' % (lo_r, hi_r)) in js or ('۱۰ تا ۳۶۰۰') in js)

    print()
    if FAILED:
        print('%d failure(s).' % len(FAILED))
        return 1
    print('all good.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
