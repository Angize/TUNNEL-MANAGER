#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drive a panel action the way the browser does, and hand back its verdict.

An action that has to talk to a node answers with a KEY, not an answer: the work runs on a panel thread
so no node can time the request out. A guard that wants the outcome has to wait for it the same way the
page does -- start it, then read `acts` until it stops running.

What the panel refuses on the REQUEST thread still raises out of here, because that is what the browser
gets too: those never became an action at all.
"""
import time


def run(P, start, timeout=30):
    """start() is the api_* call that begins the action. Returns its finished handle."""
    r = start()
    key = (r or {}).get("act")
    if not key:
        raise AssertionError("this call did not start an action: %r" % (r,))
    end = time.time() + timeout
    while time.time() < end:
        h = P.api_acts({})["acts"].get(key)
        if h and h["state"] != "run":
            return h
        time.sleep(0.01)
    raise AssertionError("action %r never finished within %ss" % (key, timeout))


def raising(P, start, timeout=30):
    """Run the action and re-raise its failure as the ValueError the request thread used to carry.

    The sentence the operator reads is the same either way; what moved is only WHERE it is raised."""
    h = run(P, start, timeout)
    if h["state"] == "fail":
        raise ValueError(h["err"])
    if h["state"] == "cancel":
        raise ValueError("لغو شد")
    return h
