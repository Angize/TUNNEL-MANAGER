# -*- coding: utf-8 -*-
"""Guard: the subnet-overlap refusal says each range once, and still names the other one when it differs.

An overlap is USUALLY an exact repeat -- two tunnels that both want 192.168.43.0/24 -- and the message
then printed that prefix twice in one sentence, once as the range asked for and once in parentheses after
the other tunnel's name. The operator reads the same string twice and learns nothing from the second.

But the two ranges are not always equal: a /21 overlaps a /24 without being it, and there the other
tunnel's range is the only thing that says WHY they collide. So the parenthetical is conditional, not
deleted -- which is exactly the kind of thing that gets "simplified" back into a stutter later.

It also pins what the message must always carry: the range asked for, the other tunnel's NAME, and the
fact that the two share a node. Without the name the operator has to hunt for the tunnel to change.

Exit 1 on any failure.
"""
import importlib.util
import os
import sys

sys.dont_write_bytecode = True
PANEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tnl-central.py")

fails = []


def check(ok, msg):
    print(("  ok   " if ok else " FAIL ") + msg)
    if not ok:
        fails.append(msg)


def refusal(m, links, want):
    """Drive the real guard and return the message it refuses with, or None if it allowed the subnet."""
    m.load_links = lambda: [dict(x) for x in links]
    try:
        m._guard_subnet_overlap({"id": 1}, {"id": 2}, want)
        return None
    except ValueError as e:
        return str(e)


def main():
    spec = importlib.util.spec_from_file_location("tnl_central_overlap", PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)

    SAME = [{"id": 9, "name": "native43", "a_node": 1, "b_node": 2, "subnet": "192.168.43.0/24"}]
    WIDER = [{"id": 9, "name": "core7", "a_node": 1, "b_node": 2, "subnet": "192.168.40.0/21"}]
    WANT = "192.168.43.0/24"

    print("== an EXACT repeat says the range once ==")
    msg = refusal(m, SAME, WANT)
    check(msg is not None, "an identical range on a shared node is refused at all")
    if msg:
        check(msg.count(WANT) == 1,
              "the range appears once, not twice: %r" % msg)
        check("native43" in msg, "and the other tunnel is named, so the operator knows what to change")
        check("نودِ مشترک" in msg, "and the reason is stated: they meet on one node")

    print("\n== a DIFFERENT range is still named, or the operator cannot see why they collide ==")
    msg = refusal(m, WIDER, WANT)
    check(msg is not None, "a wider range that contains ours is refused")
    if msg:
        check("192.168.40.0/21" in msg,
              "the other tunnel's range is in the message: %r" % msg)
        check(WANT in msg, "and so is the one that was asked for")

    print("\n== ...and tunnels that share NO node may reuse a range ==")
    APART = [{"id": 9, "name": "core7", "a_node": 7, "b_node": 8, "subnet": WANT}]
    check(refusal(m, APART, WANT) is None,
          "two tunnels on unrelated pairs live on different machines, so the same range is fine")

    print()
    if fails:
        print("%d failure(s)" % len(fails))
        return 1
    print("the overlap refusal says each range once and never drops the one that matters")
    return 0


if __name__ == "__main__":
    sys.exit(main())
