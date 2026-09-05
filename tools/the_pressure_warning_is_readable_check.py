#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the conntrack-pressure banner is READ, not glimpsed.

The banner shipped inside the card's left meta column, and that column carries

    .enmeta .emcol>div{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}

so a 249-character paragraph was laid out on ONE 1190px line inside a 162px box. Thirty-four
characters survived; the operator saw «جدولِ conntrackِ نود 99» and nothing else -- not the count,
not the rest of the sentence, and not the instruction that is the whole point of the banner. No
ellipsis marked the cut either, because text-overflow does not apply to a flex container, so it did
not even look truncated. It looked like the panel had a broken string.

Three things have to hold, and each has failed at least once:

  1. THE BOX. A banner belongs to the grid, not to a column: `.emwarn` spans `grid-column:1/-1` and
     wraps. Anything with `warncap` that ends up under an `.emcol` is clipped, silently.
  2. THE COLUMN RULE. The clipping rule above is deliberate -- one short value per line, ellipsised.
     It is also a trap for the next long string somebody adds. So this walks every div the card puts
     in a column and fails on any that is long without an escape class.
  3. THE BIDI. «MMD-IR12» 99٪ inside a Persian sentence is a Latin run beside a numeric run: the
     bidi algorithm reorders the two and the line renders as نودِ «99٪ MMD-IR12» پر است -- measured
     with Range rects in a browser, not guessed. The name has to be isolated, and `.iso` is
     direction:ltr;unicode-bidi:isolate.

And the sentence has to name WHICH of the two nodes is full, which is a backend question, so that
half drives the real api_fleet: two nodes, the fuller one wins, and its name reaches the record.

    python3 tools/the_pressure_warning_is_readable_check.py
"""
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"

MAX_COL_CHARS = 48
WRAP_CLASSES = ("wrap", "feat", "tagrow", "enc-line")

fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "\n         %s" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel():
    spec = importlib.util.spec_from_file_location("panel_ctwarn", PANEL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Node(object):
    def __init__(self, tag, cls, parent):
        self.tag, self.cls, self.parent, self.body = tag, cls, parent, []

    @property
    def kids(self):
        return [b for b in self.body if isinstance(b, Node)]

    def classes(self):
        return self.cls.split()

    def all_text(self):
        return "".join(b.all_text() if isinstance(b, Node) else b for b in self.body)

    def walk(self):
        yield self
        for k in self.kids:
            for n in k.walk():
                yield n

    def ancestors(self):
        p = self.parent
        while p is not None:
            yield p
            p = p.parent


class Tree(HTMLParser):
    VOID = {"br", "img", "input", "hr", "meta", "path", "circle", "line", "polyline", "rect", "use"}

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.root = Node("#root", "", None)
        self.cur = self.root

    def handle_starttag(self, tag, attrs):
        cls = dict(attrs).get("class") or ""
        n = Node(tag, cls, self.cur)
        self.cur.body.append(n)
        if tag not in self.VOID:
            self.cur = n

    def handle_startendtag(self, tag, attrs):
        cls = dict(attrs).get("class") or ""
        self.cur.body.append(Node(tag, cls, self.cur))

    def handle_endtag(self, tag):
        n = self.cur
        while n.parent is not None and n.tag != tag:
            n = n.parent
        if n.parent is not None:
            self.cur = n.parent

    def handle_data(self, data):
        self.cur.body.append(data)


def parse(html):
    t = Tree()
    t.feed(html)
    return t.root


HARNESS = "\nfor (const [name, l] of CASES) { console.log('@@' + JSON.stringify([name, coreMeta(l)])) }\n"


def render(P, cases):
    sys.path.insert(0, str(ROOT / "tools"))
    import card_names_its_carrier_check as C
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    src = C.PRELUDE + "\n" + js + "\nconst CASES=" + json.dumps(cases, ensure_ascii=False) + ";" + HARNESS
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.js"
        p.write_text(src, encoding="utf-8")
        r = subprocess.run(["node", str(p)], capture_output=True, text=True, encoding="utf-8", timeout=120)
    if r.returncode != 0:
        print("FAIL: the page would not run:\n" + (r.stderr or "")[:900])
        sys.exit(1)
    out = {}
    for line in r.stdout.splitlines():
        if line.startswith("@@"):
            k, v = json.loads(line[2:])
            out[k] = v
    return out


BASE = {
    "id": "re17", "name": "core17", "type": "core",
    "a_name": "MMD-IR12", "b_name": "MMD-GE12", "a_node": 1, "b_node": 2,
    "a_ip": "94.182.131.35", "b_ip": "91.107.169.159", "server_side": "b",
    "transport": "raw", "raw_profile": "tcp", "subnet": "192.168.17.0/24",
    "raw_port": 19302, "raw_dports": 8, "raw_sport_rotate": 4,
    "cipher": "aes-256-gcm", "obfs": True, "gso": True,
    "rot_live": {"cli": 53661, "srv": 57363, "dport": 19302, "dports": 8,
                 "lo": 10000, "hi": 59999, "drawn": 20671},
    "ct": {"pct": 99, "count": 64881, "max": 65536, "node": "MMD-IR12"},
}


def v(**kw):
    d = dict(BASE)
    d.update(kw)
    return d


# The silent half matters as much as the loud half: a banner that cannot be switched off is noise,
# and an operator who already ticked the switch is being told to tick it again.
CASES = [
    ("rotate/tcp at 99", v(), True),
    ("rotate/udp at 80", v(raw_profile="udp",
                           ct={"pct": 80, "count": 52429, "max": 65536, "node": "MMD-GE12"}), True),
    ("reactive/tcp at 100", v(raw_sport_rotate=0, raw_sport_random=True,
                              ct={"pct": 100, "count": 65536, "max": 65536, "node": "MMD-IR12"}), True),
    ("a long node name", v(ct={"pct": 97, "count": 63000, "max": 65536,
                               "node": "MMD-IR12-frankfurt-edge-01"}), True),
    # A node name is operator-typed, so it reaches the sentence through two hazards: String.replace
    # reads $& and $' in the REPLACEMENT as backreferences, and < in a name would open a tag.
    ("a name full of $&", v(ct={"pct": 91, "count": 60000, "max": 65536,
                                "node": "ir$&-a$`b$'<x>"}), True),
    ("the switch is on", v(conntrack_bypass=True), False),
    ("under the threshold", v(ct={"pct": 42, "count": 27000, "max": 65536, "node": "MMD-IR12"}), False),
    ("the port never moves", v(raw_sport_rotate=0, rot_live={}), False),
    ("bare makes no flows", v(raw_profile="bare", raw_proto=253), False),
    ("udp is not raw", v(transport="udp"), False),
    ("the node reported none", v(ct=None), False),
]


def fleet_once(P, nodes, ct, link):
    P.load_nodes = lambda: nodes
    P.load_links = lambda: [dict(link)]
    P._ensure_cached = lambda ns: None
    P._cached_ping = lambda nid: {}
    P._cached_list = lambda nid: {"ok": True, "configs": [], "ct": ct.get(nid),
                                  "health": {"core17": {"up": True, "alive": True}},
                                  "sports": {}, "rots": {}}
    P.link_drift = lambda lid: None
    P.rb_last = lambda lid: None
    return P.api_fleet({"kind": "core"})["links"][0]


def main():
    P = load_panel()
    css = re.findall(r"<style[^>]*>(.*?)</style>", P.INDEX_HTML, re.S)[0]

    print("\n-- the column rule this guard exists for --")
    m = re.search(r"\.enmeta \.emcol>div\{([^}]*)\}", css)
    check(m is not None, "the meta column still clips its rows")
    if m:
        d = m.group(1).replace(" ", "")
        check("white-space:nowrap" in d and "overflow:hidden" in d,
              "  by nowrap + overflow:hidden, so a long string in there still needs an escape", d)

    print("\n-- the banner's own box --")
    m = re.search(r"\.enmeta \.emwarn\{([^}]*)\}", css)
    check(m is not None, ".emwarn is styled at all")
    if m:
        d = m.group(1).replace(" ", "")
        check("grid-column:1/-1" in d, "  it spans the whole meta grid, not one column", d)
        check("text-align:center" in d, "  and it is centred", d)
    check(re.search(r"\.iso\{[^}]*unicode-bidi:isolate", css) is not None,
          ".iso really isolates, so a Latin name cannot reorder a Persian sentence")

    print("\n-- rendered cards --")
    html = render(P, [[n, l] for n, l, _ in CASES])
    longest = ("", 0)
    for name, l, want in CASES:
        root = parse(html[name])
        warns = [n for n in root.walk() if "warncap" in n.classes()]
        check(len(warns) == (1 if want else 0),
              "%s: %s" % (name, "the banner is drawn" if want else "the card stays silent"),
              "found %d" % len(warns))
        for w in warns:
            anc = [c for a in w.ancestors() for c in a.classes()]
            check("emcol" not in anc, "%s:   it is not inside a clipping column" % name, anc)
            check("enmeta" in anc, "%s:   it is a row of the meta grid" % name, anc)
            check("emwarn" in w.classes(), "%s:   it carries emwarn" % name, w.classes())
            txt = w.all_text()
            check("{" not in txt and "}" not in txt,
                  "%s:   every placeholder was filled" % name, txt[:90])
            check(txt.rstrip().endswith("روشن کن."),
                  "%s:   the sentence reaches its instruction" % name, txt[-40:])
            node = l["ct"]["node"]
            check(node in txt, "%s:   it names the node under pressure" % name, txt[:90])
            iso = [n for n in w.walk() if "iso" in n.classes() and node in n.all_text()]
            check(len(iso) == 1, "%s:   and the name is bidi-isolated" % name,
                  "%d isolating elements carry it" % len(iso))
        for col in [n for n in root.walk() if "emcol" in n.classes()]:
            for div in col.kids:
                if div.tag != "div":
                    continue
                if any(c in WRAP_CLASSES for c in div.classes()):
                    continue
                t = " ".join(div.all_text().split())
                if len(t) > longest[1]:
                    longest = (t, len(t))
                if len(t) > MAX_COL_CHARS:
                    check(False, "%s: a %d-char row sits in a clipping column with no escape class"
                          % (name, len(t)), t[:90])
    check(True, "the longest unescaped column row is %d chars, under the %d limit: %s"
          % (longest[1], MAX_COL_CHARS, longest[0]))

    print("\n-- which node, through the real api_fleet --")
    NODES = [{"id": 1, "name": "MMD-IR12"}, {"id": 2, "name": "MMD-GE12"}]
    LINK = {"id": "re17", "type": "core", "name": "core17", "a_node": 1, "b_node": 2,
            "server_side": "b", "transport": "raw", "raw_profile": "tcp",
            "raw_sport_rotate": 4, "psk": "s3cret", "tunnel_id": 17}
    for label, a, b, want in (
            ("the client side is fuller", (64881, 65536), (3000, 65536), "MMD-IR12"),
            ("the server side is fuller", (3000, 65536), (64881, 65536), "MMD-GE12"),
            ("a bigger table is emptier", (40000, 65536), (60000, 262144), "MMD-IR12")):
        ct = {1: {"count": a[0], "max": a[1]}, 2: {"count": b[0], "max": b[1]}}
        rec = fleet_once(P, NODES, ct, LINK)
        got = (rec.get("ct") or {}).get("node")
        check(got == want, "%s: the record names %s" % (label, want), got)
        pct = (rec.get("ct") or {}).get("pct")
        check(isinstance(pct, int) and 0 <= pct <= 100,
              "%s:   and carries a whole percentage" % label, pct)

    rec = fleet_once(P, NODES, {1: None, 2: None}, LINK)
    check("ct" not in rec, "a node that reports no table leaves the record without one", rec.get("ct"))

    rec = fleet_once(P, NODES, {1: {"count": 500, "max": 65536}, 2: None}, LINK)
    check((rec.get("ct") or {}).get("node") == "MMD-IR12",
          "one side reporting is enough to name that side", (rec.get("ct") or {}).get("node"))

    print()
    if fails:
        print("FAILED (%d)" % len(fails))
        for f in fails:
            print("  - " + f)
        return 1
    print("the pressure banner is whole, centred, and names its node")
    return 0


if __name__ == "__main__":
    sys.exit(main())
