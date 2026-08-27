#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the log keeps a DAY, forgets on a clock, and is searched where it is held.

What the log used to be was a list of 500. On a fleet having a bad hour the five hundredth event could
be half an hour old, so the one place an operator looks to find out what happened overnight had already
thrown the night away — and nothing said so.

Three claims now, and each one is a way the old shape failed:

  * age decides, not count. Six hundred events an hour old all stay; one event a day and a minute old
    goes, however quiet the panel has been.
  * forgetting happens on a CLOCK. A panel that logs nothing still has to let yesterday go, so the
    sweep runs in events_loop rather than only on the next write.
  * the browser holds the whole kept day, so its search reads every event and not a page of them — and
    a poll that brings nothing new does not pull the day down again to redraw the same rows.

The category an event is filed under is decided in ONE place and travels with the event, so a chip's
count and the rows behind it cannot disagree.

Exit 1 on any failure.
"""
import ast
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import list_diff_keeps_untouched_rows_check as G     # noqa: E402  (its DOM stub is the one that can run setList)

PANEL = HERE.parent / "tnl-central.py"
H = 3600
FAILS = []


def check(ok, msg, detail=""):
    print(("  ok   " if ok else " FAIL ") + msg + (("   " + str(detail)) if not ok and detail else ""))
    if not ok:
        FAILS.append(msg)


def load(state):
    spec = importlib.util.spec_from_file_location("tnl_log_guard", PANEL)
    P = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(P)
    root = P.CENTRAL_DIR
    for k in dir(P):                     # sweep, so no constant is left pointing at the real state dir
        v = getattr(P, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(P, k, os.path.join(state, os.path.relpath(v, root)))
    P.CENTRAL_DIR = state
    return P


def ev(P, age, kind="sys", fa="e", level="ok", dfa=""):
    return {"ts": int(time.time()) - age, "level": level, "kind": kind, "fa": fa, "dfa": dfa}


def part_age(P):
    print("== 1) a day is the rule, and the count is not ==")
    now = int(time.time())
    rows = [(1, "just now"), (6 * H, "six hours"), (24 * H - 120, "a day less two minutes"),
            (24 * H + 60, "a day and a minute"), (3 * 24 * H, "three days")]
    P.save_json(P.EVENTS_FILE, [ev(P, a, fa=n) for a, n in rows])
    P.ev_sweep()
    kept = [e["fa"] for e in P.load_events()]
    check(kept == ["just now", "six hours", "a day less two minutes"],
          "everything inside the day stays, everything past it goes", kept)
    check(all(now - e["ts"] <= P.EVENTS_TTL for e in P.load_events()),
          "...and nothing older than EVENTS_TTL survives a sweep")
    check(P.EVENTS_TTL == 24 * H, "the day is 24 hours", P.EVENTS_TTL)

    # The defect this replaces: a list of 500 threw away events that were minutes old.
    P.save_json(P.EVENTS_FILE, [ev(P, 3600, fa="e%d" % i) for i in range(601)])
    P.ev_sweep()
    check(len(P.load_events()) == 601,
          "six hundred and one events an hour old are ALL still there", len(P.load_events()))
    check(not hasattr(P, "EVENTS_CAP"), "there is no count-based cap left to decide this")

    print("== 2) the ceiling is a guard, and it sits far above a day's worth ==")
    P.save_json(P.EVENTS_FILE, [ev(P, 60, fa="e%d" % i) for i in range(P.EVENTS_MAX + 300)])
    P.ev_sweep()
    check(len(P.load_events()) == P.EVENTS_MAX,
          "a runaway is bounded at EVENTS_MAX=%d" % P.EVENTS_MAX, len(P.load_events()))
    check(P.EVENTS_MAX >= 5000, "...and the bound is well above what a day normally holds", P.EVENTS_MAX)


def part_clock(P):
    print("== 3) forgetting happens on a clock, not only on the next write ==")
    P.save_json(P.EVENTS_FILE, [ev(P, 30 * H, fa="yesterday"), ev(P, 60, fa="recent")])
    dropped = P.ev_sweep()                       # nothing was logged; the sweep alone must do it
    check(dropped == 1 and [e["fa"] for e in P.load_events()] == ["recent"],
          "a sweep with no new event still takes yesterday out", [e["fa"] for e in P.load_events()])
    before = os.path.getmtime(P.EVENTS_FILE)
    time.sleep(0.05)
    check(P.ev_sweep() == 0 and os.path.getmtime(P.EVENTS_FILE) == before,
          "...and a sweep with nothing to drop does not rewrite the file")

    src = ast.parse(PANEL.read_text(encoding="utf-8"))
    loop = next((n for n in ast.walk(src)
                 if isinstance(n, ast.FunctionDef) and n.name == "events_loop"), None)
    calls = {n.func.id for n in ast.walk(loop) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    check("ev_sweep" in calls, "events_loop is what runs it", sorted(calls))
    check("events_loop" in PANEL.read_text(encoding="utf-8"),
          "...and events_loop is a thread the panel starts")

    print("== 4) writing a log prunes too ==")
    P.save_json(P.EVENTS_FILE, [ev(P, 30 * H, fa="yesterday")])
    P.log_event("ok", "sys", "now", "")
    check([e["fa"] for e in P.load_events()] == ["now"],
          "one write is enough to carry yesterday out", [e["fa"] for e in P.load_events()])


def part_api(P):
    print("== 5) the browser is handed the WHOLE kept day ==")
    P.save_json(P.EVENTS_FILE, [ev(P, 60 + i, fa="e%d" % i) for i in range(900)])
    r = P.api_events({})
    check(len(r["events"]) == 900, "no default limit cuts it (900 in, %d out)" % len(r["events"]))
    check(r.get("kept_hours") == 24, "...and it says how long it keeps", r.get("kept_hours"))
    check("seq" in r and "count" in r,
          "...and carries what lets a page tell nothing has changed", sorted(r))

    print("== 6) the chip an event is filed under is decided once, and travels with it ==")
    for kind, want in (("link", "tunnel"), ("rot", "rot"), ("edge", "rot"), ("burn", "rot"),
                       ("heal", "rot"), ("ech", "ech"), ("node", "node"), ("whatever", "sys")):
        check(P._ev_cat(kind) == want, "%-9s -> %s" % (kind, want), P._ev_cat(kind))
    P.save_json(P.EVENTS_FILE, [ev(P, 60, kind="edge")])
    check((P.api_events({})["events"][0] or {}).get("cat") == "rot",
          "...and the event carries it to the page")

    page = P.INDEX_HTML
    check("function logCat(" not in page,
          "the browser does not derive it a second time")
    chips = re.search(r"var order=\[(.*?)\];", page)
    drawn = set(re.findall(r"\['(\w+)'", chips.group(1))) if chips else set()
    check(drawn == set(P.EV_CATS) | {"all", "err"},
          "every chip the page draws is a category the panel produces",
          "page=%s panel=%s" % (sorted(drawn), sorted(set(P.EV_CATS) | {"all", "err"})))


DAY = [
    {"ts": 1000, "level": "ok", "kind": "link", "fa": "تونلِ «core9» وصل شد", "dfa": "از: MMD-IR2", "cat": "tunnel"},
    {"ts": 990, "level": "bad", "kind": "node", "fa": "نودِ «MMD-DE1» قطع شد", "dfa": "connection refused", "cat": "node"},
    {"ts": 980, "level": "bad", "kind": "link", "fa": "تونلِ «core7» قطع شد", "dfa": "MMD-DE1: no route to host", "cat": "tunnel"},
    {"ts": 970, "level": "ok", "kind": "ech", "fa": "کلیدِ ECH تازه شد", "dfa": "", "cat": "ech"},
]

HARNESS = r"""
var FETCHES=[],DAY=%s;
// Stubbed at fetch, not at j: node gives this file module scope, so the page's own `function j` is a
// module binding that assigning to globalThis cannot shadow. And the DOM stub's fetch never settles,
// so a stub that misses leaves the whole harness hanging with nothing printed at all.
globalThis.fetch=function(u){FETCHES.push(String(u));
 return Promise.resolve({ok:true,json:function(){
  return Promise.resolve({ok:true,events:DAY.slice(),seq:EVSEQ,count:DAY.length,kept_hours:24})}})};
var REG={},PAINTED=[];
document.getElementById=function(id){if(REG[id])return REG[id];
 var e={innerHTML:'',textContent:'',children:[],
        querySelector:function(){return null},querySelectorAll:function(){return []}};
 return (REG[id]=e)};
// Putting rows in the document is setList's job and setList has its own guard; what is at stake here is
// WHICH rows refreshLogs decided on, and whether it went to the network to decide.
setList=function(box,rows){PAINTED=rows};
function counts(){var h=logChipsHTML(),o={},m,re=/data-f="(\w+)"[^>]*>[^<]*<span class="ct">(\d+)</g;
 while((m=re.exec(h)))o[m[1]]=+m[2];return o}
var out={};
(async function(){
 cur='logs'; EVSEQ=1; LOGN=DAY.length; LOGEVS=[]; LOGSIG=''; LOGFILTER='all'; QRY.logs='';
 // The search box, from the same call logsSkel makes -- the DOM stub's parser cannot swallow the
 // whole page skeleton, so the box is built here and the fact that logsSkel builds it is asserted
 // against the source on the python side.
 var tb=toolbar('logs',T('logs_search'));
 out.searchBox=(tb.indexOf('id="q_logs"')>=0 && tb.indexOf("onSearch('logs')")>=0);
 await refreshLogs();
 out.loaded=LOGEVS.length;
 out.painted=PAINTED.length;
 FETCHES.length=0;                      // count from here: logsSkel's own first read is not what is at stake

 // the search reads the held day, and never the network
 QRY.logs='no route to host';           // this phrase lives ONLY in a detail, never in a title
 out.detailOnly={titles:logFound().map(function(e){return e.fa}),fetches:FETCHES.length};
 QRY.logs='MMD-DE1';                    // one match by title, one by detail
 out.titleOrDetail=logFound().length;
 out.chipsFollowSearch=counts();
 LOGFILTER='node';                      // a chip on top of the search narrows it further
 out.searchPlusChip=logRows().length;
 LOGFILTER='all';
 QRY.logs='چیزی که نیست';
 out.noMatch=logRows()[0].h;

 // polls that bring nothing new must not pull the day down again
 QRY.logs=''; FETCHES.length=0;
 await refreshLogs(); await refreshLogs(); await refreshLogs();
 out.quietPolls=FETCHES.length;
 EVSEQ=2; LOGN=DAY.length+1;
 DAY.unshift({ts:1010,level:'ok',kind:'sys',fa:'تازه',dfa:'',cat:'sys'});
 await refreshLogs();
 out.afterAnEvent={fetches:FETCHES.length,held:LOGEVS.length};
 LOGN=DAY.length-1; DAY.pop();          // a prune moves the count without moving the sequence
 await refreshLogs();
 out.afterAPrune={fetches:FETCHES.length,held:LOGEVS.length};
 console.log(JSON.stringify(out));
})();
"""


def part_browser(P):
    print("== 7) the page searches the day it holds, and stops re-pulling it ==")
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", P.INDEX_HTML, re.S), key=len)
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "t.js"
        f.write_text(G.PRELUDE + "\n" + js + "\n" + (HARNESS % json.dumps(DAY, ensure_ascii=False)),
                     encoding="utf-8")
        r = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8", timeout=60)
    if r.returncode or not r.stdout.strip():
        check(False, "the page's own script runs", (r.stderr or "")[:400])
        return
    o = json.loads(r.stdout.strip().splitlines()[-1])
    body = P.INDEX_HTML.split("function logsSkel()")[1].split("function ")[0]
    check("toolbar('logs'" in body, "the log page puts a search box on itself", body[:120])
    check(o["searchBox"], "...and that box is wired to the page's own search")
    check(o["loaded"] == len(DAY) and o["painted"] == len(DAY),
          "it loads the whole day, and paints every row of it", (o["loaded"], o["painted"]))
    check(o["detailOnly"]["titles"] == ["تونلِ «core7» قطع شد"],
          "a phrase that lives only in the DETAIL is found", o["detailOnly"]["titles"])
    check(o["detailOnly"]["fetches"] == 0, "...without a round trip", o["detailOnly"]["fetches"])
    check(o["titleOrDetail"] == 2, "a name in a title and a name in a detail both match",
          o["titleOrDetail"])
    check(o["chipsFollowSearch"] == {"all": 2, "tunnel": 1, "node": 1, "err": 2},
          "the chips are counted over what the search left", o["chipsFollowSearch"])
    check(o["searchPlusChip"] == 1, "a chip narrows the search further", o["searchPlusChip"])
    check("پیدا نشد" in (o["noMatch"] or ""), "nothing matching says so, in its own words", o["noMatch"])
    check(o["quietPolls"] == 0, "three polls with nothing new pull nothing", o["quietPolls"])
    check(o["afterAnEvent"] == {"fetches": 1, "held": len(DAY) + 1},
          "a new event pulls once, and lands", o["afterAnEvent"])
    check(o["afterAPrune"] == {"fetches": 2, "held": len(DAY)},
          "a prune does too, though the sequence never moved", o["afterAPrune"])


def main():
    P = load(tempfile.mkdtemp())
    part_age(P)
    part_clock(P)
    part_api(P)
    part_browser(P)
    print()
    if FAILS:
        print("%d failure(s)." % len(FAILS))
        return 1
    print("the log keeps a day, forgets it on a clock, and is searched where it is held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
