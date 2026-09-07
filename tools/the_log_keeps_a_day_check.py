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


def seed(P, rows):
    """Start the panel on this log. The store is in memory and the file is a copy of it, so putting a
    log there means writing the file AND letting the store be read from it again."""
    P.save_json(P.EVENTS_FILE, rows)
    P._ev_list, P._ev_count, P._ev_dirty = None, None, False


def part_age(P):
    print("== 1) a day is the rule, and the count is not ==")
    now = int(time.time())
    rows = [(1, "just now"), (6 * H, "six hours"), (24 * H - 120, "a day less two minutes"),
            (24 * H + 60, "a day and a minute"), (3 * 24 * H, "three days")]
    seed(P, [ev(P, a, fa=n) for a, n in rows])
    P.ev_sweep()
    kept = [e["fa"] for e in P.load_events()]
    check(kept == ["just now", "six hours", "a day less two minutes"],
          "everything inside the day stays, everything past it goes", kept)
    check(all(now - e["ts"] <= P.EVENTS_TTL for e in P.load_events()),
          "...and nothing older than EVENTS_TTL survives a sweep")
    check(P.EVENTS_TTL == 24 * H, "the day is 24 hours", P.EVENTS_TTL)

    # The defect this replaces: a list of 500 threw away events that were minutes old.
    seed(P, [ev(P, 3600, fa="e%d" % i) for i in range(601)])
    P.ev_sweep()
    check(len(P.load_events()) == 601,
          "six hundred and one events an hour old are ALL still there", len(P.load_events()))
    check(not hasattr(P, "EVENTS_CAP"), "there is no count-based cap left to decide this")

    print("== 2) the ceiling is a guard, and it sits far above a day's worth ==")
    seed(P, [ev(P, 60, fa="e%d" % i) for i in range(P.EVENTS_MAX + 300)])
    P.ev_sweep()
    check(len(P.load_events()) == P.EVENTS_MAX,
          "a runaway is bounded at EVENTS_MAX=%d" % P.EVENTS_MAX, len(P.load_events()))
    check(P.EVENTS_MAX >= 5000, "...and the bound is well above what a day normally holds", P.EVENTS_MAX)


def part_clock(P):
    print("== 3) forgetting happens on a clock, not only on the next write ==")
    seed(P, [ev(P, 30 * H, fa="yesterday"), ev(P, 60, fa="recent")])
    check([e["fa"] for e in P.load_events()] == ["recent"],
          "a panel starting on a stale log has already forgotten it", [e["fa"] for e in P.load_events()])

    # Time passing, on a panel that is up and logging nothing: the two events are both inside the day
    # when the store is read, and one of them ages out while it sits there. Nothing writes; the sweep
    # alone has to notice.
    seed(P, [ev(P, 60, fa="recent"), ev(P, 60, fa="ages out")])
    P.load_events()
    with P._events_lock:
        P._ev_list[1]["ts"] -= 2 * 24 * H
    dropped = P.ev_sweep()
    check(dropped == 1 and [e["fa"] for e in P.load_events()] == ["recent"],
          "a sweep with no new event still takes out what aged while it sat there",
          "dropped=%s kept=%s" % (dropped, [e["fa"] for e in P.load_events()]))
    before = os.path.getmtime(P.EVENTS_FILE)
    time.sleep(0.05)
    check(P.ev_sweep() == 0 and os.path.getmtime(P.EVENTS_FILE) == before,
          "...and a sweep with nothing to drop does not rewrite the file")

    src = ast.parse(PANEL.read_text(encoding="utf-8"))
    loop = next((n for n in ast.walk(src)
                 if isinstance(n, ast.FunctionDef) and n.name == "events_loop"), None)
    calls = {n.func.id for n in ast.walk(loop) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    check("ev_sweep" in calls, "events_loop is what runs it", sorted(calls))
    # ...and that loop has to be a thread somebody starts. Looking for the NAME proves nothing: it is
    # in the file because the function is defined there.
    started = {kw.value.id for n in ast.walk(src)
               if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "Thread"
               for kw in n.keywords
               if kw.arg == "target" and isinstance(kw.value, ast.Name)}
    check("events_loop" in started, "...and the panel starts it as a thread", sorted(started))

    print("== 4) a write costs nothing, because it does not touch the file ==")
    # The defect this shape replaces: log_event re-read and re-wrote the WHOLE file per event, so at a
    # day's worth each one cost tens of milliseconds under the lock, and a burst was quadratic. The
    # structural claim is the one that cannot flake -- the file is untouched until the sweep.
    seed(P, [])
    P.load_events()
    t0 = time.perf_counter()
    for i in range(800):
        P.log_event("ok", "sys", "e%d" % i, "detail")
    burst = time.perf_counter() - t0
    with open(P.EVENTS_FILE, encoding="utf-8") as f:
        on_disk = len(json.load(f))
    check(on_disk == 0, "800 events written, and the file was not touched once", on_disk)
    check(len(P.load_events()) == 800, "...they are all in the store", len(P.load_events()))
    check(burst < 1.0, "...and the burst took %.0f ms, not seconds" % (burst * 1000))
    P.ev_sweep()
    with open(P.EVENTS_FILE, encoding="utf-8") as f:
        check(len(json.load(f)) == 800, "the sweep is what puts them on disk")

    print("== 4a) newest first, which is what the ceiling and the page both lean on ==")
    # The runaway cut is a slice off the FRONT, and the page renders in the order it is handed. Both are
    # silently wrong if the store ever drifts out of order, and nothing else would say so.
    seed(P, [])
    P.load_events()
    for i in range(5):
        P.log_event("ok", "sys", "e%d" % i, "")
        time.sleep(0.002)
    held = [e["fa"] for e in P.load_events()]
    check(held == ["e4", "e3", "e2", "e1", "e0"], "the store is newest first", held)
    check([e["fa"] for e in P.api_events({})["events"]] == held,
          "...and that is the order the page is handed")
    ts = [e["ts"] for e in P.load_events()]
    check(ts == sorted(ts, reverse=True), "...and the timestamps agree with it", ts)

    print("== 4b) the ceiling is the one cut a write does make ==")
    seed(P, [ev(P, 60, fa="e%d" % i) for i in range(P.EVENTS_MAX)])
    P.load_events()
    P.log_event("ok", "sys", "one more", "")
    kept = P.load_events()
    check(len(kept) == P.EVENTS_MAX and kept[0]["fa"] == "one more",
          "at the ceiling a write pushes the oldest out and the count holds", len(kept))
    check(kept[-1]["fa"] == "e%d" % (P.EVENTS_MAX - 2),
          "...and it is the OLDEST that went, not the newest", kept[-1]["fa"])


def part_api(P):
    print("== 5) the browser is handed the WHOLE kept day ==")
    seed(P, [ev(P, 60 + i, fa="e%d" % i) for i in range(900)])
    r = P.api_events({})
    check(len(r["events"]) == 900, "no default limit cuts it (900 in, %d out)" % len(r["events"]))
    check(sorted(r) == ["events", "ok"], "...and carries nothing the page does not read", sorted(r))
    # How long it keeps is written in one place. A sentence with its own copy of the number goes wrong
    # the day the constant moves, and every check would still be green.
    said = re.search(r'logs_sub:"([^"]*)"', P.INDEX_HTML)
    check(bool(said) and (" %d " % (P.EVENTS_TTL // 3600)) in said.group(1),
          "the page's own sentence says the hours EVENTS_TTL holds",
          said.group(1)[:60] if said else None)

    print("== 6) the chip an event is filed under is decided once, and travels with it ==")
    for kind, want in (("link", "tunnel"), ("rot", "rot"), ("edge", "rot"), ("burn", "rot"),
                       ("heal", "rot"), ("ech", "ech"), ("node", "node"), ("whatever", "sys")):
        check(P._ev_cat(kind) == want, "%-9s -> %s" % (kind, want), P._ev_cat(kind))
    seed(P, [ev(P, 60, kind="edge")])
    check((P.api_events({})["events"][0] or {}).get("cat") == "rot",
          "...and the event carries it to the page")

    page = P.INDEX_HTML
    check("function logCat(" not in page,
          "the browser does not derive it a second time")
    # Every kind the panel really logs, read off the log_event calls themselves rather than a list that
    # can fall behind them -- so a chip the page draws that nothing can fill would fail here.
    src = ast.parse(PANEL.read_text(encoding="utf-8"))
    kinds = {n.args[1].value for n in ast.walk(src)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "log_event"
             and len(n.args) > 1 and isinstance(n.args[1], ast.Constant)}
    check(len(kinds) >= 4, "the panel logs %d different kinds" % len(kinds), sorted(kinds))
    produced = {P._ev_cat(k) for k in kinds} | {"all", "err"}
    chips = re.search(r"var order=\[(.*?)\];", page)
    drawn = set(re.findall(r"\['(\w+)'", chips.group(1))) if chips else set()
    check(drawn == produced,
          "every chip the page draws is one the panel can actually fill",
          "page=%s panel=%s (from kinds %s)" % (sorted(drawn), sorted(produced), sorted(kinds)))


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
function mkDay(n){var a=[];for(var i=0;i<n;i++)a.push({ts:2000-i,level:'ok',kind:'sys',cat:'sys',
  fa:'e'+i,dfa:'d'+i});return a}
var out={};
(async function(){
 cur='logs'; EVSEQ=1; LOGN=DAY.length; LOGEVS=[]; LOGSIG=''; LOGFILTER='all'; QRY.logs='';
 // The search box, from the same call logsSkel makes -- the DOM stub's parser cannot swallow the
 // whole page skeleton, so the box is built here and the fact that logsSkel builds it is asserted
 // against the source on the python side.
 var tb=toolbar('logs',T('logs_search'));
 out.searchBox=(tb.indexOf('id="q_logs"')>=0 && tb.indexOf('onSearch(hA(this))')>=0
                && tb.indexOf('data-ha="logs"')>=0);
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
 // Every empty state the page can reach, enumerated: each chip, with and without a search that misses,
 // plus the empty log. A category with nothing in it is dropped back to «همه» before the list is built,
 // so «this category is empty» is a sentence nothing can produce -- and a message nothing can reach is
 // one nobody maintains.
 out.emptyStates=[];
 ['all','tunnel','rot','ech','node','sys','err'].forEach(function(f){
  ['','zzzz-no-such-thing'].forEach(function(qq){
   LOGEVS=DAY.slice(); LOGFILTER=f; QRY.logs=qq; LOGSIG='s'+f+qq; LOGQ=''; LOGPAINT=''; LOGSHOW=LOGPAGE;
   var rows=logRows();
   if(rows.length===1&&rows[0].k==='__empty')out.emptyStates.push(rows[0].h.replace(/<[^>]*>/g,''))})});
 LOGEVS=[]; LOGFILTER='all'; QRY.logs=''; LOGSIG='e'; LOGQ=''; LOGPAINT=''; logPaint();
 out.emptyStates.push(PAINTED[0].h.replace(/<[^>]*>/g,''));
 out.noMatch=out.emptyStates[0];

 // a day is HELD and SEARCHED whole, but only a window of it is built into cards -- and the rest is
 // one tap away, with the count saying how much is left
 QRY.logs=''; LOGFILTER='all'; LOGEVS=mkDay(1200); LOGSIG='x'; LOGQ=''; LOGPAINT=''; LOGSHOW=LOGPAGE;
 logPaint();
 out.window={drawn:PAINTED.length,page:LOGPAGE,last:PAINTED[PAINTED.length-1].k};
 logMore();
 out.afterMore=PAINTED.length;
 QRY.logs='e7'; logPaint();                 // a fresh question starts at the top of its own answer
 out.searchResetsWindow=LOGSHOW;

 // building the list is THE cost on this page; a poll that brings nothing must not pay it
 QRY.logs=''; LOGFILTER='all'; LOGEVS=DAY.slice(); LOGSIG='y'; LOGQ=''; LOGPAINT='';
 var built=0,realRows=logRows,counted=0,realCounts=logCounts;
 logRows=function(){built++;return realRows()};
 logCounts=function(){counted++;return realCounts()};
 logPaint();
 var afterFirst=built,countedFirst=counted;
 logPaint(); logPaint(); logPaint();
 out.paintsWhenNothingChanged={first:afterFirst,afterThreeMore:built};
 // a tick that changes nothing must not count, filter or build -- not just skip the building
 out.workWhenNothingChanged={countedFirst:countedFirst,countedAfterThreeMore:counted};
 logCounts=realCounts;
 LOGFILTER='node'; logPaint();
 out.paintsWhenTheChipChanged=built;
 logRows=realRows; LOGFILTER='all'; LOGPAINT=''; LOGQ='';

 // a chip whose category the search emptied cannot stay active -- and falling back to «همه» is a
 // decision, so it costs ONE paint and not a second one to notice itself
 LOGEVS=DAY.slice(); LOGSIG='z'; LOGQ=''; LOGPAINT=''; QRY.logs=''; LOGFILTER='rot';   // nothing in DAY is a rotation
 var b2=0,rr=logRows; logRows=function(){b2++;return rr()};
 logPaint();
 out.emptiedChip={filter:LOGFILTER,paints:b2};
 logPaint();
 out.emptiedChipSettles=b2;
 logRows=rr;

 // polls that bring nothing new must not pull the day down again. Put the page back where the section
 // above found it first, or the fake signature this one used would count as a change.
 QRY.logs=''; LOGEVS=DAY.slice(); LOGSIG=EVSEQ+':'+LOGN; FETCHES.length=0;
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
    check(len(set(o["emptyStates"])) == 2,
          "the page has exactly two empty states, and both are reachable",
          sorted(set(o["emptyStates"])))
    check(o["quietPolls"] == 0, "three polls with nothing new pull nothing", o["quietPolls"])
    check(o["afterAnEvent"] == {"fetches": 1, "held": len(DAY) + 1},
          "a new event pulls once, and lands", o["afterAnEvent"])
    check(o["afterAPrune"] == {"fetches": 2, "held": len(DAY)},
          "a prune does too, though the sequence never moved", o["afterAPrune"])

    print("== 8) a day is held and searched whole, but drawn a window at a time ==")
    check(o["window"]["drawn"] == o["window"]["page"] + 1 and o["window"]["last"] == "__more",
          "1200 events draw %d rows and one «more»" % o["window"]["page"], o["window"])
    check(o["afterMore"] == 2 * o["window"]["page"] + 1,
          "...and «more» adds another page", o["afterMore"])
    check(o["searchResetsWindow"] == o["window"]["page"],
          "a new search is answered from its first row", o["searchResetsWindow"])
    check(o["paintsWhenNothingChanged"] == {"first": 1, "afterThreeMore": 1},
          "three paints with nothing changed build the list once",
          o["paintsWhenNothingChanged"])
    check(o["workWhenNothingChanged"] == {"countedFirst": 1, "countedAfterThreeMore": 1},
          "...and count the day once too, not once per tick", o["workWhenNothingChanged"])
    check(o["paintsWhenTheChipChanged"] == 2,
          "...and a chip that changed builds it again", o["paintsWhenTheChipChanged"])
    check(o["emptiedChip"] == {"filter": "all", "paints": 1},
          "a chip the search emptied falls back to «همه» in one paint", o["emptiedChip"])
    check(o["emptiedChipSettles"] == 1,
          "...and the paint after it does nothing at all", o["emptiedChipSettles"])


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
