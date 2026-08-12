# -*- coding: utf-8 -*-
"""Guard #41 — the fleet upload's parallelism and its three controls.

Closes the classes that this batch's bugs came from:
  * the pool must hand nodes out under the lock, honour pause/cancel, and never let one node end the sweep
  * pause must be an EXPLICIT want, not a toggle (two quick taps would race)
  * the controls must live OUTSIDE the node list -- refreshAgent rewrites it and would wipe them
  * a finished job must leave no pill and no lifted toast
  * the row must be icon-only: no «ایجنت»/«هسته» text, and the version must not go through num()
"""
import io
import os
import re
import sys
import tokenize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = io.open(os.path.join(ROOT, "tnl-central.py"), encoding="utf-8").read()
bad = []


def need(cond, msg):
    if not cond:
        bad.append(msg)


def _blank_comments(src):
    """src with every # comment blanked out, positions preserved.

    A «must not call X» assertion that greps raw source matches a comment EXPLAINING why X is not called,
    and then fails on correct code -- which is exactly what happened here. Comments are never evidence."""
    lines = src.splitlines(keepends=True)
    for t in tokenize.generate_tokens(io.StringIO(src).readline):
        if t.type == tokenize.COMMENT:
            r, c = t.start
            ln = lines[r - 1]
            lines[r - 1] = ln[:c] + " " * len(t.string) + ln[c + len(t.string):]
    return "".join(lines)


CODE = _blank_comments(SRC)


def body(name, text=None):
    """The source of one python def, up to the next top-level def."""
    m = re.search(r"\ndef %s\(.*?\n(.*?)(?=\ndef |\nclass )" % re.escape(name), text or SRC, re.S)
    return m.group(1) if m else ""


def code(name):
    """Same, but with comments blanked -- use for every «must NOT contain» assertion."""
    return body(name, CODE)


def jsfn(name):
    """The source of one browser function, up to the next top-level function."""
    m = re.search(r"\n(?:async )?function %s\(.*?\n(.*?)(?=\n(?:async )?function |\nvar )"
                  % re.escape(name), SRC, re.S)
    return m.group(1) if m else ""


# ---- 0. ONE job at a time, and exactly one way to start it
jn = body("_push_job_new")
need('if any(not v["done"] for v in _push_jobs.values()):' in jn and "raise" in jn,
     "_push_job_new must refuse a second job: PUSH_WORKERS is PER JOB, so two jobs double the uploads on "
     "the uplink, and push-status/_push_active/the pill are all single-job")
need("with _push_lock:" in jn.split('if any(not v["done"]')[0],
     "the refusal must be inside the lock or two simultaneous POSTs both win")
need(SRC.count("target=_push_worker") == 1,
     "_push_worker may be launched from ONE place (_push_start), else the single-job rule is bypassable")
need("_push_job_new(kind, nodes, current)" in body("_push_start"),
     "_push_start must forward the already-current set")
# one condition must not have two wordings
busy = re.findall(r'raise ValueError\("(یک آپلود[^"]*)"\)', SRC)
key = re.search(r'ag_p_busy:"([^"]*)"', SRC)
need(len(busy) == 1 and key and busy[0] == key.group(1),
     "the server's «busy» sentence must be byte-identical to ag_p_busy, got %r vs %r"
     % (busy, key and key.group(1)))

# ---- 0b. a node already running exactly this is not uploaded to at all
cur = body("_push_current")
need("if w and got and got == w:" in cur,
     "_push_current must skip only on a POSITIVE match -- a missing/stale ping must still be pushed to, "
     "since a needless push wastes bandwidth but a wrong skip never delivers the update")
need("_cached_ping(" in cur, "_push_current must read the same ping the row's «به‌روز» is drawn from")
need("_node_arch(" not in code("_core_job"),
     "the skip check runs INSIDE the request, so it must not call _node_arch -- that falls back to a "
     "live 10s ping and would stall the operator once per unpolled node before the job even starts")
need('_push_current(nodes, "core_sha", want)' in body("_core_job"),
     "the core push must skip nodes whose reported core_sha already matches the staged one")
need('_push_current(nodes, "sha256"' in body("api_agent_push"),
     "the agent push must skip nodes whose reported sha256 already matches the stored agent")
need('"state": "same" if n["id"] in cur else "wait"' in jn,
     "a skipped node must start settled at «همین نسخه بود», not vanish from the job")

# ---- 0c. the body is serialised ONCE, not per node
need('cache[arch] = (json.dumps(' in body("_staged_payload"),
     "the staged payload must cache the ENCODED body; caching only the dict left json.dumps running per "
     "node -- ~87ms of GIL-held CPU each, which stalls every other worker's progress")
need('enc = json.dumps({"code": src' in body("api_agent_push"),
     "the agent body must be encoded once for the fleet, not per node")
need("isinstance(body, (bytes, bytearray))" in body("node_push"),
     "node_push must send an already-encoded body verbatim instead of re-encoding it")

# ---- 1. the pool is bounded and parallel
need(re.search(r"^PUSH_WORKERS\s*=\s*[2-9]\d*\b", SRC, re.M), "PUSH_WORKERS must be a bounded (>1) constant")
w = body("_push_worker")
need("threading.Thread" in w and "PUSH_WORKERS" in w,
     "_push_worker must start PUSH_WORKERS threads (it is the parallelism)")
need("for n in nodes:" not in code("_push_worker"), "_push_worker must not walk the nodes itself -- that is the sequential shape")
need(".join()" in w, "_push_worker must join its workers before marking the job done")
need('j["done"] = True' in w, "_push_worker must still mark the job done")
need(w.index("finally:") < w.index('j["done"] = True'),
     "_push_worker must mark the job done in a finally: only one job runs at a time, so a job left "
     "not-done blocks every later push until the 1h prune")

# ---- 2. one node's failure is recorded on that node, never raised out
one = body("_push_one")
need("except Exception" in one and 'state="err"' in one,
     "_push_one must swallow a node's exception into that node's own err state")
need("raise" not in code("_push_one"), "_push_one must not re-raise -- a raise would end that worker")

# ---- 2b. cancel reaches a LIVE upload, and a cut-off node is not called a failure
need("should_abort=lambda: _push_cancelled(jid)" in one,
     "_push_one must hand node_push an abort hook or cancel cannot touch an upload in flight")
need('r.get("cancelled")' in one and 'state="skip"' in one,
     "a cut-off node must read skip -- «err» would blame the node for the operator's choice")
np = body("node_push")
need("should_abort and should_abort()" in np and '"cancelled": True' in np,
     "node_push must consult the hook between chunks and report that it aborted")
need(re.search(r"while sent < total:\s*\n\s*if should_abort", np),
     "the check must sit INSIDE the send loop -- once before it only catches an already-cancelled job")
need('if "state" in kw and kw["state"] not in PUSH_STATES' in body("_push_set"),
     "_push_set must reject an unknown state; PUSH_STATES is otherwise dead documentation")
need('"skip"' in re.search(r"^PUSH_STATES = \((.*?)\)", SRC, re.M).group(1),
     "PUSH_STATES must list skip, which cancel actually sets")

# ---- 3. handing out work is locked, and respects pause + cancel
nxt = body("_push_next")
need("with _push_lock:" in nxt, "_push_next must claim a node under the lock or two workers take the same one")
need('j["nodes"][nid]["state"] = "send"' in nxt, "_push_next must claim the node it returns")
need('j.get("cancel")' in nxt and "return None" in nxt, "_push_next must stop handing out work on cancel")
c = body("api_push_cancel")
need("_skip_waiting(j)" in c,
     "api_push_cancel must skip the queue ITSELF -- leaving it to _push_next keeps the rows reading "
     "«در نوبت» until an upload finishes, which reads as a dead button")
need('state="skip"' in body("_skip_waiting"), "_skip_waiting must be what actually marks them")
need(CODE.count('.update(state="skip"') == 1,
     "ONE place may decide what cancel does to the queue -- two copies of the invariant drift apart")
need('j.get("paused")' in nxt and '"wait"' in nxt, "_push_next must hold the queue while paused")

# ---- 4. pause is an explicit want and is reported back
p = body("api_push_pause")
need('d or {}).get("paused"' in p, "api_push_pause must take an explicit paused value, not toggle")
need('j["paused"] = want' in p, "api_push_pause must store the requested state")
need('"push-pause": api_push_pause' in SRC, "push-pause must be registered")
need(re.search(r'"push-cancel",\s*"push-pause"', SRC), "push-pause must sit in the CSRF-gated list")
need('"paused": bool(j.get("paused"))' in body("api_push_status"),
     "api_push_status must report paused or the page cannot draw the buttons")
need('"paused": False' in body("_push_job_new"), "a new job must start unpaused")

# ---- 5. the controls live outside the list that gets rewritten
need('<div id="pushFab"></div>' in SRC, "the pill's host must exist in the shell")
view = SRC.index('<div id="view"></div>')
need(SRC.index('<div id="pushFab"></div>') > view,
     "the pill's host must sit OUTSIDE #view -- inside, refreshAgent would wipe it")
fab = jsfn("pushFab")
need("if(!live)" in fab and "setHTML(box,'')" in fab, "pushFab must clear itself when the job is done")
need("classList.toggle('pushing'" in fab, "pushFab must mark the body so the toast clears the pill")
need("body.pushing .toast{bottom:" in SRC, "the toast must lift while the pill is shown")
need("pushFab(d)" in jsfn("pushPaint"), "pushPaint must repaint the pill on every poll tick")
need("pushFab(null)" in jsfn("pushPoll"), "pushPoll must drop the pill when tracking ends")
for lbl, want in (("pushPause(true)", "ag_p_pause"), ("pushPause(false)", "ag_p_resume"),
                  ("pushCancel()", "ag_p_cancel")):
    need(lbl in fab and want in fab, "the pill needs a %s button titled %s" % (lbl, want))
pp = jsfn("pushPause")
need("!!want" in pp and "post('push-pause'" in pp, "pushPause must post the explicit want")

# ---- 6. the row is icon-only and the version is a string, not a number
row = jsfn("agRow")
need("class=\"ib" in row, "the row's actions must be the icon-only .ib button")
# the content between > and </button> must be the icon and NOTHING else -- that is what «icon-only» means
need(row.count("+ic(AG_IC)+'</button>'") == 1 and row.count("+ic(COR_IC)+'</button>'") == 1,
     "each action button must contain only its icon -- no «ایجنت»/«هسته» text beside it")
need("AG_IC" in row and "COR_IC" in row, "both glyphs must come from the one pair of constants")
# the pair is borrowed from the sidebar so one thing never wears two icons, and must not reuse a glyph that
# already means something else there (cog is «تنظیمات»)
pair = re.search(r"var AG_IC='([a-z]+)',COR_IC='([a-z]+)'", SRC)
need(bool(pair), "the glyph pair must be one declaration")
if pair:
    ag, cor = pair.group(1), pair.group(2)
    nav = dict(re.findall(r'data-ic="([a-z]+)"></span> <span class="nlbl">([^<]*)</span>', SRC))
    need(nav.get(ag) == "نودها", "the agent glyph must be the nav's «نودها» icon, got %r" % nav.get(ag))
    need(nav.get(cor) == "هستهٔ اختصاصی",
         "the core glyph must be the nav's «هستهٔ اختصاصی» icon, got %r" % nav.get(cor))
    need(nav.get("cog") not in (None,) and "cog" not in (ag, cor),
         "cog is «تنظیمات» in the same nav -- reusing it gives one glyph two meanings")
need("num(i.core_ver" not in row, "core_ver is a LABEL (may be «custom») -- num() turns it into 0")
need("class=\"vline\"" in row, "the row must carry the «icon: version — icon: version» line")
for cls in ("ok", "up", "na", "offl"):
    need("'%s'" % cls in row, "the version line must be able to show the %s state" % cls)
# the row and its skeleton must not drift apart again
need('class="msg agres"' in jsfn("skAgRow"),
     "skAgRow must carry the empty .agres line or the list jumps when it loads")
need("class=\"vline\"" in jsfn("skAgRow"), "skAgRow must mirror the row's version line")

out = io.open(1, "w", encoding="utf-8", closefd=False)
if bad:
    out.write("FAIL push controls:\n" + "".join("  - %s\n" % b for b in bad))
    out.flush()
    sys.exit(1)
out.write("push controls OK\n")
out.flush()
