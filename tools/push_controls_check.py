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


def toplevel(name):
    """One def's own statements, with every nested def removed -- what runs when the function is CALLED."""
    src, out, skip = body(name, CODE), [], None
    for ln in src.splitlines():
        ind = len(ln) - len(ln.lstrip())
        if skip is not None and ln.strip() and ind <= skip:
            skip = None
        if skip is None and re.match(r"\s*def \w+\(", ln):
            skip = ind
        if skip is None:
            out.append(ln)
    return chr(10).join(out)


# ---- 0. ONE NODE at a time, a GLOBAL upload bound, and exactly one way to start a job
jn = body("_push_job_new")
need("_busy_nodes()" in code("_push_job_new") and "raise" in jn,
     "_push_job_new must refuse a node another live job is still working on -- two uploads to one node "
     "race each other's install. It must NOT refuse a second job: a per-node update has to be able to "
     "run while a fleet push is going.")
need("with _push_lock:" in jn.split("busy = _busy_nodes()")[0],
     "the refusal must be inside the lock or two simultaneous POSTs for one node both win")
need(SRC.count("target=_push_worker") == 1,
     "_push_worker may be launched from ONE place (_push_start), so nothing bypasses the busy check")
# The upload bound is what made one-job-at-a-time necessary. It has to be GLOBAL now, or several jobs
# put several times PUSH_WORKERS on the uplink and the operator's bound is gone.
need("_push_slots = threading.BoundedSemaphore(PUSH_WORKERS)" in CODE,
     "the concurrency bound must be a GLOBAL semaphore, not a per-job thread count")
need("_push_slots.acquire()" in code("_push_worker"),
     "...and every worker must take a slot before it uploads")
wl = code("_push_worker")
need(wl.index("_push_slots.acquire()") < wl.index("_push_next(jid, "),
     "the slot must be taken BEFORE the node is claimed, or a node waiting its turn shows «در حالِ آپلود» "
     "at 0% instead of «در نوبت»")
# and the merged view is what lets the single-job page follow several
need("def _push_merged(" in SRC and "PUSH_ALL" in SRC,
     "push-status with no job id must merge every live job: the page has one pill and one cancel")
for fn in ("api_push_cancel", "api_push_pause"):
    need("_push_live()" in code(fn),
         "%s with no job id must reach every live job, or the pill's button stops half the work" % fn)
sp = body("_push_start")
need("_push_job_new(kind, nodes)" in sp, "_push_start must build the job from the list it was given")
need("if not nodes:" in sp and "return None" in sp,
     "_push_start must report " + chr(171) + "nothing to do" + chr(187) + " rather than an empty job")

# the page must not refuse a start of its own any more -- the server owns that decision now, per node
need("ag_p_busy" not in SRC,
     "the client-side «one upload at a time» refusal is gone; the server refuses per NODE and says so")

# ---- 0b. a node already running exactly this is asked FIRST, and then not uploaded to
# The old shape read the panel's cached ping and dropped the node before the job existed. The node's own
# answer replaces it: every update opens with a «check» step, so a stale cache can no longer decide, and
# the operator sees the node being asked. What must not come back is sending the megabytes anyway.
for fn, ep in (("api_update_core", "core-put"), ("api_update_agent", "update")):
    pl = re.search(r"plan = \[(.*?)\]\n", code(fn), re.S)
    need(pl and '("check", "ping"' in pl.group(1),
         "%s must open its plan with a check step, or every node is sent the whole artifact" % fn)
    need(pl and pl.group(1).index('"check"') < pl.group(1).index('"%s"' % ep),
         "%s must ask BEFORE it delivers -- a check after the bytes have moved saves nothing" % fn)
need("_cached_ping(" not in code("api_update_core") and "_cached_ping(" not in code("api_update_agent"),
     "the skip must rest on the node's own reply to the check step, not on the panel's cached ping -- a "
     "stale cache that says «current» never delivers the update at all")
need("startswith(got)" in body("_core_current") and "if not got" not in body("_core_current"),
     "_core_current must skip only on a POSITIVE match: a node that reports no core_sha must still be "
     "pushed to, since a needless push wastes bandwidth but a wrong skip never delivers anything")
# the request thread must do NO per-node work: it builds the plan and returns. _node_arch falls back to a
# live 10s ping, so touching it here stalls the operator once per unpolled node before the job even starts.
for fn in ("api_update_core", "api_update_agent"):
    top = toplevel(fn)
    for call in ("_node_arch(", "_staged_bytes(", "prep(", "for n in nodes"):
        need(call not in top,
             "%s must not %s on the request thread -- the plan's builders run on the pool" % (fn, call))
need('"none": True' in body("_update_start"),
     "_update_start must tell the page when nothing was sent")
# provisioning the verify key is a ROUND TRIP to the node: once per node, not once per step
need("if not keyed:" in code("_push_one") and code("_push_one").count("_ensure_update_key(") == 1,
     "_push_one must provision the update key once per node -- calling it per step adds a network "
     "round trip to every step of every node for a key that is first-set-only anyway")
# provisioning the verify key is a ROUND TRIP to the node: once per node, not once per step
need("if not keyed:" in code("_push_one") and code("_push_one").count("_ensure_update_key(") == 1,
     "_push_one must provision the update key once per node -- calling it per step adds a network "
     "round trip to every step of every node for a key that is first-set-only anyway")
# a gate that fires must settle the node WITHOUT running the rest of the plan
one = body("_push_one")
need("if gate and gate(r):" in one and 'state="same"' in one and "return" in one,
     "_push_one must stop the plan when the check says the node already has it -- carrying on would "
     "deliver the artifact the check just proved unnecessary")

pf = jsfn("pushFab")
need("s=='wait'||s=='run'" in pf and "stoppable" in pf,
     "the pill must offer «لغو» while any node is queued or mid-step -- the operator asked for a cancel "
     "that lands at ANY step, and the plan is walked one step at a time so there is always one to stop")
need("ag_p_cancel_none" in pf, "...and say why it is disabled")
need("برگشت‌پذیر نیست" in SRC,
     "ag_p_cancel_q must admit that a node already applying cannot be recalled")
need("res.d.none" in jsfn("pushStart") and "ag_p_none" in jsfn("pushStart"),
     "pushStart must say «nothing was sent» instead of starting a phantom job")
need("pushBar({state:'wait'" not in CODE,
     "pushStart must not pre-paint «در نوبت»: the SERVER decides which nodes are in the job")

# the probe percentage is a staircase, so only multiples of its step may be stored
need(re.search(r'_TUNING_STEPS = \{"probe_min_pct": \(5, ', SRC),
     "probe_min_pct must carry a step of 5 -- each 5% is one more packet of the 20 the probe sends")
need('"probe_min_pct": (5, 100)' in SRC,
     "its range must start AT the step, or clamping 0 yields 1, which is not a multiple")
vt = body("_validate_tuning")
need("if step and v % step:" in vt and "raise ValueError" in vt,
     "_validate_tuning must REFUSE a non-multiple, not silently round it to a number the core never used")

# The agent and the core must not wear the same glyph ANYWHERE -- not just on the agent page. Scoping this
# to agentBody is how the node card's chips were missed: they drew «ایجنت» and «هسته» with one cpu, and the
# operator found it in a screenshot. So: no ic('cpu') call may exist at all, and every agent/core label must
# be preceded by the matching constant.
need("ic('cpu'" not in CODE,
     "no ic('cpu') anywhere -- the core's glyph comes from COR_IC so it cannot drift from the nav")
pairs = re.findall(r"ic\((AG_IC|COR_IC|'[a-z]+')(?:,[^)]*)?\)\s*\+\s*esc\(T\('([a-z_]+)'\)\)", CODE)
want_glyph = {"nd_agent": "AG_IC", "ag_node_agent": "AG_IC", "ag_lbl_agent": "AG_IC",
              "nd_core": "COR_IC", "ag_data_core": "COR_IC", "ag_lbl_core": "COR_IC"}
for glyph, key in pairs:
    if key in want_glyph:
        need(glyph == want_glyph[key],
             "the «%s» label must be drawn with %s, found %s" % (key, want_glyph[key], glyph))
need(len([1 for _g, k in pairs if k in want_glyph]) >= 3,
     "the label/glyph scan found almost nothing -- the regex has gone stale, not the code")
# The two CARD chips are invisible to the pair scan above: their markup is ic(...)+'</span> '+esc(T(...)),
# so the regex cannot pair them. Check them by name -- a mutation that swapped the card's glyph escaped
# precisely through this hole.
for glyph, label in (("AG_IC,'var(--acc)'", "ag_node_agent"), ("COR_IC,'#8b5cf6'", "ag_data_core")):
    i = CODE.find("ic(%s)" % glyph)
    need(i >= 0 and label in CODE[i:i + 120],
         "the «%s» card must be drawn with ic(%s)" % (label, glyph))
need("vhead(AG_IC,'ag_title'" in CODE and "vhead(COR_IC,'nav_core'" in CODE,
     "both page headers must come from the constants; 'cpu' made «ایجنت و هسته» read as the core page")
# and the overview note must use an icon, not an emoji
need("✅" not in SRC, "the overview note must use ic('okc'), not a ✅ emoji")
need("ic('okc','var(--ok)')" in SRC and "ov_all_good" in SRC, "…tinted with the ok colour")

# ---- 0c. the body is serialised ONCE per distinct body, not per node
need('_body_cache(' in code("api_update_core") and '_body_cache(' in code("api_update_agent"),
     "both payload builders must go through _body_cache; encoding per node is ~87ms of GIL-held CPU "
     "each, which stalls every other worker's progress")
need("json.dumps" not in code("api_update_core") and "json.dumps" not in code("api_update_agent"),
     "...and neither may json.dumps a body itself — that is exactly how the per-node encode came back")
need('key = body.get("url") or body["sha256"]' in code("_body_cache"),
     "_body_cache must key on the artifact, not on a constant: one shared entry would hand the amd64 "
     "body to an arm64 node and kill every core tunnel there with «Exec format error»")
need("isinstance(body, (bytes, bytearray))" in body("node_push"),
     "node_push must send an already-encoded body verbatim instead of re-encoding it")

P_STATES = re.findall(r'"(\w+)"', re.search(r"^PUSH_STATES = \((.*?)\)", SRC, re.M).group(1))
P_BUSY = re.findall(r'"(\w+)"', re.search(r"^PUSH_BUSY_STATES = \((.*?)\)", SRC, re.M).group(1))

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
need("skip" in P_STATES, "PUSH_STATES must list skip, which cancel actually sets")

# ---- 3. handing out work is locked, and respects pause + cancel
nxt = body("_push_next")
need("with _push_lock:" in nxt, "_push_next must claim a node under the lock or two workers take the same one")
need('update(state="run", step=first, pct=0)' in nxt,
     "_push_next must claim the node AND name the step it is about to run, in one write under the lock")
need(set(re.findall(r'state="(\w+)"', body("_push_one")) + ["run"]) <= set(P_STATES)
     and set(P_STATES) - {"wait"} <= set(re.findall(r'state="(\w+)"', SRC) + ["run"]),
     "PUSH_STATES, the states _push_one sets and the state _push_next claims with must be ONE set -- a "
     "state the browser has no word for paints a blank bar, and a listed state nothing sets is dead")
need(set(P_BUSY) == {"wait", "run"},
     "PUSH_BUSY_STATES must be exactly the unsettled ones: a node mid-step that is not counted busy can "
     "be claimed by a second job, and two installs race on one node")
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
