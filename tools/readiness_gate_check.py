#!/usr/bin/env python3
"""The panel refuses the two operations it has nothing to perform with, and says so before you try.

Adding a node installs the staged agent on it and pushes the staged core to it; building a core tunnel
needs that core to exist. With neither on the panel, both used to start and fail somewhere in the
middle, on the node. So:

  * `_readiness()` is the one answer, and the core half needs BOTH architectures -- nodes.json carries
    no arch, so the panel cannot know which one the next node will report.
  * `api_node_install` and the core-tunnel build refuse server-side, BEFORE any node is contacted. The
    disabled button is not the gate; a stale page or a second tab walks straight past it.
  * the browser lands on Settings at load while something is missing, and only while.

Both halves are driven, not read: the python half calls the real API entry points with a real panel
state directory, and the browser half runs the page's own script under node and reads what it did.
"""
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
sys.path.insert(0, str(ROOT / "tools"))
import act_wait as A     # noqa: E402  (building a tunnel answers with a key, so A.raising waits for its verdict)
FAILED = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else " FAIL  ") + name + (("  -- " + detail) if detail and not cond else ""))
    if not cond:
        FAILED.append(name)


GATE_MARK = "این کار به چیزی نیاز دارد که هنوز روی پنل آماده نیست"
AGENT_SRC = '#!/usr/bin/env python3\nPING = {"agent": "tnl-node", "version": 42}\nprint(PING)\n'
CORE = b"\x7fELF" + b"A" * 200000


def load_panel(state):
    """The panel with every path it writes re-pointed into `state`, by SWEEPING the module rather than
    listing the names -- a list is one constant away from silently writing into the real state dir."""
    spec = importlib.util.spec_from_file_location("tnl_readiness_check", str(PANEL))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    root = m.CENTRAL_DIR
    for k in dir(m):
        v = getattr(m, k)
        if isinstance(v, str) and v.startswith(root):
            setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
    m.CENTRAL_DIR = state
    os.makedirs(m.CORE_STAGE_DIR, exist_ok=True)
    m.log_event = lambda *a, **k: None
    left = sorted(k for k in dir(m) if isinstance(getattr(m, k), str) and getattr(m, k).startswith(root))
    if left:
        sys.exit("these panel paths still point at the real state dir: %s" % left)
    return m


def put_agent(m, on):
    for p in (m.AGENT_FILE, m.AGENT_META):
        if os.path.isfile(p):
            os.remove(p)
    if on:
        m._store_agent_src(AGENT_SRC, {"too_big": "x", "bad_py": "x", "not_agent": "x", "no_ver": "x"},
                           {"source": "git"})


def put_core(m, arches):
    for a in m.CORE_ARCHES:
        p = os.path.join(m.CORE_STAGE_DIR, "tnl-core-" + a)
        if os.path.isfile(p):
            os.remove(p)
    if os.path.isfile(m.CORE_STAGE_META):
        os.remove(m.CORE_STAGE_META)
    if not arches:
        return
    for a in arches:
        m.save_bytes(os.path.join(m.CORE_STAGE_DIR, "tnl-core-" + a), CORE + a.encode())
    m.save_json(m.CORE_STAGE_META, {"version": "v9.9.9", "arches": list(arches),
                                    "sha": {a: hashlib.sha256(CORE + a.encode()).hexdigest() for a in arches},
                                    "size": {a: len(CORE) + len(a) for a in arches}, "ts": int(time.time())})


def part_readiness(m):
    print("== 1) what «ready» means ==")
    for agent, arches, want_ok, want_missing in (
            (False, (), False, ["amd64", "arm64"]),
            (True, (), False, ["amd64", "arm64"]),
            (False, ("amd64", "arm64"), False, []),
            # THE case the operator called out: a stage that got only amd64 must NOT read ready. Today
            # _stage_core treats arm64 as best-effort, so this is reachable on any flaky fetch.
            (True, ("amd64",), False, ["arm64"]),
            (True, ("amd64", "arm64"), True, [])):
        put_agent(m, agent)
        put_core(m, arches)
        r = m._readiness()
        label = "agent=%-5s core=%-16s" % (agent, ",".join(arches) or "-")
        check("%s -> ok=%s" % (label, want_ok), r["ok"] == want_ok, json.dumps(r, ensure_ascii=False))
        check("%s -> missing=%s" % (label, want_missing or "none"), r["core_missing"] == want_missing,
              json.dumps(r["core_missing"]))


def part_gate(m):
    print("== 2) the two operations refuse, before any node is touched ==")
    touched = []
    m.node_call = lambda *a, **k: touched.append(a[1] if len(a) > 1 else "?") or {"ok": True}
    m._ssh_run = lambda *a, **k: touched.append("ssh") or (0, "", "")
    m._ping_both = lambda A, B: touched.append("ping") or ({"ips": {}}, {"ips": {}})
    m.save_json(m.NODES_FILE, [{"id": "n1", "name": "A", "host": "10.0.0.1", "port": 8099, "token": "t1"},
                               {"id": "n2", "name": "B", "host": "10.0.0.2", "port": 8099, "token": "t2"}])

    ops = [
        ("افزودن نود", lambda: m.api_node_install({"name": "new", "ssh_host": "10.0.0.9", "ssh_pass": "p"}), True),
        # A build answers with an action key; its refusal lands on the action, so the gate is read there.
        ("ساختِ تونلِ هسته",
         lambda: A.raising(m, lambda: m.api_create_tunnel({"a_node": "n1", "b_node": "n2", "type": "core"})),
         False),
    ]
    for agent, arches in ((False, ()), (True, ()), (True, ("amd64",)), (False, ("amd64", "arm64"))):
        put_agent(m, agent)
        put_core(m, arches)
        for label, run, needs_agent in ops:
            if not needs_agent and agent and arches == ("amd64", "arm64"):
                continue
            touched.clear()
            try:
                run()
                err = ""
            except ValueError as e:
                err = str(e)
            # Only the GATE's refusal counts. These calls run against a stub fleet, so a build that got
            # PAST the gate still dies further in ("could not determine node IPs") -- reading any
            # ValueError as a refusal would have scored that as the gate working.
            refused = GATE_MARK in err
            expect = (needs_agent and not agent) or len(arches) < 2
            check("%s | agent=%s core=%s -> %s" % (label, agent, ",".join(arches) or "-",
                                                   "refused" if expect else "past the gate"),
                  refused == expect, err or "no error")
            if expect:
                check("...and no node was contacted first", not touched, str(touched))
                check("...and it names what is missing", "آماده نیست" in err, err)

    # A gate on the core tunnel must not become a gate on everything: the kernel carriers install nothing.
    put_agent(m, True)
    put_core(m, ())
    touched.clear()
    try:
        A.raising(m, lambda: m.api_create_tunnel({"a_node": "n1", "b_node": "n2", "type": "gre"}))
        err = ""
    except ValueError as e:
        err = str(e)
    check("a NON-core tunnel is not gated on the core", GATE_MARK not in err, err)


def part_stage_report(m):
    print("== 3) a half-finished stage says so ==")
    put_core(m, ())
    got = {"n": 0}

    def one_arch(version, arch, on_progress=None, should_abort=None):
        got["n"] += 1
        if arch == "arm64":
            raise RuntimeError("release checksum mismatch")
        return CORE, hashlib.sha256(CORE).hexdigest()

    m._fetch_release = one_arch
    m._resolve_core_version = lambda v: "v9.9.9"
    res = m._stage_core("v9.9.9")
    check("the stage reports which arch it could not get", res.get("missing") == ["arm64"],
          json.dumps(res, ensure_ascii=False))
    check("...and readiness agrees the panel is not ready", m._readiness()["ok"] is False)


PRELUDE = r"""
const noop = () => {};
const mkClassList = () => { const s = new Set(); return {add:c=>s.add(c),remove:c=>s.delete(c),
  toggle:(c,on)=>(on?s.add(c):s.delete(c)),contains:c=>s.has(c)}; };
const _node = {value:'', style:{}, classList:mkClassList(), dataset:{}, children:[],
  appendChild:noop, addEventListener:noop, setAttribute:noop, removeAttribute:noop, remove:noop,
  querySelector:()=>null, querySelectorAll:()=>[], insertAdjacentHTML:noop, insertBefore:noop,
  getBoundingClientRect:()=>({width:0,height:0,top:0,left:0}), focus:noop, click:noop, closest:()=>null,
  getAttribute:()=>null, get innerHTML(){return ''}, set innerHTML(v){},
  get textContent(){return ''}, set textContent(v){}, parentNode:null};
const _mk = () => Object.create(_node);
function realBox(){ let html=''; return {get innerHTML(){return html}, set innerHTML(v){html=v},
  style:{}, classList:mkClassList(), querySelector:()=>null, querySelectorAll:()=>[],
  appendChild:noop, addEventListener:noop, closest:()=>null, getBoundingClientRect:()=>({width:0,height:0})} }
globalThis.__boxes = {rdbar: realBox(), view: realBox(), setBox: realBox()};
globalThis.document = {documentElement:{classList:mkClassList(),style:{},scrollHeight:0,clientHeight:0},
  body:{classList:mkClassList(),style:{},appendChild:noop}, head:{appendChild:noop},
  getElementById(id){ return globalThis.__boxes[id] || _mk() },
  querySelector:()=>null, querySelectorAll:()=>[], createElement:()=>_mk(), addEventListener:noop,
  cookie:'', readyState:'complete', title:''};
globalThis.window = globalThis;
globalThis.location = {href:'http://x/', pathname:'/', search:'', hash:'', reload:noop};
globalThis.__page = 'nodes';
globalThis.localStorage = {getItem:k=>(k==='tnl_page'?globalThis.__page:null), setItem:noop, removeItem:noop};
globalThis.matchMedia = () => ({matches:false, addEventListener:noop, addListener:noop});
globalThis.navigator = {userAgent:'node', language:'fa'};
globalThis.setInterval = () => 0;
globalThis.requestAnimationFrame = () => 0; globalThis.cancelAnimationFrame = noop;
globalThis.alert = noop; globalThis.confirm = () => true;
globalThis.getComputedStyle = () => ({getPropertyValue:()=>''});
globalThis.__RDY = %s;
globalThis.fetch = (u, o) => {
  const p = String(u).replace(/^\/api\//,'').split('?')[0];
  const d = (p === 'readiness') ? globalThis.__RDY : {ok:true};
  return Promise.resolve({ok:true, status:200, json:() => Promise.resolve(JSON.parse(JSON.stringify(d)))});
};
"""

EPILOGUE = r"""
setTimeout(() => {
  const out = {cur: cur, bar: globalThis.__boxes.rdbar.innerHTML};
  // and the switch back: once the panel IS ready, the same paint must clear the bar it drew.
  RDY = {agent:true, core:true, core_missing:[], core_version:'v1', ok:true};
  paintReady();
  out.barAfterFixed = globalThis.__boxes.rdbar.innerHTML;
  RDY = {agent:false, core:false, core_missing:['amd64','arm64'], core_version:'', ok:false};
  paintReady();
  out.barAfterBroken = globalThis.__boxes.rdbar.innerHTML;
  console.log('@@' + JSON.stringify(out));
  process.exit(0);
}, 300);
"""


def part_browser(m):
    print("== 4) the page lands on Settings while something is missing, and only while ==")
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", m.INDEX_HTML, re.S)
    js = max(blocks, key=len) if blocks else ""
    if "async function loadReadiness(" not in js:
        check("the readiness code is in the rendered page", False, "loadReadiness is missing")
        return
    cases = [
        ("nothing staged", {"agent": False, "core": False, "core_missing": ["amd64", "arm64"],
                            "core_version": "", "ok": False}, "settings"),
        ("only arm64 missing", {"agent": True, "core": False, "core_missing": ["arm64"],
                                "core_version": "v9.9.9", "ok": False}, "settings"),
        ("both staged", {"agent": True, "core": True, "core_missing": [], "core_version": "v9.9.9",
                         "ok": True}, "nodes"),
    ]
    with tempfile.TemporaryDirectory() as d:
        for label, rdy, want_page in cases:
            p = Path(d) / ("boot_%s.js" % want_page)
            p.write_text((PRELUDE % json.dumps(rdy)) + "\n" + js + "\n" + EPILOGUE, encoding="utf-8")
            try:
                r = subprocess.run(["node", str(p)], capture_output=True, text=True,
                                   encoding="utf-8", timeout=60)
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                check("[%s] the page's own script ran" % label, False, str(e))
                continue
            line = next((l for l in (r.stdout or "").splitlines() if l.startswith("@@")), "")
            if not line:
                check("[%s] the page's own script ran" % label, False, (r.stderr or r.stdout or "")[:300])
                continue
            got = json.loads(line[2:])
            check("[%s] the stored page was «nodes»; load lands on «%s»" % (label, want_page),
                  got["cur"] == want_page, got["cur"])
            if rdy["ok"]:
                check("[%s] no warning bar at all" % label, got["bar"] == "", got["bar"][:120])
            else:
                check("[%s] the bar names what is missing" % label, "rdbar" in got["bar"], got["bar"][:120])
                said_agent = "ایجنتِ نود روی پنل نیست" in got["bar"]
                check("[%s] ...and only what is missing (agent mentioned=%s)" % (label, not rdy["agent"]),
                      said_agent == (not rdy["agent"]), got["bar"][:200])
                if rdy["core_version"]:
                    check("[%s] a partial stage names the arch" % label, "arm64" in got["bar"],
                          got["bar"][:200])
            check("[%s] the bar clears once both are staged" % label, got["barAfterFixed"] == "",
                  got["barAfterFixed"][:120])
            check("[%s] ...and comes back if they go away" % label, "rdbar" in got["barAfterBroken"],
                  got["barAfterBroken"][:120])


def main():
    state = tempfile.mkdtemp(prefix="tnl-readiness-")
    try:
        m = load_panel(state)
        part_readiness(m)
        part_gate(m)
        part_stage_report(m)
        part_browser(m)
    finally:
        shutil.rmtree(state, ignore_errors=True)
    print()
    if FAILED:
        print("%d FAILED:" % len(FAILED))
        for f in FAILED:
            print("  - " + f)
        return 1
    print("the panel will not start what it cannot finish, and says so first.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
