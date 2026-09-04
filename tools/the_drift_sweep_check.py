#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: the 2026-09-04 audit's remaining drift, closed in one sweep.

Each section is one defect from that audit, and each drives the real code -- the page's own functions
under node, or the real API on a temp registry -- rather than reading a helper. The comment above each
says what the operator saw.

    python3 tools/the_drift_sweep_check.py
"""
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

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
fails = []


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "  -- %r" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel(state=None, tag="a"):
    spec = importlib.util.spec_from_file_location("tnl_sweep_" + tag, PANEL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    if state:
        root = m.CENTRAL_DIR
        for k in dir(m):
            v = getattr(m, k)
            if isinstance(v, str) and v.startswith(root):
                setattr(m, k, os.path.join(state, os.path.relpath(v, root)))
        m.CENTRAL_DIR = state
    return m


def has(js, *names):
    """A section whose subject does not exist yet must FAIL, not raise: a traceback is not a verdict."""
    missing = [n for n in names if ("function %s(" % n) not in js]
    if missing:
        check(False, "the page has no %s -- this defect is not fixed at all" % ", ".join(missing))
    return not missing


def grab(js, name):
    i = js.index("function %s(" % name)
    depth, j, started = 0, i, False
    while j < len(js):
        if js[j] == "{":
            depth += 1
            started = True
        elif js[j] == "}":
            depth -= 1
            if started and depth == 0:
                return js[i:j + 1]
        j += 1
    raise SystemExit("could not read %s out of the page" % name)


def run_js(body):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(body)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        raise AssertionError("node could not run the page code:\n" + (out.stderr or "")[:1200])
    return json.loads(out.stdout.strip().splitlines()[-1])


SHIM = """
var _F={},SEL={},SSI={},SSCB={};
function _mk(id){return {id:id,value:'',style:{},innerHTML:'',
  classList:{toggle:function(){},add:function(){},remove:function(){}}}}
function el(id){return _F[id]||null}
function mkEl(id){_F[id]=_mk(id);return _F[id]}
function esc(x){return String(x)}
function T(k){return k}
function ic(n){return ''}
function num(x){x=+x;return isFinite(x)?x:0}
function ssVal(k){return SEL[k]||''}
var _ENUMS=__ENUMS__;
var _ERR=null;
function formErr(m,t){_ERR=t}
"""


def _enums(js):
    return re.search(r"var _ENUMS=(\{.*?\});", js, re.S).group(1)


def sec_edge_port(m):
    js, enums = m.INDEX_HTML, _enums(m.INDEX_HTML)
    print("== the CDN edge port: the form takes what the backend takes, and nothing else ==")
    if not has(js, "edgePortsOK", "poolValid"):
        return
    body = SHIM.replace("__ENUMS__", enums) + "\n"
    body += "function poolGet(p){return {tls:_TLS}}\n"
    body += "var _ip4Re=/^(\\d{1,3}\\.){3}\\d{1,3}$/, _domRe=/^[A-Za-z0-9.-]{1,253}$/;\n"
    body += grab(js, "edgePortsOK") + "\n" + grab(js, "poolValid") + "\n"
    body += """
var OUT={tls:{},plain:{}};
[[true,'tls'],[false,'plain']].forEach(function(p){
  _TLS=p[0];
  [443,2053,8443,80,8080,1234,65535,0].forEach(function(port){
    OUT[p[1]][port]=poolValid('ip','104.16.0.1:'+port);
  });
});
console.log(JSON.stringify(OUT));
"""
    body = "var _TLS=true;\n" + body
    got = run_js(body)
    tls_ok = [int(k) for k, v in got["tls"].items() if v]
    plain_ok = [int(k) for k, v in got["plain"].items() if v]
    check(set(tls_ok) <= set(m._EDGE_TLS_PORTS),
          "with wss on, the form accepts only the backend's HTTPS edge ports", tls_ok)
    check(set(plain_ok) <= set(m._EDGE_PLAIN_PORTS),
          "with wss off, only the backend's HTTP ones", plain_ok)
    check(443 in tls_ok and 1234 not in tls_ok,
          "443 in, 1234 out -- the old form accepted every port from 1 to 65535",
          {"443": 443 in tls_ok, "1234": 1234 in tls_ok})

def sec_rotation(m):
    js, enums = m.INDEX_HTML, _enums(m.INDEX_HTML)
    print("== one-sided IP rotation: the form stops refusing what the backend accepts ==")
    body = SHIM.replace("__ENUMS__", enums) + "\n"
    body += "var _rotS={};\n" + grab(js, "rotSt") + "\n"
    body += "function rotCount(px,side){return (side=='a')?_A:_B}\n"
    body += grab(js, "rotValidate") + "\n"
    body += """
var OUT={};
[[2,1,'two on A, one on B'],[1,2,'one on A, two on B'],[2,2,'two on both'],[1,1,'one on each']]
 .forEach(function(c){ _A=c[0]; _B=c[1];
   var st=rotSt('ee_'); st.on=true; st.aIps=['a1','a2']; st.bIps=['b1','b2'];
   OUT[c[2]] = rotValidate('ee_')===null; });
console.log(JSON.stringify(OUT));
"""
    body = "var _A=0,_B=0;\n" + body
    got = run_js(body)
    check(got["two on A, one on B"], "two picks on ONE side is enough -- the backend's own rule", got)
    check(got["one on A, two on B"], "and the other way round", got)
    check(got["two on both"], "two on both is still fine", got)
    check(not got["one on each"], "one on each is still refused -- there is nothing to rotate", got)

def sec_cover(m):
    js, enums = m.INDEX_HTML, _enums(m.INDEX_HTML)
    print("== TLS cover is not offered when the cipher is off ==")
    body = SHIM.replace("__ENUMS__", enums) + "\n"
    body += "var _corS={Tr:'tcp',Cover:true};\nfunction corSniVis(){}\n"
    body += grab(js, "corCoverGate") + "\n"
    body += """
var OUT={};
mkEl('e_coverrow'); mkEl('e_cover');
SEL['e_cipher']='aes-256-gcm'; _corS.Tr='tcp'; _corS.Cover=true; corCoverGate();
OUT.encrypted_tcp = {shown:_F['e_coverrow'].style.display!=='none', on:_corS.Cover};
SEL['e_cipher']='none'; _corS.Cover=true; corCoverGate();
OUT.cipher_none = {shown:_F['e_coverrow'].style.display!=='none', on:_corS.Cover};
console.log(JSON.stringify(OUT));
"""
    got = run_js(body)
    check(got["encrypted_tcp"]["shown"], "on an encrypted TCP tunnel the switch is there", got)
    check(not got["cipher_none"]["shown"] and got["cipher_none"]["on"] is False,
          "with the cipher off it is hidden AND forced off -- camouflage over cleartext is what the "
          "core refuses, so the form stops offering it", got)

def sec_node_name(m):
    js, enums = m.INDEX_HTML, _enums(m.INDEX_HTML)
    print("== a Persian node name is refused by the box, not by the server ==")
    if not has(js, "nodeNameOK"):
        return
    body = SHIM.replace("__ENUMS__", enums) + "\n"
    body += grab(js, "nodeNameOK") + "\n"
    body += ("var _NODENAME_RE=" + re.search(r"var _NODENAME_RE=(/.*?/);", js).group(1) + ";\n")
    body += """
var OUT={};
['frankfurt-1','de 02','a_b.c','نودِ آلمان','آلمان','de-\\u06f2'].forEach(function(n){OUT[n]=nodeNameOK(n)});
OUT['(41 chars)'] = nodeNameOK(new Array(42).join('a'));
console.log(JSON.stringify(OUT));
"""
    got = run_js(body)
    check(got["frankfurt-1"] and got["de 02"] and got["a_b.c"], "ordinary names still pass", got)
    check(not got["نودِ آلمان"] and not got["آلمان"],
          "a Persian name is refused up front -- «اسم فارسی اصلا نباید بشه تنظیم کرد»", got)
    check(not got["(41 chars)"], "and the 40-character limit is the form's too", got)

def sec_small_js(m):
    js = m.INDEX_HTML
    print("== the proxy picker reads the field the API actually sends ==")
    check("sub:p.addr" in js and "sub:p.url" not in js,
          "p.addr, not p.url -- the subtitle was empty on every proxy for as long as it existed")

    print("== the palette lands on the page that holds the tunnel it named ==")
    pal = js[js.index("PALDATA.tuns"):] if "PALDATA.tuns" in js else js
    act = re.search(r"act:function\(\)\{var pg=\(l\.type=='core'\)\?'core':'tunnels';cur=pg;QRY\[pg\]=l\.name", js)
    check(bool(act),
          "a core tunnel jumps to the core page, and the filter is the tunnel's own name")


def backend_section():
    print("== the tunnel search knows a tunnel's own name ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "fleet")
        m.save_json(m.NODES_FILE, [{"id": "na", "name": "A", "host": "1.1.1.1", "port": 8099, "token": "t" * 20},
                                   {"id": "nb", "name": "B", "host": "2.2.2.2", "port": 8099, "token": "t" * 20}])
        m.save_json(m.LINKS_FILE, [{"id": "L1", "name": "core7", "type": "core", "tunnel_id": 7,
                                    "subnet": "192.168.7.0/24", "a_node": "na", "a_name": "A",
                                    "a_ip": "1.1.1.1", "b_node": "nb", "b_name": "B", "b_ip": "2.2.2.2"}])
        m._ensure_cached = lambda *a, **k: None
        m._cached_list = lambda nid: {}
        m._cached_ping = lambda nid: {}
        m.link_drift = lambda i: False
        m.rb_last = lambda i: None
        got = m.api_fleet({"kind": "core", "q": "core7"})
        check([L["id"] for L in got["links"]] == ["L1"],
              "searching for «core7» finds core7 -- the palette set exactly this filter and the "
              "search had never looked at `name`", got.get("total"))

    print("== an empty numeric tuning box is refused, not skipped with a green toast ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "tune")
        try:
            m.api_settings_set({"tuning": {"min_liveness_secs": ""}})
            err = None
        except Exception as e:                                    # noqa: BLE001
            err = str(e)
        check(bool(err), "clearing the box raises", err)
        check(err and "خالی" in err, "and the message says the box is empty", err)
        stored = (m.get_settings().get("tuning") or {}).get("min_liveness_secs")
        check(stored == m._TUNING_DEFAULTS["min_liveness_secs"],
              "nothing was written", stored)

    print("== the enable/disable toggle reports a side that refused ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "tog")
        m.save_json(m.NODES_FILE, [{"id": "na", "name": "A", "host": "1.1.1.1", "port": 8099, "token": "t" * 20},
                                   {"id": "nb", "name": "B", "host": "2.2.2.2", "port": 8099, "token": "t" * 20}])
        m.save_json(m.LINKS_FILE, [{"id": "L1", "name": "core1", "type": "core", "tunnel_id": 1,
                                    "subnet": "192.168.1.0/24", "a_node": "na", "a_name": "A",
                                    "a_ip": "1.1.1.1", "b_node": "nb", "b_name": "B", "b_ip": "2.2.2.2"}])
        m._refresh_cache = lambda *a, **k: None
        m.node_call = lambda n, *a, **k: {"ok": n["id"] == "na"}
        r = m.api_link_toggle({"id": "L1", "enabled": False})
        check(r.get("both") is False, "both=False when one side refused", r.get("both"))
        check(r.get("failed") == ["B"], "and it names the side", r.get("failed"))
        check(bool(r.get("msg")), "with a sentence the card can show", r.get("msg"))
        m.node_call = lambda n, *a, **k: {"ok": True}
        r = m.api_link_toggle({"id": "L1", "enabled": True})
        check(r.get("both") is True and not r.get("msg"), "and stays quiet when both answered", r)

    print("== the panel's own download proxy counts as a user of that proxy ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "px")
        m.save_json(m.NODES_FILE, [])
        m.save_json(m.SETTINGS_FILE, {"dl_proxy_on": True, "dl_proxy_id": "px1"})
        users = m._proxy_users()
        check("px1" in users and users["px1"],
              "deleting it is no longer offered as if nothing used it -- the panel's own updates go "
              "through it", users)

    print("== clearing the port box means the default, which is what the label promises ==")
    for label, ttype, want in (("vxlan", "vxlan", 4789),):
        with tempfile.TemporaryDirectory() as st:
            m = load_panel(st, "port" + label)
            m.save_json(m.NODES_FILE, [{"id": "na", "name": "A", "host": "1.1.1.1", "port": 8099, "token": "t" * 20},
                                       {"id": "nb", "name": "B", "host": "2.2.2.2", "port": 8099, "token": "t" * 20}])
            m.save_json(m.LINKS_FILE, [{"id": "L1", "name": "native1", "type": ttype, "tunnel_id": 1,
                                        "subnet": "192.168.1.0/24", "port": 5555,
                                        "a_node": "na", "a_name": "A", "a_ip": "1.1.1.1",
                                        "b_node": "nb", "b_name": "B", "b_ip": "2.2.2.2"}])
            sent = {}
            m._ping_both = lambda A, B: ({"ok": True, "ips": {"e": ["1.1.1.1"]}},
                                         {"ok": True, "ips": {"e": ["2.2.2.2"]}})
            m._flat_ips = lambda p: list((p.get("ips") or {}).get("e") or [])
            m._node_tunnel = lambda n, b, *a, **k: (sent.update({n["id"]: b}) or {"ok": True})
            m.node_call = lambda *a, **k: {"ok": True}
            m.act_step = lambda *a, **k: None
            m.act_done = lambda *a, **k: None
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            import act_wait
            act_wait.raising(m, lambda: m.api_edit_link(
                {"id": "L1", "type": ttype, "subnet": "192.168.1.0/24", "port": ""}))
            got = next((x for x in m.load_links() if x["id"] == "L1"), {}).get("port")
            check(got == want,
                  "%s: an EMPTY box gives %d, not the port it already had" % (label, want), got)


def push_section():
    print("== pause actually holds the fleet update ==")
    with tempfile.TemporaryDirectory() as st:
        m = load_panel(st, "pause")
        if not hasattr(m, "_push_paused"):
            check(False, "the panel has no _push_paused -- pause can only skip nodes still in the "
                         "queue, and with PUSH_CAP=%d there are none" % m.PUSH_CAP)
            return
        nodes = [{"id": "n%d" % i, "name": "N%d" % i} for i in range(4)]
        done = {n["id"]: 0 for n in nodes}

        def one(jid, nid, plan):
            for i, step in enumerate(plan):
                if i and m._push_paused(jid):
                    m._push_set(jid, nid, state="run", step="paused", si=i + 1, sn=len(plan))
                    while m._push_paused(jid):
                        if m._push_cancelled(jid):
                            m._push_set(jid, nid, state="skip")
                            return
                        time.sleep(0.05)
                m._push_set(jid, nid, state="run", step=step[0], si=i + 1, sn=len(plan))
                done[nid] += 1
                time.sleep(0.15)
            m._push_set(jid, nid, state="ok", pct=100)

        m._push_one = one
        jid = m._push_start("core", nodes,
                            [("check", 1, 1, 1, None), ("deliver", 1, 1, 1, None), ("install", 1, 1, 1, None)])
        time.sleep(0.2)
        m.api_push_pause({"job": m.PUSH_ALL, "paused": True})
        frozen = dict(done)
        time.sleep(0.7)
        check(frozen == done, "no node advanced a step while paused", {"at pause": frozen, "later": dict(done)})
        check(all(v["step"] == "paused" for v in m._push_jobs[jid]["nodes"].values()),
              "and every card says so", {k: v["step"] for k, v in m._push_jobs[jid]["nodes"].items()})
        m.api_push_pause({"job": m.PUSH_ALL, "paused": False})
        for _ in range(120):
            if m._push_jobs[jid]["done"]:
                break
            time.sleep(0.05)
        check(m._push_jobs[jid]["done"], "resume carries it to the end")
        check(all(v["state"] == "ok" for v in m._push_jobs[jid]["nodes"].values()),
              "with every node finished", {k: v["state"] for k, v in m._push_jobs[jid]["nodes"].items()})
        check("ups_paused" in m.INDEX_HTML, "and the word the card shows is defined")


def label_section(m):
    js = m.INDEX_HTML
    print("== the labels say what the code does ==")
    check("خودکار از شناسه" not in js,
          "the port label no longer promises a number derived from the tunnel id -- it has been "
          "DRAWN from a band since 2026-09-03")
    check("__LOGMAX__" not in js and str(m.EVENTS_MAX) in js,
          "the log subtitle names its second bound, the %d-event cap" % m.EVENTS_MAX)
    check("set_x_revive:" in js,
          "the revive row has its explanation, instead of rendering the raw key")
    check("conn_off:" in js,
          "a check on a switched-off tunnel has a sentence of its own")


def main():
    m = load_panel()
    for sec in (sec_edge_port, sec_rotation, sec_cover, sec_node_name, sec_small_js):
        try:
            sec(m)
        except Exception as e:                                    # noqa: BLE001
            check(False, "%s could not run against this page: %s" % (sec.__name__, str(e)[:120]))
    for sec in (backend_section, push_section):
        try:
            sec()
        except Exception as e:                                    # noqa: BLE001
            check(False, "%s could not run: %s" % (sec.__name__, str(e)[:140]))
    try:
        label_section(m)
    except Exception as e:                                        # noqa: BLE001
        check(False, "label_section could not run: %s" % str(e)[:140])
    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
