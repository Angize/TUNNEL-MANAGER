#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guard: editing a core tunnel does not move it to another address of its own node.

The IP picker in the core edit modal was seeded with `ips[0]` -- the node's FIRST address -- and
`pickedIP` returned whatever the picker held, throwing the `stored` argument it was given away. So on a
node with more than one routable IPv4, opening a tunnel that lives on the second address and changing
only the cipher submitted the first one. The backend accepts an explicit a_ip, so its own
"keep L['a_ip']" fallback never got a chance to run: the tunnel was rebuilt on a different address at
both ends, and nothing on screen said so.

The reverse defect is checked too, because the fix could introduce it: with a SINGLE address the field
is a disabled input showing ips[0], and the old code still submitted the stored value -- so a drifted
tunnel displayed one address and submitted another (a dead one, which the backend then refused). It now
submits nothing and lets the backend pick, which is what the disabled field already shows.

Two things the fix must NOT break, and both are driven here:
  * the operator's own pick inside the open modal survives a re-render (ceSetSrv and the rotation
    toggle both call renderRotIps again), and
  * a pick left over from the PREVIOUS modal does not outrank the tunnel now being edited.

The browser half runs the page's real functions under node. The backend half drives the real
api_edit_link and reads what was persisted, so the claim is about the whole chain and not a helper.

    python3 tools/an_edit_keeps_the_tunnel_where_it_is_check.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import act_wait                                                   # noqa: E402
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
PANEL = ROOT / "tnl-central.py"
fails = []

A_IPS = ["203.0.113.5", "203.0.113.77"]
B_IPS = ["198.51.100.9"]


def check(ok, msg, got=None):
    print(("  ok   " if ok else " FAIL  ") + msg + ("" if ok or got is None else "  -- %r" % (got,)))
    if not ok:
        fails.append(msg)


def load_panel(state=None, tag="a"):
    spec = importlib.util.spec_from_file_location("tnl_edit_" + tag, PANEL)
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


SHIM = """
var _F={},SEL={},SSI={},SSCB={};
function _mk(id){return {id:id,value:'',style:{},innerHTML:'',
  classList:{toggle:function(){},add:function(){},remove:function(){}}}}
function el(id){return _F[id]||null}
function mkEl(id){_F[id]=_mk(id);return _F[id]}
function esc(x){return String(x)}
function T(k){return k}
function ic(n){return ''}
function _ssph(p){return p||''}
var _corS={Srv:'a'},_eeS={Srv:'a',Lid:''},_rotS={};
var FLEET=[];
function nodeIps(){return []}
"""

GRAB = ("ssHTML", "ssVal", "ipItems", "ipSeed", "ipField", "rotSt", "rotFirstSel",
        "pickedIP", "ceStoredIP", "ceSeedGate", "renderRotIps", "rotPoolHTML")

DRIVER = """
var OUT=[];
function open_modal(lid, aIps, storedA){
  _F={}; mkEl('ee_aip'); mkEl('ee_bip');
  _eeS.Lid=lid; FLEET=[{id:lid,a_ip:storedA,b_ip:'198.51.100.9'}];
  var st=rotSt('ee_'); st.on=false; st.aIps=aIps; st.bIps=['198.51.100.9']; st.aSel={}; st.bSel={};
  renderRotIps('ee_');
  if(SEL['ee_aip_sel']!==undefined) mkEl('ssb_ee_aip_sel');
}
function read(storedA, aIps){
  return {shown:(SEL['ee_aip_sel']!==undefined)?SEL['ee_aip_sel']:aIps[0],
          sent:pickedIP('ee_','a',storedA)};
}
function one(label, aIps, storedA){
  SEL={}; open_modal('L1',aIps,storedA);
  var r=read(storedA,aIps); r.stored=storedA; OUT.push([label,r]);
}
one('second_of_two', ['203.0.113.5','203.0.113.77'], '203.0.113.77');
one('third_of_three',['a1','a2','203.0.113.77'],     '203.0.113.77');
one('first_of_two',  ['203.0.113.77','203.0.113.5'], '203.0.113.77');
one('drifted_single',['203.0.113.5'],                '203.0.113.77');

SEL={}; open_modal('L1',['x1','x2'],'x2'); SEL['ee_aip_sel']='x1';
open_modal('L2',['x1','x2'],'x2');
var r=read('x2',['x1','x2']); r.stored='x2'; OUT.push(['leftover_from_last_modal', r]);

SEL={}; open_modal('L3',['y1','y2'],'y2'); SEL['ee_aip_sel']='y1';
renderRotIps('ee_');
var r2=read('y2',['y1','y2']); r2.stored='y2'; OUT.push(['operator_pick_survives_rerender', r2]);
console.log(JSON.stringify(OUT));
"""


def browser_half():
    m = load_panel()
    js = m.INDEX_HTML
    missing = [n for n in GRAB if ("function %s(" % n) not in js]
    if missing:
        check(False, "the page has no %s -- the picker cannot be seeded with the tunnel's own "
                     "address, so it can only open on ips[0]" % ", ".join(missing))
        return
    body = SHIM + "\n" + "\n".join(grab(js, n) for n in GRAB) + DRIVER
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as f:
        f.write(body)
        path = f.name
    out = subprocess.run(["node", path], capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print("FAIL: node could not run the form code:\n" + (out.stderr or "")[:1500])
        fails.append("the browser half could not run")
        return
    rows = dict(json.loads(out.stdout.strip().splitlines()[-1]))

    print("== the picker opens on the address the tunnel holds, and submits it ==")
    for key, label in (("second_of_two", "the second of two node IPs"),
                       ("third_of_three", "the third of three node IPs"),
                       ("first_of_two", "the first of two (the case that always worked)")):
        r = rows[key]
        check(r["shown"] == r["stored"], "%s: the form SHOWS it" % label, r)
        check(r["sent"] == r["stored"], "%s: and SUBMITS it" % label, r)

    print("== a single node IP: what is shown is what is submitted ==")
    r = rows["drifted_single"]
    check(r["sent"] == "",
          "a drifted tunnel submits no address, so the backend picks the live one", r)

    print("== the fix does not break the two things around it ==")
    r = rows["leftover_from_last_modal"]
    check(r["shown"] == "x2" and r["sent"] == "x2",
          "a pick left over from the previous modal does not outrank this tunnel", r)
    r = rows["operator_pick_survives_rerender"]
    check(r["shown"] == "y1" and r["sent"] == "y1",
          "the operator's own pick survives a re-render inside the open modal", r)


def one_edit(tag, extra):
    """One api_edit_link on its own registry. Returns the a_ip that was persisted.

    A fresh state directory per case, because api_edit_link leaves a background writer holding
    links.json on Windows and the next save_json into the same directory then fails on the rename."""
    with tempfile.TemporaryDirectory() as state:
        m = load_panel(state, tag)
        m.save_json(m.NODES_FILE, [
            {"id": "na", "name": "A", "host": A_IPS[0], "port": 8099, "token": "t" * 20},
            {"id": "nb", "name": "B", "host": B_IPS[0], "port": 8099, "token": "t" * 20}])
        m.save_json(m.LINKS_FILE, [{
            "id": "L1", "name": "core1", "type": "core", "tunnel_id": 1,
            "subnet": "192.168.1.0/24", "transport": "udp", "cipher": "aes-256-gcm",
            "psk": "0" * 32, "port": 20001, "server_side": "a",
            "a_node": "na", "a_name": "A", "a_ip": A_IPS[1],
            "b_node": "nb", "b_name": "B", "b_ip": B_IPS[0]}])
        m._ping_both = lambda A, B: ({"ok": True, "ips": {"eth0": A_IPS}},
                                     {"ok": True, "ips": {"eth0": B_IPS}})
        m._flat_ips = lambda p: (A_IPS if (p.get("ips") or {}).get("eth0") == A_IPS else B_IPS)
        calls = []
        m.node_call = lambda n, op, *a, **k: (calls.append((n["id"], op, None)) or {"ok": True})
        m._node_tunnel = lambda n, b, *a, **k: (calls.append((n["id"], "tunnel", b.get("self_ip")))
                                                or {"ok": True, "tunnel_ip": "192.168.1.1"})

        d = {"id": "L1", "type": "core", "cipher": "aes-256-gcm", "transport": "udp",
             "server_side": "a"}
        d.update(extra)
        # api_edit_link answers with an action KEY and does the work on a panel thread, so reading
        # links.json straight after the call reads the registry BEFORE the edit -- which is how two of
        # these three cases first passed while the edit had not run at all.
        try:
            act_wait.raising(m, lambda: m.api_edit_link(d))
            err = None
        except Exception as e:                                    # noqa: BLE001
            err = str(e)
        return err, next((x for x in m.load_links() if x["id"] == "L1"), {}).get("a_ip"), calls


def backend_half():
    print("== and the backend keeps it there when the browser sends nothing ==")
    for tag, label, extra, want in (
            ("b1", "no a_ip at all", {}, A_IPS[1]),
            ("b2", "the address it already has", {"a_ip": A_IPS[1]}, A_IPS[1]),
            ("b3", "a deliberate move", {"a_ip": A_IPS[0]}, A_IPS[0])):
        err, got, calls = one_edit(tag, extra)
        check(err is None, "%-28s -> the edit actually ran" % label, err)
        sent = [c[2] for c in calls if c[1] == "tunnel" and c[0] == "na"]
        check(sent == [want],
              "%-28s -> node A is told self_ip=%s" % (label, want), sent)
        check(got == want, "%-28s -> and %s is what is stored" % (label, want), got)


def main():
    browser_half()
    backend_half()
    print()
    if fails:
        print("%d failure(s)." % len(fails))
        return 1
    print("all good.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
