#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The spoof egress test must probe the IPs the TUNNEL will use, on both ends.

The button's own text promises an answer "on THIS pair, in the direction the tunnel will use", and
that promise is the whole reason to trust it: uRPF and decoy routing are per-IP on these providers,
so a probe aimed somewhere else answers a different question. A multi-IP node can come back green on
its management address while the tunnel's chosen address is filtered — or the reverse.

`host` may also legitimately be a HOSTNAME (api_node_add accepts one), while a_ip/b_ip always come
from the node's live IP list — so aiming at `host` is an unconditional dead end for such a node, even
though the tunnel itself builds perfectly.

This drives the REAL handler with the node calls stubbed, and also checks the browser half: the picked
IPs have to be in the request body, or the server can only ever guess.

    python3 tools/spoof_egress_probe_check.py
"""
import argparse
import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

NODES = {
    "na": {"id": "na", "name": "DE", "host": "91.107.190.159"},
    "nb": {"id": "nb", "name": "IR", "host": "94.183.210.135"},
    "nh": {"id": "nh", "name": "BY-HOSTNAME", "host": "de.example.net"},
}
PINGS = {
    "na": {"ok": True, "ips": {"eth0": ["91.107.190.159", "91.107.190.200"]}},
    "nb": {"ok": True, "ips": {"eth0": ["94.183.210.135", "94.183.210.99"]}},
    "nh": {"ok": True, "ips": {"eth0": ["203.0.113.77", "203.0.113.78"]}},
}


def load_panel(path):
    spec = importlib.util.spec_from_file_location("tnl_central", str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Enough of a DOM for the button: the shared mini-DOM plus the three accessors it touches, and an id
# lookup that really walks the tree.
_EXTRA = r"""
Object.defineProperty(El.prototype, 'value', {
  get(){ return this._val !== undefined ? this._val : (this.getAttribute('value') || ''); },
  set(v){ this._val = String(v); } });
Object.defineProperty(El.prototype, 'style', { get(){ if(!this._s) this._s = {}; return this._s; } });
Object.defineProperty(El.prototype, 'className', {
  get(){ return this.getAttribute('class') || ''; },
  set(v){ this.setAttribute('class', String(v)); } });
const __root = document.createElement('div');
document.getElementById = function(id){
  const walk = n => {
    if (n.nodeType === 1 && n.getAttribute('id') === id) return n;
    for (const k of n.nodes || []) { const hit = walk(k); if (hit) return hit; }
    return null;
  };
  return walk(__root);
};
"""

# Both forms, each with rotation on and a pick that is NOT the first address, so a probe that fell
# back to a default instead of reading the pick would look different.
_DRIVE = r"""
const out = {};
const PICK = {e_:  {a:'91.107.190.200', b:'94.183.210.99'},
              ee_: {a:'91.107.190.201', b:'94.183.210.98'}};
async function press(px){
  const r = {want_a: PICK[px].a, want_b: PICK[px].b};
  try {
    __root.innerHTML = '<div id="' + px + 'egr"></div><button id="' + px + 'egrbtn"></button>'
                     + '<input id="' + px + 'rawproto" value="253">';
    FLEET = [{id:'t1', a_node:'na', b_node:'nb', a_ip:'0.0.0.0', b_ip:'0.0.0.0'}];
    _eeS.Lid = 't1'; _eeS.NodesArr = ['na','nb']; _eeS.Srv = 'a';
    _corS.Srv = 'a';
    SSI['e_a'] = [{v:'na'}]; SSI['e_b'] = [{v:'nb'}]; SEL['e_a'] = 'na'; SEL['e_b'] = 'nb';
    _rotS[px] = {on:true, secs:600,
                 aIps:['1.1.1.1', PICK[px].a], bIps:['2.2.2.2', PICK[px].b],
                 aSel:{[PICK[px].a]:true}, bSel:{[PICK[px].b]:true}};
    post = (ep, body) => { r.sent = {ep, body};
      return Promise.resolve({ok:true, d:{ok:true, sender:'na', receiver:'nb', proto:253,
                                          baseline:true, src:true}}); };
    await spoofEgressTest(px);
  } catch (e) { r.err = String((e && e.message) || e); }
  out[px === 'e_' ? 'create' : 'edit'] = r;
}
press('e_').then(() => press('ee_')).then(() => console.log('@@' + JSON.stringify(out)),
  e => console.log('@@' + JSON.stringify({create:{err:String(e && e.message || e)}})));
"""


def drive_the_button(index_html):
    """Press the egress button on both forms and hand back the request each one sent."""
    here = Path(__file__).resolve().parent
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))
    from list_diff_keeps_untouched_rows_check import PRELUDE
    node = shutil.which("node")
    if not node:
        raise SystemExit("FAIL  no `node` on PATH — a check that cannot run must not report success")
    js = max(re.findall(r"<script[^>]*>(.*?)</script>", index_html, re.S), key=len)
    with tempfile.TemporaryDirectory() as d:
        f = Path(d) / "drive.mjs"
        f.write_text(PRELUDE + _EXTRA + chr(10) + js + chr(10) + _DRIVE, encoding="utf-8")
        r = subprocess.run([node, str(f)], capture_output=True, text=True, timeout=180,
                           encoding="utf-8", errors="replace")
    line = next((l for l in (r.stdout or "").splitlines() if l.startswith("@@")), None)
    if not line:
        raise SystemExit("FAIL  the egress-button harness produced no result"
                         + chr(10) + (r.stdout or "") + (r.stderr or ""))
    return json.loads(line[2:])


def wire(P, calls):
    P.get_node = lambda i: NODES.get(i)
    P._cached_ping = lambda nid: PINGS.get(nid, {})

    def node_call(n, path, method, body=None, timeout=None):
        calls.append((n["name"], path, dict(body or {})))
        return {
            "spoof-egress-listen": {"ok": True, "token": "tok"},
            "spoof-egress-send": {"ok": True},
            "spoof-egress-result": {"done": True, "saw": {"baseline": True, "src": False, "dst": False},
                                    "observed": {}},
            "ping": PINGS.get(n["id"], {}),
        }.get(path, {})

    P.node_call = node_call
    P.time.sleep = lambda *_: None


def probe(P, calls, req):
    calls.clear()
    res = P.api_spoof_egress_probe(req)
    send = [c for c in calls if c[1] == "spoof-egress-send"]
    return res, (send[0][2] if send else {})


def main():
    here = Path(__file__).resolve()
    ap = argparse.ArgumentParser()
    ap.add_argument("--panel", default=here.parent.parent / "tnl-central.py")
    a = ap.parse_args()

    P = load_panel(a.panel)
    calls = []
    wire(P, calls)
    failures = []

    # (label, request, expected peer, expected real_src). server_side names the RECEIVER, so flipping
    # it must flip which end is probed and which end sources the baseline.
    cases = [
        ("operator picked the second IP on each node, srv=a",
         {"a_node": "na", "b_node": "nb", "server_side": "a", "proto": 58,
          "a_ip": "91.107.190.200", "b_ip": "94.183.210.99"},
         "91.107.190.200", "94.183.210.99"),
        ("same picks, srv=b — the direction flips",
         {"a_node": "na", "b_node": "nb", "server_side": "b", "proto": 58,
          "a_ip": "91.107.190.200", "b_ip": "94.183.210.99"},
         "94.183.210.99", "91.107.190.200"),
        ("no explicit pick — the node's first live IP",
         {"a_node": "na", "b_node": "nb", "server_side": "a", "proto": 58},
         "91.107.190.159", "94.183.210.135"),
        ("a pick that is not on the node — ignored, not trusted",
         {"a_node": "na", "b_node": "nb", "server_side": "a", "proto": 58, "a_ip": "8.8.8.8"},
         "91.107.190.159", "94.183.210.135"),
        ("receiver registered by HOSTNAME — must still run",
         {"a_node": "nh", "b_node": "nb", "server_side": "a", "proto": 58},
         "203.0.113.77", "94.183.210.135"),
    ]
    for label, req, want_peer, want_src in cases:
        res, body = probe(P, calls, req)
        if not res.get("ok"):
            failures.append("[%s] the probe refused to run: %r" % (label, res.get("error")))
            continue
        if body.get("peer") != want_peer:
            failures.append("[%s] probed peer=%r, want %r — per-IP filtering means a different address "
                            "is a different question" % (label, body.get("peer"), want_peer))
        if body.get("real_src") != want_src:
            failures.append("[%s] real_src=%r, want %r — the baseline has to LEAVE from the tunnel's own "
                            "IP too, not just arrive at it" % (label, body.get("real_src"), want_src))
        print("  ok  %-52s peer=%s src=%s" % (label, want_peer, want_src))

    # The browser half: the server can only aim correctly if the form sends what it picked, and the
    # picks must come from the same helper the create/edit submits use. Read the DECODED INDEX_HTML.
    js = getattr(P, "INDEX_HTML", "")
    if "<script" not in js:
        failures.append("INDEX_HTML did not decode to anything with a <script> in it — this check "
                        "cannot read its subject, so it must not report success")
    else:
        # That the SUBMIT reuses the same helper is a claim about shape, and stays a text check.
        for want, what in (
            ("function pickedIP(px,side,stored)", "one definition of which IP a form picked"),
            ("var aip=pickedIP('e_','a','');if(aip)body.a_ip=aip;", "the create submit shares the helper"),
            ("var aip=pickedIP('ee_','a',l.a_ip||'');if(aip)body.a_ip=aip;", "the edit submit shares it"),
        ):
            if want not in js:
                failures.append("browser JS: %s is missing (or the code moved and this check went "
                                "blind): %r not found" % (what, want))

        # That the PROBE carries them is a claim about behaviour, and a text check cannot make it.
        # It used to be asserted by looking for the literal `a_ip:ctx.aip||'',b_ip:ctx.bip||''` --
        # which was present, and wrong: spoofFormCtx returned the b address under the key `bare`,
        # nothing ever produced `bip`, and every probe went out with an empty b_ip on both the create
        # and the edit path. The guard was reading the typo and calling it a pass. So press the button
        # for real and read the request instead.
        for label, res in sorted(drive_the_button(js).items()):
            if res.get("err"):
                failures.append("the %s form's egress button threw: %s" % (label, res["err"]))
                continue
            body = (res.get("sent") or {}).get("body") or {}
            for side, want in (("a_ip", res["want_a"]), ("b_ip", res["want_b"])):
                if body.get(side) != want:
                    failures.append("the %s form's probe went out with %s=%r, but the form had picked "
                                    "%r — the server answers about an address the tunnel never uses"
                                    % (label, side, body.get(side), want))
            if body.get("a_ip") == res["want_a"] and body.get("b_ip") == res["want_b"]:
                print("  ok  %-52s a_ip=%s b_ip=%s"
                      % ("the %s form's probe carries both picks" % label, body["a_ip"], body["b_ip"]))

    if failures:
        print("\nFAILURES (%d):" % len(failures))
        for f in failures:
            print("  - %s" % f)
        return 1
    print("\nthe spoof egress test probes the pair the tunnel will really use")
    return 0


if __name__ == "__main__":
    sys.exit(main())
