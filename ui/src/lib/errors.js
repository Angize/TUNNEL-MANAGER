import { T } from '../i18n/fa.js'
import { ApiError } from './api.js'

const NOISE = [
  /^(dial|read|write) (tcp|udp)\s*/i,
  /connect:\s*/i,
  /context deadline exceeded:?\s*/i,
  /^bash: line \d+:\s*/i,
  /^sh: \d+:\s*/i,
  /^ssh:\s*/i,
  /^connect:\s*/i,
  /^Error:\s*/i,
  /^error:\s*/i,
]

const WHOLE = [
  [/^mtu of iface ([^ ]+) unreadable$/i, 'err_mtu_read'],
  [/^core is up but iface ([^ ]+) has not appeared yet$/i, 'err_core_slow'],
  [/^core did not come up: /i, 'err_core_why'],
  [/^iface ([^ ]+) not created: (.+) is missing on this node$/i, 'err_iface_mod'],
  [/^core unit ([^ ]+) still running after stop$/i, 'err_core_stuck'],
  [/^([^ ]+) must be between 0 and ([0-9]+)$/i, 'err_knob_range'],
  [/^ws_tls requires ws_host$/i, 'err_wstls_host'],
  [/^raw requires a psk$/i, 'err_raw_psk'],
  [/^cover requires cover_sni$/i, 'err_cover_sni'],
  [/^tunnel disabled$/i, 'err_tun_off'],
  [/^port ([0-9]+) on ([^ ]+) is already forwarded by ([^ ]+)$/i, 'err_pf_taken_fw'],
  [/^port ([0-9]+) is used by tunnel ([^ ]+)$/i, 'err_pf_taken_tun'],
  [/^port ([0-9]+)\/(tcp|udp) is in use on this node by (.+)$/i, 'err_pf_taken_proc'],
  [/^port ([0-9]+)\/(tcp|udp) is in use on this node$/i, 'err_pf_taken'],
  [/^need >=2 destinations to rotate$/i, 'err_pf_one_dst'],
  [/^([0-9.]+) is not a local IP on this node$/i, 'err_ip_gone'],
  [/^no interface$/i, 'err_no_iface'],
  [/^(tunnel )?not found$/i, 'err_not_found'],
  [/^core config missing on this node$/i, 'err_core_nocfg'],
  [/^core did not come up [(]no iface[)]$/i, 'err_core_noiface'],
  [/^bad key$/i, 'err_bad_key'],
  [/^a speed test is already running on this node$/i, 'err_speed_busy'],
  [/^update key already set by another panel [(]delete this node in the panel and add it again[)]$/i, 'err_update_key_other'],
  [/^could not save tuning state; nothing changed$/i, 'err_tune_save'],
  [/^too_small$/, 'upe_too_small'],
  [/^sha_mismatch$/, 'upe_sha_mismatch'],
  [/^bad_signature$/, 'upe_bad_signature'],
  [/^checksum_unavailable$/, 'upe_checksum_unavailable'],
  [/^download_failed$/, 'upe_download_failed'],
  [/^nothing_staged$/, 'upe_nothing_staged'],
  [/^command queue full$/i, 'err_cmdq_full'],
  [/^no ip pool on this tunnel$/i, 'err_no_ippool'],
  [/^no edge pool on this tunnel$/i, 'err_no_edgepool'],
  [/^bad axis$/i, 'err_bad_axis'],
  [/^not a ws tunnel$/i, 'err_not_ws'],
  [/^agent is restarting, retry shortly$/i, 'err_agent_restart'],
  [/^internal error [(]see node-agent\.log[)]$/i, 'err_agent_internal'],
  [/^obfs requires a psk and encryption$/i, 'err_obfs_psk'],
  [/^interface ([^ ]+) has no address$/i, 'err_tun_noaddr'],
  [
    /^nothing reached ([^ ]+) over ([^ ]+) -- the far end is not listening or the tunnel is not carrying$/i,
    'err_speed_nothing',
  ],
  [/x509:[^,]*signed by unknown authority/i, 'err_cert_unknown'],
  [/x509:[^,]*certificate has expired[^,]*/i, 'err_cert_expired'],
  [/i\/o timeout/i, 'err_timeout'],
  [/EOF$/, 'err_eof'],
]

function segment([re, key]) {
  const groups = new RegExp('(?:' + re.source + ')|').exec('').length - 1
  let src = re.source.startsWith('^') ? '(^|: )' + re.source.slice(1) : '()' + re.source
  if (src.endsWith('$')) src = src.slice(0, -1) + '(?=$| \\(|؛|;| —)'
  return { re: new RegExp(src, re.flags + 'g'), key, groups }
}

const SEGMENTS = WHOLE.map(segment)

function fill(text, values) {
  return text.replace(/\$([1-9])/g, (all, n) => (n <= values.length ? values[n - 1] || '' : all))
}

const PHRASE = [
  [/RTNETLINK answers:\s*No such file or directory/gi, 'err_rt_nomod'],
  [/RTNETLINK answers:\s*File exists/gi, 'err_rt_exists'],
  [/RTNETLINK answers:\s*Operation not supported/gi, 'err_rt_unsupported'],
  [/RTNETLINK answers:\s*Operation not permitted/gi, 'err_rt_notperm'],
  [/RTNETLINK answers:\s*Network is unreachable/gi, 'err_rt_noroute'],
  [/RTNETLINK answers:\s*Address already in use/gi, 'err_rt_addrused'],
  [/RTNETLINK answers:\s*Cannot find device/gi, 'err_rt_nodev'],
  [/RTNETLINK answers:\s*Invalid argument/gi, 'err_rt_badarg'],
  [/RTNETLINK answers:\s*([A-Za-z][A-Za-z ]+)/gi, 'err_rt_other'],
  [/Error talking to the kernel/gi, 'err_kernel'],
  [/Cannot find device/gi, 'err_rt_nodev'],
  [/Connection refused/gi, 'err_refused'],
  [/No route to host/gi, 'err_noroute'],
  [/Network is unreachable/gi, 'err_noroute'],
  [/Name or service not known/gi, 'err_dns'],
  [/Connection reset by peer/gi, 'err_reset'],
  [/timed out|timeout/gi, 'err_timeout'],
  [/unreachable/gi, 'err_unreach'],
  [/Permission denied/gi, 'err_denied'],
  [/command not found/gi, 'err_nocmd'],
  [/No such file or directory/gi, 'err_nofile'],
  [/Address family not supported/gi, 'err_afam'],
  [/broken pipe/gi, 'err_pipe'],
  [/server busy,\s*retry shortly/gi, 'err_busy'],
  [/certificate/gi, 'err_cert'],
]

export function translateError(msg) {
  let out = String(msg == null ? '' : msg)
  for (const re of NOISE) out = out.replace(re, '')
  for (const { re, key, groups } of SEGMENTS) {
    out = out.replace(re, (...m) => m[1] + fill(T(key), m.slice(2, 2 + groups)))
  }
  for (const [re, key] of PHRASE) out = out.replace(re, T(key))
  return out.trim()
}

export function readError(failure) {
  const msg = failure instanceof ApiError ? failure.message : failure.d && (failure.d.error || failure.d.msg)
  if (msg) return translateError(msg)
  return T(failure.ok ? 'failed' : 'net_read')
}

export function postError(r, fallbackKey) {
  if (r.net) return T(r.net === 'timeout' ? 'net_timeout' : 'net_drop')
  return translateError(r.d.error || r.d.msg || T(fallbackKey || 'failed'))
}
