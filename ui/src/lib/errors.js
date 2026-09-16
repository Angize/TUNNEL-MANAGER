import { T } from '../i18n/fa.js'

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
  [/^not found$/i, 'err_not_found'],
  [/^core config missing on this node$/i, 'err_core_nocfg'],
  [/^core did not come up [(]no iface[)]$/i, 'err_core_noiface'],
  [/^bad key$/i, 'err_bad_key'],
  [/^command queue full$/i, 'err_cmdq_full'],
  [/^no ip pool on this tunnel$/i, 'err_no_ippool'],
  [/^no edge pool on this tunnel$/i, 'err_no_edgepool'],
  [/^bad axis$/i, 'err_bad_axis'],
  [/^not a ws tunnel$/i, 'err_not_ws'],
  [/x509:[^,]*signed by unknown authority/i, 'err_cert_unknown'],
  [/x509:[^,]*certificate has expired[^,]*/i, 'err_cert_expired'],
  [/i\/o timeout/i, 'err_timeout'],
  [/EOF$/, 'err_eof'],
]

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
  for (const [re, key] of WHOLE) out = out.replace(re, T(key))
  for (const [re, key] of PHRASE) out = out.replace(re, T(key))
  return out.trim()
}

export function postError(r, fallbackKey) {
  if (r && r.net) return T(r.net === 'timeout' ? 'net_timeout' : 'net_drop')
  return translateError((r && r.d && (r.d.error || r.d.msg)) || T(fallbackKey || 'failed'))
}
