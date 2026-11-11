import { T } from '../../../i18n/fa.js'

export const SPROT_DEFAULT = 4
export const PEER_ACC_MIN = 3
export const POOL_MAX = 64

export const TRANSPORTS = [
  { v: 'udp', n: 'UDP', d: 'tr_udp_d' },
  { v: 'tcp', n: 'TCP', d: 'tr_tcp_d' },
  { v: 'raw', n: 'RAW', d: 'tr_raw_d' },
  { v: 'ws', n: 'CDN', d: 'tr_ws_d' },
]

export function rawProfiles() {
  return [
    { v: 'bare', m: T('rawp_bare_m') },
    { v: 'icmp', m: T('rawp_icmp_m') },
    { v: 'gre', m: T('rawp_gre_m') },
    { v: 'ipip', m: T('rawp_ipip_m') },
    { v: 'udp', m: T('rawp_udp_m') },
    { v: 'tcp', m: T('rawp_tcp_m') },
    { v: 'sctp', m: T('rawp_sctp_m') },
    { v: 'esp', m: T('rawp_esp_m') },
    { v: 'l2tpv3', m: T('rawp_l2tpv3_m') },
    { v: 'ah', m: T('rawp_ah_m') },
    { v: 'ipcomp', m: T('rawp_ipcomp_m') },
    { v: 'etherip', m: T('rawp_etherip_m') },
  ]
}

export function wsProfiles() {
  return [
    { v: 'ws', m: T('wsp_ws_m') },
    { v: 'grpc', m: T('wsp_grpc_m') },
    { v: 'http', m: T('wsp_http_m') },
  ]
}

export function fecRates() {
  return [
    { d: 20, p: 2, n: T('fec_light'), ov: T('fec_ov10') },
    { d: 16, p: 4, n: T('fec_balanced'), ov: T('fec_ov25') },
    { d: 8, p: 4, n: T('fec_strong'), ov: T('fec_ov50') },
  ]
}

export function desyncModes() {
  return [
    { v: 'ttl', t: T('ds_m_ttl_t'), s: T('ds_m_ttl_s') },
    { v: 'badsum', t: T('ds_m_bad_t'), s: T('ds_m_bad_s') },
    { v: 'both', t: T('ds_m_both_t'), s: T('ds_m_both_s') },
  ]
}

export function sniModes() {
  return [
    { v: 'split', t: T('m_split_t'), s: T('m_split_s') },
    { v: 'disorder', t: T('m_dis_t'), s: T('m_dis_s') },
    { v: 'fake', t: T('m_fake_t'), s: T('m_fake_s') },
  ]
}

const ROT_PRESETS = [
  [180, 'rot_3m'],
  [300, 'rot_5m'],
  [600, 'rot_10m'],
  [900, 'rot_15m'],
  [1800, 'rot_30m'],
  [3600, 'rot_1h'],
]

function rotPresetItems() {
  return ROT_PRESETS.map(([v, key]) => ({ v, label: T(key) }))
}

export function rotIntervalItems() {
  return [...rotPresetItems(), { v: 0, label: T('rot_onfail') }]
}

export function poolRotateItems() {
  return [
    ...rotPresetItems(),
    { v: 14400, label: T('rot_4h') },
    { v: 28800, label: T('rot_8h') },
    { v: 0, label: T('rot_off_fo') },
  ]
}

const CDN_FIELD_KEYS = {
  upw: 'http_up_workers',
  upkb: 'http_up_batch_kb',
  uprate: 'http_up_rate',
  downw: 'http_streams',
}

export const CDN_FIELD_NAMES = ['upw', 'upkb', 'uprate', 'downw']

export function cdnShape(enums) {
  const out = {}
  for (const name of CDN_FIELD_NAMES) {
    const key = CDN_FIELD_KEYS[name]
    const spec = enums.http_shape[key]
    out[name] = { k: key, lo: spec.lo, hi: spec.hi, d: spec.d }
  }
  return out
}

export function cdnLabel(name) {
  return {
    upw: T('cdn_upw_lbl'),
    upkb: T('cdn_upkb_lbl'),
    uprate: T('cdn_uprate_lbl'),
    downw: T('cdn_strm_lbl'),
  }[name]
}

export function cipherItems(enums, transport) {
  return enums.ciphers
    .filter((v) => !(v === 'none' && transport === 'raw'))
    .map((v) => ({
      v,
      label: v === 'auto' ? T('cipher_auto') : v === 'none' ? T('cipher_none') : v,
    }))
}
