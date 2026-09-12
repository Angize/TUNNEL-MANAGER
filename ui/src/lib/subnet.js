import { T } from '../i18n/fa.js'
import { num } from './num.js'

export const TUNNEL_TYPES = [
  { v: 'vxlan', label: 'VXLAN' },
  { v: 'gre', label: 'GRE' },
  { v: 'sit', label: 'SIT (IPv6)' },
  { v: 'ipip', label: 'IPIP' },
  { v: 'l2tpv3', label: 'L2TPv3' },
  { v: 'fou', label: 'IPIP-over-FOU' },
  { v: 'ipsec', label: 'IPsec' },
]

const BASE_NETS = {
  '192.168': [3232235520, 16],
  '172.16': [2886729728, 12],
  '10': [167772160, 8],
}

const BASE_ORDER = ['192.168', '172.16', '10']

export function subnetCap(base) {
  const entry = BASE_NETS[base] || BASE_NETS['192.168']
  return (1 << (24 - entry[1])) - 1
}

export function subnetForBase(type, tunnelId, base) {
  const tid = num(tunnelId) || 0
  if (type === 'sit') {
    return 'fd00:' + (tid >> 16).toString(16) + ':' + (tid & 0xffff).toString(16) + '::/64'
  }
  let pick = base
  if (tid > subnetCap(pick)) pick = BASE_ORDER.find((x) => tid <= subnetCap(x))
  if (!pick || tid < 1 || tid > subnetCap(pick)) return ''
  const entry = BASE_NETS[pick]
  const n = (entry[0] + tid * 256) >>> 0
  return ((n >>> 24) & 255) + '.' + ((n >>> 16) & 255) + '.' + ((n >>> 8) & 255) + '.' + (n & 255) + '/24'
}

export function subnetBaseOf(link) {
  const tid = num(link.tunnel_id)
  return (
    BASE_ORDER.find((x) => tid <= subnetCap(x) && subnetForBase(link.type, tid, x) === link.subnet) ||
    'custom'
  )
}

export function subnetFree(base, free) {
  if (free && free[base] != null) return num(free[base])
  return subnetCap(base)
}

export function subnetRangeItems(free) {
  return [
    { v: '192.168', label: T('snr_192'), sub: '(' + subnetFree('192.168', free) + ')' },
    { v: '10', label: T('snr_10'), sub: '(' + subnetFree('10', free) + ')' },
    { v: '172.16', label: T('snr_172'), sub: '(' + subnetFree('172.16', free) + ')' },
    { v: 'custom', label: T('snr_custom') },
  ]
}
