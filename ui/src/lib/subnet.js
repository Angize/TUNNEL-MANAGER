import { T, TF } from '../i18n/fa.js'
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

export const PORT_TYPES = ['l2tpv3', 'fou', 'vxlan']

function dotted(n) {
  return ((n >>> 24) & 255) + '.' + ((n >>> 16) & 255) + '.' + ((n >>> 8) & 255) + '.' + (n & 255)
}

function addrNum(octets) {
  return octets.reduce((n, o) => n * 256 + +o, 0)
}

export function hostAddress(subnet, host) {
  const [base, bits] = String(subnet || '').split('/')
  const octets = base.split('.')
  const prefix = bits === undefined ? 24 : num(bits)
  if (octets.length !== 4 || octets.some((o) => !/^\d{1,3}$/.test(o) || +o > 255)) return ''
  if (!(prefix >= 0 && prefix <= 32)) return ''
  const addr = addrNum(octets)
  const size = 2 ** (32 - prefix)
  return dotted(addr - (addr % size) + host) + '/' + prefix
}

function baseEntry(bases, base) {
  return bases.find((entry) => entry[0] === base)
}

export function subnetDefaultBase(bases) {
  return bases[0][0]
}

export function subnetForBase(bases, type, tunnelId, base) {
  const tid = num(tunnelId)
  if (type === 'sit') {
    return 'fd00:' + (tid >> 16).toString(16) + ':' + (tid & 0xffff).toString(16) + '::/64'
  }
  const entry = baseEntry(bases, base)
  if (!entry || tid < 1 || tid > entry[3]) return ''
  return dotted((addrNum(entry[1].split('.')) + tid * 256) >>> 0) + '/24'
}

export function subnetFitError(bases, type, tunnelId, base) {
  if (type === 'sit' || subnetForBase(bases, type, tunnelId, base)) return ''
  const [, net, prefix, cap] = baseEntry(bases, base)
  return TF('snr_no_fit', { id: num(tunnelId), net: net + '/' + prefix, cap })
}

export function subnetBaseOf(bases, link) {
  const tid = num(link.tunnel_id)
  const hit = bases.find(
    (entry) => tid <= entry[3] && subnetForBase(bases, link.type, tid, entry[0]) === link.subnet,
  )
  return hit ? hit[0] : 'custom'
}

function subnetFree(entry, free) {
  if (free && free[entry[0]] != null) return num(free[entry[0]])
  return entry[3]
}

function rangeItem(entry, free, key) {
  return {
    v: entry[0],
    label: TF(key, { net: entry[1] + '/' + entry[2] }),
    sub: '\u2067' + TF('snr_free', { n: subnetFree(entry, free) }) + '\u2069',
  }
}

export function subnetRangeItems(bases, free, type, base) {
  if (type === 'sit') {
    return [
      { v: base === 'custom' ? subnetDefaultBase(bases) : base, label: T('snr_sit') },
      { v: 'custom', label: T('snr_custom') },
    ]
  }
  const [first, ...rest] = bases
  return [
    rangeItem(first, free, 'snr_auto_rec'),
    ...rest.sort((x, y) => y[3] - x[3]).map((entry) => rangeItem(entry, free, 'snr_auto')),
    { v: 'custom', label: T('snr_custom') },
  ]
}
