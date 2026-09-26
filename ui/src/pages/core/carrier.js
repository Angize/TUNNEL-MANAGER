import { num } from '../../lib/num.js'

export const RAW_DPORT_DEFAULT = 443
export const RAW_SPORT_FIXED = 51820
export const RAW_ROT_LO = 10000
export const RAW_ROT_HI = 59999
export const CT_WARN_PCT = 80

const TAG_FAMILIES = { udp: 1, tcp: 1, raw: 1, ws: 1, http: 1, grpc: 1 }

export function carrierFamily(link) {
  const transport = link.transport || 'udp'
  if (transport !== 'ws') return transport
  if (link.cdn_carrier === 'grpc') return 'grpc'
  if (link.cdn_carrier === 'http') return 'http'
  return 'ws'
}

export function carrierLabel(link) {
  return carrierFamily(link).toUpperCase()
}

export function tagClassForFamily(family) {
  return TAG_FAMILIES[String(family).toLowerCase()] ? 'c-' + family : 'c-sys'
}

function rawProfileTag(link) {
  const profile = link.raw_profile || 'bare'
  return profile.toUpperCase() + (profile === 'bare' ? '(' + (num(link.raw_proto) || 253) + ')' : '')
}

export function carrierProfile(link) {
  return (link.transport || 'udp') === 'raw' ? rawProfileTag(link) : ''
}

export function edgeHost(value) {
  const text = String(value || '')
  const last = text.lastIndexOf(':')
  return last > 0 && text.indexOf(':') === last ? text.slice(0, last) : text
}
