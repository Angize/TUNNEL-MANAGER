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

function rawTag(profile, link, ptype) {
  if (profile === 'bare') return 'BARE(' + (num(link.raw_proto) || 253) + ')'
  if (profile === 'gre' && ptype) return 'GRE·' + ptype.toString(16).padStart(4, '0')
  return profile.toUpperCase()
}

function rawProfileTag(link) {
  const up = link.raw_profile || 'bare'
  const down = link.raw_profile_down || up
  const ptUp = num(link.raw_gre_ptype) || 0
  const ptDn = num(link.raw_gre_ptype_down) || ptUp
  const upTag = rawTag(up, link, ptUp)
  const dnTag = rawTag(down, link, ptDn)
  return dnTag === upTag ? upTag : upTag + '/' + dnTag
}

export function carrierProfile(link) {
  return (link.transport || 'udp') === 'raw' ? rawProfileTag(link) : ''
}

export function edgeCount(link) {
  return (link.edge_at || []).reduce((n, e) => n + e.addrs.length, 0)
}

export function edgePool(link) {
  return link.transport === 'ws' && (!!link.ws_pool || edgeCount(link) > 1)
}

export function peerPool(link) {
  return !!link.ip_rotate || (link.transport !== 'ws' && edgeCount(link) > 1)
}

export function edgeHost(value) {
  const text = String(value || '')
  const last = text.lastIndexOf(':')
  return last > 0 && text.indexOf(':') === last ? text.slice(0, last) : text
}
