import { T, TF } from '../i18n/fa.js'

export const CDN_PROVIDERS = ['cf', 'ar']

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

const CF_PLAN = { free: 'Free', pro: 'Pro', business: 'Business', enterprise: 'Enterprise' }

export function providerName(provider) {
  return T('cdn_p_' + provider)
}

export function labelError(label) {
  if (!label) return T('cdn_label_need')
  if (label.includes('.')) return T('cdn_label_dot')
  if (!LABEL_RE.test(label)) return T('cdn_label_bad')
  return ''
}

export function labelOf(host, zone) {
  const tail = '.' + (zone || '')
  return host && zone && host.endsWith(tail) ? host.slice(0, -tail.length) : ''
}

export function planWord(provider, plan) {
  if (provider === 'cf') return CF_PLAN[plan] || String(plan || '')
  return plan == null || plan === '' ? '' : TF('cdn_ar_level', { n: plan })
}

function zoneState(zone) {
  const why = zone.why || ''
  if (zone.ok && !why) return T('cdn_zone_on')
  const key = 'cdn_zone_' + why
  return T(key) === key ? why : T(key)
}

export function zoneKey(provider, zone) {
  return provider + ':' + zone
}

export function splitZoneKey(key) {
  const at = key.indexOf(':')
  return { provider: key.slice(0, at), zone: key.slice(at + 1) }
}

export function zoneItems(zonesBy, echOn) {
  const out = []
  for (const provider of CDN_PROVIDERS) {
    for (const z of zonesBy[provider] || []) {
      const blocked = echOn && provider !== 'cf'
      out.push({
        v: zoneKey(provider, z.name),
        label: z.name,
        sub: [providerName(provider), planWord(provider, z.plan), blocked ? T('cdn_zone_no_ech') : zoneState(z)]
          .filter(Boolean)
          .join(' · '),
      })
    }
  }
  return out
}

export function cdnSingle(form) {
  return !!form && form.Tr === 'ws' && !form.pool.pool && !!form.cdnOwner
}

export function cdnAuto(form) {
  return cdnSingle(form) || (!!form && form.Tr === 'ws' && !!form.pool.pool && !!form.poolCdn)
}

export function hasCdnKey(keys) {
  return CDN_PROVIDERS.some((p) => keys && keys[p] && keys[p].set)
}

export const EDGE_TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
export const EDGE_PLAIN_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]

export function edgeFits(edge, tls) {
  const port = edgePort(edge)
  return !port || (tls ? EDGE_TLS_PORTS : EDGE_PLAIN_PORTS).includes(port)
}

export function tlsEdges(edges) {
  return (edges || []).filter((e) => edgeFits(e, true)).map((e) => (edgePort(e) ? e : e + ':443'))
}

export function edgeError(value) {
  const at = value.lastIndexOf(':')
  const host = at >= 0 ? value.slice(0, at) : value
  const port = at >= 0 ? value.slice(at + 1) : ''
  if (!/^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(host)) return T('edge_bad_ip')
  if (at >= 0 && !(/^\d+$/.test(port) && EDGE_TLS_PORTS.concat(EDGE_PLAIN_PORTS).includes(+port))) return T('edge_bad_port')
  return ''
}

export function edgePort(edge) {
  const colon = edge.lastIndexOf(':')
  const port = colon >= 0 ? edge.slice(colon + 1) : ''
  return /^\d+$/.test(port) ? +port : 0
}
