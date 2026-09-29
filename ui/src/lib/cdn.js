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
  if (zone.ok) return T('cdn_zone_on')
  const why = zone.why || ''
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

export function cdnAuto(form) {
  return !!form && form.Tr === 'ws' && !form.pool.pool && !!form.cdnOwner
}

export function hasCdnKey(keys) {
  return CDN_PROVIDERS.some((p) => keys && keys[p] && keys[p].set)
}

export function edgePort(edge) {
  const colon = edge.lastIndexOf(':')
  const port = colon >= 0 ? edge.slice(colon + 1) : ''
  return /^\d+$/.test(port) ? +port : 0
}
