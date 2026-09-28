import { T, TF } from '../i18n/fa.js'

export const CDN_PROVIDERS = ['cf', 'ar']

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/

const CF_PLAN = { free: 'Free', pro: 'Pro', business: 'Business', enterprise: 'Enterprise' }

const SSL_WORD = { off: 'Off', flexible: 'Flexible', full: 'Full', strict: 'Full (strict)', origin_pull: 'Strict (origin pull)' }

export function providerName(provider) {
  return T('cdn_p_' + provider)
}

export function labelError(label) {
  if (!label) return T('cdn_label_need')
  if (label.includes('.')) return T('cdn_label_dot')
  if (!LABEL_RE.test(label)) return T('cdn_label_bad')
  return ''
}

export function hostOf(label, zone) {
  return (label || '…') + '.' + (zone || '…')
}

export function labelOf(host, zone) {
  const tail = '.' + (zone || '')
  return host && zone && host.endsWith(tail) ? host.slice(0, -tail.length) : ''
}

export function planWord(provider, plan) {
  if (provider === 'cf') return CF_PLAN[plan] || String(plan || '')
  return plan == null || plan === '' ? '' : TF('cdn_ar_level', { n: plan })
}

export function sslWord(ssl) {
  return SSL_WORD[ssl] || String(ssl || '')
}

function zoneState(zone) {
  if (zone.ok) return T('cdn_zone_on')
  const why = zone.why || ''
  const key = 'cdn_zone_' + why
  return T(key) === key ? why : T(key)
}

export function zoneItems(provider, zones) {
  return (zones || []).map((z) => ({
    v: z.name,
    label: z.name,
    sub: [planWord(provider, z.plan), zoneState(z)].filter(Boolean).join(' · '),
  }))
}

export function cdnLocked(form) {
  return !!(form.pool.pool || (form.Ech && form.cdnMode === 'ar'))
}

export function cdnAuto(form) {
  return !!form && form.Tr === 'ws' && form.cdnMode !== 'manual' && !cdnLocked(form)
}

export function cdnReady(form) {
  return cdnAuto(form) && !!form.cdnZone && form.cdnZoneOk && !labelError(form.cdnLabel)
}

export function edgePort(edge) {
  const colon = edge.lastIndexOf(':')
  const port = colon >= 0 ? edge.slice(colon + 1) : ''
  return /^\d+$/.test(port) ? +port : 0
}

export function autoOf(form) {
  return {
    provider: form.cdnMode,
    zone: form.cdnZone,
    label: form.cdnLabel,
    replace: form.cdnReplace === true,
    share: form.cdnMode === 'cf' && !!form.cdnShare,
  }
}

export function autoOfLink(cdn) {
  return {
    provider: cdn.provider,
    zone: cdn.zone,
    label: labelOf(cdn.host, cdn.zone),
    replace: !!cdn.replace,
    share: !!cdn.share,
  }
}

export function sameAuto(a, b) {
  return (
    a.provider === b.provider &&
    a.zone === b.zone &&
    a.label === b.label &&
    a.replace === b.replace &&
    a.share === b.share
  )
}
