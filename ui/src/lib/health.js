export const WARN_PCT = 60
const LEVEL_COLOR = { ok: 'var(--ok-tx)', warn: 'var(--gold-tx)', crit: 'var(--bad-tx)' }

export function cssVar(name) {
  return getComputedStyle(document.body).getPropertyValue(name).trim() || '#888'
}

export function usageLevel(pct, crit) {
  if (pct >= crit) return 'crit'
  if (pct >= WARN_PCT) return 'warn'
  return 'ok'
}

export function scoreLevel(score) {
  if (score >= 85) return 'ok'
  if (score >= 60) return 'warn'
  return 'crit'
}

export function shareLevel(part, whole) {
  if (part === whole) return 'ok'
  return part ? 'warn' : 'crit'
}

export function uptimeLevel(pct, [ok, bad]) {
  if (pct >= ok) return 'ok'
  if (pct >= bad) return 'warn'
  return 'crit'
}

export function uptimeColor(pct, levels) {
  return LEVEL_COLOR[uptimeLevel(pct, levels)]
}
