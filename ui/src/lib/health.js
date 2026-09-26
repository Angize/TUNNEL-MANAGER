const WARN_PCT = 60
const LEVEL_COLOR = { ok: 'var(--ok-tx)', warn: 'var(--gold-tx)', crit: 'var(--bad-tx)' }

export function cssVar(name) {
  return getComputedStyle(document.body).getPropertyValue(name).trim() || '#888'
}

export function usageLevel(pct, crit) {
  if (pct >= crit) return 'crit'
  if (pct >= WARN_PCT) return 'warn'
  return 'ok'
}

export function usageColor(pct, crit) {
  return LEVEL_COLOR[usageLevel(pct, crit)]
}

export function scoreColor(score) {
  if (score >= 85) return LEVEL_COLOR.ok
  if (score >= 60) return LEVEL_COLOR.warn
  return LEVEL_COLOR.crit
}
