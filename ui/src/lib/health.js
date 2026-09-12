export const WARN_PCT = 60
export const CRIT_PCT = 85

export function cssVar(name) {
  return getComputedStyle(document.body).getPropertyValue(name).trim() || '#888'
}

export function gaugeLevel(pct) {
  if (pct >= 88) return 'crit'
  if (pct >= 70) return 'warn'
  return 'ok'
}

export function usageColor(pct) {
  if (pct > CRIT_PCT) return cssVar('--bad')
  if (pct > WARN_PCT) return cssVar('--gold')
  return cssVar('--ok')
}

export function scoreColor(score) {
  if (score >= 85) return cssVar('--ok')
  if (score >= 60) return cssVar('--gold')
  return cssVar('--bad')
}
