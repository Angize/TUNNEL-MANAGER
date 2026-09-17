const WARN_PCT = 60
const LEVEL_COLOR = { ok: '--ok', warn: '--gold', crit: '--bad' }

export function cssVar(name) {
  return getComputedStyle(document.body).getPropertyValue(name).trim() || '#888'
}

export function usageLevel(pct, crit) {
  if (pct >= crit) return 'crit'
  if (pct >= WARN_PCT) return 'warn'
  return 'ok'
}

export function usageColor(pct, crit) {
  return cssVar(LEVEL_COLOR[usageLevel(pct, crit)])
}

export function scoreColor(score) {
  if (score >= 85) return cssVar('--ok')
  if (score >= 60) return cssVar('--gold')
  return cssVar('--bad')
}
