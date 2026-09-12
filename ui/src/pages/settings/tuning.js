import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

export function minutesToSeconds(value) {
  const n = parseInt(value, 10)
  return n >= 1 ? n * 60 : NaN
}

export function secondsToMinutes(seconds) {
  return Math.max(1, Math.round(num(seconds) / 60))
}

export function parseMinuteList(text) {
  return String(text || '')
    .split(',')
    .map((part) => minutesToSeconds(part.trim()))
    .filter((n) => !isNaN(n))
}

export function parseSecondList(text) {
  return String(text || '')
    .split(',')
    .map((part) => parseInt(part.trim(), 10))
    .filter((n) => !isNaN(n))
}

export function collectTuning(form) {
  const backoff = parseMinuteList(form.suspect)
  const revive = parseSecondList(form.revive)
  const tuning = {
    dead_retest_secs: minutesToSeconds(form.deadRetest),
    probe_min_pct: parseInt(form.probeMin, 10),
    sock_buf_mb: parseInt(form.sockBuf, 10),
  }
  if (backoff.length) tuning.suspect_backoff = backoff
  if (revive.length) tuning.ladder_revive = revive
  return tuning
}

export function stepViolation(tuning, steps) {
  for (const key of Object.keys(steps)) {
    const step = steps[key][0]
    const value = tuning[key]
    if (step && typeof value === 'number' && !isNaN(value) && value % step) {
      return T('set_step_bad')
        .replace('{f}', steps[key][1])
        .replace('{s}', step)
        .replace('{v}', value)
    }
  }
  return ''
}
