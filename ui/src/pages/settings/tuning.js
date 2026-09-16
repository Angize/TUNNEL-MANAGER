import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

function latinDigits(text) {
  return String(text || '').replace(/[۰-۹٠-٩]/g, (d) => String(d.charCodeAt(0) & 0xf))
}

export function minutesToSeconds(value) {
  const n = parseInt(latinDigits(value), 10)
  return n >= 1 ? n * 60 : NaN
}

export function secondsToMinutes(seconds) {
  return Math.max(1, Math.round(num(seconds) / 60))
}

function numberList(text) {
  return latinDigits(text)
    .split(/[\s,،]+/)
    .filter(Boolean)
    .map((part) => (/^\d+$/.test(part) ? parseInt(part, 10) : NaN))
}

export function parseMinuteList(text) {
  return numberList(text).map((n) => (n >= 1 ? n * 60 : NaN))
}

export function parseSecondList(text) {
  return numberList(text)
}

export function listViolation(form) {
  const lists = [
    [parseMinuteList(form.suspect), 'set_t_suspect'],
    [parseSecondList(form.revive), 'set_t_revive'],
  ]
  for (const [list, labelKey] of lists) {
    if (!list.length || list.some((n) => isNaN(n))) return T('set_list_bad').replace('{f}', T(labelKey))
  }
  return ''
}

export function collectTuning(form) {
  return {
    dead_retest_secs: minutesToSeconds(form.deadRetest),
    probe_min_pct: parseInt(latinDigits(form.probeMin), 10),
    sock_buf_mb: parseInt(latinDigits(form.sockBuf), 10),
    suspect_backoff: parseMinuteList(form.suspect),
    ladder_revive: parseSecondList(form.revive),
  }
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
