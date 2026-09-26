import { T, TF } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

function latinDigits(text) {
  return String(text || '').replace(/[۰-۹٠-٩]/g, (d) => String(d.charCodeAt(0) & 0xf))
}

function minutesToSeconds(value) {
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

function parseMinuteList(text) {
  return numberList(text).map((n) => (n >= 1 ? n * 60 : NaN))
}

function parseSecondList(text) {
  return numberList(text)
}

function fieldNumber(text) {
  const s = latinDigits(text).trim()
  return /^\d+$/.test(s) ? parseInt(s, 10) : NaN
}

export function rangeViolation(form, ranges) {
  const minutes = ([lo, hi]) => [Math.ceil(lo / 60), Math.floor(hi / 60)]
  const checks = [
    [[fieldNumber(form.probeMin)], ranges.probe_min_pct, 'set_t_probemin'],
    [numberList(form.revive), ranges.ladder_revive, 'set_t_revive'],
    [numberList(form.suspect), minutes(ranges.suspect_backoff), 'set_t_suspect'],
    [[fieldNumber(form.deadRetest)], minutes(ranges.dead_retest_secs), 'set_t_deadretest'],
    [[fieldNumber(form.sockBuf)], ranges.sock_buf_mb, 'set_t_sockbuf'],
    [[fieldNumber(form.tcpBuf)], ranges.tcp_buf_mb, 'set_t_tcpbuf'],
  ]
  for (const [values, [lo, hi], labelKey] of checks) {
    for (const v of values) {
      if (isNaN(v)) return TF('set_num_bad', { f: T(labelKey) })
      if (v < lo || v > hi) return TF('set_range_bad', { f: T(labelKey), lo, hi, v })
    }
  }
  return ''
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
    tcp_buf_mb: parseInt(latinDigits(form.tcpBuf), 10),
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
