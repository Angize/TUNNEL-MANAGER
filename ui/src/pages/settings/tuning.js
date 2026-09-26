import { T, TF } from '../../i18n/fa.js'
import { latinDigits, num } from '../../lib/num.js'

export const FIELDS = {
  reconcile: { labelKey: 'set_rec_int', unitKey: 'set_u_sec', kind: 'int', setting: 'reconcile_interval', half: true },
  poll: { labelKey: 'set_poll_int', unitKey: 'set_u_sec', kind: 'decimal', setting: 'poll_interval', half: true },
  ui: { labelKey: 'set_ui_int', unitKey: 'set_u_sec', kind: 'decimal', setting: 'ui_interval', half: true },
  ech: {
    labelKey: 'set_ech_int', unitKey: 'set_u_min', kind: 'decimal', setting: 'ech_refresh_mins', off: true, half: true,
  },
  probeMin: { labelKey: 'set_t_probemin', unitKey: 'set_u_pct', kind: 'int', tuning: 'probe_min_pct', stepper: true },
  revive: { labelKey: 'set_t_revive', unitKey: 'set_u_sec', kind: 'list', tuning: 'ladder_revive' },
  suspect: { labelKey: 'set_t_suspect', unitKey: 'set_u_min', kind: 'list', tuning: 'suspect_backoff', minutes: true },
  deadRetest: {
    labelKey: 'set_t_deadretest', unitKey: 'set_u_min', kind: 'int', tuning: 'dead_retest_secs', minutes: true,
  },
  sockBuf: { labelKey: 'set_t_sockbuf', unitKey: 'set_u_mb', kind: 'int', tuning: 'sock_buf_mb', stepper: true, half: true },
  tcpBuf: { labelKey: 'set_t_tcpbuf', unitKey: 'set_u_mb', kind: 'int', tuning: 'tcp_buf_mb', stepper: true, half: true },
}

const NUMBER = {
  int: /^\d+$/,
  decimal: /^(\d+\.?\d*|\.\d+)$/,
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

function fieldValues(text, kind) {
  if (kind === 'list') return numberList(text)
  const s = latinDigits(text).trim()
  return [NUMBER[kind].test(s) ? Number(s) : NaN]
}

export function fieldRange(key, config) {
  const spec = FIELDS[key]
  if (spec.setting) return config.settings_ranges[spec.setting]
  const [lo, hi] = config.tuning_ranges[spec.tuning]
  return spec.minutes ? [Math.ceil(lo / 60), Math.floor(hi / 60)] : [lo, hi]
}

export function fieldStep(key, config) {
  const spec = FIELDS[key]
  const step = spec.tuning && config.tuning_steps[spec.tuning]
  return step ? step[0] : 0
}

function listViolation(values, label) {
  return !values.length || values.some((n) => isNaN(n)) ? TF('set_list_bad', { f: label }) : ''
}

function rangeViolation(values, [lo, hi], label, spec) {
  for (const v of values) {
    if (isNaN(v)) return TF(spec.kind === 'decimal' ? 'set_dec_bad' : 'set_num_bad', { f: label })
    if (spec.off && v === 0) continue
    if (v < lo || v > hi) return TF(spec.off ? 'set_range_off_bad' : 'set_range_bad', { f: label, lo, hi, v })
  }
  return ''
}

function stepViolation(values, step, label, scale) {
  const bad = step ? values.find((v) => (v * scale) % step) : undefined
  return bad === undefined ? '' : TF('set_step_bad', { f: label, s: step, v: bad })
}

export function formErrors(form, config) {
  const out = {}
  for (const [key, spec] of Object.entries(FIELDS)) {
    const label = T(spec.labelKey)
    const values = fieldValues(form[key], spec.kind)
    const msg =
      (spec.kind === 'list' && listViolation(values, label)) ||
      rangeViolation(values, fieldRange(key, config), label, spec) ||
      stepViolation(values, fieldStep(key, config), label, spec.minutes ? 60 : 1)
    if (msg) out[key] = msg
  }
  return out
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
