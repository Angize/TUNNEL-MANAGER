import { T, TF } from '../../../i18n/fa.js'
import { latinDigits } from '../../../lib/num.js'
import { RAW_DPORTS_MAX, RAW_SPROT_MAX, SPROT_DEFAULT, cdnLabel, cdnShape } from './presets.js'
import { cdnShapeApplies, cdnShapeOn, sprotLive } from './gates.js'

function blank(text) {
  return latinDigits(text).trim() === ''
}

export function intOf(text) {
  const s = latinDigits(text).trim()
  if (!s) return 0
  return /^\d+$/.test(s) ? Number(s) : NaN
}

function inRange(n, range) {
  return n >= range[0] && n <= range[1]
}

function outside(text, range) {
  return !blank(text) && !inRange(intOf(text), range)
}

const LIMITED = {
  splitPos: ['split_pos', 'cf_f_split_pos'],
  splitTtl: ['split_ttl', 'cf_f_split_ttl'],
  dsTtl: ['fake_ttl', 'ds_ttl_lbl'],
  dsCount: ['fake_count', 'ds_count_lbl'],
}

export function limitErr(form, key, limits) {
  const [limit, name] = LIMITED[key]
  const range = limits[limit]
  return outside(form[key], range)
    ? TF('cf_range_bad', { f: T(name), lo: range[0], hi: range[1] })
    : ''
}

function rawProtoOwner(value, enums) {
  const map = (enums && enums.raw_protos) || {}
  for (const key of Object.keys(map)) if (map[key] === value) return key
  return ''
}

export function rawProtoErr(text, enums) {
  if (blank(text)) return ''
  const n = intOf(text)
  if (!(n >= 1 && n <= 255)) return T('raw_proto_bad')
  const owner = rawProtoOwner(n, enums)
  return owner ? TF('raw_proto_owned', { n, p: owner }) : ''
}

export function portErr(text, limits) {
  return outside(text, limits.port) ? T('raw_port_bad') : ''
}

export function sportErr(text, limits) {
  return outside(text, limits.port) ? T('raw_sport_bad') : ''
}

export function sprotOf(form) {
  return blank(form.rawSprot) ? SPROT_DEFAULT : intOf(form.rawSprot)
}

export function sprotErr(form) {
  if (!sprotLive(form)) return ''
  const n = sprotOf(form)
  if (!(n >= 1 && n <= RAW_SPROT_MAX)) return T('raw_sprot_bad')
  const dports = intOf(form.rawDports)
  return dports === 0 || (dports >= 1 && dports <= RAW_DPORTS_MAX)
    ? ''
    : TF('raw_dports_bad', { n: RAW_DPORTS_MAX })
}

export function bandErr(form, limits) {
  const lo = intOf(form.bandLo)
  const hi = intOf(form.bandHi)
  if (lo === 0 && hi === 0) return ''
  const band = [limits.band_min_lo, limits.port[1]]
  if (!inRange(lo, band) || !inRange(hi, band) || hi < lo) {
    return TF('band_bad', { n: limits.band_min_lo })
  }
  if (hi - lo + 1 < limits.band_min_span) {
    return TF('band_narrow', { n: limits.band_min_span })
  }
  return ''
}

export function portTriesRangeErr(form, limits) {
  const range = limits.port_tries
  return inRange(intOf(form.portTries), range)
    ? ''
    : TF('cf_range_bad', { f: T('porttries_lbl'), lo: 1, hi: range[1] })
}

export function cdnShapeValue(form, name, enums) {
  const raw = form.cdn[name]
  return blank(raw) ? cdnShape(enums)[name].d : intOf(raw)
}

export function cdnShapeErr(form, enums) {
  if (!cdnShapeOn(form)) return ''
  const shape = cdnShape(enums)
  for (const name of Object.keys(shape)) {
    const field = shape[name]
    if (!cdnShapeApplies(field, form.Cdn, enums)) continue
    const value = cdnShapeValue(form, name, enums)
    if (isNaN(value) || value < field.lo || value > field.hi) {
      return T('cdn_bad') + ' ' + cdnLabel(name) + ' ' + field.lo + '–' + field.hi
    }
  }
  return ''
}

const IP4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const DOMAIN = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$/

export function poolValid(kind, value, enums) {
  if (kind !== 'ip') return DOMAIN.test(value)
  let host = value
  const colon = value.lastIndexOf(':')
  if (colon >= 0) {
    host = value.slice(0, colon)
    const port = value.slice(colon + 1)
    const allowed = ((enums && enums.edge_ports) || {}).tls || []
    if (!(/^\d+$/.test(port) && allowed.includes(+port))) return false
  }
  return IP4.test(host)
}
