import { T } from '../../../i18n/fa.js'
import {
  PORT_TRIES_MAX,
  RAW_BAND_MIN_LO,
  RAW_BAND_MIN_SPAN,
  RAW_DPORTS_MAX,
  RAW_SPROT_MAX,
  cdnLabel,
  cdnShape,
} from './presets.js'
import { bandOn, cdnShapeApplies, cdnShapeOn, portTriesOn, sprotLive } from './gates.js'

export function intOf(text) {
  const n = parseInt(String(text || '').trim(), 10)
  return isNaN(n) ? 0 : n
}

export function rawProtoOwner(value, enums) {
  const map = (enums && enums.raw_protos) || {}
  for (const key of Object.keys(map)) if (map[key] === value) return key
  return ''
}

export function rawProtoErr(text, enums) {
  const s = String(text || '').trim()
  if (!s) return ''
  const n = parseInt(s, 10)
  if (!(n >= 1 && n <= 255)) return T('raw_proto_bad')
  const owner = rawProtoOwner(n, enums)
  return owner
    ? T('raw_proto_owned').replace('{n}', n).split('{p}').join(owner)
    : ''
}

export function portErr(text) {
  const s = String(text || '').trim()
  if (!s) return ''
  const n = parseInt(s, 10)
  return n >= 1 && n <= 65535 ? '' : T('raw_port_bad')
}

export function sportErr(text) {
  const s = String(text || '').trim()
  if (!s) return ''
  const n = parseInt(s, 10)
  return n >= 1 && n <= 65535 ? '' : T('raw_sport_bad')
}

export function sprotErr(form) {
  if (!sprotLive(form)) return ''
  const n = intOf(form.rawSprot)
  if (!(n >= 1 && n <= RAW_SPROT_MAX)) return T('raw_sprot_bad')
  const dports = intOf(form.rawDports)
  return dports === 0 || (dports >= 1 && dports <= RAW_DPORTS_MAX)
    ? ''
    : T('raw_dports_bad').replace('{n}', String(RAW_DPORTS_MAX))
}

export function bandErr(form) {
  const lo = intOf(form.bandLo)
  const hi = intOf(form.bandHi)
  if (!lo && !hi) return ''
  if (
    !(lo >= RAW_BAND_MIN_LO && lo <= 65535) ||
    !(hi >= RAW_BAND_MIN_LO && hi <= 65535) ||
    hi < lo
  ) {
    return T('band_bad').replace('{n}', String(RAW_BAND_MIN_LO))
  }
  if (hi - lo + 1 < RAW_BAND_MIN_SPAN) {
    return T('band_narrow').replace('{n}', String(RAW_BAND_MIN_SPAN))
  }
  return ''
}

export function portTriesValue(form) {
  return intOf(form.portTries)
}

export function portTriesRangeErr(form) {
  const n = portTriesValue(form)
  return n === 0 || (n >= 1 && n <= PORT_TRIES_MAX) ? '' : T('porttries_bad')
}

export function portTriesErr(form, enums) {
  if (!portTriesOn(form, enums)) return ''
  return portTriesRangeErr(form)
}

export function bandFormErr(form, enums) {
  return bandOn(form, enums) ? bandErr(form) : ''
}

export function cdnShapeValue(form, name, enums) {
  const field = cdnShape(enums)[name]
  const raw = String(form.cdn[name] || '').trim()
  if (raw === '') return field.d
  const n = parseInt(raw, 10)
  return isNaN(n) ? NaN : n
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
