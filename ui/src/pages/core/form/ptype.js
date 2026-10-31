import { latinDigits } from '../../../lib/num.js'
import { T } from '../../../i18n/fa.js'

export function ptypeHex(value) {
  return value ? value.toString(16).padStart(4, '0') : ''
}

export function ptypeInt(hex) {
  return parseInt(hex || '0', 16)
}

export function cleanPtype(text) {
  return latinDigits(text).trim().toLowerCase().replace(/^0x/, '').replace(/[^0-9a-f]/g, '').slice(0, 4)
}

export function ptypeErr(hex) {
  return hex && !ptypeInt(hex) ? T('raw_ptype_bad') : ''
}
