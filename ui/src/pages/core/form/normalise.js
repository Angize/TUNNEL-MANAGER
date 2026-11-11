import { RAW_PROTO_BARE } from '../carrier.js'
import {
  coverOk,
  desyncOk,
  dsSumOk,
  fecDatagram,
  protoVisOn,
  rawPorted,
  rawUpPorted,
  rotIsDirect,
  rotMulti,
  wkCarrier,
  wkShared,
  wssMandatory,
} from './gates.js'
import { cdnAuto } from '../../../lib/cdn.js'

export default function normalise(form, cfg, aIps, bIps) {
  const patch = {}
  const at = (key) => (key in patch ? patch[key] : form[key])
  const set = (key, value) => {
    if (at(key) !== value) patch[key] = value
  }
  const enums = cfg.enums

  if (at('Tr') === 'raw' && at('cipher') === 'none') set('cipher', 'auto')
  if (at('cipher') === 'none') set('Obfs', false)
  if (!coverOk({ ...form, ...patch })) set('Cover', false)

  const view = { ...form, ...patch }
  if (!fecDatagram(view)) set('Fec', false)
  if (!wkCarrier({ ...view, Fec: at('Fec') })) {
    set('WorkersA', 1)
    set('WorkersB', 1)
  }
  if (wkShared(view)) set('WorkersB', at('WorkersA'))
  if (!desyncOk(view)) set('Desync', false)
  if (!dsSumOk(view, enums)) set('DesyncMode', 'ttl')
  if (!rawPorted(view, enums)) {
    set('Sprot', false)
    set('Ctb', false)
  }
  if (!rawUpPorted(view, enums)) {
    set('SportRandom', false)
    set('rawDports', '')
  }
  if (!(at('Tr') === 'ws' && at('Ech'))) set('EchProxy', false)
  if (wssMandatory(view)) set('WsTls', true)

  if (protoVisOn(view) && at('rawProto') === '') set('rawProto', String(RAW_PROTO_BARE))
  if (rawPorted(view, enums)) {
    if (at('rawPort') === '') set('rawPort', String(cfg.defaults.raw_port))
    if (at('SportRandom')) set('rawSport', '')
    else if (at('rawSport') === '') set('rawSport', String(cfg.defaults.raw_sport))
  }

  if (at('Tr') === 'raw') {
    set('port', '')
    set('portAuto', false)
  } else if (at('Tr') === 'ws' && !cdnAuto({ ...form, ...patch })) {
    if (at('port') === '' || (at('portAuto') && at('port') !== '80')) {
      set('port', '80')
      set('portAuto', true)
    }
  } else if (at('portAuto') && at('port') === '80') {
    set('port', '')
    set('portAuto', false)
  }

  const ipsKnown = aIps.length > 0 && bIps.length > 0
  if (form.rot.on && !(rotIsDirect(view, enums) && (!ipsKnown || rotMulti(view, enums, aIps, bIps)))) {
    patch.rot = { ...form.rot, on: false }
  }

  return Object.keys(patch).length ? { ...form, ...patch } : form
}
