import { RAW_DPORT_DEFAULT, RAW_SPORT_FIXED } from '../carrier.js'
import {
  ctbOn,
  desyncOk,
  fecDatagram,
  protoVisOn,
  rawPortOn,
  rotIsDirect,
  rotMulti,
  sprotOn,
  wkCarrier,
  wssMandatory,
} from './gates.js'

const DS_TTL_CAP = 8

export default function normalise(form, cfg, aIps, bIps) {
  const patch = {}
  const at = (key) => (key in patch ? patch[key] : form[key])
  const set = (key, value) => {
    if (at(key) !== value) patch[key] = value
  }
  const enums = cfg.enums

  if (at('Tr') === 'raw' && at('cipher') === 'none') set('cipher', 'auto')
  if (at('cipher') === 'none') set('Obfs', false)
  if (!(at('Tr') === 'tcp' && at('cipher') !== 'none')) set('Cover', false)

  const view = { ...form, ...patch }
  if (!fecDatagram(view)) set('Fec', false)
  if (!wkCarrier({ ...view, Fec: at('Fec') })) {
    set('WorkersA', 1)
    set('WorkersB', 1)
  }
  if (!desyncOk(view)) set('Desync', false)
  if (parseInt(at('dsTtl'), 10) > DS_TTL_CAP) set('dsTtl', String(DS_TTL_CAP))
  if (!sprotOn(view)) set('Sprot', false)
  if (!ctbOn({ ...view, Sprot: at('Sprot') }, enums)) set('Ctb', false)
  if (!(at('Tr') === 'ws' && at('Ech'))) set('EchProxy', false)
  if (wssMandatory(view, form.pool)) set('WsTls', true)

  if (protoVisOn(view) && at('rawProto') === '') set('rawProto', '253')
  if (rawPortOn(view)) {
    if (at('rawPort') === '') set('rawPort', String(RAW_DPORT_DEFAULT))
    if (at('SportRandom')) set('rawSport', '')
    else if (at('rawSport') === '') set('rawSport', String(RAW_SPORT_FIXED))
  }

  if (at('Tr') === 'raw') {
    set('port', '')
    set('portAuto', false)
  } else if (at('Tr') === 'ws') {
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
