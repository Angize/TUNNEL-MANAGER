export function rawPorted(form, enums) {
  return form.Tr === 'raw' && ((enums && enums.raw_ported) || []).includes(form.RawProfile)
}

export function wsPoolOn(form) {
  return form.Tr === 'ws' && !!(form.pool && form.pool.pool)
}

export function portTriesOn(form, enums) {
  if (form.Tr === 'raw') return rawPorted(form, enums) && !!form.SportRandom
  if (wsPoolOn(form) && !form.pool.portRoll) return false
  return ((enums && enums.tr_rung) || []).includes(form.Tr)
}

export function bandOn(form, enums) {
  if (form.Tr === 'raw') return rawPorted(form, enums) && (!!form.SportRandom || !!form.Sprot)
  return ((enums && enums.tr_rung) || []).includes(form.Tr)
}

export function ctbOn(form, enums) {
  return rawPorted(form, enums)
}

export function sprotLive(form) {
  return rawPortOn(form) && !!form.Sprot
}

export function rawPortOn(form) {
  return form.Tr === 'raw' && (form.RawProfile === 'udp' || form.RawProfile === 'tcp')
}

export function protoVisOn(form) {
  return form.Tr === 'raw' && form.RawProfile === 'bare'
}

export function fecDatagram(form) {
  return form.Tr === 'udp' || form.Tr === 'raw'
}

export function wkCarrier(form) {
  if (form.Tr === 'tcp') return true
  if (form.Tr === 'ws') return form.Cdn === 'ws'
  return (form.Tr === 'raw' || form.Tr === 'udp') && !form.Fec
}

export function wkClamp(n, max) {
  const value = parseInt(n, 10)
  return value >= 1 && value <= max ? value : 1
}

export function desyncOk(form) {
  return form.Tr === 'raw' || form.Tr === 'tcp' || (form.Tr === 'ws' && form.Cdn === 'ws')
}

export function dsTtlUsed(form) {
  return !(form.Tr === 'raw' && form.DesyncMode === 'badsum')
}

export function wsProfOf(cdn) {
  return cdn === 'http' || cdn === 'grpc' ? cdn : 'ws'
}

export function cdnShapeOn(form) {
  return form.Tr === 'ws' && (form.Cdn === 'http' || form.Cdn === 'grpc')
}

export function cdnShapeApplies(field, cdn, enums) {
  return cdn === 'http' || ((enums && enums.http_shape_grpc) || []).includes(field.k)
}

export function coverOk(form) {
  return form.Tr === 'tcp' && form.cipher !== 'none'
}

export function wssMandatory(form, pool) {
  return form.Tr === 'ws' && (pool.pool || form.Cdn === 'grpc')
}

export function rotIsDirect(form, enums) {
  return ((enums && enums.tr_direct) || []).includes(form.Tr)
}

export function rotMulti(form, enums, aIps, bIps) {
  return (aIps.length > 1 || bIps.length > 1) && rotIsDirect(form, enums)
}
