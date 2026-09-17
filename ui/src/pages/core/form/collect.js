import { T } from '../../../i18n/fa.js'
import {
  bandOn,
  cdnShapeApplies,
  ctbOn,
  desyncOk,
  dsTtlUsed,
  fecDatagram,
  portTriesOn,
  rawPortOn,
  sprotLive,
  wkCarrier,
  wkClamp,
} from './gates.js'
import { CDN_FIELD_NAMES, cdnShape } from './presets.js'
import {
  bandErr,
  cdnShapeErr,
  cdnShapeValue,
  intOf,
  portErr,
  portTriesErr,
  portTriesValue,
  rawProtoErr,
  sportErr,
  sprotErr,
} from './validate.js'

function poolCollect(form, body) {
  const pool = form.pool
  if (!pool.pool) {
    body.ws_pool = false
    return ''
  }
  if (!pool.ip.length) return T('pool_need_ip')
  if (!pool.sni.length) return T('pool_need_clean')
  if (pool.ip.length < 2 && pool.sni.length < 2) return T('pool_need_axis')
  body.ws_pool = true
  body.ws_tls = true
  body.ws_edge_ips = pool.ip
  body.ws_edge_snis = pool.sni
  body.ws_rotate_secs = pool.rotate
  return ''
}

function rotPicked(ips, selected) {
  if (!ips.length) return Object.keys(selected).filter((ip) => selected[ip])
  return ips.filter((ip) => selected[ip])
}

export function rotCollect(form, aIps, bIps) {
  if (!form.rot.on) return null
  const a = rotPicked(aIps, form.rot.aSel)
  const b = rotPicked(bIps, form.rot.bSel)
  if (a.length < 2 && b.length < 2) return null
  return { a_ip_pool: a, b_ip_pool: b, rotate_secs: form.rot.secs }
}

export function rotValidate(form, aIps, bIps) {
  if (!form.rot.on) return ''
  if (rotPicked(aIps, form.rot.aSel).length < 2 && rotPicked(bIps, form.rot.bSel).length < 2) {
    return T('rot_min2')
  }
  return ''
}

export function collectCarrier(form, cfg, body) {
  const enums = cfg.enums

  if (form.Tr === 'raw') {
    if (form.cipher === 'none') return T('raw_need_enc')
    body.raw_profile = form.RawProfile
    if (form.RawProfile === 'bare') {
      const protoError = rawProtoErr(form.rawProto, enums)
      if (protoError) return protoError
      body.raw_proto = parseInt(form.rawProto || '253', 10)
    }
    const sprotError = sprotErr(form)
    if (sprotError) return sprotError
    body.raw_sport_rotate = sprotLive(form) ? intOf(form.rawSprot) : 0
    body.raw_dports = sprotLive(form) ? intOf(form.rawDports) : 0
    body.conntrack_bypass = ctbOn(form, enums) && !!form.Ctb
    if (rawPortOn(form)) {
      const dportError = portErr(form.rawPort)
      if (dportError) return dportError
      const dport = parseInt(form.rawPort, 10)
      body.raw_port = dport >= 1 && dport <= 65535 ? dport : 0
      if (body.raw_sport_rotate) {
        body.raw_sport_random = false
        body.raw_sport = 0
      } else {
        const sportError = sportErr(form.rawSport)
        if (sportError) return sportError
        body.raw_sport_random = !!form.SportRandom
        const sport = parseInt(form.rawSport, 10)
        body.raw_sport = !form.SportRandom && sport >= 1 && sport <= 65535 ? sport : 0
      }
    }
  }

  const bandError = bandOn(form, enums) ? bandErr(form) : ''
  if (bandError) return bandError
  if (bandOn(form, enums)) {
    body.sport_lo = intOf(form.bandLo)
    body.sport_hi = intOf(form.bandHi)
  }

  const triesError = portTriesErr(form, enums)
  if (triesError) return triesError
  if (portTriesOn(form, enums)) body.port_tries = portTriesValue(form)

  if (fecDatagram(form)) {
    body.fec = !!form.Fec
    if (body.fec) {
      body.fec_data = form.FecData
      body.fec_parity = form.FecParity
    }
  }

  if (wkCarrier(form)) {
    body.a_workers = wkClamp(form.WorkersA, cfg.workers_max)
    body.b_workers = wkClamp(form.WorkersB, cfg.workers_max)
  }

  if (desyncOk(form)) {
    body.fake_desync = form.Desync
    if (form.Desync) {
      if (dsTtlUsed(form)) body.fake_ttl = parseInt(form.dsTtl, 10) || 4
      body.fake_count = parseInt(form.dsCount, 10) || 2
      body.fake_mode = form.DesyncMode
      if (body.fake_mode === 'both' && body.fake_count < 2) return T('ds_both_needs2')
    }
  }

  if (form.Tr === 'ws') {
    body.ws_path = form.wsPath.trim()
    body.ws_tls = form.WsTls
    body.ech = form.Ech
    body.ech_proxy = form.Ech && form.EchProxy
    if (form.Ech && form.EchProxy) body.ech_proxy_id = form.echProxyId
    body.sni_split = form.SniSplit
    if (form.SniSplit) {
      body.split_pos = parseInt(form.splitPos, 10) || 0
      body.sni_mode = form.SniMode
      if (form.SniMode === 'disorder') body.split_ttl = parseInt(form.splitTtl, 10) || 0
      if (form.Ech && !body.split_pos) return T('sni_ech_need_pos')
    }
    body.cdn_carrier = form.Cdn
    if (form.Cdn === 'http' || form.Cdn === 'grpc') {
      const shapeError = cdnShapeErr(form, enums)
      if (shapeError) return shapeError
      const shape = cdnShape(enums)
      for (const name of CDN_FIELD_NAMES) {
        const field = shape[name]
        if (!cdnShapeApplies(field, form.Cdn, enums)) continue
        const value = cdnShapeValue(form, name, enums)
        body[field.k] =
          isNaN(value) || value < field.lo || value > field.hi ? field.d : value
      }
    }
    if (form.pool.pool) {
      const poolError = poolCollect(form, body)
      if (poolError) return poolError
    } else {
      body.ws_pool = false
      body.ws_host = form.wsHost.trim()
      body.edge_ip = form.wsEdge.trim()
      if (form.WsTls && !body.ws_host) return T('wss_need_host')
      if (form.WsTls && !body.edge_ip) return T('wss_need_edge')
      if (form.Ech && !form.WsTls) return T('ech_need_wss')
      if (form.Cdn === 'grpc' && !form.WsTls) return T('cdn_need_wss')
    }
  }

  return ''
}
