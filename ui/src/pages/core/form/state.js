import { num } from '../../../lib/num.js'
import { subnetBaseOf } from '../../../lib/subnet.js'
import { wkClamp } from './gates.js'
import { CDN_FIELD_NAMES, cdnShape } from './presets.js'

function cdnInitial(enums, link) {
  const shape = cdnShape(enums)
  const out = {}
  for (const name of CDN_FIELD_NAMES) {
    const field = shape[name]
    out[name] = String((link && link[field.k]) || field.d)
  }
  return out
}

function textOf(value) {
  return value ? String(value) : ''
}

export function createForm(cfg) {
  return {
    Srv: 'a',
    Tr: 'udp',
    Obfs: true,
    Cover: false,
    RawProfile: 'bare',
    SportRandom: false,
    Sprot: false,
    Ctb: false,
    Gso: false,
    WsTls: false,
    Ech: false,
    EchProxy: false,
    SniSplit: false,
    SniMode: 'split',
    Cdn: 'ws',
    Fec: false,
    FecData: 16,
    FecParity: 4,
    Desync: false,
    DesyncMode: 'ttl',
    WorkersA: 1,
    WorkersB: 1,

    cipher: 'auto',
    rawProto: '',
    rawPort: '',
    rawSport: '',
    rawSprot: '',
    rawDports: '',
    bandLo: '',
    bandHi: '',
    portTries: '',
    dsTtl: '4',
    dsCount: '2',
    splitPos: '0',
    splitTtl: '0',
    wsHost: '',
    wsEdge: '',
    wsPath: '',
    echProxyId: '',
    coverSni: '',
    port: '',
    portAuto: false,
    range: '192.168',
    subnet: '',
    cdn: cdnInitial(cfg.enums, null),

    aNode: '',
    bNode: '',
    aIp: '',
    bIp: '',
    rot: { on: false, secs: 600, aSel: {}, bSel: {} },
    pool: { pool: false, rotate: 600, ip: [], sni: [] },
  }
}

export function editForm(cfg, link) {
  const transport = ['tcp', 'raw', 'ws'].includes(link.transport) ? link.transport : 'udp'
  const rotSel = (list, single) => {
    const out = {}
    for (const ip of list || []) out[ip] = true
    if (single) out[single] = true
    return out
  }

  return {
    Srv: link.server_side === 'b' ? 'b' : 'a',
    Tr: transport,
    Obfs: !!link.obfs,
    Cover: !!link.cover && transport === 'tcp',
    RawProfile: link.raw_profile || 'bare',
    SportRandom: !!link.raw_sport_random,
    Sprot: !!link.raw_sport_rotate,
    Ctb: !!link.conntrack_bypass,
    Gso: !!link.gso,
    WsTls: !!link.ws_tls,
    Ech: !!link.ech,
    EchProxy: !!link.ech_proxy,
    SniSplit: !!link.sni_split,
    SniMode:
      link.sni_mode === 'disorder' || link.sni_mode === 'fake' ? link.sni_mode : 'split',
    Cdn:
      link.cdn_carrier === 'http' || link.cdn_carrier === 'grpc' ? link.cdn_carrier : 'ws',
    Fec: !!link.fec,
    FecData: link.fec_data || 16,
    FecParity: link.fec_parity || 4,
    Desync: !!link.fake_desync,
    DesyncMode: link.fake_mode || 'ttl',
    WorkersA: wkClamp(link.a_workers, cfg.workers_max),
    WorkersB: wkClamp(link.b_workers, cfg.workers_max),

    cipher: link.cipher || 'auto',
    rawProto: textOf(link.raw_proto),
    rawPort: textOf(link.raw_port),
    rawSport: textOf(link.raw_sport),
    rawSprot: textOf(link.raw_sport_rotate),
    rawDports: textOf(link.raw_dports),
    bandLo: textOf(link.sport_lo),
    bandHi: textOf(link.sport_hi),
    portTries: textOf(link.port_tries),
    dsTtl: String(link.fake_ttl || 4),
    dsCount: String(link.fake_count || 2),
    splitPos: String(link.split_pos || 0),
    splitTtl: String(link.split_ttl || 0),
    wsHost: link.ws_host || '',
    wsEdge: link.edge_ip || '',
    wsPath: link.ws_path || '',
    echProxyId: link.ech_proxy_id || '',
    coverSni: link.cover_sni || '',
    port: textOf(link.port),
    portAuto: false,
    range: subnetBaseOf(link),
    subnet: link.subnet || '',
    cdn: cdnInitial(cfg.enums, link),

    aNode: link.a_node,
    bNode: link.b_node,
    aIp: '',
    bIp: '',
    rot: {
      on: !!link.ip_rotate,
      secs: link.rotate_secs != null ? link.rotate_secs : 600,
      aSel: rotSel(link.a_ip_pool, link.a_ip),
      bSel: rotSel(link.b_ip_pool, link.b_ip),
    },
    pool: {
      pool: !!link.ws_pool,
      rotate: link.ws_rotate_secs != null ? link.ws_rotate_secs : 600,
      portRoll: !!link.ws_port_roll,
      ip: (link.ws_edge_ips || []).slice(),
      sni: (link.ws_edge_snis || []).map((s) => (s && s.host) || '').filter(Boolean),
    },
  }
}

export function nodeItemsForEdit(nodes, link) {
  const out = []
  const seen = {}
  for (const node of nodes || []) {
    if (!node.online) continue
    seen[node.id] = true
    out.push({ v: node.id, label: node.name, sub: node.host })
  }
  for (const [id, name] of [
    [link.a_node, link.a_name],
    [link.b_node, link.b_name],
  ]) {
    if (!id || seen[id]) continue
    seen[id] = true
    const node = (nodes || []).find((x) => x.id === id)
    out.push({ v: id, label: (node && node.name) || name || id, sub: (node && node.host) || '' })
  }
  return out
}

export function seedIp(ips, chosen, stored) {
  if (chosen && ips.includes(chosen)) return chosen
  if (stored && ips.includes(stored)) return stored
  return ips[0]
}

export function pickedIp(form, ips, selected, chosen, stored) {
  if (form.rot.on && ips.length > 1) {
    if (stored && selected[stored]) return stored
    return ips.find((ip) => selected[ip]) || seedIp(ips, chosen, stored) || ''
  }
  if (ips.length > 1) return seedIp(ips, chosen, stored) || ''
  return stored && ips.includes(stored) ? stored : ''
}

export function rotCount(ips, selected) {
  return ips.filter((ip) => selected[ip]).length
}

export function nodeCpus(nodes, id) {
  const node = (nodes || []).find((n) => n.id === id)
  return node ? num(node.cpus) : 0
}

export function nodeLabel(items, id) {
  const item = (items || []).find((x) => x.v === id)
  return (item && item.label) || id
}
