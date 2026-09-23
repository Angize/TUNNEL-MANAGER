import { Fragment } from 'react'
import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import {
  CT_WARN_PCT,
  RAW_DPORT_DEFAULT,
  RAW_ROT_HI,
  RAW_ROT_LO,
  RAW_SPORT_FIXED,
  carrierFamily,
  carrierLabel,
  carrierProfile,
  edgeHost,
} from './carrier.js'
import { poolRotateItems } from './form/presets.js'
import { hostAddress } from '../../lib/subnet.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

const SERVER_HOST = 1
const CLIENT_HOST = 2
const CAPS_PER_CELL = 2
const SHORT_CAP = 4
const POOL_ROTATE_DEFAULT = 600
const compact = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 })

function capabilities(link) {
  const tags = []
  if (link.transport === 'ws' && link.ws_pool) tags.push('pool')
  if (link.transport === 'ws' && link.ws_tls) tags.push('wss')
  if (link.sni_split) tags.push('SNI' + (link.sni_mode || 'split'))
  if (link.transport === 'ws' && link.ech) tags.push('ECH')
  if (link.obfs) tags.push('obfs')
  if (link.cover) tags.push('TLS')
  if (link.gso) tags.push('GSO')
  if (link.fec) tags.push('FEC ' + ((link.fec_data || 16) + '+' + (link.fec_parity || 4)))
  if (link.fake_desync) tags.push('desync')
  return tags
}

function ConntrackWarning({ link }) {
  if (link.transport !== 'raw' || link.conntrack_bypass) return null
  if (link.raw_profile !== 'udp' && link.raw_profile !== 'tcp') return null
  if (!num(link.raw_sport_rotate) && !link.raw_sport_random) return null

  const ct = link.ct || {}
  const pct = num(ct.pct)
  if (!pct || pct < CT_WARN_PCT) return null

  const parts = T('ctb_warn').replace('{p}', String(pct)).split('{n}')

  return (
    <div className="warncap no emwarn">
      <Icon name="warn" />
      <span>
        {parts[0]}
        <b className="mono iso">{String(ct.node || '')}</b>
        {parts[1]}
      </span>
    </div>
  )
}

function EdgeChips({ ip, domain }) {
  if (!ip && !domain) return <span className="echip wait">…</span>
  return (
    <>
      {ip ? <span className="echip ip">{ip}</span> : null}
      {domain ? <span className="echip dom">{domain}</span> : null}
    </>
  )
}

function EdgeBlock({ link, activeEdge }) {
  if (link.transport !== 'ws') return null

  if (link.ws_pool) {
    if (link.enabled === false) return null
    const parts = String(activeEdge || '').split(' · ')
    return (
      <div className="cedge live">
        <div className="ct">
          <span className="cdot" />
          {T('active_edge')}
        </div>
        <div className="echips">
          <EdgeChips ip={edgeHost(parts[0] || '')} domain={parts.slice(1).join(' · ')} />
        </div>
      </div>
    )
  }

  const ip = link.edge_ip ? edgeHost(link.edge_ip) : ''
  const domain = link.ws_host || ''
  if (!ip && !domain) return null

  return (
    <div className="cedge">
      <div className="ct">{T('cdn_edge')}</div>
      <div className="echips">
        <EdgeChips ip={ip} domain={domain} />
      </div>
    </div>
  )
}

function cell(label, value) {
  return { label, value }
}

function mono(value) {
  return <b className="mono">{value}</b>
}

function portCell(label, port) {
  return cell(label, mono(num(port) || '—'))
}

function TunnelIp({ subnet, host }) {
  const [ip, prefix] = hostAddress(subnet, host).split('/')
  return (
    <span className="iso">
      <CopyValue text={ip} />
      {prefix ? mono('/' + prefix) : null}
    </span>
  )
}

function rawPorted(link) {
  return link.transport === 'raw' && (link.raw_profile === 'udp' || link.raw_profile === 'tcp')
}

function rawRotating(link) {
  return !!num(link.raw_sport_rotate) || !!link.raw_sport_random
}

function sidePorts(link, rungTransports) {
  const transport = link.transport || 'udp'
  if (transport === 'raw') {
    if (!rawPorted(link)) return []
    const live = link.rot_live || {}
    const incoming = num(live.dport) || num(link.raw_port) || RAW_DPORT_DEFAULT
    if (!rawRotating(link)) {
      const client = num(link.sport_live) || num(link.raw_sport) || RAW_SPORT_FIXED
      return [[portCell(T('port_src'), client), portCell(T('port_in'), incoming)]]
    }
    return [
      [portCell(T('port_src'), live.cli), portCell(T('port_in'), incoming)],
      [portCell(T('port_in'), live.cli), portCell(T('port_src'), live.srv)],
    ]
  }
  const client = rungTransports.includes(transport) ? num(link.sport_live) : 0
  const server = num(link.port)
  if (!client && !server) return []
  return [[portCell(T('port_src'), client), portCell(T('port_in'), server)]]
}

function capCells(link) {
  const tags = capabilities(link)
  if (!tags.length) return []
  const short = (tag) => !!tag && tag.length <= SHORT_CAP
  const first = short(tags[0]) && short(tags[1]) ? CAPS_PER_CELL : 1
  const chunks = [tags.slice(0, first)]
  for (let i = first; i < tags.length; i += CAPS_PER_CELL) chunks.push(tags.slice(i, i + CAPS_PER_CELL))
  return chunks.map((chunk, i) =>
    cell(
      i ? '' : T('caps'),
      chunk.map((tag) => (
        <span key={tag} className="tag obfs">
          {tag}
        </span>
      ))
    )
  )
}

function rawCells(link) {
  if (!rawPorted(link)) return []
  const live = link.rot_live || {}
  const cells = []
  const dports = num(live.dports) || num(link.raw_dports)
  if (dports > 1) cells.push(cell(T('rot_in'), <b>{T('n_ports').replace('{n}', String(dports))}</b>))
  if (!rawRotating(link)) return cells

  const every = num(link.raw_sport_rotate)
  const lo = num(live.lo) || num(link.sport_lo) || RAW_ROT_LO
  const hi = num(live.hi) || num(link.sport_hi) || RAW_ROT_HI
  const drawn = num(live.drawn)
  cells.push(cell(T('rot_src'), <b>{every ? T('rot_every').replace('{n}', String(every)) : T('rot_on_fail')}</b>))
  cells.push(cell(T('rot_band'), <b className="mono iso">{lo + '–' + hi}</b>))
  if (drawn) cells.push(cell(T('rot_drawn'), <b>{T('n_ports').replace('{n}', compact.format(drawn))}</b>))
  return cells
}

function edgeRotation(link) {
  const secs = link.ws_rotate_secs != null ? num(link.ws_rotate_secs) : POOL_ROTATE_DEFAULT
  if (!secs) return T('rot_on_fail')
  const item = poolRotateItems().find((x) => x.v === secs)
  return item ? item.label : secs + 's'
}

function sharedCells(link) {
  const profile = carrierProfile(link)
  const cipher = link.cipher && link.cipher !== 'none' ? (link.cipher === 'auto' ? 'aes-256-gcm' : link.cipher) : ''
  const cells = [
    cell(
      T('ttype'),
      <span className={'ctag c-' + carrierFamily(link)}>
        {carrierLabel(link) + (profile ? ' · ' + profile : '')}
      </span>
    ),
    cell(
      T('enc_short'),
      cipher ? (
        <span className="encval" title={cipher}>
          {cipher.replace('-poly1305', '')}
        </span>
      ) : (
        <b>{T('no_cipher')}</b>
      )
    ),
    ...capCells(link),
    ...rawCells(link),
  ]
  if (link.transport === 'ws' && link.ws_pool) cells.push(cell(T('rot_edge'), <b>{edgeRotation(link)}</b>))
  return cells
}

function pairs(cells) {
  const rows = []
  for (let i = 0; i < cells.length; i += 2) rows.push([cells[i + 1] || null, cells[i]])
  return rows
}

function Cell({ c }) {
  return (
    <div className="cgc">
      {c && c.label ? c.label + ': ' : null}
      {c ? c.value : null}
    </div>
  )
}

export default function CoreMeta({ link, activeEdge }) {
  const { enums } = useUiConfig()
  const rungTransports = (enums && enums.tr_rung) || []
  const rows = [
    [
      cell(T('tun_ip'), <TunnelIp subnet={link.subnet} host={CLIENT_HOST} />),
      cell(T('tun_ip'), <TunnelIp subnet={link.subnet} host={SERVER_HOST} />),
    ],
    ...sidePorts(link, rungTransports),
    ...pairs(sharedCells(link)),
  ]

  return (
    <>
      <div className="enmeta cgrid">
        {rows.map(([client, server], i) => (
          <Fragment key={i}>
            <Cell c={client} />
            {i ? (
              <i />
            ) : (
              <span className="tnarrow earrow">
                <Icon name="arrows" />
              </span>
            )}
            <Cell c={server} />
          </Fragment>
        ))}
      </div>
      <ConntrackWarning link={link} />
      <EdgeBlock link={link} activeEdge={activeEdge} />
    </>
  )
}
