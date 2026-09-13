import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import PortRows from './PortRows.jsx'
import { CT_WARN_PCT, carrierFamily, carrierLabel, carrierProfile, edgeHost } from './carrier.js'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

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

  const parts = T('ctb_warn')
    .replace('{p}', String(pct))
    .replace('{c}', String(num(ct.count)))
    .replace('{m}', String(num(ct.max)))
    .split('{n}')

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

export default function CoreMeta({ link, activeEdge }) {
  const family = carrierFamily(link)
  const profile = carrierProfile(link)
  const caps = capabilities(link)
  const cipher = link.cipher && link.cipher !== 'none'

  return (
    <>
      <div className="enmeta">
        <div className="emcol">
          <div>
            {T('subnet')}: <CopyValue text={link.subnet} />
          </div>
          <PortRows link={link} />
          <div>
            {T('iface')}: <b className="mono">{link.name}</b>
          </div>
        </div>
        <span className="tnarrow earrow">↔</span>
        <div className="emcol">
          <div className="tagrow">
            {T('ttype')}: <span className={'ctag c-' + family}>{carrierLabel(link)}</span>
          </div>
          {profile ? (
            <div>
              {T('profile')}: <b className="mono">{profile}</b>
            </div>
          ) : null}
          <div className="feat">
            {T('caps')}:{' '}
            {caps.length ? (
              caps.map((tag, i) => (
                <span key={tag + i}>
                  {i ? ' ' : null}
                  <span className="tag obfs">{tag}</span>
                </span>
              ))
            ) : (
              <span className="nofeat">—</span>
            )}
          </div>
          <div className="enc-line">
            {T('enc')}:{' '}
            {cipher ? (
              <span className="encval">
                {link.cipher === 'auto' ? 'aes-256-gcm' : link.cipher}
              </span>
            ) : (
              <b>{T('no_cipher')}</b>
            )}
          </div>
        </div>
        <ConntrackWarning link={link} />
      </div>
      <EdgeBlock link={link} activeEdge={activeEdge} />
    </>
  )
}
