import { KvRow, Sep } from '../../components/Kv.jsx'
import { T } from '../../i18n/fa.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { num } from '../../lib/num.js'
import { RAW_DPORT_DEFAULT, RAW_ROT_HI, RAW_ROT_LO, RAW_SPORT_FIXED } from './carrier.js'

function count(n) {
  return Number(n).toLocaleString('en-US')
}

function RotatingSource({ link, every }) {
  const live = link.rot_live || {}
  const client = num(live.cli)
  const server = num(live.srv)
  const lo = num(live.lo) || RAW_ROT_LO
  const hi = num(live.hi) || RAW_ROT_HI
  const drawn = num(live.drawn)
  const mode = every ? T('port_src_rot') : T('port_src_rand')
  const clock = every ? T('port_src_rot_every').replace('{n}', every) : T('port_src_rot_fail')

  return (
    <>
      <KvRow label={T('port_src')}>{mode}</KvRow>
      <KvRow label={T('port_rot')} wide>
        {client ? (
          <>
            <span className="dim">{T('client')}</span>
            <b className="mono">{client}</b>
            <Sep />
          </>
        ) : null}
        {server ? (
          <>
            <span className="dim">{T('server')}</span>
            <b className="mono">{server}</b>
            <Sep />
          </>
        ) : null}
        <b className="mono">{lo + '-' + hi}</b>
        <Sep />
        <span>{clock}</span>
        {drawn ? (
          <>
            <Sep />
            <span>{T('port_src_rot_drawn').replace('{n}', count(drawn))}</span>
          </>
        ) : null}
      </KvRow>
    </>
  )
}

export default function PortRows({ link }) {
  const { enums } = useUiConfig()
  const portRungTransports = (enums && enums.tr_rung) || []
  const transport = link.transport || 'udp'
  const sportLive = num(link.sport_live)

  if (transport === 'raw') {
    if (link.raw_profile !== 'udp' && link.raw_profile !== 'tcp') return null
    const live = link.rot_live || {}
    const dports = num(live.dports)
    const liveDport = num(live.dport) || num(link.raw_port) || RAW_DPORT_DEFAULT
    const rotateEvery = num(link.raw_sport_rotate)

    return (
      <>
        <KvRow label={T('port_dst')}>
          <b className="mono">{dports > 1 ? liveDport : num(link.raw_port) || RAW_DPORT_DEFAULT}</b>
          {dports > 1 ? (
            <>
              <Sep />
              <span className="dim">
                {T('port_dst_rot') + ' · ' + T('port_dst_rot_n').replace('{n}', String(dports))}
              </span>
            </>
          ) : null}
        </KvRow>
        {rotateEvery || link.raw_sport_random ? (
          <RotatingSource link={link} every={rotateEvery} />
        ) : (
          <KvRow label={T('port_src')}>
            <b className="mono">{sportLive || num(link.raw_sport) || RAW_SPORT_FIXED}</b>
            <Sep />
            <span className="dim">{T('port_src_fixed')}</span>
          </KvRow>
        )}
      </>
    )
  }

  return (
    <>
      {link.port ? (
        <KvRow label={T('port')} mono>
          {link.port}
        </KvRow>
      ) : null}
      {sportLive && portRungTransports.includes(transport) ? (
        <KvRow label={T('port_src')} mono>
          {sportLive}
        </KvRow>
      ) : null}
    </>
  )
}
