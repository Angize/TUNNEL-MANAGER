import { T } from '../../i18n/fa.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { num } from '../../lib/num.js'
import { RAW_DPORT_DEFAULT, RAW_ROT_HI, RAW_ROT_LO, RAW_SPORT_FIXED } from './carrier.js'

function RotatingSourceRows({ link, every }) {
  const live = link.rot_live || {}
  const client = num(live.cli)
  const server = num(live.srv)
  const lo = num(live.lo) || RAW_ROT_LO
  const hi = num(live.hi) || RAW_ROT_HI
  const mode = every ? T('port_src_rot') : T('port_src_rand')
  const clock = every ? T('port_src_rot_every').replace('{n}', every) : T('port_src_rot_fail')
  const drawn = num(live.drawn)

  let band = mode + ' · ' + lo + '-' + hi + ' · ' + clock
  if (drawn) band += ' · ' + T('port_src_rot_drawn').replace('{n}', String(drawn))

  if (!client && !server) {
    return (
      <>
        <div>
          {T('port_src')}: <b className="mono">{mode}</b>
        </div>
        <div className="wrap muted">{band}</div>
      </>
    )
  }

  return (
    <>
      {client ? (
        <div>
          {T('port_src_rot_up')}: <b className="mono">{client}</b>
        </div>
      ) : null}
      {server ? (
        <div>
          {T('port_src_rot_down')}: <b className="mono">{server}</b>
        </div>
      ) : null}
      <div className="wrap muted">{band}</div>
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
        <div>
          {T('port_dst')}:{' '}
          <b className="mono">
            {dports > 1 ? liveDport : num(link.raw_port) || RAW_DPORT_DEFAULT}
          </b>
        </div>
        {dports > 1 ? (
          <div className="wrap muted">
            {T('port_dst_rot') + ' · ' + T('port_dst_rot_n').replace('{n}', String(dports))}
          </div>
        ) : null}
        {rotateEvery || link.raw_sport_random ? (
          <RotatingSourceRows link={link} every={rotateEvery} />
        ) : (
          <div>
            {T('port_src')}:{' '}
            <b className="mono">
              {T('port_src_fixed') +
                ' (' +
                (sportLive || num(link.raw_sport) || RAW_SPORT_FIXED) +
                ')'}
            </b>
          </div>
        )}
      </>
    )
  }

  return (
    <>
      {link.port ? (
        <div>
          {T('port')}: <b className="mono">{link.port}</b>
        </div>
      ) : null}
      {sportLive && portRungTransports.includes(transport) ? (
        <div>
          {T('port_src')}: <b className="mono">{sportLive}</b>
        </div>
      ) : null}
    </>
  )
}
