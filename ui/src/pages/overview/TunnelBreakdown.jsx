import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'

const TYPE_COLORS = [
  ['core', '#6366f1'],
  ['vxlan', 'var(--acc)'],
  ['gre', 'var(--ok)'],
  ['sit', '#a855f7'],
  ['ipip', '#14b8a6'],
  ['l2tpv3', '#8b5cf6'],
  ['fou', '#ec4899'],
  ['ipsec', '#f43f5e'],
]

function StateTile({ value, label, color }) {
  return (
    <div className="tb">
      <div className="n" style={{ color }}>
        {value}
      </div>
      <div className="l">{label}</div>
    </div>
  )
}

function WorstTunnelNote({ worst, fleetPing, trouble, counted }) {
  if (!worst) {
    if (!counted) return null
    return (
      <div className="onote">
        {trouble ? (
          <>
            <Icon name="warn" color="var(--bad)" /> {T('ov_trouble')}
          </>
        ) : (
          <>
            <Icon name="okc" color="var(--ok)" /> {T('ov_all_good')}
          </>
        )}
        {fleetPing != null ? (
          <>
            {' · '}
            {T('ov_fleet_ping')} <b style={{ color: 'var(--tx)' }}>{num(fleetPing)}ms</b>
          </>
        ) : null}
      </div>
    )
  }

  const loss = num(worst.loss)
  return (
    <div className="onote">
      📡 {T('ov_worst_q')} <b>{worst.name}</b>
      {worst.a && worst.b ? (
        <>
          {' '}
          <span dir="ltr" style={{ color: 'var(--tx)', fontWeight: 800 }}>
            {worst.a} <Icon name="arrows" /> {worst.b}
          </span>
        </>
      ) : null}
      {loss > 0 ? (
        <>
          {' · '}
          {T('ov_loss')} <b style={{ color: 'var(--bad)' }}>{Math.round(loss) + T('pct')}</b>
        </>
      ) : null}
      {worst.rtt != null ? (
        <>
          {' · '}
          {T('ov_ping')} <b>{Math.round(num(worst.rtt))}ms</b>
        </>
      ) : null}
    </div>
  )
}

export default function TunnelBreakdown({ summary }) {
  const up = num(summary.link_up)
  const noPing = num(summary.link_noping)
  const down = num(summary.link_down)
  const drift = num(summary.link_drift)
  const off = num(summary.link_off)

  const types = summary.link_types || {}
  const total = TYPE_COLORS.reduce((sum, [key]) => sum + num(types[key]), 0) || 1
  const present = TYPE_COLORS.filter(([key]) => num(types[key]) > 0)

  return (
    <div className="card">
      <div className="tst">
        <StateTile value={up} label={T('tst_connected')} color="var(--ok)" />
        <StateTile value={noPing} label={T('tst_noping')} color="var(--gold)" />
        <StateTile value={down} label={T('tst_down')} color={down ? 'var(--bad)' : 'var(--tx)'} />
        <StateTile
          value={drift}
          label={T('tst_rebuild')}
          color={drift ? 'var(--gold)' : 'var(--tx)'}
        />
        {off ? <StateTile value={off} label={T('st_off')} color="var(--sub)" /> : null}
      </div>

      <div className="typebar">
        {TYPE_COLORS.map(([key, color]) => (
          <i key={key} style={{ width: (num(types[key]) / total) * 100 + '%', background: color }} />
        ))}
      </div>

      <div className="typleg">
        {present.length ? (
          present.map(([key, color]) => (
            <span key={key}>
              <i className="otrack" style={{ background: color }} />
              {key} <b>{num(types[key])}</b>
            </span>
          ))
        ) : (
          <span className="muted">{T('ov_no_tunnel')}</span>
        )}
      </div>

      <WorstTunnelNote
        worst={summary.worst_tunnel}
        fleetPing={summary.fleet_avg_ping}
        trouble={down + drift > 0}
        counted={up + noPing + down + drift > 0}
      />
    </div>
  )
}
