import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { num } from '../../lib/num.js'
import { setPageQuery } from '../../lib/pageQuery.js'
import StatusGroups from './StatusGroups.jsx'

const TYPE_COLORS = [
  ['core', 'var(--h-indigo)'],
  ['vxlan', 'var(--h-sky)'],
  ['gre', 'var(--ok)'],
  ['sit', 'var(--h-grape)'],
  ['ipip', 'var(--h-teal)'],
  ['l2tpv3', 'var(--h-purple)'],
  ['fou', 'var(--h-pink)'],
  ['ipsec', 'var(--h-rose)'],
]

function WorstTunnelNote({ worst }) {
  if (!worst) return null
  const loss = num(worst.loss)
  return (
    <div className="onote">
      <Icon name="warn" color="var(--gold-tx)" /> {T('ov_worst_q')} <b>{worst.name}</b>
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
          <span className="nw">
            {T('ov_loss')} <b style={{ color: 'var(--bad-tx)' }}>{Math.round(loss) + T('pct')}</b>
          </span>
        </>
      ) : null}
      {worst.rtt != null ? (
        <>
          {' · '}
          <span className="nw">
            {T('ov_ping')} <b>{Math.round(num(worst.rtt))}ms</b>
          </span>
        </>
      ) : null}
    </div>
  )
}

export default function TunnelBreakdown({ summary, onNavigate }) {
  const types = summary.link_types || {}
  const total = TYPE_COLORS.reduce((sum, [key]) => sum + num(types[key]), 0) || 1
  const present = TYPE_COLORS.filter(([key]) => num(types[key]) > 0)
  const groups = summary.tunnel_groups || {}
  const list = (key) => groups[key] || []
  const byPing = [...list('up')].sort((a, b) => num(b.rtt) - num(a.rtt))
  const fleetPing = summary.fleet_avg_ping

  const row = (t) => (
    <button
      key={t.tab + t.name}
      type="button"
      className="sgr"
      onClick={() => onNavigate(t.tab, () => setPageQuery(t.tab, '"' + t.name + '"'))}
    >
      <span className="sgn" dir="ltr">
        {t.name}
      </span>
      <span className="sge" dir="ltr">
        {t.a} <Icon name="arrows" /> {t.b}
      </span>
      {t.loss > 0 && t.loss < 100 ? <b className="sgv crit">{Math.round(num(t.loss)) + T('pct')}</b> : null}
      {t.rtt != null ? <span className="sgm">{num(t.rtt)}ms</span> : null}
    </button>
  )

  return (
    <div className="card">
      <StatusGroups
        groups={[
          { key: 'down', tone: 'bad', title: T('tst_down'), items: list('down'), row, open: true },
          { key: 'drift', tone: 'warn', title: T('tst_rebuild'), items: list('drift'), row, open: true },
          { key: 'noping', tone: 'warn', title: T('tst_noping'), items: list('noping'), row, open: true },
          { key: 'wait', tone: 'mute', title: T('pending_check'), items: list('wait'), row },
          {
            key: 'up',
            tone: 'ok',
            title: T('tst_connected'),
            items: byPing,
            row,
            preview:
              fleetPing != null ? (
                <span>
                  {T('ov_fleet_ping')} <b>{num(fleetPing)}ms</b>
                </span>
              ) : null,
          },
          { key: 'off', tone: 'mute', title: T('st_off'), items: list('off'), row },
        ]}
      />

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

      <WorstTunnelNote worst={summary.worst_tunnel} />
    </div>
  )
}
