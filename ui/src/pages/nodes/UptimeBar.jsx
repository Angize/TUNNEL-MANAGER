import { T } from '../../i18n/fa.js'

export default function UptimeBar({ node, windowHours }) {
  const cells = node.uptime || []
  const pct = node.uptime_pct != null ? node.uptime_pct : 100

  return (
    <div className="upwrap">
      <div className="uptop">
        {T('uptime_bar')}
        <b style={{ marginInlineStart: 6 }}>{pct + T('pct')}</b>
        <span className="r">
          {windowHours} {T('ov_hours_recent')}
        </span>
      </div>
      <div className="upbar">
        {cells.map((value, i) => (
          <i key={i} className={value == null ? 'g' : value ? '' : 'd'} />
        ))}
      </div>
    </div>
  )
}
