import { T } from '../../i18n/fa.js'
import { gaugeLevel } from '../../lib/health.js'
import { num } from '../../lib/num.js'

const SIZE = 84
const RADIUS = 33
const CENTER = SIZE / 2
const STROKE = 8
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

export default function Gauge({ label, pct, sub }) {
  const value = Math.max(0, Math.min(100, Math.round(num(pct))))
  const offset = CIRCUMFERENCE * (1 - value / 100)

  return (
    <div className="gauge">
      <div className="gwrap">
        <svg width={SIZE} height={SIZE}>
          <circle
            className="gtrack"
            cx={CENTER}
            cy={CENTER}
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
          />
          <circle
            className={'gfill ' + gaugeLevel(value)}
            cx={CENTER}
            cy={CENTER}
            r={RADIUS}
            fill="none"
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE.toFixed(1)}
            strokeDashoffset={offset.toFixed(1)}
            transform={`rotate(-90 ${CENTER} ${CENTER})`}
          />
        </svg>
        <div className="gc">
          <b>
            {value}
            <i>{T('pct')}</i>
          </b>
        </div>
      </div>
      <div className="gl">{label}</div>
      <div className="gsub">{sub == null ? '…' : sub}</div>
    </div>
  )
}
