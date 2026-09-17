import { useEffect, useRef, useState } from 'react'
import { T } from '../../i18n/fa.js'
import { usageColor } from '../../lib/health.js'
import { num } from '../../lib/num.js'
import { pressable } from '../../lib/keys.js'

const TIP_MS = 2400
const OFFLINE_HEIGHT = 10
const BASE_HEIGHT = 12
const HEIGHT_PER_PCT = 0.54

export default function NodeHeat({ heat }) {
  const [tip, setTip] = useState(null)
  const timer = useRef(0)

  useEffect(() => () => clearTimeout(timer.current), [])

  const showTip = (event, node) => {
    event.stopPropagation()
    const bar = event.currentTarget
    setTip({ name: node.name, info: node.info, left: bar.offsetLeft + bar.offsetWidth / 2 })
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setTip(null), TIP_MS)
  }

  const bars = (heat || []).map((h) => {
    const pct = num(h.pct)
    return h.online
      ? {
          name: h.name,
          info: pct + T('pct'),
          height: BASE_HEIGHT + pct * HEIGHT_PER_PCT,
          background: usageColor(pct),
        }
      : {
          name: h.name,
          info: T('offline'),
          height: OFFLINE_HEIGHT,
          background: 'color-mix(in srgb, var(--sub) 35%, transparent)',
        }
  })

  return (
    <div className="card ohcard">
      <div className="oheat">
        {bars.length ? (
          bars.map((bar) => (
            <div
              key={bar.name}
              className="hbar"
              title={bar.name + ' — ' + bar.info}
              style={{ height: bar.height + 'px', background: bar.background }}
              {...pressable((e) => showTip(e, bar))}
            />
          ))
        ) : (
          <div className="muted" style={{ fontSize: 12 }}>
            {T('ov_no_nodes')}
          </div>
        )}
        {tip ? (
          <div className="htip" style={{ left: tip.left + 'px', display: 'block' }}>
            <span>{tip.name}</span> {tip.info}
          </div>
        ) : null}
      </div>
      <div className="heat-lg">
        <span>
          <i style={{ background: 'var(--ok)' }} />
          {T('st_healthy')}
        </span>
        <span>
          <i style={{ background: 'var(--gold)' }} />
          {T('st_warn')}
        </span>
        <span>
          <i style={{ background: 'var(--bad)' }} />
          {T('st_crit')}
        </span>
      </div>
      <div className="muted" style={{ textAlign: 'center', marginTop: 6, fontSize: 11 }}>
        {(heat || []).length + ' ' + T('ov_heat_note')}
      </div>
    </div>
  )
}
