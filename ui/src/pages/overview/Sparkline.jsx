import { useId } from 'react'
import { cssVar } from '../../lib/health.js'
import { num } from '../../lib/num.js'

const WIDTH = 300
const HEIGHT = 46
const PAD = 3

function linePath(values, max) {
  const points = values.length < 2 ? values.concat(values) : values
  const step = (WIDTH - 2 * PAD) / (points.length - 1)
  return (
    'M' +
    points
      .map((v, i) => {
        const x = PAD + i * step
        const y = HEIGHT - PAD - (num(v) / max) * (HEIGHT - 2 * PAD)
        return x.toFixed(1) + ',' + y.toFixed(1)
      })
      .join(' L')
  )
}

export default function Sparkline({ rx, tx }) {
  const gradientId = useId()
  if (!rx.length) return <svg className="tf-spk" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none" />

  const max = Math.max(...rx, ...tx, 1)
  const rxPath = linePath(rx, max)
  const txPath = linePath(tx, max)
  const lastX = (PAD + (rx.length - 1) * ((WIDTH - 2 * PAD) / Math.max(1, rx.length - 1))).toFixed(1)
  const okColor = cssVar('--ok')
  const accColor = cssVar('--acc')

  return (
    <svg className="tf-spk" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={okColor} stopOpacity=".22" />
          <stop offset="1" stopColor={okColor} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path
        d={`${rxPath} L${lastX},${HEIGHT - PAD} L${PAD},${HEIGHT - PAD} Z`}
        fill={`url(#${gradientId})`}
      />
      <path
        d={rxPath}
        fill="none"
        stroke={okColor}
        strokeWidth="1.8"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <path
        d={txPath}
        fill="none"
        stroke={accColor}
        strokeWidth="1.8"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  )
}
