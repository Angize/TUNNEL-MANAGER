import { useEffect, useId, useState } from 'react'
import { T } from '../../i18n/fa.js'
import { apiGet } from '../../lib/api.js'
import { cssVar } from '../../lib/health.js'
import { fmtClock, fmtDay, fmtRate } from '../../lib/num.js'
import useScrub from '../../lib/useScrub.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

const W = 300
const H = 100
const PAD = 3
const DAY = 86400000

function niceMax(v) {
  if (!(v > 0)) return 1
  const p = 10 ** Math.floor(Math.log10(v))
  return [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((m) => m * p >= v) * p
}

function pointX(i, n) {
  return ((i + 0.5) * W) / n
}

function trace(values, max) {
  const n = values.length
  const y = (v) => H - PAD - (v / max) * (H - 2 * PAD)
  const half = W / n / 2
  let line = ''
  let area = ''
  let run = []
  const flush = () => {
    if (!run.length) return
    const pts = run.length > 1 ? run : [[run[0][0] - half, run[0][1]], [run[0][0] + half, run[0][1]]]
    const d = pts.map(([px, py]) => px.toFixed(1) + ',' + py.toFixed(1)).join('L')
    line += 'M' + d
    area += 'M' + pts[0][0].toFixed(1) + ',' + (H - PAD) + 'L' + d + 'L' + pts[pts.length - 1][0].toFixed(1) + ',' + (H - PAD) + 'Z'
    run = []
  }
  values.forEach((v, i) => (v == null ? flush() : run.push([pointX(i, n), y(v)])))
  flush()
  return { line, area }
}

function liveSeries(live) {
  return {
    rx: live.map((p) => p.rx),
    tx: live.map((p) => p.tx),
    span: (i) => fmtClock(live[i].t, true),
    ticks: live.length ? [fmtClock(live[0].t, true), '', fmtClock(live[live.length - 1].t, true)] : ['', '', ''],
  }
}

function histSeries(h) {
  const n = h.rx.length
  const step = h.step * 1000
  const end = h.end * 1000
  const from = end - n * step
  const long = n * step > DAY
  const dated = n * step >= DAY
  const tick = (t) => (long ? fmtDay(t) : fmtClock(t))
  return {
    rx: h.rx,
    tx: h.tx,
    span: (i) => {
      const a = from + i * step
      return (dated ? fmtDay(a) + ' ' : '') + fmtClock(a) + '–' + fmtClock(a + step)
    },
    ticks: [dated && !long ? fmtDay(from) + ' ' + fmtClock(from) : tick(from), tick(from + (n * step) / 2), tick(end)],
  }
}

function RangePicker({ ranges, value, onChange }) {
  const units = [
    ['h', T('bw_hours')],
    ['d', T('bw_days')],
  ]
  return (
    <div className="tf-rng" role="group" aria-label={T('bw_range')}>
      <button
        type="button"
        className={'tf-live' + (value === 'live' ? ' on' : '')}
        aria-pressed={value === 'live'}
        onClick={() => onChange('live')}
      >
        <span className="pd" />
        {T('live')}
      </button>
      {units.map(([unit, word]) => (
        <span className="tf-grp" key={unit}>
          {ranges
            .filter((r) => r.endsWith(unit))
            .map((r) => (
              <button
                key={r}
                type="button"
                className={value === r ? 'on' : ''}
                aria-pressed={value === r}
                aria-label={parseInt(r, 10) + ' ' + word}
                onClick={() => onChange(r)}
              >
                {parseInt(r, 10)}
              </button>
            ))}
          <span className="tf-unit" aria-hidden="true">
            {word}
          </span>
        </span>
      ))}
    </div>
  )
}

export default function TrafficChart({ nodeId, live, now }) {
  const ranges = useUiConfig().bw_ranges
  const [range, setRange] = useState('live')
  const [hist, setHist] = useState(null)
  const [failed, setFailed] = useState('')
  const gradientId = useId()

  useEffect(() => {
    if (range === 'live') return undefined
    let alive = true
    let timer = 0
    let wait = 60
    const load = async () => {
      if (!document.hidden) {
        try {
          const r = await apiGet('traffic-history?range=' + range + (nodeId ? '&id=' + encodeURIComponent(nodeId) : ''))
          if (!alive) return
          wait = Math.min(60, Math.max(10, r.step))
          setHist(r)
          setFailed('')
        } catch {
          if (alive) setFailed(range)
        }
      }
      if (alive) timer = setTimeout(load, wait * 1000)
    }
    load()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [range, nodeId])

  const ready = range === 'live' || (hist && hist.range === range)
  const s = range === 'live' ? liveSeries(live) : ready ? histSeries(hist) : null
  const n = s ? s.rx.length : 0
  const { at, handlers } = useScrub(n)
  const vals = s ? s.rx.concat(s.tx).filter((v) => v != null) : []
  const peak = vals.length ? Math.max(...vals) : 0
  const max = niceMax(peak)
  const rx = n ? trace(s.rx, max) : null
  const tx = n ? trace(s.tx, max) : null
  const cur = at != null ? { rx: s.rx[at], tx: s.tx[at] } : now
  const show = (v) => (v == null ? '—' : fmtRate(v))
  const okColor = cssVar('--ok')
  const accColor = cssVar('--acc')
  const note = !s ? T(failed === range ? 'bw_failed' : 'bw_loading') : !vals.length && range !== 'live' ? T('bw_empty') : ''

  return (
    <div className="tf-chart">
      <div className="tf-top">
        <span className="din iso">
          ↓ <b>{show(cur && cur.rx)}</b>
        </span>
        <span className="dout iso">
          ↑ <b>{show(cur && cur.tx)}</b>
        </span>
        {at != null ? (
          <span className="tf-when">
            <bdi dir="ltr">{s.span(at)}</bdi>
          </span>
        ) : null}
      </div>
      <RangePicker ranges={ranges} value={range} onChange={setRange} />
      <div
        className={'tf-plot' + (at != null ? ' insp' : '')}
        role="slider"
        tabIndex={n ? 0 : -1}
        aria-label={T('bw_chart')}
        aria-valuemin={0}
        aria-valuemax={Math.max(0, n - 1)}
        aria-valuenow={at == null ? Math.max(0, n - 1) : at}
        aria-valuetext={
          n ? s.span(at == null ? n - 1 : at) + ' · ↓ ' + show(s.rx[at == null ? n - 1 : at]) + ' ↑ ' + show(s.tx[at == null ? n - 1 : at]) : note
        }
        {...handlers}
      >
        <svg className="tf-spk" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" stopColor={okColor} stopOpacity=".22" />
              <stop offset="1" stopColor={okColor} stopOpacity="0" />
            </linearGradient>
          </defs>
          {peak > 0 ? (
            <>
              <line className="tf-grid" x1="0" x2={W} y1={PAD} y2={PAD} vectorEffect="non-scaling-stroke" />
              <line className="tf-grid" x1="0" x2={W} y1={H / 2} y2={H / 2} vectorEffect="non-scaling-stroke" />
            </>
          ) : null}
          <line className="tf-base" x1="0" x2={W} y1={H - PAD} y2={H - PAD} vectorEffect="non-scaling-stroke" />
          {rx ? <path d={rx.area} fill={`url(#${gradientId})`} /> : null}
          {rx ? (
            <path
              d={rx.line}
              fill="none"
              stroke={okColor}
              strokeWidth="1.5"
              strokeLinejoin="round"
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
          {tx ? (
            <path
              d={tx.line}
              fill="none"
              stroke={accColor}
              strokeWidth="1.5"
              strokeLinejoin="round"
              strokeLinecap="round"
              vectorEffect="non-scaling-stroke"
            />
          ) : null}
          {at != null ? (
            <line className="tf-cur" x1={pointX(at, n)} x2={pointX(at, n)} y1="0" y2={H} vectorEffect="non-scaling-stroke" />
          ) : null}
        </svg>
        {peak > 0 ? (
          <>
            <span className="tf-y top">{fmtRate(max)}</span>
            <span className="tf-y mid">{fmtRate(max / 2)}</span>
          </>
        ) : null}
        {note ? <span className="tf-empty">{note}</span> : null}
      </div>
      <div className="tf-x" aria-hidden="true">
        {(s ? s.ticks : ['', '', '']).map((t, i) => (
          <span key={i}>{t}</span>
        ))}
      </div>
    </div>
  )
}
