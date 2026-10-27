import { useEffect, useId, useRef, useState } from 'react'
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
const PX_PER_POINT = 3

function niceMax(v) {
  if (!(v > 0)) return 1
  const p = 10 ** Math.floor(Math.log10(v))
  return [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10].find((m) => m * p >= v) * p
}

function mean(values) {
  return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null
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
    span: (i) => ({ day: '', clock: fmtClock(live[i].t, true) }),
    ticks: live.length ? [fmtClock(live[0].t, true), '', fmtClock(live[live.length - 1].t, true)] : ['', '', ''],
  }
}

function histSeries(h, slots) {
  const base = h.step * 1000
  const n = h.rx.length
  const end = h.end * 1000
  const from = end - n * base
  const step = base * Math.max(1, Math.ceil(n / Math.max(1, slots)))
  const starts = []
  const rx = []
  const tx = []
  h.rx.forEach((v, i) => {
    const g = Math.floor((from + i * base) / step) * step
    if (starts[starts.length - 1] !== g) {
      starts.push(g)
      rx.push([])
      tx.push([])
    }
    if (v != null) rx[rx.length - 1].push(v)
    if (h.tx[i] != null) tx[tx.length - 1].push(h.tx[i])
  })
  const long = n * base > DAY
  const dated = n * base >= DAY
  const fine = step < 60000
  const tick = (t) => (long ? fmtDay(t) : fmtClock(t))
  return {
    rx: rx.map(mean),
    tx: tx.map(mean),
    span: (i) => ({
      day: dated ? fmtDay(starts[i]) : '',
      clock: fmtClock(starts[i], fine) + '–' + fmtClock(starts[i] + step, fine),
    }),
    since: (i) => ({ day: dated ? fmtDay(starts[i]) : '', clock: fmtClock(starts[i]) }),
    ticks: [dated && !long ? fmtDay(from) + ' ' + fmtClock(from) : tick(from), tick(from + (n * base) / 2), tick(end)],
  }
}

function useWidth(ref) {
  const [width, setWidth] = useState(W)
  useEffect(() => {
    const el = ref.current
    if (!el) return undefined
    const ro = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width))
    ro.observe(el)
    return () => ro.disconnect()
  }, [ref])
  return width
}

function RangePicker({ ranges, value, onChange }) {
  const strip = useRef(null)
  const unit = { h: T('bw_hours'), d: T('bw_days') }

  useEffect(() => {
    const row = strip.current
    const on = row && row.querySelector('.on')
    if (!on) return
    const a = on.getBoundingClientRect()
    const b = row.getBoundingClientRect()
    if (a.left < b.left) row.scrollBy({ left: a.left - b.left - 24, behavior: 'smooth' })
    else if (a.right > b.right) row.scrollBy({ left: a.right - b.right + 24, behavior: 'smooth' })
  }, [value])

  return (
    <div className="tf-rng" role="group" aria-label={T('bw_range')} ref={strip}>
      {['live', ...ranges].map((r) => (
        <button
          key={r}
          type="button"
          className={(r === 'live' ? 'tf-live' : '') + (value === r ? ' on' : '')}
          aria-pressed={value === r}
          onClick={() => onChange(r)}
        >
          {r === 'live' ? <span className="pd" /> : null}
          {r === 'live' ? T('live') : parseInt(r, 10) + ' ' + unit[r.slice(-1)]}
        </button>
      ))}
    </div>
  )
}

export default function TrafficChart({ nodeId, live, now, initial = 'live' }) {
  const ranges = useUiConfig().bw_ranges
  const [range, setRange] = useState(initial)
  const [hist, setHist] = useState(null)
  const [failed, setFailed] = useState('')
  const gradientId = useId()
  const plot = useRef(null)
  const width = useWidth(plot)

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
  const s = range === 'live' ? liveSeries(live) : ready ? histSeries(hist, Math.floor(width / PX_PER_POINT)) : null
  const n = s ? s.rx.length : 0
  const { at, handlers } = useScrub(n)
  const vals = s ? s.rx.concat(s.tx).filter((v) => v != null) : []
  const peak = vals.length ? Math.max(...vals) : 0
  const max = niceMax(peak)
  const rx = n ? trace(s.rx, max) : null
  const tx = n ? trace(s.tx, max) : null
  const show = (v) => (v == null ? '—' : fmtRate(v))
  const focus = at == null ? n - 1 : at
  const sp = at != null ? s.span(at) : null
  const atX = at != null ? (pointX(at, n) / W) * 100 : 0
  const atY = (v) => ((H - PAD - (v / max) * (H - 2 * PAD)) / H) * 100
  const okColor = cssVar('--ok')
  const accColor = cssVar('--acc')
  const note = !s ? T(failed === range ? 'bw_failed' : 'bw_loading') : !vals.length && range !== 'live' ? T('bw_empty') : ''
  const first = s && s.since && vals.length ? s.rx.findIndex((v, i) => v != null || s.tx[i] != null) : -1
  const since = first > n * 0.15 ? s.since(first) : null
  const said = (i) => {
    const p = s.span(i)
    return (p.day ? p.day + ' ' : '') + p.clock + ' · ↓ ' + show(s.rx[i]) + ' ↑ ' + show(s.tx[i])
  }

  return (
    <div className="tf-chart">
      <div className="tf-top">
        <span className="din iso">
          ↓ <b>{show(now && now.rx)}</b>
        </span>
        <span className="dout iso">
          ↑ <b>{show(now && now.tx)}</b>
        </span>
      </div>
      <RangePicker ranges={ranges} value={range} onChange={setRange} />
      <div
        ref={plot}
        className="tf-plot"
        role="slider"
        tabIndex={n ? 0 : -1}
        aria-label={T('bw_chart')}
        aria-valuemin={0}
        aria-valuemax={Math.max(0, n - 1)}
        aria-valuenow={Math.max(0, focus)}
        aria-valuetext={n ? said(focus) : note}
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
        {sp && s.rx[at] != null ? (
          <i className="tf-dot rx" style={{ left: atX + '%', top: atY(s.rx[at]) + '%' }} />
        ) : null}
        {sp && s.tx[at] != null ? (
          <i className="tf-dot tx" style={{ left: atX + '%', top: atY(s.tx[at]) + '%' }} />
        ) : null}
        {sp ? (
          <span
            className="tf-tip"
            style={atX < 50 ? { left: `calc(${atX}% + 10px)` } : { right: `calc(${100 - atX}% + 10px)` }}
          >
            <span className="tf-tip-t">
              {sp.day ? <bdi>{sp.day}</bdi> : null}
              {sp.day ? ' ' : null}
              <bdi dir="ltr">{sp.clock}</bdi>
            </span>
            <span className="din iso">
              ↓ <b>{show(s.rx[at])}</b>
            </span>
            <span className="dout iso">
              ↑ <b>{show(s.tx[at])}</b>
            </span>
          </span>
        ) : null}
        {note ? <span className="tf-empty">{note}</span> : null}
        {since ? (
          <span className="tf-since" style={{ width: (first / n) * 100 + '%' }}>
            <span>
              {T('bw_since') + ' '}
              {since.day ? <bdi>{since.day}</bdi> : null}
              {since.day ? ' ' : null}
              <bdi dir="ltr">{since.clock}</bdi>
            </span>
          </span>
        ) : null}
      </div>
      <div className="tf-x" aria-hidden="true">
        {(s ? s.ticks : ['', '', '']).map((t, i) => (
          <span key={i}>
            <bdi>{t}</bdi>
          </span>
        ))}
      </div>
    </div>
  )
}
