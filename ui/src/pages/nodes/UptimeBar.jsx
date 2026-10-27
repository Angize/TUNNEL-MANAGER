import { useEffect, useRef, useState } from 'react'
import { T, TF } from '../../i18n/fa.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

function tone(value, [ok, bad]) {
  if (value == null) return 'g'
  if (value >= ok) return ''
  return value < bad ? 'd' : 'w'
}

function clock(t) {
  const d = new Date(t)
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0')
}

export default function UptimeBar({ node, windowHours }) {
  const levels = useUiConfig().uptime_levels
  const cells = node.uptime || []
  const pct = node.uptime_pct != null ? node.uptime_pct : 100
  const tones = cells.map((value) => tone(value, levels))
  const last = cells.length - 1
  const [at, setAt] = useState(null)
  const hold = useRef(0)

  useEffect(() => () => clearTimeout(hold.current), [])

  const span = (i) => {
    const step = windowHours * 60000
    const end = (node.uptime_end != null ? node.uptime_end * 1000 : Date.now()) - (last - i) * step
    return clock(end - step) + '–' + clock(end)
  }
  const share = (i) => (cells[i] == null ? T('up_nodata') : cells[i] + T('pct'))
  const count = (t) => tones.filter((x) => x === t).length
  const shown = at == null ? last : at

  const pick = (e) => {
    if (!cells.length) return
    const r = e.currentTarget.getBoundingClientRect()
    setAt(Math.min(last, Math.max(0, Math.floor(((e.clientX - r.left) / r.width) * cells.length))))
  }
  const press = (e) => {
    clearTimeout(hold.current)
    pick(e)
  }
  const lift = (e) => {
    if (e.pointerType === 'touch') hold.current = setTimeout(() => setAt(null), 2500)
  }
  const drop = () => {
    clearTimeout(hold.current)
    setAt(null)
  }
  const leave = (e) => {
    if (e.pointerType !== 'touch') setAt(null)
  }
  const key = (e) => {
    if (e.key === 'Escape') return setAt(null)
    const cur = at == null ? cells.length : at
    const next = { ArrowLeft: cur - 1, ArrowDown: cur - 1, ArrowRight: cur + 1, ArrowUp: cur + 1, Home: 0, End: last }[
      e.key
    ]
    if (next == null || !cells.length) return
    e.preventDefault()
    setAt(Math.min(last, Math.max(0, next)))
  }

  return (
    <div className="upwrap">
      <div className="uptop">
        {T('uptime')}
        <b style={{ marginInlineStart: 6 }}>{pct + T('pct')}</b>
        <span className="r">
          {at == null ? (
            windowHours + ' ' + T('ov_hours_recent')
          ) : (
            <>
              <bdi dir="ltr">{span(at)}</bdi>
              {' · '}
              <b>{share(at)}</b>
            </>
          )}
        </span>
      </div>
      <div
        className={'upbar' + (at == null ? '' : ' insp')}
        role="slider"
        tabIndex={cells.length ? 0 : -1}
        aria-label={TF('up_bar', { ok: count(''), warn: count('w'), bad: count('d') })}
        aria-valuemin={0}
        aria-valuemax={Math.max(0, last)}
        aria-valuenow={Math.max(0, shown)}
        aria-valuetext={span(shown) + ' · ' + share(shown)}
        onPointerDown={press}
        onPointerMove={pick}
        onPointerUp={lift}
        onPointerCancel={drop}
        onPointerLeave={leave}
        onKeyDown={key}
        onBlur={() => setAt(null)}
      >
        {tones.map((t, i) => (
          <i key={i} className={t + (i === at ? ' on' : '')} />
        ))}
      </div>
    </div>
  )
}
