import { T, TF } from '../../i18n/fa.js'
import { fmtClock } from '../../lib/num.js'
import useScrub from '../../lib/useScrub.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

function tone(value, [ok, bad]) {
  if (value == null) return 'g'
  if (value >= ok) return ''
  return value < bad ? 'd' : 'w'
}

export default function UptimeBar({ node, windowHours }) {
  const levels = useUiConfig().uptime_levels
  const cells = node.uptime || []
  const pct = node.uptime_pct != null ? node.uptime_pct : 100
  const tones = cells.map((value) => tone(value, levels))
  const last = cells.length - 1
  const { at, handlers } = useScrub(cells.length)

  const span = (i) => {
    const step = windowHours * 60000
    const end = (node.uptime_end != null ? node.uptime_end * 1000 : Date.now()) - (last - i) * step
    return fmtClock(end - step) + '–' + fmtClock(end)
  }
  const share = (i) => (cells[i] == null ? T('up_nodata') : cells[i] + T('pct'))
  const count = (t) => tones.filter((x) => x === t).length
  const shown = at == null ? last : at

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
        {...handlers}
      >
        {tones.map((t, i) => (
          <i key={i} className={t + (i === at ? ' on' : '')} />
        ))}
      </div>
    </div>
  )
}
