import { T } from '../../i18n/fa.js'
import { eventLevel, formatEventTime, layoutEvent } from './logFormat.js'

export default function LogEvent({ event, open, onToggle }) {
  const level = eventLevel(event)
  const { text, lead, rest, isPair } = layoutEvent(event)
  const foldable = rest.length > 0

  const activate = () => {
    try {
      if (window.getSelection && String(window.getSelection()) !== '') return
    } catch {
      return
    }
    onToggle()
  }

  const interactive = foldable
    ? {
        role: 'button',
        tabIndex: 0,
        'aria-expanded': open ? 'true' : 'false',
        onClick: activate,
        onKeyDown: (e) => {
          if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault()
            activate()
          }
        },
      }
    : {}

  return (
    <div
      className={'lev ' + level + (foldable ? ' tap' : '') + (foldable && open ? ' open' : '')}
      {...interactive}
    >
      <span className="lev-bar" />
      <div>
        <div className="lev-head">
          <span className="lev-lv">{T('sod_' + level)}</span>
          <span className="lev-time">{formatEventTime(event.ts)}</span>
        </div>
        <div className="lev-text">{text}</div>
        {lead.length ? (
          <div className="lev-vals">
            {lead.map((row, i) => (
              <span key={row.k + i} className={'lev-kv' + (isPair(row.k) ? ' pair' : '')}>
                <span className="lev-k">{row.k}</span>
                <span className="lev-v">{row.v}</span>
              </span>
            ))}
          </div>
        ) : null}
        {foldable ? (
          <>
            <div className="lev-fold">
              {rest.map((row, i) => (
                <div className="lev-row" key={row.k + i}>
                  <b>{row.k}</b>
                  <span>{row.v}</span>
                </div>
              ))}
            </div>
            <span className="lev-more">
              <span className="more">{T('sod_more')}</span>
              <span className="less">{T('sod_less')}</span>
            </span>
          </>
        ) : null}
      </div>
    </div>
  )
}
