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
      className={'sodev ' + level + (foldable ? ' sodtap' : '') + (foldable && open ? ' open' : '')}
      {...interactive}
    >
      <span className="sbar" />
      <div>
        <div className="shead">
          <span className="slv">{T('sod_' + level)}</span>
          <span className="stime">{formatEventTime(event.ts)}</span>
        </div>
        <div className="ssen">{text}</div>
        {lead.length ? (
          <div className="svals">
            {lead.map((row, i) => (
              <span key={row.k + i} className={'sp' + (isPair(row.k) ? ' pair' : '')}>
                <span className="sk2">{row.k}</span>
                <span className="sval">{row.v}</span>
              </span>
            ))}
          </div>
        ) : null}
        {foldable ? (
          <>
            <div className="sfold">
              {rest.map((row, i) => (
                <div className="sr" key={row.k + i}>
                  <b>{row.k}</b>
                  <span>{row.v}</span>
                </div>
              ))}
            </div>
            <span className="smore">
              <span className="more">{T('sod_more')}</span>
              <span className="less">{T('sod_less')}</span>
            </span>
          </>
        ) : null}
      </div>
    </div>
  )
}
