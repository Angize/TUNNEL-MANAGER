import { T } from '../../i18n/fa.js'
import { eventLevel, formatEventTime, layoutEvent, nameParts, valueClass } from './logFormat.js'

function Named({ text }) {
  return nameParts(text).map((seg, i) =>
    seg.name === undefined ? (
      seg.text
    ) : seg.latin ? (
      <span key={i} className="lev-nm">
        «<bdi>{seg.name}</bdi>»{seg.tail}
      </span>
    ) : (
      '«' + seg.name + '»' + seg.tail
    )
  )
}

function hitFolded(query, text, lead) {
  if (!query) return false
  const face = [text, ...lead.map((row) => row.k + ': ' + row.v)].join(' ').toLowerCase()
  return !face.includes(query)
}

export default function LogEvent({ event, open, query, onToggle, born }) {
  const level = eventLevel(event)
  const { text, notes, lead, rest, isPair } = layoutEvent(event)
  const foldable = rest.length > 0 || notes.length > 0
  const shown = foldable && (open === undefined ? hitFolded(query, text, lead) : open)

  const activate = () => {
    try {
      if (window.getSelection && String(window.getSelection()) !== '') return
    } catch {
      return
    }
    onToggle(!shown)
  }

  const interactive = foldable
    ? {
        role: 'button',
        tabIndex: 0,
        'aria-expanded': shown ? 'true' : 'false',
        onClick: activate,
        onPointerDown: (e) => {
          delete e.currentTarget.dataset.kb
        },
        onKeyDown: (e) => {
          if (e.key === ' ' || e.key === 'Enter') {
            e.preventDefault()
            e.currentTarget.dataset.kb = '1'
            activate()
          }
        },
      }
    : {}

  return (
    <div
      className={
        'lev ' +
        level +
        (foldable ? ' tap' : '') +
        (shown ? ' open' : '') +
        (born ? ' lev-new' : '')
      }
      {...interactive}
    >
      <span className="lev-bar" />
      <div>
        <div className="lev-head">
          <span className="lev-lv">{T('sod_' + level)}</span>
          <span className="lev-time">{formatEventTime(event.ts)}</span>
        </div>
        <div className="lev-text">
          <Named text={text} />
        </div>
        {lead.length ? (
          <div className="lev-vals">
            {lead.map((row, i) => (
              <span key={row.k + i} className={'lev-kv' + (isPair(row.k) ? ' pair' : '')}>
                <span className="lev-k">{row.k}</span>
                <span className={'lev-v' + valueClass(row.v)}>{row.v}</span>
              </span>
            ))}
          </div>
        ) : null}
        {foldable ? (
          <>
            <div className="lev-fold" inert={!shown}>
              <div className="lev-fold-in">
                {notes.map((note, i) => (
                  <p className="lev-note" key={'n' + i}>
                    <Named text={note} />
                  </p>
                ))}
                {rest.map((row, i) => (
                  <div className="lev-row" key={row.k + i}>
                    <b>{row.k}</b>
                    <span className={valueClass(row.v)}>{row.v}</span>
                  </div>
                ))}
              </div>
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
