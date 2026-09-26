import Icon from '../../../components/Icon.jsx'

export function Seg2({ label, style, children }) {
  return (
    <div className="seg2" role="radiogroup" aria-label={label} style={style}>
      {children}
    </div>
  )
}

export function SegOpt({ on, title, sub, onClick }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={on ? 'true' : 'false'}
      className={'segopt' + (on ? ' on' : '')}
      onClick={onClick}
    >
      <b>{title}</b>
      <span>{sub}</span>
    </button>
  )
}

export function ScrollSeg({ label, children }) {
  return (
    <div className="seg2 segwrap" role="radiogroup" aria-label={label}>
      {children}
    </div>
  )
}

export function Tiles({ p3, label, children }) {
  return (
    <div className={'pgrid' + (p3 ? ' p3' : '')} role="radiogroup" aria-label={label}>
      {children}
    </div>
  )
}

export function Tile({ on, name, meta, extra, onClick }) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={on ? 'true' : 'false'}
      className={'ptile' + (on ? ' on' : '')}
      onClick={onClick}
    >
      <div className="pn">{name}</div>
      <div className="pmeta">{meta}</div>
      {extra ? (
        <div className="pmeta" style={{ color: 'var(--gold-tx)' }}>
          {extra}
        </div>
      ) : null}
    </button>
  )
}

export function WarnCap({ text, tone, style }) {
  if (!text) return null
  return (
    <div className={'warncap ' + (tone || 'no')} style={style}>
      <Icon name="warn" />
      <span>{text}</span>
    </div>
  )
}
