import { useCallback, useLayoutEffect, useRef, useState } from 'react'
import Icon from '../../../components/Icon.jsx'
import { checkable } from '../../../lib/keys.js'

export function Seg2({ style, children }) {
  return (
    <div className="seg2" style={style}>
      {children}
    </div>
  )
}

export function SegOpt({ on, title, sub, onClick }) {
  return (
    <button type="button" className={'segopt' + (on ? ' on' : '')} onClick={onClick}>
      <b>{title}</b>
      <span>{sub}</span>
    </button>
  )
}

export function ScrollSeg({ children }) {
  const bar = useRef(null)
  const [atEnd, setAtEnd] = useState(false)

  const measure = useCallback(() => {
    const node = bar.current
    if (!node) return
    const done = Math.abs(node.scrollLeft) + node.clientWidth >= node.scrollWidth - 4
    setAtEnd((prev) => (prev === done ? prev : done))
  }, [])

  useLayoutEffect(measure)

  return (
    <div className={'trwrap' + (atEnd ? ' atend' : '')}>
      <div className="seg2 trbar" ref={bar} onScroll={measure}>
        {children}
      </div>
    </div>
  )
}

export function Tiles({ p3, children }) {
  return <div className={'pgrid' + (p3 ? ' p3' : '')}>{children}</div>
}

export function Tile({ on, name, meta, extra, onClick }) {
  return (
    <button type="button" className={'ptile' + (on ? ' on' : '')} onClick={onClick}>
      <div className="pn">{name}</div>
      <div className="pmeta">{meta}</div>
      {extra ? (
        <div className="pmeta" style={{ color: 'var(--gold)' }}>
          {extra}
        </div>
      ) : null}
    </button>
  )
}

export function TglBox({ on, title, note, locked, hidden, gap, onClick }) {
  if (hidden) return null
  return (
    <div
      className={'tglbox' + (locked ? ' dis' : '')}
      style={gap ? { marginTop: gap } : undefined}
    >
      <div className={'tglsw' + (on ? ' on' : '')} {...checkable('switch', on, onClick)} />
      <div className="tt">
        <b>{title}</b>
        <small>{note}</small>
      </div>
    </div>
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
