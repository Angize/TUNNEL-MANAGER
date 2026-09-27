import { useLayoutEffect, useRef } from 'react'
import Icon from '../../../components/Icon.jsx'

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

function frameTo(box, frame, pick, glide) {
  const on = box.querySelector(pick)
  if (!on || !on.offsetWidth) {
    frame.classList.remove('shown')
    return
  }
  const snap = !glide || !frame.classList.contains('shown')
  if (snap) frame.style.transition = 'none'
  frame.style.width = on.offsetWidth + 'px'
  frame.style.height = on.offsetHeight + 'px'
  frame.style.transform = 'translate(' + on.offsetLeft + 'px, ' + on.offsetTop + 'px)'
  frame.classList.add('shown')
  if (snap) {
    frame.getBoundingClientRect()
    frame.style.transition = ''
  }
}

function useSlidingFrame(pick) {
  const box = useRef(null)
  const frame = useRef(null)

  useLayoutEffect(() => {
    frameTo(box.current, frame.current, pick, true)
  })

  useLayoutEffect(() => {
    const b = box.current
    const f = frame.current
    const watch = new ResizeObserver(() => frameTo(b, f, pick, false))
    watch.observe(b)
    return () => watch.disconnect()
  }, [pick])

  return [box, frame]
}

export function Seg2({ label, style, children }) {
  const [box, frame] = useSlidingFrame(':scope > .segopt.on')
  return (
    <div className="seg2" role="radiogroup" aria-label={label} style={style} ref={box}>
      <i className="pframe" ref={frame} aria-hidden="true" />
      {children}
    </div>
  )
}

export function ScrollSeg({ label, children }) {
  const [box, frame] = useSlidingFrame(':scope > .segopt.on')
  return (
    <div className="seg2 segwrap" role="radiogroup" aria-label={label} ref={box}>
      <i className="pframe" ref={frame} aria-hidden="true" />
      {children}
    </div>
  )
}

export function Tiles({ p3, label, children }) {
  const [grid, frame] = useSlidingFrame(':scope > .ptile.on')
  return (
    <div className={'pgrid' + (p3 ? ' p3' : '')} role="radiogroup" aria-label={label} ref={grid}>
      <i className="pframe" ref={frame} aria-hidden="true" />
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
