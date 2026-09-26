import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import RichText from './RichText.jsx'
import { T } from '../i18n/fa.js'
import './helppop.css'

const GAP = 8
const EDGE = 12

export default function HelpPop({ id, anchor, title, text, example, leaving, onClose }) {
  const box = useRef(null)
  const [pos, setPos] = useState(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose

  useLayoutEffect(() => {
    const place = () => {
      const a = anchor.current
      const b = box.current
      if (!a || !b) return
      const r = a.getBoundingClientRect()
      if (r.bottom < 0 || r.top > innerHeight) {
        closeRef.current(false)
        return
      }
      const w = b.offsetWidth
      const h = b.offsetHeight
      const below = r.bottom + GAP + h <= innerHeight - EDGE || r.top - GAP - h < EDGE
      const left = Math.min(Math.max(EDGE, r.left + r.width / 2 - w / 2), innerWidth - EDGE - w)
      setPos({ left, top: below ? r.bottom + GAP : r.top - GAP - h, below, tip: r.left + r.width / 2 - left })
    }
    place()
    addEventListener('resize', place)
    addEventListener('scroll', place, true)
    return () => {
      removeEventListener('resize', place)
      removeEventListener('scroll', place, true)
    }
  }, [anchor])

  useEffect(() => {
    const outside = (e) => {
      const t = e.target
      if (box.current && box.current.contains(t)) return
      if (anchor.current && anchor.current.contains(t)) return
      closeRef.current(false)
    }
    const onKey = (e) => {
      if (e.key === 'Escape') closeRef.current(true)
    }
    document.addEventListener('pointerdown', outside, true)
    document.addEventListener('keydown', onKey)
    if (box.current) box.current.focus({ preventScroll: true })
    return () => {
      document.removeEventListener('pointerdown', outside, true)
      document.removeEventListener('keydown', onKey)
    }
  }, [anchor])

  const style = pos
    ? { left: pos.left, top: pos.top, '--tip': pos.tip + 'px' }
    : { opacity: 0, left: 0, top: 0 }

  return createPortal(
    <div
      ref={box}
      id={id}
      className={'hpop' + (pos && !pos.below ? ' up' : '') + (leaving ? ' out' : '')}
      role="dialog"
      aria-labelledby={id + 't'}
      tabIndex={-1}
      style={style}
    >
      <div className="hphd">
        <b id={id + 't'}>{title}</b>
        <button type="button" className="hpx" aria-label={T('close')} onClick={() => closeRef.current(true)}>
          ×
        </button>
      </div>
      <p>
        <RichText text={text} />
      </p>
      {example ? (
        <p className="hpex">
          <RichText text={example} />
        </p>
      ) : null}
    </div>,
    document.body,
  )
}
