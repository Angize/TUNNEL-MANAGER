import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from './Icon.jsx'
import RichText from './RichText.jsx'
import { T } from '../i18n/fa.js'
import './helppop.css'

const GAP = 8
const EDGE = 12

export default function HelpPop({ id, anchor, title, text, example, leaving, onClose }) {
  const box = useRef(null)
  const body = useRef(null)
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
      const inner = body.current
      const h = b.offsetHeight + (inner ? inner.scrollHeight - inner.clientHeight : 0)
      const roomBelow = innerHeight - EDGE - r.bottom - GAP
      const roomAbove = r.top - GAP - EDGE
      const below = h <= roomBelow || (h > roomAbove && roomBelow >= roomAbove)
      const room = below ? roomBelow : roomAbove
      const fit = Math.min(h, room)
      const left = Math.min(Math.max(EDGE, r.left + r.width / 2 - w / 2), innerWidth - EDGE - w)
      setPos({
        left,
        top: below ? r.bottom + GAP : r.top - GAP - fit,
        below,
        max: h > room ? room : null,
        tip: r.left + r.width / 2 - left,
      })
    }
    const onScroll = (e) => {
      if (box.current && box.current.contains(e.target)) return
      place()
    }
    place()
    addEventListener('resize', place)
    addEventListener('scroll', onScroll, true)
    return () => {
      removeEventListener('resize', place)
      removeEventListener('scroll', onScroll, true)
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
    ? { left: pos.left, top: pos.top, maxHeight: pos.max || undefined, '--tip': pos.tip + 'px' }
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
          <Icon name="x" />
        </button>
      </div>
      <div ref={body} className="hpbd">
        <p>
          <RichText text={text} />
        </p>
        {example ? (
          <p className="hpex">
            <RichText text={example} />
          </p>
        ) : null}
      </div>
    </div>,
    document.body,
  )
}
