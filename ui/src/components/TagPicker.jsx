import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { CARD_TAGS } from '../lib/cardTags.js'
import { T } from '../i18n/fa.js'

const ARM_MS = 300
const STUCK_MS = 10000

export default function TagPicker({ current, onPick, onClose }) {
  const [armed, setArmed] = useState(false)
  const armTimer = useRef(0)
  const stuckTimer = useRef(0)
  const boxRef = useRef(null)
  const onCloseRef = useRef(onClose)

  onCloseRef.current = onClose

  useEffect(() => {
    let done = false
    const arm = () => {
      if (done) return
      done = true
      armTimer.current = setTimeout(() => setArmed(true), ARM_MS)
    }
    const onKey = (e) => {
      if (e.key === 'Escape') onCloseRef.current()
    }
    stuckTimer.current = setTimeout(arm, STUCK_MS)
    document.addEventListener('touchend', arm, true)
    document.addEventListener('touchcancel', arm, true)
    document.addEventListener('mouseup', arm, true)
    document.addEventListener('keyup', arm, true)
    document.addEventListener('keydown', onKey)
    const box = boxRef.current
    const dot = box && (box.querySelector('.tagdot.on') || box.querySelector('.tagdot'))
    if (dot) dot.focus()
    return () => {
      clearTimeout(armTimer.current)
      clearTimeout(stuckTimer.current)
      document.removeEventListener('touchend', arm, true)
      document.removeEventListener('touchcancel', arm, true)
      document.removeEventListener('mouseup', arm, true)
      document.removeEventListener('keyup', arm, true)
      document.removeEventListener('keydown', onKey)
    }
  }, [])

  const pick = (tag) => {
    if (!armed) return
    onPick(tag)
  }

  return createPortal(
    <div
      className="tagov"
      onContextMenu={(e) => e.preventDefault()}
      onClick={(e) => {
        if (!armed) return
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="tagbox" ref={boxRef}>
        <div className="tgt">{T('tag_title')}</div>
        <div className="tagpal">
          {CARD_TAGS.map((colors, i) => (
            <button
              key={i}
              type="button"
              className={'tagdot' + (current === i + 1 ? ' on' : '')}
              style={{ background: `linear-gradient(140deg,${colors.a},${colors.b})` }}
              onClick={() => pick(i + 1)}
            />
          ))}
        </div>
        <button type="button" className="tagnone" onClick={() => pick(0)}>
          {T('tag_clear')}
        </button>
      </div>
    </div>,
    document.body
  )
}
