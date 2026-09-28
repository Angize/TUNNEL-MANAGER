import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react'
import { closeDialog, subscribeDialogs } from '../lib/dialog.js'
import { restoreFocus, trapTab } from '../lib/focusTrap.js'
import { leaveGhost } from '../lib/leaveGhost.js'
import { reducedMotion } from '../lib/motion.js'
import SwitchRow from './SwitchRow.jsx'
import { T } from '../i18n/fa.js'

let pressed = null

function originCard(entry) {
  if (!entry.danger || reducedMotion()) return null
  const focused = document.activeElement
  const src = focused && focused !== document.body ? focused : pressed
  return src && src.closest ? src.closest('.card') : null
}

function offsetTo(card, box) {
  const c = card.getBoundingClientRect()
  return {
    '--fx': c.left + c.width / 2 - (box.offsetLeft + box.offsetWidth / 2) + 'px',
    '--fy': c.top + c.height / 2 - (box.offsetTop + box.offsetHeight / 2) + 'px',
  }
}

function Dialog({ entry, top }) {
  const box = useRef(null)
  const safe = useRef(null)
  const veil = useRef(null)
  const [from, setFrom] = useState(null)
  const [on, setOn] = useState(entry.toggle ? !!entry.toggle.on : false)
  const textId = useId()

  useEffect(() => {
    const opener = document.activeElement
    return () => restoreFocus(opener)
  }, [])

  useEffect(() => {
    if (top && safe.current) safe.current.focus()
  }, [top])

  useLayoutEffect(() => {
    const el = box.current
    const card = originCard(entry)
    if (!card) return undefined
    setFrom(offsetTo(card, el))
    return () => {
      if (!card.isConnected) return
      const back = offsetTo(card, el)
      el.style.setProperty('--fx', back['--fx'])
      el.style.setProperty('--fy', back['--fy'])
    }
  }, [entry])

  useLayoutEffect(() => {
    const node = veil.current
    return () => leaveGhost(node)
  }, [])

  const cancelValue = entry.kind === 'confirm' ? false : undefined

  return (
    <div
      ref={veil}
      className="modalov dlgov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) closeDialog(entry.id, cancelValue)
      }}
    >
      <div
        className={'modal' + (from ? ' fromcard' : '')}
        style={from || undefined}
        ref={box}
        role="alertdialog"
        aria-modal="true"
        aria-describedby={textId}
        tabIndex={-1}
        onKeyDown={(e) => trapTab(e, box.current)}
      >
        <div className="mtext" id={textId}>
          {typeof entry.msg === 'function' ? entry.msg(on) : entry.msg}
        </div>
        {entry.toggle ? (
          <div className="dlgsw-wrap">
            <SwitchRow on={on} title={entry.toggle.title} note={entry.toggle.note} onToggle={() => setOn(!on)} />
          </div>
        ) : null}
        <div className="mbtns">
          {entry.kind === 'confirm' ? (
            <>
              <button
                type="button"
                className={'primary' + (entry.danger ? ' danger' : '')}
                onClick={() => closeDialog(entry.id, entry.toggle ? { on } : true)}
              >
                {entry.yesLabel}
              </button>
              <button type="button" ref={safe} className="ghost" onClick={() => closeDialog(entry.id, false)}>
                {T('cancel')}
              </button>
            </>
          ) : (
            <button type="button" ref={safe} className="primary" onClick={() => closeDialog(entry.id)}>
              {T('got_it')}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

export default function DialogHost() {
  const [stack, setStack] = useState([])
  const stackRef = useRef(stack)
  stackRef.current = stack

  useEffect(() => subscribeDialogs(setStack), [])

  useEffect(() => {
    const onDown = (e) => {
      pressed = e.target
    }
    document.addEventListener('pointerdown', onDown, true)
    return () => document.removeEventListener('pointerdown', onDown, true)
  }, [])

  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== 'Escape') return
      const cur = stackRef.current
      if (!cur.length) return
      const top = cur[cur.length - 1]
      e.stopImmediatePropagation()
      closeDialog(top.id, top.kind === 'confirm' ? false : undefined)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [])

  return stack.map((entry, i) => (
    <Dialog key={entry.id} entry={entry} top={i === stack.length - 1} />
  ))
}
