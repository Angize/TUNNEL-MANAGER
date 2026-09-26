import { useEffect, useId, useRef, useState } from 'react'
import { closeDialog, subscribeDialogs } from '../lib/dialog.js'
import { restoreFocus, trapTab } from '../lib/focusTrap.js'
import { T } from '../i18n/fa.js'

function Dialog({ entry, top }) {
  const box = useRef(null)
  const safe = useRef(null)
  const textId = useId()

  useEffect(() => {
    const opener = document.activeElement
    return () => restoreFocus(opener)
  }, [])

  useEffect(() => {
    if (top && safe.current) safe.current.focus()
  }, [top])

  const cancelValue = entry.kind === 'confirm' ? false : undefined

  return (
    <div
      className="modalov dlgov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) closeDialog(entry.id, cancelValue)
      }}
    >
      <div
        className="modal"
        ref={box}
        role="alertdialog"
        aria-modal="true"
        aria-describedby={textId}
        tabIndex={-1}
        onKeyDown={(e) => trapTab(e, box.current)}
      >
        <div className="mtext" id={textId}>
          {entry.msg}
        </div>
        <div className="mbtns">
          {entry.kind === 'confirm' ? (
            <>
              <button
                type="button"
                className={'primary' + (entry.danger ? ' danger' : '')}
                onClick={() => closeDialog(entry.id, true)}
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
