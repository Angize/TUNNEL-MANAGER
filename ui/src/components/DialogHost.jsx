import { useEffect, useRef, useState } from 'react'
import { closeDialog, subscribeDialogs } from '../lib/dialog.js'
import { T } from '../i18n/fa.js'

function Dialog({ entry, top }) {
  const primary = useRef(null)

  useEffect(() => {
    if (top && primary.current) primary.current.focus()
  }, [top])

  const cancelValue = entry.kind === 'confirm' ? false : undefined

  return (
    <div
      className="modalov dlgov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) closeDialog(entry.id, cancelValue)
      }}
    >
      <div className="modal">
        <div className="mtext">{entry.msg}</div>
        <div className="mbtns">
          {entry.kind === 'confirm' ? (
            <>
              <button
                ref={primary}
                className="primary"
                onClick={() => closeDialog(entry.id, true)}
              >
                {entry.yesLabel}
              </button>
              <button className="ghost" onClick={() => closeDialog(entry.id, false)}>
                {T('cancel')}
              </button>
            </>
          ) : (
            <button ref={primary} className="primary" onClick={() => closeDialog(entry.id)}>
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
