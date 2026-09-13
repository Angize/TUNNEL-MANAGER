import { useEffect, useId, useRef } from 'react'
import { createPortal } from 'react-dom'
import Icon from './Icon.jsx'

const open = []

export default function Modal({ icon, title, subtitle, footer, onClose, cls, bare, children }) {
  const id = useId()
  const box = useRef(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose

  useEffect(() => {
    open.push(id)
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onKey = (e) => {
      if (e.key !== 'Escape') return
      if (open[open.length - 1] !== id) return
      e.stopImmediatePropagation()
      closeRef.current()
    }
    document.addEventListener('keydown', onKey)
    const field = box.current && box.current.querySelector('input,select,textarea')
    if (field) field.focus()
    return () => {
      const i = open.indexOf(id)
      if (i >= 0) open.splice(i, 1)
      document.removeEventListener('keydown', onKey)
      if (!open.length) document.body.style.overflow = prev
    }
  }, [id])

  return createPortal(
    <div
      className="modalov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className={'modal wide' + (cls ? ' ' + cls : '')} ref={box}>
        {bare ? (
          children
        ) : (
          <>
            <div className="msticky">
              {icon ? (
                <span className="medi">
                  <Icon name={icon} />
                </span>
              ) : null}
              <div className="ttl">
                <h3>{title}</h3>
                {subtitle ? <div className="sb">{subtitle}</div> : null}
              </div>
              <button className="mx" onClick={onClose}>
                ✕
              </button>
            </div>
            <div className="mbody">{children}</div>
            {footer ? <div className="mfoot">{footer}</div> : null}
          </>
        )}
      </div>
    </div>,
    document.body
  )
}
