import { useEffect, useId, useLayoutEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'
import { coarsePointer, restoreFocus, trapTab } from '../lib/focusTrap.js'
import { leaveGhost } from '../lib/leaveGhost.js'
import { EASE_DRAWER, EASE_OUT, narrow, reducedMotion } from '../lib/motion.js'

const open = []
let bodyOverflow = ''


function growFrom(el, was) {
  const d = el.offsetHeight - was
  if (d <= 0 || reducedMotion()) return
  if (narrow()) {
    el.animate([{ transform: 'translateY(' + d + 'px)' }, { transform: 'none' }], {
      duration: 320,
      easing: EASE_DRAWER,
      composite: 'add',
    })
  } else {
    el.animate([{ clipPath: 'inset(' + d / 2 + 'px 0 round 22px)' }, { clipPath: 'inset(0 round 22px)' }], {
      duration: 260,
      easing: EASE_OUT,
    })
  }
  for (const part of el.querySelectorAll('.mbody, .mfoot')) {
    part.animate([{ opacity: 0, transform: 'translateY(4px)' }, { opacity: 1, transform: 'none' }], {
      duration: 200,
      delay: 60,
      easing: EASE_OUT,
      fill: 'backwards',
    })
  }
}

export default function Modal({ icon, title, subtitle, footer, onClose, cls, bare, label, loading, children }) {
  const id = useId()
  const titleId = id + 't'
  const box = useRef(null)
  const veil = useRef(null)
  const loadedFrom = useRef(0)
  const closeRef = useRef(onClose)
  closeRef.current = onClose

  useEffect(() => {
    const opener = document.activeElement
    if (!open.length) {
      bodyOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
    }
    open.push(id)
    const onKey = (e) => {
      if (open[open.length - 1] !== id || document.querySelector('.dlgov:not(.leaving)')) return
      if (e.key === 'Escape') {
        e.stopImmediatePropagation()
        closeRef.current()
        return
      }
      trapTab(e, box.current)
    }
    document.addEventListener('keydown', onKey)
    const field = !coarsePointer() && box.current && box.current.querySelector('input,select,textarea')
    if (field) field.focus()
    else if (box.current) box.current.focus()
    return () => {
      const i = open.indexOf(id)
      if (i >= 0) open.splice(i, 1)
      document.removeEventListener('keydown', onKey)
      if (!open.length) document.body.style.overflow = bodyOverflow
      restoreFocus(opener)
    }
  }, [id])

  useLayoutEffect(() => {
    const node = veil.current
    return () => leaveGhost(node)
  }, [])

  useLayoutEffect(() => {
    const el = box.current
    if (!el) return
    if (loading) {
      loadedFrom.current = el.offsetHeight
      return
    }
    const was = loadedFrom.current
    if (!was) return
    loadedFrom.current = 0
    const field = !coarsePointer() && el.querySelector('input,select,textarea')
    if (field) field.focus()
    growFrom(el, was)
  }, [loading])

  return createPortal(
    <div
      ref={veil}
      className="modalov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div
        className={'modal wide' + (cls ? ' ' + cls : '')}
        ref={box}
        role="dialog"
        aria-modal="true"
        aria-labelledby={bare ? undefined : titleId}
        aria-label={bare ? label : undefined}
        tabIndex={-1}
      >
        {bare ? (
          children
        ) : (
          <>
            <div className="msticky">
              {icon ? (
                <span className="medi" aria-hidden="true">
                  <Icon name={icon} />
                </span>
              ) : null}
              <div className="ttl">
                <h3 id={titleId}>{title}</h3>
                {subtitle ? <div className="sb">{subtitle}</div> : null}
              </div>
              <button type="button" className="mx" aria-label={T('close')} onClick={onClose}>
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
