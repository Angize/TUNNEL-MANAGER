import { useEffect, useId, useLayoutEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'
import { coarsePointer, restoreFocus, trapTab } from '../lib/focusTrap.js'
import { leaveGhost } from '../lib/leaveGhost.js'
import { EASE_OUT, reducedMotion } from '../lib/motion.js'
import { formRows } from '../lib/formRows.js'
import { SwapRoot } from '../lib/revealSwap.js'

const open = []
let bodyOverflow = ''

function cascadeIn(el, from) {
  if (reducedMotion()) return
  const body = el.querySelector('.mbody')
  const bottom = el.getBoundingClientRect().bottom
  const rows = body ? formRows(body).filter((c) => c.getBoundingClientRect().top < bottom) : []
  const parts = [...(from ? [] : [el.querySelector('.msticky')]), ...rows.slice(0, 10), el.querySelector('.mfoot')]
  parts.filter(Boolean).forEach((part, i) => {
    part.animate([{ opacity: 0, transform: 'translateY(6px)' }, { opacity: 1, transform: 'none' }], {
      duration: 240,
      delay: 80 + i * 30,
      easing: EASE_OUT,
      fill: 'backwards',
    })
  })
}

function growFrom(el, was) {
  if (reducedMotion()) return
  const d = el.offsetHeight - was
  if (d > 0) {
    el.animate([{ clipPath: 'inset(' + d / 2 + 'px 0 round 22px)' }, { clipPath: 'inset(0 round 22px)' }], {
      duration: 260,
      easing: EASE_OUT,
    })
  }
  cascadeIn(el, true)
}

export default function Modal({ icon, title, subtitle, footer, onClose, cls, bare, label, loading, children }) {
  const id = useId()
  const titleId = id + 't'
  const box = useRef(null)
  const body = useRef(null)
  const veil = useRef(null)
  const loadedFrom = useRef(0)
  const cascadeOnOpen = useRef(!bare && !loading)
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
    if (cascadeOnOpen.current && box.current) cascadeIn(box.current)
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
            <div className="mbody" ref={body}>
              <SwapRoot value={body}>{children}</SwapRoot>
            </div>
            {footer ? <div className="mfoot">{footer}</div> : null}
          </>
        )}
      </div>
    </div>,
    document.body
  )
}
