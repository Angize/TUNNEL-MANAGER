import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import Icon from './Icon.jsx'
import { T } from '../i18n/fa.js'
import { checkable } from '../lib/keys.js'
import { coarsePointer, trapTab } from '../lib/focusTrap.js'
import { leaveGhost } from '../lib/leaveGhost.js'

const SEARCH_FROM = 10
const GAP = 6
const EDGE = 12
const MIN_W = 180

function place(pop, anchor) {
  const r = anchor.getBoundingClientRect()
  const below = innerHeight - r.bottom - GAP - EDGE
  const above = r.top - GAP - EDGE
  const w = Math.min(Math.max(r.width, MIN_W), innerWidth - 2 * EDGE)
  pop.style.maxHeight = ''
  const up = pop.offsetHeight > below && above > below
  pop.classList.toggle('up', up)
  Object.assign(pop.style, {
    width: w + 'px',
    left: Math.min(Math.max(r.right - w, EDGE), innerWidth - EDGE - w) + 'px',
    top: up ? '' : r.bottom + GAP + 'px',
    bottom: up ? innerHeight - r.top + GAP + 'px' : '',
    maxHeight: Math.max(up ? above : below, 120) + 'px',
  })
}

function SelectPop({ anchor, label, onClose, children }) {
  const veil = useRef(null)
  const box = useRef(null)

  useLayoutEffect(() => {
    place(box.current, anchor.current)
  })

  useLayoutEffect(() => {
    const node = veil.current
    return () => leaveGhost(node)
  }, [])

  useLayoutEffect(() => {
    const pop = box.current
    const redo = () => place(pop, anchor.current)
    const onScroll = (e) => {
      if (!pop.contains(e.target)) redo()
    }
    addEventListener('resize', redo)
    document.addEventListener('scroll', onScroll, true)
    return () => {
      removeEventListener('resize', redo)
      document.removeEventListener('scroll', onScroll, true)
    }
  }, [anchor])

  useEffect(() => {
    const pop = box.current
    const field = !coarsePointer() && pop.querySelector('input')
    const row = pop.querySelector('.msrow.sel') || pop.querySelector('.msrow')
    const target = field || row || pop
    target.focus()
  }, [])

  return createPortal(
    <div
      ref={veil}
      className="selov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
      onKeyDown={(e) => {
        if (e.key === 'Escape') {
          e.stopPropagation()
          onClose()
        } else if (e.key === 'Tab') {
          e.stopPropagation()
          trapTab(e, box.current)
        }
      }}
    >
      <div ref={box} className="selpop" role="dialog" aria-modal="true" aria-label={label} tabIndex={-1}>
        {children}
      </div>
    </div>,
    document.body
  )
}

export default function Select({ items, value, placeholder, onChange, id, ...aria }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const buttonRef = useRef(null)

  const list = items || []
  const cur = list.find((x) => String(x.v) === String(value))
  const needle = q.trim().toLowerCase()
  const shown = needle
    ? list.filter((it) =>
        ((it.label || '') + ' ' + (it.sub || '')).toLowerCase().includes(needle)
      )
    : list

  const close = () => {
    setOpen(false)
    setQ('')
    if (buttonRef.current) buttonRef.current.focus()
  }

  const pick = (v) => {
    close()
    onChange(v)
  }

  return (
    <>
      <button
        ref={buttonRef}
        id={id}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open ? 'true' : 'false'}
        {...aria}
        className={'msbtn' + (cur ? '' : ' ph') + (open ? ' open' : '')}
        onClick={() => list.length && setOpen(true)}
      >
        <span>{cur ? cur.label : placeholder || T('select')}</span>
        <span className="cv">
          <Icon name="chev" />
        </span>
      </button>
      {open ? (
        <SelectPop anchor={buttonRef} label={placeholder || T('select')} onClose={close}>
          <div className="sspop">
            {list.length > SEARCH_FROM ? (
              <input
                className="search sspopq"
                placeholder={T('search')}
                autoComplete="off"
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            ) : null}
            <div className="sspoplist" role="radiogroup">
              {shown.map((it) => (
                <div
                  key={String(it.v)}
                  className={'msrow' + (String(it.v) === String(value) ? ' sel' : '')}
                  {...checkable('radio', String(it.v) === String(value), () => pick(it.v))}
                >
                  <span className="mscheck" />
                  <span>{it.label}</span>
                  {it.sub ? <span className="mssub">{it.sub}</span> : null}
                </div>
              ))}
            </div>
          </div>
        </SelectPop>
      ) : null}
    </>
  )
}
