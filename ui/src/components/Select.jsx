import { useEffect, useRef, useState } from 'react'
import Icon from './Icon.jsx'
import Modal from './Modal.jsx'
import { T } from '../i18n/fa.js'
import { checkable } from '../lib/keys.js'

const SEARCH_FROM = 10

export default function Select({ items, value, placeholder, onChange, id, ...aria }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const listRef = useRef(null)
  const buttonRef = useRef(null)

  const list = items || []
  const cur = list.find((x) => String(x.v) === String(value))
  const needle = q.trim().toLowerCase()
  const shown = needle
    ? list.filter((it) =>
        ((it.label || '') + ' ' + (it.sub || '')).toLowerCase().includes(needle)
      )
    : list

  useEffect(() => {
    if (!open || !listRef.current || listRef.current.parentElement.querySelector('input')) return
    const row = listRef.current.querySelector('.msrow.sel') || listRef.current.querySelector('.msrow')
    if (row) row.focus()
  }, [open])

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
        <Modal bare cls="sssheet" label={placeholder || T('select')} onClose={close}>
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
            <div className="sspoplist" role="radiogroup" ref={listRef}>
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
        </Modal>
      ) : null}
    </>
  )
}
