import { useState } from 'react'
import Icon from './Icon.jsx'
import Modal from './Modal.jsx'
import { T } from '../i18n/fa.js'

const SEARCH_FROM = 10

export default function Select({ items, value, placeholder, onChange }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')

  const list = items || []
  const cur = list.find((x) => String(x.v) === String(value))
  const needle = q.trim().toLowerCase()
  const shown = needle
    ? list.filter((it) =>
        ((it.label || '') + ' ' + (it.sub || '')).toLowerCase().includes(needle)
      )
    : list

  const pick = (v) => {
    setOpen(false)
    setQ('')
    onChange(v)
  }

  return (
    <>
      <button
        type="button"
        className={'msbtn' + (cur ? '' : ' ph') + (open ? ' open' : '')}
        onClick={() => list.length && setOpen(true)}
      >
        <span>{cur ? cur.label : placeholder || T('select')}</span>
        <span className="cv">
          <Icon name="chev" />
        </span>
      </button>
      {open ? (
        <Modal bare cls="sssheet" onClose={() => setOpen(false)}>
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
            <div className="sspoplist">
              {shown.map((it) => (
                <div
                  key={String(it.v)}
                  className={'msrow' + (String(it.v) === String(value) ? ' sel' : '')}
                  onClick={() => pick(it.v)}
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
