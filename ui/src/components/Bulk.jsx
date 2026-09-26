import { useEffect, useLayoutEffect, useRef } from 'react'
import { createPortal } from 'react-dom'
import Icon from './Icon.jsx'
import { BULK_ACTIONS, bulkNames } from '../lib/useBulk.js'
import { T } from '../i18n/fa.js'
import { leaveGhost } from '../lib/leaveGhost.js'
import './bulk.css'

export function BulkButton({ bulk }) {
  if (bulk.run) {
    const { key, i, k } = bulk.run
    const action = BULK_ACTIONS.find((a) => a.key === key)
    return (
      <div className="bulkrun">
        <Icon name={action.icon} />
        <span className="tx">{T('bulk_p_' + key) + ' ' + i + ' ' + T('bulk_of') + ' ' + k}</span>
        <span className="bar">
          <i style={{ width: Math.round((100 * i) / Math.max(k, 1)) + '%' }} />
        </span>
        {key === 'ping' ? null : (
          <button type="button" className="stop" onClick={bulk.stop}>
            {T('bulk_stop')}
          </button>
        )}
      </div>
    )
  }
  return (
    <button
      className={'ghost tone bulkbtn' + (bulk.selecting ? ' on' : '')}
      onClick={bulk.selecting ? bulk.exit : bulk.start}
    >
      <Icon name={bulk.selecting ? 'check' : 'grid'} />
      {bulk.selecting ? T('bulk_selecting') : T('bulk_btn')}
    </button>
  )
}

export function SelBox({ on }) {
  return (
    <span className={'selck' + (on ? ' on' : '')} role="checkbox" aria-checked={on ? 'true' : 'false'}>
      <Icon name="check" />
    </span>
  )
}

function Bar({ bulk }) {
  const k = bulk.picked.size

  useEffect(() => {
    document.body.classList.add('bulksel')
    return () => document.body.classList.remove('bulksel')
  }, [])

  return createPortal(
    <div className="bulkbar">
      <button type="button" className="x" title={T('bulk_exit')} onClick={bulk.exit}>
        <Icon name="x" />
      </button>
      <span className="cnt">{k + ' ' + T('bulk_of') + ' ' + bulk.count}</span>
      <button type="button" className="all" onClick={bulk.pickAll}>
        {bulk.allPicked ? T('bulk_none') : T('bulk_all')}
      </button>
      <button type="button" className="ghost tone go" disabled={!k} onClick={bulk.openSheet}>
        <Icon name="grid" />
        {T('bulk_go')}
      </button>
    </div>,
    document.body
  )
}

export function BulkBar({ bulk, active }) {
  return bulk.selecting && active ? <Bar bulk={bulk} /> : null
}

function Sheet({ bulk, links, core }) {
  const close = bulk.closeSheet
  const veil = useRef(null)
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === 'Escape') close()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [close])

  useLayoutEffect(() => {
    const node = veil.current
    return () => leaveGhost(node)
  }, [])

  const chosen = (links || []).filter((l) => bulk.picked.has(l.id))
  const actions = BULK_ACTIONS.filter((a) => core || !a.coreOnly)

  return createPortal(
    <div
      ref={veil}
      className="bsheetov"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) close()
      }}
    >
      <div className="bsheet">
        <div className="hdl" />
        <div className="bst">{T('bulk_title').replace('{k}', String(chosen.length))}</div>
        <div className="bss">{bulkNames(chosen)}</div>
        <div className="btiles">
          {actions.map((a, i) => (
            <button
              key={a.key}
              type="button"
              className={'btile t-' + a.tone}
              style={{ '--i': i }}
              onClick={() => bulk.perform(a)}
            >
              <span className="chip">
                <Icon name={a.icon} />
              </span>
              {T('bulk_t_' + a.key)}
            </button>
          ))}
        </div>
        <button type="button" className="bcancel" onClick={close}>
          {T('cancel')}
        </button>
      </div>
    </div>,
    document.body
  )
}

export function BulkSheet(props) {
  return props.bulk.sheet ? <Sheet {...props} /> : null
}
