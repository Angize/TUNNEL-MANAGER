import { useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { ActionButton } from '../core/form/HealthRow.jsx'
import useFlipList from '../../lib/useFlipList.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { LTR_TEXT } from '../../lib/form.js'
import { edgeError, edgePort } from '../../lib/cdn.js'
import { T, TF } from '../../i18n/fa.js'
import '../core/coreform.css'

export default function CdnEdges({ edges, onStatus }) {
  const [draft, setDraft] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const list = useRef(null)
  const rows = edges || []
  useFlipList(list, rows, 'cdnedges')

  const save = async (next, what) => {
    setBusy(what)
    const r = await apiPost('settings-set', { cdn_edges: next })
    setBusy('')
    if (!(r.ok && r.d.settings)) {
      toast(postError(r), 'err')
      return false
    }
    onStatus()
    return true
  }

  const add = async () => {
    const v = draft.trim()
    if (!v) return
    const bad = edgeError(v)
    if (bad) {
      setError(bad)
      return
    }
    if (rows.includes(v)) {
      setDraft('')
      return
    }
    if (await save(rows.concat(v), '+')) {
      setDraft('')
      setError('')
    }
  }

  return (
    <div className="card opc sc-panel apcard cdnhosts cdnedges">
      <div className="ophd">
        <span className="sgt cdnedgesi">
          <Icon name="grid" />
        </span>
        <div className="hd2">
          <b>{T('edges_t')}</b>
          <small>{T('edges_d')}</small>
        </div>
        <span className={'cdnchip ' + (rows.length ? 'ok' : 'off')}>
          {rows.length ? TF('edges_n', { n: rows.length }) : T('cdn_hosts_zero')}
        </span>
      </div>
      <div className="cdnhostl" ref={list}>
        {rows.map((e) => (
          <div key={e} className="erow ok">
            <span className="estat ok">
              <Icon name="okc" />
            </span>
            <span className="cdnhostc">
              <span className="eip" dir="ltr">
                {e}
              </span>
              <span className="cdnhostm">{edgePort(e) ? TF('edges_port', { p: edgePort(e) }) : T('edges_port_any')}</span>
            </span>
            <span className="eacts">
              <ActionButton
                icon="trash"
                tone="del"
                title={T('tip_delete')}
                spinning={busy === e}
                disabled={!!busy}
                onClick={() => save(rows.filter((x) => x !== e), e)}
              />
            </span>
          </div>
        ))}
      </div>
      {rows.length ? null : <div className="cdnempty">{T('edges_none')}</div>}
      <div className="cdnsni">
        <input
          {...LTR_TEXT}
          className="mono"
          aria-label={T('edges_add_ph')}
          placeholder="104.16.0.1:443"
          value={draft}
          onChange={(e) => {
            setDraft(e.target.value)
            setError('')
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') add()
          }}
        />
        <button type="button" className="padd" aria-label={T('edges_add')} disabled={!!busy} onClick={add}>
          {busy === '+' ? <span className="bspin sm" /> : '+'}
        </button>
      </div>
      {error ? <div className="cdnedgeerr">{error}</div> : null}
    </div>
  )
}
