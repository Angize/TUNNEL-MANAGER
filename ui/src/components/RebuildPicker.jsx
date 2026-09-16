import { useEffect, useRef, useState } from 'react'
import Modal from './Modal.jsx'
import Icon from './Icon.jsx'
import IpChips from './IpChips.jsx'
import { T } from '../i18n/fa.js'
import { apiPost } from '../lib/api.js'
import { postError, translateError } from '../lib/errors.js'
import { toast } from '../lib/toast.js'
import useBusy from '../lib/useBusy.js'
import { useActs } from '../state/ActsContext.jsx'

const SIDES = [
  ['a', 'a_ip'],
  ['b', 'b_ip'],
]

function firstChoice(side) {
  const free = (side.ips || []).find((x) => x.free)
  if (free) return free.ip
  return ((side.ips || [])[0] || {}).ip || ''
}

export default function RebuildPicker({ id, onClose, onDone }) {
  const [info, setInfo] = useState(null)
  const [picked, setPicked] = useState({})
  const [message, setMessage] = useState('')
  const [busy, guard] = useBusy()
  const { waitAccepted } = useActs()
  const closeRef = useRef(onClose)
  const doneRef = useRef(onDone)

  closeRef.current = onClose
  doneRef.current = onDone

  useEffect(() => {
    let alive = true
    apiPost('link-rebuild-info', { id })
      .then((r) => {
        if (!alive) return
        const d = r.d
        if (!d || !d.id) {
          toast(T('rb_no_link'), 'err')
          closeRef.current()
          return
        }
        const chosen = {}
        for (const [side, key] of SIDES) {
          if (!d[side] || !d[side].drifted) continue
          chosen[key] = firstChoice(d[side])
        }
        if (!Object.keys(chosen).length) {
          toast(T('rb_no_drift'), 'ok')
          closeRef.current()
          doneRef.current()
          return
        }
        setPicked(chosen)
        setInfo(d)
      })
      .catch(() => {
        if (!alive) return
        toast(T('rb_fetch_err'), 'err')
        closeRef.current()
      })
    return () => {
      alive = false
    }
  }, [id])

  if (!info) return null

  const rebuild = async () => {
    const body = { id }
    if (picked.a_ip) body.a_ip = picked.a_ip
    if (picked.b_ip) body.b_ip = picked.b_ip
    setMessage(T('rebuilding'))
    const r = await apiPost('rebuild-link', body)
    if (!(r.ok && r.d.act)) {
      setMessage('')
      toast(postError(r, 'rebuild_failed'), 'err')
      return
    }
    const verdict = await waitAccepted(r.d.act, () => true)
    if (verdict.gone) return
    if (verdict.err || verdict.cancelled) {
      setMessage('')
      toast(
        verdict.cancelled ? T('a_stopped') : translateError(verdict.err) || T('rebuild_failed'),
        'err'
      )
      return
    }
    onClose()
    onDone()
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(rebuild)}>
        {busy ? (
          <span className="bspin" />
        ) : (
          <>
            <Icon name="redo" />
            {T('tip_rebuild')}
          </>
        )}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon="redo"
      title={T('rb_title')}
      subtitle={info.name || ''}
      footer={footer}
      onClose={onClose}
    >
      <div style={{ color: 'var(--sub)', fontSize: 12, marginBottom: 12 }}>{T('rb_info')}</div>
      {SIDES.map(([side, key]) => {
        const block = info[side]
        if (!block || !block.drifted) return null
        const ips = block.ips || []
        return (
          <div key={key}>
            <div className="nd-sec">{block.node + ' — ' + T('rb_newip')}</div>
            <div className="rbsec">
              {ips.length ? (
                ips.map((entry) => (
                  <div
                    key={entry.ip}
                    className={'rbrow' + (picked[key] === entry.ip ? ' sel' : '')}
                    onClick={() => setPicked((prev) => ({ ...prev, [key]: entry.ip }))}
                  >
                    <span className="rbdot" />
                    <span className="mono" style={{ direction: 'ltr', fontSize: 13 }}>
                      {entry.ip}
                    </span>
                    <span className="rbtags">
                      <IpChips entry={entry} />
                    </span>
                  </div>
                ))
              ) : (
                <div className="muted" style={{ fontSize: 12, padding: '4px 2px' }}>
                  {T('rb_no_ip')}
                </div>
              )}
            </div>
          </div>
        )
      })}
      <div className="msg">{message}</div>
    </Modal>
  )
}
