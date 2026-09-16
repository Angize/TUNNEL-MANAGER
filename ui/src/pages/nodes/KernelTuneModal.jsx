import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'

function Tile({ icon, label, children, wide }) {
  return (
    <div className={'nd-tile' + (wide ? ' nd-wide' : '')}>
      <span className="medi">
        <Icon name={icon} />
      </span>
      <span>{label}</span>
      <b>{children}</b>
    </div>
  )
}

export default function KernelTuneModal({ node, onClose }) {
  const [status, setStatus] = useState(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState(null)
  const closeRef = useRef(onClose)

  closeRef.current = onClose

  useEffect(() => {
    let alive = true
    apiPost('node-kernel-tune', { id: node.id, action: 'status' })
      .then((r) => {
        if (!alive) return
        if (!(r.ok && r.d.ok)) {
          toast(readError(r), 'err')
          closeRef.current()
          return
        }
        setStatus(r.d)
      })
    return () => {
      alive = false
    }
  }, [node.id])

  if (!status) return null

  const active = !!status.active
  const bbr = !!status.bbr_available

  const run = async (action) => {
    setBusy(true)
    setMessage({ cls: '', text: T('kt_working') })
    const r = await apiPost('node-kernel-tune', { id: node.id, action })
    if (r.ok && r.d.ok) {
      toast(action === 'apply' ? T('kt_enabled') : T('kt_disabled'), 'ok')
      setStatus(r.d)
      setMessage(null)
      setBusy(false)
      return
    }
    setMessage({ cls: 'err', text: postError(r) })
    setBusy(false)
  }

  const footer = (
    <>
      {active ? (
        <button className="primary" disabled={busy} onClick={() => run('revert')}>
          {T('kt_disable')}
        </button>
      ) : (
        <button className="primary" disabled={busy || !bbr} onClick={() => run('apply')}>
          {T('kt_enable')}
        </button>
      )}
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal icon="gauge" title={T('kt_title')} subtitle={T('kt_sub')} footer={footer} onClose={onClose}>
      <div className="kt-desc">{T('kt_desc')}</div>
      <div className="nd-grid">
        <Tile icon="activity" label={T('kt_state')} wide>
          <span className={'lpill' + (active ? '' : ' off')}>
            <span className="pd" />
            {T(active ? 'kt_on' : 'kt_off')}
          </span>
        </Tile>
        <Tile icon="traf" label={T('kt_cc')}>
          <span className="mono">{status.cc || '?'}</span>
        </Tile>
        <Tile icon="swap" label={T('kt_qdisc')}>
          <span className="mono">{status.qdisc || '?'}</span>
        </Tile>
      </div>
      {bbr ? null : <div className="msg err" style={{ marginTop: 9 }}>{T('kt_nobbr')}</div>}
      <div className={message ? 'msg ' + message.cls : 'msg'}>{message ? message.text : null}</div>
    </Modal>
  )
}
