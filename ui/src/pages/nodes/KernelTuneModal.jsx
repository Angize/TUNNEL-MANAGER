import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import ModalLoading from '../../components/ModalLoading.jsx'
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

  if (!status) {
    return <ModalLoading icon="gauge" title={T('kt_title')} subtitle={T('kt_sub')} onClose={onClose} />
  }

  const active = !!status.active
  const bbr = !!status.bbr_available
  const changed = status.overridden

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
          {busy ? <span className="bspin" /> : T('kt_disable')}
        </button>
      ) : (
        <button className="primary" disabled={busy} onClick={() => run('apply')}>
          {busy ? <span className="bspin" /> : T('kt_enable')}
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
          <span className={'lpill' + (active ? (changed.length ? ' warn' : '') : ' off')}>
            <span className="pd" />
            {T(active ? (changed.length ? 'kt_on_changed' : 'kt_on') : 'kt_off')}
          </span>
        </Tile>
        <Tile icon="traf" label={T('kt_cc')}>
          <span className="mono">{status.cc || '?'}</span>
        </Tile>
        <Tile icon="swap" label={T('kt_qdisc')}>
          <span className="mono">{status.qdisc || '?'}</span>
        </Tile>
        {changed.length ? (
          <Tile icon="warn" label={T('kt_changed_head')} wide>
            {changed.map((c) => (
              <span key={c.key} className="kt-chg">
                <span className="mono kt-k">{c.key}</span>
                <span className="kt-vs">
                  <span>
                    {T('kt_want')} <bdi className="mono">{c.want}</bdi>
                  </span>
                  <span>
                    {T('kt_now')} <bdi className="mono">{c.now || '?'}</bdi>
                  </span>
                </span>
              </span>
            ))}
          </Tile>
        ) : null}
      </div>
      {bbr ? null : <div className="msg" style={{ marginTop: 9 }}>{T('kt_nobbr')}</div>}
      <div className={message ? 'msg ' + message.cls : 'msg'}>{message ? message.text : null}</div>
    </Modal>
  )
}
