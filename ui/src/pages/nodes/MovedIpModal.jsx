import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import Msg from '../../components/Msg.jsx'
import NodeTile from './NodeTile.jsx'

export default function MovedIpModal({ node, onClose, onAdopted }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')

  const adopt = async () => {
    setBusy(true)
    setMessage(T('mv_setting'))
    const r = await apiPost('node-adopt-ip', { id: node.id })
    if (r.ok && r.d.ok) {
      onClose()
      toast(T('mv_done') + r.d.host + ':' + r.d.port, 'ok')
      onAdopted()
      return
    }
    setMessage('')
    alertBox(postError(r))
    setBusy(false)
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={adopt}>
        {busy ? <span className="bspin" /> : <Icon name="check" />}
        {busy ? null : T('mv_set')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('close')}
      </button>
    </>
  )

  return (
    <Modal icon="warn" title={T('mv_title')} subtitle={node.name} footer={footer} onClose={onClose}>
      <div className="kt-desc">{T('mv_desc')}</div>
      <div className="nd-grid">
        <NodeTile icon="globe" label={T('mv_new')}>
          <span className="mono" style={{ direction: 'ltr' }}>
            {node.moved_to}
          </span>
        </NodeTile>
        <NodeTile icon="server" label={T('mv_old')}>
          <span className="mono" style={{ direction: 'ltr' }}>
            {node.host + ':' + node.port}
          </span>
        </NodeTile>
      </div>
      <Msg text={message} />
    </Modal>
  )
}
