import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import Msg from '../../components/Msg.jsx'

export default function DeleteNodeModal({ node, onClose, onDeleted }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const offline = !node.online

  const wipe = async (force) => {
    const confirmed = force
      ? await confirmBox(T('del_wipe_force_ask'), T('del_wipe_force_yes'))
      : await confirmBox(T('del_wipe_confirm'), T('del_wipe_yes'))
    if (!confirmed) return

    setBusy(true)
    setMessage(force ? T('del_force_wiping') : T('del_wiping'))
    const r = await apiPost('node-del', { id: node.id, wipe_force: !!force })
    if (r.ok && r.d.ok) {
      toast(r.d.node_wiped === false ? T('node_force_wiped') : T('node_wiped'), 'ok')
      onClose()
      onDeleted()
      return
    }
    setBusy(false)
    setMessage('')
    alertBox(postError(r))
  }

  const footer = (
    <button className="ghost" onClick={onClose}>
      {T('cancel')}
    </button>
  )

  return (
    <Modal icon="trash" title={T('nd_del')} subtitle={node.name} footer={footer} onClose={onClose}>
      <div className="muted" style={{ fontSize: 12.5, marginBottom: 13 }}>
        {T('del_how')}
      </div>
      <button
        type="button"
        className="delopt danger"
        disabled={busy}
        onClick={() => wipe(offline)}
      >
        <div className="do-t">
          {busy ? <span className="bspin ink sm" /> : <Icon name="warn" />}
          {offline ? T('del_wipe_force_yes') : T('del_wipe_t')}
        </div>
        <div className="do-s">{offline ? T('del_wipe_force_s') : T('del_wipe_s')}</div>
      </button>
      <Msg text={message} />
    </Modal>
  )
}
