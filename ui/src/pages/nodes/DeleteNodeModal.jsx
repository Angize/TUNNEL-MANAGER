import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import Msg from '../../components/Msg.jsx'
import { CdnSteps } from '../../components/ActionRow.jsx'
import { TF } from '../../i18n/fa.js'

export default function DeleteNodeModal({ node, onClose, onDeleted }) {
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [steps, setSteps] = useState(null)
  const [done, setDone] = useState(false)
  const offline = !node.online

  const send = async (force, skip) => {
    setBusy(true)
    setMessage(force ? T('del_force_wiping') : T('del_wiping'))
    const body = { id: node.id, wipe_force: !!force, ...(skip ? { cdn_skip: true } : {}) }
    const r = await apiPost('node-del', body)
    const shown = (r.ok && r.d && r.d.cdn) || []
    setSteps(shown.length ? shown : null)
    if (r.ok && r.d.ok) {
      toast(r.d.node_wiped === false ? T('node_force_wiped') : T('node_wiped'), 'ok')
      onDeleted()
      if (!shown.length) {
        onClose()
        return
      }
      setBusy(false)
      setDone(true)
      setMessage(T(skip ? 'nd_cdn_kept' : 'nd_cdn_done'))
      return
    }
    setBusy(false)
    setMessage('')
    if (r.ok && r.d.offer === 'cdn_skip') {
      if (await confirmBox(TF('nd_cdn_failed_ask', { e: postError(r) }), T('cdn_del_skip_yes'))) await send(force, true)
      return
    }
    alertBox(postError(r))
  }

  const wipe = async (force) => {
    const confirmed = force
      ? await confirmBox(T('del_wipe_force_ask'), T('del_wipe_force_yes'))
      : await confirmBox(T('del_wipe_confirm'), T('del_wipe_yes'))
    if (!confirmed) return
    await send(force, false)
  }

  const footer = (
    <button className="ghost" onClick={onClose}>
      {T(done ? 'close' : 'cancel')}
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
        disabled={busy || done}
        onClick={() => wipe(offline)}
      >
        <div className="do-t">
          {busy ? <span className="bspin ink sm" /> : <Icon name="warn" />}
          {offline ? T('del_wipe_force_yes') : T('del_wipe_t')}
        </div>
        <div className="do-s">{offline ? T('del_wipe_force_s') : T('del_wipe_s')}</div>
      </button>
      <Msg text={message} />
      <CdnSteps steps={steps} />
    </Modal>
  )
}
