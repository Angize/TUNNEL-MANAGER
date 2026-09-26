import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { LTR_TEXT, PORT_MAX, rangeLabel } from '../../lib/form.js'
import { nodeIps } from '../../lib/nodes.js'
import useBusy from '../../lib/useBusy.js'
import ListenIpField from './ListenIpField.jsx'
import RotateFields, { DEFAULT_ROTATE_MINUTES, rotateBody } from './RotateFields.jsx'
import Msg from '../../components/Msg.jsx'

export default function PortfwEditModal({ item, nodes, onClose, onSaved }) {
  const [busy, guard] = useBusy()
  const ips = nodeIps(nodes, item.node_id)
  const hasIpChoice = ips.length > 1
  const rotatedBefore = item.switch_interval > 0

  const [listenIp, setListenIp] = useState(item.listen_ip || '')
  const [listenPort, setListenPort] = useState(String(item.listen_port))
  const [dstPort, setDstPort] = useState(String(item.dst_port))
  const [dstIps, setDstIps] = useState((item.dst_ips || []).join(', '))
  const [rotate, setRotate] = useState(rotatedBefore)
  const [rotateMinutes, setRotateMinutes] = useState(
    String(rotatedBefore ? item.switch_interval / 60 : DEFAULT_ROTATE_MINUTES)
  )
  const [message, setMessage] = useState('')

  const save = async () => {
    if (!listenPort.trim() || !dstPort.trim() || !dstIps.trim()) {
      setMessage('')
      alertBox(T('pf_need_ports'))
      return
    }
    setMessage(T('saving'))
    const r = await apiPost('portfw-edit', {
      node: item.node_id,
      name: item.name,
      listen_port: listenPort.trim(),
      dst_port: dstPort.trim(),
      dst_ips: dstIps.trim(),
      ...rotateBody(rotate, rotateMinutes),
      ...(hasIpChoice ? { listen_ip: listenIp } : {}),
    })
    if (r.ok && r.d.ok) {
      onClose()
      onSaved()
      return
    }
    setMessage('')
    alertBox(postError(r))
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        {busy ? <span className="bspin" /> : T('save')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon="pen"
      title={T('pf_edit_t')}
      subtitle={item.node}
      footer={footer}
      onClose={onClose}
    >
      {hasIpChoice ? (
        <ListenIpField
          ips={ips}
          value={listenIp}
          extra={item.listen_ip}
          first
          onChange={setListenIp}
        />
      ) : null}

      <div className="grid2">
        <Field label={rangeLabel(T('pf_listen_port'), 1, PORT_MAX)} first={!hasIpChoice}>
          <NumberInput value={listenPort} onChange={setListenPort} />
        </Field>
        <Field label={rangeLabel(T('pf_dst_port'), 1, PORT_MAX)} first={!hasIpChoice}>
          <NumberInput value={dstPort} onChange={setDstPort} />
        </Field>
      </div>

      <Field label={T('pf_dst_ips')}>
        <input
          {...LTR_TEXT}
          value={dstIps}
          onChange={(e) => setDstIps(e.target.value)}
        />
      </Field>

      <RotateFields
        rotate={rotate}
        minutes={rotateMinutes}
        onRotate={setRotate}
        onMinutes={setRotateMinutes}
      />
      <Msg text={message} />
    </Modal>
  )
}
