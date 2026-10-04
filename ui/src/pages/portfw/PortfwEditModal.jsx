import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Reveal from '../../components/Reveal.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import Select from '../../components/Select.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { LTR_TEXT, PORT_MAX, rangeLabel } from '../../lib/form.js'
import { nodeIps, nodeItemsKeeping } from '../../lib/nodes.js'
import useBusy from '../../lib/useBusy.js'
import ListenIpField from './ListenIpField.jsx'
import RotateFields, { DEFAULT_ROTATE_MINUTES, rotateBody } from './RotateFields.jsx'
import Msg from '../../components/Msg.jsx'
import SaveLabel from '../../components/SaveLabel.jsx'
import useSaved from '../../lib/useSaved.js'

export default function PortfwEditModal({ item, nodes, onClose, onSaved }) {
  const [busy, guard] = useBusy()
  const [saved, markSaved] = useSaved()
  const nodeItems = nodeItemsKeeping(nodes, [[item.node_id, item.node]])
  const rotatedBefore = item.switch_interval > 0

  const [nodeId, setNodeId] = useState(item.node_id)
  const [listenIp, setListenIp] = useState(item.listen_ip || '')
  const [listenPort, setListenPort] = useState(String(item.listen_port))
  const [dstPort, setDstPort] = useState(String(item.dst_port))
  const [dstIps, setDstIps] = useState((item.dst_ips || []).join(', '))
  const [rotate, setRotate] = useState(rotatedBefore)
  const [rotateMinutes, setRotateMinutes] = useState(
    String(rotatedBefore ? item.switch_interval / 60 : DEFAULT_ROTATE_MINUTES)
  )
  const [message, setMessage] = useState('')

  const moved = nodeId !== item.node_id
  const ips = nodeIps(nodes, nodeId)
  const hasIpChoice = ips.length > 1 || (!moved && !!item.listen_ip)

  const selectNode = (id) => {
    setNodeId(id)
    setListenIp(id === item.node_id ? item.listen_ip || '' : '')
  }

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
      ...(moved ? { to_node: nodeId } : {}),
      listen_port: listenPort.trim(),
      dst_port: dstPort.trim(),
      dst_ips: dstIps.trim(),
      ...rotateBody(rotate, rotateMinutes),
      ...(hasIpChoice ? { listen_ip: listenIp } : {}),
    })
    if (r.ok && r.d.ok) {
      setMessage('')
      if (await markSaved(T('saved_ok'))) onClose()
      if (moved) toast(T('pf_moved') + r.d.name, 'ok')
      onSaved()
      return
    }
    setMessage('')
    alertBox(postError(r))
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        <SaveLabel busy={busy} saved={saved}>
          {T('save')}
        </SaveLabel>
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
      <Field label={T('pf_node')} first>
        <Select items={nodeItems} value={nodeId} placeholder={T('pf_node')} onChange={selectNode} />
      </Field>

      <Reveal show={hasIpChoice}>
        <ListenIpField
          ips={ips}
          value={listenIp}
          extra={moved ? '' : item.listen_ip}
          onChange={setListenIp}
        />
      </Reveal>

      <div className="grid2">
        <Field label={rangeLabel(T('pf_listen_port'), 1, PORT_MAX)}>
          <NumberInput value={listenPort} onChange={setListenPort} />
        </Field>
        <Field label={rangeLabel(T('pf_dst_port'), 1, PORT_MAX)}>
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
