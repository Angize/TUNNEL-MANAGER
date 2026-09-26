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
import { nodeIps } from '../../lib/nodes.js'
import useBusy from '../../lib/useBusy.js'
import ListenIpField from './ListenIpField.jsx'
import RotateFields, { DEFAULT_ROTATE_MINUTES, rotateBody } from './RotateFields.jsx'
import Msg from '../../components/Msg.jsx'

export default function PortfwAddModal({ nodes, onClose, onCreated }) {
  const [busy, guard] = useBusy()
  const nodeItems = nodes.map((n) => ({ v: n.id, label: n.name, sub: n.host }))
  const [nodeId, setNodeId] = useState(nodeItems.length ? nodeItems[0].v : '')
  const [listenIp, setListenIp] = useState('')
  const [listenPort, setListenPort] = useState('')
  const [dstPort, setDstPort] = useState('')
  const [dstIps, setDstIps] = useState('')
  const [rotate, setRotate] = useState(true)
  const [rotateMinutes, setRotateMinutes] = useState(String(DEFAULT_ROTATE_MINUTES))
  const [message, setMessage] = useState('')

  const ips = nodeIps(nodes, nodeId)
  const hasIpChoice = ips.length > 1
  const effectiveListenIp = hasIpChoice ? listenIp : ''

  const selectNode = (id) => {
    setNodeId(id)
    setListenIp('')
  }

  const create = async () => {
    if (!nodeId || !listenPort.trim() || !dstPort.trim() || !dstIps.trim()) {
      setMessage('')
      alertBox(T('pf_need_all'))
      return
    }
    setMessage(T('creating_dots'))
    const r = await apiPost('portfw', {
      node: nodeId,
      listen_port: listenPort.trim(),
      dst_port: dstPort.trim(),
      dst_ips: dstIps.trim(),
      ...rotateBody(rotate, rotateMinutes),
      listen_ip: effectiveListenIp,
    })
    if (r.ok && r.d.ok) {
      onClose()
      toast(T('pf_created') + r.d.name, 'ok')
      onCreated()
      return
    }
    setMessage('')
    alertBox(postError(r))
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(create)}>
        {busy ? <span className="bspin" /> : T('add')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal icon="plus" title={T('pf_add_t')} footer={footer} onClose={onClose}>
      <Field label={T('pf_node')} first>
        <Select
          items={nodeItems}
          value={nodeId}
          placeholder={T('pf_node')}
          onChange={selectNode}
        />
      </Field>

      <Reveal show={hasIpChoice}>
        <ListenIpField ips={ips} value={listenIp} onChange={setListenIp} />
      </Reveal>

      <div className="grid2">
        <Field label={rangeLabel(T('pf_listen_port'), 1, PORT_MAX)}>
          <NumberInput placeholder="8080" value={listenPort} onChange={setListenPort} />
        </Field>
        <Field label={rangeLabel(T('pf_dst_port'), 1, PORT_MAX)}>
          <NumberInput placeholder="443" value={dstPort} onChange={setDstPort} />
        </Field>
      </div>

      <Field label={T('pf_dst_ips')}>
        <input
          {...LTR_TEXT}
          placeholder="10.0.0.1, 10.0.0.2"
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
