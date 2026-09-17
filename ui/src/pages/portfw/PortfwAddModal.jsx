import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Select from '../../components/Select.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'
import { ipItems, nodeIps } from '../../lib/nodes.js'
import useBusy from '../../lib/useBusy.js'
import RotateFields, { DEFAULT_ROTATE_MINUTES, rotateBody } from './RotateFields.jsx'

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
  const effectiveListenIp = hasIpChoice ? listenIp || ips[0] : ''

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
      <label className="first">{T('pf_node')}</label>
      <Select
        items={nodeItems}
        value={nodeId}
        placeholder={T('pf_node')}
        onChange={selectNode}
      />

      {hasIpChoice ? (
        <>
          <label>{T('pf_lip_full')}</label>
          <Select
            items={ipItems(ips)}
            value={effectiveListenIp}
            placeholder={T('ip')}
            onChange={setListenIp}
          />
        </>
      ) : null}

      <div className="grid2">
        <div>
          <label>{rangeLabel(T('pf_listen_port'), 1, PORT_MAX)}</label>
          <input
            placeholder="8080"
            value={listenPort}
            onChange={(e) => setListenPort(e.target.value)}
          />
        </div>
        <div>
          <label>{rangeLabel(T('pf_dst_port'), 1, PORT_MAX)}</label>
          <input
            placeholder="443"
            value={dstPort}
            onChange={(e) => setDstPort(e.target.value)}
          />
        </div>
      </div>

      <label>{T('pf_dst_ips')}</label>
      <input
        placeholder="10.0.0.1, 10.0.0.2"
        value={dstIps}
        onChange={(e) => setDstIps(e.target.value)}
      />

      <RotateFields
        rotate={rotate}
        minutes={rotateMinutes}
        onRotate={setRotate}
        onMinutes={setRotateMinutes}
      />
      <div className="msg">{message}</div>
    </Modal>
  )
}
