import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Select from '../../components/Select.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'
import { ipItems, nodeIps } from '../../lib/nodes.js'
import useBusy from '../../lib/useBusy.js'
import RotateFields, { DEFAULT_ROTATE_MINUTES, rotateBody } from './RotateFields.jsx'

export default function PortfwEditModal({ item, nodes, onClose, onSaved }) {
  const [busy, guard] = useBusy()
  const ips = nodeIps(nodes, item.node_id)
  const hasIpChoice = ips.length > 1
  const rotatedBefore = item.switch_interval > 0

  const [listenIp, setListenIp] = useState(item.listen_ip || '')
  const listenItems = [{ v: '', label: T('pf_lip_all') }].concat(
    ipItems(item.listen_ip && !ips.includes(item.listen_ip) ? ips.concat([item.listen_ip]) : ips)
  )
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

  const portLabelCls = hasIpChoice ? undefined : 'first'

  return (
    <Modal
      icon="pen"
      title={T('pf_edit_t')}
      subtitle={item.node}
      footer={footer}
      onClose={onClose}
    >
      {hasIpChoice ? (
        <>
          <label className="first">{T('pf_lip')}</label>
          <Select
            items={listenItems}
            value={listenIp}
            placeholder={T('ip')}
            onChange={setListenIp}
          />
          <div className="muted" style={{ fontSize: 11, margin: '-3px 2px 12px' }}>
            {T(listenIp ? 'pf_lip_note' : 'pf_lip_all_note')}
          </div>
        </>
      ) : null}

      <div className="grid2">
        <div>
          <label className={portLabelCls}>{rangeLabel(T('pf_listen_port'), 1, PORT_MAX)}</label>
          <input value={listenPort} onChange={(e) => setListenPort(e.target.value)} />
        </div>
        <div>
          <label className={portLabelCls}>{rangeLabel(T('pf_dst_port'), 1, PORT_MAX)}</label>
          <input value={dstPort} onChange={(e) => setDstPort(e.target.value)} />
        </div>
      </div>

      <label>{T('pf_dst_ips')}</label>
      <input value={dstIps} onChange={(e) => setDstIps(e.target.value)} />

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
