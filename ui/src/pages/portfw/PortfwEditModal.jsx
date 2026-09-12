import { useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Select from '../../components/Select.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'
import { ipItems, nodeIps } from '../../lib/nodes.js'

const DEFAULT_ROTATE_MINUTES = 5

export default function PortfwEditModal({ item, nodes, onClose, onSaved }) {
  const ips = nodeIps(nodes, item.node_id)
  const hasIpChoice = ips.length > 1
  const rotatedBefore = item.switch_interval > 0

  const [listenIp, setListenIp] = useState(
    item.listen_ip && ips.includes(item.listen_ip) ? item.listen_ip : ips[0] || ''
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
      rotate,
      interval_min: rotateMinutes.trim() || DEFAULT_ROTATE_MINUTES,
      listen_ip: hasIpChoice ? listenIp : '',
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
      <button className="primary" onClick={save}>
        {T('save')}
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
            items={ipItems(ips)}
            value={listenIp}
            placeholder={T('ip')}
            onChange={setListenIp}
          />
          <div className="muted" style={{ fontSize: 11, margin: '-3px 2px 12px' }}>
            {T('pf_lip_note')}
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

      <label>{T('pf_rot_between')}</label>
      <div className="tgl">
        <span
          className={'tglsw' + (rotate ? ' on' : '')}
          onClick={() => setRotate(!rotate)}
        />
        <span className="muted">{rotate ? T('on_word') : T('off_word')}</span>
      </div>

      {rotate ? (
        <div>
          <label>{T('pf_rot_interval')}</label>
          <input value={rotateMinutes} onChange={(e) => setRotateMinutes(e.target.value)} />
        </div>
      ) : null}

      <div className="muted" style={{ fontSize: 11.5, marginTop: 9 }}>
        {T('pf_rot_note')}
      </div>
      <div className="msg">{message}</div>
    </Modal>
  )
}
