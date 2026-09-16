import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import ModalLoading from '../../components/ModalLoading.jsx'
import Select from '../../components/Select.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { ipItems, nodeIps } from '../../lib/nodes.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'
import { TUNNEL_TYPES, subnetRangeItems } from '../../lib/subnet.js'
import useBusy from '../../lib/useBusy.js'
import { useActs } from '../../state/ActsContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'

const PORT_TYPES = ['l2tpv3', 'fou']

function TypeExtra({ type, port, onPort }) {
  if (PORT_TYPES.includes(type)) {
    return (
      <>
        <label>{rangeLabel(T('ttype_port_auto_lbl'), 1, PORT_MAX)}</label>
        <input
          inputMode="numeric"
          placeholder={T('ttype_port_ph')}
          value={port}
          onChange={(e) => onPort(e.target.value)}
        />
        <div className="muted" style={{ fontSize: 11, margin: '6px 2px 11px' }}>
          {T('ttype_l2_note')}
        </div>
      </>
    )
  }
  if (type === 'vxlan') {
    return (
      <>
        <label>{T('ttype_vxlan_lbl')}</label>
        <input
          inputMode="numeric"
          placeholder="4789"
          value={port}
          onChange={(e) => onPort(e.target.value)}
        />
        <div className="muted" style={{ fontSize: 11, margin: '6px 2px 11px' }}>
          {T('ttype_vxlan_note')}
        </div>
      </>
    )
  }
  if (type === 'ipsec') {
    return (
      <div className="autonote" style={{ marginBottom: 11 }}>
        <Icon name="shield" />
        <span>{T('ttype_ipsec_note')}</span>
      </div>
    )
  }
  return null
}

function IpField({ label, ips, value, onChange }) {
  if (ips.length > 1) {
    return (
      <div>
        <label className="first">{label}</label>
        <Select items={ipItems(ips)} value={value || ips[0]} placeholder={T('ip')} onChange={onChange} />
      </div>
    )
  }
  return (
    <div>
      <label className="first">{label}</label>
      <input className="mono" value={ips[0] || '—'} disabled style={{ opacity: 0.6 }} />
    </div>
  )
}

export default function TunnelCreateModal({ onClose, onCreated }) {
  const [nodes, setNodes] = useState(null)
  const [busy, guard] = useBusy()
  const [aNode, setANode] = useState('')
  const [bNode, setBNode] = useState('')
  const [aIp, setAIp] = useState('')
  const [bIp, setBIp] = useState('')
  const [type, setType] = useState('vxlan')
  const [port, setPort] = useState('')
  const [range, setRange] = useState('192.168')
  const [customSubnet, setCustomSubnet] = useState('')
  const [message, setMessage] = useState('')
  const { waitAccepted } = useActs()
  const { subnetFree } = useSummary()
  const mounted = useRef(true)
  const closeRef = useRef(onClose)

  closeRef.current = onClose

  useEffect(() => () => {
    mounted.current = false
  }, [])

  useEffect(() => {
    let alive = true
    apiGet('node-names')
      .then((r) => {
        if (!alive) return
        const online = r.nodes.filter((n) => n.online)
        if (online.length < 2) {
          toast(T('node_min2'), 'err')
          closeRef.current()
          return
        }
        setNodes(online)
        setANode(online[0].id)
        setBNode(online[1].id)
      })
      .catch((e) => {
        if (!alive) return
        toast(readError(e), 'err')
        closeRef.current()
      })
    return () => {
      alive = false
    }
  }, [])

  if (!nodes) {
    return (
      <ModalLoading
        icon="plus"
        title={T('add_tunnel_t')}
        subtitle={T('create_sub')}
        onClose={onClose}
      />
    )
  }

  const items = nodes.map((n) => ({ v: n.id, label: n.name, sub: n.host }))
  const aIps = nodeIps(nodes, aNode)
  const bIps = nodeIps(nodes, bNode)

  const changeType = (next) => {
    setType(next)
    if (customSubnet.trim()) {
      const wantsV6 = next === 'sit'
      if (customSubnet.includes(':') !== wantsV6) setCustomSubnet('')
    }
  }

  const create = async () => {
    if (aNode === bNode) {
      setMessage('')
      alertBox(T('two_diff_nodes'))
      return
    }
    const body = {
      a_node: aNode,
      b_node: bNode,
      type,
      a_ip: aIps.length > 1 ? aIp || aIps[0] : '',
      b_ip: bIps.length > 1 ? bIp || bIps[0] : '',
    }
    if (range === 'custom') body.subnet = customSubnet.trim()
    else body.subnet_base = range
    if ((PORT_TYPES.includes(type) || type === 'vxlan') && port.trim()) body.port = port.trim()

    setMessage(T('creating_tun'))
    const r = await apiPost('create-tunnel', body)
    if (!(r.ok && r.d.act)) {
      setMessage('')
      alertBox(postError(r))
      return
    }
    const verdict = await waitAccepted(r.d.act, () => mounted.current)
    if (verdict.gone) return
    if (verdict.err || verdict.cancelled) {
      setMessage('')
      alertBox(verdict.cancelled ? T('a_stopped') : translateError(verdict.err) || T('failed'))
      return
    }
    onClose()
    onCreated()
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(create)}>
        {busy ? <span className="bspin" /> : T('create_tun_btn')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon="plus"
      title={T('add_tunnel_t')}
      subtitle={T('create_sub')}
      footer={footer}
      onClose={onClose}
    >
      <div className="grid2">
        <div>
          <label className="first">{T('src_node')}</label>
          <Select items={items} value={aNode} placeholder={T('src_node')} onChange={(v) => { setANode(v); setAIp('') }} />
        </div>
        <div>
          <label className="first">{T('dst_node')}</label>
          <Select items={items} value={bNode} placeholder={T('dst_node')} onChange={(v) => { setBNode(v); setBIp('') }} />
        </div>
      </div>

      <div className="grid2" style={{ marginTop: 11 }}>
        <IpField label={T('src_ip')} ips={aIps} value={aIp} onChange={setAIp} />
        <IpField label={T('dst_ip')} ips={bIps} value={bIp} onChange={setBIp} />
      </div>

      <label>{T('tun_type')}</label>
      <Select items={TUNNEL_TYPES} value={type} placeholder={T('ttype')} onChange={changeType} />
      <TypeExtra type={type} port={port} onPort={setPort} />

      <label>{T('local_range')}</label>
      <Select
        items={subnetRangeItems(subnetFree)}
        value={range}
        placeholder={T('range')}
        onChange={setRange}
      />
      {range === 'custom' ? (
        <div>
          <label>{T('custom_subnet')}</label>
          <input
            placeholder={T('custom_subnet_ph')}
            value={customSubnet}
            onChange={(e) => setCustomSubnet(e.target.value)}
          />
        </div>
      ) : null}

      <div className="msg">{message}</div>
    </Modal>
  )
}
