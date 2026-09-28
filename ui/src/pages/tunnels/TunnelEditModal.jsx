import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import modalLoading from '../../components/ModalLoading.jsx'
import Reveal from '../../components/Reveal.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import Select from '../../components/Select.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { endIp, ipItems, nodeIps, nodeItemsForEdit, nodeLabel, seedIp } from '../../lib/nodes.js'
import { LTR_TEXT, PORT_MAX, rangeLabel } from '../../lib/form.js'
import { TUNNEL_TYPES, subnetBaseOf, subnetFitError, subnetForBase, subnetRangeItems } from '../../lib/subnet.js'
import useBusy from '../../lib/useBusy.js'
import { useActs } from '../../state/ActsContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import Msg from '../../components/Msg.jsx'
import SaveLabel from '../../components/SaveLabel.jsx'
import useSaved from '../../lib/useSaved.js'

const PORT_TYPES = ['l2tpv3', 'fou', 'vxlan']

function EndIpField({ label, ips, current, value, onChange }) {
  const list = ips && ips.length ? ips : current ? [current] : []
  if (list.length > 1) {
    return (
      <Field label={label} first>
        <Select
          items={ipItems(list)}
          value={seedIp(list, value, current)}
          placeholder={T('ip')}
          onChange={onChange}
        />
      </Field>
    )
  }
  return (
    <Field label={label} first>
      <input className="mono" value={list[0] || '—'} disabled style={{ opacity: 0.6 }} />
    </Field>
  )
}

export default function TunnelEditModal({ link, onClose, onSaved }) {
  const { waitAccepted } = useActs()
  const [busy, guard] = useBusy()
  const [saved, markSaved] = useSaved()
  const { subnetFree } = useSummary()
  const mounted = useRef(true)
  const closeRef = useRef(onClose)
  const [nodes, setNodes] = useState(null)
  const [aNode, setANode] = useState(link.a_node)
  const [bNode, setBNode] = useState(link.b_node)
  const [type, setType] = useState(link.type)
  const [base, setBase] = useState(() => subnetBaseOf(link))
  const [subnet, setSubnet] = useState(link.subnet)
  const [aIp, setAIp] = useState('')
  const [bIp, setBIp] = useState('')
  const linkPort = link.port == null ? '' : String(link.port)
  const [port, setPort] = useState(linkPort)
  const [message, setMessage] = useState('')

  closeRef.current = onClose

  useEffect(() => () => {
    mounted.current = false
  }, [])

  useEffect(() => {
    let alive = true
    apiGet('node-names')
      .then((r) => alive && setNodes(r.nodes))
      .catch((e) => {
        if (!alive) return
        toast(readError(e), 'err')
        closeRef.current()
      })
    return () => {
      alive = false
    }
  }, [])

  const recalc = (nextType, nextBase) => {
    if (nextBase && nextBase !== 'custom') {
      setSubnet(subnetForBase(nextType, link.tunnel_id, nextBase))
    }
  }

  const changeType = (next) => {
    if (next === type) return
    setType(next)
    setPort(next === link.type ? linkPort : '')
    recalc(next, base)
  }

  const changeBase = (next) => {
    setBase(next)
    recalc(type, next)
  }

  const subtitle = (
    <>
      {link.a_name} <Icon name="arrows" /> {link.b_name}
    </>
  )

  if (!nodes) return modalLoading({ icon: 'link', title: T('edit_tun_t'), subtitle, onClose })

  const items = nodeItemsForEdit(nodes, link)
  const aIps = nodeIps(nodes, aNode)
  const bIps = nodeIps(nodes, bNode)
  const aCur = aNode === link.a_node ? link.a_ip : ''
  const bCur = bNode === link.b_node ? link.b_ip : ''
  const multiIp = aIps.length > 1 || bIps.length > 1
  const showPort = PORT_TYPES.includes(type)
  const portLabel = type === 'vxlan' ? T('le_port_4789') : T('le_port_auto')

  const save = async () => {
    if (aNode === bNode) {
      setMessage('')
      alertBox(T('two_diff_nodes'))
      return
    }
    if (!type) {
      setMessage('')
      alertBox(T('tun_type'))
      return
    }
    const fitError = base === 'custom' ? '' : subnetFitError(type, link.tunnel_id, base)
    if (fitError) {
      setMessage('')
      alertBox(fitError)
      return
    }
    const body = {
      id: link.id,
      type,
      subnet,
      a_node: aNode,
      b_node: bNode,
      a_ip: endIp(aIps, aIp, aCur),
      b_ip: endIp(bIps, bIp, bCur),
    }
    if (showPort) body.port = port.trim()

    setMessage(T('rebuilding_both'))
    const r = await apiPost('edit-link', body)
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
    setMessage('')
    if (await markSaved(T('saved_ok'))) onClose()
    onSaved()
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        <SaveLabel busy={busy} saved={saved}>
          {T('save_rebuild')}
        </SaveLabel>
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon="link"
      title={T('edit_tun_t')}
      subtitle={subtitle}
      footer={footer}
      onClose={onClose}
    >
      <div className="grid2">
        <Field label={T('tun_type')} first>
          <Select items={TUNNEL_TYPES} value={type} placeholder={T('ttype')} onChange={changeType} />
        </Field>
        <Field label={T('range')} first>
          <Select
            items={subnetRangeItems(subnetFree)}
            value={base}
            placeholder={T('range')}
            onChange={changeBase}
          />
        </Field>
      </div>

      <Field label={T('subnet')}>
        <input
          {...LTR_TEXT}
          value={subnet}
          onChange={(e) => setSubnet(e.target.value)}
        />
      </Field>

      <Reveal show={showPort}>
        <Field label={rangeLabel(portLabel, 1, PORT_MAX)}>
          <NumberInput
            placeholder={type === 'vxlan' ? '4789' : T('ttype_port_ph')}
            value={port}
            onChange={setPort}
          />
        </Field>
      </Reveal>

      <div
        className="muted"
        style={{
          fontWeight: 700,
          color: 'var(--tx)',
          margin: '16px 2px 9px',
          display: 'flex',
          alignItems: 'center',
          gap: 6,
        }}
      >
        <Icon name="pin" color="var(--acc-tx)" />
        {T('ip_each_end')}
        {multiIp ? (
          <span className="tag" style={{ fontSize: 9.5, padding: '1px 7px' }}>
            {T('multi_ip')}
          </span>
        ) : null}
      </div>

      <div className="grid2">
        <Field label={T('src_node')} first>
          <Select
            items={items}
            value={aNode}
            placeholder={T('src_node')}
            onChange={(v) => {
              setANode(v)
              setAIp('')
            }}
          />
        </Field>
        <Field label={T('dst_node')} first>
          <Select
            items={items}
            value={bNode}
            placeholder={T('dst_node')}
            onChange={(v) => {
              setBNode(v)
              setBIp('')
            }}
          />
        </Field>
      </div>

      <div className="grid2" style={{ marginTop: 11 }}>
        <EndIpField
          label={T('ip_of') + nodeLabel(items, aNode)}
          ips={aIps}
          current={aCur}
          value={aIp}
          onChange={setAIp}
        />
        <EndIpField
          label={T('ip_of') + nodeLabel(items, bNode)}
          ips={bIps}
          current={bCur}
          value={bIp}
          onChange={setBIp}
        />
      </div>

      <div className="muted" style={{ fontSize: 11.5, marginTop: 9 }}>
        {T('link_ip_note1')}
        {link.tunnel_id}
        {T('link_ip_note2')}
      </div>
      <Msg text={message} />
    </Modal>
  )
}
