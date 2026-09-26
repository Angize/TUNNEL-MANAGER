import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Reveal from '../../components/Reveal.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import Select from '../../components/Select.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { ipItems } from '../../lib/nodes.js'
import { LTR_TEXT, PORT_MAX, rangeLabel } from '../../lib/form.js'
import { TUNNEL_TYPES, subnetBaseOf, subnetFitError, subnetForBase, subnetRangeItems } from '../../lib/subnet.js'
import useBusy from '../../lib/useBusy.js'
import { useActs } from '../../state/ActsContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import Msg from '../../components/Msg.jsx'

const PORT_TYPES = ['l2tpv3', 'fou', 'vxlan']

function EndIpField({ label, ips, current, value, onChange }) {
  const list = ips && ips.length ? ips : current ? [current] : []
  if (list.length > 1) {
    return (
      <Field label={label} first>
        <Select
          items={ipItems(list)}
          value={value || (current && list.includes(current) ? current : list[0])}
          placeholder={T('ip')}
          onChange={onChange}
        />
      </Field>
    )
  }
  return (
    <Field label={label} first>
      <input className="mono" value={list[0] || current || '—'} disabled style={{ opacity: 0.6 }} />
    </Field>
  )
}

export default function TunnelEditModal({ link, onClose, onSaved }) {
  const { waitAccepted } = useActs()
  const [busy, guard] = useBusy()
  const { subnetFree } = useSummary()
  const mounted = useRef(true)
  const [type, setType] = useState(link.type)
  const [base, setBase] = useState(() => subnetBaseOf(link))
  const [subnet, setSubnet] = useState(link.subnet)
  const [aIp, setAIp] = useState('')
  const [bIp, setBIp] = useState('')
  const linkPort = link.port == null ? '' : String(link.port)
  const [port, setPort] = useState(linkPort)
  const [message, setMessage] = useState('')

  useEffect(() => () => {
    mounted.current = false
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

  const multiIp = (link.a_ips || []).length > 1 || (link.b_ips || []).length > 1
  const showPort = PORT_TYPES.includes(type)
  const portLabel = type === 'vxlan' ? T('le_port_4789') : T('le_port_auto')

  const save = async () => {
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
      a_ip: aIp || (link.a_ip && (link.a_ips || []).includes(link.a_ip) ? link.a_ip : ''),
      b_ip: bIp || (link.b_ip && (link.b_ips || []).includes(link.b_ip) ? link.b_ip : ''),
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
    onClose()
    onSaved()
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        {busy ? <span className="bspin" /> : T('save_rebuild')}
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
      subtitle={
        <>
          {link.a_name} <Icon name="arrows" /> {link.b_name}
        </>
      }
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
        <EndIpField
          label={T('ip_of') + link.a_name}
          ips={link.a_ips}
          current={link.a_ip}
          value={aIp}
          onChange={setAIp}
        />
        <EndIpField
          label={T('ip_of') + link.b_name}
          ips={link.b_ips}
          current={link.b_ip}
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
