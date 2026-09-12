import { useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Select from '../../components/Select.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { ipItems } from '../../lib/nodes.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'
import { TUNNEL_TYPES, subnetBaseOf, subnetForBase, subnetRangeItems } from '../../lib/subnet.js'
import { useActs } from '../../state/ActsContext.jsx'

const PORT_TYPES = ['l2tpv3', 'fou', 'vxlan']

function EndIpField({ label, ips, current, value, onChange }) {
  const list = ips && ips.length ? ips : current ? [current] : []
  if (list.length > 1) {
    return (
      <div>
        <label className="first">{label}</label>
        <Select
          items={ipItems(list)}
          value={value || (current && list.includes(current) ? current : list[0])}
          placeholder={T('ip')}
          onChange={onChange}
        />
      </div>
    )
  }
  return (
    <div>
      <label className="first">{label}</label>
      <input className="mono" value={list[0] || current || '—'} disabled style={{ opacity: 0.6 }} />
    </div>
  )
}

export default function TunnelEditModal({ link, onClose, onSaved }) {
  const { waitAccepted } = useActs()
  const mounted = useRef(true)
  const [type, setType] = useState(link.type)
  const [base, setBase] = useState(() => subnetBaseOf(link))
  const [subnet, setSubnet] = useState(link.subnet)
  const [aIp, setAIp] = useState('')
  const [bIp, setBIp] = useState('')
  const [port, setPort] = useState(link.port == null ? '' : String(link.port))
  const [subnetFree, setSubnetFree] = useState(null)
  const [message, setMessage] = useState('')

  useEffect(() => () => {
    mounted.current = false
  }, [])

  useEffect(() => {
    let alive = true
    apiGet('summary')
      .then((s) => {
        if (alive && s.subnet_free) setSubnetFree(s.subnet_free)
      })
      .catch(() => {})
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
    setType(next)
    recalc(next, base)
  }

  const changeBase = (next) => {
    setBase(next)
    recalc(type, next)
  }

  const multiIp = (link.a_ips || []).length > 1 || (link.b_ips || []).length > 1
  const showPort = PORT_TYPES.includes(type)
  const portLabel = type === 'vxlan' ? T('le_port_4789') : T('le_port_auto')
  const portPrefill = type === link.type ? port : ''

  const save = async () => {
    if (!type) {
      setMessage('')
      alertBox(T('tun_type'))
      return
    }
    const body = {
      id: link.id,
      type,
      subnet,
      a_ip: aIp || (link.a_ip && (link.a_ips || []).includes(link.a_ip) ? link.a_ip : ''),
      b_ip: bIp || (link.b_ip && (link.b_ips || []).includes(link.b_ip) ? link.b_ip : ''),
    }
    if (showPort) body.port = portPrefill.trim()

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
      <button className="primary" onClick={save}>
        {T('save_rebuild')}
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
      subtitle={link.a_name + ' ↔ ' + link.b_name}
      footer={footer}
      onClose={onClose}
    >
      <div className="grid2">
        <div>
          <label className="first">{T('tun_type')}</label>
          <Select items={TUNNEL_TYPES} value={type} placeholder={T('ttype')} onChange={changeType} />
        </div>
        <div>
          <label className="first">{T('range')}</label>
          <Select
            items={subnetRangeItems(subnetFree)}
            value={base}
            placeholder={T('range')}
            onChange={changeBase}
          />
        </div>
      </div>

      <label>{T('subnet')}</label>
      <input value={subnet} onChange={(e) => setSubnet(e.target.value)} />

      {showPort ? (
        <div>
          <label>{rangeLabel(portLabel, 1, PORT_MAX)}</label>
          <input
            inputMode="numeric"
            placeholder={type === 'vxlan' ? '4789' : T('ttype_port_ph')}
            value={portPrefill}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
      ) : null}

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
        <Icon name="pin" color="var(--acc)" />
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
      <div className="msg">{message}</div>
    </Modal>
  )
}
