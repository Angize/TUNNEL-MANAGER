import { useEffect, useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import { Check, Cross } from '../../components/Marks.jsx'
import { Kv, KvRow } from '../../components/Kv.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate } from '../../lib/num.js'

const ROTATE_TAG_STYLE = {
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  color: 'var(--gold)',
  borderColor: 'color-mix(in srgb, var(--gold) 34%, transparent)',
  background: 'var(--goldw)',
  direction: 'ltr',
}

const PORTFW_TAG_STYLE = {
  color: '#fb923c',
  background: 'color-mix(in srgb, #fb923c 15%, transparent)',
}

const ROTATE_BTN_STYLE = {
  color: '#fb923c',
  borderColor: 'color-mix(in srgb, #fb923c 46%, transparent)',
}

function HealthBadge({ health }) {
  if (!health.rule) return <span className="badge bad">{T('pf_disabled')}</span>
  if (health.reachable) {
    return (
      <span className="badge ok">
        {T('pf_active_badge')}
        <Check />
      </span>
    )
  }
  return (
    <span className="badge bad">
      {T('pf_rule')}
      <Check /> · {T('pf_dest')}
      <Cross />
    </span>
  )
}

export default function PortfwCard({ item, onEdit, onChanged }) {
  const health = item.health || {}
  const serverActive = health.active || ''
  const [override, setOverride] = useState(null)

  useEffect(() => {
    setOverride((cur) => (cur === null ? cur : null))
  }, [item])

  const rotates = item.switch_interval > 0
  const multiTarget = (item.dst_ips || []).length > 1
  const listenIp = item.listen_ip || item.node_ip || ''
  const activeTarget = override != null ? override : serverActive

  const rotateNow = async () => {
    setOverride('…')
    const r = await apiPost('portfw-next', { node: item.node_id, name: item.name })
    if (r.ok && r.d.ok) {
      setOverride(r.d.active)
      toast(T('pf_rotate_done') + r.d.active, 'ok')
    } else {
      setOverride(null)
      toast(translateError((r.d && (r.d.error || r.d.msg)) || T('pf_rotate_failed')), 'err')
    }
  }

  const resetTraffic = async () => {
    if (!(await confirmBox(T('pf_reset_confirm')))) return
    const r = await apiPost('traffic-reset', { node: item.node_id, name: item.name })
    if (r.ok && r.d.ok) {
      toast(T('t_reset_done'), 'ok')
      onChanged()
    } else {
      toast(postError(r), 'err')
    }
  }

  const remove = async () => {
    if (!(await confirmBox(T('pf_del_confirm')))) return
    const r = await apiPost('portfw-del', { node: item.node_id, name: item.name })
    if (!(r.ok && r.d && r.d.ok)) {
      toast(translateError((r.d && (r.d.msg || r.d.error)) || '') || T('failed'), 'err')
    }
    onChanged()
  }

  const head = (
    <div className="hmain">
      <div className="hrow1">
        <span className="hname">{item.node}</span>
        <span className="ctag" style={PORTFW_TAG_STYLE}>
          portfw
        </span>
        <b className="mono" dir="ltr" style={{ color: 'var(--sub)', fontSize: 12 }}>
          {item.listen_port} ↔ {item.dst_port}
        </b>
        <span className="hpeers">
          {rotates ? (
            <span className="tag" style={ROTATE_TAG_STYLE}>
              <Icon name="redo" />
              {item.switch_interval / 60}m
            </span>
          ) : null}
          <HealthBadge health={health} />
        </span>
      </div>
    </div>
  )

  return (
    <AccordionCard id={item.node_id + item.name} kind="portfw" className="acc" head={head}>
      <Kv>
        <KvRow label={T('pf_listen_port')} mono>
          {item.listen_port}
        </KvRow>
        <KvRow label={T('iface')} side="l" mono>
          {item.iface}
        </KvRow>
        <KvRow label={T('pf_dst_port')} mono>
          {item.dst_port}
        </KvRow>
        {listenIp ? (
          <KvRow label={T('pf_lip_lbl')} side="l" mono>
            <span style={{ color: 'var(--acc)' }}>{listenIp}</span>
          </KvRow>
        ) : null}
        <KvRow label={T('pf_targets')} wide>
          {(item.dst_ips || []).map((ip) => (
            <b key={ip} className="mono">
              {ip}
            </b>
          ))}
        </KvRow>
        {multiTarget && activeTarget ? (
          <KvRow label={T('pf_active_now')} wide>
            <b className="mono" style={{ color: 'var(--ok)' }}>
              {activeTarget}
            </b>
          </KvRow>
        ) : null}
      </Kv>

      <div className="ltraf">
        <span className="din iso">↓ {fmtRate(item.rx_bps)}</span>
        <span className="dout iso">↑ {fmtRate(item.tx_bps)}</span>
        <span className="tot">
          {T('total')}{' '}
          <span className="iso">
            <b className="din">↓{fmtBytes(item.rx_total)}</b>
            <b className="dout">↑{fmtBytes(item.tx_total)}</b>
          </span>
        </span>
      </div>

      <div className="nact iconly">
        <button className="act reset" title={T('tip_reset')} onClick={resetTraffic}>
          <Icon name="reset" />
        </button>
        {multiTarget && serverActive ? (
          <button
            className="act"
            title={T('pf_rotate_now')}
            style={ROTATE_BTN_STYLE}
            onClick={rotateNow}
          >
            <Icon name="redo" />
          </button>
        ) : null}
        <button className="act warn" title={T('tip_edit')} onClick={() => onEdit(item)}>
          <Icon name="pen" />
        </button>
        <button className="act danger" title={T('tip_delete')} onClick={remove}>
          <Icon name="trash" />
        </button>
      </div>
    </AccordionCard>
  )
}
