import { useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import { Check, Cross } from '../../components/Marks.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
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

function HealthBadge({ offline, health }) {
  if (offline) {
    return (
      <span className="badge bad" title={T('pf_node_off_t')}>
        {T('pf_node_off')}
      </span>
    )
  }
  if (health.up == null) return <span className="badge na">{T('checking')}</span>
  if (!health.rule) {
    return (
      <span className="badge bad" title={T('pf_no_rule_t')}>
        {T('pf_no_rule')}
      </span>
    )
  }
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
  const [seenActive, setSeenActive] = useState(serverActive)
  if (seenActive !== serverActive) {
    setSeenActive(serverActive)
    setOverride(null)
  }

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
      toast(postError(r, 'pf_rotate_failed'), 'err')
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
    if (!(r.ok && r.d.ok)) toast(postError(r), 'err')
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
          {item.listen_port} <Icon name="arrows" /> {item.dst_port}
        </b>
        <span className="hpeers">
          {rotates ? (
            <span className="tag" style={ROTATE_TAG_STYLE}>
              <Icon name="redo" />
              {item.switch_interval / 60}m
            </span>
          ) : null}
          <HealthBadge offline={item.offline} health={health} />
        </span>
      </div>
    </div>
  )

  return (
    <AccordionCard id={item.node_id + item.name} kind="portfw" className="acc" head={head}>
      <div className="enmeta">
        <div className="emcol">
          <div>
            {T('pf_iface')}
            <b className="mono">{item.iface}</b>
          </div>
          {listenIp ? (
            <div>
              {T('pf_lip_lbl')}
              <b className="mono" style={{ color: 'var(--acc)' }}>
                {listenIp}
              </b>
            </div>
          ) : null}
          <div>
            {T('pf_lp_lbl')}
            <b className="mono">{item.listen_port}</b>
          </div>
        </div>
        <span className="tnarrow earrow">
          <Icon name="arrows" />
        </span>
        <div className="emcol">
          <div>
            {T('pf_dp_lbl')}
            <b>{item.dst_port}</b>
          </div>
          <div className="wrap">
            {T('pf_targets')}
            <b className="mono">{(item.dst_ips || []).join(T('list_sep'))}</b>
          </div>
          {multiTarget && activeTarget ? (
            <div className="wrap">
              {T('pf_active_now')}
              <b className="mono" style={{ color: 'var(--ok)' }}>
                {activeTarget}
              </b>
            </div>
          ) : null}
        </div>
      </div>

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
