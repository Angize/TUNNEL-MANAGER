import { useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import ActBtn from '../../components/ActBtn.jsx'
import { useActionBusy } from '../../lib/useBusy.js'
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
  color: 'var(--gold-tx)',
  borderColor: 'color-mix(in srgb, var(--gold) 34%, transparent)',
  background: 'var(--goldw)',
}

const PORTFW_TAG_STYLE = {
  color: 'var(--h-orange)',
  background: 'color-mix(in srgb, var(--h-orange) 15%, transparent)',
}

const ROTATE_BTN_STYLE = {
  color: 'var(--h-orange)',
  borderColor: 'color-mix(in srgb, var(--h-orange) 46%, transparent)',
}

function rotateLabel(minutes) {
  return minutes % 60 ? minutes + ' ' + T('fmt_min') : minutes / 60 + ' ' + T('fmt_hr')
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
  if (health.reachable == null) {
    return (
      <span className="badge warn" title={T('pf_dest_unk_t')}>
        {T('pf_rule')}
        <Check /> · {T('pf_dest_unk')}
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
  const rotateEvery = rotates ? rotateLabel(item.switch_interval / 60) : ''
  const multiTarget = (item.dst_ips || []).length > 1
  const listenIp = item.listen_ip || item.node_ip || ''
  const activeTarget = override != null ? override : serverActive

  const [busyAct, withBusy] = useActionBusy()

  const rotateNow = async () => {
    const r = await withBusy('rotate', () => {
      setOverride('…')
      return apiPost('portfw-next', { node: item.node_id, name: item.name })
    })
    if (!r) return
    if (r.ok && r.d.ok) {
      setOverride(r.d.active)
      toast(T('pf_rotate_done') + r.d.active, 'ok')
    } else {
      setOverride(null)
      toast(postError(r, 'pf_rotate_failed'), 'err')
    }
  }

  const resetTraffic = async () => {
    if (!(await confirmBox(T('pf_reset_confirm'), T('reset_yes')))) return
    const r = await withBusy('reset', () =>
      apiPost('traffic-reset', { node: item.node_id, name: item.name })
    )
    if (!r) return
    if (r.ok && r.d.ok) {
      toast(T('t_reset_done'), 'ok')
      onChanged()
    } else {
      toast(postError(r), 'err')
    }
  }

  const remove = async () => {
    if (!(await confirmBox(T('pf_del_confirm'), T('confirm_del')))) return
    const r = await withBusy('del', () =>
      apiPost('portfw-del', { node: item.node_id, name: item.name })
    )
    if (!r) return
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
            <span className="tag" style={ROTATE_TAG_STYLE} title={T('pf_rot_every') + rotateEvery}>
              <Icon name="redo" />
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
              <b className="mono" style={{ color: 'var(--acc-tx)' }}>
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
          {rotates ? (
            <div className="wrap">
              {T('pf_rot_every')}
              <b>{rotateEvery}</b>
            </div>
          ) : null}
          {multiTarget && activeTarget ? (
            <div className="wrap">
              {T('pf_active_now')}
              <b className="mono" style={{ color: 'var(--ok-tx)' }}>
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
        <ActBtn cls="reset" icon="reset" title={T('tip_reset')} busy={busyAct === 'reset'} locked={!!busyAct} onClick={resetTraffic} />
        {multiTarget && serverActive ? (
          <ActBtn
            icon="redo"
            title={T('pf_rotate_now')}
            style={ROTATE_BTN_STYLE}
            busy={busyAct === 'rotate'}
            locked={!!busyAct}
            onClick={rotateNow}
          />
        ) : null}
        <ActBtn cls="warn" icon="pen" title={T('tip_edit')} locked={!!busyAct} onClick={() => onEdit(item)} />
        <ActBtn cls="danger" icon="trash" title={T('tip_delete')} busy={busyAct === 'del'} locked={!!busyAct} onClick={remove} />
      </div>
    </AccordionCard>
  )
}
