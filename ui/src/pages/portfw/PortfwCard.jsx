import { memo, useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import ActBtn from '../../components/ActBtn.jsx'
import { useActionBusy } from '../../lib/useBusy.js'
import { copyText } from '../../components/CopyValue.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate } from '../../lib/num.js'
import { checkable, pressable } from '../../lib/keys.js'

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

const OFF = { kind: 'na', word: T('st_off'), title: T('st_off') }

function nodeState(item, health) {
  if (item.enabled === false) return OFF
  if (item.offline) return { kind: 'bad', word: T('st_disc'), title: T('pf_node_off_t') }
  if (health.up == null) return { kind: 'na', word: '…', title: T('checking') }
  if (!health.rule) return { kind: 'bad', word: T('pf_no_rule'), title: T('pf_no_rule_t') }
  return { kind: 'ok', word: '', title: '' }
}

function destState(item, health) {
  if (item.enabled === false) return OFF
  if (item.offline || health.up == null || !health.rule) return { kind: 'na', word: '', title: '' }
  if (health.reachable) return { kind: 'ok', word: '', title: '' }
  if (health.reachable == null) return { kind: 'na', word: T('pf_unk'), title: T('pf_dest_unk_t') }
  return { kind: 'bad', word: T('st_disc'), title: '' }
}

function Box({ name, state, text, copy, rotating }) {
  return (
    <div className={'tnnode st-' + state.kind} title={state.title || undefined}>
      <div className="tnhead">
        <span className="tnn">{name}</span>
        <span className="tnend">
          <span className="cprot">
            {rotating ? (
              <span className="rotmark" title={T('pf_rotating')}>
                <Icon name="redo" />
              </span>
            ) : null}
          </span>
          <span className="stat">
            {state.word ? <span className={'stw ' + state.kind}>{state.word}</span> : null}
          </span>
        </span>
      </div>
      {copy ? (
        <div className="tna mono cpv" title={T('tip_copy')} {...pressable((e) => copyText(text, e))}>
          {text}
        </div>
      ) : (
        <div className="tna">{text}</div>
      )}
    </div>
  )
}

function PortfwCard({ item, onEdit, onChanged }) {
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
  const targets = item.dst_ips || []
  const multiTarget = targets.length > 1
  const listenIp = item.listen_ip || item.node_ip || ''
  const activeTarget = override != null ? override : serverActive
  const destIp = activeTarget || targets[0] || '—'
  const enabled = item.enabled !== false
  const node = nodeState(item, health)
  const dest = destState(item, health)

  const [busyAct, withBusy] = useActionBusy()
  const [toggleBusy, withToggle] = useActionBusy()

  const toggle = (e) => {
    e.stopPropagation()
    withToggle('toggle', async () => {
      const r = await apiPost('portfw-toggle', { node: item.node_id, name: item.name, enabled: !enabled })
      const err = r.ok && r.d.ok ? '' : postError(r)
      toast(err || T(enabled ? 'turned_off' : 'turned_on'), err ? 'err' : 'ok')
      await onChanged()
    })
  }

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
    <>
      <div
        className={'tsw' + (enabled ? ' on' : '') + (toggleBusy ? ' busy' : '')}
        aria-busy={!!toggleBusy}
        title={T('pf_tip_toggle')}
        {...checkable('switch', enabled, toggle)}
      />
      <div className="hmain">
        <div className="hrow1">
          <span className="hname">{item.name}</span>
          <span className="ctag" style={PORTFW_TAG_STYLE}>
            PORTFW
          </span>
          {enabled ? null : (
            <span className="offtxt" style={{ fontSize: 11 }}>
              {T('st_off')}
            </span>
          )}
          <span className="hpeers" dir="ltr">
            <span className={'sdot ' + node.kind} title={node.title || undefined} />
            <span className="pn">{item.node}</span>
            <Icon name="arrows" />
            <span className="pn">{destIp}</span>
            <span className={'sdot ' + dest.kind} title={dest.title || undefined} />
          </span>
        </div>
      </div>
    </>
  )

  return (
    <AccordionCard id={item.node_id + item.name} kind="portfw" className={'acc' + (enabled ? '' : ' off')} head={head}>
      <div className="tninfo">
        <Box name={item.node} state={node} text={listenIp || T('pf_lip_all')} copy={!!listenIp} />
        <span className="tnarrow">
          <Icon name="arrows" />
        </span>
        <Box
          name={T('pf_dest')}
          state={dest}
          text={destIp}
          copy={destIp !== '—'}
          rotating={enabled && rotates && multiTarget}
        />
      </div>

      <div className="enmeta">
        <div className="emcol">
          <div>
            {T('pf_lp_lbl')}
            <b className="mono">{item.listen_port}</b>
          </div>
          <div>
            {T('pf_iface')}
            <b className="mono">{item.iface}</b>
          </div>
        </div>
        <span className="tnarrow earrow">
          <Icon name="arrows" />
        </span>
        <div className="emcol">
          <div>
            {T('pf_dp_lbl')}
            <b className="mono">{item.dst_port}</b>
          </div>
          {multiTarget ? (
            <div className="wrap">
              {T('pf_targets')}
              <b className="mono">{targets.join(T('list_sep'))}</b>
            </div>
          ) : null}
          {rotates ? (
            <div className="wrap">
              {T('pf_rot_every')}
              <b>{rotateEvery}</b>
            </div>
          ) : null}
        </div>
      </div>

      {enabled ? (
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
      ) : (
        <div className="offbadge">
          <Icon name="warn" color="var(--bad-tx)" />
          <span>{T('pf_off_note')}</span>
        </div>
      )}

      <div className="nact iconly">
        <ActBtn cls="reset" icon="reset" title={T('tip_reset')} busy={busyAct === 'reset'} locked={!!busyAct} onClick={resetTraffic} />
        {enabled && multiTarget && serverActive ? (
          <ActBtn
            icon="redo"
            title={T('pf_rotate_now')}
            style={ROTATE_BTN_STYLE}
            busy={busyAct === 'rotate'}
            locked={!!busyAct}
            onClick={rotateNow}
          />
        ) : null}
        <ActBtn
          cls="warn"
          icon="pen"
          title={T('tip_edit')}
          busy={busyAct === 'edit'}
          locked={!!busyAct}
          onClick={() => withBusy('edit', () => onEdit(item))}
        />
        <ActBtn cls="danger" icon="trash" title={T('tip_delete')} busy={busyAct === 'del'} locked={!!busyAct} onClick={remove} />
      </div>
    </AccordionCard>
  )
}

export default memo(PortfwCard)
