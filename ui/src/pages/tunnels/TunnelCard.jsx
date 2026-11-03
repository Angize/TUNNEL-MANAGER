import { memo, useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import ActionRow from '../../components/ActionRow.jsx'
import CardBody from '../../components/CardBody.jsx'
import TagPicker from '../../components/TagPicker.jsx'
import TunnelMeta from './TunnelMeta.jsx'
import { copyText } from '../../components/CopyValue.jsx'
import { linkSideState } from './sideHealth.js'
import SideDot, { SideStatus } from './SideDot.jsx'
import DriftNote from './DriftNote.jsx'
import RebuildPicker from '../../components/RebuildPicker.jsx'
import CardResult from '../../components/CardResult.jsx'
import Grip from '../../components/Grip.jsx'
import Chevron from '../../components/Chevron.jsx'
import { SelBox } from '../../components/Bulk.jsx'
import ActBtn from '../../components/ActBtn.jsx'
import useDragging from '../../lib/useDragging.js'
import { useActionBusy } from '../../lib/useBusy.js'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate, num } from '../../lib/num.js'
import { tagClass, tagStyle } from '../../lib/cardTags.js'
import { isCardOpen, subscribeOpenCards, toggleCard } from '../../lib/openCards.js'
import useLongPress from '../../lib/useLongPress.js'
import useCardActions from '../../lib/useCardActions.js'
import { checkable, pressable } from '../../lib/keys.js'

function SideBox({ link, side }) {
  const state = linkSideState(link, side)
  return (
    <div className={'tnnode st-' + state.kind} title={state.title}>
      <div className="tnhead">
        <span className="tnn" dir="auto" title={link[side + '_name']}>
          {link[side + '_name']}
        </span>
        <span className="stat">
          <SideStatus link={link} side={side} />
        </span>
      </div>
      <div className="tna mono cpv" title={T('tip_copy')} {...pressable((e) => copyText(link[side + '_ip'], e))}>
        {link[side + '_ip']}
      </div>
    </div>
  )
}

function TunnelCard({ link, act, onEdit, onReload, onTag, register, sel }) {
  const [open, setOpen] = useState(() => isCardOpen(link.id))
  const [message, setMessage] = useState(null)
  const [picking, setPicking] = useState(false)

  useEffect(() => subscribeOpenCards(() => setOpen(isCardOpen(link.id))), [link.id])

  const hold = useLongPress(() => setPicking(true))
  const dragging = useDragging(link.id)
  const [pickingRebuild, setPickingRebuild] = useState(null)
  const enabled = link.enabled !== false
  const [busyAct, withBusy] = useActionBusy()
  const [toggleBusy, withToggle] = useActionBusy()

  const { check, speed, flip, toggle, resetTraffic, rebuild } = useCardActions({
    link,
    onReload,
    setMessage,
    withBusy,
    withToggle,
    setPickingRebuild,
    register,
  })

  const remove = async () => {
    const force =
      link.a_online === false ||
      link.b_online === false ||
      (!!act && act.state === 'fail' && act.offer === 'force')
    const confirmed = force
      ? await confirmBox(T('del_force_ask'), T('del_force_yes'))
      : await confirmBox(T('del_tun_confirm'), T('confirm_del'))
    if (!confirmed) return
    const r = await withBusy('del', () =>
      apiPost('delete-link', force ? { id: link.id, force: true } : { id: link.id })
    )
    if (!r) return
    if (!(r.ok && r.d.act)) {
      toast(postError(r), 'err')
      return
    }
    setMessage(null)
    onReload()
  }

  return (
    <>
      <div
        className={
          'card acc' +
          (enabled ? '' : ' off') +
          (open ? ' open' : '') +
          (act && act.state === 'run' ? ' acting' : '') +
          (dragging ? ' rdrag' : '') +
          (sel && sel.picked ? ' sel' : '') +
          tagClass(link)
        }
        data-rid={link.id}
        data-rk="tunnels"
        style={tagStyle(link.tag)}
      >
        <div
          className="chead"
          {...(sel
            ? pressable(() => sel.pick(link.id))
            : { ...hold, ...pressable(() => toggleCard(link.id), () => setPicking(true)), 'aria-expanded': open })}
        >
          <Grip />
          {sel ? (
            <SelBox on={sel.picked} />
          ) : (
            <div
              className={'tsw' + (enabled ? ' on' : '') + (toggleBusy ? ' busy' : '')}
              aria-busy={!!toggleBusy}
              title={T('tip_toggle')}
              {...checkable('switch', enabled, toggle)}
            />
          )}
          <div className="hmain">
            <div className="hrow1">
              <span className="hname">{link.name}</span>
              <span className={'ctag ' + (link.type || '')}>{(link.type || '').toUpperCase()}</span>
              <span className="hpeers" dir="ltr">
                <SideDot link={link} side="a" />
                <span className="pn" title={link.a_name}>
                  {link.a_name}
                </span>
                <Icon name="arrows" />
                <span className="pn" title={link.b_name}>
                  {link.b_name}
                </span>
                <SideDot link={link} side="b" />
              </span>
            </div>
          </div>
          {sel ? null : <Chevron />}
        </div>

        <CardBody open={open}>
          <DriftNote link={link} busy={busyAct === 'rebuild'} locked={!!busyAct} onRebuild={rebuild} />

          <div className="tninfo">
            <SideBox link={link} side="a" />
            <span className="tnarrow">
              <Icon name="arrows" />
            </span>
            <SideBox link={link} side="b" />
          </div>

          <TunnelMeta link={link} />

          {link.enabled === false ? (
            <div className="offbadge">
              <Icon name="plugoff" />
              <span>{T('tun_off_note')}</span>
            </div>
          ) : (
            <div className="ltraf">
              {link.rx_total != null || link.rx_bps != null ? (
                <>
                  <span className="din iso">↓ {fmtRate(link.rx_bps)}</span>
                  <span className="dout iso">↑ {fmtRate(link.tx_bps)}</span>
                </>
              ) : (
                <span className="muted" style={{ fontSize: 11 }}>
                  {T('no_live_side')}
                </span>
              )}
              <span className="tot">
                {T('total')}{' '}
                {link.rx_total != null || link.rx_bps != null ? (
                  <span className="iso">
                    <b className="din">↓{fmtBytes(link.rx_total)}</b>
                    <b className="dout">↑{fmtBytes(link.tx_total)}</b>
                  </span>
                ) : (
                  <b className="mono">—</b>
                )}
              </span>
            </div>
          )}

          <ActionRow act={act} />

          <div className="nact iconly">
            <ActBtn cls="ok" icon="activity" title={T('tip_ping')} busy={busyAct === 'ping'} locked={!!busyAct} onClick={check} />
            <ActBtn cls="info" icon="gauge" title={T('tip_speed')} busy={busyAct === 'speed'} locked={!!busyAct} onClick={speed} />
            <ActBtn
              cls="info"
              icon="swap"
              title={T('tip_flip') + (link.view_name || '—')}
              busy={busyAct === 'flip'}
              locked={!!busyAct}
              onClick={flip}
            />
            <ActBtn cls="reset" icon="reset" title={T('tip_reset')} busy={busyAct === 'reset'} locked={!!busyAct} onClick={resetTraffic} />
            <ActBtn cls="warn" icon="pen" title={T('tip_edit')} locked={!!busyAct} onClick={() => onEdit(link)} />
            <ActBtn icon="redo" title={T('tip_rebuild')} busy={busyAct === 'rebuild'} locked={!!busyAct} onClick={rebuild} />
            <ActBtn cls="danger" icon="trash" title={T('tip_delete')} busy={busyAct === 'del'} locked={!!busyAct} onClick={remove} />
          </div>

          <CardResult message={message} />
        </CardBody>
      </div>

      {picking ? (
        <TagPicker
          current={num(link.tag)}
          onPick={(tag) => {
            setPicking(false)
            onTag(link, tag)
          }}
          onClose={() => setPicking(false)}
        />
      ) : null}

      {pickingRebuild ? (
        <RebuildPicker
          id={link.id}
          start={pickingRebuild}
          onStart={() => setMessage(null)}
          onClose={() => setPickingRebuild(null)}
          onDone={onReload}
        />
      ) : null}
    </>
  )
}

export default memo(TunnelCard)
