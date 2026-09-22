import { useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { Check, Cross } from '../../components/Marks.jsx'
import ActionRow from '../../components/ActionRow.jsx'
import TagPicker from '../../components/TagPicker.jsx'
import RichText from '../../components/RichText.jsx'
import CoreMeta from './CoreMeta.jsx'
import { copyText } from '../../components/CopyValue.jsx'
import { linkSideState, sideText } from '../tunnels/sideHealth.js'
import { carrierFamily, carrierLabel } from './carrier.js'
import RebuildPicker from '../../components/RebuildPicker.jsx'
import Grip from '../../components/Grip.jsx'
import ActBtn from '../../components/ActBtn.jsx'
import useDragging from '../../lib/useDragging.js'
import { useActionBusy } from '../../lib/useBusy.js'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, translateError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate, num } from '../../lib/num.js'
import { tagClass, tagStyle } from '../../lib/cardTags.js'
import { isCardOpen, subscribeOpenCards, toggleCard } from '../../lib/openCards.js'
import useLongPress from '../../lib/useLongPress.js'
import { useActs } from '../../state/ActsContext.jsx'
import { checkable, pressable } from '../../lib/keys.js'

const VIEW_MSG_MS = 4000

function Chevron() {
  return (
    <svg
      className="chev"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.4"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  )
}

function serverIsA(link) {
  return link.server_side !== 'b'
}

function sideOrder(link) {
  return serverIsA(link) ? ['b', 'a'] : ['a', 'b']
}

function HeaderDot({ link, side }) {
  const state = linkSideState(link, side)
  return <span className={'sdot ' + state.kind} title={state.title} />
}

function SideStatus({ link, side }) {
  const state = linkSideState(link, side)
  if (state.off) {
    return (
      <>
        <span className="stw na">{state.word}</span>
        <span className="sdot na" />
      </>
    )
  }
  return state.word ? <span className={'stw ' + state.kind}>{state.word}</span> : null
}

function SideBox({ link, side, activeIp, rotating }) {
  const isServer = (side === 'a') === serverIsA(link)
  const state = linkSideState(link, side)

  return (
    <div className={'tnnode st-' + state.kind} title={state.title}>
      <div className="tnhead">
        <span className="tnn">{link[side + '_name']}</span>
        <span className="tnend">
          <span className={'rl ' + (isServer ? 'srv' : 'cli')}>
            {isServer ? T('server') : T('client')}
          </span>
          <span className="cprot">
            {rotating ? (
              <span className="rotmark" title={T('peer_rotating')}>
                <Icon name="redo" />
              </span>
            ) : null}
          </span>
          <span className="stat">
            <SideStatus link={link} side={side} />
          </span>
        </span>
      </div>
      <div className="tna mono cpv" title={T('tip_copy')} {...pressable((e) => copyText(activeIp, e))}>
        {activeIp}
      </div>
    </div>
  )
}

export default function CoreCard({ link, activeEdge, onEdit, onReload, onTag, registerCheck }) {
  const { actFor } = useActs()
  const [open, setOpen] = useState(() => isCardOpen(link.id))
  const [message, setMessage] = useState(null)
  const [picking, setPicking] = useState(false)
  const messageTimer = useRef(0)
  const checkRef = useRef(null)

  useEffect(() => subscribeOpenCards(() => setOpen(isCardOpen(link.id))), [link.id])
  useEffect(() => () => clearTimeout(messageTimer.current), [])

  const hold = useLongPress(() => setPicking(true))
  const act = actFor(link.id)
  const dragging = useDragging(link.id)
  const [pickingRebuild, setPickingRebuild] = useState(false)
  const enabled = link.enabled !== false
  const [busyAct, withBusy] = useActionBusy()
  const [toggleBusy, withToggle] = useActionBusy()
  const [first, second] = sideOrder(link)

  const activeIp = (side) => link[side + '_ip_active'] || link[side + '_ip']

  const toggle = (e) => {
    e.stopPropagation()
    withToggle('toggle', async () => {
      const next = link.enabled === false
      const r = await apiPost('link-toggle', { id: link.id, enabled: next })
      if (!(r.ok && r.d.ok)) toast(postError(r), 'err')
      else toast(next ? T('turned_on') : T('turned_off'), 'ok')
      await onReload()
    })
  }

  const check = async () => {
    const r = await withBusy('ping', () => {
      setMessage({ cls: '', text: T('checking_conn') })
      return apiPost('check-link', { id: link.id })
    })
    if (!r) return
    if (!(r.ok && r.d.ok)) {
      setMessage({ cls: 'err', text: postError(r) })
      return
    }
    if (link.enabled === false) {
      setMessage({ cls: '', text: T('conn_off') })
      return
    }
    const d = r.d
    const aUp = d.a_online && d.a_health && d.a_health.up
    const bUp = d.b_online && d.b_health && d.b_health.up
    const allOk = aUp && bUp && d.a_health.alive === true && d.b_health.alive === true
    setMessage({
      cls: allOk ? 'ok' : 'err',
      lines: {
        ok: allOk,
        head: allOk ? T('conn_ok') : T('conn_bad'),
        a: (link.a_name || 'A') + ': ' + sideText(d.a_online, d.a_health, translateError(d.a_error)),
        b: (link.b_name || 'B') + ': ' + sideText(d.b_online, d.b_health, translateError(d.b_error)),
      },
    })
  }

  checkRef.current = check

  useEffect(() => {
    if (registerCheck) registerCheck(() => checkRef.current())
  }, [registerCheck])

  const speed = async () => {
    const r = await withBusy('speed', () => {
      setMessage({ cls: '', text: T('speed_run') })
      return apiPost('link-speed', { id: link.id })
    })
    if (!r) return
    if (!(r.ok && r.d.ok)) {
      setMessage({ cls: 'err', text: postError(r) })
      return
    }
    const d = r.d
    const up = num(d.up_mbit)
    const down = num(d.down_mbit)
    setMessage({
      cls: up > 0 && down > 0 ? 'ok' : 'err',
      speed: {
        how: T('speed_how')
          .replace('{s}', String(num(d.secs)))
          .replace('{u}', String(num(d.up_streams)))
          .replace('{d}', String(num(d.down_streams))),
        down: fmtRate(down * 1e6),
        up: fmtRate(up * 1e6),
      },
    })
  }

  const flip = async () => {
    const r = await withBusy('flip', () => apiPost('link-view', { id: link.id }))
    if (!r) return
    if (!(r.ok && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    const name = r.d.view_side === 'b' ? link.b_name : link.a_name
    setMessage({ cls: 'ok', swap: true, text: T('view_switched') + name + T('view_switched2') })
    clearTimeout(messageTimer.current)
    messageTimer.current = setTimeout(
      () => setMessage((cur) => (cur && cur.swap ? null : cur)),
      VIEW_MSG_MS
    )
    onReload()
  }

  const resetTraffic = async () => {
    if (!(await confirmBox(T('reset_confirm'), T('reset_yes')))) return
    const r = await withBusy('reset', () => apiPost('traffic-reset', { id: link.id }))
    if (!r) return
    if (r.ok && r.d.ok) {
      toast(T('t_reset_done'), 'ok')
      onReload()
      return
    }
    toast(postError(r), 'err')
  }

  const restart = async () => {
    if (!(await confirmBox(T('restart_confirm'), T('restart_yes')))) return
    const r = await withBusy('restart', () => apiPost('restart-link', { id: link.id }))
    if (!r) return
    if (!(r.ok && r.d.act)) {
      toast(postError(r, 'restart_failed'), 'err')
      return
    }
    setMessage(null)
    onReload()
  }

  const rebuild = async () => {
    if (link.drift) {
      setPickingRebuild(true)
      return
    }
    if (!(await confirmBox(T('rebuild_confirm'), T('tip_rebuild')))) return
    const r = await withBusy('rebuild', () => apiPost('rebuild-link', { id: link.id }))
    if (!r) return
    if (!(r.ok && r.d.act)) {
      toast(postError(r, 'rebuild_failed'), 'err')
      return
    }
    setMessage(null)
    onReload()
  }

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
          tagClass(link)
        }
        id={'c_' + link.id}
        data-rid={link.id}
        data-rk="core"
        style={tagStyle(link.tag)}
      >
        <div
          className="chead"
          {...hold}
          {...pressable(() => toggleCard(link.id), () => setPicking(true))}
        >
          <Grip />
          <div
            className={'tsw' + (enabled ? ' on' : '') + (toggleBusy ? ' busy' : '')}
            aria-busy={!!toggleBusy}
            title={T('tip_toggle')}
            {...checkable('switch', enabled, toggle)}
          />
          <div className="hmain">
            <div className="hrow1">
              <span className="hname">{link.name}</span>
              <span className={'ctag c-' + carrierFamily(link)}>{carrierLabel(link)}</span>
              {enabled ? null : (
                <span className="offtxt" style={{ fontSize: 11 }}>
                  {T('st_off')}
                </span>
              )}
              <span className="hpeers" dir="ltr">
                <HeaderDot link={link} side={first} />
                <span className="pn">{link[first + '_name']}</span>
                <Icon name="arrows" />
                <span className="pn">{link[second + '_name']}</span>
                <HeaderDot link={link} side={second} />
              </span>
            </div>
          </div>
          <Chevron />
        </div>

        <div className="cbody" inert={!open}>
          <div className="cbody-in">
            {link.drift ? (
              <div
                className="msg err"
                style={{ margin: '0 0 9px', display: 'flex', alignItems: 'center', gap: 6 }}
              >
                <Icon name="warn" color="#e0564f" />
                <span>{T('drift_note')}</span>
              </div>
            ) : null}
            {link.rb && !link.rb.ok ? (
              <div className="msg err" style={{ margin: '0 0 9px' }}>
                {T('rb_last_fail')}
                {translateError(link.rb.error || T('rebuild_failed'))}
              </div>
            ) : null}

            <div className="tninfo">
              <SideBox
                link={link}
                side={first}
                activeIp={activeIp(first)}
                rotating={link[first + '_ip_rot']}
              />
              <span className="tnarrow">
                <Icon name="arrows" />
              </span>
              <SideBox
                link={link}
                side={second}
                activeIp={activeIp(second)}
                rotating={link[second + '_ip_rot']}
              />
            </div>

            <CoreMeta link={link} activeEdge={activeEdge} />

            {link.enabled === false ? (
              <div className="offbadge">
                <Icon name="warn" color="var(--bad)" />
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
              <ActBtn cls="info" icon="restart" title={T('tip_restart')} busy={busyAct === 'restart'} locked={!!busyAct} onClick={restart} />
              <ActBtn cls="danger" icon="trash" title={T('tip_delete')} busy={busyAct === 'del'} locked={!!busyAct} onClick={remove} />
            </div>

            <div className={message ? 'msg ' + message.cls : 'msg'}>
              {message && message.lines ? (
                <>
                  <div className="chh">
                    {message.lines.ok ? <Check /> : <Cross />} {message.lines.head}
                  </div>
                  <div className="chl">{message.lines.a}</div>
                  <div className="chl">{message.lines.b}</div>
                </>
              ) : message && message.speed ? (
                <>
                  <div className="chh">
                    {message.cls === 'ok' ? <Check /> : <Cross />} {T('speed_done')}{' '}
                    <span className="muted">{message.speed.how}</span>
                  </div>
                  <div className="chl">
                    {T('speed_down')}: {'⁦' + message.speed.down + '⁩'}
                  </div>
                  <div className="chl">
                    {T('speed_up')}: {'⁦' + message.speed.up + '⁩'}
                  </div>
                  <div className="wrap muted" style={{ marginTop: 6 }}>
                    <RichText text={T('speed_note')} />
                  </div>
                </>
              ) : message ? (
                <>
                  {message.swap ? <Icon name="swap" /> : null}
                  {message.text}
                </>
              ) : null}
            </div>
          </div>
        </div>
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
          onClose={() => setPickingRebuild(false)}
          onDone={onReload}
        />
      ) : null}
    </>
  )
}
