import { useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import { Check, Cross } from '../../components/Marks.jsx'
import ActionRow from '../../components/ActionRow.jsx'
import TagPicker from '../../components/TagPicker.jsx'
import RichText from '../../components/RichText.jsx'
import CoreMeta from './CoreMeta.jsx'
import { copyText } from '../../components/CopyValue.jsx'
import { boxClass, sideState, sideText } from '../tunnels/sideHealth.js'
import { carrierFamily, carrierLabel } from './carrier.js'
import Grip from '../../components/Grip.jsx'
import useDragging from '../../lib/useDragging.js'
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
  if (link.enabled === false) return <span className="sdot na" title={T('st_off')} />
  const state = sideState(link[side + '_online'], link[side + '_health'])
  return <span className={'sdot ' + state.kind} title={state.title} />
}

function SideStatus({ link, side, live }) {
  if (link.enabled === false) {
    return (
      <>
        <span className="stw na">{T('st_off')}</span>
        <span className="sdot na" />
      </>
    )
  }
  const health = live ? live[side + '_health'] : link[side + '_health']
  const online = live ? live[side + '_online'] : link[side + '_online']
  const state = sideState(online, health)
  return state.word ? <span className={'stw ' + state.kind}>{state.word}</span> : null
}

function SideBox({ link, side, activeIp, rotating, live }) {
  const isServer = (side === 'a') === serverIsA(link)
  const health = live ? live[side + '_health'] : link[side + '_health']
  const online = live ? live[side + '_online'] : link[side + '_online']

  return (
    <div className={'tnnode ' + boxClass(online, health)} title={sideState(online, health).title}>
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
            <SideStatus link={link} side={side} live={live} />
          </span>
        </span>
      </div>
      <div className="tna mono cpv" title={T('tip_copy')} onClick={(e) => copyText(activeIp, e)}>
        {activeIp}
      </div>
    </div>
  )
}

export default function CoreCard({ link, activeEdge, onEdit, onReload, onTag, registerCheck }) {
  const { actFor } = useActs()
  const [open, setOpen] = useState(() => isCardOpen(link.id))
  const [message, setMessage] = useState(null)
  const [live, setLive] = useState(null)
  const [picking, setPicking] = useState(false)
  const messageTimer = useRef(0)
  const checkRef = useRef(null)

  useEffect(() => subscribeOpenCards(() => setOpen(isCardOpen(link.id))), [link.id])
  useEffect(() => () => clearTimeout(messageTimer.current), [])

  const hold = useLongPress(() => setPicking(true))
  const act = actFor(link.id)
  const dragging = useDragging(link.id)
  const enabled = link.enabled !== false
  const [first, second] = sideOrder(link)

  const activeIp = (side) => link[side + '_ip_active'] || link[side + '_ip']

  const toggle = async (e) => {
    e.stopPropagation()
    const next = link.enabled === false
    const r = await apiPost('link-toggle', { id: link.id, enabled: next })
    if (!(r.ok && r.d.ok)) toast(T('failed'), 'err')
    else if (r.d.both === false) toast(translateError(r.d.msg) || T('failed'), 'err')
    else toast(next ? T('turned_on') : T('turned_off'), 'ok')
    onReload()
  }

  const check = async () => {
    setMessage({ cls: '', text: T('checking_conn') })
    const r = await apiPost('check-link', { id: link.id })
    if (!(r.ok && r.d.ok)) {
      setMessage({ cls: 'err', text: postError(r) })
      return
    }
    if (link.enabled === false) {
      setMessage({ cls: '', text: T('conn_off') })
      return
    }
    const d = r.d
    setLive(d)
    const aUp = d.a_online && d.a_health && d.a_health.up
    const bUp = d.b_online && d.b_health && d.b_health.up
    const allOk = aUp && bUp && d.a_health.alive === true && d.b_health.alive === true
    setMessage({
      cls: allOk ? 'ok' : 'err',
      lines: {
        ok: allOk,
        head: allOk ? T('conn_ok') : T('conn_bad'),
        a: (link.a_name || 'A') + ': ' + sideText(d.a_online, d.a_health),
        b: (link.b_name || 'B') + ': ' + sideText(d.b_online, d.b_health),
      },
    })
  }

  checkRef.current = check

  useEffect(() => {
    if (registerCheck) registerCheck(() => checkRef.current())
  }, [registerCheck])

  const speed = async () => {
    setMessage({ cls: '', text: T('speed_run') })
    const r = await apiPost('link-speed', { id: link.id })
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
    const r = await apiPost('link-view', { id: link.id })
    if (!(r.ok && r.d.ok)) {
      toast(T('failed'), 'err')
      return
    }
    const name = r.d.view_side === 'b' ? link.b_name : link.a_name
    setMessage({ cls: 'ok', swap: true, text: T('view_switched') + name + T('view_switched2') })
    clearTimeout(messageTimer.current)
    messageTimer.current = setTimeout(() => setMessage(null), VIEW_MSG_MS)
    onReload()
  }

  const resetTraffic = async () => {
    if (!(await confirmBox(T('reset_confirm')))) return
    const r = await apiPost('traffic-reset', { id: link.id })
    if (r.ok && r.d.ok) {
      toast(T('t_reset_done'), 'ok')
      onReload()
      return
    }
    toast(postError(r), 'err')
  }

  const restart = async () => {
    if (!(await confirmBox(T('restart_confirm'), T('restart_yes')))) return
    const r = await apiPost('restart-link', { id: link.id })
    if (!(r.ok && r.d.act)) {
      toast(postError(r, 'restart_failed'), 'err')
      return
    }
    setMessage(null)
    onReload()
  }

  const rebuild = async () => {
    if (!(await confirmBox(T('rebuild_confirm')))) return
    const r = await apiPost('rebuild-link', { id: link.id })
    if (!(r.ok && r.d.act)) {
      toast(postError(r, 'rebuild_failed'), 'err')
      return
    }
    setMessage(null)
    onReload()
  }

  const remove = async () => {
    const offline = link.a_online === false || link.b_online === false
    const confirmed = offline
      ? await confirmBox(T('del_force_ask'), T('del_force_yes'))
      : await confirmBox(T('del_tun_confirm'))
    if (!confirmed) return
    const r = await apiPost('delete-link', offline ? { id: link.id, force: true } : { id: link.id })
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
        <div className="chead" onClick={() => toggleCard(link.id)} {...hold}>
          <Grip />
          <div className={'tsw' + (enabled ? ' on' : '')} title={T('tip_toggle')} onClick={toggle} />
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
                {link[first + '_name']} ↔ {link[second + '_name']}
                <HeaderDot link={link} side={second} />
              </span>
            </div>
          </div>
          <Chevron />
        </div>

        <div className="cbody">
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
                live={live}
              />
              <span className="tnarrow">↔</span>
              <SideBox
                link={link}
                side={second}
                activeIp={activeIp(second)}
                rotating={link[second + '_ip_rot']}
                live={live}
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
              <button className="act ok" title={T('tip_ping')} onClick={check}>
                <Icon name="activity" />
              </button>
              <button className="act info" title={T('tip_speed')} onClick={speed}>
                <Icon name="gauge" />
              </button>
              <button
                className="act flip"
                title={T('tip_flip') + (link.view_name || '—')}
                onClick={flip}
              >
                <Icon name="swap" />
              </button>
              <button className="act reset" title={T('tip_reset')} onClick={resetTraffic}>
                <Icon name="reset" />
              </button>
              <button
                className="act warn"
                title={T('tip_edit')}
                onClick={() => onEdit(link)}
              >
                <Icon name="pen" />
              </button>
              <button className="act" title={T('tip_rebuild')} onClick={rebuild}>
                <Icon name="redo" />
              </button>
              <button className="act info" title={T('tip_restart')} onClick={restart}>
                <Icon name="restart" />
              </button>
              <button className="act danger" title={T('tip_delete')} onClick={remove}>
                <Icon name="trash" />
              </button>
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
                    <Check /> {T('speed_done')} <span className="muted">{message.speed.how}</span>
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
    </>
  )
}
