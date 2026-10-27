import { memo, useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import ActBtn from '../../components/ActBtn.jsx'
import { useActionBusy } from '../../lib/useBusy.js'
import UptimeBar from './UptimeBar.jsx'
import { coreVersionName } from '../agent/versions.js'
import { T, TF } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate, num } from '../../lib/num.js'
import { checkable } from '../../lib/keys.js'
import Msg from '../../components/Msg.jsx'

function NodeTraffic({ traffic }) {
  if (!traffic) return null
  return (
    <div className="ltraf ndtraf">
      <span className="din iso">↓ {fmtRate(traffic.rx_bps)}</span>
      <span className="dout iso">↑ {fmtRate(traffic.tx_bps)}</span>
      <span className="tot">
        {T('total')}{' '}
        <span className="iso">
          <b className="din">↓{fmtBytes(traffic.rx_total)}</b>
          <b className="dout">↑{fmtBytes(traffic.tx_total)}</b>
        </span>
      </span>
    </div>
  )
}

function NodeCard({
  node,
  windowHours,
  onToggle,
  onChanged,
  onEdit,
  onDetails,
  onTune,
  onDelete,
  onMovedIp,
}) {
  const [message, setMessage] = useState(null)
  const [messageOnline, setMessageOnline] = useState(node.online)
  if (messageOnline !== node.online) {
    setMessageOnline(node.online)
    setMessage(null)
  }
  const info = node.info || {}
  const enabled = node.disabled !== true
  const dot = node.online ? 'on' : node.pending ? '' : 'off'

  const [busyAct, withBusy] = useActionBusy()
  const [toggleBusy, withToggle] = useActionBusy()

  const toggle = (e) => {
    e.stopPropagation()
    withToggle('toggle', () => onToggle(node))
  }

  const test = async () => {
    const r = await withBusy('test', () => {
      setMessage({ cls: '', text: T('test_testing') })
      return apiPost('node-test', { id: node.id })
    })
    if (!r) return
    if (!r.ok) {
      setMessage({ cls: 'err', text: readError(r) })
      return
    }
    const probe = r.d.info
    if (r.d.ok) {
      const ms = probe.rtt_ms
      setMessage({
        cls: 'ok',
        check: true,
        text: T('online') + ' — ' + (probe.hostname || '') + (ms != null ? ' · ' + ms + 'ms' : ''),
      })
      return
    }
    setMessage({ cls: 'err', text: T('offline') + ': ' + (translateError(probe.error) || T('not_available')) })
  }

  const resetTraffic = async () => {
    if (!(await confirmBox(T('nreset_confirm'), T('reset_yes')))) return
    const r = await withBusy('reset', () => apiPost('traffic-reset', { node: node.id }))
    if (!r) return
    if (r.ok && r.d.ok) {
      toast(T('t_reset_done'), 'ok')
      onChanged()
      return
    }
    toast(postError(r), 'err')
  }

  const head = (
    <>
      <div
        className={'tsw' + (enabled ? ' on' : '') + (toggleBusy ? ' busy' : '')}
        aria-busy={!!toggleBusy}
        aria-label={T('nd_toggle')}
        title={T('nd_toggle')}
        {...checkable('switch', enabled, toggle)}
      />
      <span
        className={'ndot ' + dot}
        title={node.online ? T('online') : node.pending ? T('pending_check') : T('offline')}
      />
      <div className="hmain" style={{ alignItems: 'flex-start', gap: 2 }}>
        <div className="name nmrow">
          <span className="nmtxt" dir="ltr">
            {node.name}
          </span>
          {node.pending_del > 0 ? (
            <span className="tag pdel" title={T('pend_del_t')}>
              <Icon name="trash" />
              {TF('pend_del_n', { n: num(node.pending_del) })}
            </span>
          ) : null}
          {node.proxy_on ? <span className="tag">{T('proxy')}</span> : null}
          {node.moved_to ? (
            <button
              type="button"
              className="mvwarn"
              aria-label={T('nd_moved_t')}
              title={T('nd_moved_t')}
              onClick={(e) => {
                e.stopPropagation()
                onMovedIp(node)
              }}
            >
              <Icon name="warn" />
            </button>
          ) : null}
        </div>
        <div className="muted mono nmtxt" dir="ltr" style={{ fontSize: 12 }}>
          {node.host}:{node.port}
        </div>
      </div>
    </>
  )

  return (
    <AccordionCard
      id={node.id}
      kind="nodes"
      className={'node acc' + (enabled ? '' : ' off')}
      head={head}
      beforeBody={<NodeTraffic traffic={node.traffic} />}
    >
      {node.online ? (
        <div className="nchips">
          <span className="nchip">
            <Icon name="link" />
            {T('nd_tunnels')} <b>{num(info.tunnels)}</b>
          </span>
          <span className="nchip">
            <Icon name="globe" />
            {T('nd_portfw')} <b>{num(info.portfw)}</b>
          </span>
          {info.version ? (
            <span className="nchip">
              <Icon name="server" />
              {T('nd_agent')} <b>{info.version}</b>
            </span>
          ) : null}
          {info.core_sha && String(info.core_sha).length ? (
            <span className="nchip">
              <Icon name="cpu" />
              {T('nd_core')} <b>{coreVersionName(info.core_ver) || '?'}</b>
            </span>
          ) : (
            <span className="nchip" style={{ color: 'var(--sub)' }}>
              <Icon name="cpu" />
              {T('nd_core')} <b>{T('nd_core_missing')}</b>
            </span>
          )}
        </div>
      ) : (
        <div className="noff">
          <Icon name="plugoff" />
          <b>{T('not_available')}</b>
          {info.error ? <span>· {translateError(info.error)}</span> : null}
        </div>
      )}

      <UptimeBar node={node} windowHours={windowHours} />

      <div className="nact iconly">
        <ActBtn cls="ok" icon="bolt" title={T('tip_test')} busy={busyAct === 'test'} locked={!!busyAct} onClick={test} />
        {node.online ? (
          <ActBtn cls="tune" icon="gauge" title={T('tip_tune')} locked={!!busyAct} onClick={() => onTune(node)} />
        ) : null}
        <ActBtn cls="reset" icon="reset" title={T('tip_nreset')} busy={busyAct === 'reset'} locked={!!busyAct} onClick={resetTraffic} />
        <ActBtn cls="info" icon="info" title={T('tip_details')} locked={!!busyAct} onClick={() => onDetails(node)} />
        <ActBtn cls="warn" icon="pen" title={T('tip_edit')} locked={!!busyAct} onClick={() => onEdit(node)} />
        <ActBtn cls="danger" icon="trash" title={T('tip_delete')} locked={!!busyAct} onClick={() => onDelete(node)} />
      </div>

      <Msg text={message && message.text} cls={message && message.cls} check={message && message.check} />
    </AccordionCard>
  )
}

export default memo(NodeCard)
