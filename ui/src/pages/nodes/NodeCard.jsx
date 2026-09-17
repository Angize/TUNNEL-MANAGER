import { useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import { Check } from '../../components/Marks.jsx'
import UptimeBar from './UptimeBar.jsx'
import { coreVersionName } from '../agent/versions.js'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { fmtBytes, fmtRate, num } from '../../lib/num.js'
import { checkable } from '../../lib/keys.js'

const PENDING_DEL_STYLE = {
  fontSize: 9,
  padding: '1px 5px',
  background: 'color-mix(in srgb, #e0894f 18%, transparent)',
  color: '#e0894f',
}

const PROXY_TAG_STYLE = { fontSize: 9.5, padding: '1px 6px' }

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

export default function NodeCard({
  node,
  windowHours,
  onToggled,
  onChanged,
  onEdit,
  onDetails,
  onTune,
  onDelete,
  onMovedIp,
}) {
  const [message, setMessage] = useState(null)
  const info = node.info || {}
  const enabled = node.disabled !== true
  const dot = node.online ? 'on' : node.pending ? '' : 'off'

  const toggle = async (e) => {
    e.stopPropagation()
    const disabled = enabled
    onToggled(node.id, disabled)
    const r = await apiPost('node-toggle', { id: node.id, disabled })
    if (!(r.ok && r.d.ok)) {
      onToggled(node.id, !disabled)
      toast(postError(r), 'err')
      return
    }
    toast(disabled ? T('nd_hidden') : T('nd_shown'), 'ok')
  }

  const test = async () => {
    setMessage({ cls: '', text: T('test_testing') })
    const r = await apiPost('node-test', { id: node.id })
    if (!r.ok) {
      setMessage(null)
      alertBox(readError(r))
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
    setMessage(null)
    alertBox(T('offline') + ': ' + (translateError(probe.error) || T('not_available')))
  }

  const resetTraffic = async () => {
    if (!(await confirmBox(T('nreset_confirm')))) return
    const r = await apiPost('traffic-reset', { node: node.id })
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
        className={'tsw' + (enabled ? ' on' : '')}
        title={T('nd_toggle')}
        {...checkable('switch', enabled, toggle)}
      />
      {node.moved_to ? (
        <button
          className="mvwarn"
          title={T('nd_moved_t')}
          onClick={(e) => {
            e.stopPropagation()
            onMovedIp(node)
          }}
        >
          <Icon name="warn" />
        </button>
      ) : null}
      <span className="grow" />
      <div
        className="hmain"
        style={{ direction: 'ltr', alignItems: 'flex-start', gap: 2, flex: '0 1 auto', minWidth: 0 }}
      >
        <div className="name nmrow">
          <span className="nmtxt">{node.name}</span>
          {node.pending_del > 0 ? (
            <span className="tag" style={PENDING_DEL_STYLE} title={T('pend_del_t')}>
              <Icon name="trash" />
              {num(node.pending_del)}
            </span>
          ) : null}
          {node.proxy_on ? (
            <span className="tag" style={PROXY_TAG_STYLE}>
              {T('proxy')}
            </span>
          ) : null}
        </div>
        <div className="muted mono nmtxt" style={{ fontSize: 12 }}>
          {node.host}:{node.port}
        </div>
      </div>
      <span
        className={'ndot ' + dot}
        title={node.online ? T('online') : node.pending ? T('pending_check') : T('offline')}
      />
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
              {T('nd_agent')} v<b>{num(info.version)}</b>
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
        <button className="act ok" title={T('tip_test')} onClick={test}>
          <Icon name="bolt" />
        </button>
        {node.online ? (
          <button className="act" title={T('tip_tune')} onClick={() => onTune(node)}>
            <Icon name="gauge" />
          </button>
        ) : null}
        <button className="act reset" title={T('tip_nreset')} onClick={resetTraffic}>
          <Icon name="reset" />
        </button>
        <button className="act info" title={T('tip_details')} onClick={() => onDetails(node)}>
          <Icon name="info" />
        </button>
        <button className="act warn" title={T('tip_edit')} onClick={() => onEdit(node)}>
          <Icon name="pen" />
        </button>
        <button className="act danger" title={T('tip_delete')} onClick={() => onDelete(node)}>
          <Icon name="trash" />
        </button>
      </div>

      <div className={message ? 'msg ' + message.cls : 'msg'}>
        {message ? (
          <>
            {message.check ? <Check /> : null}
            {message.check ? ' ' + message.text : message.text}
          </>
        ) : null}
      </div>
    </AccordionCard>
  )
}
