import { useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import ActBtn from '../../components/ActBtn.jsx'
import useActionBusy from '../../lib/useActionBusy.js'
import { T, TF } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError, readError, translateError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import { Check } from '../../components/Marks.jsx'

function Names({ names }) {
  return (
    <div className="pxgrid">
      {names.map((name) => (
        <span key={name} className="pxcell mono" title={name}>
          {name}
        </span>
      ))}
    </div>
  )
}

function UsedBy({ nodes, tunnels, panel }) {
  const parts = [
    nodes.length ? TF('px_used_nodes', { n: nodes.length }) : '',
    tunnels.length ? TF('px_used_tunnels', { n: tunnels.length }) : '',
    panel ? T('px_used_panel_only') : '',
  ].filter(Boolean)
  if (!parts.length) {
    return (
      <div className="pxused">
        <span className="muted">{T('px_used_none')}</span>
      </div>
    )
  }
  return (
    <div className="pxu">
      <div className="pxuh">
        <b>{T('px_used')}</b>
        <span className="pxuc">{parts.join(' + ')}</span>
      </div>
      {panel ? (
        <div className="pxpanel">
          <Icon name="server" />
          {T('px_used_panel')}
        </div>
      ) : null}
      {nodes.length ? <Names names={nodes} /> : null}
      {tunnels.length ? (
        <>
          <div className="pxpanel">
            <Icon name="link" />
            {T('px_used_ech')}
          </div>
          <Names names={tunnels} />
        </>
      ) : null}
    </div>
  )
}

export default function ProxyCard({ proxy, onEdit, onChanged }) {
  const [msg, setMsg] = useState(null)

  const status = proxy.status || {}
  const dot = proxy.online ? 'on' : proxy.pending ? '' : 'off'
  const title =
    (proxy.pending ? T('pending_check') : proxy.online ? T('online') : T('offline')) +
    (status.error ? ' — ' + translateError(status.error) : '')

  const [busyAct, withBusy] = useActionBusy()

  const test = async () => {
    setMsg({ cls: '', text: T('px_testing') })
    const r = await withBusy('test', () => apiPost('proxy-test', { id: proxy.id }))
    if (!r) return
    const d = r.d
    if (r.ok && d.ok) {
      setMsg({
        cls: 'ok',
        text:
          T('px_up') + ' · ' + num(d.ms) + 'ms' +
          (d.reach != null ? ' · ' + T('px_google') + ' ' + num(d.reach) + 'ms' : ''),
        check: true,
      })
    } else {
      setMsg(null)
      alertBox(readError(r))
    }
  }

  const remove = async () => {
    if (!(await confirmBox(T('px_del_confirm'), T('confirm_del')))) return
    const r = await withBusy('del', () => apiPost('proxy-del', { id: proxy.id }))
    if (!r) return
    if (r.ok && r.d.ok) {
      toast(T('px_deleted'), 'ok')
      onChanged()
    } else {
      toast(postError(r), 'err')
    }
  }

  const head = (
    <>
      <span className="grow" />
      <div
        className="hmain"
        style={{ direction: 'ltr', alignItems: 'flex-start', gap: 2, flex: '0 1 auto', minWidth: 0 }}
      >
        <div className="name nmrow">
          <span className="nmtxt">{proxy.name}</span>
        </div>
        <div className="muted mono nmtxt" style={{ fontSize: 12 }}>
          {proxy.addr}
        </div>
      </div>
      <span className={'ndot ' + dot} title={title} />
    </>
  )

  return (
    <AccordionCard id={proxy.id} className="node acc" head={head}>
      <UsedBy nodes={proxy.nodes} tunnels={proxy.tunnels} panel={proxy.panel} />
      {status.error ? (
        <div className="pxused" style={{ color: 'var(--bad)' }}>
          {translateError(status.error)}
        </div>
      ) : null}
      <div className="nact iconly">
        <ActBtn cls="ok" icon="bolt" title={T('px_test')} busy={busyAct === 'test'} locked={!!busyAct} onClick={test} />
        <ActBtn cls="warn" icon="pen" title={T('tip_edit')} locked={!!busyAct} onClick={() => onEdit(proxy)} />
        <ActBtn cls="danger" icon="trash" title={T('tip_delete')} busy={busyAct === 'del'} locked={!!busyAct} onClick={remove} />
      </div>
      <div className={msg ? 'msg ' + msg.cls : 'msg'}>
        {msg ? (
          <>
            {msg.check ? <Check /> : null}
            {msg.check ? ' ' + msg.text : msg.text}
          </>
        ) : null}
      </div>
    </AccordionCard>
  )
}
