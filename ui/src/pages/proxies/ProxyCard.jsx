import { useState } from 'react'
import AccordionCard from '../../components/AccordionCard.jsx'
import Icon from '../../components/Icon.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { translateError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import { Check } from '../../components/Marks.jsx'

export default function ProxyCard({ proxy, onEdit, onChanged }) {
  const [msg, setMsg] = useState(null)

  const status = proxy.status || {}
  const dot = proxy.online ? 'on' : proxy.pending ? '' : 'off'
  const title =
    (proxy.pending ? T('pending_check') : proxy.online ? T('online') : T('offline')) +
    (status.error ? ' — ' + translateError(status.error) : '')

  const test = async () => {
    setMsg({ cls: '', text: T('px_testing') })
    const r = await apiPost('proxy-test', { id: proxy.id })
    const d = r.d || {}
    if (r.ok && d.ok) {
      setMsg({ cls: 'ok', text: T('px_up') + ' · ' + num(d.ms) + 'ms', check: true })
    } else {
      setMsg(null)
      alertBox(translateError(d.error || T('failed')))
    }
  }

  const remove = async () => {
    if (!(await confirmBox(T('px_del_confirm')))) return
    const r = await apiPost('proxy-del', { id: proxy.id })
    if (r.ok && r.d.ok) {
      toast(T('px_deleted'), 'ok')
      onChanged()
    } else {
      toast(translateError((r.d && (r.d.error || r.d.msg)) || T('failed')), 'err')
    }
  }

  const head = (
    <>
      <span className="grow" />
      <div
        className="hmain"
        style={{ direction: 'ltr', alignItems: 'flex-start', gap: 2, flex: '0 0 auto', minWidth: 0 }}
      >
        <div className="name" style={{ textAlign: 'left' }}>
          {proxy.name}
        </div>
        <div className="muted mono" style={{ fontSize: 12 }}>
          {proxy.addr}
        </div>
      </div>
      <span className={'ndot ' + dot} title={title} />
    </>
  )

  return (
    <AccordionCard id={proxy.id} className="node acc" head={head}>
      <div className="pxused">
        {proxy.nodes && proxy.nodes.length ? (
          T('px_used_by') + proxy.nodes.join('، ')
        ) : (
          <span className="muted">{T('px_used_none')}</span>
        )}
      </div>
      {status.error ? (
        <div className="pxused" style={{ color: 'var(--bad)' }}>
          {translateError(status.error)}
        </div>
      ) : null}
      <div className="nact iconly">
        <button className="act ok" title={T('px_test')} onClick={test}>
          <Icon name="bolt" />
        </button>
        <button className="act warn" title={T('tip_edit')} onClick={() => onEdit(proxy)}>
          <Icon name="pen" />
        </button>
        <button className="act danger" title={T('tip_delete')} onClick={remove}>
          <Icon name="trash" />
        </button>
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
