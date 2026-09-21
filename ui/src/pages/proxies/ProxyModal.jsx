import { useEffect, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import ProxyNodes from './ProxyNodes.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'
import useBusy from '../../lib/useBusy.js'

export default function ProxyModal({ proxy, onClose, onSaved }) {
  const [name, setName] = useState(proxy ? proxy.name : '')
  const [busy, guard] = useBusy()
  const [scheme, setScheme] = useState((proxy && proxy.scheme) || 'socks5')
  const [host, setHost] = useState(proxy ? proxy.host : '')
  const [port, setPort] = useState(proxy ? String(proxy.port) : '')
  const [user, setUser] = useState(proxy ? proxy.user : '')
  const [pass, setPass] = useState('')
  const [nodes, setNodes] = useState(null)
  const [initial, setInitial] = useState(() => new Set())
  const [picked, setPicked] = useState(() => new Set())

  useEffect(() => {
    if (!proxy) return undefined
    let alive = true
    apiGet('nodes')
      .then((r) => {
        if (!alive) return
        const on = new Set(r.nodes.filter((n) => n.proxy_on && n.proxy_id === proxy.id).map((n) => n.id))
        setNodes(r.nodes)
        setInitial(on)
        setPicked(on)
      })
      .catch(() => {
        if (alive) setNodes(false)
      })
    return () => {
      alive = false
    }
  }, [proxy])

  const save = async () => {
    const body = {
      name: name.trim(),
      scheme,
      host: host.trim(),
      port: port.trim(),
      user: user.trim(),
      pass,
    }
    if (proxy) body.id = proxy.id
    if (proxy && Array.isArray(nodes)) {
      body.nodes_on = [...picked].filter((id) => !initial.has(id))
      body.nodes_off = [...initial].filter((id) => !picked.has(id))
    }
    const r = await apiPost(proxy ? 'proxy-edit' : 'proxy-add', body)
    if (r.ok && r.d.ok) {
      onClose()
      toast(T('px_saved'), 'ok')
      onSaved()
    } else {
      alertBox(postError(r))
    }
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        {busy ? <span className="bspin" /> : T(proxy ? 'save' : 'add')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal
      icon={proxy ? 'pen' : 'plus'}
      title={T(proxy ? 'px_edit_t' : 'px_add_t')}
      subtitle={proxy ? proxy.name : null}
      footer={footer}
      onClose={onClose}
    >
      <label className="first">{T('px_name')}</label>
      <input maxLength={40} value={name} onChange={(e) => setName(e.target.value)} />

      <div className="authhd" style={{ marginTop: 16 }}>
        <span className="t">{T('px_type')}</span>
        <span className="authseg">
          <button
            type="button"
            className={scheme === 'socks5' ? 'on' : undefined}
            onClick={() => setScheme('socks5')}
          >
            SOCKS5
          </button>
          <button
            type="button"
            className={scheme === 'http' ? 'on' : undefined}
            onClick={() => setScheme('http')}
          >
            HTTP
          </button>
        </span>
      </div>

      <div className="grid2">
        <div>
          <label className="first">{T('px_ip')}</label>
          <input className="mono" value={host} onChange={(e) => setHost(e.target.value)} />
        </div>
        <div>
          <label className="first">{rangeLabel(T('px_port'), 1, PORT_MAX)}</label>
          <input
            className="mono"
            inputMode="numeric"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
      </div>

      <div className="grid2">
        <div>
          <label>{T('px_user')}</label>
          <input
            placeholder={T('px_opt')}
            value={user}
            onChange={(e) => setUser(e.target.value)}
          />
        </div>
        <div>
          <label>{T('px_pass')}</label>
          <input
            type="password"
            autoComplete="new-password"
            placeholder={proxy && proxy.has_pass ? T('px_pass_keep') : T('px_opt')}
            value={pass}
            onChange={(e) => setPass(e.target.value)}
          />
        </div>
      </div>

      <div className="muted" style={{ fontSize: 11.5, lineHeight: 1.9, marginTop: 6 }}>
        {T('px_hint')}
      </div>

      {proxy ? (
        <>
          <label>{T('px_nodes')}</label>
          <ProxyNodes proxyId={proxy.id} nodes={nodes} picked={picked} onPick={setPicked} />
          <div className="muted" style={{ fontSize: 11.5, lineHeight: 1.9, marginTop: 6 }}>
            {T('px_nodes_hint')}
          </div>
        </>
      ) : null}
    </Modal>
  )
}
