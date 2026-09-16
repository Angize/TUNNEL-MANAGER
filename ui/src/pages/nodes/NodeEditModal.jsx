import { useEffect, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import ProxyFields, { proxyBody } from '../../components/ProxyFields.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { translateError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { isNodeNameValid } from './nodeName.js'
import useBusy from '../../lib/useBusy.js'

export default function NodeEditModal({ node, onClose, onSaved }) {
  const [proxies, setProxies] = useState([])
  const [busy, guard] = useBusy()
  const [name, setName] = useState(node.name)
  const [host, setHost] = useState(node.host)
  const [port, setPort] = useState(String(node.port))
  const [token, setToken] = useState('')
  const [proxy, setProxy] = useState({ on: !!node.proxy_on, id: node.proxy_id || '' })
  const [message, setMessage] = useState('')

  useEffect(() => {
    let alive = true
    apiGet('proxies')
      .then((r) => {
        if (alive) setProxies(r.proxies)
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  const save = async () => {
    if (!name.trim() || !host.trim() || !port.trim()) {
      setMessage('')
      alertBox(T('need_nhp'))
      return
    }
    if (!isNodeNameValid(name.trim())) {
      setMessage('')
      alertBox(T('node_name_ascii'))
      return
    }
    setMessage(T('saving'))
    const r = await apiPost('node-edit', {
      id: node.id,
      name: name.trim(),
      host: host.trim(),
      port: port.trim(),
      token: token.trim(),
      ...proxyBody(proxy),
    })
    if (r.ok && r.d.ok) {
      onClose()
      onSaved()
      return
    }
    setMessage('')
    alertBox(translateError(r.d.error || T('failed')))
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        {busy ? <span className="bspin" /> : T('save')}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal icon="pen" title={T('nd_edit')} subtitle={node.name} footer={footer} onClose={onClose}>
      <div className="grid2">
        <div>
          <label className="first">{T('f_name')}</label>
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div>
          <label className="first">{T('f_host_ip')}</label>
          <input value={host} onChange={(e) => setHost(e.target.value)} />
        </div>
      </div>
      <div className="grid2">
        <div>
          <label>{T('f_port')}</label>
          <input value={port} onChange={(e) => setPort(e.target.value)} />
        </div>
        <div>
          <label>{T('f_token')}</label>
          <input
            placeholder={T('tok_keep')}
            value={token}
            onChange={(e) => setToken(e.target.value)}
          />
        </div>
      </div>
      <ProxyFields proxies={proxies} value={proxy} onChange={setProxy} />
      <div className="msg">{message}</div>
    </Modal>
  )
}
