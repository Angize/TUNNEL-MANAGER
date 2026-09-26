import { useEffect, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import ProxyFields, { proxyBody } from '../../components/ProxyFields.jsx'
import SecretInput from '../../components/SecretInput.jsx'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { isNodeNameValid } from './nodeName.js'
import useBusy from '../../lib/useBusy.js'
import { LTR_TEXT } from '../../lib/form.js'

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
    alertBox(postError(r))
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
        <Field label={T('f_name')} first>
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label={T('f_host_ip')} first>
          <input
            {...LTR_TEXT}
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </Field>
      </div>
      <div className="grid2">
        <Field label={T('f_port')}>
          <NumberInput value={port} onChange={setPort} />
        </Field>
        <Field label={T('f_token')}>
          <SecretInput placeholder={T('tok_keep')} value={token} onChange={setToken} />
        </Field>
      </div>
      <ProxyFields proxies={proxies} value={proxy} onChange={setProxy} />
      <div className="msg">{message}</div>
    </Modal>
  )
}
