import { useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Field from '../../components/Field.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import ProxyFields, { proxyBody } from '../../components/ProxyFields.jsx'
import SecretInput from '../../components/SecretInput.jsx'
import { T } from '../../i18n/fa.js'
import { apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { isNodeNameValid } from './nodeName.js'
import NodeIpField from './NodeIpField.jsx'
import useBusy from '../../lib/useBusy.js'
import useProxies from '../../lib/useProxies.js'

import { LTR_TEXT } from '../../lib/form.js'
import Msg from '../../components/Msg.jsx'
import SaveLabel from '../../components/SaveLabel.jsx'
import useSaved from '../../lib/useSaved.js'

export default function NodeEditModal({ node, onClose, onSaved }) {
  const [busy, guard] = useBusy()
  const [saved, markSaved] = useSaved()
  const [name, setName] = useState(node.name)
  const [host, setHost] = useState(node.host)
  const ipRef = useRef(null)
  const [port, setPort] = useState(String(node.port))
  const [token, setToken] = useState('')
  const [proxy, setProxy] = useState({ on: !!node.proxy_on, id: node.proxy_id || '' })
  const [message, setMessage] = useState('')
  const proxies = useProxies()

  const save = async () => {
    if (!ipRef.current.checkValidity()) return
    if (!name.trim() || !port.trim()) {
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
      setMessage('')
      if (await markSaved(T('saved_ok'))) onClose()
      onSaved()
      return
    }
    setMessage('')
    alertBox(postError(r))
  }

  const footer = (
    <>
      <button className="primary" disabled={busy} onClick={guard(save)}>
        <SaveLabel busy={busy} saved={saved}>
          {T('save')}
        </SaveLabel>
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
          <input {...LTR_TEXT} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <NodeIpField first inputRef={ipRef} value={host} onChange={setHost} />
      </div>
      <div className="grid2">
        <Field label={T('f_port')}>
          <NumberInput value={port} onChange={setPort} />
        </Field>
        <Field label={T('f_token')} hint={T('tok_keep')}>
          <SecretInput value={token} onChange={setToken} />
        </Field>
      </div>
      <ProxyFields proxies={proxies} value={proxy} onChange={setProxy} />
      <Msg text={message} />
    </Modal>
  )
}
