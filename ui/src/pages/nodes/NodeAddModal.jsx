import { useCallback, useEffect, useRef, useState } from 'react'
import Modal from '../../components/Modal.jsx'
import Icon from '../../components/Icon.jsx'
import { Check } from '../../components/Marks.jsx'
import ProxyFields, { proxyBody } from '../../components/ProxyFields.jsx'
import InstallProgress from './InstallProgress.jsx'
import useInstallJob from './useInstallJob.js'
import { isNodeNameValid } from './nodeName.js'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { PORT_MAX, rangeLabel } from '../../lib/form.js'

const EMPTY_PROXY = { on: false, id: '' }

export default function NodeAddModal({ onClose, onAdded }) {
  const [mode, setMode] = useState('auto')
  const [authMode, setAuthMode] = useState('pass')
  const [proxies, setProxies] = useState([])
  const [busy, setBusy] = useState(false)
  const [installed, setInstalled] = useState(false)
  const progressRef = useRef(null)

  const [auto, setAuto] = useState({
    name: '',
    host: '',
    sshPort: '',
    sshUser: '',
    agentPort: '',
    pass: '',
    key: '',
  })
  const [autoProxy, setAutoProxy] = useState(EMPTY_PROXY)

  const [manual, setManual] = useState({ name: '', host: '', port: '', token: '' })
  const [manualProxy, setManualProxy] = useState(EMPTY_PROXY)

  const onFinished = useCallback(
    (success, banner) => {
      setBusy(false)
      if (!success) return
      setInstalled(true)
      toast(banner || T('inst_node_installed'), 'ok')
      onAdded()
    },
    [onAdded]
  )

  const { state: progress, start, reset } = useInstallJob({ onFinished })

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

  const switchMode = (next) => {
    setMode(next)
    setInstalled(false)
    reset()
  }

  const autoInstall = async () => {
    const name = auto.name.trim()
    const host = auto.host.trim()
    const pass = authMode === 'pass' ? auto.pass : ''
    const key = authMode === 'key' ? auto.key.trim() : ''

    if (!name || !host) {
      alertBox(T('nadd_need_name_ip'))
      return
    }
    if (!isNodeNameValid(name)) {
      alertBox(T('node_name_ascii'))
      return
    }
    if (!pass && !key) {
      alertBox((authMode === 'key' ? T('nadd_privkey') : T('nadd_pass_word')) + T('nadd_is_required'))
      return
    }

    setBusy(true)
    setInstalled(false)
    const r = await apiPost('node-install', {
      name,
      ssh_host: host,
      ssh_port: auto.sshPort.trim(),
      ssh_user: auto.sshUser.trim(),
      agent_port: auto.agentPort.trim(),
      ssh_pass: pass,
      ssh_key: key,
      ...proxyBody(autoProxy),
    })
    if (!(r.ok && r.d.ok)) {
      setBusy(false)
      reset()
      alertBox(postError(r))
      return
    }
    start(r.d.job)
    if (progressRef.current) {
      progressRef.current.scrollIntoView({ behavior: 'smooth', block: 'center' })
    }
  }

  const addManual = async () => {
    const { name, host, port, token } = manual
    if (!name.trim() || !host.trim() || !port.trim() || !token.trim()) {
      alertBox(T('need_all_nhpt'))
      return
    }
    if (!isNodeNameValid(name.trim())) {
      alertBox(T('node_name_ascii'))
      return
    }
    setBusy(true)
    const r = await apiPost('node-add', {
      name: name.trim(),
      host: host.trim(),
      port: port.trim(),
      token: token.trim(),
      ...proxyBody(manualProxy),
    })
    setBusy(false)
    if (r.ok && r.d.ok) {
      onClose()
      toast(T('node_added_checking'), 'ok')
      onAdded()
      return
    }
    alertBox(postError(r))
  }

  const submit = () => {
    if (mode !== 'auto') return addManual()
    if (installed) return onClose()
    return autoInstall()
  }

  const primaryLabel = installed ? (
    <>
      <Check /> {T('inst_done')}
    </>
  ) : mode === 'auto' ? (
    <>
      <Icon name="bolt" />
      {progress && progress.finished && !progress.success ? T('inst_retry') : T('nadd_install_connect')}
    </>
  ) : (
    <>
      <Icon name="plus" />
      {T('nadd_add_connect')}
    </>
  )

  const footer = (
    <>
      <button
        className={'primary' + (installed ? ' done' : '')}
        disabled={busy}
        onClick={submit}
      >
        {busy ? <span className="bspin" /> : primaryLabel}
      </button>
      <button className="ghost" onClick={onClose}>
        {T('cancel')}
      </button>
    </>
  )

  return (
    <Modal icon="plus" title={T('nadd_title')} footer={footer} onClose={onClose}>
      <div className="seg">
        <button className={mode === 'auto' ? 'on' : undefined} onClick={() => switchMode('auto')}>
          <Icon name="bolt" />
          {T('nadd_auto')}
        </button>
        <button className={mode === 'manual' ? 'on' : undefined} onClick={() => switchMode('manual')}>
          <Icon name="pen" />
          {T('nadd_manual')}
        </button>
      </div>

      {mode === 'auto' ? (
        <div>
          <div className="autonote">
            <Icon name="bolt" />
            <span>{T('nadd_autonote')}</span>
          </div>
          <div className="grid2">
            <div>
              <label className="first">{T('nadd_node_name')}</label>
              <input
                placeholder="DE02"
                value={auto.name}
                onChange={(e) => setAuto({ ...auto, name: e.target.value })}
              />
            </div>
            <div>
              <label className="first">{T('nadd_srv_ip')}</label>
              <input
                placeholder="5.75.197.55"
                value={auto.host}
                onChange={(e) => setAuto({ ...auto, host: e.target.value })}
              />
            </div>
          </div>
          <div className="grid2">
            <div>
              <label>{rangeLabel(T('nadd_ssh_port'), 1, PORT_MAX)}</label>
              <input
                placeholder="22"
                value={auto.sshPort}
                onChange={(e) => setAuto({ ...auto, sshPort: e.target.value })}
              />
            </div>
            <div>
              <label>{T('nadd_ssh_user')}</label>
              <input
                placeholder="root"
                value={auto.sshUser}
                onChange={(e) => setAuto({ ...auto, sshUser: e.target.value })}
              />
            </div>
          </div>
          <div className="grid2">
            <div>
              <label>{rangeLabel(T('nadd_agent_port'), 1, PORT_MAX)}</label>
              <input
                placeholder="8099"
                value={auto.agentPort}
                onChange={(e) => setAuto({ ...auto, agentPort: e.target.value })}
              />
            </div>
            <div />
          </div>

          <div className="authbox">
            <div className="authhd">
              <span className="t">{T('nadd_ssh_auth')}</span>
              <span className="authseg">
                <button
                  type="button"
                  className={authMode === 'pass' ? 'on' : undefined}
                  onClick={() => setAuthMode('pass')}
                >
                  {T('nadd_pass')}
                </button>
                <button
                  type="button"
                  className={authMode === 'key' ? 'on' : undefined}
                  onClick={() => setAuthMode('key')}
                >
                  {T('nadd_privkey')}
                </button>
              </span>
            </div>
            {authMode === 'pass' ? (
              <input
                className="fld2"
                type="password"
                autoComplete="new-password"
                placeholder={T('nadd_pass_ph')}
                value={auto.pass}
                onChange={(e) => setAuto({ ...auto, pass: e.target.value })}
              />
            ) : (
              <textarea
                className="fld2"
                rows={3}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                value={auto.key}
                onChange={(e) => setAuto({ ...auto, key: e.target.value })}
              />
            )}
            <div className="muted" style={{ fontSize: 11, marginTop: 7 }}>
              {authMode === 'key' ? T('nadd_key_hint') : T('nadd_pass_hint')}
            </div>
          </div>

          <ProxyFields proxies={proxies} value={autoProxy} onChange={setAutoProxy} />

          <div ref={progressRef}>
            <InstallProgress state={progress} />
          </div>
        </div>
      ) : (
        <div>
          <div className="grid2">
            <div>
              <label className="first">{T('nadd_manual_name')}</label>
              <input
                placeholder="frankfurt-1"
                value={manual.name}
                onChange={(e) => setManual({ ...manual, name: e.target.value })}
              />
            </div>
            <div>
              <label className="first">{T('nadd_manual_host')}</label>
              <input
                placeholder="203.0.113.10"
                value={manual.host}
                onChange={(e) => setManual({ ...manual, host: e.target.value })}
              />
            </div>
          </div>
          <div className="grid2">
            <div>
              <label>{rangeLabel(T('nadd_agent_port2'), 1, PORT_MAX)}</label>
              <input
                placeholder="8099"
                value={manual.port}
                onChange={(e) => setManual({ ...manual, port: e.target.value })}
              />
            </div>
            <div>
              <label>{T('nadd_node_tok')}</label>
              <input
                placeholder={T('nadd_node_tok')}
                value={manual.token}
                onChange={(e) => setManual({ ...manual, token: e.target.value })}
              />
            </div>
          </div>
          <ProxyFields proxies={proxies} value={manualProxy} onChange={setManualProxy} />
        </div>
      )}
    </Modal>
  )
}
