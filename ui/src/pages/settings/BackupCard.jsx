import { useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import RestoreConfirm from './RestoreConfirm.jsx'
import UpdateRow from '../agent/UpdateRow.jsx'
import { T, TF } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'

const RETURN_WAIT_MS = 120000

function pad(n) {
  return String(n).padStart(2, '0')
}

function fileName(d) {
  return (
    'tnl-backup-' +
    d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + '-' +
    pad(d.getHours()) + pad(d.getMinutes()) + '.tar.gz'
  )
}

function saveFile(b64, name) {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/gzip' }))
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function readBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result).split(',', 2)[1] || '')
    reader.onerror = () => reject(reader.error)
    reader.readAsDataURL(file)
  })
}

async function waitForReturn(boot) {
  const until = Date.now() + RETURN_WAIT_MS
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 1500))
    try {
      const s = await apiGet('summary')
      if (s.boot && s.boot !== boot) return true
    } catch {
      continue
    }
  }
  return false
}

export default function BackupCard() {
  const [busy, setBusy] = useState('')
  const [check, setCheck] = useState(null)
  const [open, setOpen] = useState(false)
  const picker = useRef(null)

  const download = async () => {
    setBusy('get')
    const r = await apiPost('backup', {})
    setBusy('')
    if (!(r.ok && r.d.ok)) {
      alertBox(postError(r))
      return
    }
    saveFile(r.d.data, fileName(new Date()))
    toast(TF('set_bk_got', { n: r.d.nodes, l: r.d.core + r.d.system }), 'ok')
  }

  const inspect = async (file) => {
    setBusy('put')
    let data
    try {
      data = await readBase64(file)
    } catch {
      setBusy('')
      alertBox(T('set_bk_read_fail'))
      return
    }
    const r = await apiPost('backup-restore', { data })
    setBusy('')
    if (!(r.ok && r.d.ok)) {
      alertBox(postError(r))
      return
    }
    setCheck({ data, info: r.d })
  }

  const restore = async () => {
    setBusy('apply')
    const r = await apiPost('backup-restore', { data: check.data, apply: true })
    if (!(r.ok && r.d.ok)) {
      setBusy('')
      setCheck(null)
      alertBox(postError(r))
      return
    }
    toast(T('set_bk_restarting'), 'ok')
    if (await waitForReturn(r.d.boot)) {
      location.reload()
      return
    }
    setBusy('')
    setCheck(null)
    alertBox(T('set_bk_no_return'))
  }

  return (
    <div className="card opc sc-panel upc bkcard">
      <UpdateRow
        icon="shield"
        title={T('bk_card')}
        sub={T('bk_sub_short')}
        goIcon="download"
        goLabel={busy === 'get' ? T('set_bk_getting') : T('set_bk_get_btn')}
        goDisabled={!!busy}
        onGo={download}
        open={open}
        onToggle={() => setOpen((v) => !v)}
      >
        <div className="upmeta">{T('bk_meta')}</div>
        <div className="oprow">
          <button
            type="button"
            className="ghost tone tone-put"
            disabled={!!busy}
            onClick={() => picker.current && picker.current.click()}
          >
            <Icon name="upload" />
            {busy === 'put' ? T('set_bk_reading') : T('set_bk_put')}
          </button>
        </div>
        <p className="bkhint">{T('bk_hint')}</p>
      </UpdateRow>
      <input
        ref={picker}
        type="file"
        accept=".gz,.tgz,application/gzip"
        hidden
        onChange={(e) => {
          const file = e.target.files && e.target.files[0]
          e.target.value = ''
          if (file) inspect(file)
        }}
      />

      {check ? (
        <RestoreConfirm
          info={check.info}
          busy={busy === 'apply'}
          onRestore={restore}
          onClose={() => setCheck(null)}
        />
      ) : null}
    </div>
  )
}
