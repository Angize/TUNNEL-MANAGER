import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { toast } from '../../lib/toast.js'
import { runPageRefresh } from '../../lib/poll.js'
import { proxyBody } from '../../components/ProxyFields.jsx'
import { TF } from '../../i18n/fa.js'
import { endText, endTone, tally, targetText } from './bulk.js'

const POLL_MS = 700

const EMPTY_FORM = {
  text: '',
  prefix: '',
  sshPort: '',
  sshUser: '',
  agentPort: '',
  authMode: 'pass',
  pass: '',
  key: '',
  proxy: { on: false, id: '' },
}

function lostRows(rows, why) {
  return rows.map((r) => (r.state === 'run' || r.state === 'wait' ? { ...r, state: 'err', step: '', detail: why } : r))
}

function creds(form) {
  return {
    ssh_port: form.sshPort.trim(),
    ssh_user: form.sshUser.trim(),
    agent_port: form.agentPort.trim(),
    ssh_pass: form.authMode === 'pass' ? form.pass : '',
    ssh_key: form.authMode === 'key' ? form.key.trim() : '',
  }
}

function entry(x) {
  return { name: x.name, ssh_host: x.host, ssh_port: x.port, ssh_user: x.user, ssh_pass: x.pass }
}

function rebuildLine(r) {
  return (r.name && r.name !== r.host ? r.name + '  ' : '') + targetText(r)
}

export default function useBulkInstall() {
  const [form, setFormState] = useState(EMPTY_FORM)
  const [batch, setBatch] = useState(null)
  const [starting, setStarting] = useState(false)
  const [dialog, setDialog] = useState(false)
  const [asked, setAsked] = useState(false)
  const sent = useRef([])
  const registered = useRef(0)
  const current = useRef('')
  const latest = useRef(batch)
  const openRef = useRef(dialog)
  latest.current = batch
  openRef.current = dialog

  const setForm = useCallback((patch) => setFormState((f) => ({ ...f, ...patch })), [])

  const adopt = useCallback((next, rows) => {
    sent.current = rows || []
    registered.current = next ? tally(next.rows).good : 0
    current.current = next ? next.id : ''
    setBatch(next)
  }, [])

  useEffect(() => {
    let alive = true
    apiGet('install-batch')
      .then((d) => {
        if (alive && d.batch && !d.done && !current.current) {
          adopt({ id: d.batch, rows: d.rows, done: false, stopped: !!d.stopped })
        }
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [adopt])

  const id = batch ? batch.id : ''
  const done = batch ? batch.done : true

  useEffect(() => {
    if (!id || done) return undefined
    let alive = true
    let timer = 0
    const settle = (rows, over, stopped) => {
      const t = tally(rows)
      if (t.good > registered.current) {
        registered.current = t.good
        runPageRefresh()
      }
      setBatch((b) => (b && b.id === id ? { ...b, rows, done: over, stopped } : b))
      if (over && !openRef.current) toast(TF('nb_toast_done', { s: endText(t) }), endTone(t) === 'bad' ? 'err' : 'ok')
    }
    const gone = () => !alive || !latest.current || latest.current.id !== id
    const tick = async () => {
      try {
        const d = await apiGet('install-batch?batch=' + encodeURIComponent(id) + '&_=' + Date.now())
        if (gone()) return
        settle(d.rows, !!d.done, !!d.stopped)
        if (d.done) return
      } catch (e) {
        if (gone()) return
        if (e instanceof ApiError && e.status === 400) {
          settle(lostRows(latest.current.rows, readError(e)), true, true)
          return
        }
      }
      timer = setTimeout(tick, POLL_MS)
    }
    timer = setTimeout(tick, POLL_MS)
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [id, done])

  const start = useCallback(
    async (rows) => {
      setStarting(true)
      const r = await apiPost('node-install-batch', {
        ...creds(form),
        ...proxyBody(form.proxy),
        rows: rows.map(entry),
      })
      setStarting(false)
      if (!(r.ok && r.d.ok)) return postError(r)
      adopt({ id: r.d.batch, rows: r.d.rows, done: false, stopped: false }, rows)
      return ''
    },
    [form, adopt]
  )

  const stop = useCallback(async () => {
    if (!id) return
    const r = await apiPost('install-batch-stop', { batch: id })
    if (!(r.ok && r.d.ok)) toast(postError(r), 'err')
  }, [id])

  const retryRow = useCallback(
    async (i) => {
      const b = latest.current
      if (!b) return ''
      const row = b.rows[i]
      const f = await apiPost('install-forget-key', { job: row.job })
      if (!(f.ok && f.d.ok)) return postError(f)
      const r = await apiPost('install-batch-retry', {
        ...creds(form),
        batch: b.id,
        row: i,
        entry: sent.current[i] ? entry(sent.current[i]) : { name: row.name, ssh_host: row.host, ssh_port: row.port, ssh_user: row.user },
      })
      if (!(r.ok && r.d.ok)) return postError(r)
      setBatch((cur) => (cur && cur.id === b.id ? { ...cur, rows: r.d.rows, done: !!r.d.done, stopped: !!r.d.stopped } : cur))
      return ''
    },
    [form]
  )

  const editFailed = useCallback(() => {
    const rows = latest.current ? latest.current.rows : []
    const lines = rows
      .map((r, i) => (r.state === 'err' || r.state === 'stop' ? (sent.current[i] ? sent.current[i].raw : rebuildLine(r)) : null))
      .filter((line) => line !== null)
    setFormState((f) => ({ ...f, text: lines.join('\n') }))
    adopt(null)
  }, [adopt])

  const finish = useCallback(() => {
    setFormState(EMPTY_FORM)
    adopt(null)
  }, [adopt])

  const ask = useCallback(() => setAsked(true), [])
  const took = useCallback(() => setAsked(false), [])

  return { form, setForm, batch, starting, start, stop, retryRow, editFailed, finish, dialog, setDialog, asked, ask, took }
}
