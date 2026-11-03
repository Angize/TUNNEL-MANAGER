import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { FIELDS, collectTuning, formErrors, secondsToMinutes } from './tuning.js'
import { T, TF } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { alertBox, askBox, confirmBox } from '../../lib/dialog.js'
import { setLeaveGuard } from '../../lib/leaveGuard.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'

const FormContext = createContext(null)

export function useSettingsForm() {
  return useContext(FormContext)
}

function changedCount(form, mode, saved) {
  if (!form || !saved) return 0
  let n = mode === saved.mode ? 0 : 1
  for (const key of Object.keys(form)) {
    if (form[key] !== saved.form[key]) n += 1
  }
  return n
}

export function SettingsFormProvider({ tabs, children }) {
  const config = useUiConfig()
  const defaults = config.settings_defaults
  const tuningDefaults = config.tuning_defaults
  const probeSamples = num(config.probe_samples)
  const [agentGen, setAgentGen] = useState(0)

  const [form, setForm] = useState(null)
  const [token, setToken] = useState('')
  const [mode, setMode] = useState(defaults.reconcile_mode)
  const [saved, setSaved] = useState(null)
  const [busy, setBusy] = useState(false)
  const [loadError, setLoadError] = useState('')
  const [loaded, setLoaded] = useState(0)
  const loadTurn = useRef(0)
  const [touched, setTouched] = useState({})
  const [tried, setTried] = useState(0)

  const apply = useCallback((s) => {
    const { tuning } = s
    const next = {
      apiOn: !!s.api_external,
      reconcile: String(s.reconcile_interval),
      poll: String(s.poll_interval),
      ui: String(s.ui_interval),
      ech: String(s.ech_refresh_mins),
      window: String(s.uptime_window),
      probeMin: String(tuning.probe_min_pct),
      revive: tuning.ladder_revive.join(', '),
      suspect: tuning.suspect_backoff.map((x) => secondsToMinutes(x)).join(', '),
      deadRetest: String(secondsToMinutes(tuning.dead_retest_secs)),
      sockBuf: String(tuning.sock_buf_mb),
      tcpBuf: String(tuning.tcp_buf_mb),
    }
    setMode(s.reconcile_mode)
    setForm(next)
    setSaved({ form: next, mode: s.reconcile_mode })
    setTouched({})
    setTried(0)
  }, [])

  const load = useCallback(async () => {
    setLoadError('')
    setLoaded(0)
    const mine = ++loadTurn.current
    let s
    try {
      s = await apiGet('settings', (p) => {
        if (mine === loadTurn.current) setLoaded(p)
      })
    } catch (e) {
      setLoadError(readError(e))
      return
    }
    apply(s)
  }, [apply])

  useEffect(() => {
    load()
  }, [load])

  const dirty = changedCount(form, mode, saved)
  const allErrors = useMemo(() => (form ? formErrors(form, config) : {}), [form, config])
  const errors = tried
    ? allErrors
    : Object.fromEntries(Object.entries(allErrors).filter(([key]) => touched[key]))

  useEffect(() => {
    if (!dirty) return undefined
    return setLeaveGuard(
      (target) =>
        target === 'settings' ||
        tabs.includes(target) ||
        askBox(TF('set_leave_confirm', { n: dirty }), T('set_leave_yes'))
    )
  }, [dirty, tabs])

  const set = (key) => (value) => setForm((prev) => ({ ...prev, [key]: value }))

  const touch = (key) => setTouched((prev) => (prev[key] ? prev : { ...prev, [key]: true }))

  const save = async () => {
    const bad = Object.entries(allErrors)
    if (bad.length) {
      const [key, msg] = bad[0]
      setTried((n) => n + 1)
      toast(TF('set_field_bad', { f: T(FIELDS[key].labelKey), m: msg }), 'err')
      return
    }
    const tuning = collectTuning(form)
    setBusy(true)
    const r = await apiPost('settings-set', {
      api_external: form.apiOn,
      reconcile_mode: mode,
      reconcile_interval: form.reconcile,
      poll_interval: form.poll,
      ui_interval: form.ui,
      ech_refresh_mins: form.ech,
      uptime_window: form.window,
      tuning,
    })
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      apply(r.d.settings)
      setBusy(false)
      return
    }
    setBusy(false)
    alertBox(postError(r))
  }

  const revert = () => {
    setForm(saved.form)
    setMode(saved.mode)
    setTouched({})
    setTried(0)
  }

  const newToken = async () => {
    if (!(await confirmBox(T('set_api_new_confirm'), T('set_api_new')))) return
    const r = await apiPost('api-token-new', {})
    if (r.ok && r.d.ok) {
      setToken(String(r.d.token || ''))
      toast(T('set_api_new_done'), 'ok')
      return
    }
    toast(postError(r), 'err')
  }

  const reset = async () => {
    if (!(await confirmBox(T('set_reset_confirm'), T('set_reset_yes')))) return
    const r = await apiPost('settings-set', { tuning: tuningDefaults, ...defaults })
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      apply(r.d.settings)
      setAgentGen((n) => n + 1)
      return
    }
    toast(postError(r), 'err')
  }

  const value = {
    form, mode, setMode, token, busy, loadError, loaded, dirty, agentGen, probeSamples, errors, tried,
    load, set, touch, save, revert, newToken, reset,
  }

  return <FormContext.Provider value={value}>{children}</FormContext.Provider>
}
