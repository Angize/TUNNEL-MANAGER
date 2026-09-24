import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { collectTuning, listViolation, rangeViolation, secondsToMinutes, stepViolation } from './tuning.js'
import { T, TF } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
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
    const a = form[key]
    const b = saved.form[key]
    const same = typeof a === 'string' && typeof b === 'string' ? a.trim() === b.trim() : a === b
    if (!same) n += 1
  }
  return n
}

export function SettingsFormProvider({ tabs, children }) {
  const config = useUiConfig()
  const defaults = useMemo(() => config.settings_defaults || {}, [config])
  const tuningDefaults = useMemo(() => config.tuning_defaults || {}, [config])
  const tuningSteps = useMemo(() => config.tuning_steps || {}, [config])
  const tuningRanges = useMemo(() => config.tuning_ranges || {}, [config])
  const probeSamples = num(config.probe_samples) || 20
  const [agentGen, setAgentGen] = useState(0)

  const [form, setForm] = useState(null)
  const [token, setToken] = useState('')
  const [mode, setMode] = useState('alert')
  const [saved, setSaved] = useState(null)
  const [busy, setBusy] = useState(false)
  const [loadError, setLoadError] = useState('')

  const settingValue = useCallback(
    (source, key) => (source && source[key] != null && source[key] !== '' ? source[key] : defaults[key]),
    [defaults]
  )

  const apply = useCallback((s) => {
    const tuning = s.tuning || {}
    const tuned = (key) => (tuning[key] != null ? tuning[key] : tuningDefaults[key])
    const nextMode = s.reconcile_mode === 'auto' ? 'auto' : 'alert'
    const next = {
      apiOn: !!s.api_external,
      reconcile: String(settingValue(s, 'reconcile_interval')),
      poll: String(settingValue(s, 'poll_interval')),
      ui: String(settingValue(s, 'ui_interval')),
      ech: String(settingValue(s, 'ech_refresh_mins')),
      window: String(settingValue(s, 'uptime_window')),
      probeMin: String(tuned('probe_min_pct')),
      revive: (tuned('ladder_revive') || []).join(', '),
      suspect: (tuned('suspect_backoff') || []).map((x) => secondsToMinutes(x)).join(', '),
      deadRetest: String(secondsToMinutes(tuned('dead_retest_secs'))),
      sockBuf: String(tuned('sock_buf_mb')),
    }
    setMode(nextMode)
    setForm(next)
    setSaved({ form: next, mode: nextMode })
  }, [settingValue, tuningDefaults])

  const load = useCallback(async () => {
    setLoadError('')
    let s
    try {
      s = await apiGet('settings')
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

  useEffect(() => {
    if (!dirty) return undefined
    return setLeaveGuard(
      (target) =>
        target === 'settings' ||
        tabs.includes(target) ||
        confirmBox(TF('set_leave_confirm', { n: dirty }), T('set_leave_yes'))
    )
  }, [dirty, tabs])

  const set = (key) => (value) => setForm((prev) => ({ ...prev, [key]: value }))

  const save = async () => {
    const tuning = collectTuning(form)
    const bad = listViolation(form) || rangeViolation(form, tuningRanges) || stepViolation(tuning, tuningSteps)
    if (bad) {
      alertBox(bad)
      return
    }
    setBusy(true)
    const r = await apiPost('settings-set', {
      api_external: form.apiOn,
      reconcile_mode: mode,
      reconcile_interval: form.reconcile.trim(),
      poll_interval: form.poll.trim(),
      ui_interval: form.ui.trim(),
      ech_refresh_mins: form.ech.trim(),
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
    const body = { tuning: tuningDefaults, ...defaults }
    delete body.log_hidden
    const r = await apiPost('settings-set', body)
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      apply(r.d.settings)
      setAgentGen((n) => n + 1)
      return
    }
    toast(postError(r), 'err')
  }

  const value = {
    form, mode, setMode, token, busy, loadError, dirty, agentGen, probeSamples,
    load, set, save, revert, newToken, reset,
  }

  return <FormContext.Provider value={value}>{children}</FormContext.Provider>
}
