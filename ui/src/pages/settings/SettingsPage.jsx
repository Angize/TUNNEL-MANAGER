import { useCallback, useEffect, useMemo, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import { SettingsSkeleton } from '../../components/Skeleton.jsx'
import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import Select from '../../components/Select.jsx'
import SettingRow from './SettingRow.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import ModePicker, { modeLabel } from './ModePicker.jsx'
import AgentPage from '../agent/AgentPage.jsx'
import { collectTuning, secondsToMinutes, stepViolation } from './tuning.js'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { alertBox, confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { num } from '../../lib/num.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import './settings.css'

const WINDOW_OPTIONS = [
  { v: '1', label: 'h1' },
  { v: '3', label: 'h3' },
  { v: '6', label: 'h6' },
  { v: '8', label: 'h8' },
  { v: '12', label: 'h12' },
  { v: '24', label: 'h24' },
]

function NumberField({ value, onChange, min, max, step, wide }) {
  return (
    <input
      className={'search' + (wide ? ' wtxt' : '')}
      type="number"
      step={step}
      min={min}
      max={max}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

function TextField({ value, onChange }) {
  return (
    <input
      className="search wtxt"
      type="text"
      inputMode="numeric"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

export default function SettingsPage() {
  const config = useUiConfig()
  const defaults = useMemo(() => config.settings_defaults || {}, [config])
  const tuningDefaults = useMemo(() => config.tuning_defaults || {}, [config])
  const tuningSteps = useMemo(() => config.tuning_steps || {}, [config])
  const probeSamples = num(config.probe_samples) || 20

  const [form, setForm] = useState(null)
  const [token, setToken] = useState('')
  const [mode, setMode] = useState('alert')
  const [picking, setPicking] = useState(false)
  const [message, setMessage] = useState('')

  const settingValue = useCallback(
    (source, key) => (source && source[key] != null && source[key] !== '' ? source[key] : defaults[key]),
    [defaults]
  )

  const load = useCallback(async () => {
    let s = {}
    try {
      s = await apiGet('settings')
    } catch {
      s = {}
    }
    const tuning = s.tuning || {}
    const tuned = (key) => (tuning[key] != null ? tuning[key] : tuningDefaults[key])
    setMode(s.reconcile_mode === 'auto' ? 'auto' : 'alert')
    setToken(String(s.api_token || ''))
    setForm({
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
    })
  }, [settingValue, tuningDefaults])

  useEffect(() => {
    load()
  }, [load])

  if (!form) {
    return (
      <>
        <PageHead icon="cog" titleKey="nav_settings" subKey="set_sub" />
        <div className="stpage">
          <SettingsSkeleton />
          <p className="stnote">{T('set_apply_note')}</p>
          <div className="stsave">
            <button className="ghost" disabled>
              <Icon name="undo" />
              {T('set_reset')}
            </button>
            <button className="primary" disabled>
              <Icon name="check" />
              {T('save')}
            </button>
            <span className="msg" />
          </div>
          <div className="sec" style={{ marginTop: 16 }}>
            <Icon name="redo" color="var(--acc)" />
            {T('set_agent_update')}
          </div>
          <AgentPage headless />
        </div>
      </>
    )
  }

  const set = (key) => (value) => setForm((prev) => ({ ...prev, [key]: value }))

  const probeHint = T('set_pm_hint')
    .replace('{n}', Math.ceil(Math.max(5, Math.min(100, parseInt(form.probeMin, 10) || 0)) * probeSamples / 100))
    .replace('{c}', probeSamples)

  const save = async () => {
    const tuning = collectTuning(form)
    const bad = stepViolation(tuning, tuningSteps)
    if (bad) {
      setMessage('')
      alertBox(bad)
      return
    }
    setMessage(T('saving'))
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
    setMessage('')
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      return
    }
    alertBox(postError(r))
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
    const r = await apiPost('settings-set', body)
    if (r.ok && r.d.ok) {
      toast(T('set_saved'), 'ok')
      await load()
      return
    }
    toast(postError(r), 'err')
  }

  return (
    <>
      <PageHead icon="cog" titleKey="nav_settings" subKey="set_sub" />

      <div className="stpage">
        <div className="stgrid">
          <SettingsGroup icon="cog" titleKey="set_g1" chipKey="set_g1c" tone="sc-panel">
            <SettingRow
              label={T('set_on_ipchange')}
              helpKey="set_on_ipchange_d"
              exampleKey="set_x_ipchange"
            >
              <button type="button" className="setfield" onClick={() => setPicking(true)}>
                <span className="val">{modeLabel(mode)}</span>
                <span className="cv">
                  <Icon name="chev" />
                </span>
              </button>
            </SettingRow>

            <SettingRow label={T('set_rec_int')} helpKey="set_rec_range" exampleKey="set_x_rec">
              <NumberField value={form.reconcile} onChange={set('reconcile')} min={5} max={3600} />
            </SettingRow>

            <SettingRow label={T('set_poll_int')} helpKey="set_poll_range" exampleKey="set_x_poll">
              <NumberField value={form.poll} onChange={set('poll')} min={0.3} max={60} step={0.1} />
            </SettingRow>

            <SettingRow label={T('set_ui_int')} helpKey="set_ui_range" exampleKey="set_x_ui">
              <NumberField value={form.ui} onChange={set('ui')} min={0.3} max={60} step={0.1} />
            </SettingRow>

            <SettingRow label={T('set_ech_int')} helpKey="set_ech_range" exampleKey="set_x_ech">
              <NumberField value={form.ech} onChange={set('ech')} min={0} max={1440} step={1} />
            </SettingRow>

            <SettingRow label={T('set_upwin')} helpKey="set_upwin_d" exampleKey="set_x_upwin">
              <Select
                items={WINDOW_OPTIONS.map((o) => ({ v: o.v, label: T(o.label) }))}
                value={form.window}
                onChange={set('window')}
              />
            </SettingRow>
          </SettingsGroup>

          <SettingsGroup icon="activity" titleKey="set_gkd" chipKey="set_gkdc" tone="sc-conn">
            <SettingRow
              label={T('set_t_probemin')}
              helpKey="set_t_probemin_d"
              exampleKey="set_x_probemin"
            >
              <NumberField value={form.probeMin} onChange={set('probeMin')} min={5} max={100} step={5} />
            </SettingRow>
            <p className="srnote">{probeHint}</p>

            <SettingRow label={T('set_t_revive')} helpKey="set_t_revive_d" exampleKey="set_x_revive">
              <TextField value={form.revive} onChange={set('revive')} />
            </SettingRow>
          </SettingsGroup>

          <SettingsGroup icon="redo" titleKey="set_g2" chipKey="set_g2c" tone="sc-pool">
            <SettingRow
              label={T('set_t_suspect')}
              helpKey="set_t_suspect_d"
              exampleKey="set_x_suspect"
            >
              <TextField value={form.suspect} onChange={set('suspect')} />
            </SettingRow>

            <SettingRow
              label={T('set_t_deadretest')}
              helpKey="set_t_deadretest_d"
              exampleKey="set_x_deadretest"
            >
              <NumberField value={form.deadRetest} onChange={set('deadRetest')} min={1} max={1440} step={1} />
            </SettingRow>
          </SettingsGroup>

          <SettingsGroup icon="bolt" titleKey="set_g5" chipKey="set_g5c" tone="sc-perf">
            <SettingRow
              label={T('set_t_sockbuf')}
              helpKey="set_t_sockbuf_d"
              exampleKey="set_x_sockbuf"
            >
              <NumberField value={form.sockBuf} onChange={set('sockBuf')} min={0} max={64} step={1} />
            </SettingRow>
          </SettingsGroup>

          <SettingsGroup icon="globe" titleKey="set_g6" chipKey="set_g6c" tone="sc-panel">
            <SettingRow label={T('set_api_on')} helpKey="set_api_on_d" exampleKey="set_x_api_on">
              <div className="srtgl">
                <div
                  className={'tglsw' + (form.apiOn ? ' on' : '')}
                  onClick={() => set('apiOn')(!form.apiOn)}
                />
              </div>
            </SettingRow>

            <SettingRow
              label={T('set_api_token')}
              helpKey="set_api_token_d"
              exampleKey="set_x_api_token"
            >
              <div className="srtoken">
                {token ? (
                  <CopyValue text={token} />
                ) : (
                  <span className="muted">{T('set_api_none')}</span>
                )}
                <button type="button" className="ghost" onClick={newToken}>
                  <Icon name="redo" />
                  {T('set_api_new')}
                </button>
              </div>
            </SettingRow>
          </SettingsGroup>
        </div>

        <p className="stnote">{T('set_apply_note')}</p>
        <div className="stsave">
          <button className="ghost" onClick={reset}>
            <Icon name="undo" />
            {T('set_reset')}
          </button>
          <button className="primary" onClick={save}>
            <Icon name="check" />
            {T('save')}
          </button>
          <span className="msg">{message}</span>
        </div>

        <div className="sec" style={{ marginTop: 16 }}>
          <Icon name="redo" color="var(--acc)" />
          {T('set_agent_update')}
        </div>
        <AgentPage headless />
      </div>

      {picking ? (
        <ModePicker
          value={mode}
          onPick={(next) => {
            setMode(next)
            setPicking(false)
          }}
          onClose={() => setPicking(false)}
        />
      ) : null}
    </>
  )
}
