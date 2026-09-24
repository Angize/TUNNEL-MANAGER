import { useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Select from '../../components/Select.jsx'
import SettingRow from './SettingRow.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import ModePicker, { modeLabel } from './ModePicker.jsx'
import SaveDock from './SaveDock.jsx'
import FormGate from './FormGate.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'

const WINDOW_OPTIONS = [
  { v: '1', label: 'h1' },
  { v: '3', label: 'h3' },
  { v: '6', label: 'h6' },
  { v: '8', label: 'h8' },
  { v: '12', label: 'h12' },
  { v: '24', label: 'h24' },
]

function NumberField({ value, onChange, min, max, step }) {
  return (
    <input
      className="search"
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

export default function ValuesTab({ active }) {
  const f = useSettingsForm()
  const [picking, setPicking] = useState(false)

  if (!f.form) {
    return (
      <div className="stpage">
        <FormGate />
      </div>
    )
  }

  const { form, set, mode, setMode, probeSamples } = f
  const probeHint = T('set_pm_hint')
    .replace('{n}', Math.ceil(Math.max(5, Math.min(100, parseInt(form.probeMin, 10) || 0)) * probeSamples / 100))
    .replace('{c}', probeSamples)

  return (
    <div className="stpage">
      <div className="card sg">
        <SettingsGroup section icon="cog" titleKey="set_g1" chipKey="set_g1c" tone="sc-panel">
          <SettingRow label={T('set_on_ipchange')} helpKey="set_on_ipchange_d" exampleKey="set_x_ipchange">
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

        <SettingsGroup section icon="activity" titleKey="set_gkd" chipKey="set_gkdc" tone="sc-conn">
          <SettingRow label={T('set_t_probemin')} helpKey="set_t_probemin_d" exampleKey="set_x_probemin">
            <NumberField value={form.probeMin} onChange={set('probeMin')} min={5} max={100} step={5} />
          </SettingRow>
          <p className="srnote">{probeHint}</p>

          <SettingRow label={T('set_t_revive')} helpKey="set_t_revive_d" exampleKey="set_x_revive">
            <TextField value={form.revive} onChange={set('revive')} />
          </SettingRow>
        </SettingsGroup>

        <SettingsGroup section icon="redo" titleKey="set_g2" chipKey="set_g2c" tone="sc-pool">
          <SettingRow label={T('set_t_suspect')} helpKey="set_t_suspect_d" exampleKey="set_x_suspect">
            <TextField value={form.suspect} onChange={set('suspect')} />
          </SettingRow>

          <SettingRow label={T('set_t_deadretest')} helpKey="set_t_deadretest_d" exampleKey="set_x_deadretest">
            <NumberField value={form.deadRetest} onChange={set('deadRetest')} min={1} max={1440} step={1} />
          </SettingRow>
        </SettingsGroup>

        <SettingsGroup section icon="bolt" titleKey="set_g5" chipKey="set_g5c" tone="sc-perf">
          <SettingRow label={T('set_t_sockbuf')} helpKey="set_t_sockbuf_d" exampleKey="set_x_sockbuf">
            <NumberField value={form.sockBuf} onChange={set('sockBuf')} min={0} max={64} step={1} />
          </SettingRow>
        </SettingsGroup>
      </div>

      <p className="stnote">{T('set_apply_note')}</p>
      {active && f.dirty ? <SaveDock count={f.dirty} busy={f.busy} onRevert={f.revert} onSave={f.save} /> : null}
      <div className="stdefaults">
        <button className="ghost" onClick={f.reset} disabled={f.busy}>
          <Icon name="reset" />
          {T('set_reset_all')}
        </button>
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
    </div>
  )
}
