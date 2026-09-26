import { useEffect, useRef, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import Select from '../../components/Select.jsx'
import NumberInput from '../../components/NumberInput.jsx'
import Stepper from '../../components/Stepper.jsx'
import ListField from '../../components/ListField.jsx'
import SettingRow from './SettingRow.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import ModePicker, { modeLabel } from './ModePicker.jsx'
import SaveDock from './SaveDock.jsx'
import FormGate from './FormGate.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { FIELDS, fieldRange, fieldStep } from './tuning.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { T, TF } from '../../i18n/fa.js'

function ValueRow({ name, helpKey, exampleKey }) {
  const { form, set, touch, errors } = useSettingsForm()
  const config = useUiConfig()
  const spec = FIELDS[name]
  const list = spec.kind === 'list'
  const range = fieldRange(name, config)

  return (
    <SettingRow
      label={T(spec.labelKey)}
      helpKey={helpKey}
      exampleKey={exampleKey}
      unit={list || spec.stepper ? '' : T(spec.unitKey)}
      error={errors[name]}
      wide={list}
      half={spec.half}
    >
      {list ? (
        <ListField
          value={form[name]}
          range={range}
          placeholder={T(spec.unitKey)}
          onChange={(value) => {
            set(name)(value)
            touch(name)
          }}
        />
      ) : spec.stepper ? (
        <Stepper
          min={range[0]}
          max={range[1]}
          step={fieldStep(name, config)}
          unit={T(spec.unitKey)}
          value={form[name]}
          onChange={set(name)}
          onBlur={() => touch(name)}
        />
      ) : (
        <NumberInput
          className="search"
          kind={spec.kind}
          value={form[name]}
          onChange={set(name)}
          onBlur={() => touch(name)}
        />
      )}
    </SettingRow>
  )
}

export default function ValuesTab({ active }) {
  const f = useSettingsForm()
  const config = useUiConfig()
  const [picking, setPicking] = useState(false)
  const root = useRef(null)
  const shownTry = useRef(0)
  const { tried } = f

  useEffect(() => {
    if (tried === shownTry.current) return
    shownTry.current = tried
    const bad = active && root.current && root.current.querySelector('[aria-invalid="true"]')
    if (!bad) return
    bad.scrollIntoView({ block: 'center', behavior: 'smooth' })
    bad.focus({ preventScroll: true })
  }, [tried, active])

  if (!f.form) {
    return (
      <div className="stpage">
        <FormGate />
      </div>
    )
  }

  const { form, set, mode, setMode, probeSamples } = f
  const [probeLo, probeHi] = fieldRange('probeMin', config)
  const probePct = Math.max(probeLo, Math.min(probeHi, parseInt(form.probeMin, 10) || 0))
  const probeHint = TF('set_pm_hint', { n: Math.ceil((probePct * probeSamples) / 100), c: probeSamples })

  return (
    <div className="stpage" ref={root}>
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

          <ValueRow name="reconcile" helpKey="set_rec_range" exampleKey="set_x_rec" />
          <ValueRow name="poll" helpKey="set_poll_range" exampleKey="set_x_poll" />
          <ValueRow name="ui" helpKey="set_ui_range" exampleKey="set_x_ui" />
          <ValueRow name="ech" helpKey="set_ech_range" exampleKey="set_x_ech" />

          <SettingRow label={T('set_upwin')} helpKey="set_upwin_d" exampleKey="set_x_upwin">
            <Select
              items={config.uptime_windows.map((h) => ({ v: String(h), label: T('h' + h) }))}
              value={form.window}
              onChange={set('window')}
            />
          </SettingRow>
        </SettingsGroup>

        <SettingsGroup section icon="activity" titleKey="set_gkd" chipKey="set_gkdc" tone="sc-conn">
          <ValueRow name="probeMin" helpKey="set_t_probemin_d" exampleKey="set_x_probemin" />
          <p className="srnote">{probeHint}</p>

          <ValueRow name="revive" helpKey="set_t_revive_d" exampleKey="set_x_revive" />
        </SettingsGroup>

        <SettingsGroup section icon="redo" titleKey="set_g2" chipKey="set_g2c" tone="sc-pool">
          <ValueRow name="suspect" helpKey="set_t_suspect_d" exampleKey="set_x_suspect" />
          <ValueRow name="deadRetest" helpKey="set_t_deadretest_d" exampleKey="set_x_deadretest" />
        </SettingsGroup>

        <SettingsGroup section icon="bolt" titleKey="set_g5" chipKey="set_g5c" tone="sc-perf">
          <ValueRow name="sockBuf" helpKey="set_t_sockbuf_d" exampleKey="set_x_sockbuf" />
          <ValueRow name="tcpBuf" helpKey="set_t_tcpbuf_d" exampleKey="set_x_tcpbuf" />
        </SettingsGroup>
      </div>

      <div className="stfoot">
        <p className="stnote">{T('set_apply_note')}</p>
        <button className="ghost tone tone-renew" onClick={f.reset} disabled={f.busy}>
          <Icon name="reset" />
          {T('set_reset_all')}
        </button>
      </div>
      {active && f.dirty ? <SaveDock count={f.dirty} busy={f.busy} onRevert={f.revert} onSave={f.save} /> : null}

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
