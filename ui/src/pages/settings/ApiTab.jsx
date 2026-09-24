import { lazy, Suspense, useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import SettingRow from './SettingRow.jsx'
import SettingsGroup from './SettingsGroup.jsx'
import SaveDock from './SaveDock.jsx'
import FormGate from './FormGate.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'
import { checkable } from '../../lib/keys.js'

const ApiRef = lazy(() => import('./ApiRef.jsx'))
const GATE_GROUPS = [['sc-panel', 2]]

function ApiGroup({ f }) {
  const { form, set, token } = f

  return (
    <SettingsGroup icon="globe" titleKey="set_g6" chipKey="set_g6c" tone="sc-panel">
      <SettingRow label={T('set_api_on')} helpKey="set_api_on_d" exampleKey="set_x_api_on">
        <div className="srtgl">
          <div
            className={'tglsw' + (form.apiOn ? ' on' : '')}
            {...checkable('switch', form.apiOn, () => set('apiOn')(!form.apiOn))}
          />
        </div>
      </SettingRow>

      <SettingRow label={T('set_api_token')} helpKey="set_api_token_d" exampleKey="set_x_api_token">
        <div className="srtoken">
          {token ? (
            <>
              <CopyValue text={token} />
              <span className="srtonce">{T('set_api_once')}</span>
            </>
          ) : null}
          <button type="button" className="ghost" onClick={f.newToken}>
            <Icon name="redo" />
            {T('set_api_new')}
          </button>
        </div>
      </SettingRow>
    </SettingsGroup>
  )
}

export default function ApiTab({ active }) {
  const f = useSettingsForm()
  const [seen, setSeen] = useState(active)

  useEffect(() => {
    if (active) setSeen(true)
  }, [active])

  return (
    <div className="stpage">
      {f.form ? <ApiGroup f={f} /> : <FormGate groups={GATE_GROUPS} />}

      {seen ? (
        <Suspense fallback={<div className="card muted">{T('loading')}</div>}>
          <ApiRef />
        </Suspense>
      ) : null}

      {active && f.dirty ? <SaveDock count={f.dirty} busy={f.busy} onRevert={f.revert} onSave={f.save} /> : null}
    </div>
  )
}
