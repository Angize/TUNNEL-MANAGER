import { lazy, Suspense, useEffect, useState } from 'react'
import Icon from '../../components/Icon.jsx'
import CopyValue from '../../components/CopyValue.jsx'
import { ApiCardSkeleton } from '../../components/Skeleton.jsx'
import SaveDock from './SaveDock.jsx'
import FormGate from './FormGate.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'
import { checkable } from '../../lib/keys.js'

const ApiRef = lazy(() => import('./ApiRef.jsx'))

function ApiGroup({ f }) {
  const { form, set, token } = f

  return (
    <div className="card opc sc-panel apcard">
      <div className="ophd">
        <span className="sgt">
          <Icon name="globe" />
        </span>
        <div className="hd2">
          <b>{T('set_api_title')}</b>
          <small>{T('set_api_card_sub')}</small>
        </div>
        <div
          className={'tglsw' + (form.apiOn ? ' on' : '')}
          aria-label={T('set_api_on')}
          {...checkable('switch', form.apiOn, () => set('apiOn')(!form.apiOn))}
        />
      </div>
      <div className="oprow">
        {token ? (
          <CopyValue key={token} text={token} className="aptok" />
        ) : (
          <div className="aptok">
            <Icon name="lock" />
            {T('set_api_hidden')}
          </div>
        )}
        <button type="button" className="ghost tone tone-renew opfit" onClick={f.newToken}>
          <Icon name="redo" />
          {T('set_api_new')}
        </button>
      </div>
      {token ? <div className="aponce">{T('set_api_once')}</div> : null}
    </div>
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
      {f.form ? <ApiGroup f={f} /> : <FormGate skeleton={<ApiCardSkeleton />} />}

      {seen ? (
        <Suspense fallback={<div className="card muted">{T('loading')}</div>}>
          <ApiRef />
        </Suspense>
      ) : null}

      <SaveDock show={active && !!f.dirty} count={f.dirty} busy={f.busy} onRevert={f.revert} onSave={f.save} />
    </div>
  )
}
