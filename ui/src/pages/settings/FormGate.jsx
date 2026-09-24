import Icon from '../../components/Icon.jsx'
import { SettingsSkeleton } from '../../components/Skeleton.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'

export default function FormGate() {
  const { loadError, load } = useSettingsForm()
  return (
    <div className="stpage">
      {loadError ? (
        <div className="card loadfail">
          <span>{T('set_load_fail') + ' ' + loadError}</span>
          <button className="ghost" onClick={load}>
            <Icon name="redo" />
            {T('retry')}
          </button>
        </div>
      ) : (
        <SettingsSkeleton />
      )}
    </div>
  )
}
