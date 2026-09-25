import Icon from '../../components/Icon.jsx'
import { SettingsSkeleton } from '../../components/Skeleton.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'

export default function FormGate({ skeleton }) {
  const { loadError, load } = useSettingsForm()
  if (!loadError) return skeleton || <SettingsSkeleton />
  return (
    <div className="card loadfail">
      <span>{T('set_load_fail') + ' ' + loadError}</span>
      <button className="ghost" onClick={load}>
        <Icon name="redo" />
        {T('retry')}
      </button>
    </div>
  )
}
