import Icon from '../../components/Icon.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'

export default function FormGate() {
  const { loadError, load } = useSettingsForm()
  if (!loadError) return null
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
