import LoadFail from '../../components/LoadFail.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import { T } from '../../i18n/fa.js'

export default function FormGate() {
  const { loadError, load } = useSettingsForm()
  if (!loadError) return null
  return <LoadFail text={T('set_load_fail') + ' ' + loadError} onRetry={load} />
}
