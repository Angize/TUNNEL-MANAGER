import Icon from '../components/Icon.jsx'
import { T } from '../i18n/fa.js'

export default function ReadinessBar({ readiness, onNavigate }) {
  if (!readiness || readiness.ok) return null

  const missing = []
  if (!readiness.agent) missing.push(T('rdy_agent'))
  if (!readiness.core) {
    missing.push(
      readiness.core_version
        ? T('rdy_core_arch').replace('{a}', (readiness.core_missing || []).join('، '))
        : T('rdy_core')
    )
  }

  return (
    <div className="rdbar">
      <Icon name="warn" />
      <div className="rdtx">
        <b>{T('rdy_title')}</b>
        <span>{missing.join(' · ') + ' — ' + T('rdy_why')}</span>
      </div>
      <button type="button" className="ghost" onClick={() => onNavigate('settings')}>
        {T('rdy_go')}
      </button>
    </div>
  )
}
