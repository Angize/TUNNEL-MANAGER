import Icon from './Icon.jsx'
import useBusy from '../lib/useBusy.js'
import { T } from '../i18n/fa.js'

export default function LoadFail({ text, onRetry }) {
  const [busy, guard] = useBusy()
  return (
    <div className="card loadfail" role="alert">
      <span>{text}</span>
      <button type="button" className="ghost" disabled={busy} aria-busy={busy} onClick={guard(onRetry)}>
        {busy ? <span className="bspin ink sm" /> : <Icon name="redo" />}
        {T('retry')}
      </button>
    </div>
  )
}
