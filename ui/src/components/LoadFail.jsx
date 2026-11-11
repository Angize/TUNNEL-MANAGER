import { useState } from 'react'
import Icon from './Icon.jsx'
import useBusy from '../lib/useBusy.js'
import { T } from '../i18n/fa.js'

export default function LoadFail({ text, onRetry, inline }) {
  const [busy, guard] = useBusy()
  const [tries, setTries] = useState(0)
  const retry = guard(async () => {
    await onRetry()
    setTries((n) => n + 1)
  })
  return (
    <div className={(inline ? 'msg' : 'card') + ' loadfail'} role="alert">
      <span key={tries}>{text}</span>
      <button type="button" className="ghost" aria-disabled={busy || undefined} aria-busy={busy} onClick={retry}>
        {busy ? <span className="bspin ink sm" /> : <Icon name="redo" />}
        {T('retry')}
      </button>
    </div>
  )
}
