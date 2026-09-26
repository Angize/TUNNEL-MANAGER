import { useEffect, useState } from 'react'
import Icon from '../components/Icon.jsx'
import { T, TF } from '../i18n/fa.js'

export default function ConnBar({ lost, onRetry }) {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (!lost) return undefined
    setNow(Date.now())
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [lost])

  if (!lost) return null
  const text = lost.last
    ? TF('net_lost_s', { s: Math.max(0, Math.round((now - lost.last) / 1000)) })
    : T('net_lost_never')

  return (
    <div className="rdbar" role="alert">
      <Icon name="warn" />
      <div className="rdtx">
        <b>{T('net_lost_t')}</b>
        <span>{text}</span>
      </div>
      <button type="button" className="ghost" onClick={onRetry}>
        {T('net_retry')}
      </button>
    </div>
  )
}
