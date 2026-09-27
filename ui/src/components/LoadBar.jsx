import { useEffect, useState } from 'react'
import { T } from '../i18n/fa.js'
import './loadbar.css'

const LEAVE_MS = 400

export default function LoadBar({ on, value }) {
  const [live, setLive] = useState(on)
  if (on && !live) setLive(true)

  useEffect(() => {
    if (on || !live) return undefined
    const t = setTimeout(() => setLive(false), LEAVE_MS)
    return () => clearTimeout(t)
  }, [on, live])

  if (!live) return null
  const p = on ? Math.min(Math.max(value || 0, 0), 1) : 1
  return (
    <div className="ldslot">
      <div
        className={'ldbar' + (on ? (p ? '' : ' wait') : ' done')}
        role="progressbar"
        aria-label={T('loading')}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(p * 100)}
      >
        <i style={{ transform: 'scaleX(' + p + ')' }} />
      </div>
    </div>
  )
}
