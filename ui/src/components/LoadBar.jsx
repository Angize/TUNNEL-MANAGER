import { useLayoutEffect, useRef, useState } from 'react'
import { T } from '../i18n/fa.js'
import './loadbar.css'

const LEAVE_MS = 400
const SHOW_MS = 160

export default function LoadBar({ on, value }) {
  const [live, setLive] = useState(on)
  const since = useRef(0)
  if (on && !live) setLive(true)

  useLayoutEffect(() => {
    if (on) {
      if (!since.current) since.current = performance.now()
      return undefined
    }
    const early = !since.current || performance.now() - since.current < SHOW_MS
    since.current = 0
    if (!live) return undefined
    if (early) {
      setLive(false)
      return undefined
    }
    const t = setTimeout(() => setLive(false), LEAVE_MS)
    return () => clearTimeout(t)
  }, [on, live])

  if (!live) return null
  const p = on ? Math.min(Math.max(value || 0, 0), 1) : 1
  const wait = on && !p
  return (
    <div className="ldslot">
      <div
        className={'ldbar' + (on ? (wait ? ' wait' : '') : ' done')}
        role="progressbar"
        aria-label={T('loading')}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={wait ? undefined : Math.round(p * 100)}
      >
        <i style={wait ? undefined : { transform: 'scaleX(' + p + ')' }} />
      </div>
    </div>
  )
}
