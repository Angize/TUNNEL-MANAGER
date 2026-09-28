import { useLayoutEffect, useRef } from 'react'
import { EASE_OUT, reducedMotion } from '../lib/motion.js'

const DRAW_MS = 200
const WAIT_MS = 100

export default function KnobCheck({ on }) {
  const path = useRef(null)
  const was = useRef(on)

  useLayoutEffect(() => {
    const turnedOn = on && !was.current
    was.current = on
    if (!turnedOn || reducedMotion()) return
    path.current.animate([{ strokeDashoffset: 24 }, { strokeDashoffset: 0 }], {
      duration: DRAW_MS,
      delay: WAIT_MS,
      easing: EASE_OUT,
      fill: 'backwards',
    })
  }, [on])

  return (
    <svg className="tgck" viewBox="0 0 24 24" aria-hidden="true">
      <path ref={path} d="M20 6 9 17l-5-5" />
    </svg>
  )
}
