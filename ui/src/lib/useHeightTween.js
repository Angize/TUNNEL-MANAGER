import { useLayoutEffect, useRef } from 'react'
import { EASE_OUT, reducedMotion } from './motion.js'

const TWEEN_MS = 260

export default function useHeightTween(ref, key, on) {
  const was = useRef(0)

  useLayoutEffect(() => {
    const el = ref.current
    if (!el || !on) {
      was.current = 0
      return
    }
    const running = el.getAnimations().filter((a) => a.id === 'hgrow')
    const from = running.length ? parseFloat(getComputedStyle(el).height) : was.current
    running.forEach((a) => a.cancel())
    const to = el.offsetHeight
    was.current = to
    if (!from || Math.abs(from - to) < 1 || reducedMotion()) return
    const a = el.animate(
      [
        { height: from + 'px', overflow: 'hidden' },
        { height: to + 'px', overflow: 'hidden' },
      ],
      { duration: TWEEN_MS, easing: EASE_OUT }
    )
    a.id = 'hgrow'
  }, [ref, key, on])
}
