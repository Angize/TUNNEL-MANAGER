import { useEffect, useRef, useState } from 'react'

export default function useScrub(count) {
  const [at, setAt] = useState(null)
  const hold = useRef(0)
  const last = count - 1

  useEffect(() => () => clearTimeout(hold.current), [])

  const pick = (e) => {
    if (!count) return
    const r = e.currentTarget.getBoundingClientRect()
    setAt(Math.min(last, Math.max(0, Math.floor(((e.clientX - r.left) / r.width) * count))))
  }
  const drop = () => {
    clearTimeout(hold.current)
    setAt(null)
  }

  return {
    at: at == null || !count ? null : Math.min(at, last),
    handlers: {
      onPointerDown: (e) => {
        clearTimeout(hold.current)
        pick(e)
      },
      onPointerMove: pick,
      onPointerUp: (e) => {
        if (e.pointerType === 'touch') hold.current = setTimeout(() => setAt(null), 2500)
      },
      onPointerCancel: drop,
      onPointerLeave: (e) => {
        if (e.pointerType !== 'touch') setAt(null)
      },
      onKeyDown: (e) => {
        if (e.key === 'Escape') {
          if (at != null) {
            e.stopPropagation()
            setAt(null)
          }
          return
        }
        const cur = at == null ? count : Math.min(at, last)
        const next = { ArrowLeft: cur - 1, ArrowDown: cur - 1, ArrowRight: cur + 1, ArrowUp: cur + 1, Home: 0, End: last }[
          e.key
        ]
        if (next == null || !count) return
        e.preventDefault()
        setAt(Math.min(last, Math.max(0, next)))
      },
      onBlur: () => setAt(null),
    },
  }
}
