import { useCallback, useRef, useState } from 'react'

export default function useBusy() {
  const [busy, setBusy] = useState(false)
  const running = useRef(false)

  const guard = useCallback(
    (fn) => async () => {
      if (running.current) return
      running.current = true
      setBusy(true)
      try {
        await fn()
      } finally {
        running.current = false
        setBusy(false)
      }
    },
    []
  )

  return [busy, guard]
}
