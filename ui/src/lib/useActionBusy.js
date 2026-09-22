import { useCallback, useRef, useState } from 'react'

export default function useActionBusy() {
  const [busy, setBusy] = useState('')
  const running = useRef(false)

  const withBusy = useCallback(async (key, fn) => {
    if (running.current) return undefined
    running.current = true
    setBusy(key)
    try {
      return await fn()
    } finally {
      running.current = false
      setBusy('')
    }
  }, [])

  return [busy, withBusy]
}
