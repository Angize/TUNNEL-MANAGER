import { useCallback, useRef, useState } from 'react'

export function useActionBusy() {
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

export default function useBusy() {
  const [busy, withBusy] = useActionBusy()
  const guard = useCallback((fn) => () => withBusy('run', fn), [withBusy])
  return [!!busy, guard]
}
