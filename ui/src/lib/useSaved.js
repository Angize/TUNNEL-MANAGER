import { useCallback, useEffect, useRef, useState } from 'react'

const SAVED_MS = 550

export default function useSaved() {
  const [saved, setSaved] = useState('')
  const alive = useRef(true)

  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])

  const markSaved = useCallback((text) => {
    setSaved(text)
    return new Promise((resolve) => setTimeout(() => resolve(alive.current), SAVED_MS))
  }, [])

  return [saved, markSaved]
}
