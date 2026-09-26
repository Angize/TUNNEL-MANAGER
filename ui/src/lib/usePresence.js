import { useEffect, useState } from 'react'

export default function usePresence(show, exitMs) {
  const [shown, setShown] = useState(show)
  if (show && !shown) setShown(true)
  useEffect(() => {
    if (show || !shown) return undefined
    const timer = setTimeout(() => setShown(false), exitMs)
    return () => clearTimeout(timer)
  }, [show, shown, exitMs])
  return shown
}
