import { useEffect, useState } from 'react'

export default function useSecondTick(active) {
  const [, setTick] = useState(0)

  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(() => setTick((n) => n + 1), 1000)
    return () => clearInterval(timer)
  }, [active])
}
