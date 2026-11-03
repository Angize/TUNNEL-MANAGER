import { useEffect, useState } from 'react'

export default function useSecondTick() {
  const [, setTick] = useState(0)

  useEffect(() => {
    const timer = setInterval(() => setTick((n) => n + 1), 1000)
    return () => clearInterval(timer)
  }, [])
}
