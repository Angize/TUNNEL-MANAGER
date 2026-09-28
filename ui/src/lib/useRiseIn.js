import { useLayoutEffect, useRef } from 'react'
import { CASCADE, riseIn } from './riseIn.js'

export default function useRiseIn(box, ready) {
  const done = useRef(false)

  useLayoutEffect(() => {
    if (done.current || !ready) return
    done.current = true
    if (box.current) riseIn([...box.current.querySelectorAll(CASCADE)])
  }, [box, ready])
}
