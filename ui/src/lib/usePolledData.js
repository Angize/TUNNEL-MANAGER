import { useCallback, useEffect, useRef, useState } from 'react'
import { setPageRefresh } from './poll.js'

export default function usePolledData(load, key) {
  const [data, setData] = useState(null)
  const alive = useRef(true)
  const loader = useRef(load)

  loader.current = load

  const reload = useCallback(async () => {
    let value
    try {
      value = await loader.current()
    } catch {
      return
    }
    if (alive.current && value !== undefined) setData(value)
  }, [])

  useEffect(() => {
    alive.current = true
    reload()
    const off = setPageRefresh(reload)
    return () => {
      alive.current = false
      off()
    }
  }, [reload, key])

  return [data, reload]
}
