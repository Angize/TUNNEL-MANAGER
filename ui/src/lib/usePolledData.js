import { useCallback, useEffect, useRef, useState } from 'react'
import { setPageRefresh } from './poll.js'

export default function usePolledData(load, key, active = true) {
  const [data, setData] = useState(null)
  const alive = useRef(true)
  const loader = useRef(load)
  const wasActive = useRef(active)

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
    return () => {
      alive.current = false
    }
  }, [reload, key])

  useEffect(() => {
    if (active && !wasActive.current) reload()
    wasActive.current = active
    if (!active) return undefined
    return setPageRefresh(reload)
  }, [reload, active])

  return [data, reload]
}
