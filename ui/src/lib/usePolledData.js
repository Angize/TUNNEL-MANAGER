import { useCallback, useEffect, useRef, useState } from 'react'
import { setPageRefresh } from './poll.js'
import { sameDeep } from './sameDeep.js'

export default function usePolledData(load, key, active = true, onLoaded) {
  const [data, setData] = useState(null)
  const [progress, setProgress] = useState(0)
  const hasData = useRef(false)
  const alive = useRef(true)
  const latest = useRef(0)
  const loader = useRef(load)
  const loaded = useRef(onLoaded)
  const wasActive = useRef(active)

  loader.current = load
  loaded.current = onLoaded

  const reload = useCallback(async () => {
    const mine = ++latest.current
    const report = hasData.current
      ? undefined
      : (p) => {
          if (mine === latest.current) setProgress(p)
        }
    let value
    try {
      value = await loader.current(report)
    } catch {
      return
    }
    if (!alive.current || mine !== latest.current || value === undefined) return
    hasData.current = true
    setData((prev) => sameDeep(prev, value))
    if (loaded.current) loaded.current(value)
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

  return [data, reload, progress]
}
