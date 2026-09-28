import { useCallback, useEffect, useRef, useState } from 'react'
import { setPageRefresh } from './poll.js'
import { sameDeep } from './sameDeep.js'

export default function usePolledData(load, key, active = true, onLoaded) {
  const [data, setData] = useState(null)
  const [progress, setProgress] = useState(0)
  const hasData = useRef(false)
  const first = useRef(null)
  const alive = useRef(true)
  const latest = useRef(0)
  const loader = useRef(load)
  const loaded = useRef(onLoaded)
  const keyNow = useRef(key)
  const wasActive = useRef(active)

  loader.current = load
  loaded.current = onLoaded
  keyNow.current = key

  const reload = useCallback(() => {
    const cold = !hasData.current
    if (cold && first.current && first.current.key === keyNow.current) return first.current.run
    const mine = ++latest.current
    const report = cold
      ? (p) => {
          if (mine === latest.current) setProgress(p)
        }
      : undefined
    if (report) setProgress(0)
    const run = (async () => {
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
    })()
    if (cold) {
      first.current = { key: keyNow.current, run }
      run.then(() => {
        if (first.current && first.current.run === run) first.current = null
      })
    }
    return run
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
