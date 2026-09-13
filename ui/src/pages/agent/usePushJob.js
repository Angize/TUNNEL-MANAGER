import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { T } from '../../i18n/fa.js'

const POLL_MS = 400
const MAX_FAILURES = 45
const SETTLE_MS = 4500
const JOB_ALL = '*'

export default function usePushJob({ onSettled }) {
  const [state, setState] = useState(null)
  const [seeded, setSeeded] = useState({})
  const job = useRef(null)
  const gen = useRef(0)
  const alive = useRef(true)
  const onSettledRef = useRef(onSettled)

  onSettledRef.current = onSettled

  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])

  useEffect(() => {
    document.body.classList.toggle('pushing', !!(state && !state.done))
    return () => document.body.classList.remove('pushing')
  }, [state])

  const poll = useCallback(async () => {
    const mine = gen.current
    let failures = 0
    let finished = false
    try {
      for (;;) {
        let r = null
        try {
          r = await apiGet('push-status?job=' + encodeURIComponent(JOB_ALL) + '&_=' + Date.now())
        } catch {
          r = null
        }
        if (!alive.current) return
        if (!r || !r.ok) {
          failures += 1
          if (failures >= MAX_FAILURES) {
            toast(T('ag_p_lost'), 'err')
            return
          }
        } else {
          failures = 0
          setState(r)
          if (r.done) {
            finished = true
            break
          }
        }
        await new Promise((done) => setTimeout(done, POLL_MS))
      }
    } finally {
      job.current = null
      if (alive.current && !finished) {
        setState(null)
        setSeeded({})
      }
    }
    setTimeout(() => {
      if (!alive.current) return
      onSettledRef.current()
      if (gen.current !== mine) return
      setState(null)
      setSeeded({})
    }, SETTLE_MS)
  }, [])

  const adopt = useCallback(async () => {
    if (job.current) return
    let r = null
    try {
      r = await apiGet('push-status')
    } catch {
      return
    }
    if (!r || !r.ok || r.idle || !r.job || r.done) return
    job.current = JOB_ALL
    gen.current += 1
    setState(r)
    poll()
  }, [poll])

  const start = useCallback(
    async (command, body, ids) => {
      gen.current += 1
      setState((prev) => (prev && prev.done ? null : prev))
      setSeeded(Object.fromEntries((ids || []).map((id) => [id, true])))
      const res = await apiPost(command, body)
      if (!(res.ok && res.d)) {
        setSeeded({})
        toast(postError(res), 'err')
        return
      }
      if (res.d.none) {
        setSeeded({})
        toast(T('ag_p_none'), 'ok')
        return
      }
      if (!res.d.job) {
        setSeeded({})
        toast(postError(res), 'err')
        return
      }
      if (job.current) return
      job.current = JOB_ALL
      await poll()
    },
    [poll]
  )

  const cancel = useCallback(async () => {
    if (!job.current) return
    if (!(await confirmBox(T('ag_p_cancel_q'), T('ag_p_cancel')))) return
    const r = await apiPost('push-cancel', { job: job.current })
    if (!(r.ok && r.d && r.d.ok)) toast(postError(r), 'err')
  }, [])

  const pause = useCallback(async (paused) => {
    if (!job.current) return
    const r = await apiPost('push-pause', { job: job.current, paused: !!paused })
    if (!(r.ok && r.d && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    setState((prev) => (prev ? { ...prev, paused: !!paused } : prev))
  }, [])

  return useMemo(
    () => ({ state, seeded, start, adopt, cancel, pause }),
    [state, seeded, start, adopt, cancel, pause]
  )
}
