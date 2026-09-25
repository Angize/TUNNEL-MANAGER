import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { MAX_POLL_FAILURES } from '../../lib/poll.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { T } from '../../i18n/fa.js'

const POLL_MS = 400
const SETTLE_MS = 4500
const RECOVER_MS = 5000
const JOB_ALL = '*'

export default function usePushJob({ onSettled }) {
  const [state, setState] = useState(null)
  const [seeded, setSeeded] = useState({})
  const job = useRef(null)
  const settle = useRef(0)
  const recover = useRef(0)
  const adoptRef = useRef(null)
  const alive = useRef(true)
  const onSettledRef = useRef(onSettled)

  onSettledRef.current = onSettled

  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
      window.clearTimeout(settle.current)
      window.clearInterval(recover.current)
    }
  }, [])

  useEffect(() => {
    document.body.classList.toggle('pushing', !!(state && !state.done))
    return () => document.body.classList.remove('pushing')
  }, [state])

  const poll = useCallback(async () => {
    let failures = 0
    let last = null
    try {
      for (;;) {
        let r = null
        try {
          r = await apiGet('push-status?job=' + encodeURIComponent(JOB_ALL) + '&_=' + Date.now())
        } catch {
          r = null
        }
        if (!alive.current) return
        if (!r) {
          failures += 1
          if (failures >= MAX_POLL_FAILURES) {
            toast(T('ag_p_lost'), 'err')
            window.clearInterval(recover.current)
            recover.current = window.setInterval(() => {
              if (!alive.current || job.current) {
                window.clearInterval(recover.current)
                return
              }
              if (adoptRef.current) adoptRef.current()
            }, RECOVER_MS)
            return
          }
        } else {
          failures = 0
          last = r
          setState(r)
          if (r.done) break
        }
        await new Promise((done) => setTimeout(done, POLL_MS))
      }
    } finally {
      job.current = null
    }
    if (!alive.current) return
    window.clearTimeout(settle.current)
    settle.current = window.setTimeout(() => {
      if (!alive.current || job.current) return
      onSettledRef.current()
      setSeeded({})
      if (last && Object.values(last.nodes || {}).some((n) => n.state === 'err')) return
      setState(null)
    }, SETTLE_MS)
  }, [])

  const adopt = useCallback(async () => {
    if (job.current) return
    let r
    try {
      r = await apiGet('push-status')
    } catch {
      return
    }
    if (r.done) return
    job.current = JOB_ALL
    window.clearTimeout(settle.current)
    setState(r)
    poll()
  }, [poll])

  adoptRef.current = adopt

  const start = useCallback(
    async (command, body, ids) => {
      window.clearTimeout(settle.current)
      setState((prev) => (prev && prev.done ? null : prev))
      setSeeded(Object.fromEntries((ids || []).map((id) => [id, true])))
      const res = await apiPost(command, body)
      if (!res.ok) {
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
    if (!(r.ok && r.d.ok)) toast(postError(r), 'err')
  }, [])

  const pause = useCallback(async (paused) => {
    if (!job.current) return
    const r = await apiPost('push-pause', { job: job.current, paused: !!paused })
    if (!(r.ok && r.d.ok)) {
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
