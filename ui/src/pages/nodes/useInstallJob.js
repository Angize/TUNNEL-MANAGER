import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, apiGet, apiPost } from '../../lib/api.js'
import { postError, readError } from '../../lib/errors.js'
import { MAX_POLL_FAILURES } from '../../lib/poll.js'
import { T } from '../../i18n/fa.js'

const TICK_MS = 150
const POLL_MS = 380
const MIN_SPIN_MS = 600

export async function forgetInstallKey(job) {
  const response = await apiPost('install-forget-key', { job })
  return response.ok && response.d.ok ? '' : postError(response)
}

function now() {
  return window.performance && performance.now ? performance.now() : Date.now()
}

export default function useInstallJob({ onFinished }) {
  const [state, setState] = useState(null)
  const job = useRef(null)
  const timer = useRef(0)
  const onFinishedRef = useRef(onFinished)

  onFinishedRef.current = onFinished

  const stop = useCallback(() => {
    if (job.current) job.current.cancelled = true
    clearTimeout(timer.current)
    timer.current = 0
    job.current = null
  }, [])

  useEffect(() => stop, [stop])

  const poll = useCallback((c) => {
    apiGet('install-status?job=' + encodeURIComponent(c.job))
      .then((d) => {
        c.polling = false
        c.failures = 0
        c.steps = d.steps
        c.transfer = d.transfer
        if (d.banner) c.banner = d.banner
        c.done = !!d.done
        c.success = !!d.success
        c.hostkey = !!d.hostkey
      })
      .catch((e) => {
        c.polling = false
        if (e instanceof ApiError && e.status === 400) {
          c.error = readError(e)
          c.done = true
          c.success = false
          return
        }
        c.failures++
        if (c.failures >= MAX_POLL_FAILURES) {
          c.error = T('inst_panel_lost')
          c.resume = true
          c.done = true
          c.success = false
        }
      })
  }, [])

  const publish = useCallback((c) => {
    setState({
      job: c.job,
      hostkey: c.hostkey,
      steps: c.steps,
      resume: !!c.resume,
      revealIdx: c.revealIdx,
      banner: c.banner,
      error: c.error,
      success: c.success,
      finished: c.finished,
    })
  }, [])

  const tick = useCallback(() => {
    const c = job.current
    if (!c || c.cancelled) return

    const t = now()
    if (!c.done && !c.polling && t - c.lastPoll >= POLL_MS) {
      c.polling = true
      c.lastPoll = t
      poll(c)
    }

    let started = 0
    for (let i = 0; i < c.steps.length; i++) {
      if (c.steps[i].state !== 'wait') started = i + 1
    }
    const current = c.steps[c.revealIdx - 1]?.state
    const currentTerminal = current === 'ok' || current === 'err' || current === 'warn'

    if (c.revealIdx < started && t - c.lastReveal >= MIN_SPIN_MS && currentTerminal) {
      c.revealIdx++
      c.lastReveal = t
    }

    if (
      !c.finished &&
      c.done &&
      (c.error || c.revealIdx >= started) &&
      t - c.lastReveal >= MIN_SPIN_MS &&
      (started > 0 || c.error)
    ) {
      c.finished = true
      publish(c)
      clearTimeout(timer.current)
      job.current = null
      onFinishedRef.current(c.success, c.banner, c.transfer)
      return
    }

    publish(c)
    timer.current = setTimeout(tick, TICK_MS)
  }, [poll, publish])

  const start = useCallback(
    (jobId, previous) => {
      stop()
      job.current = {
        job: jobId,
        steps: previous?.steps || [],
        banner: T('inst_installing'),
        done: false,
        success: false,
        hostkey: false,
        error: '',
        revealIdx: previous?.revealIdx || 1,
        lastReveal: now(),
        lastPoll: 0,
        polling: false,
        failures: 0,
        finished: false,
        cancelled: false,
      }
      tick()
    },
    [stop, tick]
  )

  const reset = useCallback(() => {
    stop()
    setState(null)
  }, [stop])

  return { state, start, reset }
}
