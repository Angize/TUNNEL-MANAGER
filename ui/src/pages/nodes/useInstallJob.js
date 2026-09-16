import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError, apiGet } from '../../lib/api.js'
import { readError } from '../../lib/errors.js'
import { MAX_POLL_FAILURES } from '../../lib/poll.js'
import { T } from '../../i18n/fa.js'

const TICK_MS = 150
const POLL_MS = 380
const MIN_SPIN_MS = 600

export function installSteps() {
  return [
    { label: T('inst_ssh'), detail: T('inst_connecting') },
    { label: T('inst_agent'), detail: T('inst_waiting') },
    { label: T('inst_service'), detail: T('inst_waiting') },
    { label: T('inst_register'), detail: T('inst_waiting') },
  ]
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
    apiGet('install-status?job=' + encodeURIComponent(c.job) + '&_=' + Date.now())
      .then((d) => {
        c.polling = false
        c.failures = 0
        c.steps = d.steps
        c.confirmed = c.steps.map((s) => s.state)
        if (d.banner) c.banner = d.banner
        c.done = !!d.done
        c.success = !!d.success
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
          c.done = true
          c.success = false
        }
      })
  }, [])

  const publish = useCallback((c) => {
    setState({
      steps: c.steps.slice(),
      confirmed: c.confirmed.slice(),
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
    for (let i = 0; i < c.confirmed.length; i++) {
      if (c.confirmed[i] && c.confirmed[i] !== 'wait') started = i + 1
    }
    const cur = c.revealIdx - 1
    const currentTerminal =
      cur < 0 || (c.confirmed[cur] && c.confirmed[cur] !== 'wait' && c.confirmed[cur] !== 'run')

    if (c.revealIdx < started && t - c.lastReveal >= MIN_SPIN_MS && currentTerminal) {
      c.revealIdx++
      c.lastReveal = t
    }

    if (
      !c.finished &&
      c.done &&
      c.revealIdx >= started &&
      t - c.lastReveal >= MIN_SPIN_MS &&
      (started > 0 || c.error)
    ) {
      c.finished = true
      publish(c)
      clearTimeout(timer.current)
      job.current = null
      onFinishedRef.current(c.success, c.banner)
      return
    }

    publish(c)
    timer.current = setTimeout(tick, TICK_MS)
  }, [poll, publish])

  const start = useCallback(
    (jobId) => {
      job.current = {
        job: jobId,
        steps: installSteps().map((s) => ({ label: s.label, detail: s.detail })),
        confirmed: ['run', 'wait', 'wait', 'wait'],
        banner: T('inst_installing'),
        done: false,
        success: false,
        error: '',
        revealIdx: 1,
        lastReveal: now(),
        lastPoll: 0,
        polling: false,
        failures: 0,
        finished: false,
        cancelled: false,
      }
      tick()
    },
    [tick]
  )

  const reset = useCallback(() => {
    stop()
    setState(null)
  }, [stop])

  return { state, start, stop, reset }
}
