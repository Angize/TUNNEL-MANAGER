import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import { apiGet, apiPost } from '../lib/api.js'
import { postError } from '../lib/errors.js'
import { toast } from '../lib/toast.js'
import { actSeen } from '../lib/acts.js'
import { num } from '../lib/num.js'
import { T } from '../i18n/fa.js'

const ActsContext = createContext(null)

const EMPTY = {
  acts: {},
  now: 0,
  buildCount: 0,
  actFor: () => null,
  pendingFor: () => [],
  dismiss: () => {},
  cancel: async () => {},
  refresh: async () => {},
  waitAccepted: async () => ({ ok: true }),
}

const ACCEPT_TIMEOUT_MS = 45000
const ACCEPT_POLL_MS = 280

function runningBuilds(acts) {
  let n = 0
  for (const key of Object.keys(acts)) {
    if (key.startsWith('new:') && acts[key].state === 'run') n++
  }
  return n
}

export function ActsProvider({ children }) {
  const [state, setState] = useState({ acts: {}, now: 0, buildCount: 0 })
  const dismissed = useRef({})
  const [dismissTick, setDismissTick] = useState(0)

  const refresh = useCallback(async () => {
    let r
    try {
      r = await apiGet('acts')
    } catch {
      return
    }
    setState({ acts: r.acts, now: num(r.now), buildCount: runningBuilds(r.acts) })
  }, [])

  const isLive = useCallback(
    (act) => !!act && !dismissed.current[actSeen(act)],
    []
  )

  const actFor = useCallback(
    (linkId) => {
      const act = state.acts['link:' + linkId]
      return isLive(act) ? act : null
    },
    [state.acts, isLive]
  )

  const pendingFor = useCallback(
    (page) => {
      const out = []
      for (const key of Object.keys(state.acts)) {
        const act = state.acts[key]
        if (!key.startsWith('new:')) continue
        if (act.page !== page || act.state === 'done') continue
        if (isLive(act)) out.push(act)
      }
      return out.sort((a, b) => num(a.started) - num(b.started))
    },
    [state.acts, isLive]
  )

  const dismiss = useCallback((seen) => {
    dismissed.current[seen] = true
    setDismissTick((n) => n + 1)
  }, [])

  const cancel = useCallback(
    async (key) => {
      const r = await apiPost('act-cancel', { act: key })
      if (!(r.ok && r.d.ok)) toast(postError(r), 'err')
      await refresh()
    },
    [refresh]
  )

  const waitAccepted = useCallback(async (key, stillMounted) => {
    const end = Date.now() + ACCEPT_TIMEOUT_MS
    while (Date.now() < end) {
      if (stillMounted && !stillMounted()) return { gone: true }
      let r = null
      try {
        r = await apiGet('acts')
      } catch {
        r = null
      }
      if (r) {
        setState({ acts: r.acts, now: num(r.now), buildCount: runningBuilds(r.acts) })
        const act = r.acts[key]
        if (!act) return { err: T('act_lost') }
        if (act.state === 'fail') return { err: act.err }
        if (act.state === 'cancel') return { cancelled: true }
        if (act.state === 'done' || num(act.si) >= 1) return { ok: true }
      }
      await new Promise((done) => setTimeout(done, ACCEPT_POLL_MS))
    }
    return { ok: true }
  }, [])

  const value = useMemo(
    () => ({
      acts: state.acts,
      now: state.now,
      buildCount: state.buildCount,
      actFor,
      pendingFor,
      dismiss,
      cancel,
      refresh,
      waitAccepted,
      dismissTick,
    }),
    [state, actFor, pendingFor, dismiss, cancel, refresh, waitAccepted, dismissTick]
  )

  return <ActsContext.Provider value={value}>{children}</ActsContext.Provider>
}

export function useActs() {
  return useContext(ActsContext) || EMPTY
}
