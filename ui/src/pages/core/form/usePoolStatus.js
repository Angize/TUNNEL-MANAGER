import { useCallback, useEffect, useRef, useState } from 'react'
import { apiPost } from '../../../lib/api.js'
import { postError, readError } from '../../../lib/errors.js'
import { getUiInterval } from '../../../lib/poll.js'
import { toast } from '../../../lib/toast.js'
import { T } from '../../../i18n/fa.js'

const PENDING_MS = 12000
const RETEST_STEPS = [1200, 3000, 5500, 8000]
const SELECT_STEPS = [1200, 3000, 5500, 8000, 11000]

const EMPTY = { act: { ip: '', sni: '' }, live: {}, now: 0, polledMs: 0, stale: false, why: '' }

function applyStatus(reply) {
  const pair = reply.pair || {}
  const act = { ip: '', sni: '' }
  if (pair.low_kind) act[pair.low_kind] = String(pair.low || '')
  if (pair.high_kind) act[pair.high_kind] = String(pair.high || '')
  const live = {}
  for (const h of reply.health || []) {
    if (!h || !h.key) continue
    live[(h.kind === 'sni' ? 'sni' : 'ip') + ':' + h.key] = {
      state: String(h.state || 'healthy'),
      next: +h.next_retest_unix || 0,
      fails: +h.fails || 0,
    }
  }
  return {
    act,
    live,
    now: +reply.now || Math.floor(Date.now() / 1000),
    polledMs: Date.now(),
    stale: false,
    why: '',
  }
}

export default function usePoolStatus(lid, enabled) {
  const [status, setStatus] = useState(EMPTY)
  const [pending, setPending] = useState(null)
  const timers = useRef([])
  const alive = useRef(true)

  const tick = useCallback(async () => {
    if (!lid) return
    const r = await apiPost('edge-status', { id: lid })
    if (!alive.current) return
    if (r.ok && r.d.ok && r.d.pool && !r.d.error) setStatus(applyStatus(r.d))
    else setStatus((prev) => ({ ...prev, stale: true, why: readError(r) }))
  }, [lid])

  const schedule = useCallback(
    (steps) => {
      for (const ms of steps) timers.current.push(setTimeout(tick, ms))
    },
    [tick]
  )

  useEffect(() => {
    alive.current = true
    const held = timers.current
    if (!lid || !enabled) return () => {}
    let timer = null
    const loop = () => {
      Promise.resolve(tick()).finally(() => {
        if (alive.current) timer = setTimeout(loop, getUiInterval())
      })
    }
    loop()
    return () => {
      alive.current = false
      if (timer) clearTimeout(timer)
      for (const t of held) clearTimeout(t)
      held.length = 0
    }
  }, [lid, enabled, tick])

  useEffect(() => {
    if (!pending) return
    if (status.act[pending.kind] === pending.key || Date.now() - pending.ts > PENDING_MS) {
      setPending(null)
    }
  }, [status, pending])

  const retest = useCallback(
    async (kind, key) => {
      if (!lid) {
        toast(T('pool_make_first'), 'err')
        return
      }
      const r = await apiPost('pool-retest-now', { id: lid, kind, key })
      if (r.ok && r.d.ok) {
        toast(T('peer_probe_pulled'), 'ok')
        schedule(RETEST_STEPS)
      } else toast(postError(r), 'err')
    },
    [lid, schedule]
  )

  const select = useCallback(
    async (kind, key) => {
      if (!lid) {
        toast(T('pool_make_first'), 'err')
        return
      }
      if (pending) return
      setPending({ kind, key, ts: Date.now() })
      const r = await apiPost('pool-select', { id: lid, kind, key })
      if (r.ok && r.d.ok) {
        toast(T('pool_edge_active'), 'ok')
        schedule(SELECT_STEPS)
        return
      }
      setPending(null)
      toast(postError(r), 'err')
    },
    [lid, pending, schedule]
  )

  return { status, pending, retest, select }
}
