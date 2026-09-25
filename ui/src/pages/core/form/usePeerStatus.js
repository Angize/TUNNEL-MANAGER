import { useCallback, useEffect, useRef, useState } from 'react'
import { apiPost } from '../../../lib/api.js'
import { postError, readError } from '../../../lib/errors.js'
import { getUiInterval } from '../../../lib/poll.js'
import { toast } from '../../../lib/toast.js'
import { T } from '../../../i18n/fa.js'

const PENDING_MS = 12000
const RETEST_STEPS = [1200, 3000, 5500, 8000]
const SELECT_STEPS = [1200, 3000, 5500, 8000, 11000]

const EMPTY_SIDE = { active: '', addrs: [], live: {} }
const EMPTY = { dst: EMPTY_SIDE, src: EMPTY_SIDE, now: 0, polledMs: 0, stale: false, why: '' }

function applySide(section) {
  const live = {}
  for (const h of (section && section.health) || []) {
    if (!h || !h.key) continue
    live[h.key] = {
      state: String(h.state || 'healthy'),
      next: +h.next_retest_unix || 0,
      total: +h.retest_secs || 0,
    }
  }
  return {
    active: String((section && section.active) || ''),
    addrs: (((section && section.addrs) || [])).map(String),
    live,
  }
}

export default function usePeerStatus(lid) {
  const [status, setStatus] = useState(EMPTY)
  const [pending, setPending] = useState(null)
  const timers = useRef([])
  const alive = useRef(true)

  const tick = useCallback(async () => {
    if (!lid) return
    const r = await apiPost('peer-status', { id: lid })
    if (!alive.current) return
    if (r.ok && r.d.ok && !r.d.pool) return
    if (!(r.ok && r.d.ok) || r.d.error) {
      setStatus((prev) => ({ ...prev, stale: true, why: readError(r) }))
      return
    }
    setStatus({
      dst: applySide(r.d.dst),
      src: applySide(r.d.src),
      now: +r.d.now || Math.floor(Date.now() / 1000),
      polledMs: Date.now(),
      stale: false,
      why: '',
    })
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
    if (!lid) return () => {}
    let running = true
    let timer = null
    const loop = () => {
      Promise.resolve(tick()).finally(() => {
        if (running) timer = setTimeout(loop, getUiInterval())
      })
    }
    loop()
    return () => {
      running = false
      alive.current = false
      if (timer) clearTimeout(timer)
      for (const t of held) clearTimeout(t)
      held.length = 0
    }
  }, [lid, tick])

  useEffect(() => {
    if (!pending) return
    const side = status[pending.side] || EMPTY_SIDE
    if (side.active === pending.key) {
      setPending(null)
      toast(T('peer_moved'), 'ok')
    } else if (Date.now() - pending.ts > PENDING_MS) {
      setPending(null)
      toast(T('select_not_taken'), 'err')
    }
  }, [status, pending])

  const retest = useCallback(
    async (side, key) => {
      if (!lid) return
      const r = await apiPost('peer-retest-now', {
        id: lid,
        kind: side === 'src' ? 'src' : 'dst',
        key,
      })
      if (r.ok && r.d.ok) {
        toast(T('peer_probe_pulled'), 'ok')
        schedule(RETEST_STEPS)
      } else toast(postError(r), 'err')
    },
    [lid, schedule]
  )

  const select = useCallback(
    async (side, key) => {
      if (!lid || pending || !key) return
      setPending({ side, key, ts: Date.now() })
      const r = await apiPost('peer-select', { id: lid, side, key })
      if (r.ok && r.d.ok) {
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
