import { useCallback, useEffect, useRef, useState } from 'react'
import { apiPost } from './api.js'
import { postError } from './errors.js'
import { confirmBox } from './dialog.js'
import { toast } from './toast.js'
import { closeAllCards } from './openCards.js'
import { useActs } from '../state/ActsContext.jsx'
import { T } from '../i18n/fa.js'

const NAMES_SHOWN = 3

export const BULK_ACTIONS = [
  { key: 'ping', icon: 'activity', tone: 'ok' },
  { key: 'restart', icon: 'restart', tone: 'acc', coreOnly: true, endpoint: 'restart-link', act: true },
  { key: 'rebuild', icon: 'redo', tone: 'tx', endpoint: 'rebuild-link', act: true },
  { key: 'reset', icon: 'reset', tone: 'gold', endpoint: 'traffic-reset' },
  { key: 'off', icon: 'plugoff', tone: 'bad', endpoint: 'link-toggle', enabled: false },
  { key: 'on', icon: 'bolt', tone: 'ok', endpoint: 'link-toggle', enabled: true },
]

export function bulkNames(links) {
  const shown = links.slice(0, NAMES_SHOWN).map((l) => '\u2068' + l.name + '\u2069').join('، ')
  const rest = links.length - NAMES_SHOWN
  return rest > 0 ? shown + T('bulk_more').replace('{n}', String(rest)) : shown
}

export default function useBulk({ list, checkRefs, onDone }) {
  const { waitDone } = useActs()
  const [selecting, setSelecting] = useState(false)
  const [picked, setPicked] = useState(() => new Set())
  const [status, setStatus] = useState({})
  const [run, setRun] = useState(null)
  const [sheet, setSheet] = useState(false)
  const stopRef = useRef(false)
  const runRef = useRef(false)
  const listRef = useRef(list)

  listRef.current = list

  useEffect(() => {
    const live = new Set((list || []).map((l) => l.id))
    setPicked((prev) => {
      const next = new Set([...prev].filter((id) => live.has(id)))
      return next.size === prev.size ? prev : next
    })
  }, [list])

  const start = useCallback(() => {
    closeAllCards()
    setStatus({})
    setPicked(new Set())
    setSelecting(true)
  }, [])

  const exit = useCallback(() => {
    if (runRef.current) return
    setSelecting(false)
    setSheet(false)
    setPicked(new Set())
    setStatus({})
  }, [])

  const pick = useCallback((id) => {
    if (runRef.current) return
    setPicked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const ids = (list || []).map((l) => l.id)
  const allPicked = ids.length > 0 && ids.every((id) => picked.has(id))

  const pickAll = useCallback(() => {
    if (runRef.current) return
    const every = (listRef.current || []).map((l) => l.id)
    setPicked((prev) => (every.length && every.every((id) => prev.has(id)) ? new Set() : new Set(every)))
  }, [])

  const runOne = async (action, link) => {
    if (action.endpoint === 'link-toggle' && (link.enabled !== false) === action.enabled) return ''
    const body = action.endpoint === 'link-toggle' ? { id: link.id, enabled: action.enabled } : { id: link.id }
    const r = await apiPost(action.endpoint, body)
    if (action.act) {
      if (!(r.ok && r.d.act)) return postError(r)
      const w = await waitDone(r.d.act)
      return w.ok ? '' : w.err || T('bulk_st_fail')
    }
    return r.ok && r.d.ok ? '' : postError(r)
  }

  const perform = async (action) => {
    setSheet(false)
    const links = (listRef.current || []).filter((l) => picked.has(l.id))
    const k = links.length
    if (!k || runRef.current) return
    if (action.key !== 'ping') {
      const ask = T('bulk_q_' + action.key).replace('{k}', String(k)) + '\n' + bulkNames(links)
      if (!(await confirmBox(ask, T('bulk_yes_' + action.key)))) return
    }

    runRef.current = true
    stopRef.current = false
    const mark = (id, st, err) => setStatus((prev) => ({ ...prev, [id]: { st, err } }))
    setStatus(Object.fromEntries(links.map((l) => [l.id, { st: 'wait' }])))
    let ok = 0
    let bad = 0
    let skipped = 0

    try {
      if (action.key === 'ping') {
        setRun({ key: action.key, i: 0, k })
        await Promise.all(
          links.map(async (link) => {
            mark(link.id, 'run')
            const check = checkRefs.current[link.id]
            const res = check ? await check() : 'bad'
            if (res === 'ok') ok++
            else if (res !== 'off') bad++
            mark(link.id, res === 'ok' || res === 'off' ? res : 'bad')
            setRun((r) => r && { ...r, i: r.i + 1 })
          })
        )
      } else {
        for (let i = 0; i < k; i++) {
          const link = links[i]
          if (stopRef.current) {
            skipped++
            mark(link.id, 'skip')
            continue
          }
          setRun({ key: action.key, i: i + 1, k })
          mark(link.id, 'run')
          const err = await runOne(action, link)
          if (err) {
            bad++
            mark(link.id, 'fail', err)
          } else {
            ok++
            mark(link.id, 'done')
          }
        }
      }
    } finally {
      runRef.current = false
      setRun(null)
    }

    let msg = T(action.key === 'ping' ? 'bulk_ping_done' : 'bulk_done')
      .replace('{a}', T('bulk_t_' + action.key))
      .replace('{ok}', String(ok))
      .replace('{k}', String(k))
    if (bad && action.key !== 'ping') msg += T('bulk_bad').replace('{n}', String(bad))
    if (skipped) msg += T('bulk_skip').replace('{n}', String(skipped))
    toast(msg, bad ? 'err' : 'ok')
    await onDone()
  }

  const stop = useCallback(() => {
    stopRef.current = true
  }, [])

  return {
    selecting,
    picked,
    status,
    run,
    sheet,
    allPicked,
    count: ids.length,
    start,
    exit,
    pick,
    pickAll,
    stop,
    perform,
    openSheet: () => setSheet(true),
    closeSheet: () => setSheet(false),
  }
}
