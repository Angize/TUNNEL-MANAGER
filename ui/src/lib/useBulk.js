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
  const shown = links.slice(0, NAMES_SHOWN).map((l) => '⁨' + l.name + '⁩').join('، ')
  const rest = links.length - NAMES_SHOWN
  return rest > 0 ? shown + T('bulk_more').replace('{n}', String(rest)) : shown
}

export default function useBulk({ list, checkRefs, onDone }) {
  const { waitDone } = useActs()
  const [selecting, setSelecting] = useState(false)
  const [picked, setPicked] = useState(() => new Set())
  const [run, setRun] = useState(null)
  const [sheet, setSheet] = useState(false)
  const stopRef = useRef(false)
  const runRef = useRef(false)
  const listRef = useRef(list)

  listRef.current = list
  const ids = (list || []).map((l) => l.id)
  const idsKey = ids.join(' ')

  useEffect(() => {
    const live = new Set(idsKey ? idsKey.split(' ') : [])
    setPicked((prev) => {
      const next = new Set([...prev].filter((id) => live.has(id)))
      return next.size === prev.size ? prev : next
    })
  }, [idsKey])

  const start = useCallback(() => {
    if (runRef.current) return
    closeAllCards()
    setPicked(new Set())
    setSelecting(true)
  }, [])

  const exit = useCallback(() => {
    setSelecting(false)
    setSheet(false)
    setPicked(new Set())
  }, [])

  const pick = useCallback((id) => {
    setPicked((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const allPicked = ids.length > 0 && ids.every((id) => picked.has(id))

  const pickAll = useCallback(() => {
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
      return w.ok ? '' : w.err
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

    exit()
    runRef.current = true
    stopRef.current = false
    let ok = 0
    let bad = 0
    let skipped = 0
    let firstErr = ''

    try {
      if (action.key === 'ping') {
        setRun({ key: action.key, i: 0, k })
        await Promise.all(
          links.map(async (link) => {
            const check = checkRefs.current[link.id]
            const res = check ? await check() : 'bad'
            if (res === 'ok') ok++
            else if (res === 'bad') bad++
            setRun((r) => r && { ...r, i: r.i + 1 })
          })
        )
      } else {
        for (let i = 0; i < k; i++) {
          if (stopRef.current) {
            skipped = k - i
            break
          }
          setRun({ key: action.key, i: i + 1, k })
          const err = await runOne(action, links[i])
          if (!err) ok++
          else {
            bad++
            if (!firstErr) firstErr = links[i].name + ': ' + err
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
    if (firstErr) msg += ' — ' + firstErr
    toast(msg, bad ? 'err' : 'ok')
    await onDone()
  }

  const stop = useCallback(() => {
    stopRef.current = true
  }, [])

  return {
    selecting,
    picked,
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
