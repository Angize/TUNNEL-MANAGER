import { useCallback, useEffect, useRef, useState } from 'react'
import { confirmBox } from './dialog.js'
import { toast } from './toast.js'
import { closeAllCards } from './openCards.js'
import { registerCommand } from './pageCommand.js'
import { useActs } from '../state/ActsContext.jsx'
import { T } from '../i18n/fa.js'

const NAMES_SHOWN = 3

export const BULK_ACTIONS = [
  { key: 'ping', icon: 'activity', tone: 'ok' },
  { key: 'restart', icon: 'restart', tone: 'acc', coreOnly: true },
  { key: 'rebuild', icon: 'redo', tone: 'tx' },
  { key: 'reset', icon: 'reset', tone: 'gold' },
  { key: 'off', icon: 'plugoff', tone: 'bad', enabled: false },
  { key: 'on', icon: 'bolt', tone: 'ok', enabled: true },
]

const PING = BULK_ACTIONS.find((a) => a.key === 'ping')

export function bulkNames(links) {
  const shown = links.slice(0, NAMES_SHOWN).map((l) => '\u2068' + l.name + '\u2069').join('، ')
  const rest = links.length - NAMES_SHOWN
  return rest > 0 ? shown + T('bulk_more').replace('{n}', String(rest)) : shown
}

export default function useBulk({ list, command, onDone }) {
  const { waitDone } = useActs()
  const [selecting, setSelecting] = useState(false)
  const [picked, setPicked] = useState(() => new Set())
  const [run, setRun] = useState(null)
  const [sheet, setSheet] = useState(false)
  const stopRef = useRef(false)
  const runRef = useRef(false)
  const listRef = useRef(list)
  const actRefs = useRef({})
  const wanted = useRef(false)
  const pingAll = useRef(null)

  listRef.current = list
  const ids = (list || []).map((l) => l.id)
  const idsKey = ids.join(' ')
  const ready = list !== null

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

  const register = useCallback((id, fn) => {
    actRefs.current[id] = fn
  }, [])

  const allPicked = ids.length > 0 && ids.every((id) => picked.has(id))

  const pickAll = useCallback(() => {
    const every = (listRef.current || []).map((l) => l.id)
    setPicked((prev) => (every.length && every.every((id) => prev.has(id)) ? new Set() : new Set(every)))
  }, [])

  const cardAction = (link, name, arg) => {
    const fn = actRefs.current[link.id]
    return fn ? fn(name, arg) : Promise.resolve(undefined)
  }

  const runOne = async (action, link) => {
    const toggle = action.enabled !== undefined
    if (toggle && (link.enabled !== false) === action.enabled) return ''
    const res = await cardAction(link, toggle ? 'toggle' : action.key, action.enabled)
    if (res === undefined) return T('bulk_busy')
    if (typeof res === 'string') return res
    if (res.err) return res.err
    const w = await waitDone(res.act)
    return w.ok ? '' : w.err
  }

  const execute = async (action, links) => {
    const k = links.length
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
            const res = await cardAction(link, 'ping')
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
    await execute(action, links)
  }

  pingAll.current = () => {
    const links = listRef.current || []
    if (!links.length) {
      toast(T('no_tunnel_check'), 'err')
      return
    }
    if (!runRef.current) execute(PING, links)
  }

  useEffect(
    () =>
      registerCommand(command, () => {
        if (listRef.current === null) wanted.current = true
        else pingAll.current()
      }),
    [command]
  )

  useEffect(() => {
    if (!wanted.current || !ready) return
    wanted.current = false
    pingAll.current()
  }, [ready])

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
    register,
    stop,
    perform,
    openSheet: () => setSheet(true),
    closeSheet: () => setSheet(false),
  }
}
