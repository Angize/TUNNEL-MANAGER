import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import LoadBar from '../../components/LoadBar.jsx'
import useRiseIn from '../../lib/useRiseIn.js'
import { onScreen, stepFor } from '../../lib/riseIn.js'
import Reveal from '../../components/Reveal.jsx'
import LogEvent from './LogEvent.jsx'
import LogFiltersPanel from './LogFiltersPanel.jsx'
import useHiddenTypes from './useHiddenTypes.js'
import { eventKey } from './logFormat.js'
import { T } from '../../i18n/fa.js'
import { apiGet, apiPost } from '../../lib/api.js'
import { postError } from '../../lib/errors.js'
import { confirmBox } from '../../lib/dialog.js'
import { toast } from '../../lib/toast.js'
import { setLS } from '../../lib/storage.js'
import { setPageRefresh } from '../../lib/poll.js'
import { reducedMotion } from '../../lib/motion.js'
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import './logs.css'

const PAGE_SIZE = 200
const SEEN_KEY = 'tnl_logs_seen'
const BORN_STEP_MS = 40
const BORN_SPAN_MS = 200
const BORN_MS = 600
const NO_BORN = new Set()

function idKey(id) {
  const [a, b] = String(id || '').split('-')
  return [Number(a) || 0, Number(b) || 0]
}

function idAfter(a, b) {
  return a[0] > b[0] || (a[0] === b[0] && a[1] > b[1])
}

function newestId(events, start) {
  let top = start
  for (const e of events) {
    const k = idKey(e.id)
    if (idAfter(k, top)) top = k
  }
  return top
}

export default function LogsPage() {
  const { ev_types: evTypes, ev_groups: evGroups } = useUiConfig()
  const { evSeq, logCount, loaded } = useSummary()

  const [events, setEvents] = useState(null)
  const [progress, setProgress] = useState(0)
  const [hiddenOut, setHiddenOut] = useState(0)
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [show, setShow] = useState(PAGE_SIZE)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [openIds, setOpenIds] = useState({})
  const [born, setBorn] = useState(NO_BORN)
  const [kbFilters, setKbFilters] = useState(false)
  const [clearing, setClearing] = useState(false)
  const newest = useRef(null)
  const listBox = useRef(null)
  const signature = useRef('')
  const flight = useRef(null)

  useRiseIn(listBox, events !== null)

  const loadRef = useRef(() => {})

  const refetch = useCallback(() => {
    flight.current = null
    signature.current = ''
    loadRef.current()
  }, [])

  const { hidden, hiddenCount, known, adoptFromServer, isPending, toggleType, toggleGroup } =
    useHiddenTypes({ evTypes, onSaved: refetch })

  const load = useCallback(async () => {
    const sig = evSeq + ':' + logCount
    if (sig === signature.current || flight.current) return
    const mine = {}
    flight.current = mine
    let r = null
    try {
      r = await apiGet('events', newest.current ? undefined : setProgress)
    } catch {
      r = null
    }
    if (flight.current !== mine) return
    flight.current = null
    if (!r) return
    signature.current = sig
    const before = newest.current
    newest.current = newestId(r.events, before || [0, 0])
    if (before) {
      const fresh = r.events.filter((e) => idAfter(idKey(e.id), before))
      if (fresh.length) setBorn(new Set(fresh))
    }
    setEvents(r.events)
    setHiddenOut(r.hidden_out)
    if (!isPending()) adoptFromServer(r.hidden)
  }, [evSeq, logCount, adoptFromServer, isPending])

  loadRef.current = load

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => setPageRefresh(() => loadRef.current()), [])

  useEffect(() => {
    if (loaded) setLS(SEEN_KEY, String(evSeq))
  }, [evSeq, loaded])

  useEffect(() => {
    setShow(PAGE_SIZE)
  }, [filter, query])

  useEffect(() => {
    if (!born.size) return undefined
    const timer = setTimeout(() => setBorn(NO_BORN), BORN_MS)
    return () => clearTimeout(timer)
  }, [born])

  useLayoutEffect(() => {
    if (!born.size || !listBox.current) return
    const rows = [...listBox.current.querySelectorAll('.loglist > .lev-new')].filter(onScreen)
    const step = stepFor(rows.length, BORN_STEP_MS, BORN_SPAN_MS)
    rows.forEach((el, i) => el.style.setProperty('--d', Math.round(i * step) + 'ms'))
  }, [born])

  const keys = useMemo(() => {
    const list = events || []
    const map = new Map()
    const seen = {}
    for (let i = list.length - 1; i >= 0; i--) {
      const base = eventKey(list[i])
      const n = seen[base] || 0
      seen[base] = n + 1
      map.set(list[i], n ? base + '-' + n : base)
    }
    return map
  }, [events])

  const q = query.trim().toLowerCase()

  const found = useMemo(() => {
    const list = events || []
    if (!q) return list
    return list.filter((e) => ((e.text || '') + ' ' + (e.detail || '')).toLowerCase().includes(q))
  }, [events, q])

  const counts = useMemo(() => {
    const c = { all: found.length, err: 0 }
    for (const [group] of evGroups) c[group] = 0
    for (const e of found) {
      if (c[e.cat] != null) c[e.cat]++
      if (e.level === 'bad') c.err++
    }
    return c
  }, [found, evGroups])

  const visible = useMemo(
    () =>
      found.filter((e) =>
        filter === 'all' ? true : filter === 'err' ? e.level === 'bad' : e.cat === filter
      ),
    [found, filter]
  )

  const clearLogs = async () => {
    if (!(await confirmBox(T('logs_clear_confirm'), T('logs_clear')))) return
    setClearing(true)
    try {
      const r = await apiPost('events-clear', {})
      if (!(r.ok && r.d.ok)) {
        toast(postError(r), 'err')
        return
      }
      const list = listBox.current
      if (list && !reducedMotion()) {
        try {
          await list.animate([{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'translateY(8px)' }], {
            duration: 200,
            easing: 'cubic-bezier(.23, 1, .32, 1)',
            fill: 'forwards',
          }).finished
        } catch {
          list.getAnimations().forEach((a) => a.cancel())
        }
      }
      toast(T('logs_cleared'), 'ok')
      setEvents([])
      setHiddenOut(0)
      refetch()
    } finally {
      setClearing(false)
    }
  }

  const chipOrder = [['all', T('logc_all')], ['err', T('logc_err')], ...evGroups].filter(
    ([key]) => key === 'all' || key === filter || counts[key] > 0
  )

  const hiddenTypes = hiddenCount ? T('logf_types').replace('{n}', hiddenCount) : undefined

  const openFilters = (e, open) => {
    setKbFilters(!e.detail)
    setFiltersOpen(open)
  }

  const shown = visible.slice(0, show)
  const remaining = visible.length - shown.length

  const more = (e) => {
    if (e.detail) setBorn(new Set(visible.slice(show, show + PAGE_SIZE)))
    setShow(show + PAGE_SIZE)
  }

  return (
    <div className="logs">
      <PageHead icon="list" titleKey="logs_title" />

      <div className="tbtnrow">
        <button
          type="button"
          className={'ghost lgfbtn' + (filtersOpen ? ' on' : '')}
          disabled={!known}
          aria-label={hiddenTypes && T('logf_btn') + '، ' + hiddenTypes}
          onClick={(e) => openFilters(e, !filtersOpen)}
        >
          <Icon name="cog" />
          {T('logf_btn')}
          {hiddenCount ? (
            <span className="ct" title={hiddenTypes}>
              {hiddenCount}
            </span>
          ) : null}
        </button>
        <button
          type="button"
          className="ghost tone tone-del"
          disabled={clearing || events === null || (!events.length && !hiddenOut)}
          onClick={clearLogs}
        >
          {clearing ? <span className="bspin ink sm" /> : <Icon name="trash" />}
          {T('logs_clear')}
        </button>
      </div>

      <Toolbar value={query} placeholder={T('logs_search')} onSearch={setQuery} />

      <Reveal show={filtersOpen && known} instant={kbFilters}>
        {known ? (
          <LogFiltersPanel
            evTypes={evTypes}
            evGroups={evGroups}
            hidden={hidden}
            onToggleType={toggleType}
            onToggleGroup={toggleGroup}
          />
        ) : null}
      </Reveal>

      <LoadBar on={events === null} value={progress} />
      {events === null ? null : !events.length ? (
        <div className={'card muted empty' + (hiddenOut ? ' lgfempty' : '')}>
          {T(hiddenOut ? 'logf_empty' : 'logs_empty')}
          {hiddenOut && !filtersOpen ? (
            <button type="button" className="ghost" onClick={(e) => openFilters(e, true)}>
              <Icon name="cog" />
              {T('logf_open')}
            </button>
          ) : null}
        </div>
      ) : (
        <div ref={listBox}>
          <div className="logchips">
            {chipOrder.map(([key, label]) => (
              <button
                key={key}
                type="button"
                className={'fchip' + (filter === key ? ' on' : '')}
                aria-pressed={filter === key}
                onClick={() => setFilter(key)}
              >
                {label}
                <span className="ct">{counts[key] || 0}</span>
              </button>
            ))}
            {hiddenOut && !filtersOpen ? (
              <button type="button" className="fchip lgfhid" onClick={(e) => openFilters(e, true)}>
                <Icon name="cog" />
                {T('logf_hidden').replace('{n}', hiddenOut)}
              </button>
            ) : null}
          </div>

          <div>
            {shown.length ? (
              <div className="loglist">
                {shown.map((event) => {
                  const key = keys.get(event)
                  return (
                    <LogEvent
                      key={key}
                      event={event}
                      open={openIds[key]}
                      query={q}
                      born={born.has(event)}
                      onToggle={(next) => setOpenIds((prev) => ({ ...prev, [key]: next }))}
                    />
                  )
                })}
              </div>
            ) : (
              <div className="card muted">
                {T(q || filter === 'all' ? 'logs_no_match' : 'logc_empty')}
              </div>
            )}
            {remaining > 0 ? (
              <button type="button" className="card muted logmore" onClick={more}>
                {T('logs_more').replace('{n}', remaining)}
              </button>
            ) : null}
          </div>
        </div>
      )}
    </div>
  )
}
