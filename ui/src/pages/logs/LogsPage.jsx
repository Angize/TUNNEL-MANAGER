import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import PageHead from '../../components/PageHead.jsx'
import Icon from '../../components/Icon.jsx'
import Toolbar from '../../components/Toolbar.jsx'
import { Sk } from '../../components/Skeleton.jsx'
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
import { useUiConfig } from '../../state/UiConfigContext.jsx'
import { useSummary } from '../../state/SummaryContext.jsx'
import './logs.css'

const PAGE_SIZE = 200
const SEEN_KEY = 'tnl_logs_seen'

function LogSkeleton() {
  return (
    <div className="card loglist">
      {Array.from({ length: 5 }, (_, i) => (
        <div className="lev" key={i}>
          <span className="lev-bar sk" />
          <div>
            <div className="lev-head">
              <Sk className="lev-lv" w={42} />
              <Sk className="lev-time" w={64} />
            </div>
            <Sk as="div" className="lev-text" w={i % 2 ? '46%' : '62%'} />
          </div>
        </div>
      ))}
    </div>
  )
}

export default function LogsPage() {
  const { ev_types: evTypes, ev_groups: evGroups } = useUiConfig()
  const { evSeq, logCount } = useSummary()

  const [events, setEvents] = useState(null)
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [show, setShow] = useState(PAGE_SIZE)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const [openIds, setOpenIds] = useState({})
  const signature = useRef('')

  const loadRef = useRef(() => {})

  const onSaved = useCallback(() => {
    signature.current = ''
    loadRef.current()
  }, [])

  const { hidden, hiddenCount, adoptFromServer, isPending, toggleType, toggleGroup } =
    useHiddenTypes({ evTypes, onSaved })

  const load = useCallback(async () => {
    const sig = evSeq + ':' + logCount
    if (sig === signature.current) return
    let r
    try {
      r = await apiGet('events')
    } catch {
      return
    }
    signature.current = sig
    setEvents(r.events)
    if (!isPending()) adoptFromServer(r.hidden)
  }, [evSeq, logCount, adoptFromServer, isPending])

  loadRef.current = load

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => setPageRefresh(() => loadRef.current()), [])

  useEffect(() => {
    setLS(SEEN_KEY, String(evSeq))
  }, [evSeq])

  useEffect(() => {
    setShow(PAGE_SIZE)
  }, [filter, query])

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

  const found = useMemo(() => {
    const list = events || []
    const q = query.trim().toLowerCase()
    if (!q) return list
    return list.filter((e) => ((e.fa || '') + ' ' + (e.dfa || '')).toLowerCase().includes(q))
  }, [events, query])

  const counts = useMemo(() => {
    const c = { all: found.length, err: 0 }
    for (const [group] of evGroups) c[group] = 0
    for (const e of found) {
      if (c[e.cat] != null) c[e.cat]++
      if (e.level === 'bad') c.err++
    }
    return c
  }, [found, evGroups])

  const activeFilter = filter !== 'all' && !(counts[filter] > 0) ? 'all' : filter

  const visible = useMemo(
    () =>
      found.filter((e) =>
        activeFilter === 'all' ? true : activeFilter === 'err' ? e.level === 'bad' : e.cat === activeFilter
      ),
    [found, activeFilter]
  )

  const clearLogs = async () => {
    if (!(await confirmBox(T('logs_clear_confirm')))) return
    const r = await apiPost('events-clear', {})
    if (!(r.ok && r.d && r.d.ok)) {
      toast(postError(r), 'err')
      return
    }
    toast(T('logs_cleared'), 'ok')
    setEvents([])
    signature.current = ''
    load()
  }

  const chipOrder = [['all', T('logc_all')]]
    .concat(evGroups.map(([key, label]) => [key, label]))
    .concat([['err', T('logc_err')]])
    .filter(([key]) => key === 'all' || counts[key] > 0)

  const shown = visible.slice(0, show)
  const remaining = visible.length - shown.length

  return (
    <div className="logs">
      <PageHead icon="list" titleKey="logs_title" />

      <div className="tbtnrow">
        <button
          type="button"
          className={'ghost lgfbtn' + (filtersOpen ? ' on' : '')}
          onClick={() => setFiltersOpen(!filtersOpen)}
        >
          <Icon name="cog" />
          {T('logf_btn')}
          {hiddenCount ? <span className="ct">{hiddenCount}</span> : null}
        </button>
        <button type="button" className="ghost" onClick={clearLogs}>
          <Icon name="trash" />
          {T('logs_clear')}
        </button>
      </div>

      <Toolbar value={query} placeholder={T('logs_search')} onSearch={setQuery} />

      {filtersOpen ? (
        <LogFiltersPanel
          evTypes={evTypes}
          evGroups={evGroups}
          hidden={hidden}
          onToggleType={toggleType}
          onToggleGroup={toggleGroup}
        />
      ) : null}

      {events === null ? (
        <LogSkeleton />
      ) : !events.length ? (
        <div className="card muted">{T(hiddenCount ? 'logf_empty' : 'logs_empty')}</div>
      ) : (
        <>
          {hiddenCount && !filtersOpen ? (
            <div className="lgfnote">
              <Icon name="cog" />
              {T('logf_on').replace('{n}', hiddenCount)}
            </div>
          ) : null}
          <div className="logchips">
            {chipOrder.map(([key, label]) => (
              <div
                key={key}
                className={'fchip' + (activeFilter === key ? ' on' : '')}
                role="button"
                tabIndex={0}
                onClick={() => setFilter(key)}
                onKeyDown={(e) => {
                  if (e.key === ' ' || e.key === 'Enter') {
                    e.preventDefault()
                    setFilter(key)
                  }
                }}
              >
                {label}
                <span className="ct">{counts[key] || 0}</span>
              </div>
            ))}
          </div>

          <div>
            {shown.length ? (
              <div className="card loglist">
                {shown.map((event) => {
                  const key = keys.get(event)
                  return (
                    <LogEvent
                      key={key}
                      event={event}
                      open={!!openIds[key]}
                      onToggle={() => setOpenIds((prev) => ({ ...prev, [key]: !prev[key] }))}
                    />
                  )
                })}
              </div>
            ) : (
              <div className="card muted">{T('logs_no_match')}</div>
            )}
            {remaining > 0 ? (
              <div
                className="card muted logmore"
                role="button"
                tabIndex={0}
                onClick={() => setShow(show + PAGE_SIZE)}
                onKeyDown={(e) => {
                  if (e.key === ' ' || e.key === 'Enter') {
                    e.preventDefault()
                    setShow(show + PAGE_SIZE)
                  }
                }}
              >
                {T('logs_more').replace('{n}', remaining)}
              </div>
            ) : null}
          </div>
        </>
      )}
    </div>
  )
}
