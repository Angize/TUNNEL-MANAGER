import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Sidebar from './shell/Sidebar.jsx'
import TopBar from './shell/TopBar.jsx'
import TabBar from './shell/TabBar.jsx'
import ReadinessBar from './shell/ReadinessBar.jsx'
import CommandPalette from './shell/CommandPalette.jsx'
import { apiGet } from './lib/api.js'
import { getLS, setLS } from './lib/storage.js'
import { applyStoredTheme, isDark, toggleTheme } from './lib/theme.js'
import { num } from './lib/num.js'
import { runPageRefresh, setUiInterval } from './lib/poll.js'
import { stopReorder } from './lib/reorder.js'
import { mayLeave } from './lib/leaveGuard.js'
import ToastHost from './components/ToastHost.jsx'
import DialogHost from './components/DialogHost.jsx'
import { UiConfigProvider } from './state/UiConfigContext.jsx'
import { SummaryProvider } from './state/SummaryContext.jsx'
import { ActsProvider, useActs } from './state/ActsContext.jsx'
import { T } from './i18n/fa.js'
import { HUB_IDS, hasPage, hubFirst, hubOf, pageComponent } from './pages/index.jsx'

const DEFAULT_INTERVAL = 2000
const HIDDEN_INTERVAL = 4000
const BOOT_INTERVAL = 6000
const MIN_INTERVAL = 300
const READY_RECHECK = 60000
const SEEN_KEY = 'tnl_logs_seen'
const PAGE_KEY = 'tnl_page'
const KIND_KEY = 'tnl_kind_'

function firstPage() {
  const saved = getLS(PAGE_KEY)
  return hubOf(saved) || (hasPage(saved) ? saved : 'overview')
}

function firstKinds() {
  const saved = getLS(PAGE_KEY)
  const out = {}
  for (const hub of HUB_IDS) {
    const kind = hubOf(saved) === hub ? saved : getLS(KIND_KEY + hub)
    out[hub] = hubOf(kind) === hub ? kind : hubFirst(hub)
  }
  return out
}

function withKind(prev, kind) {
  const hub = hubOf(kind)
  return hub && prev[hub] !== kind ? { ...prev, [hub]: kind } : prev
}

function Shell() {
  const [page, setPage] = useState(firstPage)
  const [kinds, setKinds] = useState(firstKinds)
  const [summary, setSummary] = useState({ counts: {}, evSeq: '0-0', logCount: 0, loaded: false })
  const [unread, setUnread] = useState(0)
  const [dark, setDark] = useState(false)
  const [palette, setPalette] = useState(false)
  const [readiness, setReadiness] = useState(null)
  const [uiConfig, setUiConfig] = useState(null)
  const { refresh: actsRefresh } = useActs()
  const interval = useRef(DEFAULT_INTERVAL)
  const pageRef = useRef(page)
  const readinessRef = useRef(null)
  const readinessSeq = useRef(0)
  const readinessAt = useRef(0)
  const navigated = useRef(false)

  pageRef.current = page

  const loadReadiness = useCallback(async (boot) => {
    const mine = ++readinessSeq.current
    let r
    readinessAt.current = Date.now()
    try {
      r = await apiGet('readiness')
    } catch {
      return
    }
    if (mine !== readinessSeq.current) return
    readinessRef.current = r
    setReadiness(r)
    if (boot && !r.ok && !navigated.current) {
      setKinds((prev) => withKind(prev, 'set-upkeep'))
      setPage('settings')
    }
  }, [])

  useEffect(() => stopReorder, [page, kinds])

  useEffect(() => {
    applyStoredTheme()
    setDark(isDark())
    document.title = T('app_title')
  }, [])

  useEffect(() => {
    let alive = true
    let retry = 0
    const loadConfig = () =>
      apiGet('ui-config')
        .then((cfg) => {
          if (alive) setUiConfig(cfg)
        })
        .catch(() => {
          if (alive) retry = setTimeout(loadConfig, DEFAULT_INTERVAL)
        })
    loadConfig()
    loadReadiness(true)
    return () => {
      alive = false
      clearTimeout(retry)
    }
  }, [loadReadiness])

  useEffect(() => {
    if (readinessRef.current) loadReadiness(false)
  }, [page, loadReadiness])

  useEffect(() => {
    setLS(PAGE_KEY, page)
  }, [page])

  useEffect(() => {
    for (const hub of HUB_IDS) setLS(KIND_KEY + hub, kinds[hub])
  }, [kinds])

  useEffect(() => {
    let alive = true
    let timer = 0
    let ticking = false

    const fetchSummary = async () => {
      const raw = getLS(SEEN_KEY)
      let s
      try {
        s = await apiGet('summary' + (raw === '' ? '' : '?seen=' + encodeURIComponent(raw)))
      } catch {
        return
      }
      if (!alive) return

      const seq = String(s.ev_seq || '0-0')
      setSummary({
        counts: {
          nodes_total: num(s.nodes_total),
          proxies: num(s.proxies),
          links: num(s.links),
          portfw: num(s.portfw),
          core: num(s.core),
          log_count: num(s.log_count),
        },
        evSeq: seq,
        logCount: num(s.log_count),
        subnetFree: s.subnet_free || null,
        loaded: true,
      })
      if (s.ui_interval) {
        interval.current = Math.max(MIN_INTERVAL, Math.round(num(s.ui_interval) * 1000))
        setUiInterval(interval.current)
      }

      if (raw === '' || pageRef.current === 'logs') {
        setLS(SEEN_KEY, String(seq))
        setUnread(0)
        return
      }
      setUnread(num(s.log_unread))
    }

    const tick = async () => {
      if (ticking) return
      if (document.hidden) {
        timer = setTimeout(tick, Math.max(interval.current, HIDDEN_INTERVAL))
        return
      }
      ticking = true
      try {
        await fetchSummary()
        if (!alive) return
        if (
          !readinessRef.current ||
          !readinessRef.current.ok ||
          Date.now() - readinessAt.current >= READY_RECHECK
        )
          await loadReadiness(!readinessRef.current)
        if (!alive) return
        await actsRefresh()
        if (!alive) return
        await runPageRefresh()
      } finally {
        ticking = false
      }
      if (!alive) return
      timer = setTimeout(tick, interval.current)
    }

    const onVisible = () => {
      if (document.hidden) return
      clearTimeout(timer)
      tick()
    }

    fetchSummary()
    actsRefresh()
    timer = setTimeout(tick, BOOT_INTERVAL)
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      alive = false
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [actsRefresh, loadReadiness])

  const navigate = useCallback(async (id, before) => {
    if (!(await mayLeave(id))) return
    if (before) before()
    navigated.current = true
    const hub = hubOf(id)
    if (hub) {
      setKinds((prev) => withKind(prev, id))
      setPage(hub)
      return
    }
    setPage(id)
  }, [])

  const onKind = useCallback((kind) => setKinds((prev) => withKind(prev, kind)), [])

  const onToggleTheme = useCallback(() => {
    setDark(toggleTheme())
  }, [])

  const summaryValue = useMemo(
    () => ({
      counts: summary.counts,
      evSeq: summary.evSeq,
      logCount: summary.logCount,
      subnetFree: summary.subnetFree,
      loaded: summary.loaded,
    }),
    [summary]
  )

  useEffect(() => {
    const onKey = (e) => {
      if (!((e.ctrlKey || e.metaKey) && (e.code === 'KeyK' || e.key.toLowerCase() === 'k'))) return
      if (palette) {
        e.preventDefault()
        setPalette(false)
        return
      }
      const tag = e.target && e.target.tagName
      if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return
      if (document.querySelector('.modalov')) return
      e.preventDefault()
      setPalette(true)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [palette])

  const Page = pageComponent(page) || pageComponent('overview')

  return (
    <>
      <div className="shell">
        <Sidebar
          page={page}
          counts={summary.counts}
          unread={unread}
          dark={dark}
          onNavigate={navigate}
          onToggleTheme={onToggleTheme}
        />
        <main className="main">
          <TopBar dark={dark} onToggleTheme={onToggleTheme} />
          <ReadinessBar readiness={readiness} onNavigate={navigate} />
          <div id="view" className="pg" key={page}>
            {uiConfig ? (
              <UiConfigProvider value={uiConfig}>
                <SummaryProvider value={summaryValue}>
                  <Page onNavigate={navigate} kind={kinds[page]} onKind={onKind} />
                </SummaryProvider>
              </UiConfigProvider>
            ) : (
              <div className="card muted">{T('loading')}</div>
            )}
          </div>
        </main>
      </div>
      <TabBar page={page} unread={unread} onNavigate={navigate} />
      {palette ? (
        <CommandPalette
          dark={dark}
          onNavigate={navigate}
          onToggleTheme={onToggleTheme}
          onClose={() => setPalette(false)}
        />
      ) : null}
      <ToastHost />
      <DialogHost />
    </>
  )
}

export default function App() {
  return (
    <ActsProvider>
      <Shell />
    </ActsProvider>
  )
}
