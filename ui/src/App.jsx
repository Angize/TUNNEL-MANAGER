import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import Sidebar from './shell/Sidebar.jsx'
import TopBar from './shell/TopBar.jsx'
import ReadinessBar from './shell/ReadinessBar.jsx'
import CommandPalette from './shell/CommandPalette.jsx'
import { apiGet } from './lib/api.js'
import { getLS, setLS } from './lib/storage.js'
import { applyStoredTheme, isDark, toggleTheme } from './lib/theme.js'
import { num } from './lib/num.js'
import { runPageRefresh, setUiInterval } from './lib/poll.js'
import ToastHost from './components/ToastHost.jsx'
import DialogHost from './components/DialogHost.jsx'
import { UiConfigProvider } from './state/UiConfigContext.jsx'
import { SummaryProvider } from './state/SummaryContext.jsx'
import { ActsProvider, useActs } from './state/ActsContext.jsx'
import { T } from './i18n/fa.js'
import { hasPage, pageComponent } from './pages/index.jsx'

const DEFAULT_INTERVAL = 2000
const HIDDEN_INTERVAL = 4000
const BOOT_INTERVAL = 6000
const MIN_INTERVAL = 300
const SEEN_KEY = 'tnl_logs_seen'
const PAGE_KEY = 'tnl_page'

function firstPage() {
  const saved = getLS(PAGE_KEY)
  return hasPage(saved) ? saved : 'overview'
}

function Shell() {
  const [page, setPage] = useState(firstPage)
  const [summary, setSummary] = useState({ counts: {}, evSeq: 0, logCount: 0 })
  const [unread, setUnread] = useState(0)
  const [dark, setDark] = useState(false)
  const [palette, setPalette] = useState(false)
  const [drawer, setDrawer] = useState(false)
  const [readiness, setReadiness] = useState(null)
  const [uiConfig, setUiConfig] = useState(null)
  const { refresh: actsRefresh } = useActs()
  const interval = useRef(DEFAULT_INTERVAL)
  const pageRef = useRef(page)

  pageRef.current = page

  useEffect(() => {
    applyStoredTheme()
    setDark(isDark())
    document.title = T('app_title')
  }, [])

  useEffect(() => {
    let alive = true
    apiGet('ui-config')
      .then((cfg) => {
        if (alive) setUiConfig(cfg)
      })
      .catch(() => {})
    apiGet('readiness')
      .then((r) => {
        if (!alive) return
        setReadiness(r)
        if (r && !r.ok) setPage('settings')
      })
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [])

  useEffect(() => {
    document.body.classList.toggle('navopen', drawer)
  }, [drawer])

  useEffect(() => {
    setLS(PAGE_KEY, page)
  }, [page])

  useEffect(() => {
    let alive = true
    let timer = 0

    const fetchSummary = async () => {
      let s = {}
      try {
        s = await apiGet('summary')
      } catch {
        s = {}
      }
      if (!alive) return

      const seq = num(s.ev_seq)
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
      })
      if (s.ui_interval) {
        interval.current = Math.max(MIN_INTERVAL, Math.round(num(s.ui_interval) * 1000))
        setUiInterval(interval.current)
      }

      const raw = getLS(SEEN_KEY)
      let seen
      if (raw === '') {
        seen = seq
        setLS(SEEN_KEY, String(seq))
      } else {
        seen = num(raw)
      }
      if (pageRef.current === 'logs') {
        seen = seq
        setLS(SEEN_KEY, String(seq))
      }
      setUnread(Math.max(0, seq - seen))
    }

    const tick = async () => {
      if (document.hidden) {
        timer = setTimeout(tick, Math.max(interval.current, HIDDEN_INTERVAL))
        return
      }
      await fetchSummary()
      if (!alive) return
      await actsRefresh()
      if (!alive) return
      await runPageRefresh()
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
  }, [actsRefresh])

  const navigate = useCallback((id) => {
    setPage(id)
    setDrawer(false)
  }, [])

  const onToggleTheme = useCallback(() => {
    setDark(toggleTheme())
  }, [])

  const summaryValue = useMemo(
    () => ({ counts: summary.counts, evSeq: summary.evSeq, logCount: summary.logCount }),
    [summary]
  )

  useEffect(() => {
    const onKey = (e) => {
      if (!((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K'))) return
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
      <div className="backdrop" onClick={() => setDrawer(false)} />
      <div className="shell">
        <Sidebar page={page} counts={summary.counts} unread={unread} onNavigate={navigate} />
        <main className="main">
          <TopBar dark={dark} onMenu={() => setDrawer(true)} onToggleTheme={onToggleTheme} />
          <ReadinessBar readiness={readiness} onNavigate={navigate} />
          <div id="view">
            {uiConfig ? (
              <UiConfigProvider value={uiConfig}>
                <SummaryProvider value={summaryValue}>
                  <Page onNavigate={navigate} />
                </SummaryProvider>
              </UiConfigProvider>
            ) : (
              <div className="card muted">{T('loading')}</div>
            )}
          </div>
        </main>
      </div>
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
