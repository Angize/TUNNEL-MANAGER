import { useCallback, useEffect, useRef, useState } from 'react'
import Sidebar from './shell/Sidebar.jsx'
import TopBar from './shell/TopBar.jsx'
import { apiGet } from './lib/api.js'
import { getLS, setLS } from './lib/storage.js'
import { applyStoredTheme, isDark, toggleTheme } from './lib/theme.js'
import { num } from './lib/num.js'
import { runPageRefresh } from './lib/poll.js'
import ToastHost from './components/ToastHost.jsx'
import DialogHost from './components/DialogHost.jsx'
import { T } from './i18n/fa.js'
import PAGES from './pages/index.jsx'

const DEFAULT_INTERVAL = 2000
const SEEN_KEY = 'tnl_logs_seen'
const PAGE_KEY = 'tnl_page'

function firstPage() {
  const saved = getLS(PAGE_KEY)
  return saved && PAGES[saved] ? saved : 'overview'
}

export default function App() {
  const [page, setPage] = useState(firstPage)
  const [counts, setCounts] = useState({})
  const [unread, setUnread] = useState(0)
  const [dark, setDark] = useState(false)
  const [drawer, setDrawer] = useState(false)
  const interval = useRef(DEFAULT_INTERVAL)
  const pageRef = useRef(page)

  pageRef.current = page

  useEffect(() => {
    applyStoredTheme()
    setDark(isDark())
    document.title = T('app_title')
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

    const tick = async () => {
      if (document.hidden) {
        timer = setTimeout(tick, Math.max(interval.current, 4000))
        return
      }
      let s = {}
      try {
        s = await apiGet('summary')
      } catch {
        s = {}
      }
      if (!alive) return
      setCounts({
        nodes_total: num(s.nodes_total),
        proxies: num(s.proxies),
        links: num(s.links),
        portfw: num(s.portfw),
        core: num(s.core),
        log_count: num(s.log_count),
      })
      if (s.ui_interval) interval.current = Math.max(300, Math.round(num(s.ui_interval) * 1000))

      const seq = num(s.ev_seq)
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

      await runPageRefresh()
      if (!alive) return
      timer = setTimeout(tick, interval.current)
    }

    const onVisible = () => {
      if (document.hidden) return
      clearTimeout(timer)
      tick()
    }

    tick()
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      alive = false
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [])

  const navigate = useCallback((id) => {
    setPage(id)
    setDrawer(false)
  }, [])

  const onToggleTheme = useCallback(() => {
    setDark(toggleTheme())
  }, [])

  const Page = PAGES[page] || PAGES.overview

  return (
    <>
      <div className="backdrop" onClick={() => setDrawer(false)} />
      <div className="shell">
        <Sidebar page={page} counts={counts} unread={unread} onNavigate={navigate} />
        <main className="main">
          <TopBar dark={dark} onMenu={() => setDrawer(true)} onToggleTheme={onToggleTheme} />
          <div id="view">
            <Page />
          </div>
        </main>
      </div>
      <ToastHost />
      <DialogHost />
    </>
  )
}
