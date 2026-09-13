import Pending from './Pending.jsx'
import OverviewPage from './overview/OverviewPage.jsx'
import ProxiesPage from './proxies/ProxiesPage.jsx'
import LogsPage from './logs/LogsPage.jsx'
import NodesPage from './nodes/NodesPage.jsx'
import LinksPage from './links/LinksPage.jsx'
import AgentPage from './agent/AgentPage.jsx'
import SettingsPage from './settings/SettingsPage.jsx'
import './overview/overview.css'

const PAGES = {
  overview: { component: OverviewPage },
  nodes: { component: NodesPage },
  proxies: { component: ProxiesPage },
  links: { component: LinksPage },
  logs: { component: LogsPage },
  agent: { component: AgentPage },
  settings: { component: SettingsPage },
}

export function hasPage(id) {
  return Object.prototype.hasOwnProperty.call(PAGES, id)
}

export function pageComponent(id) {
  const entry = PAGES[id]
  if (!entry) return null
  if (entry.component) return entry.component
  if (!entry.pending) {
    entry.pending = function PendingPage() {
      return <Pending icon={entry.icon} titleKey={entry.titleKey} subKey={entry.subKey} />
    }
  }
  return entry.pending
}
