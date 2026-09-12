import Pending from './Pending.jsx'
import OverviewPage from './overview/OverviewPage.jsx'
import ProxiesPage from './proxies/ProxiesPage.jsx'
import PortfwPage from './portfw/PortfwPage.jsx'
import LogsPage from './logs/LogsPage.jsx'
import './overview/overview.css'

const PAGES = {
  overview: { component: OverviewPage },
  nodes: { icon: 'server', titleKey: 'nav_nodes', subKey: 'nodes_sub' },
  proxies: { component: ProxiesPage },
  tunnels: { icon: 'link', titleKey: 'nav_tunnels', subKey: 'tun_sub' },
  portfw: { component: PortfwPage },
  core: { icon: 'cpu', titleKey: 'nav_core', subKey: 'core_sub' },
  logs: { component: LogsPage },
  settings: { icon: 'cog', titleKey: 'nav_settings', subKey: 'set_sub' },
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
