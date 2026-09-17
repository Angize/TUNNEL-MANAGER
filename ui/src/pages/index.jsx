import OverviewPage from './overview/OverviewPage.jsx'
import ProxiesPage from './proxies/ProxiesPage.jsx'
import LogsPage from './logs/LogsPage.jsx'
import NodesPage from './nodes/NodesPage.jsx'
import LinksPage from './links/LinksPage.jsx'
import SettingsPage from './settings/SettingsPage.jsx'
import './overview/overview.css'

const PAGES = {
  overview: OverviewPage,
  nodes: NodesPage,
  proxies: ProxiesPage,
  links: LinksPage,
  logs: LogsPage,
  settings: SettingsPage,
}

export function hasPage(id) {
  return Object.prototype.hasOwnProperty.call(PAGES, id)
}

export function pageComponent(id) {
  return hasPage(id) ? PAGES[id] : null
}
