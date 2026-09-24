import OverviewPage from './overview/OverviewPage.jsx'
import FleetPage, { FLEET_KINDS } from './fleet/FleetPage.jsx'
import LinksPage, { LINK_KINDS } from './links/LinksPage.jsx'
import LogsPage from './logs/LogsPage.jsx'
import SettingsPage, { SETTINGS_KINDS } from './settings/SettingsPage.jsx'
import './overview/overview.css'

const PAGES = {
  overview: OverviewPage,
  fleet: FleetPage,
  links: LinksPage,
  logs: LogsPage,
  settings: SettingsPage,
}

const HUBS = {
  fleet: { kinds: FLEET_KINDS.map((k) => k.id), first: 'nodes' },
  links: { kinds: LINK_KINDS.map((k) => k.id), first: 'core' },
  settings: { kinds: SETTINGS_KINDS.map((k) => k.id), first: 'set-values' },
}

export const HUB_IDS = Object.keys(HUBS)

export function hubOf(id) {
  return HUB_IDS.find((hub) => HUBS[hub].kinds.includes(id)) || null
}

export function hubFirst(hub) {
  return HUBS[hub].first
}

export function hasPage(id) {
  return Object.prototype.hasOwnProperty.call(PAGES, id)
}

export function pageComponent(id) {
  return hasPage(id) ? PAGES[id] : null
}
