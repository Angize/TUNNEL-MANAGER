import Pending from './Pending.jsx'
import ProxiesPage from './proxies/ProxiesPage.jsx'

const META = {
  overview: { icon: 'dash', titleKey: 'nav_overview', subKey: 'ov_sub' },
  nodes: { icon: 'server', titleKey: 'nav_nodes', subKey: 'nodes_sub' },
  tunnels: { icon: 'link', titleKey: 'nav_tunnels', subKey: 'tun_sub' },
  portfw: { icon: 'fwd', titleKey: 'nav_portfw', subKey: 'pf_sub' },
  core: { icon: 'cpu', titleKey: 'nav_core', subKey: 'core_sub' },
  logs: { icon: 'list', titleKey: 'nav_logs', subKey: '' },
  settings: { icon: 'cog', titleKey: 'nav_settings', subKey: 'set_sub' },
}

const PAGES = { proxies: ProxiesPage }
for (const [id, meta] of Object.entries(META)) {
  PAGES[id] = () => <Pending {...meta} />
}

export default PAGES
