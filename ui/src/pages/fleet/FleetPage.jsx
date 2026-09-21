import TabPager from '../../components/TabPager.jsx'
import NodesPage from '../nodes/NodesPage.jsx'
import ProxiesPage from '../proxies/ProxiesPage.jsx'

export const FLEET_KINDS = [
  { id: 'nodes', labelKey: 'nav_nodes', subKey: 'nodes_sub', count: 'nodes_total', Page: NodesPage },
  { id: 'proxies', labelKey: 'nav_proxies', subKey: 'px_sub', count: 'proxies', Page: ProxiesPage },
]

export default function FleetPage(props) {
  return <TabPager icon="server" titleKey="nav_fleet" kinds={FLEET_KINDS} {...props} />
}
