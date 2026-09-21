import TabPager from '../../components/TabPager.jsx'
import TunnelsPage from '../tunnels/TunnelsPage.jsx'
import CorePage from '../core/CorePage.jsx'
import PortfwPage from '../portfw/PortfwPage.jsx'

export const LINK_KINDS = [
  { id: 'tunnels', labelKey: 'nav_tunnels', subKey: 'tun_sub', count: 'links', Page: TunnelsPage },
  { id: 'core', labelKey: 'nav_core', subKey: 'core_sub', count: 'core', Page: CorePage },
  { id: 'portfw', labelKey: 'nav_portfw', subKey: 'pf_sub', count: 'portfw', Page: PortfwPage },
]

export default function LinksPage(props) {
  return <TabPager icon="link" titleKey="nav_links" kinds={LINK_KINDS} {...props} />
}
