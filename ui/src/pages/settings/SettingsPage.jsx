import { useState } from 'react'
import TabPager from '../../components/TabPager.jsx'
import { SettingsFormProvider } from './SettingsForm.jsx'
import ValuesTab from './ValuesTab.jsx'
import ApiTab from './ApiTab.jsx'
import UpkeepTab from './UpkeepTab.jsx'
import CdnTab from './CdnTab.jsx'
import CdnEdgeTab from './CdnEdgeTab.jsx'
import './settings.css'

const CDN_PAGES = [
  { id: 'cdn-cloud', labelKey: 'cdn_pg_cloud', Page: CdnTab },
  { id: 'cdn-edge', labelKey: 'cdn_pg_edge', Page: CdnEdgeTab },
]

function CdnPages({ active, onNavigate }) {
  const [page, setPage] = useState(CDN_PAGES[0].id)
  return <TabPager nested kinds={CDN_PAGES} kind={page} onKind={setPage} active={active} onNavigate={onNavigate} />
}

export const SETTINGS_KINDS = [
  { id: 'set-api', labelKey: 'set_tab_api', subKey: 'set_api_sub', Page: ApiTab },
  { id: 'set-cdn', labelKey: 'set_tab_cdn', subKey: 'set_cdn_sub', Page: CdnPages },
  { id: 'set-upkeep', labelKey: 'set_tab_upkeep', subKey: 'set_upkeep_sub', Page: UpkeepTab },
  { id: 'set-values', labelKey: 'set_tab_values', subKey: 'set_sub', Page: ValuesTab },
]

const TAB_IDS = SETTINGS_KINDS.map((k) => k.id)

export default function SettingsPage(props) {
  return (
    <SettingsFormProvider tabs={TAB_IDS}>
      <TabPager icon="cog" titleKey="nav_settings" kinds={SETTINGS_KINDS} snug {...props} />
    </SettingsFormProvider>
  )
}
