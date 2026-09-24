import TabPager from '../../components/TabPager.jsx'
import { SettingsFormProvider } from './SettingsForm.jsx'
import ValuesTab from './ValuesTab.jsx'
import ApiTab from './ApiTab.jsx'
import UpkeepTab from './UpkeepTab.jsx'
import './settings.css'

export const SETTINGS_KINDS = [
  { id: 'set-values', labelKey: 'set_tab_values', subKey: 'set_sub', Page: ValuesTab },
  { id: 'set-api', labelKey: 'set_tab_api', subKey: 'set_api_sub', Page: ApiTab },
  { id: 'set-upkeep', labelKey: 'set_tab_upkeep', subKey: 'set_upkeep_sub', Page: UpkeepTab },
]

const TAB_IDS = SETTINGS_KINDS.map((k) => k.id)

export default function SettingsPage(props) {
  return (
    <SettingsFormProvider tabs={TAB_IDS}>
      <TabPager icon="cog" titleKey="nav_settings" kinds={SETTINGS_KINDS} {...props} />
    </SettingsFormProvider>
  )
}
