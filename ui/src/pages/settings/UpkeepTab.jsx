import AgentPage from '../agent/AgentPage.jsx'
import BackupCard from './BackupCard.jsx'
import { useSettingsForm } from './SettingsForm.jsx'

export default function UpkeepTab() {
  const { agentGen } = useSettingsForm()
  return (
    <>
      <BackupCard />
      <AgentPage key={agentGen} headless />
    </>
  )
}
