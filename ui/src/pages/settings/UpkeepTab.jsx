import { useRef } from 'react'
import AgentPage from '../agent/AgentPage.jsx'
import BackupCard from './BackupCard.jsx'
import { useSettingsForm } from './SettingsForm.jsx'
import useRiseIn from '../../lib/useRiseIn.js'

export default function UpkeepTab() {
  const { agentGen } = useSettingsForm()
  const box = useRef(null)
  useRiseIn(box, true)
  return (
    <div className="upkeep" ref={box}>
      <BackupCard />
      <AgentPage key={agentGen} headless />
    </div>
  )
}
