import { createContext, useCallback, useContext, useState } from 'react'
import { BulkFabHost } from '../pages/nodes/NodeBulk.jsx'
import TransferModal from '../pages/nodes/TransferModal.jsx'
import { runPageRefresh } from '../lib/poll.js'

const TransferContext = createContext(null)

export function useOpenTransfer() {
  return useContext(TransferContext)
}

export default function NodeJobs({ children, onNavigate }) {
  const [sessions, setSessions] = useState([])
  const [active, setActive] = useState(null)
  const open = useCallback((node, nodes, filtered) => {
    setSessions(current => current.some(session => session.node.id === node.id)
      ? current : [...current, { node, nodes, filtered }])
    setActive(node.id)
  }, [])

  function finish(id) {
    setActive(null)
    setSessions(current => current.filter(session => session.node.id !== id))
    runPageRefresh()
  }

  return (
    <TransferContext.Provider value={open}>
      {children}
      <div className="node-jobs">
        <BulkFabHost onNavigate={onNavigate} />
        {sessions.map(session => (
          <TransferModal key={session.node.id} {...session} minimized={active !== session.node.id}
            onMinimize={() => setActive(null)} onRestore={() => setActive(session.node.id)}
            onClose={() => finish(session.node.id)} />
        ))}
      </div>
    </TransferContext.Provider>
  )
}
