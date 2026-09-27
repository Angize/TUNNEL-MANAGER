import { createContext, useContext } from 'react'
import useBulkInstall from '../pages/nodes/useBulkInstall.js'

const BulkInstallContext = createContext(null)

export function BulkInstallProvider({ children }) {
  const bulk = useBulkInstall()
  return <BulkInstallContext.Provider value={bulk}>{children}</BulkInstallContext.Provider>
}

export function useBulk() {
  return useContext(BulkInstallContext)
}
