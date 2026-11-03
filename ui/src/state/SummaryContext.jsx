import { createContext, useContext } from 'react'

const SummaryContext = createContext(null)

export function SummaryProvider({ value, children }) {
  return <SummaryContext.Provider value={value}>{children}</SummaryContext.Provider>
}

export function useSummary() {
  return useContext(SummaryContext)
}
