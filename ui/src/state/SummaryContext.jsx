import { createContext, useContext } from 'react'

const SummaryContext = createContext({
  counts: {},
  evSeq: 0,
  logCount: 0,
  subnetFree: null,
  loaded: false,
})

export function SummaryProvider({ value, children }) {
  return <SummaryContext.Provider value={value}>{children}</SummaryContext.Provider>
}

export function useSummary() {
  return useContext(SummaryContext)
}
