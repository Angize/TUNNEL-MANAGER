import { createContext, useContext } from 'react'

const UiConfigContext = createContext(null)

export function UiConfigProvider({ value, children }) {
  return <UiConfigContext.Provider value={value}>{children}</UiConfigContext.Provider>
}

export function useUiConfig() {
  const value = useContext(UiConfigContext)
  if (!value) throw new Error('useUiConfig used outside UiConfigProvider')
  return value
}
