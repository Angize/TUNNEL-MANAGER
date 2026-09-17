import { getLS, setLS } from './storage.js'

const KEY = 'tnl_dark'

export function isDark() {
  return document.documentElement.classList.contains('dark')
}

export function applyStoredTheme() {
  if (getLS(KEY)) document.documentElement.classList.add('dark')
}

export function toggleTheme() {
  const dark = document.documentElement.classList.toggle('dark')
  setLS(KEY, dark ? '1' : '')
  return dark
}
