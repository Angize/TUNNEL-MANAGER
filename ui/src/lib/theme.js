import { getLS, setLS } from './storage.js'

const KEY = 'tnl_dark'

export function isDark() {
  return document.body.classList.contains('dark')
}

export function applyStoredTheme() {
  if (getLS(KEY)) document.body.classList.add('dark')
}

export function toggleTheme() {
  const dark = document.body.classList.toggle('dark')
  setLS(KEY, dark ? '1' : '')
  return dark
}
