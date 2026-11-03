export const LOGS_SEEN_KEY = 'tnl_logs_seen'

export function getLS(key) {
  try {
    return localStorage.getItem(key) || ''
  } catch {
    return ''
  }
}

export function setLS(key, value) {
  try {
    localStorage.setItem(key, value)
  } catch {
    return
  }
}
