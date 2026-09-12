let pageRefresh = null

export function setPageRefresh(fn) {
  pageRefresh = fn
  return () => {
    if (pageRefresh === fn) pageRefresh = null
  }
}

export function runPageRefresh() {
  if (!pageRefresh) return Promise.resolve()
  try {
    return Promise.resolve(pageRefresh()).catch(() => {})
  } catch {
    return Promise.resolve()
  }
}

let uiInterval = 2000

export function setUiInterval(ms) {
  uiInterval = ms
}

export function getUiInterval() {
  return uiInterval
}
