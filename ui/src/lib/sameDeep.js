function plain(value) {
  return !!value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype
}

export function sameDeep(prev, next) {
  if (prev === next) return prev
  const list = Array.isArray(prev) && Array.isArray(next)
  if (!list && !(plain(prev) && plain(next))) return next
  const keys = list ? next.map((_, i) => i) : Object.keys(next)
  let same = list ? prev.length === next.length : Object.keys(prev).length === keys.length
  const out = list ? [] : {}
  for (const key of keys) {
    out[key] = sameDeep(prev[key], next[key])
    if (out[key] !== prev[key]) same = false
  }
  return same ? prev : out
}
