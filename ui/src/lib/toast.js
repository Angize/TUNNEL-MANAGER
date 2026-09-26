const SHOW_MS = 3400
const SHOW_ERR_MS = 7000
const FADE_MS = 320

let seq = 0
let items = []
const listeners = new Set()

function emit() {
  for (const fn of listeners) fn(items)
}

export function subscribeToasts(fn) {
  listeners.add(fn)
  fn(items)
  return () => listeners.delete(fn)
}

export function dismissToast(id) {
  if (!items.some((t) => t.id === id && t.show)) return
  items = items.map((t) => (t.id === id ? { ...t, show: false } : t))
  emit()
  setTimeout(() => {
    items = items.filter((t) => t.id !== id)
    emit()
  }, FADE_MS)
}

export function toast(msg, kind) {
  const id = ++seq
  items = [...items, { id, msg: String(msg == null ? '' : msg), kind: kind || '', show: false }]
  emit()
  setTimeout(() => {
    items = items.map((t) => (t.id === id ? { ...t, show: true } : t))
    emit()
  }, 10)
  setTimeout(() => dismissToast(id), kind === 'err' ? SHOW_ERR_MS : SHOW_MS)
}
