const SHOW_MS = 3400
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

export function toast(msg, kind) {
  const id = ++seq
  items = [...items, { id, msg: String(msg == null ? '' : msg), kind: kind || '', show: false }]
  emit()
  setTimeout(() => {
    items = items.map((t) => (t.id === id ? { ...t, show: true } : t))
    emit()
  }, 10)
  setTimeout(() => {
    items = items.map((t) => (t.id === id ? { ...t, show: false } : t))
    emit()
    setTimeout(() => {
      items = items.filter((t) => t.id !== id)
      emit()
    }, FADE_MS)
  }, SHOW_MS)
}
