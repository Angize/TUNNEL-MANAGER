const state = {}
const listeners = new Set()

export function subscribeOpenCards(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function isCardOpen(id) {
  return !!state[id]
}

export function toggleCard(id) {
  state[id] = !state[id]
  for (const fn of listeners) fn(state)
}
