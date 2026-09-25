const state = {}
const listeners = new Set()
const openedOnce = new Set()

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

export function openCardOnce(id, token) {
  if (openedOnce.has(token)) return
  openedOnce.add(token)
  if (state[id]) return
  state[id] = true
  for (const fn of listeners) fn(state)
}

export function closeAllCards() {
  let changed = false
  for (const id of Object.keys(state)) {
    if (!state[id]) continue
    state[id] = false
    changed = true
  }
  if (changed) for (const fn of listeners) fn(state)
}

export function closeCard(id) {
  if (!state[id]) return
  state[id] = false
  for (const fn of listeners) fn(state)
}
