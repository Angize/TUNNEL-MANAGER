import { closeAllCards } from './openCards.js'

const state = { mode: false, draggingId: '' }
let saving = false
const listeners = new Set()

function emit() {
  for (const fn of listeners) fn(state)
}

export function subscribeReorder(fn) {
  listeners.add(fn)
  return () => listeners.delete(fn)
}

export function reorderMode() {
  return state.mode
}

export function draggingId() {
  return state.draggingId
}

export function toggleReorder() {
  state.mode = !state.mode
  document.body.classList.toggle('reord-on', state.mode)
  if (state.mode) closeAllCards()
  emit()
}

export function setDragging(id) {
  state.draggingId = id
  document.body.classList.toggle('rdragging', !!id)
  emit()
}

export function setSaving(on) {
  saving = on
}

export function listBusy() {
  return !!state.draggingId || saving
}
