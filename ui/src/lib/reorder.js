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

function setMode(on) {
  state.mode = on
  document.body.classList.toggle('reord-on', on)
  if (on) closeAllCards()
  emit()
}

export function toggleReorder() {
  setMode(!state.mode)
}

export function stopReorder() {
  if (state.mode) setMode(false)
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
