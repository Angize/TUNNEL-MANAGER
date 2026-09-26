let seq = 0
let stack = []
const listeners = new Set()

function emit() {
  for (const fn of listeners) fn(stack)
}

export function subscribeDialogs(fn) {
  listeners.add(fn)
  fn(stack)
  return () => listeners.delete(fn)
}

function push(entry) {
  stack = [...stack, entry]
  emit()
}

export function closeDialog(id, value) {
  const entry = stack.find((d) => d.id === id)
  stack = stack.filter((d) => d.id !== id)
  emit()
  if (entry) entry.resolve(value)
}

export function confirmBox(msg, yesLabel) {
  return new Promise((resolve) => {
    push({ id: ++seq, kind: 'confirm', danger: true, msg, yesLabel, resolve })
  })
}

export function askBox(msg, yesLabel) {
  return new Promise((resolve) => {
    push({ id: ++seq, kind: 'confirm', danger: false, msg, yesLabel, resolve })
  })
}

export function alertBox(msg) {
  return new Promise((resolve) => {
    push({ id: ++seq, kind: 'alert', msg, resolve })
  })
}
