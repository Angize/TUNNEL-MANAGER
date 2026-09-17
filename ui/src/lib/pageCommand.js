const handlers = {}
const queued = new Set()

export function registerCommand(name, fn) {
  handlers[name] = fn
  if (queued.delete(name)) fn()
  return () => {
    if (handlers[name] === fn) delete handlers[name]
  }
}

export function runCommand(name) {
  const fn = handlers[name]
  if (fn) fn()
  else queued.add(name)
}
