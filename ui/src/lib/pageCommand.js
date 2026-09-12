const handlers = {}

export function registerCommand(name, fn) {
  handlers[name] = fn
  return () => {
    if (handlers[name] === fn) delete handlers[name]
  }
}

export function runCommand(name) {
  const fn = handlers[name]
  if (fn) fn()
}
