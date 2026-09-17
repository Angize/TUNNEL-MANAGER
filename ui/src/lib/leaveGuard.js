let guard = null

export function setLeaveGuard(fn) {
  guard = fn
  return () => {
    if (guard === fn) guard = null
  }
}

export function mayLeave(target) {
  return guard ? guard(target) : true
}
