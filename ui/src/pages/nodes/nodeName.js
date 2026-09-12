const NODE_NAME = /^[A-Za-z0-9 _.-]{1,40}$/

export function isNodeNameValid(name) {
  return NODE_NAME.test(String(name || ''))
}
