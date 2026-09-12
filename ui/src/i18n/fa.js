import common from './fa/common.js'
import errors from './fa/errors.js'

export const FA = {
  ...common,
  ...errors,
}

export function T(key) {
  return key in FA ? FA[key] : key
}

export function TF(key, vars) {
  let out = T(key)
  if (!vars) return out
  for (const [k, v] of Object.entries(vars)) out = out.split('{' + k + '}').join(String(v))
  return out
}
