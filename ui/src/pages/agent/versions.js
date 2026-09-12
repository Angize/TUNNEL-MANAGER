export function versionNumber(value) {
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(String(value || ''))
  return m ? +m[1] * 1e6 + +m[2] * 1e3 + +m[3] : -1
}

export function versionIsNewer(have, want) {
  const a = versionNumber(have)
  const b = versionNumber(want)
  return a >= 0 && b >= 0 && a > b
}
