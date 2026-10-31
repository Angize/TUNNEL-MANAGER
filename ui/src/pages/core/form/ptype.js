export function ptypeHex(value) {
  const n = Number(value) || 0
  if (n <= 0 || n > 0xffff) return ''
  return n.toString(16).padStart(4, '0')
}

export function ptypeInt(hex) {
  const h = String(hex || '').trim()
  if (!h) return 0
  const n = parseInt(h, 16)
  if (!Number.isInteger(n) || n < 0 || n > 0xffff) return 0
  return n
}

export function ptypeValid(hex) {
  const h = String(hex || '').trim()
  return h === '' || /^[0-9a-fA-F]{1,4}$/.test(h)
}
