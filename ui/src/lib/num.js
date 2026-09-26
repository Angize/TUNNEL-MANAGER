import { T } from '../i18n/fa.js'

export function latinDigits(text) {
  return String(text == null ? '' : text).replace(/[۰-۹٠-٩]/g, (d) => String(d.charCodeAt(0) & 0xf))
}

export function num(x) {
  const n = +x
  return isFinite(n) ? n : 0
}

export function fmtUptime(s) {
  const t = +s || 0
  const d = Math.floor(t / 86400)
  const h = Math.floor((t % 86400) / 3600)
  const m = Math.floor((t % 3600) / 60)
  const c = Math.floor(t % 60)
  if (d > 0) return d + ' ' + T('fmt_day') + ' ' + T('fmt_and') + ' ' + h + ' ' + T('fmt_hr')
  if (h > 0) return h + ' ' + T('fmt_hr') + ' ' + T('fmt_and') + ' ' + m + ' ' + T('fmt_min')
  if (m > 0) return m + ' ' + T('fmt_min')
  return c + ' ' + T('fmt_sec')
}

export function fmtBytes(n) {
  let v = num(n)
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (v >= 1024 && i < 4) {
    v /= 1024
    i++
  }
  const s = i ? (v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)) : Math.round(v)
  return s + ' ' + u[i]
}

export function fmtRate(b) {
  let v = num(b)
  const u = ['bps', 'Kbps', 'Mbps', 'Gbps']
  let i = 0
  while (v >= 1000 && i < 3) {
    v /= 1000
    i++
  }
  const s = i ? (v < 10 ? v.toFixed(1) : Math.round(v)) : Math.round(v)
  return s + ' ' + u[i]
}
