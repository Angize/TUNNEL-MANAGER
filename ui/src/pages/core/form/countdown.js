export function remain(now, polledMs, next) {
  if (!next || !now) return -1
  const elapsed = now + (Date.now() - (polledMs || Date.now())) / 1000
  return Math.max(0, Math.round(next - elapsed))
}

export function countdownText(seconds) {
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  return (h ? h + ':' + (m < 10 ? '0' + m : m) : m) + ':' + (s < 10 ? '0' + s : s)
}

export function barPercent(total, left) {
  if (left < 0 || !total) return -1
  return Math.max(0, Math.min(100, Math.round(((total - left) / total) * 100)))
}
