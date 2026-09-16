const LEAD_MAX = 3
const INLINE_MAX = 34
const PAIR_KEYS = { 'از': true, 'به': true }
const KEY_MAX = 16
const KEY_FORBIDDEN = /[،؛؟.!?()«»—]/

export function valueClass(value) {
  return /[\u0600-\u06FF]/.test(String(value)) ? ' fa' : ''
}

export function eventLevel(event) {
  if (event.level === 'bad') return 'bad'
  if (event.level === 'warn') return 'warn'
  return 'ok'
}

export function eventKey(event) {
  const s = (event.ts || 0) + '|' + (event.fa || '') + '|' + (event.dfa || '')
  let h = 0
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0
  return 'k' + (h >>> 0)
}

export function splitDetail(detail) {
  const rows = []
  const notes = []
  for (const line of detail ? detail.split('\n') : []) {
    const cut = line.indexOf(': ')
    const key = cut > 0 ? line.slice(0, cut) : ''
    if (key && key.length <= KEY_MAX && !KEY_FORBIDDEN.test(key)) {
      rows.push({ k: key, v: line.slice(cut + 2) })
    } else {
      notes.push(line)
    }
  }
  return { rows, notes }
}

export function sentence(title, notes) {
  let out = String(title || '').trim()
  for (const note of notes) {
    const next = String(note || '').trim()
    if (!next) continue
    out += (/[.!؟۔]$/.test(out) ? ' ' : ' — ') + next
  }
  return out
}

export function layoutEvent(event) {
  const { rows, notes } = splitDetail(event.dfa || '')
  const lead = []
  const rest = []
  for (const row of rows) {
    if (PAIR_KEYS[row.k]) {
      lead.push(row)
    } else if (lead.length < LEAD_MAX && String(row.v).length <= INLINE_MAX) {
      lead.push(row)
    } else {
      rest.push(row)
    }
  }
  return { text: sentence(event.fa || '', notes), lead, rest, isPair: (k) => !!PAIR_KEYS[k] }
}

export function formatEventTime(ts) {
  const d = new Date(ts * 1000)
  try {
    return d.toLocaleString('fa-IR-u-nu-latn', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return d.toISOString().slice(0, 16).replace('T', ' ')
  }
}
