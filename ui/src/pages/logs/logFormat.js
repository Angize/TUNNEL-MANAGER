const LEAD_MAX = 3
const INLINE_MAX = 34
const PAIR_KEYS = { 'از': true, 'به': true }
const KEY_MAX = 16
const KEY_FORBIDDEN = /[،؛؟.!?()«»—]/
const NOTE_MAX = 110
const NOTE_HEAD_MIN = 24
const NOTE_CUTS = [' — ', '. ', '؛ ']

export function valueClass(value) {
  return /[\u0600-\u06FF]/.test(String(value)) ? ' fa' : ''
}

export function eventLevel(event) {
  if (event.level === 'bad') return 'bad'
  if (event.level === 'warn') return 'warn'
  return 'ok'
}

export function eventKey(event) {
  const s = (event.ts || 0) + '|' + (event.text || '') + '|' + (event.detail || '')
  let h = 0
  for (let i = 0; i < s.length; i++) h = ((h << 5) - h + s.charCodeAt(i)) | 0
  return 'k' + (h >>> 0)
}

function splitDetail(detail) {
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

function sentence(title, notes) {
  let out = String(title || '').trim()
  for (const note of notes) {
    const next = String(note || '').trim()
    if (!next) continue
    out += (/[.!؟۔]$/.test(out) ? ' ' : ' — ') + next
  }
  return out
}

function cutNote(note) {
  if (note.length <= NOTE_MAX) return [note, '']
  let at = -1
  let cut = ''
  for (const sep of NOTE_CUTS) {
    const i = note.indexOf(sep, NOTE_HEAD_MIN)
    if (i > 0 && (at < 0 || i < at)) {
      at = i
      cut = sep
    }
  }
  if (at < 0) return [note, '']
  const head = note.slice(0, cut === '. ' ? at + 1 : at)
  return [head, note.slice(at + cut.length).trim()]
}

function foldNotes(notes) {
  const lines = notes.map((note) => String(note || '').trim()).filter(Boolean)
  if (!lines.length) return { inline: [], folded: [] }
  const [head, tail] = cutNote(lines[0])
  return { inline: [head], folded: (tail ? [tail] : []).concat(lines.slice(1)) }
}

export function nameParts(text) {
  const bits = String(text || '').split(/«([^»]+)»([^\s«]*)/)
  const out = []
  for (let i = 0; i < bits.length; i += 3) {
    if (bits[i]) out.push({ text: bits[i] })
    if (i + 1 < bits.length) {
      out.push({ name: bits[i + 1], tail: bits[i + 2] || '', latin: !/[\u0600-\u06FF]/.test(bits[i + 1]) })
    }
  }
  return out
}

export function layoutEvent(event) {
  const { rows, notes } = splitDetail(event.detail || '')
  const { inline, folded } = foldNotes(notes)
  const lead = []
  const rest = []
  const repeated = new Set(rows.map((row) => row.k)).size < rows.length
  for (const row of rows) {
    if (repeated) {
      rest.push(row)
    } else if (PAIR_KEYS[row.k]) {
      lead.push(row)
    } else if (lead.length < LEAD_MAX && String(row.v).length <= INLINE_MAX) {
      lead.push(row)
    } else {
      rest.push(row)
    }
  }
  return { text: sentence(event.text || '', inline), notes: folded, lead, rest, isPair: (k) => !!PAIR_KEYS[k] }
}

export function formatEventTime(ts) {
  const d = new Date(ts * 1000)
  try {
    return d.toLocaleString('fa-IR-u-nu-latn', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return d.toISOString().slice(0, 19).replace('T', ' ')
  }
}
