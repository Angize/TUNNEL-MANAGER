import { latinDigits } from '../../lib/num.js'
import { isNodeNameValid } from './nodeName.js'
import { TF } from '../../i18n/fa.js'

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
const FQDN = /^(?=.{1,253}$)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z][A-Za-z0-9-]*$/
const USER = /^[A-Za-z0-9_.-]{1,32}$/
const PORT = /^\d{1,5}$/

function splitTarget(token) {
  const t = latinDigits(token)
  const at = t.lastIndexOf('@')
  const rest = at >= 0 ? t.slice(at + 1) : t
  const colon = rest.lastIndexOf(':')
  return {
    user: at >= 0 ? t.slice(0, at) : '',
    host: colon >= 0 ? rest.slice(0, colon) : rest,
    port: colon >= 0 ? rest.slice(colon + 1) : '',
    hasUser: at >= 0,
    hasPort: colon >= 0,
  }
}

function hostRank(t) {
  if (IPV4.test(t.host)) return 2
  if (FQDN.test(t.host)) return 1
  return 0
}

export function parseLine(raw, line) {
  const words = [...raw.matchAll(/\S+/g)]
  const targets = words.map((w) => splitTarget(w[0]))
  let at = -1
  let best = 0
  targets.forEach((t, i) => {
    const rank = hostRank(t)
    if (rank > best) {
      best = rank
      at = i
    }
  })
  if (at < 0) return { line, raw, err: 'no_host' }
  const t = targets[at]
  const name = words
    .slice(0, at)
    .map((w) => w[0])
    .join(' ')
  let err = ''
  if (t.hasPort && !(PORT.test(t.port) && +t.port >= 1 && +t.port <= 65535)) err = 'bad_port'
  else if (t.hasUser && !USER.test(t.user)) err = 'bad_user'
  else if (name && !isNodeNameValid(name)) err = 'bad_name'
  return {
    line,
    raw,
    name,
    host: t.host,
    port: t.port,
    user: t.user,
    pass: raw.slice(words[at].index + words[at][0].length).trim(),
    err,
  }
}

export function parseList(text) {
  const rows = []
  String(text || '')
    .split(/\r?\n/)
    .forEach((raw, i) => {
      const s = raw.trim()
      if (s && !s.startsWith('#')) rows.push(parseLine(s, i + 1))
    })
  return rows
}

export function autoName(prefix, n, count) {
  return prefix + '-' + String(n).padStart(count > 99 ? 3 : 2, '0')
}

export function prefixValid(prefix, count) {
  const pre = String(prefix || '').trim()
  return !pre || isNodeNameValid(autoName(pre, 1, count))
}

export function resolveList(rows, { prefix, sharedAuth, nodes }) {
  const low = (s) => String(s || '').trim().toLowerCase()
  const panelNames = new Set(nodes.map((n) => low(n.name)))
  const panelHosts = new Set(nodes.map((n) => low(n.host)))
  const listNames = new Set(rows.filter((r) => r.name).map((r) => low(r.name)))
  const pre = String(prefix || '').trim()
  const preOk = prefixValid(pre, rows.length)
  let counter = 0
  const nextAuto = () => {
    for (;;) {
      const name = autoName(pre, ++counter, rows.length)
      if (!panelNames.has(low(name)) && !listNames.has(low(name))) return name
    }
  }
  const seenHosts = new Set()
  const seenNames = new Set()
  return rows.map((r) => {
    if (r.err === 'no_host') return { ...r, status: 'no_host' }
    const h = low(r.host)
    let status = r.err || (seenHosts.has(h) ? 'dup_host' : panelHosts.has(h) ? 'host_taken' : '')
    seenHosts.add(h)
    const auto = !r.name && !status
    if (auto && !preOk) status = 'bad_prefix'
    const name = r.name || (auto && pre && preOk ? nextAuto() : r.host)
    const n = low(name)
    if (!status) {
      if (!isNodeNameValid(name)) status = 'bad_name'
      else if (seenNames.has(n)) status = 'dup_name'
      else if (panelNames.has(n)) status = 'name_taken'
      else if (!r.pass && !sharedAuth) status = 'no_auth'
      else status = 'ok'
    }
    seenNames.add(n)
    return { ...r, name, auto, status }
  })
}

export function targetText(r) {
  return (r.user ? r.user + '@' : '') + r.host + (r.port ? ':' + r.port : '')
}

export function listCounts(rows) {
  const c = { all: rows.length, ok: 0, auth: 0, bad: 0 }
  for (const r of rows) {
    if (r.status === 'ok') c.ok++
    else if (r.status === 'no_auth') c.auth++
    else c.bad++
  }
  return c
}

export function tally(rows) {
  const t = { ok: 0, warn: 0, err: 0, stop: 0, run: 0, wait: 0 }
  for (const r of rows) t[r.state] = (t[r.state] || 0) + 1
  t.good = t.ok + t.warn
  t.bad = t.err + t.stop
  t.end = t.good + t.bad
  return t
}

export function endTone(t) {
  return t.err ? 'bad' : t.stop ? 'mid' : 'ok'
}

export function endText(t) {
  return [
    ['nb_part_ok', t.good],
    ['nb_part_err', t.err],
    ['nb_part_stop', t.stop],
  ]
    .filter(([, n]) => n)
    .map(([key, n]) => TF(key, { n }))
    .join(' · ')
}
