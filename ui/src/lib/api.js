import { confirmBox } from './dialog.js'
import { T } from '../i18n/fa.js'

export const NET_TIMEOUT = 20000
export const NET_POST_TIMEOUT = 300000

const HEADERS = {
  'Content-Type': 'application/json',
  'X-Requested-With': 'tnl-central',
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

let signedOut = false

function leaveIfSignedOut(status) {
  if (status !== 401 || signedOut) return
  signedOut = true
  location.replace('/')
}

function abortAfter(ms) {
  const ac = new AbortController()
  return { signal: ac.signal, timer: setTimeout(() => ac.abort(), ms) }
}

async function readBody(r) {
  try {
    const d = await r.json()
    return d.code === 'busy' ? { ...d, error: T('err_panel_busy') } : d
  } catch {
    return {}
  }
}

export async function apiGet(path) {
  const g = abortAfter(NET_TIMEOUT)
  try {
    const r = await fetch('/api/' + path, { signal: g.signal })
    if (r.ok) return await r.json()
    leaveIfSignedOut(r.status)
    const d = await readBody(r)
    throw new ApiError(r.status, d.error)
  } finally {
    clearTimeout(g.timer)
  }
}

export async function apiPost(path, body, ms) {
  const g = abortAfter(ms || NET_POST_TIMEOUT)
  try {
    const r = await fetch('/api/' + path, {
      method: 'POST',
      headers: HEADERS,
      body: JSON.stringify(body || {}),
      signal: g.signal,
    })
    leaveIfSignedOut(r.status)
    return { ok: r.ok, d: await readBody(r) }
  } catch (e) {
    return { ok: false, d: {}, net: e && e.name === 'AbortError' ? 'timeout' : 'drop' }
  } finally {
    clearTimeout(g.timer)
  }
}

export async function logout() {
  if (!(await confirmBox(T('logout_q'), T('logout_yes')))) return
  await apiPost('logout')
  location.href = '/'
}
