export const NET_TIMEOUT = 20000
export const NET_POST_TIMEOUT = 300000

const HEADERS = {
  'Content-Type': 'application/json',
  'X-Requested-With': 'tnl-central',
}

function abortAfter(ms) {
  const ac = new AbortController()
  return { signal: ac.signal, timer: setTimeout(() => ac.abort(), ms) }
}

export async function apiGet(path) {
  const g = abortAfter(NET_TIMEOUT)
  try {
    const r = await fetch('/api/' + path, { signal: g.signal })
    return await r.json()
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
    let d = {}
    try {
      d = await r.json()
    } catch {
      d = {}
    }
    return { ok: r.ok, d }
  } catch (e) {
    return { ok: false, d: {}, net: e && e.name === 'AbortError' ? 'timeout' : 'drop' }
  } finally {
    clearTimeout(g.timer)
  }
}

export function logout() {
  return apiPost('logout').then(() => {
    location.href = '/'
  })
}
