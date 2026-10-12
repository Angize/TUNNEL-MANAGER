import { useEffect, useState } from 'react'
import { apiPost } from '../../../lib/api.js'

export default function useCdnPorts(ask) {
  const sig = ask && ask.zones.length ? JSON.stringify(ask) : ''
  const [got, setGot] = useState({ sig: '', infos: null })

  useEffect(() => {
    if (!sig) return undefined
    let alive = true
    const { zones, ...rest } = JSON.parse(sig)
    Promise.all(zones.map((zone) => apiPost('cdn-ports', { ...rest, zone }))).then((rs) => {
      if (!alive) return
      const infos = rs.filter((r) => r.ok && r.d.ok).map((r) => r.d)
      setGot({ sig, infos: infos.length ? infos : null })
    })
    return () => {
      alive = false
    }
  }, [sig])

  return sig && got.sig === sig ? got.infos : null
}
